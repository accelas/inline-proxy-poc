# CNI-Owned BPF Attach, Proxy-Owned Listener FD

Date: 2026-04-27
Status: approved design, ready for implementation planning

## Revision: 2026-04-27 (post-review)

Decisions §1 and §3 below were superseded after implementation review.
The implemented design moves `LoadAndPin` from the proxy daemon's
startup into the CNI plugin's invocation for the proxy DS pod
(detected via `IsProxyPod()`). This eliminates the cold-node race
and the `WaitForPinnedProg` poll entirely, because kubelet admits
the proxy DS pod first (system-node-critical) and serialises CNI
calls. The proxy daemon now opens the already-pinned maps via
`BpfLoader::OpenExistingPin` and writes config + listener fd.

Trade-off accepted: the CNI binary picks up the libbpf dependency and
the embedded skeleton, growing it from "tiny" to "moderate." The
"CNI is libbpf-free" property is no longer maintained.

`docs/architecture.md` sections 2.6 and 8 reflect the implemented
design.

## Goal

Move the TC-ingress BPF program's **load and attach** out of the proxy daemon and into the CNI plugin. The proxy keeps responsibility for **loading the program once at startup, pinning it, and writing the maps** — but stops owning per-interface attach state. The CNI plugin opens the pinned program by path and calls `tc filter add` itself when it creates each `wan_<hash>` interface.

External behavior is unchanged. The split is purely a re-shape of who does what at boot and at pod admission.

## Motivation

Today the proxy daemon attaches BPF reactively: a `StateReconciler` watches `/var/run/inline-proxy-cni/*` state files, an `InterfaceRegistry` notices each new `wan_*` interface, and a `BpfLoader` lazily loads the skeleton on first attach and runs `tc filter add` over netlink. This creates three problems:

1. **Split responsibility for one operation.** The CNI plugin creates `wan_<hash>` and configures its addresses, routes, and netns membership — then exits, leaving the interface un-armed. The proxy then races to attach BPF to the same interface. "Make a workload pod's network operational" is one job split across two processes connected by a state-file watcher.
2. **Reactive reconciliation overhead.** `StateReconciler` and `InterfaceRegistry` exist solely to drive BPF attach/detach. They are 200+ lines of bookkeeping that disappears once attach is co-located with interface creation.
3. **Implicit ordering coupling.** The proxy must be running, must have noticed the state file, and must have completed `AttachIngress` before traffic on `wan_<hash>` will be intercepted. Today this happens to work because CNI ADD finishes before the workload pod sends its first packet, but the timing is incidental.

Putting attach in the CNI plugin makes "I created this interface" and "I made this interface intercept traffic" a single atomic step in a single process.

## Scope

In scope:

- Splitting `src/bpf/loader.{hpp,cpp}` into a slim proxy-side loader (load, pin, write maps) plus a new CNI-side `src/bpf/tc_attach.{hpp,cpp}` (open pin, ensure clsact, attach TC ingress).
- Pinning the program and both maps under `/sys/fs/bpf/inline-proxy/`.
- Adding a bounded poll on the CNI side so that workload pod CNI ADDs landing before proxy startup wait for the pinned program to appear (timeout 30s).
- Deleting `src/proxy/interface_registry.{hpp,cpp}` and `src/proxy/state_reconciler.{hpp,cpp}` and their tests.
- Rewriting the boot sequence in `src/proxy/main.cpp` / `config.cpp` to load+pin+write maps once, then run the listener.
- Updating `src/cni/main.cpp` to wait for the pinned program before invoking the splice, and `src/cni/splice_executor.cpp` to call the new attacher inside its existing proxy-netns scope.
- Updating the architecture doc (sections 2.6 and 8) and the test surface.

Out of scope:

- Changes to `ingress_redirect.bpf.c` (the BPF program itself) or to its observable behavior.
- Changes to the splice topology, k8s API client, or CNI-args parsing.
- Changes to the proxy listener, relay, or upstream-source machinery.
- A clean-uninstall path that unpins maps when the daemonset is deleted (manual cleanup remains).
- Multi-listener / multi-port intercept (still one entry per map, key 0).

## Decisions

### 1. Proxy loads and pins; CNI only attaches

The proxy daemon is the **sole loader** of the BPF program. At startup it opens and loads the embedded skeleton, then pins three objects under `/sys/fs/bpf/inline-proxy/`:

- `prog` — the TC ingress program
- `config_map` — array map (1 entry) holding `{enabled, listener_port, skb_mark}`
- `listener_map` — sockmap (1 entry) holding the listener fd

The CNI plugin **never** loads the program and never writes either map. On each ADD it:

1. Polls `/sys/fs/bpf/inline-proxy/prog` for up to 30s (200 ms interval) until the file exists.
2. Calls `bpf(BPF_OBJ_GET, …)` to get a program fd from the pin.
3. Enters the proxy netns (`ScopedNetns::Enter(netns_paths.proxy)`).
4. Builds a clsact qdisc on `wan_<hash>` if not already present.
5. Adds a TC ingress filter pointing at the program fd.

Step 3 is mandatory: the splice (`src/cni/splice_executor.cpp:534`) calls `MoveLinkToNetns(plan.wan_name, proxy_netns_fd)` before returning, so by the time the attach runs `wan_<hash>` lives in the proxy netns and is invisible to a netlink call from the host root netns. The pin path itself is on the host filesystem and is reachable from any netns, so `bpf_obj_get` happens before the netns entry; the program fd, once obtained, remains valid across the netns switch.

The cleanest place to run the attach is **inside the splice itself**: `SpliceExecutor::ExecuteSplice` already opens a `ScopedNetns::Enter(netns_paths.proxy)` block (`splice_executor.cpp:545`+) for proxy-side address and link-up work. The TC attach is added inside that block, after the wan-side address/up has succeeded. Today the wan address, wan link-up, and the lan/peer veth creation are chained into one `if (!A || !B || !C)` (`splice_executor.cpp:552-558`); implementing this design requires splitting that compound condition so the attach can run between "wan link is up" and the lan/peer work. This avoids re-entering the proxy netns from `cni/main.cpp` and keeps "create interface, attach BPF" atomic in one process.

The CNI binary therefore needs nothing of the BPF skeleton, the embedded `.bpf.o`, or libbpf. A raw `syscall(SYS_bpf, BPF_OBJ_GET, …)` plus the existing netlink TC machinery is sufficient.

### 2. Pin location is `/sys/fs/bpf/inline-proxy/`

The proxy daemonset already mounts `hostPath: /sys/fs/bpf` with `mountPropagation: Bidirectional`. CNI runs on the host directly. Both sides see the same bpffs without any additional mount work or namespace coordination.

### 3. Bounded poll on CNI startup race

There is no kubelet guarantee that the proxy daemon is `Ready` before another pod's CNI ADD fires on a fresh node. The CNI-side resolution is a bounded poll: 30 seconds total elapsed (measured against `CLOCK_MONOTONIC`), 200 ms cadence, on the existence of `/sys/fs/bpf/inline-proxy/prog`. If the pin never appears, CNI ADD returns an error and kubelet retries on its own schedule.

Rejected alternatives:
- *Fail-fast.* Cleaner code but emits a stream of "failed to setup network" events on every fresh node bringup until the proxy is ready.
- *CNI lazy-loads as a fallback.* Walks back the "proxy is sole loader" property and forces the CNI binary to embed the BPF object.
- *Block on the install side* (don't drop the CNI binary into `/opt/cni/bin` until the proxy is Ready). Most invasive, requires installer↔proxy coordination, and breaks chained CNI cases where another plugin sits in front.

### 4. Aggressive removal of `InterfaceRegistry` and `StateReconciler`

Both files exist to drive BPF attach/detach from observed interface state. With BPF attach moved to CNI, neither has a job. Both are deleted, along with their tests. The proxy stops watching `/var/run/inline-proxy-cni/*` entirely; it boots, sets up BPF state once, and then runs only the listener. The `/interfaces` admin endpoint, whose body is currently `InterfaceRegistry::SummaryText()`, is removed entirely. (If a future need for that listing arises, the state files under `/var/run/inline-proxy-cni/*` are still there and can be read directly.) The remaining admin endpoints (`/healthz`, `/readyz`, `/metrics`, `/sessions`) are unchanged.

The session counter is already held by `ProxyState` (`active_sessions_`, with `increment_sessions()` / `decrement_sessions()`). Today it is double-bookkept: `InterfaceRegistry::IncrementSessions()` and `ProxyState::increment_sessions()` are called together at the same call site. The work is to delete the `InterfaceRegistry` copy and its call sites, leaving the existing `ProxyState` counter as the sole source of truth.

`AdminHttp`'s constructor currently takes `InterfaceRegistry&`. Its signature loses that parameter; `src/proxy/admin_http.{hpp,cpp}` and `tests/admin_http_test.cpp` drop their `interface_registry.hpp` includes.

### 5. Restart reuses existing pins when the program tag matches

When the proxy restarts and finds an existing pin at `/sys/fs/bpf/inline-proxy/prog`, it does not unconditionally re-load. It first opens the pinned program, queries `bpf_prog_info.tag` (a SHA1 over the verifier IR), and compares against the tag of the program embedded in the new binary:

- **Tag match**: reuse the existing pinned program and maps. Skip skeleton load. Re-write `config_map[0]` and `listener_map[0]` (idempotent for config, mandatory for listener). Existing TC filters continue to reference the same program by id; in-flight workload pods see no disruption from the proxy bounce.
- **Tag mismatch** (proxy was upgraded): unpin the old program/maps, load the new skeleton, pin afresh. Already-attached TC filters keep referencing the old program by id and continue working until their interfaces are deleted; the kernel reclaims the old program when its last filter detaches.

Tag match is the common path for crash-restart and deploy-without-image-change. Tag mismatch is the upgrade path. The tag-equality check is the one piece of new logic this introduces.

### 6. Map writes are idempotent and order-independent against CNI

`config_map[0]` is written by the proxy at startup. It may be written before or after CNI has attached the program to any interface. Either order is fine: until the proxy writes, `cfg->enabled` reads as `0` and the program returns `TC_ACT_OK` immediately, so packets fall through unintercepted (the same behavior as today's "proxy not yet ready" window).

`listener_map[0]` is similar. Until written, `bpf_map_lookup_elem` returns NULL, the program does not call `bpf_sk_assign`, and packets fall through.

This means the proxy can write the maps whenever it likes during startup as long as both writes complete before it advertises readiness. Order between map writes and pin creation also does not matter, because TC filters created via `bpf_obj_get` only need the program to exist — they do not require map contents.

The listener_map is a `BPF_MAP_TYPE_SOCKMAP`. Inserting an fd into a sockmap requires that the fd be a TCP socket in the `LISTEN` state at the moment of `bpf_map_update_elem`; the kernel rejects non-listening fds. The proxy boot sequence therefore must `bind()` and `listen()` on the transparent listener *before* the `WriteListenerFd` call.

## Architecture

```
┌───────────────────────────────┐         ┌────────────────────────────┐
│       proxy daemon (DS)       │         │   inline_proxy_cni binary  │
│  netns: inline-proxy-system   │         │   runs on host, root netns │
├───────────────────────────────┤         ├────────────────────────────┤
│ Startup:                      │         │ ADD (per pod):             │
│   1. bind+listen on listener  │         │   1. wait≤30s for pinned   │
│   2. skel.open + skel.load    │         │      prog                  │
│   3. mkdir pin dir            │         │   2. bpf_obj_get(prog)     │
│   4. pin prog + config_map    │         │   3. run splice; inside    │
│      + listener_map           │         │      its proxy-netns scope:│
│      (or open existing pin    │         │      ensure clsact + tc    │
│      if tag matches)          │         │      filter add on         │
│   5. write config_map[0]      │         │      wan_<hash>            │
│   6. write listener_map[0]    │         │ DEL: nothing BPF-related   │
│   7. mark /readyz             │         │      (interface delete     │
│ Run: accept loop              │         │      drops qdisc/filter)   │
│ Shutdown: leave pins alone    │         │                            │
└───────────────────────────────┘         └────────────────────────────┘
              │                                          │
              └────── shared bpffs at /sys/fs/bpf ───────┘
                      (host-mounted into proxy pod)
```

## Components

### Proxy: `src/bpf/loader.{hpp,cpp}` (shrunk)

```cpp
class BpfLoader {
public:
    // Idempotent. Loads the skeleton, pins prog/config_map/listener_map
    // under pin_dir. If the pinned prog already exists and its tag
    // matches the embedded program, reuses it without re-loading.
    bool LoadAndPin(std::string_view pin_dir);

    // Writes config_map[0] = {1, port, mark}. Safe to call repeatedly.
    bool WriteConfig(std::uint32_t listener_port, std::uint32_t skb_mark);

    // Writes listener_map[0] = listener_fd. Replaces any prior entry.
    bool WriteListenerFd(int listener_fd);

private:
    bool OpenPinnedOrLoadFresh(std::string_view pin_dir);
    bool TagsMatch(int existing_prog_fd) const;
    struct ingress_redirect_skel* skel_ = nullptr;
};
```

Removed from the current API: `AttachIngress`, `DetachIngress`, `IsIngressAttached`, `ConfigureListenerSocket` (renamed/split into `WriteConfig` + `WriteListenerFd`).

### CNI: `src/bpf/tc_attach.{hpp,cpp}` (new)

```cpp
class TcAttacher {
public:
    explicit TcAttacher(std::string pin_dir);

    // Polls /<pin_dir>/prog for up to `timeout` (CLOCK_MONOTONIC).
    // Called from cni/main.cpp at the top of ADD, before the splice runs.
    bool WaitForPinnedProg(std::chrono::seconds timeout);

    // Resolves ifindex by name in the *current* netns, ensures clsact,
    // attaches a TC ingress filter referencing the pinned prog. Caller
    // must already be inside the netns containing `ifname`.
    bool AttachToInterface(std::string_view ifname);

private:
    int OpenPinnedProg();   // syscall(SYS_bpf, BPF_OBJ_GET, ...)
    bool EnsureClsact(unsigned int ifindex);
    bool AttachIngressFilter(unsigned int ifindex, int prog_fd);

    std::string pin_dir_;
};
```

The TC netlink helpers (`MakeTcRequest`, `EnsureClsactQdisc`, `AttachIngressFilter`, `RemoveIngressFilter`) move from `loader.cpp` to `tc_attach.cpp` essentially unchanged.

`AttachToInterface` is called by `SpliceExecutor::ExecuteSplice` from inside the existing `ScopedNetns::Enter(netns_paths.proxy)` block, immediately after `SetLinkUp(plan.wan_name)`. `WaitForPinnedProg` is called once per CNI ADD by `cni/main.cpp` before invoking the splice — failing fast if the proxy is not yet ready, before any veths or routes have been created.

### Files deleted

- `src/proxy/interface_registry.hpp`
- `src/proxy/interface_registry.cpp`
- `src/proxy/state_reconciler.hpp`
- `src/proxy/state_reconciler.cpp`
- `tests/interface_registry_test.cpp`
- `tests/state_reconciler_test.cpp`

### Files modified

- `src/proxy/main.cpp`, `src/proxy/config.cpp`: new boot sequence (bind+listen → load+pin → write maps → accept loop). No interface watcher. Drop `registry.IncrementSessions()` / `registry.DecrementSessions()` call sites; the parallel `proxy_state.increment_sessions()` / `decrement_sessions()` calls already cover the bookkeeping.
- `src/proxy/admin_http.{hpp,cpp}`: drop the `InterfaceRegistry&` constructor parameter and the `interface_registry.hpp` include. Remove the `/interfaces` endpoint handler (the only consumer of the registry). The remaining endpoints (`/healthz`, `/readyz`, `/metrics`, `/sessions`) are unchanged.
- `src/cni/splice_executor.{hpp,cpp}`: in `ExecuteSplice`, inside the existing proxy-netns scope, split the compound `if (AddInterfaceAddress(wan) || SetLinkUp(wan) || CreateVethPair(lan,peer))` so a TC attach call can run between wan link-up and the lan/peer veth creation. Add a `TcAttacher` collaborator as a `CniExecutionOptions` field — matching the existing `splice_runner` injection-seam pattern, so tests can substitute a stub.
- `src/cni/main.cpp`: before invoking the splice, call `TcAttacher::WaitForPinnedProg` so we fail early if the proxy isn't up. Splice itself runs the attach.
- `src/bpf/BUILD.bazel`: split `:loader` into `:loader` (proxy, depends on skeleton) and `:tc_attach` (CNI, no skeleton dep).
- `src/cni/BUILD.bazel`: `:cni_splice` adds a dep on `//src/bpf:tc_attach`.
- `src/proxy/BUILD.bazel`: drop `interface_registry.{hpp,cpp}` and `state_reconciler.{hpp,cpp}` from `srcs`/`hdrs`.
- `tests/BUILD.bazel`: drop the `interface_registry_test` and `state_reconciler_test` targets; add `bpf_attacher_test`; rewrite `bpf_loader_test` accordingly. Remove the `interface_registry.hpp` include from `admin_http_test`.
- `docs/architecture.md`: rewrite section 2.6 and section 8 to describe the new split.

## Data flow

### Cold node bringup, proxy comes up first (typical)

```
t=0   kubelet schedules proxy DS (system-node-critical)
t=1   proxy starts:
        - bind 127.0.0.1:15001 (listener_fd = 7)
        - skel.open + skel.load
        - mkdir -p /sys/fs/bpf/inline-proxy
        - bpf_obj_pin(prog,         /sys/fs/bpf/inline-proxy/prog)
        - bpf_obj_pin(config_map,   /sys/fs/bpf/inline-proxy/config_map)
        - bpf_obj_pin(listener_map, /sys/fs/bpf/inline-proxy/listener_map)
        - config_map[0]   = {1, listener_port, skb_mark}
        - listener_map[0] = 7
        - /readyz green
t=5   first annotated workload pod scheduled
t=5.1 kubelet invokes inline_proxy_cni ADD
        - WaitForPinnedProg returns immediately
        - bpf_obj_get(prog) -> prog_fd
        - splice runs:
            * create root_wan + wan_<hash> veth pair in root netns
            * MoveLinkToNetns(wan_<hash>, proxy_netns)
            * ScopedNetns::Enter(proxy_netns):
                - addr/up wan_<hash>
                - clsact + tc filter add ingress on wan_<hash>
                - rest of proxy-side splice work
        - return success
t=5.2 first packet on wan_<hash>:
        - TC program reads config_map[0]; enabled=1
        - skc_lookup miss -> listener_map[0] = 7 -> bpf_sk_assign
        - traffic enters the proxy
```

### Cold node bringup, CNI ADD races proxy startup

```
t=0   workload pod CNI ADD fires; splice completes
t=0.1 WaitForPinnedProg starts polling /sys/fs/bpf/inline-proxy/prog
t=2.4 proxy comes up, pins prog/maps
t=2.5 WaitForPinnedProg sees the pin; CNI proceeds with attach
t=2.5 CNI ADD success
```

If 30 s elapses with no pin, CNI returns error; kubelet retries CNI ADD on its own schedule.

### Proxy restart with tag-match (zero disruption)

```
- old proxy SIGTERM, exits
- pinned prog/maps survive (refcount held by pin + by attached TC filters)
- existing TC filters on wan_* keep firing the program
- listener_map[0] now references closed fd; bpf_sk_assign returns
  non-zero and the program returns that non-zero verdict (per
  ingress_redirect.bpf.c: "return assign_rc == 0 ? TC_ACT_OK : assign_rc").
  This causes the kernel to drop or shoot the SYN, producing a brief
  drop window for *new* connections. Established connections continue
  to flow because the program's primary path (skc_lookup) still finds
  their established sockets, so it never reaches the listener_map.
- new proxy starts:
    - bind listener (new fd)
    - skel.open + skel.load -> fresh in-process program
    - read tag of existing pinned prog; compare to embedded program tag
    - tags match: skip pin replacement
    - WriteConfig(...) (idempotent)
    - WriteListenerFd(new_fd)
    - /readyz green
- new connections start hitting the new listener fd
```

### Proxy restart with tag-mismatch (upgrade path)

```
- new proxy starts; skeleton is a different build
- tag query on existing pinned prog returns OLD tag
- unpin old prog and old maps
- pin new prog and new maps
- existing TC filters still reference OLD prog by id and keep firing
  (kernel keeps the OLD program alive until last filter detaches)
- new attaches (new CNI ADDs) use the NEW prog by reading the new pin
- node eventually converges to all filters pointing at the NEW prog
  as workload pods churn; OLD prog is reclaimed when the last filter
  referencing it goes away
```

### Workload pod deletion

```
- kubelet invokes inline_proxy_cni DEL
- existing splice teardown removes veth pairs and state file
- removing wan_<hash> implicitly drops its qdisc and filter
- nothing BPF-specific in the CNI DEL path
```

## Error handling

### Proxy startup

| Failure | Behavior |
|---|---|
| `bind()` listener fails | exit non-zero; kubelet restarts |
| `skel.load` fails (verifier rejected, no CAP_BPF) | exit non-zero |
| pin dir cannot be created (no bpffs) | exit non-zero with explicit "bpffs not mounted" message |
| `bpf_obj_pin` reports already-pinned | open existing pin, run tag check; not an error |
| Tag-mismatch path: unpin or repin fails | exit non-zero; manual `rm -rf /sys/fs/bpf/inline-proxy/` recovery |
| `config_map[0]` or `listener_map[0]` write fails | exit non-zero (state is inconsistent) |

### CNI ADD

| Failure | Behavior |
|---|---|
| `WaitForPinnedProg` times out | return CNI error; kubelet retries on schedule |
| `bpf_obj_get` fails | return CNI error; kubelet retries |
| `EnsureClsact` fails | return CNI error; existing `RollbackSplice` cleans up |
| TC filter add fails | return CNI error; existing `RollbackSplice` cleans up |

There is no explicit BPF rollback step: if `tc filter add` failed, nothing is attached; if it succeeded, the rollback's interface deletion drops the filter automatically.

### Steady state

| Failure | Behavior |
|---|---|
| Proxy crash; listener fd closed | brief drop window for new connections; existing connections continue (BPF only intercepts packets without an established socket); recovers when proxy restarts |
| Manual `rm /sys/fs/bpf/inline-proxy/prog` | already-attached TC filters still work (kernel holds prog by id); next CNI ADD fails until proxy is bounced to repin |
| Workload pod CNI DEL | qdisc + filter removed implicitly with the interface; no BPF state to clean |
| Daemonset uninstall | pins remain; `listener_map[0]` references dead fd; new connections fall through. Manual cleanup `rm -rf /sys/fs/bpf/inline-proxy/` per node |

### Observability

- Existing `attach-ingress ok` / `attach-ingress failed` log lines move from the proxy to the CNI binary (visible in kubelet/CNI debug logs).
- Proxy gains startup logs: `bpf-pin loaded`, `bpf-pin reused (tag match)`, `bpf-pin replaced (tag mismatch)`, `listener_fd written = N`.
- No new admin endpoints. (`/interfaces` is removed; if a future need arises to expose BPF state via HTTP, that's a separate change.)

## Testing

### Unit tests

- `tests/bpf_loader_test.cpp` (proxy-side, rewritten):
  - `LoadAndPin_CreatesPinsUnderRoot` — points at a tmpfs/bpffs test root, asserts the three pins exist after `LoadAndPin`.
  - `LoadAndPin_IsIdempotent` — second call with same root succeeds.
  - `LoadAndPin_TagMatchReuse` — pre-pin a known prog, call again, assert the prog id is unchanged.
  - `LoadAndPin_TagMismatchReplace` — pre-pin a *different* prog, call `LoadAndPin`, assert the new prog id replaces the old.
  - `WriteConfig` and `WriteListenerFd` — assert via `bpf_map__lookup_elem` reads.
  - All cases skip-with-warning when running without CAP_BPF.

- `tests/bpf_attacher_test.cpp` (new, CNI-side):
  - `WaitForPinnedProg_ReturnsImmediatelyWhenPresent`.
  - `WaitForPinnedProg_TimesOut`.
  - `AttachToInterface_AttachesViaTcIngress` — uses `tests/fd_netns_harness.hpp` to set up a netns and dummy interface, pre-pin a trivial prog, call attach, assert the filter is present on the interface.

- `tests/interface_registry_test.cpp` is **deleted**.

### Integration tests

- Existing CNI end-to-end test gains a check that after a successful ADD, `tc filter show dev wan_<hash> ingress` reports an `ingress_redirect` filter referencing the pinned prog id.
- Race test: start CNI ADD before `LoadAndPin` runs in a sibling thread; assert it polls until the pin appears, then succeeds.
- Restart test: run `LoadAndPin` once, observe prog id; run again, assert prog id unchanged when binary unchanged. Force a tag mismatch (e.g., by pre-pinning a different prog), assert prog id changes and pin is replaced.

### Manual smoke test

- Bring up a fresh node with the new proxy + CNI.
- Schedule one annotated workload pod, hit it, verify traffic flows.
- `kubectl rollout restart` the proxy DS; verify in-flight workload pods continue working through the bounce (modulo brief drop window for new connections).
- Schedule a second annotated pod; verify its CNI ADD attaches BPF correctly without re-loading the program (prog id stable across the two pods).

## Migration

This is a breaking internal split with no externally visible behavior change. Migration is rip-and-replace in a single change set:

- Old proxy + new CNI is incompatible (CNI looks for pins the old proxy never creates). Don't ship.
- New proxy + old CNI is incompatible (new proxy doesn't watch interfaces; old CNI doesn't attach). Don't ship.

Both binaries ship together. The daemonset image and the CNI installer image are versioned together (already true today). On rolling upgrade, kubelet replaces the proxy pod, which loads + pins on startup; the installer drops the new CNI binary on each node; subsequent pod admissions use the new path. In-flight pods on the old path keep working because their TC filters stay attached to the old program until their interfaces are deleted.

## Open questions

None at design time. Implementation choices that may surface during planning:

- Whether `WaitForPinnedProg` should also probe `inotify` for faster wakeup; 200 ms polling is fine but trivially upgradeable later.
- Whether to compute the embedded program tag once at proxy startup or on every `LoadAndPin` call. Once is sufficient.
