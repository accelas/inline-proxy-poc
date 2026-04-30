# CNI-side splice reconciler

## Background

PR #9 (CNI-owned BPF attach) split splice plumbing across two callers:
the daemon DS pod owns BPF load+pin during its CNI ADD, and per-pod
splice setup happens during the workload pod's CNI ADD. When the
daemon DS pod is replaced (image upgrade, OOM, eviction, manual
restart), workload pods previously spliced into the old proxy netns
become orphaned: their `peer_<id>` is reaped because its pair-mate
`lan_<id>` died with the old netns; their `eth0` still has /32 with a
default route pointing at a now-non-existent linklocal gateway. The
new daemon comes up healthy and serves *new* workloads, but every
previously-spliced workload pod is silently broken until something
forces a fresh CNI ADD.

PR #11 (\"CNI: restore workload netns state on splice rollback\")
addresses mid-ADD failures by restoring eth0 on partial-splice
cleanup. It does not address this orphan-on-DS-restart case.

A first attempt — `feature/splice-reconciler`, archived as a
reference branch — placed an orphan reconciler inside the proxy
daemon's startup. Issue #12 documents why that approach failed: the
daemon container has its own netns, so `CreateVethPair` from inside
it puts both halves of every veth pair in the daemon's netns instead
of one half in root netns. The repair \"succeeded\" structurally but
left workloads unreachable.

## Goal

Repair orphaned workload splices automatically when the new daemon DS
pod's CNI ADD fires. The CNI plugin runs as a host process invoked
by kubelet — its caller netns is root — so `CreateVethPair` correctly
puts `rwan_<id>` in root and `wan_<id>` in the new proxy netns. By
the time the new daemon container starts, the data plane is restored
for every previously-spliced pod that fits within a self-imposed
deadline.

Non-goals:

- Periodic rescan or runtime reconciliation. Triggered only by a new
  daemon DS pod's CNI ADD.
- Querying the K8s API for live pod state. The on-disk state file is
  the source of truth.
- Cleaning up state files for pods whose workload netns has
  disappeared. Kubelet's CNI DEL is responsible.
- Re-pinning BPF objects (already handled by `LoadAndPin` in the
  existing IsProxyPod branch and `OpenExistingPin` in the daemon
  startup path).
- Daemon-side reconciliation. Removed entirely after the failed
  attempt; the daemon process never enters the splice flow at boot.

## Trigger

The repair fires inside `SpliceExecutor::HandleAdd`'s `IsProxyPod`
branch (`src/cni/splice_executor.cpp:343`), after `proxy_pod_pinner`
succeeds and before the early-return that skips the rest of HandleAdd.
This branch executes precisely when kubelet calls CNI ADD for the new
daemon DS pod — the exact event that creates the orphan condition.

The CNI plugin runs as a host process. `CreateVethPair`, route adds,
and rule installs all happen in root netns naturally; the architectural
mismatch from the daemon-side approach disappears.

The new daemon's netns path is obtained via
`ResolveWorkloadNetnsPath(invocation)`, which reads
`request.prev_result->interfaces[].sandbox`. This depends on the
upstream CNI plugin in the chain (flannel, bridge, etc.) populating
the `sandbox` field on the matching interface for the daemon DS pod.
Standard plugins do this by convention. If the upstream plugin omits
`sandbox`, the resolver returns `nullopt` and the silent-skip branch
in Failure handling applies — repair is bypassed and the daemon
still boots.

## Detection

Per state file:

1. `stat()` the recorded `proxy_netns_path`.
2. `stat()` the new proxy netns path (the daemon DS pod's own netns,
   resolved via `ResolveWorkloadNetnsPath(invocation)` since the
   daemon DS pod is itself the \"workload\" for this CNI invocation).
3. Compare `(st_dev, st_ino)`. Equal → splice is intact, skip. Not
   equal (including ENOENT on the recorded path) → repair candidate.

A fresh DS pod always gets a fresh netns inode, so the predicate fires
precisely when wanted.

## Per-state-file procedure

For each `${state_root}/container-*.json`:

1. **Deadline check.** If `now() >= deadline`, bump
   `skipped_deadline_exceeded` for the rest of the iteration and
   return.
2. **Parse JSON.** On parse error → `failed++`, log, continue.
3. **Workload-netns existence check.** If `workload_netns_path` does
   not exist on disk → `skipped_workload_gone++`, continue.
4. **Inode comparison.** If `proxy_netns_path` resolves to the same
   `(st_dev, st_ino)` as the new proxy netns → `skipped_intact++`,
   continue.
5. **Reconstruct `CniRequest`.** Wrap `prev_result` in
   `{\"cniVersion\":\"1.0.0\",\"name\":\"restore\",\"prevResult\":<prev_result>}`
   and call `ParseCniRequest` (the same recipe `HandleDel` uses at
   `splice_executor.cpp:404-406`).
6. **Fabricate `PodInfo workload_pod` and `PodInfo proxy_pod`** so
   `HandleAdd` admits the orphan to its full splice path. The
   downstream predicates that need to pass are `IsAnnotationEnabled`
   (workload-side) and `MatchesNodeLocalProxy` (proxy-side: requires
   `running == true` + `namespace_name == "inline-proxy-system"` +
   `labels["app"] == "inline-proxy"` + `proxy.node_name ==
   workload.node_name`). Field mapping:

   | Field | Source |
   |-------|--------|
   | `workload_pod.name` | state file `pod_name` |
   | `workload_pod.namespace_name` | state file `pod_namespace` |
   | `workload_pod.node_name` | state file `proxy_node_name` (the recorded node ID; same node executed both the original splice and this repair) |
   | `workload_pod.running` | hardcoded `true` |
   | `workload_pod.annotations["inline-proxy.example.com/enabled"]` | hardcoded `"true"` |
   | `proxy_pod.name` | state file `proxy_name` |
   | `proxy_pod.namespace_name` | state file `proxy_namespace`, defaulting to `"inline-proxy-system"` if missing |
   | `proxy_pod.node_name` | matches `workload_pod.node_name` |
   | `proxy_pod.running` | hardcoded `true` |
   | `proxy_pod.labels["app"]` | hardcoded `"inline-proxy"` |
7. **Construct `CniInvocation`** from container_id, ifname, request.
8. **Call `executor.HandleAdd(invocation, workload_pod, proxy_pod)`**
   with `options.proxy_netns_path = current_proxy_netns`. On success
   → `repaired++`. Otherwise log `result.stderr_text` + `failed++`.

The state file is rewritten by `HandleAdd`'s normal `StateStore::Write`
final step, so subsequent CNI DEL invocations correctly see the new
proxy netns path.

## Failure handling

Three classes of error, all of which let the daemon DS pod's CNI ADD
return success regardless:

- **Per-pod failure** (parse error, malformed prev_result, HandleAdd
  failure): logged + counted; never propagates.
- **Deadline exceeded** (default 30s): remaining pods bump
  `skipped_deadline_exceeded`; the function returns; the daemon comes
  up; remaining orphans wait for the next daemon restart.
- **`ResolveWorkloadNetnsPath(invocation)` returns nullopt** (no
  sandbox in the daemon's prev_result): repair is skipped silently
  with a single log line; `proxy_pod_pinner` already succeeded so the
  daemon still boots.

The CNI ADD itself never fails because of repair. This guarantees
that a failed orphan never blocks the daemon from booting — strictly
better than the pre-repair state where the same orphan was already
broken.

## Trust model

The state file is treated as authoritative for what was admitted:

- If the file exists, the workload pod was at some point successfully
  admitted as an annotated proxy workload, so we synthesise a workload
  `PodInfo` whose `annotations` map satisfies `IsAnnotationEnabled`
  and a proxy `PodInfo` whose `running`/`namespace_name`/`labels`/
  `node_name` satisfy `MatchesNodeLocalProxy`.
- If the workload's annotation has since been removed, kubelet has
  not yet called CNI DEL (otherwise the state file would be gone), so
  re-splicing is still semantically correct: the pod is in a
  splice-tracked lifecycle phase.
- We do not call the K8s API. The apiserver may be briefly unavailable
  during a control-plane upgrade, which is exactly when recovery
  should be most robust.

## Public API

Single new module `src/cni/splice_repair.{hpp,cpp}`:

```cpp
namespace inline_proxy {

struct SpliceRepairResult {
    std::size_t total_state_files = 0;
    std::size_t skipped_intact = 0;
    std::size_t skipped_workload_gone = 0;
    std::size_t skipped_deadline_exceeded = 0;
    std::size_t repaired = 0;
    std::size_t failed = 0;
};

SpliceRepairResult RepairOrphanedSplices(
    SpliceExecutor& executor,
    std::filesystem::path current_proxy_netns,
    std::chrono::steady_clock::duration deadline = std::chrono::seconds(30));

}  // namespace inline_proxy
```

The function takes the executor by reference so callers can stub
`splice_runner` for unit testing. `current_proxy_netns` is the new
proxy netns path (resolved from the invocation in the CNI hookup; an
explicit parameter for testability). Default deadline is 30s.

`RepairOrphanedSplices` reads `state_root` from the executor's
options. `SpliceExecutor` does not currently expose `options_`
publicly; this spec assumes a one-line addition of a const accessor:

```cpp
const CniExecutionOptions& options() const { return options_; }
```

That accessor in `splice_executor.hpp`'s public section is a small
prerequisite for the implementation. (The unmerged daemon-side
branch already added it; carrying the change forward is essentially
free.)

## Hookup in `HandleAdd`

`splice_executor.cpp:343-350` becomes:

```cpp
if (IsProxyPod(workload_pod)) {
    if (!options_.proxy_pod_pinner(options_.pin_dir)) {
        result.stderr_text = \"failed to LoadAndPin BPF program for proxy DS pod\";
        return result;
    }
    if (const auto self_netns = ResolveWorkloadNetnsPath(invocation);
        self_netns.has_value()) {
        const auto repair = RepairOrphanedSplices(*this, *self_netns);
        std::cerr << \"splice-repair total=\" << repair.total_state_files
                  << \" repaired=\" << repair.repaired
                  << \" skipped_intact=\" << repair.skipped_intact
                  << \" skipped_workload_gone=\" << repair.skipped_workload_gone
                  << \" skipped_deadline_exceeded=\" << repair.skipped_deadline_exceeded
                  << \" failed=\" << repair.failed << \"\\n\";
    } else {
        std::cerr << \"splice-repair skipped: cannot resolve daemon DS pod netns from prev_result\\n\";
    }
    result.success = true;
    return result;
}
```

The `options.proxy_netns_path` override mechanism on
`CniExecutionOptions` (already honored at `splice_executor.cpp:482-483`)
is what `RepairOrphanedSplices` uses internally to point per-orphan
`HandleAdd` invocations at the new proxy netns. The hookup itself
relies on `*this` — the same `SpliceExecutor` instance — so all
caller-injected options (notably `tc_attacher` and `state_root`)
propagate.

## Idempotency on kubelet retry

If the daemon DS pod's CNI ADD fails for any reason and kubelet
retries, repair is idempotent:

- Pods repaired in the first attempt have state files pointing at
  the first attempt's netns. If kubelet retries within the same
  sandbox (same netns), inodes match → `skipped_intact++` → no work.
  If kubelet creates a new sandbox (fresh netns), inodes don't match
  → repaired again, against the new netns.
- Half-completed pods replay through `HandleAdd` cleanly because
  PR #11's cleanup logic handles partial workload-side state.
- The deadline applies per-attempt; retries get a fresh 30s budget.

## BUILD wiring

`src/cni/BUILD.bazel`'s `cni_splice` cc_library adds
`splice_repair.cpp` to `srcs` and `splice_repair.hpp` to `hdrs`. The
existing `cni_splice` deps (`cni_parser`, `cni_types`, `k8s_client`,
`//src/bpf:loader`, `//src/bpf:tc_attach`, `//src/shared:shared`)
already cover everything `splice_repair.cpp` needs:

- `cni_types`: `CniRequest`, `PrevResult`, `PodInfo`, `CniInvocation`
- `cni_parser`: `ParseCniRequest`
- `k8s_client`: `PodInfo` (transitively included in headers)
- `//src/shared:shared`: `StateStore`, `StateFields`

No additional `deps` entries are needed and no new Bazel target is
created. The CNI binary `inline_proxy_cni` already depends on
`cni_splice` and so transitively links the reconciler.

The unmerged daemon-side `src/proxy/splice_repair.{hpp,cpp}` and its
BUILD wiring are not carried forward; the new approach is a clean
re-implementation in the right module. The unmerged branch is
preserved for reference but no longer load-bearing.

## Tests

### `tests/splice_repair_test.cpp` (unit, no root)

Inject a `splice_runner`-stubbed `SpliceExecutor` so `ExecuteSplice`
short-circuits and the test observes which calls were issued. Eight
tests:

1. `EmptyStateRootProducesZeroCounts` — empty existing dir.
2. `NonexistentStateRootProducesZeroCounts` — first-ever-boot path.
3. `MatchingProxyInodeIsSkippedIntact` — current-netns match.
4. `MissingWorkloadNetnsIsSkippedAsGone` — workload netns gone.
5. `OrphanedFileTriggersHandleAddWithCurrentNetns` — splice_runner
   invoked with correct args.
6. `RunnerFailureCountsAsFailed` — splice_runner returns false.
7. `MalformedStateFileCountsAsFailed` — bad JSON.
8. **NEW: `DeadlineExceededShortCircuitsScan`** — pre-set deadline of
   0ns; assert no per-pod work runs and counts roll up under
   `skipped_deadline_exceeded`.

### `tests/splice_repair_netns_test.cpp` (integration, root-gated)

`NetnsFixture::RunSpliceRepairScenario` is unchanged from the
unmerged branch's implementation — it already drives the repair via
real netlink in a process whose netns context is suitable for
`CreateVethPair` to put one half in root. The integration scenario
is netns-context-agnostic at its outermost level; only the test
binary's netns context matters.

### `tests/cni_add_del_test.cpp` (unit)

Add one test: `ProxyPodAddTriggersRepairWithSelfNetns`. Stubs
`proxy_pod_pinner` to return true; stubs `splice_runner` to record
its arguments. Constructs a state file with a non-matching proxy
netns inode. Invokes `HandleAdd` for an `IsProxyPod` workload.
Asserts `splice_runner` was invoked with `proxy_netns_path` equal to
the IsProxyPod invocation's resolved workload netns path (the new
daemon's own netns).

## Operational considerations

- Repair runs synchronously inside the daemon DS pod's CNI ADD. The
  30s deadline puts a hard ceiling on contribution to ADD latency.
- kubelet's CNI invocation timeout is typically 3 minutes (containerd
  stream limit); 30s is well under that.
- Repair runs ONLY when a new daemon DS pod is created. Steady-state
  workload CNI ADDs go through the existing path unchanged.
- First-ever boot: state dir empty → walk yields zero orphans →
  instant return.
- Multi-orphan upgrade: 30s comfortably handles tens of orphans;
  beyond that the next daemon restart picks up the leftovers.

## Reverts vs the unmerged daemon-side approach

The `feature/splice-reconciler` branch attempted this work from the
daemon side. None of those commits are merged. This spec replaces
that approach entirely:

- `src/proxy/splice_repair.{hpp,cpp}` — not carried forward; new
  module lives at `src/cni/splice_repair.{hpp,cpp}`.
- `src/proxy/config.cpp` daemon-startup hookup — not carried forward;
  daemon never enters splice flow.
- `deploy/base/proxy-daemonset.yaml`'s `/var/run/netns` mount — not
  needed; CNI plugin runs as a host process with native access.

The reusable assets are intellectual: the per-state-file procedure,
the unit test scenarios, and the integration test driver. All port
verbatim into the new module.

## Future work (explicitly deferred)

- Periodic re-reconcile during steady-state. Trigger-only is
  sufficient for the daemon-replacement case.
- Garbage-collecting state files whose workload netns has
  disappeared. Kubelet's CNI DEL is responsible.
- Repairing splices broken by causes other than DS-pod replacement
  (e.g., a manually-deleted veth). Out of scope.
- Manual-trigger CLI mode (e.g., `inline_proxy_cni reconcile`) for
  operator use. YAGNI; revisit if operators ever need it.
