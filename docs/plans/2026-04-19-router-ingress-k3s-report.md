# Router-Style Ingress on k3s: implementation report and pitfalls

Date: 2026-04-19
Branch: `feature/router-ingress`
Current head when writing: `bcc2302` (`Make routed k3s ingress use proxy-sourced upstream connects`)

## 1. Outcome

The router-style ingress redesign now works on the tested k3s node **with one important behavioral change**:

- the proxy **does not preserve the original client pod IP** on the proxy-to-backend hop
- instead, the proxy uses a **proxy-local source** for the upstream/backend connection

This was the only mode that passed both:

- local verification (`bazel test //... --test_output=errors`)
- live k3s verification (fresh service curl returned `HTTP 200`)

## 2. What was implemented

The branch contains two substantive implementation commits plus supporting design/plan commits:

- `8754259` — route annotated pod ingress through the proxy without replacing `eth0`
- `bcc2302` — make routed k3s ingress use proxy-sourced upstream connects

Net effect:

1. **Routed CNI topology for annotated pods only**
   - root namespace routes protected pod traffic to the proxy
   - proxy owns routed `wan_*` and `lan_*` links
   - workload keeps its Kubernetes pod IP on `eth0`

2. **k3s-safe proxy behavior**
   - deployment enables:
     - `INLINE_PROXY_DEBUG_USE_PROXY_SOURCE=1`
     - `INLINE_PROXY_DEBUG_SKIP_LOCAL_SOURCE=1`
     - `INLINE_PROXY_INTERCEPT_PORT=80`
   - these envs are now part of the committed daemonset manifest

3. **Regression coverage updates**
   - routed CNI and namespace tests updated
   - transparent socket test added for proxy-source bind behavior

## 3. Verified evidence

## 3.1 Local verification

Passed:

```bash
bazel test //... --test_output=errors
bazel build //...
bazel build //src/proxy:proxy_daemon //src/cni:inline_proxy_cni //src/bpf:loader
```

Key focused suites also passed repeatedly:

```bash
bazel test //tests:cni_add_del_test //tests:splice_executor_netns_test //tests:transparent_socket_test //tests:deploy_manifest_test --test_output=errors
bazel test //tests:interface_registry_test //tests:relay_session_close_callback_test //tests:bpf_loader_test --test_output=errors
```

## 3.2 Manifest verification

Passed on the remote k3s host:

```bash
kubectl apply --dry-run=client -k deploy/base
kubectl apply --dry-run=server -k deploy/base
```

The committed daemonset manifest contains the required envs:

- `INLINE_PROXY_DEBUG_USE_PROXY_SOURCE=1`
- `INLINE_PROXY_DEBUG_SKIP_LOCAL_SOURCE=1`
- `INLINE_PROXY_INTERCEPT_PORT=80`

## 3.3 Live k3s verification

Fresh route10 deployment from current branch behavior succeeded.

Observed results:

- in-cluster curl to `inline-proxy-caddy-demo.default.svc.cluster.local` returned `HTTP 200 OK`
- proxy logs showed accepted intercepted connections
- proxy metrics incremented during live verification

## 3.4 Rollback verification

The cluster was repeatedly rolled back to the previously known-good images:

- `localhost/inline-proxy/proxy-daemon:dbg9`
- `localhost/inline-proxy/installer:route3`

Rollback was re-verified with:

- fresh in-cluster curl checks returning `ok`
- daemon and installer `Running/Ready`
- active state files matching the currently running annotated Caddy pods

## 4. Pitfalls and lessons learned

This section is the main reason for this report.

## 4.1 The original source-preserving design does **not** survive this routed k3s topology

The most important pitfall:

> In this routed topology on k3s, the proxy cannot reliably bind the proxy-to-workload socket to the original client pod IP.

When the proxy tried to preserve the original client source on the backend hop, live k3s behavior failed with:

- accepted transparent connection at the proxy
- zero useful end-to-end service response
- in debug-sync mode, upstream connect failures like `so_error=111` / `ECONNREFUSED`

So the working fix deliberately changes semantics:

- **proxy still sees original src/dst at ingress**
- **backend socket source is proxy-local**

## 4.2 Local namespace tests were not enough by themselves

The local netns harnesses were necessary, but they were not sufficient to catch the real failure.

Why:

- the local tests did not reproduce the exact k3s host forwarding / kube-router / service-routing environment
- the routed branch could pass locally while still failing on real k3s

Lesson:

> For networking changes in this repo, local netns coverage is necessary but live k3s validation is mandatory.

## 4.3 BPF redirect was **not** the main problem

A tempting wrong conclusion would have been “the tc/BPF path is broken.”

Live evidence showed the opposite:

- `bpf_printk` / trace evidence showed port-80 interception firing
- daemon logs showed accepted transparent connections
- proxy metrics incremented

So the real problem was later in the flow.

Lesson:

> Do not blame tc/BPF first when proxy metrics and accepted-connection logs prove ingress interception is alive.

## 4.4 Host firewall / kube-router policy complicated diagnosis

The k3s node had kube-router-managed policy chains in `iptables`/`nft` state.
This made the host forwarding path much harder to reason about.

A partial hypothesis was that host FORWARD rules alone were the blocker. Temporary ACCEPT probes did not fully resolve the failure.

Lesson:

> Host forwarding/policy is part of the problem space, but it was not the full root cause by itself.

## 4.5 Localizing extra IPs onto `wan_*` is dangerous

Two separate “localization” ideas turned out to be problematic in routed mode:

1. adding protected pod `/32`s onto `wan_*`
2. localizing client `/32`s onto `wan_*` via `LocalSourceManager`

These increased routing ambiguity and interacted badly with the routed topology.

The successful live configuration avoided both.

Lesson:

> In routed mode, avoid making `wan_*` pretend to own unrelated pod/client addresses unless you have a formally proven routing model for them.

## 4.6 Stale state can create misleading noise

At points during debugging, stale `/var/run/inline-proxy-cni` state caused repeated log noise like:

- `attach-ingress failed to resolve ifindex for wan_*`

By the end of verification, the active state files matched the active annotated pods, and this stale-noise condition was no longer present in the rollback state.

Lesson:

> Always compare active state files against currently running annotated pod IPs before trusting interface-reconcile noise.

## 4.7 Debug envs are now operationally important

The current working routed deployment relies on env-driven behavior in the daemonset.

That means the manifest matters, not just the proxy binary.

Lesson:

> Deploying only the binary change without the corresponding daemonset envs is not enough to reproduce the working behavior.

## 5. Current operational interpretation

As of this report:

- the routed ingress branch is **working on the tested k3s setup**
- it is working with the **k3s-safe behavior change** described above
- the implementation is verified locally and live
- rollback safety has also been verified repeatedly

## 6. Remaining risks

1. **Semantic deviation from original requirement**
   - original client source is no longer preserved on the proxy-to-backend hop
   - if strict end-to-end source preservation is still required, this branch is not the final architecture

2. **Single-environment proof so far**
   - verified on the tested single-node k3s setup
   - other CNIs / node topologies / network-policy stacks may behave differently

3. **Manifest-coupled behavior**
   - routed success depends on the committed daemonset env configuration
   - accidental manifest drift can silently reintroduce failures

4. **Stale state handling remains a thing to watch**
   - final rollback state looked clean, but this remains a known operational sharp edge for future edits

## 7. Recommended follow-up

If the team accepts the k3s-safe semantic change, next steps should be:

1. explicitly document that routed mode uses proxy-local backend source
2. add a dedicated note in deployment docs / status docs so future sessions do not re-debug the same issue
3. consider a clearer non-"DEBUG_" naming surface for the now-required routed behavior once the behavior is accepted as permanent

If strict original-source preservation is still mandatory, then the correct next step is **not** polish on this branch, but a deeper architecture redesign.

## 8. Bottom line

The branch is working, but the working form is:

> **router-style ingress on k3s with proxy-sourced backend connects, not original-client-sourced backend connects.**

That distinction is the key pitfall, the key lesson, and the key decision point for future work.
