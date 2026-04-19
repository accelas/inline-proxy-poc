# Router-Style Inline Proxy Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Convert annotated-pod interception from the current moved-eth0 hybrid splice into a router-style ingress path where the primary CNI keeps baseline pod networking and the chained CNI inserts the proxy as the routed next hop.

**Architecture:** Preserve the primary-CNI-created workload `eth0` as the pod-IP owner, add a routed upstream root↔proxy veth pair plus a routed downstream proxy↔workload veth pair, rewrite the root namespace host route for the annotated pod to the proxy upstream IP, and update workload/proxy routes so transparent proxy sessions still preserve original src/dst. Extend the existing namespace-backed e2e tests instead of inventing a new harness.

**Tech Stack:** C++20, Bazel, GoogleTest, Linux netns/veth/routing APIs, tc/eBPF loader, k3s-oriented chained CNI flow.

---

## File map

- `src/cni/splice_executor.cpp/.hpp` — replace moved-eth0 splice with routed root↔proxy and proxy↔workload link setup, state persistence, and DEL restoration.
- `src/shared/netlink.cpp/.hpp` — add any small helpers needed for route/address deletion/restoration that are cleaner as reusable primitives.
- `tests/cni_add_del_test.cpp` — lock state fields and non-netns behavior for routed setup.
- `tests/netns_fixture.cpp/.hpp` — evolve the existing splice e2e fixture to model primary-CNI baseline networking plus routed proxy insertion.
- `tests/splice_executor_netns_test.cpp` — keep the current e2e entrypoint, but validate the new routed behavior.
- `tests/ebpf_intercept_fd_netns_test.cpp`, `tests/fd_netns_harness.cpp/.hpp` — only adjust if the explicit routed `wan_*` assumptions require it.

### Task 1: Lock the routed splice contract in tests

**Files:**
- Modify: `tests/cni_add_del_test.cpp`
- Modify: `tests/netns_fixture.cpp`
- Modify: `tests/netns_fixture.hpp`
- Modify: `tests/splice_executor_netns_test.cpp` (only if assertions/messages need adjustment)

- [ ] **Step 1: Write/extend the failing unit-level expectations for routed state**

Add assertions in `tests/cni_add_del_test.cpp` for the new persisted fields needed by routed cleanup, for example root-side peer name and the fact that the workload/proxy netns paths are still recorded. Keep the existing fake splice-runner path so the test fails on missing routed state fields rather than real netns operations.

- [ ] **Step 2: Run the targeted unit test to verify it fails**

Run: `bazel test //tests:cni_add_del_test --test_output=errors`
Expected: FAIL because the routed state fields/expectations are not implemented yet.

- [ ] **Step 3: Rewrite the existing splice e2e scenario to describe the new topology**

In `tests/netns_fixture.cpp`, keep the current named namespaces and primary-CNI-like bridge-backed baseline, but change `RunSpliceExecutorScenario()` so it expects:
- workload `eth0` to remain the pod-IP owner
- a new routed downstream peer in the workload namespace
- a root-side upstream peer in the root namespace
- pod traffic to reach the proxy first and still arrive at the workload with transparent semantics

- [ ] **Step 4: Run the routed splice e2e test and verify it fails for the right reason**

Run: `bazel test //tests:splice_executor_netns_test --test_output=errors`
Expected: FAIL because `SpliceExecutor` still implements the old moved-eth0 topology.

- [ ] **Step 5: Commit the failing-test scaffold**

```bash
git add tests/cni_add_del_test.cpp tests/netns_fixture.cpp tests/netns_fixture.hpp tests/splice_executor_netns_test.cpp
git commit -m "test: describe routed proxy insertion behavior"
```

### Task 2: Replace the old splice with routed root↔proxy and proxy↔workload links

**Files:**
- Modify: `src/cni/splice_executor.cpp`
- Modify: `src/cni/splice_executor.hpp`
- Modify: `src/shared/netlink.cpp`
- Modify: `src/shared/netlink.hpp`

- [ ] **Step 1: Make the old splice test fail against the new implementation target**

Re-run the routed e2e from Task 1 before touching production code.

Run: `bazel test //tests:splice_executor_netns_test --test_output=errors`
Expected: FAIL on old topology assumptions.

- [ ] **Step 2: Implement upstream routed link creation**

In `SpliceExecutor`, stop renaming/moving workload `eth0` into the proxy namespace. Instead:
- create a root-side peer and proxy `wan_*` veth pair
- move only the proxy end into the proxy namespace
- assign deterministic transit IPs
- install `podIP/32 via <proxy_wan_ip> dev <root_peer>` in the root namespace
- persist the root peer name for DEL

- [ ] **Step 3: Implement downstream routed link creation without replacing workload `eth0`**

Still in `SpliceExecutor`:
- create a proxy `lan_*` veth pair
- move the workload-side peer into the workload namespace without renaming away the primary CNI `eth0`
- assign deterministic downstream transit IPs
- normalize the pod IP on workload `eth0` to `/32`
- make workload default/original routes point to the proxy transit next hop so return traffic comes back through the proxy

- [ ] **Step 4: Implement proxy-side routing and DEL restoration**

Configure the proxy namespace so:
- `podIP/32` routes to the workload transit peer
- upstream/default forwarding goes out the root-side transit peer
- DEL removes root route rewrites, deletes the created veth pairs, and restores workload addresses/routes from saved `prevResult`

- [ ] **Step 5: Run targeted tests to verify the new routed splice passes**

Run: `bazel test //tests:cni_add_del_test //tests:splice_executor_netns_test --test_output=errors`
Expected: PASS.

- [ ] **Step 6: Commit the routed splice implementation**

```bash
git add src/cni/splice_executor.cpp src/cni/splice_executor.hpp src/shared/netlink.cpp src/shared/netlink.hpp tests/cni_add_del_test.cpp tests/netns_fixture.cpp tests/netns_fixture.hpp tests/splice_executor_netns_test.cpp
git commit -m "feat: route annotated pod ingress through the proxy"
```

### Task 3: Reconcile transparent interception assumptions with the explicit routed `wan_*` path

**Files:**
- Modify: `tests/ebpf_intercept_fd_netns_test.cpp` (if needed)
- Modify: `tests/fd_netns_harness.cpp`
- Modify: `tests/fd_netns_harness.hpp`
- Modify: `src/proxy/interface_registry.cpp` (only if interface tracking assumptions break)
- Modify: `src/proxy/config.cpp` (only if intercept-port plumbing needs adjustment)

- [ ] **Step 1: Run the existing transparent e2e proof against the routed branch state**

Run: `bazel test //tests:ebpf_intercept_fd_netns_test --test_output=errors`
Expected: PASS if the current explicit routed `wan_*` harness is already sufficient; otherwise FAIL with a concrete routed-assumption mismatch.

- [ ] **Step 2: Apply the minimal fixes needed to keep transparent interception proof aligned**

Only change the interception harness or proxy plumbing if the routed redesign broke an assumption about how `wan_*` links are configured or replayed into the loader. Prefer preserving the existing harness structure.

- [ ] **Step 3: Re-run the transparent e2e proof**

Run: `bazel test //tests:ebpf_intercept_fd_netns_test --test_output=errors`
Expected: PASS.

- [ ] **Step 4: Commit any interception-alignment fix (skip if no code changed)**

```bash
git add tests/ebpf_intercept_fd_netns_test.cpp tests/fd_netns_harness.cpp tests/fd_netns_harness.hpp src/proxy/interface_registry.cpp src/proxy/config.cpp
git commit -m "fix: keep transparent interception aligned with routed wan links"
```

### Task 4: Final verification and repo hygiene

**Files:**
- Modify: implementation/test files touched above
- Optional: `docs/plans/2026-04-19-inline-proxy-k3s-status.md` only if the known-blocker description changes materially

- [ ] **Step 1: Run focused verification for the routed redesign**

Run: `bazel test //tests:cni_add_del_test //tests:splice_executor_netns_test //tests:ebpf_intercept_fd_netns_test --test_output=errors`
Expected: PASS.

- [ ] **Step 2: Run broad regression coverage once the focused suite is green**

Run: `bazel test //... --test_output=errors`
Expected: PASS.

- [ ] **Step 3: Inspect git status and summarize remaining diffs**

Run: `git status --short`
Expected: only intentional implementation changes or nothing left to commit.

- [ ] **Step 4: Commit any final cleanup**

```bash
git add -A
git commit -m "chore: finish routed inline proxy cleanup"
```
