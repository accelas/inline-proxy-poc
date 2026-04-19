# Inline Proxy PoC on k3s: goal, design, implementation status, and current blockers

Date: 2026-04-19
Branch: `main`
Current head when writing: `34734e2` (`fix: support embedded k3s kubeconfig credentials`)

## 1. Purpose of this document

This document is a handoff/status capture for the inline transparent proxy PoC. It is written so a later session can resume without re-deriving the architecture, deployment history, runtime findings, and remaining blockers.

This document covers:

- the intended PoC goal
- the approved design
- the code layout and what is implemented
- what was actually tested on a live k3s host
- the issues discovered during real deployment
- fixes already made
- the current known gap preventing end-to-end proof via proxy metrics
- recommended next steps

---

## 2. Goal of the PoC

The PoC goal is **not** a minimal smoke test. The goal is to demonstrate the architecture from the design gist in a way that is credible for scale and can later be evolved into a productized system.

### Functional goal

For **annotated backend pods** on k3s:

- insert a **node-local inline proxy** using a **chained CNI plugin**
- keep the app pod unaware of the proxy
- preserve the app pod IP model from Kubernetes' perspective
- forward inbound TCP traffic through a transparent proxy before it reaches the workload
- use **Caddy** as the demo backend workload

### Technology constraints

- target: **k3s**
- proxy runs as a **DaemonSet**
- proxy exposes an HTTP endpoint for Kubernetes health/readiness and metrics
- custom chained CNI plugin is written in **C++**
- **yajl** is a hard requirement for JSON parsing in the custom CNI plugin only
- repository base comes from `../mango-template`
- proxy code can reuse pieces from `../http-endpoint`, but should remain fundamentally **single-threaded / event-loop based**

### Proxy data-plane requirement agreed with the user

The proxy data plane for the PoC is intentionally simple userspace transparent forwarding:

- listen on `INADDR_LOOPBACK` with `IP_TRANSPARENT`
- on `accept()` use `getsockname()` and `getpeername()` to recover original dst/src
- create upstream socket with `IP_TRANSPARENT`
- `bind()` upstream socket to original source
- `connect()` to original destination
- relay bytes using simple `read()` / `write()` loops

### Verification goal

The proxy must expose a monotonic metric proving real traffic traversal, specifically a counter like:

- `inline_proxy_total_connections`

This metric is intended to be the primary runtime proof that actual service traffic crossed the proxy path.

---

## 3. Approved high-level design

### 3.1 Node-local architecture

The intended architecture is:

1. **chained CNI plugin** runs after the primary CNI
2. for annotated workload pods, the plugin identifies the **node-local proxy pod**
3. the plugin performs a **splice**:
   - move the original workload interface peer into proxy netns as `wan_*`
   - create a replacement veth pair
   - move the replacement workload-facing peer back into the workload netns as `eth0`
   - keep a proxy-facing `lan_*` inside the proxy netns
4. the proxy DaemonSet owns the `wan_*` and `lan_*` interfaces
5. proxy receives the intercepted connections and relays to original dst using transparent sockets

### 3.2 Multi-node stance

The design is **multi-node ready** in the sense that:

- there is one proxy DaemonSet pod per node
- the CNI plugin must choose the proxy pod on the **same node** as the workload pod
- there is no cross-node coordination plane
- everything important is node-local

### 3.3 Proxy runtime design

The proxy daemon was intentionally designed as:

- single-threaded
- event-loop driven
- admin HTTP listener + transparent listener + sessions all on one loop
- no worker pool for steady-state traffic

This was a deliberate departure from the thread-pool shape of `../http-endpoint`.

### 3.4 Productizable naming

The repo/manifests use intentionally replaceable product-style names such as:

- namespace: `inline-proxy-system`
- daemonset: `inline-proxy-daemon`
- installer: `inline-proxy-installer`
- CNI binary: `inline-proxy-cni`
- annotation: `inline-proxy.example.com/enabled`

---

## 4. Repository layout and implemented components

Current repo areas of interest:

- `src/cni/`
  - CNI main
  - CNI arg parsing
  - Kubernetes lookup client
  - splice executor
  - yajl parser
- `src/proxy/`
  - proxy daemon
  - admin HTTP metrics/readiness
  - relay/session state
- `src/bpf/`
  - eBPF-related code/loader pieces
- `src/shared/`
  - netns/netlink/state helpers
- `deploy/base/`
  - namespace / RBAC / DaemonSets / demo workloads
- `deploy/scripts/`
  - CNI installer and reconcile scripts
- `tests/`
  - unit tests and netns/integration-style coverage
- `docs/plans/`
  - original design + plan docs

Important existing docs:

- `docs/plans/2026-04-18-inline-proxy-poc-design.md`
- `docs/plans/2026-04-18-inline-proxy-poc.md`

---

## 5. Current code status by subsystem

## 5.1 Proxy daemon

Status: **implemented and running**

What is present:

- daemon process builds and runs
- admin HTTP endpoints exist
- readiness/health exist
- metrics endpoint exists
- request/session metric added

Known metrics exposed:

- `inline_proxy_ready`
- `inline_proxy_active_sessions`
- `inline_proxy_total_connections`

Relevant commit:

- `a902b0e` — `feat: expose total proxy connection count`

Observed live behavior on k3s:

- daemon pod becomes Ready
- `/metrics` works
- `inline_proxy_total_connections` remains `0` even when demo traffic succeeds

Interpretation:

- the daemon itself is healthy
- current failure is not a daemon boot issue
- the missing end-to-end proof is because traffic is not yet actually traversing the daemon

---

## 5.2 Chained CNI plugin

Status: **partially implemented, not yet achieving real in-cluster splice**

What it currently does successfully:

- parses CNI input
- resolves pod identity
- looks up workload pod metadata via Kubernetes API
- finds node-local proxy pod metadata via Kubernetes API
- detects annotation gating
- persists splice plan / state under `/var/run/inline-proxy-cni/`
- returns `prevResult` JSON so the chain remains valid

What it does **not** yet achieve in real cluster execution:

- live workload/proxy netns discovery from actual kubelet/container runtime context
- actual interface move/rename/splice on the running cluster path
- resulting interception that feeds traffic into the proxy daemon

The main reason is visible in the current code path:

- `src/cni/main.cpp` constructs `SpliceExecutor executor;` with default options
- `src/cni/splice_executor.cpp` only calls real `ExecuteSplice(...)` if `options_.workload_netns_path` or `options_.proxy_netns_path` are set
- in the real kubelet invocation path, those options are not populated
- therefore `HandleAdd(...)` persists state but does not actually perform the network splice

In short:

- **planning is real**
- **state persistence is real**
- **actual pod/proxy wiring is still missing in-cluster**

This is the main architectural gap behind the still-zero metrics.

---

## 5.3 Kubernetes lookup client in CNI

Status: **substantially improved during real deployment debugging**

Originally the client assumed in-cluster service env/serviceaccount semantics. That was wrong for a host-installed CNI binary.

Fixes made:

### 5.3.1 Load credentials from host kubeconfig

Relevant commit:

- `e853510` — `fix: load cni kube credentials from k3s kubeconfig`

Effect:

- if service env vars are absent, the client can load host kubeconfig material instead of failing with `KUBERNETES_SERVICE_HOST is not set`

### 5.3.2 Decode chunked HTTP responses from apiserver

Relevant commit:

- `8fa9bc9` — `fix: decode chunked kube api responses`

Why needed:

- k3s apiserver returned HTTP/1.1 responses with `Transfer-Encoding: chunked`
- previous client code extracted the raw body without chunk decoding
- JSON parsing then failed on valid pod responses

### 5.3.3 Support embedded kubeconfig credentials

Relevant commit:

- `34734e2` — `fix: support embedded k3s kubeconfig credentials`

Why needed:

- `/etc/rancher/k3s/k3s.yaml` embeds cert/key/CA data instead of always pointing to file paths
- the client now supports embedded material, writing temporary files when needed

Current outcome:

- the CNI plugin can now talk to the k3s API successfully enough to create annotated workload sandboxes
- this was a real blocker during live deployment and is now resolved enough for workload pods to start

Remaining note:

- there were runtime observations of 403s while the plugin was still using less-privileged credentials paths during earlier rollout attempts; later changes moved support toward the admin kubeconfig path
- the running cluster eventually admitted annotated Caddy pods after these auth-related fixes

---

## 5.4 Installer / k3s integration

Status: **repo and remote test path both required fixes**

### 5.4.1 k3s runtime CNI path

Relevant commit:

- `d2f14ea` — `fix: install k3s cni plugin into runtime path`

Reason:

- kubelet on this host searched for plugins under `/var/lib/rancher/k3s/data/cni`
- earlier installer logic preferred `/var/lib/rancher/k3s/data/current/bin`
- result was sandbox creation failure because kubelet could not find `inline-proxy-cni`

### 5.4.2 symlinked k3s CNI binaries

Relevant commit:

- `66c63c4` — `fix: detect symlinked k3s cni binaries`

Reason:

- `/var/lib/rancher/k3s/data/cni` contains symlink entries on this host
- installer selection logic only treated regular files as a valid populated directory
- it therefore incorrectly fell back to another bin path

### 5.4.3 remote installer image drift

During live remote testing, the repo manifests were not enough by themselves because the remote cluster used ad-hoc locally built images.

Temporary images used on the remote host:

- `localhost/inline-proxy/proxy-daemon:test`
- `localhost/inline-proxy/installer:test`
- later an additional replacement installer tag:
  - `localhost/inline-proxy/installer:fix`

Reason for the extra installer tag:

- the running installer pod was using a stale image layout and crashed with:
  - `/bin/sh: 0: cannot open /opt/inline-proxy/scripts/install-cni.sh: No such file`
- rebuilding and retagging the installer image resolved that runtime mismatch on the remote host

Current remote installer state at the time of writing:

- installer pod is running on remote host with the rebuilt image override
- installer log shows:
  - `installed inline-proxy-cni into /host/var/lib/rancher/k3s/data/cni and reconciled /host/var/lib/rancher/k3s/agent/etc/cni/net.d`

Important caveat:

- this running remote image override is **not** reflected in the committed base manifests, which still reference placeholder product images
- the remote deployment used patched local temp manifests and `kubectl set image` during testing

---

## 5.5 Deployment manifests and demo workloads

Status: **working enough to deploy and start annotated workloads**

Base manifests under `deploy/base/` include:

- namespace
- RBAC
- proxy daemon DaemonSet
- installer DaemonSet
- Caddy demo Deployment + Service
- curl client demo pod

Current base demo behavior on remote host:

- annotated Caddy pods are running
- client pod can repeatedly curl the Caddy service successfully

Important caveat:

- this does **not** yet prove interception because the real splice path is not happening yet

---

## 6. Live k3s deployment history and findings

This section records what actually happened on the host `10.229.155.1`.

## 6.1 Remote host facts

Remote system:

- host: `10.229.155.1`
- hostname: `meta-dev`
- distro: Debian 13
- sudo: passwordless sudo worked
- podman: present

k3s installation:

- installed via upstream install script on the remote host
- cluster came up successfully
- single-node cluster for testing

## 6.2 Temporary local/remote staging used during test

Local temp dirs used during deployment work:

- `/tmp/inline-proxy-remote-build`
- `/tmp/inline-proxy-k3s-test/base`

Remote temp dirs used:

- `/tmp/inline-proxy-remote-build`
- `/tmp/inline-proxy-k3s-test/base`

These were used to:

- copy built binaries from Bazel
- build temporary podman images on the remote host
- patch image references in manifests for local test tags

## 6.3 Runtime issues discovered in order

### Issue 1: kubelet could not find the plugin binary

Symptom:

- pod sandbox creation failed with plugin not found under `/var/lib/rancher/k3s/data/cni`

Resolution:

- fixed installer path logic and mount points
- added symlink-aware directory detection

### Issue 2: host-side plugin had no in-cluster env/serviceaccount context

Symptom:

- CNI failed with `KUBERNETES_SERVICE_HOST is not set`

Resolution:

- added kubeconfig-based credential loading for host-installed CNI

### Issue 3: valid apiserver responses were not parsed

Symptom:

- CNI failed with `failed to parse Kubernetes pod response`

Root cause:

- HTTP body was chunked
- client did not decode `Transfer-Encoding: chunked`

Resolution:

- implemented chunked transfer decoding

### Issue 4: kubeconfig credential form mismatch

Symptom:

- need to support embedded CA/cert/key material from k3s admin kubeconfig

Resolution:

- added support for embedded kubeconfig data and temp file materialization

### Issue 5: installer pod image drift

Symptom:

- installer pod started but failed because script path inside image was missing

Resolution:

- rebuilt and retagged remote installer image
- updated remote DaemonSet image to the fixed tag

## 6.4 Current remote cluster state at time of writing

Observed state after the fixes above:

- `inline-proxy-daemon` — Running
- `inline-proxy-installer` — Running (using remote ad-hoc fixed image)
- annotated Caddy pods — Running
- client pod — Running
- client can curl Caddy service repeatedly

Observed state files on host:

- files exist under `/var/run/inline-proxy-cni/`
- they record generated `wan_*` / `lan_*` names and preserved `prevResult`

This proves the plugin is participating in CNI ADD for annotated pods.

---

## 7. Current known issue / primary blocker

## 7.1 High-level statement

**The deployment is healthy, but traffic is not yet traversing the proxy.**

The clearest evidence is:

- proxy metrics are reachable
- repeated service traffic succeeds
- `inline_proxy_total_connections` remains `0`
- `/sessions` remains `active_sessions=0`

## 7.2 Why this is happening

The missing link is the **real interface splice in the live cluster path**.

Current implementation behavior:

- CNI plugin does workload lookup and proxy lookup
- CNI plugin persists a splice plan to disk
- CNI plugin passes back `prevResult`
- workload pods start successfully

But current implementation does not yet:

- discover the actual netns path of the workload pod and proxy pod during real kubelet execution
- enter those netns instances
- rename/move the original workload interface into the proxy netns as `wan_*`
- create the replacement veth pair and reinstall `eth0` into the workload netns

Because of that:

- there is no actual `wan_*`/`lan_*` live topology feeding the proxy daemon
- Caddy still receives traffic via the normal CNI path
- proxy sees no sessions

## 7.3 Secondary runtime caveat

The installer image currently running on the remote cluster is an ad-hoc locally built tag (`localhost/inline-proxy/installer:fix`). This is fine for testing, but subsequent sessions should not assume the checked-in manifests alone reproduce the exact remote runtime state.

---

## 8. What has been proven already

The following are already proven by live deployment, not just by local tests:

1. a k3s cluster can be installed on the remote host
2. the manifest set can be applied to k3s
3. the custom CNI plugin can be installed into the k3s runtime CNI path
4. the chained plugin is invoked for annotated pods
5. the plugin can use Kubernetes API lookups from the host-installed CNI context
6. the proxy daemon can run and expose metrics/readiness in-cluster
7. annotated Caddy pods can be created and reach Running state
8. client traffic to the service works
9. current metrics prove that traffic is **not yet** being intercepted

That last point is important: the current runtime result is a **useful negative result**. The metrics are doing their job by proving the architecture is not yet complete.

---

## 9. Recommended next steps for the next session

Priority order:

### Step 1: make the CNI plugin execute the real splice in live cluster execution

This is the main missing feature.

The next session should focus on:

- obtaining the actual workload netns path during kubelet CNI ADD
- obtaining the proxy pod netns path on the same node
- feeding those paths into `SpliceExecutor`
- validating that `ExecuteSplice(...)` actually runs on real pod creation

Questions the next session will likely need to resolve concretely:

- how to resolve workload container netns path robustly from CNI invocation/runtime artifacts
- how to resolve the proxy pod netns path from the node-local proxy pod metadata
- whether CRI/containerd inspection is needed, or whether netns paths are inferable through CNI/runtime artifacts on k3s

### Step 2: verify live interface topology after pod creation

After Step 1, verify on the host / in namespaces:

- `wan_*` exists in proxy pod netns
- `lan_*` exists in proxy pod netns
- replacement `eth0` exists in workload pod netns
- original path has actually been moved

### Step 3: verify proxy metrics increase under traffic

Repeat the test:

- curl from client pod to service several times
- read proxy metrics before/after
- expect `inline_proxy_total_connections` to increase

That is the main end-to-end PoC success criterion.

### Step 4: verify teardown / DEL behavior

After real splice works, also verify:

- pod deletion cleans up state files
- interfaces are cleaned up correctly
- repeated rollout does not leave stale `wan_*`/`lan_*` artifacts

---

## 10. Useful commands and evidence from this session

### Local verification commands used repeatedly

```bash
bazel test //tests:k8s_client_test //tests:deploy_manifest_test //tests:cni_add_del_test --test_output=errors
bazel build //src/cni:inline_proxy_cni
bazel build //src/proxy:proxy_daemon
```

### Remote cluster inspection patterns used

```bash
ssh 10.229.155.1 'sudo kubectl get pods -A -o wide'
ssh 10.229.155.1 'sudo kubectl get events -A --sort-by=.lastTimestamp | tail -n 60'
ssh 10.229.155.1 'sudo journalctl -u k3s -n 80 --no-pager'
```

### Remote CNI config inspection

```bash
ssh 10.229.155.1 'sudo sed -n "1,220p" /var/lib/rancher/k3s/agent/etc/cni/net.d/10-flannel.conflist'
```

### Remote state inspection

```bash
ssh 10.229.155.1 'sudo find /var/run/inline-proxy-cni -maxdepth 2 -type f -print'
```

### Remote proxy metrics check

Example pattern used:

```bash
PROXY_IP=$(sudo kubectl get pod -n inline-proxy-system inline-proxy-daemon-6dkrk -o jsonpath='{.status.podIP}')
curl -fsS http://$PROXY_IP:8080/metrics
curl -fsS http://$PROXY_IP:8080/sessions
```

Observed result at the time of writing:

```text
inline_proxy_ready 1
inline_proxy_active_sessions 0
inline_proxy_total_connections 0
active_sessions=0
```

---

## 11. Commits relevant to this handoff

Recent commits that matter most for the current state:

- `34734e2` — `fix: support embedded k3s kubeconfig credentials`
- `8fa9bc9` — `fix: decode chunked kube api responses`
- `e853510` — `fix: load cni kube credentials from k3s kubeconfig`
- `66c63c4` — `fix: detect symlinked k3s cni binaries`
- `d2f14ea` — `fix: install k3s cni plugin into runtime path`
- `a902b0e` — `feat: expose total proxy connection count`
- `d5d2a30` — merge of the initial PoC branch into `main`

---

## 12. Bottom line

The project is no longer blocked on basic cluster bring-up, installer placement, API connectivity, or metrics exposure.

The system now has:

- live k3s deployment
- live chained CNI participation
- live proxy pod
- live annotated workload pods
- live verification metrics

The remaining blocker is the most important architectural one:

> **the real network splice is not yet occurring in the live kubelet/CNI path, so traffic still bypasses the proxy.**

That is the next session’s core task.
