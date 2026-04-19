# Router-Style Inline Proxy for Annotated Pods

Date: 2026-04-19
Status: approved design for implementation planning

## Goal

Change the inline proxy PoC from a hybrid splice topology into a **router-style ingress path** for **annotated pods only**.

The primary CNI plugin remains responsible for baseline pod networking. The chained custom CNI plugin rewrites the topology only for annotated pods so that ingress traffic to the pod is routed through the node-local proxy pod. The proxy application remains transparent at the socket layer: it accepts traffic headed to the workload, recovers the original source and destination, and opens the upstream connection using `IP_TRANSPARENT` bound to the original source address.

## Scope

This design covers:

- annotated pods only
- ingress path only
- k3s as the target environment
- primary CNI remains the source of pod IP assignment and base route setup
- chained CNI performs post-setup route/topology rewrite
- proxy stays transparent and source-preserving

This design does **not** cover:

- unannotated pods
- egress interception
- broad node-wide route rewrites beyond protected pods
- abandoning pod IP ownership by the workload

## Design decisions

### 1. Pod IP ownership stays with the workload

The workload keeps the Kubernetes pod IP. The proxy does **not** take ownership of the pod IP.

Reasoning:
- this is less invasive to the primary CNI contract
- this better preserves Kubernetes semantics
- this minimizes the chance of fighting kubelet/CNI expectations
- it keeps the proxy as an inline router/appliance rather than turning it into the pod endpoint

### 2. The primary CNI owns baseline networking

The primary CNI plugin still:
- creates the baseline pod network
- assigns the pod IP
- sets up the default topology and initial routes

The chained custom CNI then modifies only annotated pods.

### 3. The custom chained CNI owns proxy insertion

For annotated pods, the chained custom CNI rewrites the post-primary topology so that:
- the node/root namespace routes that pod’s `podIP/32` toward the proxy
- the proxy has an upstream routed link and a downstream routed link
- the workload keeps its pod IP and reaches the proxy over a downstream transit subnet

### 4. Ingress only for the first router-style version

Only traffic headed **to** annotated pods is moved through the proxy path.

We do not redesign all workload egress for this iteration.

### 5. Transparent proxying remains the app-level behavior

The proxy app must continue to:
- accept traffic destined to the workload
- recover original src/dst
- create the upstream socket with `IP_TRANSPARENT`
- bind that upstream socket to the original source address

This preserves the PoC’s transparent-proxy requirement while changing the network topology around it.

## Topology

## Baseline before chained-CNI rewrite

After the primary CNI completes, the node has the normal route-based pod topology, and the workload owns its pod IP.

Conceptually:

- root namespace has a route to `podIP/32`
- workload namespace has `eth0` with the pod IP
- workload default route points at the primary CNI gateway

## Topology after chained-CNI rewrite for an annotated pod

The chained custom CNI changes the topology to:

- **root namespace ↔ proxy namespace**: routed upstream link (`wan_*` path)
- **proxy namespace ↔ workload namespace**: routed downstream link (`lan_*` path)
- root namespace route for `podIP/32` points to the proxy’s upstream transit IP
- workload keeps the pod IP on `eth0`
- workload also gets a downstream transit IP on `eth0`
- proxy routes pod-bound traffic over the downstream link

Conceptual flow:

`client/upstream -> root namespace route -> proxy wan -> proxy transparent listener -> proxy upstream transparent socket -> workload eth0`

Even though the proxy does transparent socket handling internally, the network shape is now router-style on both sides.

## Addressing model

Each protected pod gets two transit subnets.

### Upstream transit: root namespace ↔ proxy namespace

Allocate a small per-pod transit subnet, for example:
- root-side peer: `169.254.X.1/30`
- proxy `wan_*`: `169.254.X.2/30`

Purpose:
- root namespace forwards pod-bound traffic to the proxy over this routed link

### Downstream transit: proxy namespace ↔ workload namespace

Allocate a second small per-pod transit subnet, for example:
- proxy `lan_*`: `169.254.Y.1/30`
- workload `eth0` transit address: `169.254.Y.2/30`

Purpose:
- proxy reaches the workload over an explicit routed next hop

### Workload identity address

The workload keeps the Kubernetes pod IP on `eth0`.

Recommended representation:
- normalize pod IP to a `/32` on `eth0`
- keep the transit subnet on the same interface for next-hop routing

Reasoning:
- preserves pod identity
- avoids making the proxy own the pod IP
- makes routes explicit and easier to debug

## Namespace responsibilities

### Root namespace

For each annotated pod, the chained CNI must:

1. create a routed veth pair between root ns and proxy ns
2. assign the root-side upstream transit address
3. install or replace the route for `podIP/32` so it points to the proxy upstream IP

Desired route shape:
- `podIP/32 via <proxy_wan_ip> dev <root_wan_peer>`

The root namespace becomes the upstream router that forwards pod-bound traffic toward the proxy.

### Proxy namespace

The proxy namespace must contain:

- the proxy-side upstream interface (`wan_*`)
- the proxy-side downstream interface (`lan_*`)
- route to the workload pod IP via the workload-side downstream transit peer
- local transparent listener routing setup
- forwarding enabled
- ingress interception on the upstream-facing interface

Responsibilities:
- accept ingress traffic from the upstream routed link
- steer eligible traffic to the transparent listener
- create transparent upstream connection to the workload
- maintain session metrics and readiness endpoints

### Workload namespace

The workload namespace must contain:

- `eth0` carrying the pod IP as `/32`
- a downstream transit address on `eth0`
- route(s) that let the workload return traffic via the proxy where needed for ingress symmetry

The workload remains the owner of the pod IP, but the proxy is now its ingress router.

## CNI behavior

## Add behavior for annotated pods

For annotated pods, the chained CNI should do the following after reading `prevResult`:

1. Parse and persist baseline networking facts:
   - pod IP
   - original routes
   - workload netns path
   - any root-namespace route/interface information needed for rewrite

2. Resolve the node-local proxy pod and proxy namespace.

3. Build an upstream routed link:
   - create veth pair between root ns and proxy ns
   - assign upstream transit IPs
   - bring links up

4. Build a downstream routed link:
   - create veth pair between proxy ns and workload ns
   - move workload-side peer into workload ns
   - rename workload-side peer to `eth0` only if replacing the existing interface is required by implementation strategy; otherwise attach transit config to the existing workload-facing path deliberately and consistently
   - assign downstream transit IPs

5. Reconfigure the workload interface state:
   - preserve pod IP on workload side
   - normalize pod IP to `/32` if needed
   - install route/default-next-hop behavior toward proxy for ingress-path correctness

6. Rewrite root namespace routing:
   - replace route for `podIP/32` so it goes via proxy upstream IP

7. Configure proxy namespace routing:
   - route pod IP to workload-side transit peer
   - enable forwarding
   - install any local interception/policy routing required by the transparent listener

8. Persist enough state for DEL cleanup and reconciliation.

## Add behavior for unannotated pods

Unannotated pods remain unchanged. The chained CNI passes through `prevResult` and does not rewrite topology.

## Add behavior for proxy pods

Proxy pods are not rewritten as protected workloads. The chained CNI may still record proxy identity metadata needed for workload-to-proxy matching.

## Del behavior

For protected pods, DEL must clean up:

- root namespace upstream veth peer
- proxy-side upstream interface
- proxy-side downstream interface
- workload-side downstream peer if separate from the preserved workload interface
- root namespace `podIP/32` route rewrite
- proxy namespace routes/rules
- any persisted state files

DEL should be idempotent and best-effort on partially-torn-down namespaces.

## Proxy behavior

The proxy remains a transparent application, not a NAT gateway.

It should continue to:

- expose readiness/health/metrics
- count total accepted/intercepted connections
- recover original source and destination from accepted traffic
- create the upstream connection with `IP_TRANSPARENT`
- bind to the original source address
- connect to the workload pod IP/destination

This means the network design changes, but the application-level transparent relay model stays intact.

## Interception model

Ingress interception should occur on the proxy’s upstream-facing interface.

The current branch already moved toward tc/eBPF-based socket assignment. That can remain the interception mechanism as long as it is adapted to the new routed `wan_*` path.

The implementation should not assume the old moved-workload-interface model. It should assume that `wan_*` is now the proxy-side interface of an explicit routed upstream link.

## Error handling and rollback

If any step in the chained-CNI rewrite fails for an annotated pod:

- do not leave partial route rewrites behind
- remove created veth pairs when possible
- restore the root namespace route for the pod if it was changed
- restore workload namespace routes if they were changed
- fail the CNI ADD clearly enough for diagnosis

State persistence should happen only after the topology rewrite is sufficiently complete to be meaningfully recoverable.

## Testing strategy

Implementation must be driven by tests.

### Unit/integration test focus

1. **Route rewrite logic**
   - verify root namespace route for annotated pod changes to proxy next hop
   - verify unannotated pods are untouched

2. **Proxy/workload transit configuration**
   - verify downstream transit IPs and routes are installed as expected

3. **Proxy namespace routing**
   - verify pod IP route points toward workload transit peer
   - verify forwarding/interception prerequisites are configured

4. **DEL cleanup**
   - verify route and interface cleanup for annotated pods
   - verify repeated DEL remains safe

5. **Namespace resolution**
   - keep netns resolution tests for workload/proxy discovery

6. **End-to-end routed namespace harness**
   - add/update a netns harness that proves:
     - root namespace routes pod traffic to proxy
     - proxy accepts/intercepts the traffic
     - workload receives traffic with expected transparency behavior

### Runtime validation target

Success for the k3s PoC is:

- annotated pod traffic increments proxy metrics
- unannotated pods bypass the proxy
- the pod remains reachable through Kubernetes Service routing
- proxy sessions/metrics prove actual traversal

## Files expected to change during implementation

Likely implementation surface:

- `src/cni/splice_executor.cpp`
- `src/cni/splice_executor.hpp`
- `src/cni/netns_resolver.cpp`
- `src/cni/netns_resolver.hpp`
- `src/shared/netlink.cpp`
- `src/shared/netlink.hpp`
- `src/shared/netns.cpp`
- `src/shared/netns.hpp`
- `src/proxy/interface_registry.cpp`
- `src/proxy/interface_registry.hpp`
- `src/proxy/config.cpp`
- `src/proxy/relay_session.cpp`
- `tests/cni_add_del_test.cpp`
- `tests/netns_fixture.cpp`
- `tests/netns_fixture.hpp`
- `tests/ebpf_intercept_fd_netns_test.cpp`
- additional routed-topology tests as needed

## What changes from the current branch

The most important design change is:

- **old branch direction:** preserve the original upstream workload attachment by moving workload `eth0` into proxy netns as `wan_*`, then route only the downstream side
- **new approved direction:** let the primary CNI keep the baseline pod networking, and have the chained CNI insert the proxy as a router by creating explicit upstream and downstream routed links and rewriting the root namespace route for annotated pods

This is a deliberate architectural shift toward a true router-style appliance model.

## Success criteria

This design is successful if, for annotated pods only:

- the workload keeps its Kubernetes pod IP
- the node/root namespace forwards pod-bound ingress traffic to the proxy
- the proxy routes/intercepts on explicit routed links
- the proxy app still preserves original source/destination semantics
- metrics prove real traffic traversal
- unannotated pods remain on the baseline primary-CNI path unchanged
