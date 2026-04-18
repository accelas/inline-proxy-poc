# Inline Transparent Proxy PoC Design

**Date:** 2026-04-18
**Status:** Approved design for implementation planning

## Goal

Build a k3s-installable proof of concept for a transparent inline proxy that protects annotated backend pods, using a chained CNI plugin and a per-node proxy DaemonSet. The PoC should demonstrate scalability-oriented architecture rather than a minimal redirect hack.

## Scope

- Target platform: k3s on Debian 13 with kernel 6.10+
- Demo backend: Caddy
- Data plane deployment: DaemonSet, one proxy pod per node
- Control point: chained CNI plugin in C++
- JSON parser requirement: yajl is mandatory for the custom CNI plugin only
- Project base: `../mango-template`
- Proxy admin HTTP endpoint may reuse code from `../http-endpoint`

## Non-goals

- Host-netns-only redirect architecture
- Sidecar-based interception
- Worker-pool or backend-compute-oriented proxy application model
- Product-level hardening beyond what is needed for a credible PoC
- UDP or IPv6 support in the first iteration

## Architecture Summary

The PoC follows the inline splice architecture from the design gist.

For each annotated backend pod on a node:

1. The chained CNI plugin runs after the primary CNI.
2. It discovers the node-local proxy DaemonSet pod.
3. It moves the original pod-side peer into the proxy netns as `wan_<id>`.
4. It creates a replacement veth pair between the proxy netns and the app pod netns.
5. The proxy owns both `wan_<id>` and `lan_<id>` and sits inline between host networking and the backend pod.

The proxy daemon accepts intercepted traffic on a transparent loopback listener, reconstructs original source/destination addresses from the accepted socket, opens a second transparent socket bound to the original source, connects to the original destination, then relays bytes bidirectionally.

## Deployment Components

### 1. `inline-proxy-cni`

A chained CNI plugin implemented in C++.

Responsibilities:
- Parse stdin JSON using yajl
- Read CNI env and Kubernetes-specific arguments
- Fetch pod metadata from the Kubernetes API
- Detect opt-in annotation
- Discover the node-local proxy pod
- Perform splice operations for annotated pods
- Persist per-pod state for reliable DEL cleanup

### 2. `inline-proxy-daemon`

A DaemonSet-hosted proxy pod.

Responsibilities:
- Own extra per-pod `wan_*` and `lan_*` interfaces
- Attach ingress eBPF programs to `wan_*`
- Run the transparent TCP listener
- Create upstream transparent sockets to the original destination
- Relay traffic using a single-threaded event loop
- Expose admin HTTP endpoints

### 3. `inline-proxy-installer`

A node-level installer/reconciler.

Responsibilities:
- Install the CNI binary on each node
- Patch the active k3s CNI conflist to include the chained plugin
- Reconcile drift if the CNI config is overwritten

### 4. Demo workload

- Caddy Deployment + Service
- Annotation-based opt-in on backend pods
- Test client workload to validate same-node and cross-node flows

## Data Plane Design

### Transparent relay model

The proxy listener:
- binds to `INADDR_LOOPBACK`
- enables `IP_TRANSPARENT`
- accepts intercepted TCP connections

After `accept()`:
- `getpeername()` recovers the original client source
- `getsockname()` recovers the original destination
- the proxy creates a second socket with `IP_TRANSPARENT`
- it `bind()`s the upstream socket to the original source
- it `connect()`s to the original destination
- it relays data with simple `read()`/`write()` loops under a single-threaded event loop

### Event model

The proxy daemon is intentionally single-threaded:
- one event loop
- one admin HTTP listener
- one transparent listener
- all relay sessions managed on that same loop
- no worker pool

This keeps the PoC focused on the topology and scalability story instead of backend task isolation.

## eBPF Strategy

The PoC assumes Debian 13 / kernel 6.10+ and is therefore eBPF-first.

Planned use:
- ingress attachment on each `wan_*`
- steer eligible TCP traffic to the transparent listener
- no initial iptables/nft TPROXY fallback path in the first implementation

The goal is to demonstrate the scalable node-local appliance model, not a lowest-common-denominator fallback.

## CNI Plugin Design

### Pod role handling

On `ADD`, the plugin branches into three cases:

1. **Proxy pod**
   - record proxy identity and node-local netns metadata
   - no splice

2. **Annotated workload pod**
   - verify local proxy availability
   - perform splice
   - persist state in `/var/run/inline-proxy-cni/`

3. **Unannotated workload pod**
   - pass through unchanged

On `DEL`, the plugin:
- loads saved state
- tears down proxy-side interfaces and related bookkeeping
- cleans up host-local records

### Multi-node behavior

The plugin always targets the proxy pod on the **same node** as the workload pod. It filters by:
- namespace
- labels
- `spec.nodeName`
- running state

This keeps the system node-local while remaining compatible with multi-node k3s clusters.

## Code Reuse Strategy

### From `../mango-template`

Use as the repository base and overall Bazel/C++ skeleton.

### From `../http-endpoint`

Reuse selectively:
- event loop / fd registration primitives
- socket helpers
- buffer and RAII utilities
- lightweight HTTP server building blocks for admin endpoints

Do **not** inherit the thread-pool/backend-compute design as a primary architecture for the proxy.

## Naming and Productization

All demo-facing names should be explicitly easy to replace with a product name later.

Use clearly rebrandable names such as:
- namespace: `inline-proxy-system`
- daemonset: `inline-proxy-daemon`
- installer: `inline-proxy-installer`
- CNI binary: `inline-proxy-cni`
- annotation: `inline-proxy.example.com/enabled: "true"`

These names should be concentrated in manifest templates and code constants rather than scattered across the codebase.

## Proposed Repo Layout

- `src/cni/` — chained CNI plugin in C++ using yajl
- `src/proxy/` — single-threaded proxy daemon
- `src/bpf/` — eBPF program(s) and loader glue
- `src/shared/` — netns, netlink, config, and utility code
- `tests/` — unit and namespace-based integration tests
- `deploy/` — k3s manifests, DaemonSets, RBAC, demo workloads
- `docs/plans/` — design and implementation plans

## Demo Validation Goals

The PoC should prove:
- only annotated Caddy pods are spliced
- client traffic to the Caddy Service is intercepted transparently
- the proxy can surface original source/destination tuples
- same-node and cross-node client-to-server traffic work in DaemonSet mode
- the admin HTTP API exposes meaningful health and session visibility

## Risks and Constraints

- kernel/eBPF behavior may require careful validation of the exact helper/attach model
- startup races between workload pods and the local proxy pod must be handled cleanly
- k3s CNI reconciliation may vary slightly by environment and must be implemented defensively
- integration with different primary CNIs is a future portability goal, but k3s defaults are the initial validation target

## Success Criteria

This PoC is successful if:
- annotated backend pods are transparently intercepted through the node-local inline proxy
- the proxy reconstructs and reports original client/source and destination tuples correctly
- cross-node k3s traffic continues to function with DaemonSet-local proxies only
- the project structure, naming, and manifests are ready to be adapted into broader or productized use later
