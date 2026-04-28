# Inline Proxy PoC — Architecture and Traffic Paths

This doc describes the network topology the inline proxy creates for
annotated pods on k3s, what the custom CNI plugin does during pod
setup, how an inbound request flows through the proxy, and which
traffic paths actually work end-to-end.

The implementation is the **routed-ingress** topology: the pod keeps
its primary-CNI `eth0` and the cluster pod IP, and the node routes the
pod's traffic *through* the proxy rather than moving `eth0` anywhere.
Source: `src/cni/splice_executor.cpp`, `src/proxy/*`.

An older **splice topology** (rename `eth0` → `wan_*` and move it into
the proxy netns) is archived in git history. It relied on transparent
original-client-source backend binds, which flannel/kube-router reject
for pod-to-pod traffic on k3s. It never worked reliably and has been
replaced.

## 1. Baseline (before the custom CNI runs)

k3s ships with flannel as the primary CNI and a Linux bridge `cni0` on
the node's host netns. Every pod the primary CNI creates gets one veth
pair — one end on the bridge, the other end in the pod netns named
`eth0`:

```
host netns                               pod netns
┌────────────────────┐                   ┌────────────────────────┐
│ cni0 bridge        │                   │ eth0                   │
│  10.42.0.1/24      │◄──── veth ───────►│  10.42.0.X/24          │
│                    │                   │  default via 10.42.0.1 │
└────────────────────┘                   └────────────────────────┘
```

All pods (proxy pod, caddy pods, coredns, etc.) look like this at the
end of the primary-CNI step.

## 2. What the chained `inline-proxy-cni` plugin does

Entry: `src/cni/main.cpp` → `SpliceExecutor::HandleAdd` in
`src/cni/splice_executor.cpp`. The plugin runs **after** flannel.

### 2.1 Passes through unless the pod is annotated

If the pod is the proxy pod itself, or if the annotation
`inline-proxy.example.com/enabled=true` is not set, the plugin emits
the primary CNI's prevResult unchanged. Those pods retain the plain
bridge topology above and behave identically to any other k3s pod.

### 2.2 Creates a routed upstream link

For annotated pods the plugin creates a veth pair in the **root**
namespace:

- `rwan_<hash>` stays in the root namespace with a link-local /30
  address (`169.254.X.1/30`).
- `wan_<hash>` is moved into the **proxy** namespace and given the
  matching `169.254.X.2/30`.

It then rewrites the root namespace's route to the pod:

```
host netns (routes):
  10.42.0.Y/32 via 169.254.X.2 dev rwan_<hash>
```

Inbound traffic addressed to the pod now goes out `rwan_<hash>` and
lands on `wan_<hash>` in the proxy namespace — this is the
interception point.

### 2.3 Creates a routed downstream link

Inside the proxy namespace the plugin creates a second veth pair:

- `lan_<hash>` stays in the proxy namespace with `169.254.X.5/30`.
- `peer_<hash>` is moved into the **workload** namespace with
  `169.254.X.6/30`.

### 2.4 Rewrites the workload namespace

The workload's primary-CNI `eth0` stays put (it is never renamed or
moved). The plugin:

1. Flushes flannel's `/24` address from `eth0`.
2. Re-adds the pod's address as a `/32` on `eth0`, so the pod's IP
   identity is preserved but it no longer claims the `/24`.
3. Routes the pod's default path through the proxy:
   `default via 169.254.X.5 dev peer_<hash>`.

From the cluster's perspective the workload still answers at its pod
IP, but every packet it sends or receives now traverses the proxy.

### 2.5 Installs per-pod source routing in the proxy

Inside the proxy namespace the plugin installs a per-pod routing
table:

```
rule:  from 10.42.0.Y/32 lookup <table>
table: default via 169.254.X.1 dev wan_<hash>
       10.42.0.Y/32 dev lan_<hash>
```

This makes workload egress — packets the proxy forwards on behalf of
the pod — leave through `wan_<hash>` back toward the node, exactly
mirroring the ingress path. Return packets to the pod IP end up back
on `lan_<hash>` and into the workload namespace.

### 2.6 Loads and pins the BPF program (proxy DS pod CNI), attaches it (service pod CNI)

The BPF program is loaded and pinned by the CNI plugin during the
proxy DS pod's CNI ADD. Pins live at
`/sys/fs/bpf/inline-proxy/{prog,config_map,listener_map}`.

When the proxy daemon container subsequently boots inside that pod,
it opens the already-pinned `config_map` and `listener_map` and
writes `config_map[0]` (port, mark) and `listener_map[0]` (its
listener fd). The proxy daemon never loads the skeleton, never pins,
and never runs TC netlink calls.

When a service pod is admitted, the same CNI plugin (running for that
pod's ADD) creates the `wan_<hash>` interface, moves it into the
proxy netns, and inside that netns attaches the pinned program as a
TC ingress filter. The pin is guaranteed to exist because kubelet
admits the proxy DS pod first (system-node-critical priority) and
serialises CNI invocations per node, so the proxy DS pod's CNI ADD
always completes before any service pod's CNI ADD begins.

The BPF program redirects matching TCP flows to the listener via
`bpf_sk_assign`, preserving the original dst via SO_ORIGINAL_DST.

## 3. Topology after the routed splice

```
        ingress from the cluster
                 │
                 ▼
         ┌───────────────┐
         │ cni0 bridge   │   (root netns)
         │ 10.42.0.1/24  │
         └───────┬───────┘
                 │
         root-ns route:
         10.42.0.Y/32 via 169.254.X.2 dev rwan_<hash>
                 │
                 ▼
         ┌───────────────┐
         │ rwan_<hash>   │   169.254.X.1/30  (root netns)
         └───────┬───────┘
                 │        (veth pair)
         ┌───────▼───────────┐
         │ wan_<hash>        │   169.254.X.2/30  (PROXY netns)
         │  TC-ingress BPF   │
         │  → bpf_sk_assign  │
         │     to listener   │
         └───────┬───────────┘
                 │         (IP_TRANSPARENT listener)
                 ▼
         ┌───────────────────┐
         │ proxy userspace   │   127.0.0.1:15001
         │ connects upstream │
         └───────┬───────────┘
                 │   (egress via per-pod src rule:
                 │    from 10.42.0.Y lookup <tbl>
                 │    table: Y/32 dev lan_<hash>)
                 ▼
         ┌───────────────────┐
         │ lan_<hash>        │   169.254.X.5/30  (proxy netns)
         └───────┬───────────┘
                 │         (veth pair)
         ┌───────▼───────────┐
         │ peer_<hash>       │   169.254.X.6/30  (workload netns)
         └───────┬───────────┘
                 │
         workload-ns route:
         default via 169.254.X.5 dev peer_<hash>
                 │
                 ▼
         ┌───────────────────┐
         │ eth0 (unchanged)  │   10.42.0.Y/32   (workload netns)
         │ the workload      │
         └───────────────────┘
```

Key facts:

- **Pod IP is preserved.** From the rest of the cluster's perspective
  the workload's address doesn't change — it's still `10.42.0.Y`.
- **`eth0` is never renamed or moved.** The primary CNI keeps full
  ownership of the pod's layer-2 identity; the plugin only rewrites
  addresses and routes.
- All rewritten links use `169.254.X.0/30`s carved out of the RFC
  5735 link-local block, invisible to the rest of the cluster.
- Only **annotated** pods go through this path. Unannotated pods
  retain the plain `cni0` bridge topology and are unaffected.

## 4. Inbound traffic path

1. Cluster sends a SYN to `10.42.0.Y:80`.
2. Node forwards via `cni0` per the root-ns route and lands on
   `rwan_<hash>` → `wan_<hash>` in the proxy netns.
3. TC-ingress BPF on `wan_<hash>` calls `bpf_sk_assign` to direct the
   flow to the proxy's transparent listener at `127.0.0.1:15001`.
4. Proxy `accept()` yields a socket with the original src
   (`10.42.0.X`) and original dst (`10.42.0.Y:80`, recovered via
   `SO_ORIGINAL_DST`).
5. Proxy opens an upstream TCP socket bound to `INADDR_ANY:0`
   (`INLINE_PROXY_USE_PROXY_SOURCE=1`, the default in the deploy
   manifest) and `connect()`s to `10.42.0.Y:80`.
6. The upstream SYN egresses the proxy netns. The per-pod source rule
   doesn't fire here (source is the proxy's IP, not the pod's), so
   it follows the default route out `wan_<hash>` and eventually back
   to the pod.
7. The return path bounces back through `lan_<hash>` →
   `peer_<hash>` → workload `eth0`.

## 5. Workload egress path

1. Workload sends a packet with source `10.42.0.Y`.
2. Workload's default route sends it out `peer_<hash>` toward
   `169.254.X.5` (`lan_<hash>` in proxy netns).
3. The proxy netns's per-pod source rule
   `from 10.42.0.Y/32 lookup <table>` steers the packet into the
   per-pod table, which routes `default via 169.254.X.1 dev
   wan_<hash>` — i.e. back to root via the upstream link.
4. If the flow's destination matches the intercept port (80 by
   default), TC-ingress BPF on `wan_<hash>` captures it when it
   *arrives* from root, handing it to the proxy just like an inbound
   flow would.

## 6. Traffic paths that work vs. paths that intentionally don't

Works end-to-end:

- Pod → pod (both on the same node) — the client pod's packet to
  `10.42.0.Y` follows the root-ns route to the proxy, gets intercepted,
  and reaches the annotated backend.
- External client → Service → annotated pod — the kube-proxy DNAT and
  downstream route all converge on the same node path; the proxy
  intercepts on `wan_*`.

Does not work (by construction):

- Traffic whose source is the host's bridge gateway IP `10.42.0.1`.
  The proxy can't safely source packets from that address without
  breaking ARP resolution for every pod on the node; the TC-ingress
  intercept still fires but the return path can't complete.

## 7. The `/32` transparent-source fallback still in-tree

`src/proxy/local_source.{hpp,cpp}` holds an off-by-default code path
for the original transparent-source pattern: the proxy briefly adds
the client IP as a `/32` to `wan_*` interfaces before the upstream
connect, so the kernel accepts a `bind()` to that foreign IP and
delivers return packets back to the proxy.

- On the routed deployment this machinery is completely bypassed.
  `deploy/base/proxy-daemonset.yaml` sets
  `INLINE_PROXY_SKIP_LOCAL_SOURCE=1`, which makes
  `AcquireLocalSourceAddress` a no-op, and
  `INLINE_PROXY_USE_PROXY_SOURCE=1`, which makes the upstream bind
  target `INADDR_ANY` rather than the original client address.
- It is kept in-tree because it's the only way to run the proxy in
  true transparent-source mode on a kernel that allows source
  spoofing across the cluster network. The file-level comment in
  `local_source.hpp` spells out that the whole module can be deleted
  once that mode stops being a supported configuration.

## 8. Interface contract with the daemon

The proxy daemon does not load BPF, pin maps, or watch interfaces.
At startup it:

1. Binds and listens on the transparent listener.
2. Opens the existing pinned `config_map` and `listener_map` at
   `/sys/fs/bpf/inline-proxy/` (created by its own pod's CNI ADD).
3. Writes `config_map[0] = {enabled, listener_port, skb_mark}`.
4. Writes `listener_map[0] = listener_fd`.
5. Marks `/readyz` green.

The CNI plugin owns the BPF lifecycle:

- **Proxy DS pod ADD:** loads the embedded BPF skeleton and pins
  prog/config_map/listener_map. On a binary upgrade (tag mismatch)
  the existing pins are replaced; on a same-binary restart the
  existing pins are reused so already-attached TC filters keep
  reading from the same kernel maps the new proxy daemon will write
  to.
- **Service pod ADD:** opens the prog pin (guaranteed to exist),
  creates `wan_<hash>`, moves it into the proxy netns, and runs
  `tc filter add ingress` referencing the prog.
- **CNI DEL:** no-op for BPF — removing `wan_<hash>` drops its
  qdisc and filter automatically.

If the proxy daemon container restarts inside an existing pod (no
new CNI ADD), the pinned maps persist; the new container opens them
and overwrites `listener_map[0]` with its new listener fd. Already-
attached TC filters continue reading from the same maps, so existing
pods see no interception gap.

The pin path `/sys/fs/bpf/inline-proxy/` is on host bpffs (mounted
into the proxy pod via hostPath with bidirectional propagation). CNI
runs on the host directly and reaches the same bpffs natively.
