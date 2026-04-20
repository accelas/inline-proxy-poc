# Inline Proxy PoC — Architecture and Traffic Paths

This doc describes the network topology the inline proxy creates for
annotated pods on k3s, what the custom CNI plugin does during pod setup,
how an inbound request flows through the proxy, and which traffic paths
actually work end-to-end.

## 1. Baseline topology (before the custom CNI runs)

k3s ships with flannel as the primary CNI and a Linux bridge `cni0` on
the node's host netns. Every pod the primary CNI creates gets one veth
pair — one end on the bridge, the other end in the pod netns named
`eth0`:

```
host netns                               pod netns
┌────────────────────┐                   ┌───────────────────────┐
│ cni0 bridge        │                   │ eth0                  │
│  10.42.0.1/24      │◄──── veth ───────►│  10.42.0.X/24         │
│                    │                   │  default via 10.42.0.1│
└────────────────────┘                   └───────────────────────┘
```

All pods (proxy pod, caddy pods, coredns, whatever) look like this at
the end of the primary-CNI step.

## 2. What the chained `inline-proxy-cni` plugin does

Source: `src/cni/main.cpp` → `SpliceExecutor::HandleAdd` in
`src/cni/splice_executor.cpp`. The plugin runs **after** flannel, so
the veth above already exists.

For every new pod sandbox the plugin:

### 2.1 Passes through unless the pod is annotated

`splice_executor.cpp:398-406`. If the pod is the proxy pod itself, or if
the annotation `inline-proxy.example.com/enabled=true` is not set, the
plugin emits the primary CNI's prevResult unchanged.

### 2.2 Resolves the node-local proxy pod

`src/cni/k8s_client.cpp::FindNodeLocalProxyPod` picks the
`inline-proxy-daemon` pod on the same node as the workload. Its netns
path is resolved via CRI / `/var/run/netns/`.

### 2.3 Performs a "splice" of the workload's eth0 into the proxy netns

`SpliceExecutor::ExecuteSplice` runs five staged steps, each with
rollback. At each stage it enters the appropriate netns via
`ScopedNetns::Enter`.

1. **In the workload netns:** rename `eth0 → wan_<hash>`, move
   `wan_<hash>` **into the proxy pod's netns**. The host-side peer (still
   plugged into `cni0`) is untouched — from the bridge's perspective,
   packets destined for the workload IP still land on the same bridge
   port.
2. **In the proxy netns:** bring `wan_<hash>` up, enable `proxy_arp`,
   create a fresh veth pair `lan_<hash>` / `peer_<hash>`, flush addresses
   off `wan_<hash>` (the workload's original pod IP is no longer assigned
   to this interface), move `peer_<hash>` into the workload netns.
3. **In the workload netns:** rename `peer_<hash> → eth0` (new eth0),
   re-assign the original pod IP as `/32`, add a link-local `/30` for the
   proxy link, set default route via the proxy's link-local IP.
4. **In the proxy netns:** assign the other `/30` half to `lan_<hash>`,
   enable `ip_forward=1`, add a `10.42.0.X/32 via <workload-LL> dev lan_`
   route so the proxy can reach the real pod IP out `lan_`, install
   per-pod policy-routing rules `from <pod_ip> lookup <route_table>`,
   and populate `<route_table>` with `default via 10.42.0.1 dev wan_`.
5. **Persist state** to `/var/run/inline-proxy-cni/container-<id>.json`
   so `HandleDel` on pod teardown can reverse everything.

### 2.4 Resulting topology for annotated workloads

```
                           host netns
          ┌──────────────────────────────────────────────┐
          │          cni0 bridge (10.42.0.1/24)          │
          └──▲──────────────────────▲──────────────▲─────┘
             │(unchanged by splice) │              │
        host-side veth of           │host-side     │other pods
        workload's ORIGINAL eth0    │veth to proxy │
             │                      │pod eth0      │
             ▼                      ▼              ▼
   ╔══════════════════════════╗   ┌──────────────────┐
   ║       proxy netns        ║   │ proxy pod's own  │
   ║ ┌──────────────────────┐ ║   │   eth0 (pod IP)  │
   ║ │ wan_<hash>           │ ║   └──────────────────┘
   ║ │  (addressless, BPF   │ ║
   ║ │   tc-ingress attached│ ║
   ║ │   proxy_arp=1)       │ ║
   ║ └────────┬─────────────┘ ║     workload netns
   ║          │ ip_forward    ║   ┌────────────────────────────┐
   ║          ▼               ║   │ NEW eth0 = peer_<hash>     │
   ║ ┌──────────────────────┐ ║   │  pod IP /32 + link-local/30│
   ║ │ lan_<hash>           │◄╬───│  default via proxy-side-LL │
   ║ │  (link-local /30)    │ ║   └────────────────────────────┘
   ║ └──────────────────────┘ ║
   ║                          ║
   ║ ip rule from <pod_ip>    ║
   ║  lookup <route_table>    ║
   ║ <route_table>:           ║
   ║  default via 10.42.0.1   ║
   ║         dev wan_<hash>   ║
   ║                          ║
   ║ ip rule fwmark 0x100     ║
   ║  lookup 100              ║
   ║ table 100:               ║
   ║  local 0/0 dev lo        ║
   ║                          ║
   ║ transparent listener:    ║
   ║  0.0.0.0:15001           ║
   ║   (IP_TRANSPARENT)       ║
   ╚══════════════════════════╝
```

Key topological facts:

- **The pod IP stays the same.** From the rest of the cluster's
  perspective the workload's address doesn't change.
- Any packet destined for the workload pod reaches `cni0`, gets
  forwarded to the **original** host-side veth, and now lands on
  `wan_<hash>` **in the proxy netns** — not in the workload pod. This is
  the interception point.
- Proxy ↔ workload uses a fresh private `/30` link (`lan_<hash>` ↔
  workload's new `eth0`) that's invisible to the rest of the cluster.
- Per-pod policy-routing tables give return packets a deterministic
  path back out `wan_` so they reach the real client.

### 2.5 Installer DaemonSet

Separately, `deploy/base/proxy-installer-daemonset.yaml` runs a
privileged pod on each node that:

1. Copies `inline_proxy_cni` into the node's CNI bin directory
   (`/var/lib/rancher/k3s/data/cni/` for k3s).
2. Rewrites the active CNI conflist to add
   `{"type": "inline-proxy-cni", ...}` chained after flannel.
3. Loops every 5 minutes to resist drift.

## 3. Runtime flow of an inbound connection

Example: `coredns (10.42.0.6)` → `caddy (10.42.0.151):80`.

1. **Client kernel** sends TCP SYN `10.42.0.6 → 10.42.0.151:80`. The
   client's default route sends it to `cni0` via its own host-side veth.
2. `cni0` forwards to the **original** host-side veth for caddy's pod IP.
   That veth's pod-side is now `wan_<hash>` in the proxy netns.
3. **TC ingress BPF** on `wan_<hash>` fires
   (`src/bpf/ingress_redirect.bpf.c`):
   - checks IPv4 + TCP + `dst_port == cfg->listener_port` (80),
   - tries `bpf_skc_lookup_tcp` for the 4-tuple (miss for SYN),
   - falls back to `bpf_map_lookup_elem(&listener_map, &0)` → the proxy
     daemon's transparent listener fd,
   - `bpf_sk_assign(skb, listener, 0)` hands the SYN to the listener,
   - sets `skb->mark = cfg->skb_mark` (`0x100`) so the
     `fwmark 0x100 → table 100 (local 0/0 dev lo)` rule delivers locally.
4. The **proxy's transparent listener** (`src/proxy/transparent_listener.cpp`,
   `0.0.0.0:15001`, `IP_TRANSPARENT`) `accept()`s.
   `getsockname()` on the accepted fd returns the *original* dst
   `10.42.0.151:80` — that's the `IP_TRANSPARENT` magic.
5. **`CreateRelaySession`** (`src/proxy/relay_session.cpp:234`):
   - `AcquireLocalSourceAddress(10.42.0.6)` adds the client IP as `/32`
     to every `wan_*` in the netns so the kernel will recognize return
     packets as locally deliverable. Skipped for already-local /
     gateway IPs (see §4).
   - Creates an upstream socket with `IP_TRANSPARENT` + `IP_FREEBIND`,
     `bind()`s to the client's address, `connect()`s to the original
     dst. Routed out `lan_<hash>` via the splice's `/32` route.
6. **Caddy** receives the SYN as if it came straight from
   `10.42.0.6`, responds normally. The reply is
   `src=10.42.0.151, dst=10.42.0.6`; caddy's default route sends it back
   out its (new) `eth0` → `lan_<hash>` in the proxy netns.
7. In the proxy netns the reply matches
   `from 10.42.0.151 lookup <route_table>`; the table has
   `default via 10.42.0.1 dev wan_<hash>`, so it would otherwise egress
   `wan_`. But the kernel first does a TCP socket lookup, finds the
   relay's upstream socket (bound to `10.42.0.6`), and delivers the
   packet locally. Bytes flow.
8. The proxy relays bytes client-side ↔ upstream-side.
   `inline_proxy_total_connections` increments on every `accept()`.

## 4. Traffic paths: what works end-to-end

Whether a given path works depends on **what source IP the proxy
actually sees** when `getpeername()` runs on the accepted fd. The BPF
intercept fires for every path that reaches `wan_<hash>` on the
configured port — so `inline_proxy_total_connections` increments in
all the cases below. The question is whether the relay's upstream
return path completes.

`LocalSourceManager::Acquire` skips adding the client IP as `/32` if
that IP is already locally assigned in the proxy netns or is a
next-hop gateway in any route. This was the fix for issue #2: assigning
the cni0 bridge IP (`10.42.0.1`) to a `wan_` interface poisons ARP for
the entire netns (the kernel suppresses replies whose sender IP is one
of its own addresses), breaking kubelet probes and cluster
connectivity.

### Paths that work end-to-end

| Path | Source IP the proxy sees | Why it works |
|---|---|---|
| Pod-to-pod on the same node (e.g., `coredns` → `caddy`) | the client pod's IP (e.g., `10.42.0.6`) | Pod IP is not in the proxy netns (`cni0` lives in host netns; individual pod IPs are not locally assigned inside the proxy netns). LocalSourceManager adds `/32` on `wan_*` → return path delivered locally. |
| Pod-to-pod across nodes | remote pod IP | Same reasoning; flannel VXLAN-encapsulates, the decapsulated inner packet has the source pod IP. |
| `NodePort` with `externalTrafficPolicy: Local` | real external IP | Node preserves source, `/32` assignment safe. |
| External LB with source preservation (L2/BGP, PROXY protocol terminated before the proxy) | real external IP | Same as above. |
| Direct routed access to pod IPs from outside the cluster (e.g., Calico BGP, or a custom route to flannel subnet) | external IP | Same as above. |

### Paths where the BPF counter increments but the response does not complete

| Path | Source IP the proxy sees | Why it fails |
|---|---|---|
| Host-originated (`curl http://<podIP>` on the node itself) | `10.42.0.1` (cni0 gateway) | `10.42.0.1` is a next-hop gateway in the proxy netns → LocalSourceManager skips the `/32` (would break ARP). No recognition path for return packets → relay session times out. |
| `NodePort` / `LoadBalancer` with default `externalTrafficPolicy: Cluster` | `10.42.0.1` after k8s SNATs source to the node | Same reason. |
| kubelet/probe traffic from the node | `10.42.0.1` | Same reason. |

For these paths the design needs a different return-path mechanism
(e.g., TC egress BPF on `lan_*` marking return packets so the
`fwmark 0x100 → table 100 (local 0/0 dev lo)` rule catches them without
`/32` assignment). That's a separate design change, not a bug; tracked
only as "future work" until a concrete need arises.

### Paths the splice design rejects

- Traffic to pods **not** annotated with
  `inline-proxy.example.com/enabled=true`: the chained CNI passes through
  without splicing. The workload's original veth ↔ eth0 stays intact;
  traffic flows the normal flannel way.
- Traffic to the proxy pod's own IP: never spliced; cni0 forwards
  normally to the proxy pod's own `eth0`.

## 5. Verifying on k3s

```bash
# Verify pod-to-pod works end-to-end:
PROXY=$(kubectl get pod -n inline-proxy-system -l app=inline-proxy -o jsonpath='{.items[0].metadata.name}')
PROXY_IP=$(kubectl get pod -n inline-proxy-system "$PROXY" -o jsonpath='{.status.podIP}')
CADDY_IP=$(kubectl get pod -n default -l app=inline-proxy-caddy-demo -o jsonpath='{.items[0].status.podIP}')
COREDNS=$(kubectl get pod -n kube-system -l k8s-app=kube-dns -o jsonpath='{.items[0].metadata.name}')
COREDNS_NETNS=$(sudo crictl inspectp $(sudo crictl pods --name "$COREDNS" -q) | jq -r '.info.runtimeSpec.linux.namespaces[]|select(.type=="network").path')

# counter before
curl -fsS http://$PROXY_IP:8080/metrics | grep ^inline_proxy_total

# drive traffic from a real cluster pod
sudo nsenter --net=$COREDNS_NETNS bash -c "
  exec 3<>/dev/tcp/$CADDY_IP/80
  printf 'GET / HTTP/1.0\r\nHost: caddy\r\n\r\n' >&3
  head -c 80 <&3
  exec 3<&-
"

# counter after (should be +1)
curl -fsS http://$PROXY_IP:8080/metrics | grep ^inline_proxy_total

# proxy log confirms the relay
kubectl logs -n inline-proxy-system "$PROXY" --tail=3 | grep 'accepted transparent'
```

Expected: `inline_proxy_total_connections` goes 0 → 1 and the proxy log
shows `accepted transparent connection client=<coredns_IP>:N
original_dst=<caddy_IP>:80`.

## 6. Related docs

- `docs/plans/2026-04-18-inline-proxy-poc-design.md` — original PoC design
  rationale.
- `docs/plans/2026-04-19-inline-proxy-k3s-status.md` — live-deployment
  status doc from before the skeleton-loader rewrite (historical).
- `docs/superpowers/specs/2026-04-19-router-style-inline-proxy-design.md` —
  approved redesign toward a router-style topology that replaces the
  splice; not yet implemented.
- `docs/superpowers/specs/2026-04-19-bpf-skeleton-loader-design.md` — the
  BPF-loader rewrite spec this branch implements.
