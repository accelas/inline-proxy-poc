# inline_proxy_poc

Inline transparent proxy proof of concept for k3s.

## Layout

- `src/shared/` — common support code shared by all components
- `src/proxy/` — proxy daemon package
- `src/cni/` — chained CNI plugin package
- `src/bpf/` — eBPF loader package
- `deploy/` — deployment notes and manifests

Productizable names are deliberately isolated around the `inline-proxy-*` prefix and
the annotation key `inline-proxy.example.com/enabled`. Those values are intended to
be replaced by a future product name without changing the surrounding architecture.

## Architecture

See [`docs/architecture.md`](docs/architecture.md) for the full topology, a
walk-through of what the chained CNI plugin does during pod setup, the
runtime flow of an inbound connection, and which traffic paths work
end-to-end vs. which hit the BPF intercept but intentionally can't
complete the return path (e.g., host-originated traffic sourced from the
`cni0` gateway IP).

## Build

```bash
bazel build //...
```

## Test

```bash
bazel test //...
```

## Demo targets

- `//src/proxy:proxy_daemon` — node-local transparent relay daemon
- `//src/cni:inline_proxy_cni` — chained CNI plugin
- `//src/bpf:loader` — eBPF loader userspace support

## k3s deployment

Deployment manifests and installer scripts live under `deploy/base/` and
`deploy/scripts/`.

The demo workload uses:

- `inline-proxy-daemon` DaemonSet
- `inline-proxy-installer` DaemonSet
- annotated `inline-proxy-caddy-demo` backend pods
- `inline-proxy-client-demo` traffic generator

See `deploy/README.md` for install and validation commands.

## Onboarding

End-to-end walkthrough: clone → local tests → deploy to k3s → verify pod-to-pod interception. Assumes one build host (local) and one k3s node (remote, reachable as `$K3S_HOST` over SSH). A single-box setup works too — just use `localhost` and skip the `scp` steps.

### 1. Host prerequisites

Build host:
- Linux, kernel ≥ 5.15 (needs `BPF_MAP_TYPE_SOCKMAP` and `bpf_sk_assign`)
- `bazel` 7+ (bzlmod)
- `clang-19` at `/usr/bin/clang-19` (for CO-RE BPF compile)
- `bpftool` (skeleton generation; discovered via `which bpftool`)
- `gcc-14`
- `libelf-dev`, `pkg-config`
- `podman` (or `docker`)

k3s node:
- k3s installed with `flannel` CNI
- SSH access with `sudo` + `kubectl` + `k3s ctr`
- Matching kernel capabilities (same floor as the build host)

### 2. Clone and run local tests

```bash
git clone https://github.com/accelas/inline-proxy-poc
cd inline-proxy-poc
bazel test //... --test_output=errors
```

Expected: all tests pass except `k8s_client_test` (pre-existing TLS mock issue, tracked separately).

### 3. Build release binaries

```bash
bazel build -c opt \
    //src/proxy:proxy_daemon \
    //src/cni:inline_proxy_cni
```

Outputs:
- `bazel-bin/src/proxy/proxy_daemon`
- `bazel-bin/src/cni/inline_proxy_cni`

### 4. Build container images on the k3s node

Pick a fresh tag to avoid the containerd image-cache confusing identical tags (e.g., `v1`, `v2`, …). This walkthrough uses `v1`.

```bash
TAG=v1
K3S_HOST=meta-dev   # your k3s node

# Stage files on the node
ssh $K3S_HOST 'mkdir -p /tmp/inline-proxy-build'
scp bazel-bin/src/proxy/proxy_daemon                $K3S_HOST:/tmp/inline-proxy-build/
scp bazel-bin/src/cni/inline_proxy_cni              $K3S_HOST:/tmp/inline-proxy-build/
scp deploy/scripts/install-cni.sh                   $K3S_HOST:/tmp/inline-proxy-build/
scp deploy/scripts/reconcile-cni.sh                 $K3S_HOST:/tmp/inline-proxy-build/
scp deploy/Containerfile.proxy                      $K3S_HOST:/tmp/inline-proxy-build/
scp deploy/Containerfile.installer                  $K3S_HOST:/tmp/inline-proxy-build/

# Build and import on the node
ssh $K3S_HOST bash -s "$TAG" <<'REMOTE'
set -eu
TAG=$1
cd /tmp/inline-proxy-build
podman build -f Containerfile.proxy      -t localhost/inline-proxy/proxy-daemon:$TAG .
podman build -f Containerfile.installer  -t localhost/inline-proxy/installer:$TAG    .
podman save  -o proxy-daemon-$TAG.tar    localhost/inline-proxy/proxy-daemon:$TAG
podman save  -o installer-$TAG.tar       localhost/inline-proxy/installer:$TAG
sudo k3s ctr images import proxy-daemon-$TAG.tar
sudo k3s ctr images import installer-$TAG.tar
REMOTE
```

### 5. Deploy

The `kubectl apply -k` call needs the manifest directory on the machine running kubectl. Stage `deploy/base` alongside the binaries, then apply.

```bash
scp -r deploy/base $K3S_HOST:/tmp/inline-proxy-build/deploy/
ssh $K3S_HOST kubectl apply -k /tmp/inline-proxy-build/deploy/base
ssh $K3S_HOST kubectl -n inline-proxy-system set image \
    ds/inline-proxy-daemon    proxy-daemon=localhost/inline-proxy/proxy-daemon:$TAG
ssh $K3S_HOST kubectl -n inline-proxy-system set image \
    ds/inline-proxy-installer installer=localhost/inline-proxy/installer:$TAG
ssh $K3S_HOST kubectl -n inline-proxy-system rollout status ds/inline-proxy-daemon    --timeout=60s
ssh $K3S_HOST kubectl -n inline-proxy-system rollout status ds/inline-proxy-installer --timeout=60s
ssh $K3S_HOST kubectl wait --for=condition=Ready pod -l app=inline-proxy-caddy-demo --timeout=120s
```

Note: `deploy/base` ships with placeholder images (`ghcr.io/example/...`); the `set image` calls above point them at the tags you just built.

### 6. End-to-end verification

Drive traffic from an existing pod (coredns) to an annotated caddy pod, and confirm the proxy intercepted it.

```bash
# 6a. Get the proxy pod IP and an annotated caddy pod IP
PROXY_IP=$(ssh $K3S_HOST kubectl -n inline-proxy-system get pod -l app=inline-proxy -o jsonpath='{.items[0].status.podIP}')
CADDY_IP=$(ssh $K3S_HOST kubectl get pod -l app=inline-proxy-caddy-demo -o jsonpath='{.items[0].status.podIP}')

# 6b. Baseline counter
ssh $K3S_HOST "curl -s http://$PROXY_IP:8080/metrics" | grep '^inline_proxy_total_connections '

# 6c. Drive one request from the coredns netns
ssh $K3S_HOST bash -s "$CADDY_IP" <<'REMOTE'
set -eu
CADDY_IP=$1
CORE_ID=$(sudo crictl ps --name coredns -q)
CORE_PID=$(sudo crictl inspect "$CORE_ID" | awk '/^    "pid":/ {gsub(/[^0-9]/,"",$2); print $2; exit}')
sudo nsenter -t "$CORE_PID" -n bash -c "
  exec 3<>/dev/tcp/$CADDY_IP/80
  printf 'GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n' >&3
  head -c 50 <&3
  echo
"
REMOTE

# 6d. Counter should have incremented
ssh $K3S_HOST "curl -s http://$PROXY_IP:8080/metrics" | grep '^inline_proxy_total_connections '

# 6e. Proxy log should show the intercept
ssh $K3S_HOST kubectl -n inline-proxy-system logs ds/inline-proxy-daemon --tail=20 | grep 'accepted transparent connection'
```

Expected: counter goes up by one and the log line reads `accepted transparent connection client=<coredns-ip>:<port> original_dst=<caddy-ip>:80`.

### 7. Tear down

```bash
ssh $K3S_HOST kubectl delete -k deploy/base
```

### Environment flags

The daemon reads these at startup. Defaults match the splice/transparent topology on `main`.

| Env var | Default | Meaning |
|---|---|---|
| `INLINE_PROXY_INTERCEPT_PORT` | `80` | TC-ingress destination port to hijack |
| `INLINE_PROXY_USE_PROXY_SOURCE` | unset | `1` → upstream socket binds to the proxy's own IP instead of the original client. Required for the routed-ingress branch on k3s (flannel rejects spoofed pod sources). |
| `INLINE_PROXY_SKIP_LOCAL_SOURCE` | unset | `1` → skip adding the `/32` client IP to `wan_*` interfaces. Pairs with `USE_PROXY_SOURCE=1`. |

### Branches

- `main` — splice topology (pod's `eth0` renamed `wan_*`, moved into proxy netns). Transparent source-preserving. Uses `/32` trick.
- `feature/router-ingress` — routed topology (no `eth0` replacement; node routes `podIP/32` at proxy). Uses `USE_PROXY_SOURCE=1` + `SKIP_LOCAL_SOURCE=1` because k3s/flannel drops spoofed pod-to-pod sources. Verified end-to-end on k3s.

## Verification snapshot

Current verification commands for this branch:

```bash
bazel test //... --test_output=errors
bazel build //src/proxy:proxy_daemon //src/cni:inline_proxy_cni //src/bpf:loader
```
