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
