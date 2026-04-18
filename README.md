# inline_proxy_poc

Inline transparent proxy proof of concept for k3s.

## Layout

- `src/shared/` — common support code shared by all components
- `src/proxy/` — proxy daemon package
- `src/cni/` — chained CNI plugin package
- `src/bpf/` — eBPF loader package
- `deploy/` — deployment notes and manifests

## Build

```bash
bazel build //...
```

## Test

```bash
bazel test //...
```
