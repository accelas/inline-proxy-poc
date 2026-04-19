# Deployment

This directory contains k3s-oriented deployment artifacts for the inline proxy PoC.

## Base resources

- `base/namespace.yaml` — `inline-proxy-system` namespace
- `base/rbac.yaml` — daemon and installer service accounts / RBAC
- `base/proxy-daemonset.yaml` — node-local proxy DaemonSet
- `base/proxy-installer-daemonset.yaml` — per-node installer/reconciler DaemonSet
- `base/caddy-demo.yaml` — annotated Caddy backend Deployment + Service
- `base/client-demo.yaml` — curl-based client pod that continuously drives traffic
- `base/kustomization.yaml` — one-shot kustomize entrypoint

## Installer behavior

`scripts/install-cni.sh` assumes the installer container image already includes:

- `/opt/inline-proxy/bin/inline_proxy_cni`
- `/opt/inline-proxy/scripts/install-cni.sh`
- `/opt/inline-proxy/scripts/reconcile-cni.sh`

It installs the `inline_proxy_cni` binary into the active k3s or generic CNI bin
directory, then calls `scripts/reconcile-cni.sh` to append the chained plugin into
the active CNI conflist. The installer DaemonSet keeps running and re-runs the
same install/reconcile flow on a fixed interval to catch drift.

If the node has multiple plausible CNI configs, set `INLINE_PROXY_CNI_CONF_FILE`
in the installer DaemonSet to force the exact file to patch.

The reconciler adds an entry like:

```json
{
  "type": "inline-proxy-cni",
  "name": "inline-proxy-chained",
  "enabledAnnotation": "inline-proxy.example.com/enabled",
  "proxyNamespace": "inline-proxy-system",
  "proxyLabelSelector": "app=inline-proxy"
}
```

## Apply

```bash
kubectl apply -k deploy/base
```

## Validate installer rollout

```bash
kubectl get pods -n inline-proxy-system -o wide
kubectl logs -n inline-proxy-system ds/inline-proxy-installer
kubectl logs -n inline-proxy-system ds/inline-proxy-daemon
```

## Validate same-node traffic

```bash
kubectl get pods -n default -o wide
kubectl exec -n default inline-proxy-client-demo -- \
  curl -sv http://inline-proxy-caddy-demo.default.svc.cluster.local/
kubectl port-forward -n inline-proxy-system ds/inline-proxy-daemon 8080:8080
curl -s http://127.0.0.1:8080/sessions
curl -s http://127.0.0.1:8080/metrics
```

## Validate cross-node traffic

Pin the client and one Caddy pod to different nodes, then re-run the curl check:

```bash
kubectl get pods -n default -o wide
kubectl exec -n default inline-proxy-client-demo -- \
  curl -sv http://inline-proxy-caddy-demo.default.svc.cluster.local/
kubectl logs -n inline-proxy-system ds/inline-proxy-daemon --tail=200
```

The expected signal is:

- annotated Caddy pods continue serving through the Service
- proxy admin endpoints remain healthy
- daemon logs / counters show sessions on the node hosting the backend pod

One practical way to force cross-node placement during the demo is to add distinct
`nodeSelector` or `nodeAffinity` rules to the client pod and one Caddy replica, then
confirm placement with `kubectl get pods -o wide`.

## Unannotated control case

Remove the annotation from the Caddy pod template and re-apply:

```bash
kubectl patch deployment inline-proxy-caddy-demo -n default --type=json \
  -p='[{"op":"remove","path":"/spec/template/metadata/annotations/inline-proxy.example.com~1enabled"}]'
```

Traffic should still succeed, but the proxy daemon session counters should no longer
increase for that workload.
