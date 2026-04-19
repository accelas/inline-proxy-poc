#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
: "${INLINE_PROXY_CNI_PLUGIN_NAME:=inline-proxy-cni}"
: "${INLINE_PROXY_CNI_BINARY_SOURCE:=/opt/inline-proxy/bin/inline_proxy_cni}"
: "${INLINE_PROXY_PROXY_NAMESPACE:=inline-proxy-system}"
: "${INLINE_PROXY_PROXY_LABEL:=app=inline-proxy}"
: "${INLINE_PROXY_ANNOTATION_KEY:=inline-proxy.example.com/enabled}"

choose_bin_dir() {
  for candidate in "$@"; do
    if [ -d "$candidate" ] && find "$candidate" -maxdepth 1 \( -type f -o -type l \) | grep -q .; then
      printf '%s\n' "$candidate"
      return 0
    fi
  done
  return 1
}

choose_conf_dir() {
  for candidate in "$@"; do
    if [ -d "$candidate" ] && find "$candidate" -maxdepth 1 \( -name '*.conflist' -o -name '*.conf' \) | grep -q .; then
      printf '%s\n' "$candidate"
      return 0
    fi
  done
  return 1
}

HOST_BIN_DIR=$(choose_bin_dir /host/var/lib/rancher/k3s/data/cni /host/var/lib/rancher/k3s/data/current/bin /host/opt/cni/bin)
HOST_CONF_DIR=$(choose_conf_dir /host/var/lib/rancher/k3s/agent/etc/cni/net.d /host/etc/cni/net.d)

if [ ! -f "$INLINE_PROXY_CNI_BINARY_SOURCE" ]; then
  echo "missing chained CNI binary at $INLINE_PROXY_CNI_BINARY_SOURCE" >&2
  exit 1
fi

TARGET_BIN="$HOST_BIN_DIR/$INLINE_PROXY_CNI_PLUGIN_NAME"
install -m 0755 "$INLINE_PROXY_CNI_BINARY_SOURCE" "$TARGET_BIN"

/bin/sh "$SCRIPT_DIR/reconcile-cni.sh" "$HOST_CONF_DIR" "$INLINE_PROXY_CNI_PLUGIN_NAME" "$INLINE_PROXY_PROXY_NAMESPACE" "$INLINE_PROXY_PROXY_LABEL" "$INLINE_PROXY_ANNOTATION_KEY"

echo "installed $INLINE_PROXY_CNI_PLUGIN_NAME into $HOST_BIN_DIR and reconciled $HOST_CONF_DIR"
