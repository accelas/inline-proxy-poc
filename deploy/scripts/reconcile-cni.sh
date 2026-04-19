#!/bin/sh
set -eu

if [ "$#" -ne 5 ]; then
  echo "usage: $0 <cni-conf-dir> <plugin-name> <proxy-namespace> <proxy-label> <annotation-key>" >&2
  exit 2
fi

CONF_DIR=$1
PLUGIN_NAME=$2
PROXY_NAMESPACE=$3
PROXY_LABEL=$4
ANNOTATION_KEY=$5

if ! command -v python3 >/dev/null 2>&1; then
  echo "python3 is required to reconcile the active CNI conflist" >&2
  exit 1
fi

TARGET_CONF=$(find "$CONF_DIR" -maxdepth 1 \( -name '*.conflist' -o -name '*.conf' \) | sort | head -n1)
if [ -z "${TARGET_CONF:-}" ]; then
  echo "no active CNI config found in $CONF_DIR" >&2
  exit 1
fi

python3 - "$TARGET_CONF" "$PLUGIN_NAME" "$PROXY_NAMESPACE" "$PROXY_LABEL" "$ANNOTATION_KEY" <<'PY'
import json
import pathlib
import sys

conf_path = pathlib.Path(sys.argv[1])
plugin_name = sys.argv[2]
proxy_namespace = sys.argv[3]
proxy_label = sys.argv[4]
annotation_key = sys.argv[5]

config = json.loads(conf_path.read_text())

plugin_entry = {
    "type": plugin_name,
    "name": "inline-proxy-chained",
    "enabledAnnotation": annotation_key,
    "proxyNamespace": proxy_namespace,
    "proxyLabelSelector": proxy_label,
}

plugins = config.get("plugins")
if plugins is None:
    plugins = [config]
    config = {
        "cniVersion": config.get("cniVersion", "1.0.0"),
        "name": config.get("name", "inline-proxy-chain"),
        "plugins": plugins,
    }

if any(plugin.get("type") == plugin_name for plugin in plugins):
    sys.exit(0)

plugins.append(plugin_entry)
conf_path.write_text(json.dumps(config, indent=2) + "\n")
PY
