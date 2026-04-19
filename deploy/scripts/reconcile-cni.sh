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

python3 - "$CONF_DIR" "$PLUGIN_NAME" "$PROXY_NAMESPACE" "$PROXY_LABEL" "$ANNOTATION_KEY" "${INLINE_PROXY_CNI_CONF_FILE:-}" <<'PY'
import json
import pathlib
import sys

conf_dir = pathlib.Path(sys.argv[1])
plugin_name = sys.argv[2]
proxy_namespace = sys.argv[3]
proxy_label = sys.argv[4]
annotation_key = sys.argv[5]
explicit_path = sys.argv[6]

def load_json(path: pathlib.Path):
    try:
        return json.loads(path.read_text())
    except Exception:
        return None

def score_candidate(path: pathlib.Path) -> int:
    score = 0
    if path.name.endswith(".conflist"):
        score += 100
    if path.name == "10-flannel.conflist":
        score += 200
    payload = load_json(path)
    if payload is None:
        return -1
    plugins = payload.get("plugins", [payload])
    for plugin in plugins:
        plugin_type = plugin.get("type", "")
        if plugin_type == "flannel":
            score += 75
        if plugin_type == "bridge":
            score += 25
        if plugin_type == plugin_name:
            score += 500
    return score

if explicit_path:
    conf_path = pathlib.Path(explicit_path)
else:
    candidates = sorted(conf_dir.glob("*.conflist")) + sorted(conf_dir.glob("*.conf"))
    if not candidates:
        raise SystemExit(f"no CNI config found in {conf_dir}")
    scored = sorted(
        ((score_candidate(path), path) for path in candidates),
        key=lambda item: (item[0], item[1].name),
        reverse=True,
    )
    best_score, conf_path = scored[0]
    if best_score < 0:
        raise SystemExit(f"unable to parse any CNI config in {conf_dir}")

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
