#!/bin/sh
# Operator-side TokenRequest rotation for hosts not managed by the Ansible role.
#
# Required environment:
#   BOOTSTRAP_KUBECONFIG  admin/operator kubeconfig on THIS controller only
#   TARGET_KUBECONFIG     path to write the service kubeconfig
#   KUBECTL               optional, default kubectl
# Optional:
#   SERVICE_NAMESPACE     default change-guard
#   SERVICE_ACCOUNT       default change-guard
#   TOKEN_TTL             default 12h (explicit short TTL)
#   SERVICE_NAMESPACE_DEFAULT default demo (kubeconfig context namespace)
#
# The target host never needs the bootstrap credential.  Run this from the
# operator/CI host and deliver TARGET_KUBECONFIG out of band if it is remote.
set -eu

: "${BOOTSTRAP_KUBECONFIG:?set BOOTSTRAP_KUBECONFIG}"
: "${TARGET_KUBECONFIG:?set TARGET_KUBECONFIG}"
KUBECTL="${KUBECTL:-kubectl}"
SERVICE_NAMESPACE="${SERVICE_NAMESPACE:-change-guard}"
SERVICE_ACCOUNT="${SERVICE_ACCOUNT:-change-guard}"
TOKEN_TTL="${TOKEN_TTL:-12h}"
CONTEXT_NAMESPACE="${SERVICE_NAMESPACE_DEFAULT:-demo}"

case "$TOKEN_TTL" in
  *[!0-9smh]*|'') echo "TOKEN_TTL must look like 30m, 6h or 24h" >&2; exit 2 ;;
esac
for binary in "$KUBECTL"; do
  command -v "$binary" >/dev/null 2>&1 || { echo "missing $binary" >&2; exit 2; }
done

umask 077
tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT INT TERM

"$KUBECTL" --kubeconfig "$BOOTSTRAP_KUBECONFIG" config view --raw --minify -o json > "$tmpdir/cluster.json"
server="$(python3 - "$tmpdir/cluster.json" <<'PY'
import json, sys
with open(sys.argv[1], encoding="utf-8") as handle:
    value = json.load(handle)
print(value["clusters"][0]["cluster"]["server"])
PY
)"
ca_data="$(python3 - "$tmpdir/cluster.json" <<'PY'
import json, sys
with open(sys.argv[1], encoding="utf-8") as handle:
    value = json.load(handle)
print(value["clusters"][0]["cluster"]["certificate-authority-data"])
PY
)"
token="$("$KUBECTL" --kubeconfig "$BOOTSTRAP_KUBECONFIG" -n "$SERVICE_NAMESPACE" create token "$SERVICE_ACCOUNT" --duration="$TOKEN_TTL")"
[ -n "$token" ] || { echo "TokenRequest returned an empty token" >&2; exit 1; }

python3 - "$TARGET_KUBECONFIG" "$server" "$ca_data" "$token" "$CONTEXT_NAMESPACE" <<'PY'
import json, os, sys
path, server, ca_data, token, namespace = sys.argv[1:6]
config = {
    "apiVersion": "v1",
    "kind": "Config",
    "clusters": [{"name": "change-guard", "cluster": {"server": server, "certificate-authority-data": ca_data}}],
    "users": [{"name": "change-guard", "user": {"token": token}}],
    "contexts": [{"name": "change-guard", "context": {"cluster": "change-guard", "user": "change-guard", "namespace": namespace}}],
    "current-context": "change-guard",
}
directory = os.path.dirname(os.path.abspath(path)) or "."
temp = os.path.join(directory, f".{os.path.basename(path)}.tmp")
with open(temp, "w", encoding="utf-8") as handle:
    json.dump(config, handle, indent=2)
    handle.write("\n")
    handle.flush()
    os.fsync(handle.fileno())
os.chmod(temp, 0o600)
os.replace(temp, path)
PY

echo "rotated $TARGET_KUBECONFIG with TTL $TOKEN_TTL" >&2
