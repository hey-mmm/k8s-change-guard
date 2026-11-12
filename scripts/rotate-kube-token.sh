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
# The target host never needs the bootstrap credential.  This script is pure
# shell and never prints the minted token.  Run it from the operator/CI host and
# deliver TARGET_KUBECONFIG out of band if it is remote.
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
command -v "$KUBECTL" >/dev/null 2>&1 || { echo "missing $KUBECTL" >&2; exit 2; }

umask 077
tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT INT TERM

server=$("$KUBECTL" --kubeconfig "$BOOTSTRAP_KUBECONFIG" config view --raw --minify -o jsonpath='{.clusters[0].cluster.server}')
ca_data=$("$KUBECTL" --kubeconfig "$BOOTSTRAP_KUBECONFIG" config view --raw --minify -o jsonpath='{.clusters[0].cluster.certificate-authority-data}')

case "$server" in
  https://*) ;;
  *) echo "bootstrap kubeconfig must contain an https server URL" >&2; exit 1 ;;
esac
case "$server" in
  *[!A-Za-z0-9:/._-]*) echo "bootstrap server URL contains unexpected characters" >&2; exit 1 ;;
esac
case "$ca_data" in
  ''|*[!A-Za-z0-9+/=]*) echo "bootstrap kubeconfig is missing a valid certificate-authority-data value" >&2; exit 1 ;;
esac

token=$("$KUBECTL" --kubeconfig "$BOOTSTRAP_KUBECONFIG" -n "$SERVICE_NAMESPACE" create token "$SERVICE_ACCOUNT" --duration="$TOKEN_TTL")
[ -n "$token" ] || { echo "TokenRequest returned an empty token" >&2; exit 1; }
case "$token" in
  *[!A-Za-z0-9._-]*) echo "TokenRequest returned a malformed token" >&2; exit 1 ;;
esac

target_dir=$(dirname -- "$TARGET_KUBECONFIG")
[ -d "$target_dir" ] || { echo "target directory does not exist: $target_dir" >&2; exit 1; }
temporary=$(mktemp "$target_dir/.change-guard-kubeconfig.XXXXXX")
trap 'rm -rf "$tmpdir" "$temporary"' EXIT INT TERM

# The token is base64url/JWT and CA data is base64, so both are safe as plain
# YAML scalars after the character checks above.  No credential is printed.
{
  printf 'apiVersion: v1\n'
  printf 'kind: Config\n'
  printf 'clusters:\n'
  printf '  - name: change-guard\n'
  printf '    cluster:\n'
  printf '      server: %s\n' "$server"
  printf '      certificate-authority-data: %s\n' "$ca_data"
  printf 'users:\n'
  printf '  - name: change-guard\n'
  printf '    user:\n'
  printf '      token: %s\n' "$token"
  printf 'contexts:\n'
  printf '  - name: change-guard\n'
  printf '    context:\n'
  printf '      cluster: change-guard\n'
  printf '      user: change-guard\n'
  printf '      namespace: %s\n' "$CONTEXT_NAMESPACE"
  printf 'current-context: change-guard\n'
} > "$temporary"
chmod 0600 "$temporary"
mv -f "$temporary" "$TARGET_KUBECONFIG"
trap 'rm -rf "$tmpdir"' EXIT INT TERM

echo "rotated $TARGET_KUBECONFIG with TTL $TOKEN_TTL" >&2
