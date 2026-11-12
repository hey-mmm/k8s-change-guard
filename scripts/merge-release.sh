#!/usr/bin/env bash
# Trusted operator entry point for a guarded merge.
#
# The daemon is paused so the single-writer state lock is not contended.  The
# service-owned proxy environment is read only after dropping privileges.  The
# Go binary performs all proof, approval, CI, tree and lease checks.
set -euo pipefail
[[ "$(id -u)" == 0 ]] || { echo 'Run this trusted script with sudo.' >&2; exit 2; }
[[ $# == 1 && "$1" =~ ^[1-9][0-9]*$ ]] || { echo 'Usage: merge-release.sh PR_NUMBER' >&2; exit 2; }

binary="${CHANGE_GUARD_BIN:-/opt/change-guard/current/k8s-change-guard}"
[[ -x "$binary" ]] || { echo "missing executable change-guard binary: $binary" >&2; exit 2; }

was_active=0
if systemctl is-active --quiet change-guard.service; then was_active=1; fi
restore_polling() {
  if [[ "$was_active" == 1 ]]; then systemctl start change-guard.service; fi
}
trap restore_polling EXIT
systemctl stop change-guard.service

# Do not export the proxy file into this root shell.  Parse it only inside the
# unprivileged child, then exec the fixed Go merge command.
runuser -u change-guard -- /bin/bash -c '
  set -euo pipefail
  set -a
  if [[ -f /etc/change-guard/proxy.env ]]; then source /etc/change-guard/proxy.env; fi
  set +a
  exec "$1" merge --config /etc/change-guard/config.yaml --pr "$2"
' guard-merger "$binary" "$1"
