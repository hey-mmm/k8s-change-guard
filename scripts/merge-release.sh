#!/usr/bin/env bash
# Trusted operator entry point. Pause polling to avoid the nonblocking state lock.
set -euo pipefail
[[ "$(id -u)" == 0 ]] || { echo 'Run this trusted script with sudo.' >&2; exit 2; }
[[ $# == 1 && "$1" =~ ^[1-9][0-9]*$ ]] || { echo 'Usage: merge-release.sh PR_NUMBER' >&2; exit 2; }
was_active=0
if systemctl is-active --quiet change-guard.service; then was_active=1; fi
restore_polling() {
  if [[ "$was_active" == 1 ]]; then systemctl start change-guard.service; fi
}
trap restore_polling EXIT
systemctl stop change-guard.service
# Parse the service-owned proxy environment only after dropping privileges.
runuser -u change-guard -- /bin/bash -c '
  set -euo pipefail
  set -a
  if [[ -f /etc/change-guard/proxy.env ]]; then source /etc/change-guard/proxy.env; fi
  set +a
  cd /opt/change-guard/current
  exec ./venv/bin/python -m change_guard.merge --config /etc/change-guard/config.yaml --pr "$1"
' guard-merger "$1"
