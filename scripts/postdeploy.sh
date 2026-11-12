#!/bin/sh
# Read-only post-deployment verifier (Go binary wrapper).
#
# Example:
#   scripts/postdeploy.sh verify --config /etc/change-guard/config.yaml \
#     --expected-sha <main-commit> --expected-app-sha <image-source-commit> \
#     --report /var/lib/change-guard/reports/<id>.json
#
# Set CHANGE_GUARD_BIN when the binary is not installed at the Ansible default.
set -eu

binary="${CHANGE_GUARD_BIN:-/opt/change-guard/current/k8s-change-guard}"
if [ ! -x "$binary" ]; then
  if command -v change-guard >/dev/null 2>&1; then
    binary=$(command -v change-guard)
  else
    echo "change-guard binary not found; set CHANGE_GUARD_BIN" >&2
    exit 2
  fi
fi

exec "$binary" postdeploy "$@"
