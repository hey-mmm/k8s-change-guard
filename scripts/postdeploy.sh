#!/bin/sh
# Read-only post-deployment verifier.
# Example:
#   scripts/postdeploy.sh verify --config /etc/change-guard/config.yaml \
#     --expected-sha <main-commit> --report /var/lib/change-guard/reports/<id>.json
set -eu
exec python3 -m change_guard.postdeploy "$@"
