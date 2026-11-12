#!/bin/sh
# Reproducible synthetic scenario matrix for the Go evaluation kernel.
#
# This is regression evidence built from synthetic manifests/evidence and
# explicit AI stubs.  It is NOT a live cluster/model experiment and must not be
# reported as live acceptance.
set -eu

repo=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
go_bin="${GO:-go}"
output="${1:-scenario-matrix.json}"
binary="${CHANGE_GUARD_BIN:-}"

case "$output" in
  --help|-h)
    echo "usage: scripts/scenario-matrix.sh [OUTPUT.json]" >&2
    echo "   or: CHANGE_GUARD_BIN=/path/to/change-guard scripts/scenario-matrix.sh [OUTPUT.json]" >&2
    exit 0
    ;;
esac

cd "$repo"
if [ -n "$binary" ]; then
  [ -x "$binary" ] || { echo "missing executable CHANGE_GUARD_BIN: $binary" >&2; exit 2; }
  exec "$binary" scenario --output "$output"
fi

command -v "$go_bin" >/dev/null 2>&1 || { echo "missing Go toolchain: $go_bin" >&2; exit 2; }
exec "$go_bin" run ./cmd/change-guard scenario --output "$output"
