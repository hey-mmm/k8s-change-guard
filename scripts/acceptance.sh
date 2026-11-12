#!/bin/sh
# Local Go acceptance runner (no deployment, no Python).
#
# Runs formatting, vet, unit/security tests, knowledge verification, the
# synthetic scenario matrix, and (on Linux) a deterministic release build.
# A live host check is opt-in via --health-config.
set -eu

repo=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
go_bin="${GO:-go}"
skip_release=0
health_config=""

usage() {
  echo "usage: scripts/acceptance.sh [--skip-release] [--health-config YAML]" >&2
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --skip-release) skip_release=1 ;;
    --health-config) shift; health_config=${1:?--health-config requires a value} ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown argument: $1" >&2; usage; exit 2 ;;
  esac
  shift
done

command -v "$go_bin" >/dev/null 2>&1 || { echo "missing Go toolchain: $go_bin" >&2; exit 2; }
cd "$repo"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT INT TERM

echo "== gofmt"
gofmt_bin=$(command -v gofmt 2>/dev/null || true)
if [ -z "$gofmt_bin" ]; then
  gofmt_bin=$("$go_bin" env GOROOT)/bin/gofmt
fi
unformatted=$("$gofmt_bin" -l cmd internal scripts/packaging 2>/dev/null || true)
if [ -n "$unformatted" ]; then
  echo "unformatted Go files:" >&2
  echo "$unformatted" >&2
  exit 1
fi

echo "== go vet"
"$go_bin" vet ./...

echo "== go test"
"$go_bin" test ./...

echo "== build binary"
"$go_bin" build -trimpath -buildvcs=false -o "$tmp/change-guard" ./cmd/change-guard

echo "== verify knowledge"
"$tmp/change-guard" verify-knowledge --knowledge-dir knowledge --output "$tmp/knowledge.json"

echo "== synthetic scenario matrix"
"$tmp/change-guard" scenario --output "$tmp/scenario-matrix.json"

if [ "$skip_release" -eq 0 ]; then
  case "$(uname -s 2>/dev/null || true)" in
    Linux)
      echo "== deterministic release build"
      scripts/build-release.sh --output "$tmp/release.tar.gz"
      ;;
    *)
      echo "== release build skipped (scripts/build-release.sh targets Linux tooling)"
      ;;
  esac
fi

if [ -n "$health_config" ]; then
  echo "== live health check"
  scripts/health-check.sh --config "$health_config" --binary "$tmp/change-guard"
fi

echo "acceptance: local Go checks PASS"
echo "note: this is not live cluster/model/deployment acceptance"
