#!/bin/sh
# Build the single static Linux Go binary and deterministic knowledge bundle.
#
# This is a build-time script.  The target host receives only the tarball; it
# needs no Python runtime, virtualenv, pip, or source tree.
set -eu

repo=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
version=""
arch="amd64"
output=""
go_bin="${GO:-go}"

while [ "$#" -gt 0 ]; do
  case "$1" in
    --repo) shift; repo=${1:?--repo requires a value} ;;
    --version) shift; version=${1:?--version requires a value} ;;
    --arch) shift; arch=${1:?--arch requires a value} ;;
    --output) shift; output=${1:?--output requires a value} ;;
    --go) shift; go_bin=${1:?--go requires a value} ;;
    -h|--help)
      echo "usage: scripts/build-release.sh [--repo DIR] [--version VERSION] [--arch amd64|arm64] [--output FILE] [--go PATH]" >&2
      exit 0
      ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
  shift
done

case "$arch" in
  amd64|arm64) ;;
  *) echo "unsupported architecture: $arch (use amd64 or arm64)" >&2; exit 2 ;;
esac

if [ -z "$version" ]; then
  version=$(sed -n 's/^const Version = "\([^"]*\)"/\1/p' "$repo/internal/guard/common.go" | head -n 1)
fi
if [ -z "$version" ]; then
  echo "cannot determine release version" >&2
  exit 2
fi
if [ -z "$output" ]; then
  output="$repo/dist/k8s-change-guard-$version.tar.gz"
fi

command -v "$go_bin" >/dev/null 2>&1 || { echo "missing Go toolchain: $go_bin" >&2; exit 2; }
[ -f "$repo/cmd/change-guard/main.go" ] || { echo "missing cmd/change-guard" >&2; exit 2; }

stage=$(mktemp -d "${TMPDIR:-/tmp}/change-guard-release.XXXXXX")
cleanup() { rm -rf "$stage"; }
trap cleanup EXIT INT TERM

mkdir -p "$stage"
(
  cd "$repo"
  CGO_ENABLED=0 GOOS=linux GOARCH="$arch" "$go_bin" build \
    -trimpath -buildvcs=false -tags netgo,osusergo \
    -ldflags "-s -w -buildid=" \
    -o "$stage/k8s-change-guard" ./cmd/change-guard
)
chmod 0755 "$stage/k8s-change-guard"

if find "$repo/knowledge" -type l -print | grep -q .; then
  echo "refusing to package symlinks in knowledge/" >&2
  exit 2
fi
cp -R "$repo/knowledge" "$stage/knowledge"
find "$stage/knowledge" -type d -exec chmod 0755 {} +
find "$stage/knowledge" -type f -exec chmod 0644 {} +
cp "$repo/config.example.yaml" "$stage/config.example.yaml"
chmod 0644 "$stage/config.example.yaml"
if [ -f "$repo/README.md" ]; then
  cp "$repo/README.md" "$stage/README.md"
  chmod 0644 "$stage/README.md"
fi
# Binary is the only executable in the trusted archive.
find "$stage" -type f ! -name k8s-change-guard -exec chmod 0644 {} +

mkdir -p "$(dirname "$output")"
(
  cd "$repo"
  "$go_bin" run ./scripts/packaging \
    --stage "$stage" \
    --output "$output" \
    --version "$version" \
    --arch "$arch"
)
