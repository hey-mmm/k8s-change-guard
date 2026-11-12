#!/bin/sh
# Build a deterministic trusted tarball for the Ansible role.
set -eu
exec python3 "$(dirname "$0")/build-release.py" "$@"
