#!/bin/sh
# Read-only RBAC boundary check for the change-guard service account.
# Exits non-zero when a required read is missing or a forbidden write/read is
# unexpectedly allowed.  It never changes cluster state.
set -eu

KUBECONFIG_PATH="${1:-/etc/change-guard/kubeconfig}"
KUBECTL="${KUBECTL:-kubectl}"
NAMESPACE="${NAMESPACE:-demo}"
ARGOCD_NAMESPACE="${ARGOCD_NAMESPACE:-argocd}"

allowed() {
  "$KUBECTL" --kubeconfig "$KUBECONFIG_PATH" auth can-i "$@" >/dev/null 2>&1
}
denied() {
  if "$KUBECTL" --kubeconfig "$KUBECONFIG_PATH" auth can-i "$@" >/dev/null 2>&1; then
    return 1
  fi
  return 0
}

fail=0
check_allowed() {
  if ! allowed "$@"; then
    echo "MISSING allowed permission: kubectl auth can-i $*" >&2
    fail=1
  fi
}
check_denied() {
  if ! denied "$@"; then
    echo "FORBIDDEN permission is allowed: kubectl auth can-i $*" >&2
    fail=1
  fi
}

check_allowed get nodes
check_allowed list pods --all-namespaces
check_allowed get applications.argoproj.io -n "$ARGOCD_NAMESPACE"
check_denied get secrets -n "$NAMESPACE"
check_denied get pods --subresource=log -n "$NAMESPACE"
check_denied create pods --subresource=exec -n "$NAMESPACE"
check_denied create deployments -n "$NAMESPACE"
check_denied patch applications.argoproj.io -n "$ARGOCD_NAMESPACE"

exit "$fail"
