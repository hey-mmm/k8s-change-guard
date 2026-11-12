#!/bin/sh
# Read-only RBAC boundary check for the change-guard service account.
# Exits non-zero when a required read is missing or a forbidden write/read is
# unexpectedly allowed.  It never changes cluster state and uses no Python.
set -eu

KUBECONFIG_PATH="${1:-/etc/change-guard/kubeconfig}"
KUBECTL="${KUBECTL:-kubectl}"
NAMESPACE="${NAMESPACE:-demo}"
ARGOCD_NAMESPACE="${ARGOCD_NAMESPACE:-argocd}"

decision() {
  "$KUBECTL" --kubeconfig "$KUBECONFIG_PATH" auth can-i "$@" 2>/dev/null | tr -d '\r' || true
}

allowed() {
  [ "$(decision "$@")" = "yes" ]
}
denied() {
  [ "$(decision "$@")" = "no" ]
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
    echo "FORBIDDEN permission is allowed or could not be checked: kubectl auth can-i $*" >&2
    fail=1
  fi
}

check_allowed get nodes
check_allowed list pods --all-namespaces
check_allowed get applications.argoproj.io -n "$ARGOCD_NAMESPACE"
check_denied get secrets -n "$NAMESPACE"
check_denied get secrets --all-namespaces
check_denied get pods --subresource=log -n "$NAMESPACE"
check_denied create pods --subresource=exec -n "$NAMESPACE"
check_denied create deployments -n "$NAMESPACE"
check_denied delete pods -n "$NAMESPACE"
check_denied patch applications.argoproj.io -n "$ARGOCD_NAMESPACE"
check_denied create serviceaccounts/token -n change-guard

exit "$fail"
