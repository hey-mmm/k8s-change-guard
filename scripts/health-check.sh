#!/bin/sh
# Read-only health check for an installed change-guard host.
#
# It never mutates cluster state, never prints a token, and never invokes Python.
# The optional RBAC checks use `kubectl auth can-i` only.
#
# Example:
#   scripts/health-check.sh --config /etc/change-guard/config.yaml
#   scripts/health-check.sh --config ./config.example.yaml --binary ./change-guard \
#     --service '' --no-http
set -eu

binary="${CHANGE_GUARD_BIN:-/opt/change-guard/current/k8s-change-guard}"
config="${CHANGE_GUARD_CONFIG:-/etc/change-guard/config.yaml}"
kubeconfig="${CHANGE_GUARD_KUBECONFIG:-}"
service="${CHANGE_GUARD_SERVICE:-change-guard.service}"
timer="${CHANGE_GUARD_TIMER:-change-guard-token-renew.timer}"
min_remaining="${CHANGE_GUARD_MIN_REMAINING:-3600}"
timeout="${CHANGE_GUARD_HTTP_TIMEOUT:-10}"
check_timer=1
check_http=1
check_rbac=0

usage() {
  echo "usage: scripts/health-check.sh [--binary PATH] [--config YAML]" >&2
  echo "       [--kubeconfig PATH] [--service UNIT|''] [--timer UNIT|'']" >&2
  echo "       [--min-remaining SECONDS] [--timeout SECONDS]" >&2
  echo "       [--rbac] [--no-http] [--no-timer]" >&2
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --binary) shift; binary=${1:?--binary requires a value} ;;
    --config) shift; config=${1:?--config requires a value} ;;
    --kubeconfig) shift; kubeconfig=${1:?--kubeconfig requires a value} ;;
    --service) shift; service=${1-} ;;
    --timer) shift; timer=${1-} ;;
    --min-remaining) shift; min_remaining=${1:?--min-remaining requires a value} ;;
    --timeout) shift; timeout=${1:?--timeout requires a value} ;;
    --rbac) check_rbac=1 ;;
    --no-http) check_http=0 ;;
    --no-timer) check_timer=0 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown argument: $1" >&2; usage; exit 2 ;;
  esac
  shift
done

# Top-level YAML scalar reader; the config keys used here are intentionally
# simple and are never sourced or evaluated as shell.
config_value() {
  [ -f "$config" ] || return 0
  sed -n "s/^[[:space:]]*$1:[[:space:]]*//p" "$config" |
    head -n 1 |
    sed -e 's/[[:space:]]#.*$//' -e 's/[[:space:]]*$//' \
        -e 's/^"//' -e 's/"$//' -e "s/^'//" -e "s/'$//"
}

failures=0
passes=0
fail() { echo "FAIL $*"; failures=$((failures + 1)); }
pass() { echo "PASS $*"; passes=$((passes + 1)); }
skip() { echo "SKIP $*"; }

[ -n "$kubeconfig" ] || kubeconfig=$(config_value kubeconfig)
[ -n "$kubeconfig" ] || kubeconfig=/etc/change-guard/kubeconfig

# 1. Service unit.
if [ -n "$service" ]; then
  if ! command -v systemctl >/dev/null 2>&1; then
    skip "systemctl unavailable; service $service not checked"
  elif [ "$(systemctl is-active "$service" 2>/dev/null || true)" = "active" ]; then
    pass "service $service is active"
  else
    fail "service $service is not active"
  fi
fi

# 2. Binary and version.
if [ ! -x "$binary" ]; then
  fail "change-guard binary is missing or not executable: $binary"
elif version=$("$binary" --version 2>&1); then
  if [ -n "$version" ]; then
    pass "binary version: $version"
  else
    fail "binary did not report a version"
  fi
else
  fail "binary --version failed: $version"
fi

# 3. Token expiry (never prints the token).
if [ ! -r "$kubeconfig" ]; then
  fail "kubeconfig is not readable: $kubeconfig"
elif [ -x "$binary" ]; then
  if token_json=$("$binary" check-token "$kubeconfig" --min-remaining "$min_remaining" 2>&1); then
    pass "token valid with at least ${min_remaining}s remaining: $token_json"
  else
    status=$?
    if [ "$status" -eq 1 ]; then
      fail "token must be rotated: $token_json"
    else
      fail "token could not be checked: $token_json"
    fi
  fi
fi

# 4. Renewal timer.
if [ "$check_timer" -eq 1 ] && [ -n "$timer" ]; then
  if ! command -v systemctl >/dev/null 2>&1; then
    skip "systemctl unavailable; timer $timer not checked"
  elif ! systemctl cat "$timer" >/dev/null 2>&1; then
    skip "timer $timer is not installed"
  elif [ "$(systemctl is-active "$timer" 2>/dev/null || true)" = "active" ]; then
    pass "timer $timer is active"
  else
    fail "timer $timer is not active"
  fi
fi

# 5. Read-only HTTP readiness/provenance checks.
if [ "$check_http" -eq 1 ]; then
  demo_url=$(config_value demo_url)
  ready_path=$(config_value ready_path)
  version_path=$(config_value version_path)
  [ -n "$ready_path" ] || ready_path=/readyz
  [ -n "$version_path" ] || version_path=/version
  if [ -z "$demo_url" ]; then
    skip "demo_url is not configured; HTTP checks skipped"
  elif ! command -v curl >/dev/null 2>&1; then
    fail "curl is unavailable; HTTP checks cannot run"
  else
    tmp=$(mktemp)
    trap 'rm -f "$tmp" "$tmp.err"' EXIT INT TERM
    for path in "$ready_path" "$version_path"; do
      case "$path" in
        /*) ;;
        *) fail "HTTP path is not absolute: $path"; continue ;;
      esac
      : > "$tmp"
      code=$(curl --silent --show-error --max-time "$timeout" -o "$tmp" -w '%{http_code}' "${demo_url}${path}" 2>"$tmp.err" || true)
      if [ "$code" = "200" ]; then
        pass "GET $path returned HTTP 200"
      else
        detail=$(head -c 200 "$tmp.err" 2>/dev/null | tr '\n' ' ' || true)
        fail "GET $path returned HTTP ${code:-000}${detail:+: $detail}"
      fi
    done
  fi
fi

# 6. Optional least-privilege RBAC checks.
if [ "$check_rbac" -eq 1 ]; then
  kubectl_bin=$(config_value kubectl)
  [ -n "$kubectl_bin" ] || kubectl_bin=kubectl
  namespace=$(config_value namespace)
  [ -n "$namespace" ] || namespace=demo
  argocd_namespace=$(config_value argocd_namespace)
  [ -n "$argocd_namespace" ] || argocd_namespace=argocd
  if ! command -v "$kubectl_bin" >/dev/null 2>&1; then
    fail "kubectl is unavailable: $kubectl_bin"
  elif ! "$kubectl_bin" --kubeconfig "$kubeconfig" auth can-i get nodes >/dev/null 2>&1; then
    fail "service cannot get nodes"
  elif ! "$kubectl_bin" --kubeconfig "$kubeconfig" auth can-i list pods --all-namespaces >/dev/null 2>&1; then
    fail "service cannot list pods cluster-wide"
  elif ! "$kubectl_bin" --kubeconfig "$kubeconfig" auth can-i get applications.argoproj.io -n "$argocd_namespace" >/dev/null 2>&1; then
    fail "service cannot read Argo CD Applications"
  elif "$kubectl_bin" --kubeconfig "$kubeconfig" auth can-i get secrets -n "$namespace" >/dev/null 2>&1; then
    fail "service can read Secrets"
  elif "$kubectl_bin" --kubeconfig "$kubeconfig" auth can-i get pods --subresource=log -n "$namespace" >/dev/null 2>&1; then
    fail "service can read Pod logs"
  elif "$kubectl_bin" --kubeconfig "$kubeconfig" auth can-i create pods --subresource=exec -n "$namespace" >/dev/null 2>&1; then
    fail "service can exec into Pods"
  elif "$kubectl_bin" --kubeconfig "$kubeconfig" auth can-i create deployments -n "$namespace" >/dev/null 2>&1; then
    fail "service can write Deployments"
  else
    pass "RBAC required reads present and forbidden reads/writes denied"
  fi
fi

if [ "$failures" -eq 0 ]; then
  echo "health: PASS (${passes} checks)"
  exit 0
fi
echo "health: FAIL (${failures} failed, ${passes} passed)"
exit 1
