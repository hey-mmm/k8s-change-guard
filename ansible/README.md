# Deploying k8s-change-guard (Go single binary)

The role installs one immutable static Linux binary, runs the daemon as an
independent unprivileged user, grants read-only Kubernetes access, and gives the
service a short-lived TokenRequest kubeconfig. It does **not** copy the
controller's bootstrap/admin kubeconfig to the service identity.

The current Go `0.3.0` migration, Windows/Linux tests, and single-binary release
build are complete and ready to deploy. It is **not deployed yet**; the root
deployment round will execute this playbook and the live acceptance steps.
Historical Python `0.2.3` deployment and live evidence remain in
`docs/acceptance.md` as history only; do not treat it as Go live acceptance.

## 1. Supported target

- Debian/Ubuntu only (package names and systemd paths are Debian-specific).
- `amd64` or `arm64`.
- The lab target is the control-plane host `11.0.1.10` (`master`), because the
  root-only `change-guard renew-token` helper uses the local
  `/etc/kubernetes/admin.conf`. For a separate host, use controller-side
  rotation; do not copy the admin kubeconfig into the service config directory.
- Production Helm rendering requires Linux bubblewrap. Keep namespace creation
  available to the service user.

The role installs `bubblewrap`, `ca-certificates`, `curl`, `git`, `gzip`,
`netcat-openbsd`, `openssh-client`, `python3`, and `tar`. `python3` is only
Ansible's remote interpreter; the guard runtime is the Go binary. Preinstalled
executable Helm/kubectl are reused; a missing binary is downloaded only with a
pinned SHA-256.

## 2. Build the trusted artifact

```sh
VERSION='0.3.0'
scripts/build-release.sh --version "$VERSION"
# -> dist/k8s-change-guard-0.3.0.tar.gz and SHA-256 in the JSON output
```

On Windows:

```powershell
pwsh -NoProfile -File scripts/build-release.ps1 -Go E:/Go/bin/go.exe -Version 0.3.0
```

The release version is the `Version` constant in `internal/guard/common.go`;
`--version` only changes the artifact name/JSON field. The tarball contains only:

```text
k8s-change-guard      # the only executable
knowledge/
config.example.yaml
README.md
```

It never contains tests, Ansible, Python, scripts, VCS metadata, or credentials.

Do not let Git normalize `knowledge/sources/`: `.gitattributes` sets
`knowledge/sources/* -text` because the knowledge hashes attest exact source
bytes.

## 3. Inputs and credentials

Copy `ansible/group_vars/all.yml.example` to `ansible/group_vars/all.yml` and
set at least:

```yaml
change_guard_version: "<new-version>"
change_guard_artifact: "{{ playbook_dir }}/../dist/k8s-change-guard-<new-version>.tar.gz"
change_guard_artifact_checksum: "<64-hex SHA-256 from build-release>"

change_guard_github_token_src: "{{ playbook_dir }}/../secrets/github-token"
change_guard_deepseek_token_src: "{{ playbook_dir }}/../secrets/deepseek-token"
change_guard_merge_deploy_key_src: "{{ playbook_dir }}/../secrets/merge-deploy-key"
change_guard_merge_known_hosts_src: "{{ playbook_dir }}/../secrets/github_known_hosts"

change_guard_bootstrap_kubeconfig: "{{ lookup('env', 'HOME') }}/.kube/config"
change_guard_token_ttl: "12h"
change_guard_token_refresh_before_seconds: 7200
change_guard_force_token_rotation: false
```

Credential source files live on the controller, are copied with mode `0600`,
and are owned by `change-guard`. They are never placed in inventory. The role
never copies the controller's bootstrap kubeconfig to the target or to the
service identity; TokenRequest and RBAC are applied on the controller
(`delegate_to: localhost`).

The GitHub PAT is separate from the merge deploy key:

- PAT: repository-limited, Metadata read, Contents read, Pull requests read,
  Issues read, Commit statuses **read/write**. No Administration, Checks,
  Contents write, or Issues write (leave `report_comment: false`).
- Deploy key: one dedicated write key for the repository. It is used only by
  the Go `merge` command; it is not given to the daemon for arbitrary pushes.

## 4. Critical policy inputs

Set the aggregate check name as a single string:

```yaml
change_guard_merge_required_ci: "Test, lint, render"
```

Keep it a string (not a three-element list). The Go merge command matches one
aggregate GitHub Actions check name bound to the PR head.

Set the operator-approved chart pin to the exact `charts/demo` Git blob digest:

```yaml
change_guard_approved_chart_digest: "194baf90afd746299e256dc0bf144a12bc6f6325bacf77b40ff01e50b0c3e05d"
```

This is the real digest computed from the current `charts/demo` Git blobs; the
old `0b2b...` value is stale. The digest is
`sha256(canonical_json({path under charts/demo: sha256(exact git blob bytes)}))`;
CRLF/LF differences change it, and `gitops/demo/values.yaml` is deliberately not
part of the pin. A missing pin is ERROR/BLOCK; a mismatch is BLOCK and cannot
be approved.

`.github/workflows/` changes are a hard BLOCK; Go merge independently compares
base/head workflow trees.

## 5. Deploy

```sh
ansible-playbook -i ansible/inventory.example.ini ansible/site.yml
# add --ask-become-pass if the SSH user needs a sudo password
```

Order of operations:

1. preflight: Debian/Ubuntu, literal version, trusted SHA-256, controller
   credential files, controller kubectl, unprivileged userns.
2. packages: runtime packages and Helm/kubectl selection.
3. user/directories: `change-guard` system user with `nologin`, private state
   dir, config dir, release root.
4. release: SHA-256 check on both sides, immutable
   `/opt/change-guard/releases/<version>`, single binary + knowledge,
   `.artifact.sha256`, `.complete`, `current` symlink. The installed binary must
   report the pinned version and be the only executable release file.
5. RBAC: namespace, ServiceAccount, node/pod cluster readers, demo workload
   reader, separate Argo CD reader.
6. token: use Go `check-token`; reuse a fresh kubeconfig or mint a `12h`
   TokenRequest on the controller and atomically install it as `0600`.
7. configure: non-secret config, PAT/DeepSeek token, proxy env, optional merge
   deploy key and known-hosts.
8. service: hardened systemd unit running `current/k8s-change-guard daemon`.
9. renewal: Go `renew-token` 6-hour timer and `check-token` hourly monitor timer.
10. verify: service state, binary version, token freshness, timers, required
    reads, forbidden reads/writes.

Ansible `copy.checksum` is SHA-1 only, so the role explicitly verifies SHA-256
on the controller and again after copying. A completed version directory with
a different artifact digest is refused instead of reused.

## 6. TokenRequest renewal and expiry check

- TTL: `12h` by default.
- Renew timer: `change-guard-token-renew.timer`, every 6 hours.
- Check timer: `change-guard-token-check.timer`, every hour; it fails the unit
  when the remaining lifetime drops to the refresh window
  (`change_guard_token_refresh_before_seconds`, default `7200`).
- Helper: `/opt/change-guard/current/k8s-change-guard`.
- Fixed renew command:
  `change-guard renew-token` → `/usr/bin/kubectl --kubeconfig=/etc/kubernetes/admin.conf -n change-guard create token change-guard --duration=12h`.
- The helper atomically replaces `/etc/change-guard/kubeconfig` with mode
  `0600`, preserving server/CA; it never prints the token.
- `change-guard check-token /etc/change-guard/kubeconfig --min-remaining N`
  decodes the JWT `exp` locally and exits 0 valid / 1 rotate / 2 error.
- The daemon reads the kubeconfig per kubectl invocation, so renewal does not
  require a restart.
- The service user cannot execute the root helper, read
  `/etc/kubernetes/admin.conf`, or modify the timer/unit.

If the host is not a control-plane node, use controller-side rotation:

```sh
ansible-playbook -i ansible/inventory.example.ini ansible/rotate-token.yml
# or, outside Ansible:
BOOTSTRAP_KUBECONFIG="$HOME/.kube/config" \
TARGET_KUBECONFIG=/tmp/change-guard-kubeconfig \
TOKEN_TTL=12h sh scripts/rotate-kube-token.sh
```

## 7. RBAC and systemd

The applied RBAC has no Secrets, `pods/log`, `pods/exec`, or write verbs.

Allowed:

- `get/list/watch nodes`;
- `get/list/watch pods` in all namespaces (capacity accounting);
- demo namespace pods/services/endpoints/deployments/replicasets read;
- Argo CD Applications/AppProjects/ApplicationSets read in `argocd`.

Denied:

- Secrets;
- Pod logs and exec;
- workload writes;
- Argo CD writes.

The service unit uses an independent user, empty capability set,
`NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome`, `PrivateTmp`,
read-only config/release paths, and a writable state directory. It deliberately
keeps `RestrictNamespaces=false` so bubblewrap can create the namespaces needed
by `--unshare-all`. The unit does not set `RLIMIT_AS`; `MemoryHigh=1536M` and
`MemoryMax=2G` bound the cgroup.

## 8. Idempotency and verification

```sh
ansible-playbook -i ansible/inventory.example.ini ansible/site.yml
ansible-playbook -i ansible/inventory.example.ini ansible/site.yml
```

The second recap should report `changed=0` (unless the token enters its refresh
window or a credential/input changed). The verify phase checks:

- service active and running as `change-guard` with `nologin`;
- binary reports the pinned Go version;
- credential files `0600`, service-owned;
- short-lived kubeconfig unexpired and readable by the Go `check-token` helper;
- both token timers active;
- required reads work: nodes, all-namespace pods, Argo CD Applications;
- forbidden actions fail: Secrets, pod logs/exec, workload writes, Argo writes;
- installed config has string `merge_required_ci` and a non-empty
  `approved_chart_digest`.

Standalone checks:

```sh
sh scripts/verify-rbac.sh /etc/change-guard/kubeconfig
sh scripts/health-check.sh --config /etc/change-guard/config.yaml --rbac
```

Historical Python `0.2.3` evidence and the Go live acceptance checklist are in
`docs/acceptance.md`.

## 9. Merge deploy key and post-deploy

The optional merge integration installs:

- `/etc/change-guard/merge-deploy-key` (`0600`, service-owned);
- `/etc/change-guard/github_known_hosts` (`0600`, service-owned);
- `config.yaml` keys `merge_deploy_key`, `merge_known_hosts`,
  `merge_ssh_proxy`, `merge_required_ci`, `approved_chart_digest`, and optional
  `merge_fetch_depth`.

Prefer the root wrapper from the trusted deployment directory, which pauses
polling and restores it on exit:

```sh
sudo scripts/merge-release.sh <number>
```

The wrapper stops `change-guard.service`, uses `trap ... EXIT` to restore the
previous polling state, reads `/etc/change-guard/proxy.env` after dropping to
`change-guard` via `runuser`, and executes the fixed Go merge command. To run
the binary directly, stop the daemon/serialize first; otherwise it may fail
with a daemon lock error:

```sh
sudo systemctl stop change-guard.service
sudo -u change-guard \
  env HTTP_PROXY=http://11.0.1.1:7890 \
      HTTPS_PROXY=http://11.0.1.1:7890 \
      NO_PROXY='127.0.0.1,localhost,::1,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,.svc,.cluster.local' \
  /opt/change-guard/current/k8s-change-guard merge \
  --config /etc/change-guard/config.yaml --pr <number>
sudo systemctl start change-guard.service
```

It validates the current report schema/policy binding, exact head/base, approval,
workflow tree equality, independently recomputed chart pin, head-bound GitHub
Actions CI, synthetic parents/tree, report digest, and exact lease before pushing.
It does not push the synthetic commit, call the GitHub Merge API, or check out
candidate code.

Post-deploy verifier:

```sh
sudo -u change-guard \
  /opt/change-guard/current/k8s-change-guard postdeploy verify \
  --config /etc/change-guard/config.yaml \
  --expected-sha <main-head-gitops-revision> \
  --expected-app-sha <image-source-commit> \
  --report /var/lib/change-guard/reports/<evaluation-id>.json
```

`--expected-sha` is the Argo/GitOps revision; `--expected-app-sha` is the image
source commit exposed by `/version`. They are normally different and both must
be supplied. The verifier is read-only; on failure it returns an
`open_revert_pr` recommendation and never rolls back or mutates the cluster.

## 10. Known deployment caveats

- The GitHub ruleset DeployKey bypass is repository-wide, not per-key.
- GitHub success statuses have no project-defined TTL; the daemon revokes stale
  statuses while running, and merge re-validates before pushing.
- `.github/workflows/` changes are a hard BLOCK.
- Updating `charts/demo` requires a separate trusted `approved_chart_digest`
  update; the Go merge recomputes it from the head tree.
- fast-forward may leave the GitHub PR unmarked as merged; verify manually
  rather than granting the guard PR write/merge API permissions.
- Post-deploy needs both `--expected-sha` and `--expected-app-sha`.
- The root-only token helper depends on the local
  `/etc/kubernetes/admin.conf`; a separate guard host needs controller-side
  rotation.
- Go `0.3.0` is built and ready to deploy, but live deployment acceptance has not
  run yet; the historical Python `0.2.3` evidence is not current Go proof.
