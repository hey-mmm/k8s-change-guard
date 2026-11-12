# Deploying k8s-change-guard

The role installs an immutable trusted release, runs the daemon as an independent
unprivileged user, grants read-only Kubernetes access, and gives the service a
short-lived TokenRequest kubeconfig. It does **not** copy the controller's
bootstrap/admin kubeconfig to the service identity.

Current release, deployment, merge/revert and post-deploy results are recorded in
`docs/acceptance.md`. This README intentionally does not copy time-sensitive
version/test/CI numbers; historical deployment notes are not current status.

## 1. Supported target

- Debian/Ubuntu only (package names and systemd paths are Debian-specific).
- `amd64` or `arm64`.
- The lab target is the control-plane host `11.0.1.10` (`master`), because the
  root-only token renewal helper uses the local
  `/etc/kubernetes/admin.conf`. If the role is deployed to a separate host,
  replace that renewal path with controller-side rotation; do not copy the
  admin kubeconfig into the service config directory.
- Production Helm rendering requires Linux bubblewrap. The lab host has
  bubblewrap `0.6.1`; the role must keep namespace creation available to the
  service user.

The role installs `bubblewrap`, `ca-certificates`, `curl`, `gzip`, `python3`,
`python3-pip`, `python3-requests`, `python3-setuptools`, `python3-venv`,
`python3-yaml`, and `tar`. Preinstalled executable Helm/kubectl are reused; a
missing binary is downloaded only with a pinned SHA-256. The role does not
install `git`, `ssh`, or `nc`, which the merge helper needs on the host.

## 2. Build the trusted artifact

```sh
# First make pyproject.toml project.version and __version__ equal to <new-version>.
VERSION='<new-version>'
scripts/build-release.sh --version "$VERSION"
# -> dist/k8s-change-guard-<new-version>.tar.gz and a SHA-256 in the JSON output
```

`--version` only changes the tarball name/JSON field; it does not modify
`pyproject.toml` or `change_guard/__init__.py`. A release whose artifact name and
package metadata disagree is not acceptable.

The tarball contains only `change_guard/`, `knowledge/`, `pyproject.toml`,
`requirements.txt`, and `config.example.yaml`. It never contains tests,
Ansible, scripts, VCS metadata, or credentials. Keep `dist/` out of Git.

Do not let Git normalize `knowledge/sources/`: `.gitattributes` sets
`knowledge/sources/* -text` because the knowledge hashes attest exact source
bytes. A CRLF checkout once caused a project CI mismatch; keep the bytes intact.

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
(`delegate_to: localhost`). The lab target is itself the control plane, so its
root-only `/etc/kubernetes/admin.conf` already exists for the fixed renewal
helper; that is a host-admin trust boundary, not a service credential.

The GitHub PAT is separate from the merge deploy key:

- PAT: repository-limited, Metadata read, Contents read, Pull requests read,
  Issues read, Commit statuses **read/write**. No Administration, Checks,
  Contents write, or Issues write (leave `report_comment: false`).
- Deploy key: one dedicated write key for the repository. It is used only by
  `python -m change_guard.merge`; it is not given to the daemon for arbitrary
  pushes.

## 4. Critical policy inputs

Set the aggregate check name as a single string:

```yaml
change_guard_merge_required_ci: "Test, lint, render"
```

Keep it a string (not a three-element list). The role defaults and example now
use this single string; `merge.py` matches one aggregate GitHub Actions check
name bound to the PR head.

Set the operator-approved chart pin to the exact `charts/demo` Git blob digest:

```yaml
change_guard_approved_chart_digest: "194baf90afd746299e256dc0bf144a12bc6f6325bacf77b40ff01e50b0c3e05d"
```

This is the real digest computed from the current `charts/demo` Git blobs; the
old parent `work/approved-chart.json` value `0b2b...` is stale and must not be used.
The digest is `sha256(canonical_json({path under charts/demo: sha256(exact git
blob bytes)}))`; CRLF/LF differences change it, and `gitops/demo/values.yaml`
is deliberately not part of the pin. A missing pin is ERROR/BLOCK; a mismatch
is BLOCK and cannot be approved. Updating a chart template requires a separate,
trusted operator update to this pin. `merge.py` recomputes it from the head tree
and refuses forged reports.

`.github/workflows/` changes are a hard BLOCK; `merge.py` independently compares
base/head workflow trees. This closes the PR-editable-workflow/CI spoof path.

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
   `/opt/change-guard/releases/<version>`, venv with a `.pth` path entry,
   `.artifact.sha256`, `.complete`, `current` symlink.
5. RBAC: namespace, ServiceAccount, node/pod cluster readers, demo workload
   reader, separate Argo CD reader.
6. token: reuse a sufficiently fresh kubeconfig or mint a `12h` TokenRequest
   on the controller, atomically install it as `0600`.
7. configure: non-secret config, PAT/DeepSeek token, proxy env, optional merge
   deploy key and known-hosts.
8. service: hardened systemd unit, enabled and started.
9. renewal: root-only helper plus 6-hour timer.
10. verify: service state, user, credential modes, token freshness, required
    reads, forbidden reads/writes.

Ansible `copy.checksum` is SHA-1 only, so the role explicitly verifies SHA-256
on the controller and again after copying. A completed version directory with
a different artifact digest is refused instead of reused. Python/knowledge
files stay `0644`; the role never recursively marks the tree `0755`.

## 6. TokenRequest renewal

- TTL: `12h` by default.
- Timer: `change-guard-token-renew.timer`, every 6 hours.
- Helper: `/usr/local/lib/change-guard/renew-service-token.py`, `0700 root`.
- Fixed command:
  `/usr/bin/kubectl --kubeconfig=/etc/kubernetes/admin.conf -n change-guard create token change-guard --duration=12h`.
- The helper atomically replaces `/etc/change-guard/kubeconfig` with mode
  `0600`, preserving server/CA; it never prints the token.
- The daemon reads the kubeconfig per kubectl invocation, so renewal does not
  require a restart.
- The service user cannot execute the helper, read `/etc/kubernetes/admin.conf`,
  or modify the timer/unit.

This is token replacement, not a Kubernetes lease extension. The merge command
uses a separate Git `--force-with-lease` compare-and-swap on the old `main` SHA.

If the host is not a control-plane node, the local helper will fail. Use
controller-side rotation instead:

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

The systemd unit uses an independent user, empty capability set,
`NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome`, `PrivateTmp`,
read-only config/release paths, and a writable state directory. It deliberately
keeps `RestrictNamespaces=false` so bubblewrap can create the namespaces needed
by `--unshare-all`. The unit does not set `RLIMIT_AS`; `MemoryHigh=1536M` and
`MemoryMax=2G` bound the cgroup, and `LimitNPROC`/`TasksMax=8192` leave room for
Go helpers. Over-hardening namespaces or setting an aggressive `RLIMIT_AS`
breaks real Helm rendering; do not trade working isolation for a score.

`sandbox_tmpfs_bytes` is currently only validated by the renderer; bubblewrap
0.6.1 has no `--size` option. Actual bounds come from output/FSIZE limits, the
child `RLIMIT_*` settings, and the service cgroup.

## 8. Idempotency and verification

```sh
ansible-playbook -i ansible/inventory.example.ini ansible/site.yml
ansible-playbook -i ansible/inventory.example.ini ansible/site.yml
```

The second recap should report `changed=0` (unless the token enters its refresh
window or a credential/input changed). The verify phase checks:

- service active and running as `change-guard` with `nologin`;
- credential files `0600`, service-owned;
- short-lived kubeconfig unexpired and readable;
- required reads work: nodes, all-namespace pods, Argo CD Applications;
- forbidden actions fail: Secrets, pod logs/exec, workload writes, Argo writes
  (subresources checked with `--subresource=log|exec`);
- installed config has string `merge_required_ci` and a non-empty
  `approved_chart_digest`; report policy binding/schema 2 is in use;
- bwrap namespace creation and a real Helm render under the same hardening.

Standalone RBAC check:

```sh
sh scripts/verify-rbac.sh /etc/change-guard/kubeconfig
```

Current deployment/merge/revert/post-deploy evidence and final acceptance are in
`docs/acceptance.md`. Historical 0.2.1 notes are kept only as history; do not
reuse their test counts or recap as current status.

## 9. Merge deploy key and post-deploy

The optional merge integration installs:

- `/etc/change-guard/merge-deploy-key` (`0600`, service-owned);
- `/etc/change-guard/github_known_hosts` (`0600`, service-owned);
- `config.yaml` keys `merge_deploy_key`, `merge_known_hosts`,
  `merge_ssh_proxy`, `merge_required_ci`, `approved_chart_digest`, and optional
  `merge_fetch_depth` (default 128).

Prefer the root wrapper from the trusted deployment directory, which pauses polling
and restores it on exit:

```sh
sudo scripts/merge-release.sh <number>
```

The wrapper stops `change-guard.service` to avoid the non-blocking state lock,
uses a `trap ... EXIT` to restore the previous polling state, and reads
`/etc/change-guard/proxy.env` after dropping to `change-guard` via `runuser`.
Direct Python is still possible, but stop the daemon/serialize first; otherwise it
may fail with `DaemonBusy`:

```sh
sudo systemctl stop change-guard.service
sudo -u change-guard \
  env HTTP_PROXY=http://11.0.1.1:7890 \
      HTTPS_PROXY=http://11.0.1.1:7890 \
      NO_PROXY='127.0.0.1,localhost,::1,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,.svc,.cluster.local' \
  /opt/change-guard/current/venv/bin/python -m change_guard.merge \
  --config /etc/change-guard/config.yaml --pr <number>
sudo systemctl start change-guard.service
```

It validates the current report schema/policy binding, exact head/base, approval,
workflow tree equality, independently recomputed chart pin, head-bound GitHub
Actions CI, synthetic parents/tree, report digest, and exact lease before pushing.
GitHub Actions `pull_request` checks are bound to the PR **head**, not the
synthetic merge commit; the command therefore queries head checks and proves the
synthetic tree equals the head tree, then fast-forwards `main` to the evaluated
head with `--force-with-lease=refs/heads/main:<old-main>`. It does not push the
synthetic commit, call the GitHub Merge API, or check out/execute candidate code.
`main` becomes a normal single-parent head; rollback is `git revert <head>` with
no `-m 1`.

After the PR is closed/merged, the daemon revokes the historical
`change-guard/release` status on the old head; a guard **error/pending** on main
or the old head may therefore be revocation, not a post-deploy failure. The merge
record plus the report/approval/CI at merge time are the gate proof; do not force
a permanent green status for appearance.

Post-deploy verifier:

```sh
sudo -u change-guard \
  /opt/change-guard/current/venv/bin/python -m change_guard.postdeploy verify \
  --config /etc/change-guard/config.yaml \
  --expected-sha <main-head-gitops-revision> \
  --expected-app-sha <image-source-commit> \
  --report /var/lib/change-guard/reports/<evaluation-id>.json
```

`--expected-sha` is the Argo/GitOps revision; `--expected-app-sha` is the image
source commit exposed by `/version`. They are normally different and both must
be supplied. The pod check matches the Pod **spec** container name/image and
verifies the runtime digest from `status.containerStatuses[].imageID`; do not use
`status.containerStatuses[].image` as the manifest reference (containerd may
report a config ID there). The verifier is read-only. On failure it returns an
`open_revert_pr` recommendation; it never rolls back or mutates the cluster.

## 10. Known deployment caveats

- The GitHub ruleset DeployKey bypass is repository-wide, not per-key. Keep
  exactly one write deploy key and audit it regularly; IR-02 cannot be fixed by
  the platform or by a per-key ruleset setting.
- GitHub success statuses have no project-defined TTL. The daemon revokes stale
  statuses while running, and the merge command re-validates; manual revocation
  is still needed if the daemon is down.
- `.github/workflows/` changes are now a hard BLOCK, and merge independently
  compares base/head workflow trees. Do not treat a green check name alone as
  proof unless the workflow tree is unchanged.
- GitHub Actions checks are bound to the PR head; synthetic merge check-runs can
  be empty. Never switch merge back to synthetic-check lookup.
- Updating `charts/demo` requires a separate trusted `approved_chart_digest`
  update. The current real digest is `194baf90...c3e05d`, not the stale
  `0b2b...` reference.
- `pyproject.toml`/`__version__` must agree with the release; `--version` only
  changes the tarball name.
- `knowledge/sources/` is pinned with `-text`; CRLF conversion changes hashes
  and has caused CI failure.
- fast-forward may leave the GitHub PR unmarked as merged; root should verify
  manually rather than granting the guard PR write/merge API permissions.
- Post-deploy needs both `--expected-sha` (GitOps revision) and
  `--expected-app-sha` (image source commit); they are usually different.
- The root-only token helper depends on the local
  `/etc/kubernetes/admin.conf`; a separate guard host needs controller-side
  rotation.
