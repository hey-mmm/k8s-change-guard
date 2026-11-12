# 运维与演示 Runbook

适用主机：`11.0.1.10`（master，guard 与项目一控制面同机）。
服务用户：`change-guard`。状态目录：`/var/lib/change-guard`。
当前运行版本、真实合并/回退/发布后结果与最终验收以 `docs/acceptance.md` 为准。
本文只描述操作，不复制时效数据；验收结论不在本文重复。

## 1. 五分钟日常检查

```sh
export REPO='hey-mmm/Full-Stack-Observability-in-Kubernetes'

systemctl is-active change-guard.service
systemctl is-enabled change-guard.service
systemctl show change-guard.service -p NRestarts -p ActiveState -p SubState
journalctl -u change-guard.service --since '-30 min' --no-pager | tail -80

systemctl list-timers change-guard-token-renew.timer --no-pager
systemctl status change-guard-token-renew.timer --no-pager

python /usr/local/lib/change-guard/check-token-expiry.py \
  /etc/change-guard/kubeconfig --min-remaining 3600

curl -fsS http://10.98.137.77:9090/-/ready
curl -fsS http://10.104.233.119:8080/readyz

# 策略绑定与 chart pin（值不应是旧 0b2b... 参考）
sudo -u change-guard /opt/change-guard/current/venv/bin/python - <<'PY'
import yaml
c = yaml.safe_load(open('/etc/change-guard/config.yaml', encoding='utf-8'))
assert isinstance(c.get('merge_required_ci'), str)
assert c.get('approved_chart_digest'), 'chart pin missing'
print('merge_required_ci =', c['merge_required_ci'])
print('approved_chart_digest =', c['approved_chart_digest'])
PY
```

期望：

- 服务 `active (running)`，没有反复重启；
- timer 下次触发在 6 小时内，最近一次 `change-guard-token-renew.service` 成功；
- token 剩余时间大于 1 小时；正常情况下应大于 6 小时；
- Prometheus 和 demo 直连成功（不经过代理）。

看最近评估：

```sh
ls -lt /var/lib/change-guard/reports | head
for f in $(ls -t /var/lib/change-guard/reports/ev-*.json | head -5); do
  jq -r '[.evaluation_id,.pull_request.number,.decision,.head_sha[0:12],.expires_at] | @tsv' "$f"
done
```

不要把报告全文贴到公开 issue；报告可能有运行证据和内部地址。

## 2. PR 与状态巡检

```sh
gh pr list --repo "$REPO" --state open \
  --json number,title,isDraft,headRefOid,baseRefName,updatedAt

# 对每个 open PR 看 guard 状态
gh api "repos/$REPO/commits/<head-sha>/statuses" |
  jq '.[] | select(.context=="change-guard/release") |
      {state,description,created_at}'
```

状态含义：

| 状态 | 含义 | 运维动作 |
| --- | --- | --- |
| `pending` | 正在评估，或 REVIEW 等待审批 | 看描述里的 evaluation id；不要重复催评估 |
| `success` + PASS | 当前报告/证据有效 | 可进入受信合并流程 |
| `success` + REVIEW approved | 当前审批绑定了该评估 | 可进入受信合并流程 |
| `failure` | BLOCK | 修 PR；不能审批覆盖 |
| `error` | 采集/渲染/模型/状态发布失败；也可能是 closed/merged PR 的历史状态撤销 | 先看 PR 状态和 merge 记录；已合并的 guard error 不等于 postdeploy 失败 |

如果状态描述是旧的 `success`，先确认 daemon 是否仍在轮询、报告是否过期。GitHub
不会因为时间过去自动把 success 改成 failure。

## 3. 6 小时 TokenRequest 续期

### 3.1 正常状态

- TokenRequest TTL：`12h`
- timer：每 `6h` 触发一次
- 最近一次成功：`systemctl status change-guard-token-renew.service`
- 剩余时间：`check-token-expiry.py ... --min-remaining 3600` 退出 0

```sh
systemctl start change-guard-token-renew.service
systemctl status change-guard-token-renew.service --no-pager
journalctl -u change-guard-token-renew.service -n 80 --no-pager
```

helper 只执行固定的：

```text
/usr/bin/kubectl --kubeconfig=/etc/kubernetes/admin.conf \
  -n change-guard create token change-guard --duration=12h
```

并原子替换 `/etc/change-guard/kubeconfig`（`0600 change-guard`），保留 server/CA。
daemon 每次调用 kubectl 重新读文件，不需要重启。

### 3.2 续期失败/即将过期

```sh
python /usr/local/lib/change-guard/check-token-expiry.py \
  /etc/change-guard/kubeconfig --min-remaining 3600
```

- 退出 1：进入续期窗口，立即手动触发 timer service，或运行 Ansible 轮换。
- 退出 2：文件不可读/不是 JWT/没有 `exp`；检查权限和 kubeconfig 结构，不要猜。

```sh
# 控制器上强制轮换（会重跑 role，需要 artifact 和 bootstrap kubeconfig）
ansible-playbook -i ansible/inventory.example.ini ansible/rotate-token.yml

# 非 Ansible 环境：在控制器生成，再按受控方式放到主机
BOOTSTRAP_KUBECONFIG="$HOME/.kube/config" \
TARGET_KUBECONFIG=/tmp/change-guard-kubeconfig \
TOKEN_TTL=12h sh scripts/rotate-kube-token.sh
```

如果 guard 不在 master 上，本机没有 `/etc/kubernetes/admin.conf`，timer 会失败；
必须改成控制器侧轮换/下发，不能把 admin kubeconfig 复制到服务配置目录。

**不要把“token 续期”说成“lease 续租”**：这是新 token 替换旧 token；合并命令里的
lease 是 Git push 的 `--force-with-lease`。

## 4. PAT 轮换

1. 在 GitHub 生成新的 fine-grained PAT，权限仍为：
   Metadata read、Contents read、Pull requests read、Issues read、
   Commit statuses read/write；不要加 Administration/Checks/Contents write。
2. 写入控制器的 staging 文件，保持 `0600`：

   ```sh
   install -m 600 /dev/null secrets/github-token
   # 用编辑器写入，不要 echo 到 shell 历史
   chmod 600 secrets/github-token
   ```

3. 重新部署，让角色复制并重启：

   ```sh
   ansible-playbook -i ansible/inventory.example.ini ansible/site.yml
   ```

4. 验证：

   ```sh
   stat -c '%a %U:%G %n' /etc/change-guard/github-token
   journalctl -u change-guard.service -n 80 --no-pager | grep -i -E 'credential|status|error' || true
   ```

5. 用一次性 SHA 做状态写探测（见 `creation-steps.md` 3.6），预期 `201`；不要拿
   `main` HEAD 做实验。确认后撤销旧 PAT。

注意：当前 fine-grained PAT 的能力检查要求 token 所属账号有 `push`/`admin`
仓库角色；协作者权限端点 403 是预期，不要为了它加 Administration。

## 5. 部署密钥轮换

部署密钥只用于 `merge.py`，不用于日常 push。

1. 生成新 ed25519 key（无口令，供 BatchMode）：

   ```sh
   umask 077
   ssh-keygen -t ed25519 -f secrets/merge-deploy-key-new -N '' \
     -C 'change-guard-merge-<date>'
   ```

2. 在项目一 Settings -> Deploy keys 添加公钥，勾选 **Allow write access**。
3. 更新控制器 staging 路径，重新部署，让角色安装 `0600`。
4. 用一条低风险 PR 走完整审批/合并，确认 `merge.py` 可用。
5. 从 GitHub 删除旧 deploy key；确认仓库只剩一把写部署密钥。
6. 审计：

   ```sh
   gh api repos/hey-mmm/Full-Stack-Observability-in-Kubernetes/keys |
     jq '.[] | {id,title,read_only,created_at}'
   ```

任何新增写部署密钥都会获得 ruleset 1 的 bypass 能力，因为 GitHub 的 DeployKey
bypass 是仓库级布尔，不是按 key ID。发现未知 key 立即按事故处理。

## 6. 升级 guard release

1. 选新版本号，绝不重用已有版本目录；同时把 `pyproject.toml` 的
   `project.version` 和 `change_guard/__init__.py` 的 `__version__` 改成同一个
   `<新版本>`。`--version` 只决定 tarball 名，不会改包内元数据。
2. 构建并记录 SHA-256：

   ```sh
   VERSION='<新版本>'
   scripts/build-release.sh --version "$VERSION"
   sha256sum "dist/k8s-change-guard-${VERSION}.tar.gz"
   ```

3. 更新 `ansible/group_vars/all.yml` 的 `change_guard_version`、artifact 路径、
   checksum；确认 `change_guard_merge_required_ci` 是字符串、`approved_chart_digest`
   是当前真实 chart pin（当前 `194baf90...`）；部署：

   ```sh
   ansible-playbook -i ansible/inventory.example.ini ansible/site.yml
   ansible-playbook -i ansible/inventory.example.ini ansible/site.yml
   ```

4. 第二次预期 `changed=0`；检查服务、token、RBAC、日志、policy binding 和 chart pin。
5. 旧 release 目录保留在 `/opt/change-guard/releases/`，便于回滚。

同一版本不同 tarball checksum 会被拒绝（`Release ... already installed with a
different artifact SHA-256`）。这是不可变 release 的保护，不要删除 `.complete`
或手改 `.artifact.sha256` 绕过。

不要把 `--version` 当成版本号同步：`pyproject.toml` 和 `__version__` 不一致时，
tarball 名和包内 `change-guard --version` 会互相矛盾，审计无法判断实际代码版本。

## 7. 标准发布演示

### 7.1 正常发布

1. 项目一功能 PR：CI 构建 `ghcr.io/hey-mmm/observability-demo:sha-<commit>`。
2. 发布 PR **只改 `gitops/demo/values.yaml`**（image digest/配置），不是 chart 自带的
   默认 values，使用 digest：

   ```yaml
   image:
     repository: ghcr.io/hey-mmm/observability-demo
     digest: sha256:<64-hex>
   ```

3. guard 轮询后发布 `pending`，随后 PASS/REVIEW/BLOCK/ERROR。
4. PASS：进入合并；REVIEW：按第 8 节审批；BLOCK/ERROR：修 PR。
5. 合并后跑发布后验证（第 9 节）。

### 7.2 BLOCK 演示

在 PR 中把副本设为 0、设置 `DEMO_STARTUP_FAIL=true`、删除 readinessProbe，或放行
非白名单镜像。等待 guard 状态为 `failure`。`.github/workflows/` 变更或
`charts/demo` 与操作员 pin 不一致也会是 BLOCK/ERROR，不可审批。**不要**在演示中尝试
用审批覆盖 BLOCK；它必须失败。

已记录的真实证据：零副本危险 PR 的 merge API 返回 405；`DEMO_STARTUP_FAIL=true`
在对应评估中解析为 `FAULT_INJECTION` BLOCK。详见
[真实拒绝证据](evidence/hard-boundary-live-rejections.json)和[验收报告](acceptance.md)。

### 7.3 REVIEW 演示

资源明显缩减、当前错误率/延迟、容量不足、AI 新风险等会进入 REVIEW。REVIEW 不是
“随便点个 approve”：必须使用当前评估 ID 的精确评论。

## 8. 精确审批与合并

### 8.1 审批

从状态描述或报告评论取得：

```text
/guard approve ev-xxxxxxxxxxxxxxxxxxxxxxxx
```

由配置的 `approvers` 在原 PR 上发一条**整条只有这个命令**的评论。审批必须：

- 作者是 allowlist 成员；
- 作者有当前写/管理权限；
- 时间在 `evaluated_at` 之后、`expires_at` 之前；
- 当前 head/base 未变；
- 不是标签、旧评论或“LGTM”。

审批后状态应变成：

```text
success  REVIEW approved by <login> [ev-...]
```

### 8.2 合并前

```sh
sudo -u change-guard /opt/change-guard/current/venv/bin/python - <<'PY'
import yaml
c = yaml.safe_load(open('/etc/change-guard/config.yaml', encoding='utf-8'))
ci = c.get('merge_required_ci', 'Test, lint, render')
assert isinstance(ci, str), f"merge_required_ci must be a string, got {type(ci)}"
assert c.get('approved_chart_digest'), 'approved_chart_digest is required'
print('merge_required_ci =', ci)
print('approved_chart_digest =', c['approved_chart_digest'])
PY
```

确认：

- PR 是 open、非 draft、base=main；
- 当前 head 的 `Test, lint, render` check run 是 GitHub Actions completed/success；
- 报告 schema 2、policy binding 与当前 guard/rule/policy 一致；
- report `chart_digest` 等于 head `charts/demo` 的 Git blob digest，且在
  `approved_chart_digest` 白名单内；
- base/head 的 `.github/workflows/` 完全一致（否则硬 BLOCK）；
- 报告未过期，当前 head/base 未变。

注意：GitHub Actions 的 `pull_request` check 绑定 **head**，不是 synthetic merge；
不要用 synthetic 的 check-runs 或普通 status 代替 head CI。`merge_required_ci`
现在在 role defaults/example 中是单个字符串；若实际配置又变成列表，先修配置。

### 8.3 执行

正常合并推荐 root 包装脚本（在受信部署目录执行；例如
`/home/myt/change-guard-deploy/scripts/merge-release.sh`）：

```sh
sudo scripts/merge-release.sh <N>
```

它会暂停 `change-guard.service`，避免 daemon 的非阻塞 state lock 与 merge 争抢；
`trap ... EXIT` 在退出时恢复原 polling 状态，并在 `runuser -u change-guard` 后读取
`/etc/change-guard/proxy.env` 再执行底层 merge。

底层 Python 仍可直接运行，但必须先停 daemon 或串行化，否则可能得到 `DaemonBusy`：

```sh
sudo systemctl stop change-guard.service
sudo -u change-guard \
  env HTTP_PROXY=http://11.0.1.1:7890 \
      HTTPS_PROXY=http://11.0.1.1:7890 \
      NO_PROXY='127.0.0.1,localhost,::1,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,.svc,.cluster.local' \
  /opt/change-guard/current/venv/bin/python -m change_guard.merge \
  --config /etc/change-guard/config.yaml --pr <N>
sudo systemctl start change-guard.service
```

成功输出 `MERGED`，记录 `strategy=fast-forward`、`merge_sha=head`、
`synthetic_merge_sha` 和 `rollback.command=git revert <head>`。失败输出 `REFUSED`，
退出 1。不要用 GitHub UI Merge 或管理员 token 直接 push 绕过；那会破坏更新入口模型。

合并记录：`/var/lib/change-guard/merges/<head>.json`。

fast-forward 推送后 GitHub 是否自动把 PR 标记为 merged 不由 guard 保证；若未自动
标记，由 root 人工核对，不要为此增加 PR write PAT 或 merge API 权限。

合并后 PR 会 closed/merged，daemon 会撤销旧 head 上的历史 `change-guard/release`
状态；因此 main/旧 head 出现 guard **error/pending** 可能只是评估撤销，不是
postdeploy 失败。门禁有效性看 merge 记录和合并当时的报告/审批/CI，不要为了好看
维持永久绿。

## 9. 发布后验证与回退

```sh
sudo -u change-guard \
  /opt/change-guard/current/venv/bin/python -m change_guard.postdeploy verify \
  --config /etc/change-guard/config.yaml \
  --expected-sha <main_head_commit> \
  --expected-app-sha <image_source_commit> \
  --report /var/lib/change-guard/reports/<evaluation_id>.json \
  --output /tmp/postdeploy.json
```

`--expected-sha` 是 Argo 应同步的 GitOps revision（merge 后的 main head）；
`--expected-app-sha` 是 `/version` 暴露的镜像源提交。两者通常不同，必须同时传；
不能用一个替代另一个。

验证器按 Pod **spec** 的容器名/image 校验期望镜像，并用
`status.containerStatuses[].imageID` 核运行 digest。containerd 的
`status.containerStatuses[].image` 可能是 config ID（`sha256:<config>`），不是
manifest 引用；不要用它判断“镜像不对”。若 `pods` 失败，先看 spec.image、imageID
和 `digest_caveats`，再看 acceptance 中的当前结果。

当前发布后证据与最终结论见 `docs/acceptance.md`；失败时验证器给出
`open_revert_pr` 建议，只读、不自动回滚。

手工核对：

```sh
kubectl -n argocd get application demo -o json |
  jq '{revision:.status.sync.revision,sync:.status.sync.status,health:.status.health.status}'
kubectl -n demo get deployment demo
kubectl -n demo get pods
```

注意：Argo revision 应等于 `main` 上的 head；镜像 index digest 与运行 Pod 的
imageID digest 在多架构场景可能不同，不能简单断言相等。

回退 PR（main 是单父 head，不加 `-m 1`）：

```sh
export BAD_HEAD='<bad main head sha>'
git fetch origin main
git switch -c "revert/${BAD_HEAD:0:12}" origin/main
git revert --no-edit "$BAD_HEAD"
git push origin "HEAD:revert/${BAD_HEAD:0:12}"
gh pr create --repo "$REPO" --base main \
  --head "revert/${BAD_HEAD:0:12}" \
  --title "Revert ${BAD_HEAD:0:12}" \
  --body "Revert the release that failed post-deploy verification."
```

回退 PR 仍走 guard + 审批 + merge，不允许直接改集群或让模型自动回滚。

## 10. 事故处理

### 10.1 daemon 停机，GitHub 上仍有旧 success

这是最危险的窗口。GitHub 状态没有 TTL。

1. 暂停所有合并操作；
2. 恢复 daemon：

   ```sh
   systemctl restart change-guard.service
   journalctl -u change-guard.service -n 100 --no-pager
   ```

3. 确认当前 PR 的 head/base 和报告有效期；不要只看旧 success；
4. 必要时由管理员把旧状态改成 error/pending（使用管理凭据，不要让服务 PAT 具备
   额外权限）：

   ```sh
   gh api --method POST \
     "repos/$REPO/statuses/<head-sha>" \
     -f state=error \
     -f context=change-guard/release \
     -f description='Stale evaluation revoked manually'
   ```

5. 重新评估并走 `merge.py`；不要用管理员 push 代替。

### 10.2 token 过期

- 症状：daemon 日志出现 Kubernetes 401/403、证据采集 ERROR、状态 error；
- 处理：手动触发续期或 Ansible 轮换；确认 `check-token-expiry` 退出 0；
- 不要重启服务来“刷新 token”；token 是文件，重启不会变新。

### 10.3 代理/网络

- GitHub 走 `HTTP_PROXY/HTTPS_PROXY`；集群内地址走 `NO_PROXY`；
- `service_github_via_proxy`、`service_internal_prometheus_direct` 可手工 curl 验证；
- 如果 `nc` 缺失，`merge.py` 的 SSH ProxyCommand 会失败；安装 netcat-openbsd。

### 10.4 ruleset 漂移

```sh
gh api repos/$REPO/rulesets |
  jq '.[] | {id,name,enforcement}'
gh api repos/$REPO/rulesets/<id> |
  jq '{bypass_actors,rules,current_user_can_bypass}'
```

必须恢复：

- ruleset 1 只有 DeployKey bypass；
- ruleset 2 无 bypass；
- contexts 仍是 `change-guard/release`、`Test, lint, render`；
- 普通用户 `current_user_can_bypass=never`。

### 10.5 部署密钥/PAT 泄漏

1. 立即在 GitHub 撤销对应 deploy key/PAT；
2. 停止服务，轮换凭据，重新部署；
3. 检查 `main` 最近提交、ruleset 变更、Actions run 和 merge 记录；
4. 如果部署密钥泄漏，假定它可以绕过更新入口；按安全事件升级，不要只改密码。

### 10.6 guard 主机被入侵

服务用户拥有 GitHub deploy key 和状态写 PAT，属于信任边界。处置：

- 停止 systemd 服务和 timer；
- 撤销 PAT、deploy key；
- 轮换 TokenRequest/DeepSeek key；
- 保留 `/var/lib/change-guard` 证据，检查 reports/merges；
- 检查集群只读权限之外的异常；guard 本身没有写权限，但不能假设主机未被改。

## 11. 已知限制（运维必须知道）

1. 当前版本、部署、真实合并、回退和发布后状态以 `docs/acceptance.md` 为准；本文
   不复制权威时效数据，也不把历史版本的测试/部署数字当现状。
2. GitHub success 状态没有分钟级 TTL；daemon 停机时旧状态仍在，靠 merge 前重校验
   和人工撤销兜底。
3. DeployKey bypass 是仓库级，不能平台限制到单 key；仓库只能有一把写部署密钥，
   必须定期审计。
4. `.github/workflows/` 变更现在是不可审批的硬 BLOCK，merge 还会独立复核；
   这是对“PR 可改 workflow 伪造 CI”的修复，不是可选加固。
5. `charts/demo` 受操作员 `approved_chart_digest` pin 约束。当前真实 pin 是
   `194baf90afd746299e256dc0bf144a12bc6f6325bacf77b40ff01e50b0c3e05d`；旧
   `0b2b...` 参考值不可用。更新模板必须另行审查并更新 pin。
6. `pyproject.toml` 和 `__version__` 必须同步；`--version` 只影响 tarball 名，
   不能替代元数据。
7. root-only 续期 helper 依赖 master 本机 `/etc/kubernetes/admin.conf`；独立主机
   需改用控制器轮换。
8. 单 worker、本地 PVC，没有节点/磁盘容灾；增加副本不等于高可用。
9. 发布后失败只建议 Git revert PR，不自动回滚、不直接改集群；main 是单父 head，
   回退不加 `-m 1`。
10. `--expected-sha` 是 Argo/GitOps revision，`--expected-app-sha` 是镜像源提交，
    两者通常不同，必须同时传。
11. fast-forward 后 GitHub 可能不会自动把 PR 标记为 merged；由 root 人工核对，
    不要为此给 guard 增加 PR write PAT。
12. `knowledge/sources/` 用 `-text` 保持精确字节；CRLF 转换会改变摘要并导致 CI
    失败，不要把换行归一化当作修复。
13. `sandbox_tmpfs_bytes` 目前只是配置项；bwrap 0.6.1 没有 `--size`，实际边界靠
    RLIMIT/输出限制和 systemd cgroup。
14. 服务是轮询模式，没有公网 webhook；状态更新有轮询间隔和网络延迟。

## 12. 演示口径

演示时只展示真实结果：

- 可以展示 pending -> success/failure 的状态变化；
- 可以展示 BLOCK PR 被拒绝；
- 可以展示精确 `/guard approve <evaluation_id>` 和 `merge.py` 的 lease；
- 可以展示发布后 Argo/Deployment/HTTP/metrics；
- **不要**展示尚未跑过的“CI 已通过”“最终验收通过”或伪造的 commit；
- 失败就说失败，记录日志和下一步，不用模型或人工审批把 BLOCK 变绿。
