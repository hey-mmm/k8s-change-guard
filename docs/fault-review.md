# 故障复盘：开发、部署与验收中遇到的问题

本文保留 Python `0.2.x` 开发、部署和验收的历史问题。Go `0.3.1` 已修复 0.3.0 的
`check-token` 参数顺序问题，完成部署级 live、危险 PR8 BLOCK 和 PR9 REVIEW 精确
审批；但正式 merge 先因评估 ID 缺省被拒绝、显式 ID 后匿名 CI 403，`main` 未变。
当前 Go `0.3.2`（commit `41f2ba1`）修复这两个合并缺陷，已完成两遍 Ansible 和
完整真实验收；发布和回退各通过 6/6 postdeploy，见 [最终验收](go-acceptance-final.md)。历史 Python 的真实
merge/回退/发布后结果见 `docs/acceptance.md`，不能当作 Go 版本的完整上线证明。

## 0. Go 迁移备注（2026-11-12）

- 运行入口改为单个静态 Go 二进制；Ansible 不再创建 venv、不再安装 Python 包，也不再
  调用 `change_guard.*` 模块。
- token 续期/到期检查改为 Go `renew-token` / `check-token`，systemd 指向
  `/opt/change-guard/current/k8s-change-guard`。
- 健康、验收、场景矩阵、RBAC、token 轮换脚本改为 shell，不再调用 Python。
- 新增 `testdata/python-oracle.json` 作为 151-case 冻结决策 oracle；Go 测试直接读取，
  运行时不依赖 Python。
- 修复 Windows `build-release.ps1` 的 GOOS/`go run` 与 cwd 回归；staging 删除前校验
  路径位于临时根目录。
- 0.3.0 首次真实 Ansible 部署在 `check-token KUBECONFIG --min-remaining ...` 失败
  （Go `flag` 在首个位置参数停止解析），已回切 Python `0.2.3`。修复为兼容两种顺序，
  增加 `TestCheckTokenFlagsBeforeAndAfterPath`，并升版 0.3.1 以避开不可变目录冲突。
- 0.3.1 部署成功并完成 PR8/PR9 部分验收；正式 merge 因 `merge-release.sh` 漏传
  `--evaluation-id` 和匿名 CI 403 被拒绝，`main` 未变。0.3.2 在 state lock 内取当前
  索引评估、CI 使用现有 token，并保留固定 URL/禁 redirect/2 MiB/head-app 校验。
- 详细文件、测试与部署边界见 `go-migration.md`。

## 1. 历史 Python 证据等级

| 证据 | 结果 | 能说明什么 |
| --- | --- | --- |
| 项目二 `b96937e`（Python 0.2.3） | 已推送 | 历史 Python 实现；包含 postdeploy 容器镜像修复 |
| Actions run `43193175196` | 成功 | 0.2.3 的 GitHub Actions 成功 |
| 上级 `work/final-0.2.3-deployment.json` | 0.2.3 已部署 | 部署探针、版本/policy binding、active |
| 上级 `final-0.2.3-deploy.txt` | `ok=87 changed=11` | 0.2.3 首次部署 |
| 上级 `final-0.2.3-idempotent.txt` | `ok=75 changed=0 failed=0` | 0.2.3 幂等 |
| 当前测试 | `182 tests OK (skipped=3)` | 0.2.3 回归；以 CI/acceptance 为准 |
| `docs/evidence/merge-pr-2.json` | `MERGED`，fast-forward | 真实 PR2 合入 main `e6064c5...` |
| `docs/evidence/postdeploy-e606...json` | 6/6 pass | 0.2.3 验证器；app 7/7，rps 1.877，error 0，p95 .00475 |
| `docs/evidence/merge-pr-6.json` | `MERGED`，fast-forward | 真实 revert PR6 合入 main `321eb95...` |
| `docs/evidence/postdeploy-initial-containerd-false-negative.json` | pods fail | 历史误报：containerd configID，不是真镜像错误 |
| `docs/evidence/hard-boundary-live-rejections.json` | PR3/4/5 BLOCK + 405 | CI 绿仍被硬边界挡住，均关闭 |
| `docs/evidence/github-ci-head-binding.json` | head 有 check、synthetic 为 0 | GitHub Actions check 绑定 PR head |

0.2.1 的 174 tests、0.2.2 的 181 tests、0.2.3 的 182 tests 都只作为历史 Python 证据
保留。Go `0.3.0` 的 Windows/Linux 测试、151-case 对照和 25/25 场景矩阵已完成，但
首次部署因 `check-token` 参数顺序失败并回切；修复后升版 `0.3.1`，已完成部署级
验证（两遍 Ansible、服务、RBAC、timer、renew、knowledge、collect、render、DeepSeek、
`daemon --once`），并完成 PR8 BLOCK 和 PR9 REVIEW 审批；正式 merge 被安全拒绝，
`main` 未变。0.3.2 修复合并路径后已完成部署级 verify，完整 live/PR/发布/回退结论已写入 [最终验收](go-acceptance-final.md)。

## 2. 问题总表

| ID | 问题 | 影响 | 状态 |
| --- | --- | --- | --- |
| F-01 | 项目二初始空仓库/无 commit | 无法配置依赖分支的 required checks、无法跑 CI | 已解决：0.2.3 `b96937e` + run `43193175196` |
| F-02 | GitHub Git blob 的 base64 带换行 | 候选树读取失败，PR 无法评估 | 已修，含回归测试 |
| F-03 | PAT 缺 Commit statuses 写权限 / 协作者权限端点 403 | 状态 POST 403；审批权限检查被误判 | PAT 已更换；不申请 Administration |
| F-04 | bwrap 0.6.1 与初版 systemd hardening 不兼容 | Helm 渲染在 bwrap 启动前失败 | 已按 0.6.1 能力调整并实测 |
| F-05 | TokenRequest 12h 到期后服务失效 | 12h 后 Kubernetes 采集全部失败 | 已加 root-only 6h 续期 timer |
| F-06 | 不可变 release/幂等与同版本漂移 | 旧代码被静默复用或文件权限错误 | 已加 checksum/`.complete`/漂移拒绝 |
| F-07 | 知识库 CRLF 被 Git 转换 | 摘要/CI 失败，构建与 CI 字节不一致 | 已加 `.gitattributes knowledge/sources/* -text` |
| F-08 | PR check 绑定 head，synthetic 无 check | 旧 merge 查 synthetic 永远缺 CI | 已改为 head CI + fast-forward |
| F-09 | PR 修改 CI workflow 伪造检查 | CI 门禁可被同仓库写权限作者绕过 | 已修：硬 BLOCK + merge 独立复核 |
| F-10 | chart 模板动态/条件渲染与 pin 错误 | guard 可能信任非操作员模板 | 已加 `approved_chart_digest`，当前 `194baf...` |
| F-11 | 缓存报告未绑定 guard/rule/policy | 升级后可能复用旧 PASS | 已加 schema 2 / policy binding |
| F-12 | DeployKey bypass 是仓库级 | 任何写部署密钥都能绕过更新入口 | 平台限制；只保留一把写 key 并审计 |
| F-13 | GitHub success 状态没有 TTL | daemon 停机时旧绿色状态仍在 | 设计限制；merge 前重校验 + 人工撤销 |
| F-14 | GitOps revision 与镜像源提交混淆 | 发布后验证可能用错 SHA | 已加 `--expected-app-sha`，必须同时传 |
| F-15 | Windows symlink 测试跳过/全链路验收 | 本地通过不等于 Linux/全链路 | 0.2.3 已部署/合并/回退/postdeploy；最终结论与 revert postdeploy 以 acceptance 为准 |
| F-16 | Go `check-token` 只接受 flag 在前 | 0.3.0 首次 Ansible token 检查 `rc=2`，token/verify/timer 均会失败 | 已修：兼容位置参数在前/flag 在前 + CLI 回归；升版 0.3.1，0.3.0 保留 |
| F-17 | 0.3.1 merge 可选评估 ID 未实现 | 正式发布 `REFUSED: invalid evaluation id`，`main` 未变 | 已修（0.3.2）：在 state lock 内取当前索引；显式只接受当前记录 |
| F-18 | 0.3.1 CI check-runs 匿名查询 | 共享出口配额耗尽时 403 `public CI check lookup failed` | 已修（0.3.2）：用现有 `github.token`；不改 URL/redirect/2 MiB/head-app 校验 |
| F-19 | AI 把未改的脱敏 env 当新风险 | PR9 产生一条误报，增加人工核对 | 已由独立 reviewer 用 base/head blob 证伪；AI 风险只到 REVIEW，不能自批 |

## 3. F-01：空仓库阻塞 CI 与分支保护（已解决）

**现象**：项目二初始没有 `main` 分支/提交，GitHub API 返回
`Git Repository is empty`；无法创建依赖分支的 required checks，也无法运行 CI。

**修复**：项目二已推送实现提交，当前 0.2.3 为 `b96937e`；其 GitHub Actions
run `43193175196` 成功。项目一 ruleset 已实际生效：危险 PR 的 merge API 返回 405，
直接更新 main 返回 422（见 `restriction-proof.json`）。

**注意**：CI 成功只证明该提交通过 CI；当前 0.2.3 的部署、真实合并/回退/发布后
结果见 `docs/acceptance.md`，不要用某个历史 run 代替完整验收。

## 4. F-02：GitHub base64 换行导致候选树读取失败

**现象**：真实 PR 探测时，`github._fetch_blob` 拒绝 GitHub 返回的 blob 内容；
GitHub API 的 `content` 字段按固定列宽换行，直接用严格 base64 解码会失败。

**修复**（`change_guard/github.py`）：

```python
raw = base64.b64decode(''.join(content.split()), validate=True)
```

仍然保留：只去掉传输空白、`validate=True`、校验响应 `size`、tree entry `size` 和
Git blob SHA-1、超限拒绝。

**验证**：`tests/test_transport_regression.py` 覆盖折行 base64。

## 5. F-03：PAT 权限与审批权限端点

**现象 A**：早期 token 读取仓库/评论返回 200，但 `POST /statuses/<sha>` 返回
403；GitHub 接受了权限声明，实际 token 没有 Commit statuses 写能力。

**现象 B**：`GET /repos/.../collaborators/hey-mmm/permission` 返回 403
`Resource not accessible by personal access token`，因为 fine-grained PAT 没有
Administration: read。

**修复/策略**：

- fine-grained PAT 的 Commit statuses 必须是 **Read and write**；只有 read 或
  Checks 写权限不够；
- 个人仓库审批不依赖协作者权限端点：读取当前仓库元数据，要求
  `owner.type == "User"`、`owner.login` 与评论作者一致、评论
  `author_association == "OWNER"`；
- 组织/非 owner 仍走显式权限端点；拿不到权限时 fail closed，不把 403 当有权限；
- 不增加 Administration、Checks、Contents write 等无关权限。

**验证**：用一次性 SHA 做状态写探测，预期 201；不要用 `main` HEAD。开发记录显示
后续状态 POST 已返回 201。fine-grained PAT 不返回 `X-OAuth-Scopes`，启动检查仍
把状态写标为 `inferred`；只有真实发布/显式探测才能证明。

## 6. F-04：bubblewrap 0.6.1 与 systemd hardening

**现象**：早期 systemd 过度限制 namespace 后，bwrap 在 Helm 启动前失败；另一类
失败是 Go 的 Helm/kubectl 在低 `RLIMIT_AS`/NPROC 下无法启动。

**根因/修复**：

- bwrap 需要 user/mount/net/pid/ipc/uts namespace；unit 保留
  `RestrictNamespaces=false`，只靠独立用户、空 capabilities、`NoNewPrivileges`、
  只读系统/配置/源码、私有 tmp 和 cgroup 内存限制约束；
- 实验机是 bubblewrap **0.6.1**，没有 `--size`；不能声称 tmpfs 已精确限额；
- 不设置 systemd `RLIMIT_AS`；使用 `MemoryHigh=1536M`、`MemoryMax=2G`；
- `LimitNPROC=8192`、`TasksMax=8192`，避免 Go helper 起线程被误杀；
- `SystemCallFilter` 显式允许 bwrap 需要的 mount/unshare/pivot_root 等；
- renderer 自身仍设置 `RLIMIT_AS`/`RLIMIT_FSIZE`/`RLIMIT_CPU`/`RLIMIT_NOFILE`。

**验证**：0.2.1 部署证明显示 `systemd-analyze exposure 2.4 OK`、bwrap/真实
Helm 渲染成功、服务不能读 `/etc/kubernetes/admin.conf`、`/root`、`/home/myt`。

**残留**：`sandbox_tmpfs_bytes` 目前只是配置项，bwrap 0.6.1 无 `--size`；实际
边界靠输出上限、`RLIMIT_FSIZE` 和 systemd cgroup，不能写成“tmpfs 精确限额”。

## 7. F-05：TokenRequest 12 小时到期

**现象**：服务 TokenRequest kubeconfig 只有 12 小时有效期；到期后 Kubernetes 读取
失败，daemon 报 ERROR，但服务进程可能仍是 active。

**修复/实现**：

- root-only Go `change-guard renew-token`（二进制 `0755 root`）；
- 固定命令：
  `/usr/bin/kubectl --kubeconfig=/etc/kubernetes/admin.conf -n change-guard create token change-guard --duration=12h`；
- 原子替换 `/etc/change-guard/kubeconfig`（`0600 change-guard`），保留 server/CA，
  不打印 token；
- timer 每 6 小时触发，12h TTL 留 6h 余量；
- service 用户不能执行 helper、不能读 admin.conf、不能改 timer/unit；
- Ansible 普通运行检查剩余时间，不超过 `7200s` 时轮换。

**验证**：0.2.1 证明记录手动触发 `Result=success`、`ExecMainStatus=0`、
`remaining_seconds=43199`、timer enabled/active。

**边界**：helper 依赖 guard 主机本机 `/etc/kubernetes/admin.conf`（实验在 master）；
独立主机必须改成控制器侧轮换。这是“新 token 替换旧 token”，不是 Kubernetes
Lease 续租；合并里的 lease 是 Git `--force-with-lease`。

## 8. F-06：release 幂等与同版本漂移

**问题/修复**：

- Ansible `copy.checksum` 是 SHA-1，不能作为安全边界；角色在控制器和主机两侧都
  显式算 SHA-256；
- 已完成版本目录带 `.complete` 和 `.artifact.sha256`；同版本不同 SHA-256 直接拒绝；
- venv 用 `--system-site-packages` + `.pth` 指向不可变 release，不依赖旧 pip；
- 目录 `0755`、文件 `0644`，不递归 chmod；拒绝路径逃逸/symlink/可执行源码；
- 预装 Helm/kubectl 可用则复用，缺失才按固定 checksum 下载。

**验证**：0.2.1 证明首次 `ok=87 changed=12`、第二次 `ok=75 changed=0`；旧 release
`0.1.2/0.1.3/0.2.0` 目录未被修改；同版本漂移拒绝有历史记录。

## 9. F-07：知识库 CRLF 导致摘要/CI 失败

**现象**：`knowledge/sources/` 的摘要引用依赖精确文件字节；Git 在 Windows/不同
checkout 上做 CRLF 转换后，SHA-256 与仓库记录不一致，项目二 CI 失败。

**修复**：`.gitattributes` 增加：

```gitattributes
* text=auto eol=lf
*.sh text eol=lf
# Knowledge hashes attest exact snapshot bytes, including source line endings.
knowledge/sources/* -text
```

`0ee9502` 的提交信息是 “Preserve attested source bytes across checkout platforms”。

**验证/要求**：

```sh
git check-attr text -- knowledge/sources/drills.md
# text: unset
git ls-files --eol knowledge/sources
```

不要用“把知识库换行统一”修复；那会改变被引用的原文摘要。构建、CI、部署必须使用
同一份精确字节。

## 10. F-08：GitHub Actions check 绑定 PR head，不是 synthetic merge

**真实发现**（`docs/evidence/github-ci-head-binding.json`）：

- PR #2 head `e6064c5...` 的 check-runs 有 `Test, lint, render` success；
- synthetic merge `6809c2a...` 的 check-runs 是 `[]`；
- 虽然 Actions checkout 的是 synthetic merge，但 `pull_request` check 绑定 head。

旧 Python merge 查询 synthetic 的 check-runs，真实环境永远缺 CI；向 synthetic 写
required status 也不会成为 main 上 head 的状态。详见上级
`work/merge-runtime-fix-notes.md`。

**最终 0.2.2/0.2.3 语义**：

1. 保留 report/policy/审批/TTL/workflow/chart pin 校验；
2. `compare.merge_base_commit.sha == base`，证明 base 是 head 祖先；
3. 读取 PR synthetic merge，核验 parents `[base, head]`；
4. 核验 synthetic tree == head commit tree；
5. 查 **head** 的 `Test, lint, render` check-run，要求 GitHub Actions、
   completed/success、`head_sha` 匹配、响应完整；
6. 临时 bare repo fetch head/base，核验本地 head tree、base 存在、祖先关系；
7. fresh 校验后把 `change-guard/release=success` 写到 head；
8. exact lease 快进推送 `<head>:refs/heads/main`，不推 synthetic；
9. merge record 的 `merge_sha == head`，rollback 是普通 `git revert <head>`。

**验证**：`tests/test_merge.py` 覆盖 synthetic tree/parents、head CI、fast-forward
URL/lease、record/rollback。真实闭环：
`docs/evidence/merge-pr-2.json` 显示 PR2 head `e6064c5...` 以 fast-forward 合入
main（GitHub `merged=true`）；`docs/evidence/merge-pr-6.json` 显示 revert PR6 head
`321eb95...` 同样 fast-forward 合入，`merge_sha == head`、`github_merge_api_used=false`。

**注意**：直接推送 head 后 GitHub 的 PR merged 标记以 GitHub 实际状态为准；不要
为此增加 PR write PAT 或 merge API 权限。

## 11. F-09：PR 修改 CI workflow 伪造检查（IR-01，已修）

**问题**：项目一 `pull_request` 使用 PR 分支上的 workflow；旧 ruleset/merge 只按
`Test, lint, render` 名称和 `github-actions` app 判断成功。同仓库写权限作者可以把
job 改成空操作，仍得到同名成功检查。

**修复（0.2.1/0.2.2，见上级 `work/security-fix-notes.md`）**：

- daemon 比较 base/head Git tree 的 `.github/workflows/` path/mode/kind/blob SHA；
  任何变更加 `WORKFLOW_CHANGE_BLOCKED`，severity **BLOCK**，不可审批；
- `_build_context()` 同时用 tree signature，不依赖可能截断的 changed path 列表；
- `_load_valid_cached()` 拒绝记录 workflow 变更的旧 PASS；
- 旧 merge 程序独立调用 Git Trees API 比较 base/head，不信任报告结论；报告记录
  `workflow_changed=true` 也拒绝。

**证据/测试**：`tests/test_daemon.py`、`tests/test_merge.py` 覆盖 workflow 硬阻断、
伪造 PASS 不复用、merge 独立 tree 检查。真实证据
`docs/evidence/hard-boundary-live-rejections.json`：PR4（workflow 变更）在 CI
`Test, lint, render` 为 success 时仍为 BLOCK、merge API 405，并已关闭未合并。

## 12. F-10：chart pin 与动态条件渲染

**问题**：`charts/demo` 模板变化可能改变实际部署资源，单次 values 渲染不能证明
模板行为；旧参考上级 `work/approved-chart.json` 的 digest 与真实 Git blob 字节不一致。

**修复/事实**：

- 新增 `approved_chart_digest`（单个/列表），算法：
  `sha256(canonical_json({路径相对 charts/demo: sha256(精确 Git blob 字节)}))`；
- 精确字节不经过 checkout，不做 CRLF/LF 归一化；`gitops/demo/values.yaml` 不纳入
  pin，仍参与渲染和全部普通规则；
- 缺失 pin：ERROR（`APPROVED_CHART_DIGEST_NOT_CONFIGURED`）；不匹配：BLOCK
  （`APPROVED_CHART_DIGEST_MISMATCH`），不能审批；
- merge 从 head tree 独立重算，要求报告 `chart_digest` 与实际一致且在白名单；
- 模板升级必须由操作员另行、受信地更新 pin，guard 不自动信任。

**真实拒绝**：`docs/evidence/hard-boundary-live-rejections.json` 中 PR5（chart
变更）在 CI 绿时仍为 BLOCK（`APPROVED_CHART_DIGEST_MISMATCH`/`TEMPLATE_FILE_CHANGE`）、
merge API 405，并已关闭未合并。

**真实 digest**：

```text
194baf90afd746299e256dc0bf144a12bc6f6325bacf77b40ff01e50b0c3e05d
```

来源：`docs/evidence/chart-digest-main-823770e.json`、上级 `work/chart-digest-main.json`，
由 GitHub Git Trees/Blobs API 与 `git cat-file` 两种方式确认。旧
`0b2b19a416a9a59d9b89ef0b78a81f7dfa28cfc557c534e5eaaf6ed3a3b780a0` 的
`templates/NOTES.txt` / `_helpers.tpl` 与真实 blob 不一致，**未使用**。

## 13. F-11：报告缓存未绑定 guard/rule/policy

**问题**：旧 schema 1 报告只绑定 head/base/TTL；代码、规则或策略配置变化后可能
复用旧 PASS。

**修复**：

- `SCHEMA_VERSION=2`；报告写 `guard_version`、`rule_version`、`policy_binding`、
  `policy_digest`、`approved_chart_digests`、`workflow_changed`；
- policy digest 只纳入明确列出的策略字段（approvers、chart pin、阈值、端点、超时、
  Argo/demo 配置等），排除凭据值/路径、state_dir、poll_seconds 等运行性配置；
- `_load_valid_cached()` 比较 schema/binding/guard/rule/policy digest/report digest/
  workflow/chart pin；
- 旧 merge 程序在初始、push 前 15s、13s 校验都使用当前 policy binding；不一致拒绝。

**验证**：0.2.1 证明显示所有报告 schema 2、policy binding/chart pin 匹配；旧
schema 1 缓存自然失效并重评。测试覆盖代码/规则/策略升级使旧报告失效。

## 14. F-12：DeployKey bypass 的仓库级范围（IR-02）

**事实**：GitHub ruleset 的 DeployKey bypass 是仓库级 actor（REST 读回
`actor_type: DeployKey, actor_id: null`；GraphQL `deployKey: true` 只能 `ALWAYS`），
不能按某一把 key 收窄。

**影响**：任何拥有写权限的部署密钥都能绕过 ruleset 的 update/deletion/
non-fast-forward/PR 限制；ruleset 2（required checks）没有 bypass，仍要求
`change-guard/release` 和 `Test, lint, render`。

**约束**：项目一仓库只保留一把专用写部署密钥；定期审计
`GET /repos/{owner}/{repo}/keys`，发现未知 `read_only=false` 立即撤销；部署密钥
泄漏按安全事件处理。文档不能把该 bypass 描述成“只允许 merge 程序的 key”。

## 15. F-13：旧 success 状态没有 TTL

**事实**：GitHub commit status 不会因时间过去自动失效；head 不变时旧 success 仍
被分支保护看到。

**缓解**：daemon 在报告过期后主动改旧状态；merge 程序推送前重新读取
report/policy/审批/head/base/CI/workflow/chart pin，并用旧 main SHA lease；但 daemon
停机时无法撤销旧状态，人工必须把旧 success 改为 error/pending。不能声称“状态会
自动过期”。

**合并后的正常撤销**：PR closed/merged 后，daemon 会撤销该 PR/旧 head 上的历史
`change-guard/release` 状态，因此 main 或旧 head 出现 guard error/pending 可能只是
报告撤销，不是 postdeploy 失败。门禁有效性看 merge 记录和合并当时的报告/审批/CI，
不要为了好看保持永久绿。

## 16. F-14：发布后验证的 GitOps revision 与镜像源提交不同

**问题**：`--expected-sha` 是 Argo 应同步的 GitOps revision（发布 PR 的 main head）；
`/version` 的 `gitSha` 是构建镜像的**应用代码提交**。两者通常不同。只传一个会导致
错误的 provenance 校验。

**修复**：旧 postdeploy 新增 `--expected-app-sha`；未提供时默认使用
`--expected-sha`（兼容旧命令），但正式发布必须显式同时传：

```sh
--expected-sha <main-head>
--expected-app-sha <image-source-commit>
```

`--expected-image`/`--report` 用于镜像 digest；验证器只读，失败给
`open_revert_pr`。

## 17. F-15：测试通过不等于 Linux/全链路验收

- Windows 开发机有 3 个 symlink 测试跳过；
- 历史：0.2.1 为 174 tests，0.2.2 为 181 tests；当前 0.2.3 为 182 tests
  且 CI run `43193175196` 成功；
- 0.2.3 已完成部署/幂等、真实 PR2 fast-forward 合并、0.2.3 发布后验证、真实
  revert PR6 合并；revert 后的 postdeploy 当时仍在运行，结果以 acceptance 为准；
- 真实硬边界拒绝：PR3（零副本/startup fail）、PR4（workflow）、PR5（chart）
  均为 BLOCK + merge 405，CI 绿仍被挡住，均已关闭未合并；
- `docs/acceptance.md` 由 root 负责最终结论，本文只记录闭环事实，不替 root
  宣布最终接受结论。

## 18. 做得对、不要回退的地方

- 硬规则 BLOCK 不允许 AI 或人工评论覆盖；
- workflow 变更硬 BLOCK，chart pin 不匹配硬 BLOCK；
- 模型失败/引用错误是 ERROR，不是 PASS；
- 证据缺失/过期/非数不解释成 0；
- 候选代码不在受信进程执行，Helm 始终在 bwrap 内；
- 不把 admin kubeconfig 复制给服务；
- 不因为“分数好看”关掉 bwrap 需要的 namespace；
- 合并失败不降级为管理员直接 push；
- 发布后失败只建议 revert PR，不自动改集群；
- 文档不写凭据值，也不把未跑过的 CI/验收写成已完成。

## 19. 收尾事项（不由本文宣布）

1. 等 revert 后的 postdeploy 结果，不要提前写通过；
2. root 在 `docs/acceptance.md` 写最终接受/不接受结论、PR 链接和完整证据索引；
3. 若改用独立 guard 主机，重新设计 TokenRequest 轮换（当前 helper 依赖 master
   本机 `/etc/kubernetes/admin.conf`）。

## 20. 版本与命令注意

- 示例版本统一写 `<新版本>`；发布前让 `internal/guard/common.go` 的 `Version` 等于该版本；
- `build-release.sh --version` 只改 tarball 名/JSON，不改二进制内版本；
- 正常发布修改 `gitops/demo/values.yaml`，不是 `charts/demo` 自带默认 values；
- 回退普通 head 用 `git revert <head>`，不加 `-m 1`；
- 所有合并/发布后命令以当前版本实际 `--help` 和 `docs/acceptance.md` 的记录为准；正常
  合并优先用 `sudo scripts/merge-release.sh <PR>`。

## 21. 真实闭环（0.2.3，2026-11-12）

以下是历史问题之后的真实闭环；最终 acceptance 结论仍由 root 写。

### 21.1 0.2.3 部署

- commit `b96937e`，Actions run `43193175196` 成功，`182 tests OK (skipped=3)`；
- 上级 `work/final-0.2.3-deployment.json`：0.2.3、artifact SHA、policy binding、
  chart pin `194baf...`、服务 active；
- `final-0.2.3-deploy.txt`：`ok=87 changed=11 failed=0`；
- `final-0.2.3-idempotent.txt`：`ok=75 changed=0 failed=0`。

### 21.2 PR2 真实 fast-forward 合并

`docs/evidence/merge-pr-2.json`（0.2.2 执行）：

- head `e6064c5df42ab701fac6a1e1be4bfac467a0410d`；
- base `823770eff4e9384ceb83aa1561f9b5f95239c221`；
- `strategy=fast-forward`、`merge_sha=head`、`github_merge_api_used=false`；
- synthetic `6809c2a...` 的 tree 等于 head tree；
- 评审结果 REVIEW，审批后合并；GitHub `merged=true`；
- main 变为 head `e6064c5...`，不是 synthetic merge commit。

### 21.3 0.2.3 发布后验证（PR2）

`docs/evidence/postdeploy-e6064c5...json`：

- 6 项全 pass：argo、deployment、pods、endpoints、http_version、metrics；
- `--expected-sha=e6064c5...`，`--expected-app-sha=823770e...`；
- `/version` gitSha 为 `823770e...`，与 GitOps revision 不同；
- `/healthz`、`/readyz`、`/version`、`/metrics`、`/work` 及 SLI 标签检查 7/7 PASS
  （`docs/evidence/release-app-acceptance.txt`）；
- 观测 60s：request_rate `1.877127...`，error_ratio `0.0`，p95 `0.00475`，
  firing_alerts 为空。

### 21.4 首次 postdeploy 假失败与修复

首次 0.2.2 验证器在 `pods` 报 “does not run the expected image”，仅此一项 fail；
`docs/evidence/postdeploy-initial-containerd-false-negative.json` 保留原样。

根因：containerd 的 `status.containerStatuses[].image` 是 **config ID**
（`sha256:<config>`），不是 manifest 镜像引用；Pod `spec.containers[].image` 和
`status...imageID` 实际正确。

修复（0.2.3）：按 Pod **spec** 的容器名/镜像匹配目标，并用 `imageID` 校验运行
digest；新增 containerd config ID 回归测试。修复后 0.2.3 的 6/6 pass 即上面的
postdeploy 证据。不要再用 `status.image` 判断镜像错误。

### 21.5 真实 revert PR6

- `docs/evidence/revert-pr.json`：PR6，revert `e6064c5...`，head
  `321eb9517b83dc0e9261e16dcdb26016332dd7c3`；
- `docs/evidence/merge-pr-6.json`（0.2.3 执行）：fast-forward，
  `merge_sha=head=321eb95...`，`github_merge_api_used=false`；
- main 现在是 `321eb9517b83dc0e9261e16dcdb26016332dd7c3`；
- revert 后的 postdeploy 已完成：6/6 pass，服务 7/7；正流量约 1.871 req/s，
  服务端错误率 0，P95 4.75 ms，Argo Synced/Healthy。
  完整记录见 [最终验收报告](acceptance.md)。

### 21.6 危险 PR 的真实硬拒绝

`docs/evidence/hard-boundary-live-rejections.json`（多为 0.2.1 评估，0.2.2 又有报告）：

- PR3：零副本/`DEMO_STARTUP_FAIL`，`FAULT_INJECTION` BLOCK，merge API 405；
- PR4：`.github/workflows/` 变更，`WORKFLOW_CHANGE_BLOCKED` BLOCK，405；
- PR5：chart 变更，`APPROVED_CHART_DIGEST_MISMATCH`/`TEMPLATE_FILE_CHANGE` BLOCK，405；
- 三者的 `Test, lint, render` 均为 success（CI 绿），仍被 guard/ruleset 挡住；
- 均关闭未合并；`main_before == main_after`，没有绕过。

### 21.7 合并包装脚本与 daemon 状态撤销

- `scripts/merge-release.sh` 供 root 使用：暂停 `change-guard.service`，`trap EXIT`
  恢复；`runuser -u change-guard` 后读取 `proxy.env`，再执行底层 merge。
- 0.3.1 曾因该脚本漏传 `--evaluation-id` 被拒绝，操作员临时用同边界的 fallback
  shell 补传后又被匿名 CI 403 拒绝；这不是可复制的操作路径，0.3.2 已修复。当前
  正式入口仍是 `sudo scripts/merge-release.sh <PR>`，由 merge 在 state lock 内取
  当前评估，**不要**再手工拼 fallback 或停 daemon 后直接推 main。
- PR closed/merged 后 daemon 会撤销旧 head 的历史 guard 状态；main/旧 head 出现
  guard error/pending 可能只是撤销，不是 postdeploy 失败。门禁证明看 merge 记录
  和当时的报告/审批/CI，不能为了好看保持永久绿。
- 最终结论、PR 链接和完整证据索引见 [验收报告](acceptance.md)。

### 21.8 发布切换期间两次连接拒绝

客户端流量在北京时间 17:32:44–17:32:45 记录两次 curl `(7) Connection refused`。
全段演练 2205 次请求中 2203 次成功，0 次 HTTP 失败、2 次传输失败；这两次请求未到达
应用，因此不会计入应用的 5xx 比例。切换后与回退后的观察窗口均正常，但不能据此
声称零中断发布。根因尚未单独复现定位，端点、kube-proxy 与优雅终止的时序需要后续
独立实验验证；当前不作无证据归因。原始错误和清理记录见
[traffic-cleanup.json](evidence/traffic-cleanup.json)。

## 22. Go 0.3.1 PR 部分验收与 0.3.2 修复（2026-11-12）

### 22.1 危险 PR8

- PR8 零副本 head 得到 `REPLICAS_ZERO`/BLOCK；追加 `DEMO_STARTUP_FAIL=true` 后旧
  head 失效，新 head 重新评估为 `FAULT_INJECTION`/BLOCK，`main` 仍是 `321eb951...`。
- GitHub merge API 返回 405（required `change-guard/release` failing）；普通账号直接
  更新 main 的探测返回 422（2 个 required checks + 必须走 PR）。见
  [保护证明](evidence/go-danger-protection-proof.json) 和
  [head 重评](evidence/go-danger-head-invalidation.json)。
- PR7 是 test driver 中断后产生的重复 PR，已记录 BLOCK 并关闭；验收以 PR8 为准。

### 22.2 正常 PR9 与审批

- PR9 head `a9a29da30832380bbdbda091177c738d7a7fde4b`，base `321eb951...`，只改
  `gitops/demo/values.yaml`；评估 REVIEW，审批 `ev-e941441d7a1f429dfbf37dd5` 由
  用户授权的 dsh 操作员以 owner `hey-mmm` 发出，CI `Test, lint, render` 绑定 head。
- **AI 误报**：DeepSeek 认为脱敏的 env 值可能带入故障开关；独立 reviewer 用 base/head
  精确 blob 证明 `APP_ENV`、`DEMO_ERROR_RATE`、`DEMO_LATENCY_MS`、
  `DEMO_STARTUP_FAIL` 均未改变。保留的真实 REVIEW 限制是未预留 requests、
  `KubeCPUOvercommit` 和零初始流量。见
  [独立复核](evidence/go-release-independent-review.json) 和
  [审批记录](evidence/go-approval-ev-e941441d7a1f429dfbf37dd5.json)。
- 在线 DeepSeek 只出建议，没有审批/合并/回滚权限；审批是人工代理动作，不是模型自批。

### 22.3 两次安全拒绝与 0.3.2 修复

- 第一次 `scripts/merge-release.sh 9`：脚本只传 PR 号码，Go 在入口拒绝空评估 ID，
  `REFUSED: invalid evaluation id`；见 [首次拒绝日志](evidence/go-merge-0.3.1-refused.log)。
- 第二次临时 shell 显式补 ID：CI check-runs 走匿名出口配额，返回
  `REFUSED: public CI check lookup failed`；`main` 未变。见
  [fallback 记录](evidence/go-merge-eval-fallback-9.json)。同一 head 用现有最小
  token 读取 check-runs 为 200、2 个检查，说明不需要新权限；认证查询与后续正式合并已验证，见 [合并记录](evidence/go-merge-record-9.json)。
- 0.3.2（`41f2ba1`）改为 state lock 内取该 PR 当前索引的 evaluation，显式 ID 只接受
  当前记录；CI 请求使用 `github.token`，固定 URL、禁 redirect、2 MiB 上限、
  head/app/required-name/latest-success 校验不变。`go test ./...` / `go vet ./...`
  通过；0.3.2 preflight、两遍 Ansible（第二遍 `changed=0`）和部署级 verify 完成。
- 0.3.2 的正式合并、发布后 6/6、反向提交回退和回退后 6/6 已通过，见 [最终验收](go-acceptance-final.md)。

### 22.4 最终 live 的模型解释矛盾

只读收尾探测中，DeepSeek 文本称“AI result status is invalid (ERROR)”，而结构化 `ai.status=ok`、`ai.error=null`，Go 最终决策为 REVIEW。保留原始响应，不能把模型叙述当作运行状态或门禁裁决。本次没有根据该探测新增审批或合并；已有发布与回退采用各自绑定的评估记录。见 [最终验收](go-acceptance-final.md)。
