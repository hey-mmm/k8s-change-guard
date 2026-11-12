# 项目二验收报告

## 状态声明（2026-11-12，Go 0.3.2）

| 项目 | 状态 | 说明 |
| --- | --- | --- |
| 历史 Python `0.2.3` | 已完成（历史） | 部署、真实门禁拒绝、正常发布、Git revert 与 postdeploy 均有原始证据 |
| Go `0.3.0` 首次部署 | **失败并回切（历史）** | Ansible 在 `check-token` 位置参数顺序处失败；`current` 回切 Python `0.2.3`，失败 release 保留 |
| Go `0.3.1` 部署 | **已完成（部署级，历史）** | 两遍 Ansible（第二遍 `changed=0`）、服务、RBAC、timer、renew、knowledge、collect、render、真实 DeepSeek、`daemon --once` 通过 |
| Go `0.3.1` PR 验收 | **部分完成（历史）** | PR8 危险发布 BLOCK、new-head 重评、merge API 405、直推 422；PR9 REVIEW 精确审批成功；正式 merge 因评估 ID 缺省和匿名 CI 403 被安全拒绝，`main` 未变 |
| 当前 Go `0.3.2` 实现 | 代码、测试与打包已完成 | commit `41f2ba1`；`go test ./...` / `go vet ./...` 通过；artifact `3485074` bytes / `39291800...` |
| Go `0.3.2` 部署 | **已完成（部署级）** | preflight、stage、两遍 Ansible（第二遍 `changed=0`）、服务、RBAC、timer、renew、knowledge、verify 通过 |
| Go `0.3.2` PR/受限合并 | **已完成（PR 级）** | PR8 新评估 BLOCK + 405/422；PR9 新评估 REVIEW、owner 精确审批，`merge-release.sh 9` 省略评估 ID 后 fast-forward `MERGED`，`main` 变为 `a9a29da...` |
| Go `0.3.2` postdeploy/回退/final live | **已完成** | 发布和回退各 6/6，通过真实接口与最终清理；见 [最终验收](go-acceptance-final.md) |

Go 0.3.2 已完成真实门禁、发布、回退和最终环境验收。危险 PR8 被阻断；PR9 与回退 PR10 均经新评估、精确审批、可信 CI 和受限 fast-forward 合入，发布与回退各通过 6/6 postdeploy。最终两节点 Ready、ArgoCD Synced / Healthy、业务恢复旧镜像，测试流量已清理。 详见 [Go 最终验收](go-acceptance-final.md)；历史版本记录保留各自的时间和范围。

## Go `0.3.2` 当前构建与部署（2026-11-12）

- 源码：commit `41f2ba1`（“Fix current-evaluation merge selection and authenticate CI proof lookups”）。修复两项 0.3.1 合并缺陷：
  - `merge` 的 `--evaluation-id` 可省略；取得 state lock、读取索引后，解析该 PR 的 **当前** recorded evaluation。显式 ID 必须与当前索引完全一致；旧 ID、未索引 PR、缺失/非法记录 fail closed。
  - CI check-runs 使用服务现有的 `github.token`，修复匿名共享出口配额 403；仍固定 `api.github.com`、禁止 redirect、保留 2 MiB 上限和 head/app/required-name/latest-success 校验。
- 测试：`go test ./... -count=1` 与 `go vet ./...` 通过；新增评估 ID 选择、显式旧 ID 拒绝、Bearer 认证、403 不泄露、redirect 拒绝等回归。详见 [Go merge 修复复核](evidence/go-merge-fix-review.md) 和 [本地验证记录](evidence/go-0.3.2-local-validation.json)（137 个测试函数、151 个 oracle case、25 个合成场景）。
- CI：[run 43229323225](https://github.com/hey-mmm/k8s-change-guard/actions/runs/43229323225) 在 `ubuntu-24.04` 与 `windows-latest` 成功。
- 构建：`3485074` bytes、22 个文件、SHA-256 `3929180048fbfc107eaf18bfb22b19983be56f326467d15dcc6a511d2b074be8`；见 [构建记录](evidence/go-build-artifact-0.3.2.json) 和 [preflight](evidence/go-0.3.2-preflight.json)。
- 部署前 root-only 备份：`/var/backups/change-guard/pre-go-0.3.2-20261112-133927`；旧 0.3.0/0.3.1/Python `0.2.3` release 保留。
- Ansible：第一遍 `ok=84 changed=7 failed=0 unreachable=0 skipped=13`，第二遍 `ok=73 changed=0 failed=0 unreachable=0 skipped=23`；见 [首次部署](evidence/go-0.3.2-ansible-deploy.txt) 和 [幂等](evidence/go-0.3.2-ansible-idempotent.txt)。
- 运行态：`current -> /opt/change-guard/releases/0.3.2`；`change-guard 0.3.2 (rules go-2026-11-12.1)`；静态 ELF、service `active/enabled`、`NRestarts=0`；双 timer active；服务用户 `nologin`。见 [部署摘要](evidence/go-0.3.2-deployment.json) 和 [运行态](evidence/go-0.3.2-runtime.txt)。
- RBAC：nodes、all-namespace pods、Argo 只读成功；Secrets、Pod logs、Pod exec、Deployment 写、Argo patch 均拒绝；见 [RBAC 证据](evidence/go-0.3.2-rbac.txt)。
- Token：手动 renew `Result=success`，`check-token` 返回 `valid`、剩余 `43200s`；见 [renew](evidence/go-0.3.2-renew-token.txt)、[renew 前](evidence/go-0.3.2-check-token-before.txt)/[后](evidence/go-0.3.2-check-token-after.txt)。
- Knowledge：sources=3、cases=15；见 [knowledge](evidence/go-0.3.2-knowledge.json)。
- **0.3.2 PR/受限合并（已完成 PR 级，不是 final live）**：
  - PR8 用 0.3.2 新评估 `ev-250e5d31f8ee30f9dd9ec867` 仍为 `FAULT_INJECTION`/BLOCK；merge API 405、直推 422，`main` 未变，PR8 从未合并。
  - PR9 用 0.3.2 新评估 `ev-78c8a50fe61439c39c1a05d8` 为 REVIEW，owner `hey-mmm` 精确审批后执行 `scripts/merge-release.sh 9`；脚本**没有**传 `--evaluation-id`，Go 0.3.2 在锁内取当前索引记录，结果 `MERGED`、fast-forward、`github_merge_api_used=false`，`main` 从 `321eb951...` 变为 head `a9a29da...`。这真实验证了省略 ID 和 CI 认证两个修复。
  - 证据：[0.3.2 PR 验收摘要](evidence/go-0.3.2-postdeploy-acceptance.md)、[merge 记录](evidence/go-merge-record-9.json)、[新审批](evidence/go-approval-ev-78c8a50fe61439c39c1a05d8.json)、[PR9 汇总](evidence/go-pr9-032-acceptance-summary.json)。
- Go 0.3.2 已完成真实门禁、发布、回退和最终环境验收。危险 PR8 被阻断；PR9 与回退 PR10 均经新评估、精确审批、可信 CI 和受限 fast-forward 合入，发布与回退各通过 6/6 postdeploy。最终两节点 Ready、ArgoCD Synced / Healthy、业务恢复旧镜像，测试流量已清理。 详见 [Go 最终验收](go-acceptance-final.md)；历史版本记录保留各自的时间和范围。

## Go `0.3.1` PR 验收（历史，部分完成）

0.3.1 的部署本身成功，但真实发布在受限合并前停止；`main` 始终是
`321eb9517b83dc0e9261e16dcdb26016332dd7c3`。这段历史保留，不被 0.3.2 覆盖。

- 危险 PR #7 是重复创建，已记录 `REPLICAS_ZERO`/BLOCK 后关闭；canonical 验收转到 PR8。见 [PR7 记录](evidence/go-danger-initial-attempt.json)。
- PR #8：零副本 head `273c033d...` 得到 `REPLICAS_ZERO`/BLOCK；追加启动故障提交后旧 head 的评估失效，新 head `9953651...` 重新评估为 `FAULT_INJECTION`/BLOCK。GitHub merge API 返回 405，普通账号直接更新 main 返回 422，`main` 未变。见 [BLOCK 报告](evidence/go-danger-second-report.json)、[head 重评](evidence/go-danger-head-invalidation.json)、[保护证明](evidence/go-danger-protection-proof.json)。
- PR #9：head `a9a29da30832380bbdbda091177c738d7a7fde4b`，base `321eb951...`，只改 `gitops/demo/values.yaml`。评估为 REVIEW（容量未预留、告警、低流量、AI 额外风险），审批评论绑定 `ev-e941441d7a1f429dfbf37dd5`，作者 `hey-mmm`，CI `Test, lint, render` success 且绑定该 head。见 [独立复核](evidence/go-release-independent-review.json) 和 [审批记录](evidence/go-approval-ev-e941441d7a1f429dfbf37dd5.json)。
- 审批是**用户授权的 dsh 操作员代表 owner** 发出的精确人工决定，不是在线 DeepSeek 自批。PR9 的 DeepSeek 曾把未改动的脱敏 env 值误报为“可能带入演练故障开关”；独立 reviewer 用 base/head 精确 blob 证明 `APP_ENV`、`DEMO_ERROR_RATE`、`DEMO_LATENCY_MS`、`DEMO_STARTUP_FAIL` 均未改变，该条为 AI 误报。未预留 requests、`KubeCPUOvercommit`、零初始流量是保留的 REVIEW 限制。
- 正式合并被安全拒绝两次：先是随仓库交付的 `scripts/merge-release.sh <PR>` 漏传 `--evaluation-id`，Go 返回 `REFUSED: invalid evaluation id`；见 [首次拒绝日志](evidence/go-merge-0.3.1-refused.log)。操作员显式补 ID 后，CI 查询走匿名出口配额，返回 `REFUSED: public CI check lookup failed`；见 [第二次 merge](evidence/go-merge-eval-fallback-9.json)。两次均未更新 main。后续 0.3.2 认证查询与正式合并已通过，见 [合并记录](evidence/go-merge-record-9.json)；`go-ci-merge-9.json` 是该成功轮次的记录。
- 0.3.2 的修复正是针对这两个缺陷；在 0.3.2 live/PR 重跑完成前，0.3.1 只能称为“部署成功 + 门禁/审批部分验收”，不是完整发布成功。

## Go `0.3.0` 首次部署失败（历史，保留）

- 首次 Ansible 在 `ansible/roles/change_guard/tasks/token.yml:19` 失败：`check-token KUBECONFIG --min-remaining 7200` 返回 `rc=2`，而 `check-token --min-remaining 7200 KUBECONFIG` 成功。根因是 Go `flag` 在首个位置参数处停止解析。
- 部署在 release 安装后、config/service 切换前中止；操作员立即把 `current` 回切到 `/opt/change-guard/releases/0.2.3`，Python 服务保持 active，规则集和 main 未改变。失败 release `/opt/change-guard/releases/0.3.0` 与 `.complete`/`.artifact.sha256` 原样保留。
- 证据：[Ansible 原始输出](evidence/go-0.3.0-ansible-deploy.txt)、[失败检查记录](evidence/go-0.3.0-blocker-check-token.txt)、[部署摘要](evidence/go-0.3.0-deployment.json)、[回切后状态](evidence/go-blocked-final-state.json)、[CLI 对照](evidence/go-check-token-bug.json)。
- 0.3.0 artifact 仍是 `3481524` bytes / SHA-256 `28ffe1c159bb39ad851c9ad9b30a34a7f66b3ea5796907218dbb7ab86ddb97e3`；不覆盖、不重算、不伪改。修复后因不可变版本目录冲突升为 `0.3.1`。

## Go `0.3.1` 部署与部署级 live（已完成，2026-11-12）

- 构建：`0.3.1`，`3482084` bytes，22 个文件，SHA-256 `51c42df2b07a13e60c6558df09fd320e058533818a4b45fe41c08faf3240f9ec`；GitHub 双平台 CI [run 43225049084](https://github.com/hey-mmm/k8s-change-guard/actions/runs/43225049084) 成功。构建摘要见 [go-build-artifact-0.3.1.json](evidence/go-build-artifact-0.3.1.json)。
- 部署前 root-only 备份：`/var/backups/change-guard/pre-go-0.3.1-20261112-131735`；旧 Python `0.2.3` release 保留。
- Ansible：第一遍 `ok=85 changed=11 failed=0 unreachable=0`，第二遍 `ok=73 changed=0 failed=0 unreachable=0`；artifact SHA-256 在控制器和目标机双侧一致。
- 运行态：`current -> /opt/change-guard/releases/0.3.1`；`change-guard 0.3.1 (rules go-2026-11-12.1)`；ELF 64-bit x86-64 静态链接；service `active/enabled`，`NRestarts=0`；服务用户 `change-guard` 为 `nologin`；release 中无 Python/venv。
- RBAC：nodes、all-namespace pods、Argo Application 只读成功；Secrets、Pod logs、Pod exec、Deployment 写、Argo patch 均被拒绝。sandbox 只挂载候选 chart/values 数据，不执行 PR 代码。
- Token：手动 renew 成功（`Result=success`），renew 后 `check-token` 返回 `valid`、剩余约 `43199s`；0.3.1 的位置参数在前与 flag 在前写法均通过。
- Knowledge/渲染/采集：sources=3、cases=15；受信 `823770e` 树的 7 个 chart 文件、chart digest `194baf90...e05d`，bwrap render 产出 Service/Deployment/ServiceMonitor；collect `nodes=2 pods=28 errors=[]`。
- 真实 DeepSeek：`status=ok`、`deepseek-chat`、citations=3；无 AI 结果时 evaluate 按预期 fail-closed 为 ERROR，带真实 AI 结果后为 REVIEW（新工作负载、35 个未预留 Pod、低流量等需人工确认），`daemon --once` 第一次即 `status=ok`。
- 证据：[preflight](evidence/go-0.3.1-preflight.json)、[首次 Ansible](evidence/go-0.3.1-ansible-deploy.txt)、[幂等](evidence/go-0.3.1-ansible-idempotent.txt)、[部署摘要](evidence/go-0.3.1-deployment.json)、[运行态/unit](evidence/go-0.3.1-runtime.txt)、[RBAC](evidence/go-0.3.1-rbac.txt)、[renew](evidence/go-0.3.1-renew-token.txt)、[check-token 前](evidence/go-0.3.1-check-token-before.txt)/[后](evidence/go-0.3.1-check-token-after.txt)、[knowledge](evidence/go-0.3.1-knowledge.json)、[collect](evidence/go-0.3.1-collect.json)、[render](evidence/go-0.3.1-render.json)、[AI](evidence/go-0.3.1-ai.json)、[final report](evidence/go-0.3.1-final-report.json)、[daemon once](evidence/go-0.3.1-daemon-once.txt)。
- **边界**：以上是部署级验证，不是完整项目验收。0.3.1 随后完成了危险 PR8 的 BLOCK/new-head 重评，以及 PR9 的 REVIEW 精确审批；但受限 merge 因 0.3.1 自身缺陷被安全拒绝，Argo 同步后的 postdeploy 和 Git revert 没有发生（见上节）。不能用本节或历史 Python 记录替代完整发布结果。

## 历史 Python `0.2.3` 证据

验收日期：2026-11-12（Asia/Shanghai）。当时运行版本 **0.2.3**，代码验证提交 `b96937e`；[对应 GitHub Actions](https://github.com/hey-mmm/k8s-change-guard/actions/runs/43193175196) 成功。以下结论只适用于该历史版本。

| 项目 | 历史真实结果 | 证据 |
| --- | --- | --- |
| 本地回归 | 182 tests OK；Windows 的 3 个 symlink 测试跳过；Linux CI 成功 | [旧测试记录](../test-output.txt)、[Actions](https://github.com/hey-mmm/k8s-change-guard/actions/runs/43193175196) |
| 风险矩阵 | 25/25，分别记录规则、AI stub 与最终决策 | [scenario-matrix.json](evidence/scenario-matrix.json) |
| master 安装 | 0.2.3；首次 `ok=87 changed=11 failed=0`；第二次 `ok=75 changed=0 failed=0` | [部署](evidence/deployment-0.2.3.json)、[幂等原始输出](evidence/ansible-idempotent-0.2.3.txt) |
| 权限与续期 | 最终 10/10 RBAC 边界；只读；12h token 手动续期成功，6h timer active | [最终运行状态](evidence/final-runtime-proof.json) |
| 分支保护 | 两组 active ruleset；普通账号直接更新 main 被 422 拒绝 | [规则及唯一写 deploy key 审计](evidence/github-protection-and-key-audit.json)、[拒绝证据](evidence/block-and-direct-update-refused.json) |
| 零副本 | PR #3 原始提交得到 REPLICAS_ZERO/BLOCK，合并 405 | [报告](evidence/ev-93cd0090e77f94a000fe401c.json)、[拒绝证据](evidence/block-and-direct-update-refused.json) |
| PR 追加提交 | 同一 PR 改为启动故障后，新 SHA、新评估 ID；FAULT_INJECTION/BLOCK，合并 405 | [head 更新](evidence/pr-head-update.json)、[真实拒绝](evidence/hard-boundary-live-rejections.json) |
| CI workflow 修改 | PR #4 即使 CI success，仍 WORKFLOW_CHANGE_BLOCKED/BLOCK，合并 405 | [真实拒绝](evidence/hard-boundary-live-rejections.json) |
| Chart 修改 | PR #5 未获独立受信 pin 更新，APPROVED_CHART_DIGEST_MISMATCH/BLOCK，合并 405 | [真实拒绝](evidence/hard-boundary-live-rejections.json) |
| 监控采集失败 | 隔离配置指向拒绝连接端点，真实采集返回 ERROR，AI 正常也不能放行 | [隔离实测](evidence/isolated-live-failure-probes.json) |
| 模型超时 | 真实 DeepSeek API 设置 1 秒截止，Read timed out，最终 ERROR | [隔离实测](evidence/isolated-live-failure-probes.json) |
| 正常发布 | PR #2 REVIEW → 限定审批 → fast-forward 合并 → 6/6 发布后检查 + 7/7 服务检查 | [合并](evidence/merge-pr-2.json)、[发布后](evidence/postdeploy-e6064c5df42ab701fac6a1e1be4bfac467a0410d.json)、[服务](evidence/release-app-acceptance.txt) |
| Git revert 回退 | PR #6 真实 git revert → REVIEW/审批 → 合并 → 6/6 + 7/7；恢复旧 digest/应用源码版本 | [revert PR](evidence/revert-pr.json)、[合并](evidence/merge-pr-6.json)、[回退后](evidence/postdeploy-321eb9517b83dc0e9261e16dcdb26016332dd7c3.json)、[服务](evidence/revert-app-acceptance.txt) |

历史风险矩阵是**合成证据与显式 AI stub 的回归**，不是 25 次真实集群或模型演练。监控失败测试只改隔离评估配置，没有停止生产 Prometheus；模型超时测试调用真实 API，但没有发布 GitHub 状态或改集群。

历史发布与回退的 GitOps revision、应用源码 SHA 与镜像 digest：

| 阶段 | GitOps revision | 应用源码 SHA | 镜像 manifest digest |
| --- | --- | --- | --- |
| 基线 | `823770eff4e9384ceb83aa1561f9b5f95239c221` | `c0bff8abf5625903e5b9b19b586e9660b9fe7a8c` | `sha256:456dfbbecf18b66b5b9e5c02bcba50c5fd4458f467e4b29c8d11d049d998677d` |
| [发布 PR #2](https://github.com/hey-mmm/Full-Stack-Observability-in-Kubernetes/pull/2) | `e6064c5df42ab701fac6a1e1be4bfac467a0410d` | `823770eff4e9384ceb83aa1561f9b5f95239c221` | `sha256:af77edde6463b40b795b3588e545582c8cd026bd57eec2c43f150a566c2120e7` |
| [回退 PR #6](https://github.com/hey-mmm/Full-Stack-Observability-in-Kubernetes/pull/6) | `321eb9517b83dc0e9261e16dcdb26016332dd7c3` | `c0bff8abf5625903e5b9b19b586e9660b9fe7a8c` | `sha256:456dfbbecf18b66b5b9e5c02bcba50c5fd4458f467e4b29c8d11d049d998677d` |

当时集群有 `KubeCPUOvercommit` 和 35 项未预留 requests 风险，因此正常发布与回退均为 **REVIEW，不伪造真实 PASS**。发布审批绑定 `ev-2d5caa588956d577aa7d7666`，回退审批绑定 `ev-3197f2cadf956f6dfcc349f8`；硬 BLOCK 从未审批覆盖。

历史发布后观测：发布后 60 秒等待、1.877 req/s、服务端 5xx=0、P95 4.75 ms；回退后 1.871 req/s、5xx=0、P95 4.75 ms。指标来自采集器最近 **5 分钟**聚合，60 秒不是只覆盖新版本的精确指标桶。演练流量共 2205 次请求，2203 成功、0 次 HTTP 失败、**2 次传输失败**（curl connection refused），因此不能宣称零中断或 99.9% SLO。

## Go `0.3.2` 本地验收清单

这些检查可以在不部署的情况下复现；它们**不是 live 验收**。

```bash
# Linux 或具备 Go 1.25+ 的环境
go test ./...
go vet ./...
gofmt -l cmd internal scripts/packaging
go run ./cmd/change-guard verify-knowledge --knowledge-dir knowledge
go run ./cmd/change-guard scenario --output /tmp/scenario-matrix.json

# 可选：Linux 上构建确定性 release tarball
sh scripts/build-release.sh --output /tmp/k8s-change-guard.tar.gz

# 可选：Windows 上跨编译 Linux 二进制并打包（验证 GOOS 隔离）
pwsh -NoProfile -File scripts/build-release.ps1 -Go go
```

| Go 验收项 | 状态 | 备注 |
| --- | --- | --- |
| gofmt / go vet | 已通过（Windows 本轮；Linux CI） | gofmt 覆盖 `cmd`、`internal`、`scripts/packaging` |
| `go test ./...` | 已通过（0.3.2 本地；Linux master 133 顶层测试为 0.3.0/0.3.1 历史） | 覆盖规则、渲染边界、GitHub/merge、postdeploy、renew；新增评估 ID 选择与 CI 认证回归 |
| 151-case Python decision oracle | 已转成 Go 测试输入并通过 | `testdata/python-oracle.json`，Go 测试直接读取，不运行 Python |
| 25-case synthetic scenario matrix | 25/25 通过 | Go `scenario` 子命令；合成证据 + AI stub，不是 live |
| knowledge hash 校验 | 已通过 | Go `verify-knowledge`，不依赖 Python |
| 单二进制打包 | 已生成 `dist/k8s-change-guard-0.3.2.tar.gz` | `3485074` bytes、22 个文件、SHA-256 `3929180048fbfc107eaf18bfb22b19983be56f326467d15dcc6a511d2b074be8`（见[构建记录](evidence/go-build-artifact-0.3.2.json)） |
| 历史 artifact 保留 | 0.3.1 `51c42df2...`、0.3.0 `28ffe1c1...` | 不覆盖、不重算、不改写失败/部分验收结论 |
| `check-token` 参数兼容 | 已修复并有测试 | 位置参数在前与 flag 在前都通过；0.3.0 只支持后者，见上节失败历史 |
| merge 评估 ID / CI 认证 | 0.3.2 已修复并有测试 | 省略 ID 时在当前索引取记录；显式 ID 只接受当前记录；CI 用现有 token，禁 redirect、2 MiB 上限不变 |
| Ansible 单二进制安装 | 0.3.2 已部署并由真实两遍运行验证 | 第一遍 `ok=84 changed=7`，第二遍 `ok=73 changed=0`；证据见上节 |
| Go token renew / check-token | 已接入 systemd 与 Ansible | `renew-token`、`check-token`、两个 timer |
| shell health / acceptance / scenario | 已新增 | 仅 shell，无 Python 运行时调用 |

## Go 0.3.2 真实发布、回退与最终验收

Go 0.3.2 已完成真实门禁、发布、回退和最终环境验收。危险 PR8 被阻断；PR9 与回退 PR10 均经新评估、精确审批、可信 CI 和受限 fast-forward 合入，发布与回退各通过 6/6 postdeploy。最终两节点 Ready、ArgoCD Synced / Healthy、业务恢复旧镜像，测试流量已清理。

详见 [Go 最终验收](go-acceptance-final.md)；历史版本记录保留各自的时间和范围。

结论口径：

- 正常发布真实结果通常是 **REVIEW**，由用户授权的 dsh 操作员以 owner 身份对当前 evaluation ID 精确审批；在线 DeepSeek 没有自批、合并或回滚权限。PASS 只表示规则/证据无需人工确认，合成场景的 PASS 不是 live PASS。
- AI 只能解释和新增 REVIEW 风险，**不能推翻 BLOCK**；AI 建议需独立核对。PR9 的“未改 env 被脱敏”风险就是被 base/head blob 证伪的误报，真实 REVIEW 限制（未预留 requests、告警、低流量）仍然保留。`RBAC` 保持只读，`bubblewrap` 只挂载候选数据并禁用网络/插件。
- 单 worker、本地 PVC 不具备节点或磁盘容灾；指标来自最近 5 分钟窗口，不是 60 秒专属桶；99.9% SLO 需要完整七天数据。60 秒只用于 Argo/工作负载稳定等待，不能当作新版本专属观测桶。

完整复现见[创建步骤](creation-steps.md)，日常操作见[runbook](runbook.md)。
