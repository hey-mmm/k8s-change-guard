# 项目二验收报告

## 状态声明（2026-11-12，Go 迁移后）

| 项目 | 状态 | 说明 |
| --- | --- | --- |
| 历史 Python `0.2.3` | 已完成（历史） | 部署、真实门禁拒绝、正常发布、Git revert 与 postdeploy 均有原始证据 |
| 当前 Go `0.3.0` 实现 | 代码、测试与打包已完成 | 单二进制、Ansible 单二进制安装、Go token 助手、shell 健康/验收/场景工具、Go CI；Windows/Linux 测试通过 |
| Go `0.3.0` live 验收 | **未执行 / 待完成** | 尚未部署 Go 二进制，也没有 Go daemon 的 GitHub/Kubernetes/DeepSeek 实测 |

**不能把历史 Python `0.2.3` 证据说成当前 Go 版本已经上线。** 本文下半部分的真实发布、回退和 postdeploy 记录全部属于 Python `0.2.3`；Go 版本已完成可复现的 Windows/Linux 回归、151-case 对照、25/25 场景矩阵与单二进制打包，live 验收仍需在 root 部署轮次执行。

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

## Go `0.3.0` 本地验收清单

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
| `go test ./...` | 已通过（Windows 本轮；Linux master 133 顶层测试） | 覆盖规则、渲染边界、GitHub/merge、postdeploy、renew |
| 151-case Python decision oracle | 已转成 Go 测试输入并通过 | `testdata/python-oracle.json`，Go 测试直接读取，不运行 Python |
| 25-case synthetic scenario matrix | 25/25 通过 | Go `scenario` 子命令；合成证据 + AI stub，不是 live |
| knowledge hash 校验 | 已通过 | Go `verify-knowledge`，不依赖 Python |
| 单二进制打包 | 已生成 `dist/k8s-change-guard-0.3.0.tar.gz` | SHA-256 见 [迁移记录](go-migration.md#030-发布产物) |
| Ansible 单二进制安装 | 已就绪，未部署 | release/service/token/renewal/verify 均指向同一二进制 |
| Go token renew / check-token | 已接入 systemd 与 Ansible | `renew-token`、`check-token`、两个 timer |
| shell health / acceptance / scenario | 已新增 | 仅 shell，无 Python 运行时调用 |

## Go live 验收（待执行，不能提前声称通过）

部署后至少需要重新执行并记录：

1. Ansible 首次安装与第二次幂等运行（`changed=0`），确认 release 目录只有单二进制和只读 knowledge。
2. `systemctl is-active change-guard.service`、两个 token timer，以及 `change-guard check-token`。
3. RBAC 10 项边界（`sh scripts/verify-rbac.sh`）和服务健康检查（`sh scripts/health-check.sh --rbac`）。
4. 一次真实危险 PR 的 BLOCK 与 405 拒绝、一次正常 REVIEW 审批/受限合并、一次真实 `git revert` PR。
5. Argo 同步后的 6/6 postdeploy 检查与 HTTP `/version` 镜像源提交绑定。
6. 把当次 commit、Actions URL、报告、审批、merge 和 postdeploy 证据写入本节；在此之前 live 结论保持 pending。

完整复现见[创建步骤](creation-steps.md)，日常操作见[runbook](runbook.md)。
