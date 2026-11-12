# 项目二验收报告

验收日期：2026-11-12（Asia/Shanghai）。最终运行版本 **0.2.3**，代码验证提交 `b96937e`；[对应 GitHub Actions](https://github.com/hey-mmm/k8s-change-guard/actions/runs/43193175196) 成功。

**功能验收通过**：门禁已实际阻止不合规 PR；正常 digest 发布和真实 `git revert` PR 均经新鲜证据、精确审批、受限合并、Argo 同步和发布后验证完成。当前停在回退后的已知版本。发布切换期间记录到两次客户端连接拒绝，因此不宣称零中断发布或达成七天 99.9% SLO。

## 验收范围与结果

| 项目 | 真实结果 | 证据 |
| --- | --- | --- |
| 本地回归 | 182 tests OK；Windows 的 3 个 symlink 测试跳过；Linux CI 成功 | [测试代码](../tests/)、[Actions](https://github.com/hey-mmm/k8s-change-guard/actions/runs/43193175196) |
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

矩阵是**合成证据与显式 AI stub 的回归**，不是 25 次真实集群或模型演练。监控失败测试只改隔离评估配置，没有停止生产 Prometheus；模型超时测试调用真实 API，但没有发布 GitHub 状态或改集群。TTL、审批撤销、伪造引用、格式错误、旧规则/旧程序报告失效等边界还由自动化回归覆盖，不冒充已逐项进行破坏性线上演练。

## 发布、审批与回退

| 阶段 | GitOps revision | 应用源码 SHA | 镜像 manifest digest |
| --- | --- | --- | --- |
| 基线 | `823770eff4e9384ceb83aa1561f9b5f95239c221` | `c0bff8abf5625903e5b9b19b586e9660b9fe7a8c` | `sha256:456dfbbecf18b66b5b9e5c02bcba50c5fd4458f467e4b29c8d11d049d998677d` |
| [发布 PR #2](https://github.com/hey-mmm/Full-Stack-Observability-in-Kubernetes/pull/2) | `e6064c5df42ab701fac6a1e1be4bfac467a0410d` | `823770eff4e9384ceb83aa1561f9b5f95239c221` | `sha256:af77edde6463b40b795b3588e545582c8cd026bd57eec2c43f150a566c2120e7` |
| [回退 PR #6](https://github.com/hey-mmm/Full-Stack-Observability-in-Kubernetes/pull/6) | `321eb9517b83dc0e9261e16dcdb26016332dd7c3` | `c0bff8abf5625903e5b9b19b586e9660b9fe7a8c` | `sha256:456dfbbecf18b66b5b9e5c02bcba50c5fd4458f467e4b29c8d11d049d998677d` |

当前集群有 `KubeCPUOvercommit` 和 35 项未预留 requests 风险，因此正常发布与回退均为 **REVIEW，不伪造真实 PASS**。受托验收操作员依据用户授予的决策权限，核对故障开关关闭、无新增副本/requests、surge 额外 50m CPU/64Mi 可容纳后，使用操作员身份发出精确评估 ID 审批；这不是用户亲自在 GitHub 点击审批。

发布审批绑定 `ev-2d5caa588956d577aa7d7666`，[审批记录](evidence/approval-ev-2d5caa588956d577aa7d7666.json)；回退绑定 `ev-3197f2cadf956f6dfcc349f8`，[审批记录](evidence/approval-ev-3197f2cadf956f6dfcc349f8.json)。硬 BLOCK 从未审批覆盖。

发布合并由 0.2.2 执行，回退合并和最终发布后验证由 0.2.3 执行。零副本与独立策略边界的拒绝证据分别来自当时 0.2.0/0.2.1，0.2.2 又生成相同硬阻断报告；最终版本保留相应回归。报告各自保留实际 guard version，不将历史报告冒充最终版本新演练。

合并未使用 GitHub merge API，未关闭 ruleset。程序核对 synthetic parents/tree、head CI、当前 head/base、报告摘要、版本/策略、审批与 TTL，然后以专用 deploy key 和 exact lease 快进 main。GitHub 已将两个 PR 标记 merged。回退提交来自实际 `git revert e6064c5...`，没有直接改 Deployment，也没有让模型执行回滚。

## 发布后指标与可用性

| 阶段 | 观测等待 | 正流量 | 服务端 5xx 比例 | P95 | Argo/镜像/HTTP |
| --- | --- | --- | --- | --- | --- |
| 发布后 | 60 秒 | 1.877 req/s | 0 | 4.75 ms | 全部通过 |
| 回退后 | 60 秒 | 1.871 req/s | 0 | 4.75 ms | 全部通过 |

指标来自当前采集器最近 **5 分钟**的 rate/histogram 聚合；60 秒是检查前的等待观察期，不能将其描述成只涵盖新版本的精确 60 秒指标桶。

[客户端流量日志摘要](evidence/traffic-cleanup.json)显示：基线 3600 秒共 6974 次成功；发布/回退演练流量共 2205 次请求，2203 次成功，0 次 HTTP 失败、**2 次传输失败**。失败发生在北京时间 17:32:44–17:32:45，均为 curl `(7) Connection refused`，与新版本切换时间重合。Prometheus 服务端 5xx=0 不包含这些未到达应用的连接失败，因此不能用它宣称用户侧全程无错误。尚未单独定位其为 EndpointSlice/kube-proxy 收敛还是其他网络时序问题；后续可针对端点切换与优雅终止做独立实验，不能在没有证据时归因。

验收流量已停止，无无限后台压测。危险演练 PR #3/#4/#5 均关闭未合并。

## AI 的实际价值与限制

真实 DeepSeek 返回了结构化建议与可追溯案例，例如启动失败时旧 Pod 仍 Ready 不代表新版本发布成功、零副本会撤掉服务能力、单 worker surge 和未预留 requests 的容量风险。报告保留案例 ID、源提交、原文行号与 SHA-256；模型没有执行工具，也没有覆盖硬规则。

本次也出现 AI 因环境变量被脱敏而猜测可能带故障开关的 REVIEW 建议；操作员查看精确候选 values 后确认只是版本元数据变化。这说明 AI 会产生额外人工工作，不能把这些建议都算成新增有效发现。25 组回归分别记录规则判断、AI 建议和最终结果，但当前样本不足以给出模型准确率或收益比例。

最初发布后验证器误把 containerd 的配置 ID 当 manifest 镜像引用，产生失败建议；没有触发自动回滚。0.2.3 改为按 Pod spec 的容器名/镜像匹配，再核对实际 imageID，新增回归后重跑通过。[原始失败记录](evidence/postdeploy-initial-containerd-false-negative.json)保留以便追溯。

## 最终运行边界

- master `11.0.1.10`、worker `11.0.1.11` 都 Ready，Agent 0.2.3 active；当前 Argo 为回退提交的 Synced/Healthy。
- ServiceAccount 无 Secret、日志、exec、Deployment/Argo 写权限；固定 root 续期路径与常驻只读服务分离。
- GitHub DeployKey bypass 是仓库级类别；当前审计只保留一把写 deploy key，平台不能按单把 key ID 收窄。服务主机、部署密钥和管理员属于信任边界。
- 已合并/关闭 PR 的 guard 状态会撤销，历史 main 可能显示 guard error；它表示评估不再可用于新合并，不代表已经通过的发布后检查失效。合并时的有效性查不可变报告、审批和 merge 记录。
- Chart pin 更新和 workflow 维护必须经受信运维流程，普通发布 PR 不能自行改变信任策略。main 的绿色状态不替代受限合并程序。
- 单 worker、本地 PVC 无节点/磁盘容灾；模型别名无法固定供应商权重；60 秒观察不证明长期 SLO。尚无自动回滚；异常只给出 Git revert PR 建议。

完整复现见[创建步骤](creation-steps.md)，日常操作见[runbook](runbook.md)，故障与修复见[复盘](fault-review.md)。
