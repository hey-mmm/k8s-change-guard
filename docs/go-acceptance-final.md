# Go 0.3.2 最终验收（2026-11-12）

Go 0.3.2 已完成真实门禁、发布、回退和最终环境验收。危险 PR8 被阻断；PR9 与回退 PR10 均经新评估、精确审批、可信 CI 和受限 fast-forward 合入，发布与回退各通过 6/6 postdeploy。最终两节点 Ready、ArgoCD Synced / Healthy、业务恢复旧镜像，测试流量已清理。

| 项目 | 结果 | 证据 |
| --- | --- | --- |
| Go 构建与回归 | 双平台 CI、151 份冻结 Python 对照、25/25 合成场景通过 | [CI](https://github.com/hey-mmm/k8s-change-guard/actions/runs/43229323225)、[本地记录](evidence/go-0.3.2-local-validation.json) |
| 部署 | 两遍 Ansible，第二遍 changed=0；静态 Go 服务、只读 RBAC 与凭据续期通过 | [部署摘要](evidence/go-0.3.2-deployment.json) |
| 危险发布 | PR8 BLOCK，GitHub 合并 405、直接更新主分支 422，未发布 | [PR8](https://github.com/hey-mmm/Full-Stack-Observability-in-Kubernetes/pull/8)、[独立验收](evidence/go-pr8-032-acceptance-summary.json) |
| 正常发布 | PR9 REVIEW 经受托操作员精确批准，受限合入 a9a29da30832380bbdbda091177c738d7a7fde4b | [PR9](https://github.com/hey-mmm/Full-Stack-Observability-in-Kubernetes/pull/9)、[合并记录](evidence/go-merge-record-9.json) |
| 发布后验证 | 6/6 通过；窗口内 700/700 请求为 2xx | [原始结果](evidence/go-postdeploy-release9-032b.json) |
| Git 回退 | PR10 创建反向提交，恢复发布前完整 Git 树；新评估和审批后受限合入 | [PR10](https://github.com/hey-mmm/Full-Stack-Observability-in-Kubernetes/pull/10)、[反向提交](evidence/go-revert-pr-create.json)、[合并记录](evidence/go-merge-record-10.json) |
| 回退后验证 | 6/6 通过；窗口内 119/119 请求为 2xx | [原始结果](evidence/go-postdeploy-revert10-032.json) |
| 真实接口与最终清理 | Kubernetes、Prometheus、受限 Helm、DeepSeek、daemon once 通过；流量停止，规则未放宽 | [最终记录](evidence/go-final-032-acceptance.json)、[部署/live](evidence/go-0.3.2-deployment.json) |

正常发布评估：ev-78c8a50fe61439c39c1a05d8；回退评估：ev-84b855038c1eb1ab7e6ce3ce。审批均绑定各自的报告、候选 head、目标 base、策略版本和有效期；旧版报告与审批没有复用。主分支最终为 88ced0cacdb5c6ea2cefd186c51af017125e4ea3，运行镜像源提交为 c0bff8abf5625903e5b9b19b586e9660b9fe7a8c，镜像 digest 为 sha256:456dfbbecf18b66b5b9e5c02bcba50c5fd4458f467e4b29c8d11d049d998677d。

本次回退通过 Git API 创建以发布 head 为父提交、以发布前树为新树的反向提交；对这里的单父最新发布，其变更等同 git revert。没有声称操作员实际执行过 git revert CLI，也没有直接修改集群回滚。

REVIEW 由用户授权的独立 dsh 操作员代表仓库 owner 审查和批准。在线 DeepSeek 只有分析权限，不能自行批准、推翻 BLOCK、合并或操作集群。单 worker 的容量告警和未声明 requests 的 Pod 是明确接受并记录的实验限制；模型对未改环境变量的疑虑已由 base/head 原始 blob 核对，不能只相信模型。

最终只读 live 探测中，DeepSeek 的解释文字出现“AI result status is invalid (ERROR)”的矛盾表述，但结构化响应 `ai.status=ok`、`ai.error=null`，确定性最终决策为 REVIEW。该文字不代表采集器或门禁返回 ERROR，也没有据此放行；保留在 [原始 AI 结果](evidence/go-0.3.2-ai.json) 与 [最终评估](evidence/go-0.3.2-final-report.json)，作为模型解释仍需核对的限制。

发布后验证先形成 5 分钟业务指标窗口，再执行实际观察。窗口内成功请求只说明本次测试结果，不证明全过程零中断或七天 99.9% SLO；单 worker 与本地 PVC 也不提供节点或磁盘容灾。

首次 postdeploy 因操作员传入裸 digest 被拒绝，完整镜像引用修正后通过，原失败记录保留为 [attempt1](evidence/go-postdeploy-release9-032-attempt1.json)。0.3.0 token 参数问题、0.3.1 合并参数和匿名 API 配额问题及其失败记录见 [故障复盘](fault-review.md)，不把历史失败改写为成功。
