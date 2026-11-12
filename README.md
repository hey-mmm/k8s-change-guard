# Kubernetes 发布变更风险守护 Agent

复用 [项目一](https://github.com/hey-mmm/Full-Stack-Observability-in-Kubernetes) 的 Kubernetes、Prometheus、GHCR 和 Argo CD，在发布配置进入 main 前收集证据并控制放行。运行于 master 的独立 systemd 用户，不接收公网 webhook，不执行 PR 中的程序，不向集群写入。

**当前版本：Go 0.3.2，迁移、真实发布门禁、发布与回退验收已完成。** Go 0.3.2 已完成真实门禁、发布、回退和最终环境验收。危险 PR8 被阻断；PR9 与回退 PR10 均经新评估、精确审批、可信 CI 和受限 fast-forward 合入，发布与回退各通过 6/6 postdeploy。最终两节点 Ready、ArgoCD Synced / Healthy、业务恢复旧镜像，测试流量已清理。 详细证据见 [最终验收](docs/go-acceptance-final.md)。Python 原版备份完整保留。

| 版本 | 事实 | 状态 |
| --- | --- | --- |
| Python `0.2.3` | 历史部署、REVIEW 审批、发布与 revert | 历史证据，不是 Go |
| Go `0.3.0` | artifact `3481524` bytes / `28ffe1c1...`；首次 Ansible 因 `check-token` 参数顺序失败 | 已回切，失败 release 保留 |
| Go `0.3.1` | artifact `3482084` bytes / `51c42df2...`；部署级 live 通过；危险 PR8 为 BLOCK，PR9 为 REVIEW 且精确审批成功；正式 merge 安全拒绝，`main` 未变 | 历史部署成功 + 部分 PR 验收，不是完整发布成功 |
| Go `0.3.2` | artifact `3485074` bytes / `39291800...`；修复当前评估选择与 CI 认证；部署级 verify 通过；PR9 受限合并 PASS，PR8 BLOCK | 当前版本；完整验收通过 |

Python 源码备份在分支 `backup/python-0.2.3`、标签 `python-v0.2.3`（均指向 `d21cef44...`），离线副本与恢复命令见 [迁移记录](docs/go-migration.md#python-备份)。

| 文档 | 内容 |
| --- | --- |
| [完整创建步骤](docs/creation-steps.md) | 从零构建 Go 0.3.2、Ansible 安装、规则、发布与复现 |
| [项目讲解](docs/project-explained.md) | 模块职责、工具配合、AI 与人工审批的实际边界 |
| [设计与安全边界](docs/design.md) | 隔离、权限、提交绑定、TTL、人工确认 |
| [验收报告](docs/acceptance.md) | 历史 Python 证据、0.3.0 失败、0.3.1 部分 PR 验收、0.3.2 部署、发布和回退验收 |
| [故障复盘](docs/fault-review.md) | 开发部署中遇到的问题与修复（含 Python→Go 迁移历史） |
| [运维与演示](docs/runbook.md) | 日常检查、轮换、演示、精确审批、Git revert PR、回切 Python |
| [Ansible](ansible/README.md) | 单二进制部署参数与安装细节 |
| [迁移记录](docs/go-migration.md) | Python 备份/恢复、迁移期 151 对照与 133 顶层测试、0.3.1 部分验收与 0.3.2 修复 |

## 快速本地验证（Go，不依赖 Python）

需要 Go 1.25+。生产 Helm 渲染仍必须在 Linux bubblewrap 中完成；Windows 只运行规则、采集、预渲染与打包测试。

```bash
go test ./...
go vet ./...
go run ./cmd/change-guard verify-knowledge --knowledge-dir knowledge
go run ./cmd/change-guard scenario --output /tmp/scenario-matrix.json

# 或在 Linux 运行本仓库的 shell 验收脚本（不部署）
sh scripts/acceptance.sh
```

`scenario` 输出的是**合成清单、合成证据和显式 AI stub** 的 25 组回归，不是 25 次真实集群/模型实验。

## 运行接口

生产环境只安装一个静态 Linux 二进制：`/opt/change-guard/current/k8s-change-guard`。

```bash
# 生产服务（由 systemd 启动）
change-guard daemon --config /etc/change-guard/config.yaml --once

# 正常合并：root 运行包装脚本。脚本暂停 daemon，0.3.2 在 state lock 内
# 自动取该 PR 当前索引的 evaluation，退出时恢复 polling，并读取 proxy.env
sudo scripts/merge-release.sh <PR>

# 0.3.2 的 merge 支持省略 --evaluation-id。显式 ID 只用于核对，必须等于
# 当前索引记录；旧 ID/未索引 PR 一律拒绝。不要为绕过拒绝手工拼 fallback 命令。

# 发布后只读验证：--expected-sha 是 Argo/GitOps revision，--expected-app-sha 是镜像源提交
change-guard postdeploy verify --config /etc/change-guard/config.yaml \
  --expected-sha <main-commit> --expected-app-sha <image-source-commit> \
  --report /var/lib/change-guard/reports/<evaluation_id>.json

# Token 到期检查与 root-only 续期（0.3.1 起同时接受位置参数在前/flag 在前）
change-guard check-token /etc/change-guard/kubeconfig --min-remaining 3600
sudo change-guard renew-token

# 0.3.0 只接受 flag 在前；该差异曾导致首次部署失败，0.3.1 修复并保留回归测试
change-guard check-token --min-remaining 3600 /etc/change-guard/kubeconfig

# 命令参数以实际 --help 为准
change-guard --help
```

`PASS / REVIEW / BLOCK / ERROR` 各自记录规则、证据、AI 分析和最终决策。BLOCK 不可由 AI 或人工覆盖；ERROR 必须修复后重评；REVIEW 审批绑定评估 ID、head SHA、main 基线、策略绑定与有效期。真实正常发布通常是 **REVIEW + 人工精确批准**，不是自动 PASS；AI 新增风险最多提升到 REVIEW。`.github/workflows/` 变更、`charts/demo` digest 不在操作员白名单、报告策略绑定不一致均为不可审批的硬阻断。

**谁可以审批**：REVIEW 的 `/guard approve <evaluation_id>` 由用户授权的 dsh 操作员以仓库 owner 身份、对当前评估发出；它代表 owner 的人工决定，不是模型决定。在线 DeepSeek 只产生解释和额外风险，没有 GitHub 凭据、审批身份或集群执行工具，**不能自批、不能合并、不能回滚**。0.3.1 的 PR9 就是这样完成精确审批的；随后受限 merge 仍因实现缺陷被拒绝，没有被包装成成功。

## 真实门禁的必要条件

GitHub 成功状态没有分钟级 TTL。项目一 main 设置两组独立规则：更新入口只允许部署密钥（GitHub 的 DeployKey bypass 是仓库级，不能按单 key 限制，实际只保留一把写 key）；CI 与 `change-guard/release` 检查无 bypass。GitHub Actions 的 `pull_request` check 绑定 PR **head**，不是 synthetic merge；受信合并程序独立核验 synthetic 父提交与树等于 head 树、head CI 成功，并只用精确旧 main lease 快进推送 head。普通账号即使能创建 PR，也无法用旧绿色状态直接合并。`.github/workflows/` 变更和 `charts/demo` 不在操作员 pin 白名单都是不可审批的硬 BLOCK。

专用部署密钥属于信任边界，持有人可绕过更新入口限制；它只放在服务主机的受限路径，仓库必须只有一把写部署密钥。仓库管理员能够改规则、集群管理员能够直改集群，本项目不声称能限制这些管理员。更新 `charts/demo` 模板必须由操作员另行更新 `approved_chart_digest`（当前真实 Git blob digest 为 `194baf90afd746299e256dc0bf144a12bc6f6325bacf77b40ff01e50b0c3e05d`，不是旧的 `0b2b...` 参考值）；guard 不会自动信任新模板。

合并后 PR 会 closed/merged，daemon 会撤销旧 head 上的历史 guard 状态；main/旧 head 出现 guard error/pending 可能只是撤销，不是 postdeploy 失败。门禁证明看 merge 记录和当时的报告/审批/CI，不要为了好看维持永久绿。

## 实验环境

- master：`11.0.1.10`；worker：`11.0.1.11`。
- master 提供轻量 Agent；业务与观测平台复用项目一。
- 外网代理：`http://11.0.1.1:7890`；集群内流量通过 `NO_PROXY` 直连。
- 单 worker、本地 PVC，不具备节点或磁盘容灾；指标是最近 5 分钟聚合，部署后 60 秒等待不是新版本专属桶，99.9% SLO 仍需完整七天数据。
- 模型 API 超时/坏引用导致 ERROR；模型新增风险导致 REVIEW，模型没有集群执行工具。

仓库、报告和日志中不得包含 GitHub token、DeepSeek key、SSH 私钥、sudo 密码或管理员 kubeconfig。
