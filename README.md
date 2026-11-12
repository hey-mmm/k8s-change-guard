# Kubernetes 发布变更风险守护 Agent

复用 [项目一](https://github.com/hey-mmm/Full-Stack-Observability-in-Kubernetes) 的 Kubernetes、Prometheus、GHCR 和 Argo CD，在发布配置进入 main 前收集证据并控制放行。运行于 master 的独立 systemd 用户，不接收公网 webhook，不执行 PR 中的程序，不向集群写入。

**当前状态：Go 0.3.0 代码、Windows/Linux 测试、151-case 对照、25/25 场景矩阵和单二进制构建均已完成，产物可直接部署；尚未部署到实验环境。** 历史 `0.2.3` 的部署、危险 PR 拒绝、正常发布和 Git revert 证据来自 Python 实现，保留在 [验收报告](docs/acceptance.md) 中仅作历史证据，不能当作 Go 版本已经上线或通过 live 验收；Go live 验收由 root 在部署轮次执行。

| 文档 | 内容 |
| --- | --- |
| [完整创建步骤](docs/creation-steps.md) | Go 单二进制构建、Ansible 安装、规则、发布与复现 |
| [项目讲解](docs/project-explained.md) | 模块职责、工具配合、AI 的实际价值 |
| [设计与安全边界](docs/design.md) | 隔离、权限、提交绑定、TTL、人工确认 |
| [验收报告](docs/acceptance.md) | 历史 Python 证据与 Go live 验收清单 |
| [故障复盘](docs/fault-review.md) | 开发部署中遇到的问题与修复（含迁移历史） |
| [运维与演示](docs/runbook.md) | 日常检查、轮换、演示、Git revert PR |
| [Ansible](ansible/README.md) | 单二进制部署参数与安装细节 |
| [迁移记录](docs/go-migration.md) | Python→Go 迁移范围、151 对照、133 顶层测试、构建与部署边界 |

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

# 正常合并：root 运行包装脚本；会暂停 daemon，退出时恢复，并读取 proxy.env
sudo scripts/merge-release.sh <PR>

# 底层命令仍可运行，但必须先停 daemon/串行化，否则可能得到 busy/锁错误
change-guard merge --config /etc/change-guard/config.yaml --pr <编号>

# 发布后只读验证：--expected-sha 是 Argo/GitOps revision，--expected-app-sha 是镜像源提交
change-guard postdeploy verify --config /etc/change-guard/config.yaml \
  --expected-sha <main-commit> --expected-app-sha <image-source-commit> \
  --report /var/lib/change-guard/reports/<evaluation_id>.json

# Token 到期检查与 root-only 续期（无参数固定路径）
change-guard check-token /etc/change-guard/kubeconfig --min-remaining 3600
sudo change-guard renew-token

# 命令参数以实际 --help 为准
change-guard --help
```

`PASS / REVIEW / BLOCK / ERROR` 各自记录规则、证据、AI 分析和最终决策。BLOCK 不可由 AI 或人工覆盖；ERROR 必须修复后重评；REVIEW 审批绑定评估 ID、head SHA、main 基线、策略绑定与有效期。`.github/workflows/` 变更、`charts/demo` digest 不在操作员白名单、报告策略绑定不一致均为不可审批的硬阻断。

## 真实门禁的必要条件

GitHub 成功状态没有分钟级 TTL。项目一 main 设置两组独立规则：更新入口只允许部署密钥（GitHub 的 DeployKey bypass 是仓库级，不能按单 key 限制，实际只保留一把写 key）；CI 与 `change-guard/release` 检查无 bypass。GitHub Actions 的 `pull_request` check 绑定 PR **head**，不是 synthetic merge；受信合并程序独立核验 synthetic 父提交与树等于 head 树、head CI 成功，并只用精确旧 main lease 快进推送 head。普通账号即使能创建 PR，也无法用旧绿色状态直接合并。`.github/workflows/` 变更和 `charts/demo` 不在操作员 pin 白名单都是不可审批的硬 BLOCK。

专用部署密钥属于信任边界，持有人可绕过更新入口限制；它只放在服务主机的受限路径，仓库必须只有一把写部署密钥。仓库管理员能够改规则、集群管理员能够直改集群，本项目不声称能限制这些管理员。更新 `charts/demo` 模板必须由操作员另行更新 `approved_chart_digest`（当前真实 Git blob digest 为 `194baf90afd746299e256dc0bf144a12bc6f6325bacf77b40ff01e50b0c3e05d`，不是旧的 `0b2b...` 参考值）；guard 不会自动信任新模板。

合并后 PR 会 closed/merged，daemon 会撤销旧 head 上的历史 guard 状态；main/旧 head 出现 guard error/pending 可能只是撤销，不是 postdeploy 失败。门禁证明看 merge 记录和当时的报告/审批/CI，不要为了好看维持永久绿。

## 实验环境

- master：`11.0.1.10`；worker：`11.0.1.11`。
- master 提供轻量 Agent；业务与观测平台复用项目一。
- 外网代理：`http://11.0.1.1:7890`；集群内流量通过 `NO_PROXY` 直连。
- 单 worker、本地 PVC，不具备节点或磁盘容灾；99.9% SLO 仍需完整七天数据。
- 模型 API 超时/坏引用导致 ERROR；模型新增风险导致 REVIEW，模型没有集群执行工具。

仓库、报告和日志中不得包含 GitHub token、DeepSeek key、SSH 私钥、sudo 密码或管理员 kubeconfig。
