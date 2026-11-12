# Kubernetes 发布变更风险守护 Agent

复用 [项目一](https://github.com/hey-mmm/Full-Stack-Observability-in-Kubernetes) 的 Kubernetes、Prometheus、GHCR 和 Argo CD，在发布配置进入 main 前收集证据并控制放行。运行于 master 的独立 systemd 用户，不接收公网 webhook，不执行 PR 中的程序，不向集群写入。

**完成状态与真实限制以 [验收报告](docs/acceptance.md) 为准。测试通过、服务 active、状态绿色均不能单独代表发布已验收。**

| 文档 | 内容 |
| --- | --- |
| [完整创建步骤](docs/creation-steps.md) | 环境、凭据、安装、规则、发布与复现 |
| [项目讲解](docs/project-explained.md) | 模块职责、工具配合、AI 的实际价值 |
| [设计与安全边界](docs/design.md) | 隔离、权限、提交绑定、TTL、人工确认 |
| [验收报告](docs/acceptance.md) | 测试、真实 PR 拒绝、发布后结果、原始证据 |
| [故障复盘](docs/fault-review.md) | 开发部署中遇到的问题与修复 |
| [运维与演示](docs/runbook.md) | 日常检查、轮换、演示、Git revert PR |
| [Ansible](ansible/README.md) | 参数与安装细节 |

## 快速本地验证

```bash
python -m venv .venv
. .venv/bin/activate
python -m pip install -e .
python -m unittest discover -s tests -v
python scripts/scenario-matrix.py --output /tmp/scenario-matrix.json
python -m change_guard verify-knowledge --knowledge-dir knowledge
```

Windows 可以运行规则/采集/模型测试以及预渲染清单评估；**生产 Helm 渲染必须在 Linux bubblewrap 中完成**，缺少隔离环境时失败退出。

## 运行接口

```bash
# 生产服务：只执行可信已安装版本
python -m change_guard.daemon --config /etc/change-guard/config.yaml --once

# 显式合并：核对当前报告/精确提交/审批/CI/有效期，再以专用密钥更新 main
python -m change_guard.merge --config /etc/change-guard/config.yaml --pr <编号>

# 命令参数以实际 --help 为准
python -m change_guard --help
python -m change_guard.postdeploy --help
```

`PASS / REVIEW / BLOCK / ERROR` 各自记录规则、证据、AI 分析和最终决策。BLOCK 不可由 AI 或人工覆盖；ERROR 必须修复后重评；REVIEW 审批绑定评估 ID、head SHA、main 基线与有效期。

## 真实门禁的必要条件

GitHub 成功状态没有分钟级 TTL。项目一 main 设置两组独立规则：更新入口只允许专用部署密钥；CI 与 `change-guard/release` 检查无绕过者。受信合并程序在更新前再次校验当前报告、人工审批和证据时效，并使用精确旧 main 的 lease。普通账号即使能创建 PR，也无法用旧绿色状态直接合并。

专用部署密钥属于信任边界，持有人可绕过更新入口限制；它只放在服务主机的受限路径。仓库管理员能够改规则，集群管理员能够直改集群，本项目不声称能限制这些管理员。

## 实验环境

- master：`11.0.1.10`；worker：`11.0.1.11`。
- master 提供轻量 Agent；业务与观测平台复用项目一。
- 外网代理：`http://11.0.1.1:7890`；集群内流量通过 `NO_PROXY` 直连。
- 单 worker、本地 PVC，不具备节点或磁盘容灾；99.9% SLO 仍需完整七天数据。
- 模型 API 超时/坏引用导致 ERROR；模型新增风险导致 REVIEW，模型没有集群执行工具。

仓库、报告和日志中不得包含 GitHub token、DeepSeek key、SSH 私钥、sudo 密码或管理员 kubeconfig。
