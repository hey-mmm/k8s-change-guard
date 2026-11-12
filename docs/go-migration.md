# Python → Go 迁移记录

本次将 Agent 核心、命令行、GitHub 轮询门禁、受限合并、发布后验证、知识检索、DeepSeek 调用及短期集群凭据续期统一迁移为 Go 0.3.0。运行形态为一个静态 Linux 二进制和受信知识库；Helm、kubectl、bubblewrap、Git、OpenSSH 继续作为固定的外部工具。Ansible 仍使用其自身所需的 Python，Agent 服务无需 Python、pip 或虚拟环境。

## Python 备份

迁移基线为 `d21cef44b95e74889fb92390a49f55b5e7d92631`（Python 0.2.3）。删除主分支活动 Python 实现前，已创建并核验：

- [备份分支 backup/python-0.2.3](https://github.com/hey-mmm/k8s-change-guard/tree/backup/python-0.2.3)。
- [备份标签 python-v0.2.3](https://github.com/hey-mmm/k8s-change-guard/tree/python-v0.2.3)。
- 本地源码 ZIP 与含完整 Git 历史的 bundle，附 SHA-256。

备份范围为 Git 跟踪文件及 Git 历史，不打包凭据、kubeconfig、服务状态目录或虚拟环境。旧 master release 另行保留，操作员可以按运维文档回切。

## 模块对应关系

| 原 Python 模块 | Go 实现 | 主要职责 |
| --- | --- | --- |
| engine.py | internal/guard/engine.go | 规则、字段差异、容量、证据新鲜度、最终决策 |
| renderer.py | internal/guard/renderer.go | 仅复制允许路径、严格 YAML、bubblewrap 隔离渲染、资源上限 |
| evidence.py | internal/guard/evidence.go | 固定只读 Kubernetes / Prometheus 采集 |
| ai.py | internal/guard/ai.go | 知识来源与原始字节校验、案例检索、DeepSeek 结构与引用校验 |
| github.py | internal/guard/github.go | 精确 Git 对象、路径限制、状态与评论读取 |
| daemon.py | internal/guard/daemon.go | 不可变报告、策略与提交绑定、审批、缓存、失效处理 |
| merge.py | internal/guard/merge.go | 独立重查后使用精确 lease 快进 head 到 main |
| postdeploy.py | internal/guard/postdeploy.go | ArgoCD、Deployment、Pod 镜像、Endpoints、HTTP、指标六类验证 |
| cli.py、运维 Python | cmd/change-guard、internal/guard/renew.go | CLI、25 场景矩阵、凭据续期与到期检查 |

## 回归方法

`testdata/python-oracle.json` 是迁移前一次性生成的 151 份固定输入、决策与规则期望。Go 测试直接读取 JSON，不启动 Python。它覆盖原规则测试的 101 次评估和 25 场景启用、关闭 AI 的 50 次评估。另有独立安全测试、GitHub / daemon / merge、AI schema / 引用、发布后验证、续期等测试。

已核验的集成结果：

- Windows `go test ./...`、`go vet ./...` 通过。
- 151 份 Python 决策与规则对照全部通过。
- Go CLI 的 25/25 合成场景通过；不能将其当成 25 次真实发布。
- 受信知识库来源、快照与片段 SHA-256 校验通过。
- Windows 交叉编译的 Linux 测试二进制在 master 实际运行，133 个顶层测试通过，包括 Linux `flock` 与旧服务锁的互斥验证。

## 0.3.0 发布产物

Windows 使用 `E:/Go/bin/go.exe`（Go 1.25.4）构建：

```powershell
pwsh -NoProfile -File scripts/build-release.ps1 -Go E:/Go/bin/go.exe -Version 0.3.0
```

结果：

- artifact：`dist/k8s-change-guard-0.3.0.tar.gz`
- version `0.3.0`，arch `amd64`，22 个文件，`3481524` bytes
- SHA-256：`28ffe1c159bb39ad851c9ad9b30a34a7f66b3ea5796907218dbb7ab86ddb97e3`
- 包内二进制：ELF 64-bit x86-64，`CGO_ENABLED=0`、`GOOS=linux`、`GOARCH=amd64`、Go 1.25.4
- 重复构建得到相同 SHA-256（确定性归档）
- 归档只含 `k8s-change-guard`、`knowledge/`、`config.example.yaml`、`README.md`

实际部署、GitHub PR、审批、发布与回退的结果以 [验收报告](acceptance.md) 中的 Go 验收部分和独立 `go-*` 原始证据为准，历史 Python 成绩不复用为 Go 上线证明。

## 迁移时修正的问题

1. 锁不能使用“文件存在即占用”的方式，否则进程被终止或主机重启后可能永久拒绝运行。Linux 改为内核 `flock`，Windows 测试使用内核文件锁。
2. 配置了沙箱资源上限就必须实际执行。找不到可信 `prlimit` 时渲染失败，不退回缺少上限的执行方式。
3. Windows 脚本交叉编译 Linux 服务后，恢复主机 Go 环境再运行打包工具；避免在 Windows 执行 Linux 二进制。
4. 区分可选 AI 结果缺失（nil）与模型返回空对象：空对象属于无效结果，明确 ERROR。
5. 测试资源使用与测试工作目录相对的路径，避免交叉编译后嵌入的 Windows 源文件绝对路径使 Linux 测试找不到知识库。

## 保留的边界

决策优先级仍为 BLOCK > ERROR > REVIEW > PASS。AI 不降低硬阻断，不直接写集群或执行回滚。审批仍绑定精确 evaluation、head、base、策略与有效期。main 两组保护规则继续启用，工作流变更和未批准 Chart 摘要继续硬阻断。部署后异常仍通过 Git revert PR 恢复。

Go 中 JSON 整数通常按数值处理：数学上为整数的 `2.0` 可以被接受为整数；多处同时标签不匹配时，证据按键排序输出，可能与 Python 的插入顺序不同。两者不改变硬风险的决策策略。完整七天 SLO、单 worker 节点容灾和本地 PVC 磁盘容灾不在迁移验收结论内。
