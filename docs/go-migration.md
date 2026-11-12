# Python → Go 迁移记录

本次将 Agent 核心、命令行、GitHub 轮询门禁、受限合并、发布后验证、知识检索、DeepSeek 调用及短期集群凭据续期统一迁移为 Go。当前版本为 **0.3.2**；运行形态为一个静态 Linux 二进制和受信知识库，Helm、kubectl、bubblewrap、Git、OpenSSH 继续作为固定的外部工具。Ansible 仍使用其自身所需的 Python，Agent 服务无需 Python、pip 或虚拟环境。

> **版本历史（不要混用）**
>
> - `0.3.0` 曾在首次 Ansible 部署中因 `check-token` 位置参数顺序失败，已回切 Python `0.2.3`；该失败 release 目录保留且不修改。
> - root 修复 CLI 后构建 `0.3.1`，以避免同一不可变版本目录出现不同 artifact。`0.3.1` 完成了真实部署和部署级 live，并完成危险 PR8 BLOCK 和 PR9 REVIEW 精确审批；但正式 merge 先因 `--evaluation-id` 缺省被拒绝，显式 ID 后又因匿名 CI 403 失败，`main` 未变。
> - `0.3.2`（commit `41f2ba1`）修复上述两个合并缺陷：state lock 内取该 PR 当前索引的评估、CI check-runs 使用现有 token；已完成构建、测试、两遍 Ansible 和部署级 verify。真实发布、回退和最终 live 已通过，见最终验收。
> - `0.3.0`/`0.3.1` 的构建记录和真实结果都是历史事实，不改写成成功。完整结论只以 [验收报告](acceptance.md) 与独立 `go-*` 原始证据为准。

## Python 备份

迁移基线为 `d21cef44b95e74889fb92390a49f55b5e7d92631`（Python 0.2.3）。删除主分支活动 Python 实现前，已创建并核验：

- [备份分支 backup/python-0.2.3](https://github.com/hey-mmm/k8s-change-guard/tree/backup/python-0.2.3)，指向 `d21cef44b95e74889fb92390a49f55b5e7d92631`。
- [备份标签 python-v0.2.3](https://github.com/hey-mmm/k8s-change-guard/tree/python-v0.2.3)，同样指向 `d21cef44b95e74889fb92390a49f55b5e7d92631`。
- 本地 `outputs/python-backup-0.2.3/`：`python-0.2.3-source.zip`（全部 Git 跟踪文件）、`k8s-change-guard-python.bundle`（全部引用与完整历史）、`sha256.json` 和 `恢复说明.md`。
- `work/python-baseline/` 保留迁移前的工作副本，供只读比对；它不是运行时依赖。

恢复源码（任选一种，均不需要旧虚拟环境）：

```sh
# 从远端分支或标签恢复
git fetch origin backup/python-0.2.3 python-v0.2.3
git switch --detach backup/python-0.2.3
# 或
git clone <项目二仓库 URL> recovered-python
git -C recovered-python checkout python-v0.2.3

# 从离线 bundle 恢复（推荐的离线路径）
git clone k8s-change-guard-python.bundle recovered-python
git -C recovered-python checkout python-v0.2.3
```

恢复后先核对备份文件摘要，再决定是否回切服务：

```sh
cd outputs/python-backup-0.2.3
jq -r '.[] | "\(.Hash|ascii_downcase)  \(.file)"' sha256.json | sha256sum -c -
# Windows PowerShell:
# Get-FileHash .\python-0.2.3-source.zip, .\k8s-change-guard-python.bundle -Algorithm SHA256
```

备份只包含 Git 跟踪文件和 Git 历史，不包含 token、私钥、kubeconfig、服务状态目录、虚拟环境或 `/etc` 配置。源码恢复不等于服务恢复；生产回切还要使用 master 上保留的旧 Python release、旧 unit 和旧非密配置，由 root 按 [runbook](runbook.md#13-回切到-python-023) 执行，并先核对目标 release 与 `current` 指向。不要把备份 ZIP 直接覆盖到 `/opt/change-guard/current`。

## 模块对应关系

| 原 Python 模块 | Go 实现 | 主要职责 |
| --- | --- | --- |
| engine.py | internal/guard/engine.go | 规则、字段差异、容量、证据新鲜度、最终决策 |
| renderer.py | internal/guard/renderer.go | 仅复制允许路径、严格 YAML、bubblewrap 隔离渲染、资源上限 |
| evidence.py | internal/guard/evidence.go | 固定只读 Kubernetes / Prometheus 采集 |
| ai.py | internal/guard/ai.go | 知识来源与原始字节校验、案例检索、DeepSeek 结构与引用校验 |
| github.py | internal/guard/github.go | 精确 Git 对象、路径限制、状态与评论读取 |
| daemon.py | internal/guard/daemon.go | 不可变报告、策略与提交绑定、审批、缓存、失效处理 |
| merge.py | internal/guard/merge.go | 独立重查；在当前索引解析评估 ID；使用精确 lease 快进 head 到 main |
| postdeploy.py | internal/guard/postdeploy.go | ArgoCD、Deployment、Pod 镜像、Endpoints、HTTP、指标六类验证 |
| cli.py、运维 Python | cmd/change-guard、internal/guard/renew.go | CLI、25 场景矩阵、凭据续期与到期检查 |

## 回归方法

`testdata/python-oracle.json` 是迁移前一次性生成的 151 份固定输入、决策与规则期望。Go 测试直接读取 JSON，不启动 Python。它覆盖原规则测试的 101 次评估和 25 场景启用、关闭 AI 的 50 次评估。另有独立安全测试、GitHub / daemon / merge、AI schema / 引用、发布后验证、续期等测试。

已核验的迁移集成结果（0.3.0/0.3.1 迁移期）：

- Windows `go test ./...`、`go vet ./...` 通过。
- 151 份 Python 决策与规则对照全部通过。
- Go CLI 的 25/25 合成场景通过；不能将其当成 25 次真实发布。
- 受信知识库来源、快照与片段 SHA-256 校验通过。
- Windows 交叉编译的 Linux 测试二进制在 master 实际运行，133 个顶层测试通过，包括 Linux `flock` 与旧服务锁的互斥验证。
- `cmd/change-guard/main_test.go` 的 `TestCheckTokenFlagsBeforeAndAfterPath` 覆盖 `check-token` 的“位置参数在前”和“flag 在前”两种顺序及 `--flag=value` 形式；这是 0.3.0 参数顺序故障的回归测试。

0.3.2 的 `go test ./... -count=1` 与 `go vet ./...` 也通过，并新增当前评估 ID 选择、显式旧 ID 拒绝、CI Bearer 认证、403 不泄露和 redirect 拒绝回归；这些是合并路径修复测试，不等同真实 live。

## 0.3.0 首次部署失败（历史，保留原记录）

0.3.0 产物本身可构建，首次真实 Ansible 部署在切换 release 后、写 config/service 前失败，随后立即回切：

- 失败任务：`ansible/roles/change_guard/tasks/token.yml:19`
  `Check remaining token lifetime with the installed Go binary`。
- 命令：`... check-token /etc/change-guard/kubeconfig --min-remaining 7200`。
- 结果：`rc=2`，输出
  `{"status":"error","error":"usage: change-guard check-token KUBECONFIG [--min-remaining SECONDS]"}`。
- 根因：Go `flag` 包在第一个位置参数处停止解析；当时 CLI 只接受
  `check-token --min-remaining 7200 KUBECONFIG`。因此 token/verify 任务和每小时的
  token-check unit 都会失败；token 和二进制本身没有损坏。
- 回切：`/opt/change-guard/current` 恢复为 `releases/0.2.3`，Python `change-guard.service`
  保持 active。`/opt/change-guard/releases/0.3.0` 与 `.complete`、
  `.artifact.sha256` 保留供检查，**不得手改或删除标记来绕过不可变检查**。
- 修复：先识别首个非 flag 位置参数并移到参数末尾，再调用 `flags.Parse`，从而同时支持
  “位置参数在前”和“flag 在前”；Ansible 任务、systemd unit 与文档无需二选一。另加 CLI
  回归测试。由于二进制改变、0.3.0 的同版本不可变目录已存在，版本升为 0.3.1。
- 代理当时也出现独立的环境阻塞；它不是这个 CLI bug 的原因，也不作为 Go 门禁结论。

0.3.0 构建记录（保留，不伪改）：

- artifact：`dist/k8s-change-guard-0.3.0.tar.gz`
- version `0.3.0`，arch `amd64`，22 个文件，`3481524` bytes
- SHA-256：`28ffe1c159bb39ad851c9ad9b30a34a7f66b3ea5796907218dbb7ab86ddb97e3`
- 部署结果：首次 Ansible 失败并回切 Python 0.2.3；**不能称为成功上线**。

## 0.3.1 发布产物（历史，保留）

Windows 使用 `E:/Go/bin/go.exe`（Go 1.25.4）构建：

```powershell
pwsh -NoProfile -File scripts/build-release.ps1 -Go E:/Go/bin/go.exe -Version 0.3.1
```

`internal/guard/common.go` 的 `Version` 已是 `0.3.1`；`--version` 只改变产物名/JSON 字段。结果以构建 JSON 为准：

- artifact：`dist/k8s-change-guard-0.3.1.tar.gz`
- version `0.3.1`，arch `amd64`，22 个文件，`3482084` bytes
- SHA-256：`51c42df2b07a13e60c6558df09fd320e058533818a4b45fe41c08faf3240f9ec`
- 包内二进制：ELF 64-bit x86-64，`CGO_ENABLED=0`、`GOOS=linux`、`GOARCH=amd64`、Go 1.25.4
- 归档只含 `k8s-change-guard`、`knowledge/`、`config.example.yaml`、`README.md`
- 构建脚本按确定性归档设计（固定 mtime/uid/gid/mode 与 gzip metadata）；本轮 JSON 记录的是单次构建结果，不把“重复构建相同”写成未经记录的事实。
- 旧的 `0.3.0` artifact 保留在 `dist/`，不覆盖、不改名、不重算哈希。

真实部署结果（部署级，不是完整项目验收）：0.3.1 于 2026-11-12 部署到 master，第一遍 Ansible `ok=85 changed=11 failed=0`，第二遍 `ok=73 changed=0 failed=0`；`current` 指向 `releases/0.3.1`，服务报告 `change-guard 0.3.1 (rules go-2026-11-12.1)`、静态 ELF，systemd active、双 timer active、只读 RBAC、renew-token、knowledge、collect（2 nodes / 28 pods）、bwrap render（7 个 chart 文件 / `194baf90...`）、真实 DeepSeek 和 `daemon --once` 均通过。证据见 [acceptance.md](acceptance.md) 的 0.3.1 部署小节。

0.3.1 的 PR 历史同样保留：PR8 危险发布先 BLOCK，追加启动故障后旧 head 失效、新 head 重评仍 BLOCK，merge API 405、直推 422；PR9 为 REVIEW 并由用户授权操作员精确审批 `ev-e941441d7a1f429dfbf37dd5`。正式 merge 先因脚本漏传 `--evaluation-id` 返回 `invalid evaluation id`，显式补 ID 后又因匿名 CI 配额 403 返回 `public CI check lookup failed`，`main` 未变。0.3.1 因此只是“部署成功 + 门禁/审批部分验收”，不是完整发布成功。

## 0.3.2 发布产物（当前）

0.3.2 在 commit `41f2ba1`（“Fix current-evaluation merge selection and authenticate CI proof lookups”）修复 0.3.1 暴露的两个实现缺陷：

- `merge --evaluation-id` 可省略；取得 state lock、读取当前索引后解析该 PR 的 recorded evaluation。显式 ID 必须与当前索引完全一致，旧 ID/未索引 PR/缺失记录 fail closed。
- CI check-runs 使用现有 `github.token`，修复匿名共享出口配额 403；请求仍固定 `api.github.com`、禁止 redirect、保留 2 MiB 响应上限、head SHA、`github-actions` app、required name 和 latest-success 校验。

构建与验证：

- `go test ./... -count=1`、`go vet ./...` 通过；新增评估 ID 选择、显式旧 ID 拒绝、Bearer 认证、403 不泄露和 redirect 拒绝回归。
- artifact：`dist/k8s-change-guard-0.3.2.tar.gz`
- version `0.3.2`，arch `amd64`，22 个文件，`3485074` bytes
- SHA-256：`3929180048fbfc107eaf18bfb22b19983be56f326467d15dcc6a511d2b074be8`；构建记录见 [go-build-artifact-0.3.2.json](evidence/go-build-artifact-0.3.2.json)
- 归档内容与 0.3.1 相同，只含单二进制、knowledge、`config.example.yaml`、`README.md`；0.3.0/0.3.1 artifact 均保留，不覆盖、不重算。

部署级结果：0.3.2 于 2026-11-12 部署到 master，部署前备份 `/var/backups/change-guard/pre-go-0.3.2-20261112-133927`；第一遍 Ansible `ok=84 changed=7 failed=0`，第二遍 `ok=73 changed=0 failed=0`；`current -> releases/0.3.2`，服务 `change-guard 0.3.2 (rules go-2026-11-12.1)`、静态 ELF、双 timer active、只读 RBAC、renew-token、knowledge 均通过。证据见 [acceptance.md](acceptance.md) 的 0.3.2 小节。**0.3.2 的最终 live、PR、发布后验证和回退均已完成，见 [最终验收](go-acceptance-final.md)。**

实际部署、GitHub PR、审批、发布与回退的结果以 [验收报告](acceptance.md) 中的分项和独立 `go-*` 原始证据为准。历史 Python 成绩不复用为 Go 上线证明。

## 迁移时修正的问题

1. 锁不能使用“文件存在即占用”的方式，否则进程被终止或主机重启后可能永久拒绝运行。Linux 改为内核 `flock`，Windows 测试使用内核文件锁。
2. 配置了沙箱资源上限就必须实际执行。找不到可信 `prlimit` 时渲染失败，不退回缺少上限的执行方式。
3. Windows 脚本交叉编译 Linux 服务后，恢复主机 Go 环境再运行打包工具；避免在 Windows 执行 Linux 二进制。
4. 区分可选 AI 结果缺失（nil）与模型返回空对象：空对象属于无效结果，明确 ERROR。
5. 测试资源使用与测试工作目录相对的路径，避免交叉编译后嵌入的 Windows 源文件绝对路径使 Linux 测试找不到知识库。
6. `check-token` 必须兼容文档/Ansible/unit 已使用的“位置参数在前”写法；修复同时保留 flag-first，并用 CLI 测试固定两种顺序。该问题曾导致 0.3.0 首次部署失败，修复后升版 0.3.1。
7. 0.3.1 的 `merge-release.sh` 只传 PR 号码，而 merge 要求显式评估 ID，导致正常发布被 `invalid evaluation id` 拒绝。0.3.2 改为在 state lock 内从当前索引解析；显式 ID 仅作核对，旧 ID 仍然拒绝。
8. 0.3.1 的 CI check-runs 查询走匿名出口，配额耗尽时 403。0.3.2 改用服务已有的 `github.token`；不新增 Checks/Administration 权限，也不改变固定 URL、2 MiB 上限和 head/app/CI 校验。

## 保留的边界

决策优先级仍为 BLOCK > ERROR > REVIEW > PASS。AI 不降低硬阻断，不直接写集群或执行回滚；模型新增风险最多把结果提升到 REVIEW。审批仍绑定精确 evaluation、head、base、策略与有效期；0.3.1 的 PR9 审批由用户授权的 dsh 操作员以 owner 身份发出，在线 DeepSeek 没有自批/合并/回滚权限。AI 的额外风险需要独立核对：PR9 中“未改 env 被脱敏”这一条已被 base/head 精确 blob 证伪，属于误报；未预留 requests、告警和低流量等真实 REVIEW 限制保留。main 两组保护规则继续启用，工作流变更和未批准 Chart 摘要继续硬阻断。部署后异常仍通过 Git revert PR 恢复。

正常发布的真实结果通常是 **REVIEW + 人工精确批准**，不是自动 PASS：单 worker 的资源/容量余量、低流量和当前错误/延迟都可能要求人工确认。合成场景中的 PASS 不能当作真实集群 PASS。每份报告只能代表当次 head/base 和有效期；合并前必须重校验。

Go 中 JSON 整数通常按数值处理：数学上为整数的 `2.0` 可以被接受为整数；多处同时标签不匹配时，证据按键排序输出，可能与 Python 的插入顺序不同。两者不改变硬风险的决策策略。

发布后的 60 秒等待只用于确认 Argo/工作负载进入稳定状态；指标来自最近 **5 分钟**聚合窗口，不是精确覆盖新版本的 60 秒。单 worker、本地 PVC 不具备节点/磁盘容灾，99.9% SLO 需要完整七天真实数据，迁移测试和一次发布验收都不能证明它。
