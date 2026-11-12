# 项目二完整创建步骤（Go 单二进制版）

本文按当前工作树中的 **Go 0.3.0** 实现编写，目标是把
`k8s-change-guard` 以单个静态 Linux 二进制部署到 `11.0.1.10`（master），让它只读
Kubernetes/Prometheus、轮询项目一仓库、发布 `change-guard/release` 状态，并只在当前
报告、审批、CI 和精确 Git 父提交都成立时才允许更新项目一 `main`。

> **状态声明（必须先读）**
>
> - 历史最终服务是 Python `0.2.3`；其部署、合并、回退和 postdeploy 证据见
>   [验收报告](acceptance.md)，只是历史证据。
> - 当前 Go `0.3.0` 已完成代码、单二进制打包、Ansible 和本地工具，Windows/Linux
>   测试通过，产物已生成并可部署；**尚未部署**。Go 版本的 live 验收保持 pending，
>   文档不把本地测试或历史 Python 结果当作 Go 上线成功。
> - 示例版本统一写 `<新版本>`。发布时 `internal/guard/common.go` 的 `Version` 与
>   `scripts/build-release.sh` 的 tarball 版本必须一致；`--version` 只改变产物名/JSON。

## 1. 架构与信任边界

| 位置 | 角色 | 本项目中的职责 |
| --- | --- | --- |
| `11.0.1.10` master | 控制面 + guard 主机 | 运行一个独立的 `change-guard` systemd 用户；只读 Kubernetes/Prometheus；轮询 GitHub，发布提交状态；受信合并命令在这里使用部署密钥 |
| `11.0.1.11` worker | 业务节点 | 继续运行项目一的 demo、Prometheus、Argo CD 等工作负载；guard 不把业务负载调度到 master |
| GitHub 项目一仓库 | 发布源 | `hey-mmm/Full-Stack-Observability-in-Kubernetes`；包含 `charts/demo`、`gitops/demo/values.yaml`、Argo CD Application 和 CI |
| GitHub 项目二仓库 | guard 源代码 | `hey-mmm/k8s-change-guard` |
| GHCR | 镜像仓库 | `ghcr.io/hey-mmm/observability-demo`；发布必须使用不可变 digest |
| DeepSeek | 模型服务 | 只解释已有证据、引用受信故障案例、提出额外风险；没有集群执行工具 |

数据流：

```text
项目一功能代码 PR
  -> GitHub Actions 测试/构建镜像
  -> 发布 PR（只改固定 chart/values，带精确 digest）
  -> guard 读取 GitHub 候选树（不执行 PR 代码）
  -> bubblewrap 内 Helm 渲染新旧两版
  -> 只读 Kubernetes/Prometheus 证据
  -> 确定性规则 + DeepSeek 解释
  -> PASS / REVIEW / BLOCK / ERROR
  -> GitHub change-guard/release 状态（写在 PR head）
  -> 人工审批（仅 REVIEW，精确评估 ID）
  -> Go merge 校验报告/策略绑定/审批/head CI/synthetic 树/base 祖先/lease
  -> fast-forward 推送已评估 head 到 main（不推 synthetic）
  -> Argo CD 同步
  -> Go postdeploy 只读验证（GitOps revision 与镜像源提交分别传入）
```

**不属于本项目能限制的对象**：仓库管理员可以改 ruleset、添加部署密钥；集群管理员可以
直接改集群；能读部署密钥的人可以绕过更新入口。这些都属于信任边界。

## 2. 前置条件

### 2.1 项目一必须已经可用

1. 仓库默认分支为 `main`，`charts/demo` 和 `gitops/demo/values.yaml` 存在，Argo CD
   Application `demo` 指向该仓库 `main`。
2. demo 工作负载在 `demo` namespace，镜像仓库为
   `ghcr.io/hey-mmm/observability-demo`。
3. 项目一 CI 的聚合检查名为 `Test, lint, render`（以项目一 `main` 实际 workflow 为准）。
4. 项目一支持 digest 发布：`helm template` 能把 `image.digest` 渲染成
   `ghcr.io/hey-mmm/observability-demo@sha256:...`。
5. `charts/demo` 的精确 Git blob pin 已由操作员确认；当前真实 digest 是
   `194baf90afd746299e256dc0bf144a12bc6f6325bacf77b40ff01e50b0c3e05d`。旧的
   `0b2b...` 不是当前值，不能使用。
6. 正常发布修改 `gitops/demo/values.yaml`；模板文件变更必须另行走操作员 pin 更新。
7. `.github/workflows/` 在 base/head 必须完全一致；任何 workflow 修改都是不可审批的硬 BLOCK。

### 2.2 构建主机与目标主机

| 组件 | 要求 |
| --- | --- |
| 构建主机 | Go 1.25+；Linux 用 `scripts/build-release.sh`，Windows 用 `scripts/build-release.ps1` |
| 目标主机 | Debian/Ubuntu，`amd64` 或 `arm64`，systemd |
| 目标运行时 | 单个静态 Linux 二进制；不需要 Python、virtualenv、pip 或源码树 |
| Go 二进制 | `CGO_ENABLED=0 GOOS=linux`，`-trimpath -buildvcs=false -tags netgo,osusergo` |
| 渲染隔离 | Linux bubblewrap；Windows 只能跑规则/采集/预渲染测试，不能当作生产渲染证据 |
| 时钟 | 主机时间必须同步；报告、审批 TTL 和 JWT `exp` 都依赖时间 |

### 2.3 网络

- master 外网通过 `http://11.0.1.1:7890` 代理访问 GitHub/DeepSeek。
- `NO_PROXY` 至少覆盖：
  `127.0.0.1,localhost,::1,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,.svc,.cluster.local,11.0.1.10,11.0.1.11,10.98.137.77,10.104.233.119`
- Prometheus 和 demo 的 ClusterIP 必须从 master 直连，不能被代理劫持。
- 不开放公网 webhook；guard 主动轮询 GitHub，没有监听端口。

### 2.4 目标主机依赖

Ansible 角色安装：

```text
bubblewrap ca-certificates curl git gzip netcat-openbsd openssh-client python3 tar
```

`python3` 只是 Ansible 的远端解释器，不是 change-guard 运行时。服务、token helper、
CLI 和打包 helper 都是 Go。预装可执行的 Helm/kubectl 会复用；缺失时才按固定 SHA-256
下载。

### 2.5 知识库字节与 CRLF

`knowledge/sources/` 的摘要引用校验基于**精确文件字节**。Git 在 Windows/不同
checkout 上做 CRLF 转换会改变 SHA-256，仓库用 `.gitattributes` 固定：

```gitattributes
* text=auto eol=lf
*.sh text eol=lf
knowledge/sources/* -text
```

部署/构建前确认：

```sh
git check-attr text -- knowledge/sources/drills.md
# 预期输出包含 "text: unset"
```

不要对 `knowledge/sources/` 重新规范化行尾。

## 3. 凭据准备（只记录名称和权限，不写值）

所有凭据留在受信主机/控制器的受限文件里，不进入 Git、inventory、命令历史或日志。
控制器上建议 `umask 077`。

### 3.1 GitHub PAT（服务身份）

服务使用一个**只限项目一仓库**的 fine-grained PAT。最小权限：

- Metadata: read；
- Contents: read；
- Pull requests: read；
- Issues: read；
- Commit statuses: read/write。

不要给 Administration、Checks、Contents write、Issues write。保持
`report_comment: false`。控制器文件示例（路径只在 Ansible 变量里引用）：

```text
secrets/github-token
```

### 3.2 DeepSeek API key

放在控制器 `secrets/deepseek-token`，部署后为
`/etc/change-guard/deepseek-token`，`0600`，归 `change-guard` 用户。

### 3.3 合并部署密钥（可选）

- 一把专用写 deploy key：`secrets/merge-deploy-key`；
- GitHub host key：`secrets/github_known_hosts`；
- 仅由 root 包装脚本在停止 daemon 后调用 Go `merge`；不交给 daemon 做任意 push。

GitHub 的 DeployKey bypass 是**仓库级类别**，不能按单把 key ID 收窄；实际只保留一把写 key。

### 3.4 Kubernetes 身份

- 控制器保存 bootstrap/admin kubeconfig（只用于 apply RBAC 和 mint TokenRequest）；
- 目标只得到短生命周期 ServiceAccount token 的 `/etc/change-guard/kubeconfig`，`0600`；
- 目标永远不接收管理员 kubeconfig；
- root-only `change-guard renew-token` 固定读取 `/etc/kubernetes/admin.conf` 和
  `/etc/change-guard/kubeconfig`，无参数、无环境命令注入。

## 4. 构建与打包

### 4.1 版本

Go 版本常量在 `internal/guard/common.go`：

```go
const Version = "0.3.0"
const RuleVersion = "go-2026-11-12.1"
```

发布前确认 `Version` 是要发布的版本。`build-release.sh|ps1 --version` 只影响 tarball
文件名和 JSON，不修改源码常量。

### 4.2 Linux

```sh
scripts/build-release.sh --version "$VERSION"
# -> dist/k8s-change-guard-$VERSION.tar.gz
# -> JSON: status/version/arch/artifact/sha256/bytes/files
```

### 4.3 Windows

```powershell
pwsh -NoProfile -File scripts/build-release.ps1 -Go E:/Go/bin/go.exe -Version 0.3.0
# -> dist\k8s-change-guard-0.3.0.tar.gz
```

脚本已保证：

1. 所有路径先 `Push-Location $Repo`，从任意 cwd 调用都能找到 `cmd/change-guard`；
2. 交叉编译设置 `GOOS=linux GOARCH=amd64 CGO_ENABLED=0`；
3. 在 `go run ./scripts/packaging` 之前**恢复宿主 GOOS/GOARCH/CGO/GOFLAGS**，避免在
   Windows 上尝试执行 Linux 二进制；
4. 临时 staging 目录解析后必须位于系统临时根目录内，才允许递归删除。

### 4.4 产物内容

tarball 只包含：

```text
k8s-change-guard      # 唯一可执行文件，0755
knowledge/            # 0644 文件
config.example.yaml
README.md
```

不包含 tests、Ansible、Python、脚本、VCS 元数据或凭据。所有 tar entry 的 mtime、
uid/gid、mode 和 gzip metadata 归一化，重复构建相同输入得到相同字节。

### 4.5 本地验收（不部署）

```sh
go test ./...
go vet ./...
go run ./cmd/change-guard verify-knowledge --knowledge-dir knowledge
go run ./cmd/change-guard scenario --output /tmp/scenario-matrix.json
sh scripts/acceptance.sh          # Linux，含 gofmt/vet/test/scenario/release artifacts
```

Windows 使用 `gofmt`、`go vet ./...`、`go test ./...` 和
`scripts/build-release.ps1`。`scenario` 是合成回归，不是 live。

## 5. Ansible 单二进制部署

### 5.1 inventory

```ini
[change_guard]
11.0.1.10 ansible_user=<ssh-user>

[change_guard:vars]
ansible_python_interpreter=/usr/bin/python3
ansible_become=true
```

### 5.2 group_vars

复制 `ansible/group_vars/all.yml.example` 为 `ansible/group_vars/all.yml`，至少设置：

```yaml
change_guard_version: "<新版本>"
change_guard_artifact: "{{ playbook_dir }}/../dist/k8s-change-guard-{{ change_guard_version }}.tar.gz"
change_guard_artifact_checksum: "<64-hex SHA-256>"

change_guard_repository: "hey-mmm/Full-Stack-Observability-in-Kubernetes"
change_guard_base_branch: "main"
change_guard_status_context: "change-guard/release"
change_guard_approvers:
  - "hey-mmm"

change_guard_github_token_src: "{{ playbook_dir }}/../secrets/github-token"
change_guard_deepseek_token_src: "{{ playbook_dir }}/../secrets/deepseek-token"
change_guard_bootstrap_kubeconfig: "{{ lookup('env', 'HOME') }}/.kube/config"
change_guard_token_ttl: "12h"
change_guard_token_refresh_before_seconds: 7200
change_guard_force_token_rotation: false

change_guard_merge_required_ci: "Test, lint, render"
change_guard_approved_chart_digest: "194baf90afd746299e256dc0bf144a12bc6f6325bacf77b40ff01e50b0c3e05d"
```

`change_guard_merge_required_ci` 必须是单个字符串。`change_guard_approved_chart_digest`
是精确 Git blob digest；普通发布 PR 不能自行更新。

### 5.3 执行

```sh
# 从仓库根目录执行；首次会安装 RBAC、token、config、service 与 timers
ansible-playbook -i ansible/inventory.example.ini ansible/site.yml

# 幂等检查：第二次应 changed=0（token 未进入刷新窗口时）
ansible-playbook -i ansible/inventory.example.ini ansible/site.yml
```

角色顺序：

1. `preflight`：Debian/Ubuntu、版本格式、artifact SHA-256、控制器凭据、kubectl、userns；
2. `packages`：运行时包与 Helm/kubectl 选择；
3. `user`：`change-guard` 系统用户、state/config/release 目录；
4. `release`：双侧 SHA-256、解包单二进制+knowledge、版本核验、唯一可执行文件、不可变
   `/opt/change-guard/releases/<version>`、`.artifact.sha256`、`.complete`、`current` symlink；
5. `rbac`：namespace、ServiceAccount、node/pod 只读、demo workload 只读、Argo CD 只读；
6. `token`：用 Go `check-token` 判断是否需要新 token；在控制器上 mint `12h` TokenRequest；
7. `configure`：非密配置、PAT/DeepSeek token、proxy env、可选 merge 部署密钥；
8. `service`：hardened systemd unit，指向 `current/k8s-change-guard daemon`；
9. `renewal`：Go `renew-token` 6h timer + `check-token` 1h monitor timer；
10. `verify`：service/timers、用户、凭据权限、token、RBAC 边界、二进制版本。

### 5.4 安装后的固定路径

| 路径 | 用途 | 权限 |
| --- | --- | --- |
| `/opt/change-guard/current/k8s-change-guard` | 唯一 Go 二进制 | `0755 root` |
| `/opt/change-guard/releases/<version>/knowledge` | 知识库 | `0644` 文件 |
| `/etc/change-guard/config.yaml` | 非密配置 | `0640 root:change-guard` |
| `/etc/change-guard/kubeconfig` | 短生命周期 token | `0600 change-guard` |
| `/etc/change-guard/github-token` | GitHub PAT | `0600 change-guard` |
| `/etc/change-guard/deepseek-token` | DeepSeek key | `0600 change-guard` |
| `/etc/change-guard/proxy.env` | 代理环境 | `0600 change-guard` |
| `/var/lib/change-guard/` | 状态/报告 | `0700 change-guard` |
| `change-guard-token-renew.timer` | 每 6h 固定续期 | root oneshot |
| `change-guard-token-check.timer` | 每 1h 到期监测 | root oneshot |

## 6. Token 续期与检查

Go CLI 提供两个固定命令：

```sh
# 只读取 kubeconfig、解码 JWT exp，不打印 token；0=valid, 1=rotate, 2=error
change-guard check-token /etc/change-guard/kubeconfig --min-remaining 3600

# root-only、无参数；固定 kubectl admin.conf + change-guard/change-guard + 12h
sudo change-guard renew-token
```

systemd unit：

```ini
# change-guard-token-renew.service
ExecStart=/opt/change-guard/current/k8s-change-guard renew-token

# change-guard-token-check.service
ExecStart=/opt/change-guard/current/k8s-change-guard check-token \
  /etc/change-guard/kubeconfig --min-remaining 60
```

续期服务以 root 运行，只写 `/etc/change-guard`；daemon 继续以 `change-guard` 用户运行。
服务用户不能执行 root helper、读 `/etc/kubernetes/admin.conf` 或改 unit/timer。若 guard
主机不是 control-plane，使用控制侧轮换：

```sh
BOOTSTRAP_KUBECONFIG="$HOME/.kube/config" \
TARGET_KUBECONFIG=/tmp/change-guard-kubeconfig \
TOKEN_TTL=12h sh scripts/rotate-kube-token.sh
```

`rotate-kube-token.sh` 已改为纯 shell，不再调用 Python；token 只写入 `0600` 文件，不打印。

## 7. 健康、验收与场景工具

```sh
# 本机/目标主机只读健康检查（service、binary、token、timer、HTTP、可选 RBAC）
sh scripts/health-check.sh --config /etc/change-guard/config.yaml
sh scripts/health-check.sh --config /etc/change-guard/config.yaml --rbac

# 本地 Go 验收（gofmt/vet/test/scenario/knowledge/release，不部署）
sh scripts/acceptance.sh

# 独立合成场景矩阵；需要 Go 或已安装二进制
sh scripts/scenario-matrix.sh /tmp/scenario-matrix.json
CHANGE_GUARD_BIN=/opt/change-guard/current/k8s-change-guard \
  sh scripts/scenario-matrix.sh /tmp/scenario-matrix.json

# RBAC 边界
sh scripts/verify-rbac.sh /etc/change-guard/kubeconfig
```

这些脚本都是 shell 或 Go，不依赖 Python。`scenario` 结果必须标注 synthetic；`health`
只读，不修改集群。

## 8. 合并与发布后验证

### 8.1 合并

```sh
sudo scripts/merge-release.sh <PR>
```

包装脚本：

- 要求 root；
- 记录 daemon 原状态，停止 `change-guard.service`；
- `trap ... EXIT` 恢复原状态；
- 以 `change-guard` 用户读取 `proxy.env`；
- 执行 `change-guard merge --config ... --pr <PR>`；
- 不做额外 push、不改 ruleset、不调用 GitHub Merge API。

Go merge 仍校验报告 schema/策略绑定、精确 head/base、审批、workflow tree equality、
独立重算 chart pin、head-bound GitHub Actions CI、synthetic parents/tree、报告摘要和精确
lease，再 fast-forward `main` 到已评估 head。它不推送 synthetic commit。

### 8.2 发布后验证

```sh
sudo -u change-guard /opt/change-guard/current/k8s-change-guard postdeploy verify \
  --config /etc/change-guard/config.yaml \
  --expected-sha <main-head-gitops-revision> \
  --expected-app-sha <image-source-commit> \
  --report /var/lib/change-guard/reports/<evaluation-id>.json
```

`--expected-sha` 是 Argo/GitOps revision；`--expected-app-sha` 是镜像源提交暴露在
`/version` 的 `gitSha`，两者通常不同。Pod 检查匹配 Pod **spec** 的容器名/镜像，并核对
`status.containerStatuses[].imageID`；不把 containerd config ID 当 manifest 引用。
验证器只读，失败只给 `open_revert_pr` 建议，不自动回滚。

## 9. GitHub 规则与 CI

仓库 CI（`.github/workflows/ci.yml`）：

- Linux `ubuntu-24.04` 与 Windows `windows-latest`；
- Go 1.25.x；
- `gofmt -l cmd internal scripts/packaging`，有任何输出即失败；
- `go vet ./...`；
- `go test ./...`；
- `change-guard scenario`、`verify-knowledge`；
- Linux 执行 shell `bash -n` 与 `scripts/build-release.sh`；
- Windows 执行 `scripts/build-release.ps1`，覆盖 GOOS/`go run` 回归。

GitHub 分支保护仍应保持：

- 更新入口只允许专用 deploy key；
- CI 与 `change-guard/release` 必需检查无 bypass；
- Actions check 绑定 PR head，不是 synthetic merge；
- `.github/workflows/` 变更硬 BLOCK；
- `charts/demo` pin 变更必须由独立受信操作员流程完成。

## 10. 已知边界

- 单 worker、本地 PVC，无节点/磁盘容灾；99.9% SLO 需要完整七天数据。
- GitHub DeployKey bypass 是仓库级，平台不能按 key 收窄。
- Guard 无法限制仓库管理员改规则或集群管理员直改集群。
- 模型没有集群执行工具；AI 新增风险只能提升到 REVIEW，不能覆盖硬 BLOCK。
- 发布后验证失败只建议 Git revert PR，不自动回滚。
- Windows 本地渲染不是生产证据；生产 Helm 渲染必须在 Linux bubblewrap 内完成。
- 旧 Python `0.2.3` 证据不能当作 Go `0.3.0` live 通过；Go live 验收见
  [acceptance.md](acceptance.md) 的待执行清单。
