# 项目二完整创建步骤（可复现）

本文按当前工作树中的 Python、Ansible、脚本和已记录的实验环境编写，目标是把
`k8s-change-guard` 部署到 `11.0.1.10`（master），让它只读集群、轮询项目一仓库、
发布 `change-guard/release` 状态，并只在当前报告、审批、CI 和精确 Git 父提交都成立时
才允许更新项目一 `main`。

> **状态声明（必须先读）**
>
> - 当前最终服务为 `0.2.3`；真实合并、回退、发布后验证和最终验收结论以 `docs/acceptance.md` 为准。
> - 本文是创建/复现步骤，不复制实时版本、测试数量或验收数字；历史版本的验证只作为历史证据，不能充当现状。
> - 示例版本统一用 `<新版本>`；发布前让 `pyproject.toml` 的 `version` 与 `change_guard/__init__.py` 的 `__version__` 相等。

## 1. 架构与信任边界

| 位置 | 角色 | 本项目中的职责 |
| --- | --- | --- |
| `11.0.1.10` master | 控制面 + guard 主机 | 运行一个独立的 `change-guard` systemd 用户；只读 Kubernetes/Prometheus；轮询 GitHub，发布提交状态；受信合并命令在这里使用部署密钥 |
| `11.0.1.11` worker | 业务节点 | 继续运行项目一的 demo、Prometheus、Argo CD 等工作负载；guard 不把业务负载调度到 master |
| GitHub 项目一仓库 | 发布源 | `hey-mmm/Full-Stack-Observability-in-Kubernetes`；包含 `charts/demo`、`gitops/demo/values.yaml`、Argo CD Application 和 CI |
| GitHub 项目二仓库 | guard 源代码 | `hey-mmm/k8s-change-guard`；当前 commit/版本/CI 以 `docs/acceptance.md` 为准 |
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
  -> 受信 merge 校验报告/策略绑定/审批/head CI/synthetic 树/base 祖先/lease
  -> fast-forward 推送已评估 head 到 main（不推 synthetic）
  -> Argo CD 同步
  -> 发布后只读验证（GitOps revision 与镜像源提交分别传入）
```

**不属于本项目能限制的对象**：仓库管理员可以改 ruleset、添加部署密钥；集群管理员可以
直接改集群；能读部署密钥的人可以绕过更新入口。这些都属于信任边界，文档不能声称
guard 能阻止他们。

## 2. 前置条件

### 2.1 项目一必须已经可用

先在项目一仓库确认以下事实；任何一项不成立，guard 的发布链就不完整：

1. 仓库为 `hey-mmm/Full-Stack-Observability-in-Kubernetes`，默认分支 `main`。
2. `charts/demo` 和 `gitops/demo/values.yaml` 存在，Argo CD Application `demo`
   指向该仓库的 `main`。
3. demo 工作负载在 `demo` namespace，镜像仓库为
   `ghcr.io/hey-mmm/observability-demo`。
4. 项目一 CI 的聚合检查名是 `Test, lint, render`（以项目一 `main` 上实际
   workflow 为准）。本项目 ruleset 和 `merge.py` 都按这个名称校验。
5. 项目一已经支持 digest 发布：`helm template` 能把 `image.digest` 渲染成
   `ghcr.io/hey-mmm/observability-demo@sha256:...`，且 CI 会拒绝非法 digest。
   没有这个能力时，不要打开 `require_digest: true` 假装通过。
6. 项目一 `main` 已经应用本项目的两组 ruleset（见第 9 节），或者你准备在 guard
   上线前应用；否则“旧绿色状态直接合并”的窗口仍然存在。
7. GHCR 镜像实际存在，且发布 PR 使用 digest，不是可移动 tag。
8. `charts/demo` 的精确 Git blob pin 已经由操作员确认。当前真实 Git blob digest 是
   `194baf90afd746299e256dc0bf144a12bc6f6325bacf77b40ff01e50b0c3e05d`；旧参考文件
   上级 `work/approved-chart.json` 的 `0b2b19...` 与真实 blob 不一致，不能使用。
9. 正常发布修改 `gitops/demo/values.yaml`（image digest/配置），不是 `charts/demo`
   自带的默认 `values.yaml`；模板文件变更必须另行走操作员 pin 更新。
10. `.github/workflows/` 在 base/head 必须完全一致；任何 workflow 修改都是不可审批
    的硬 BLOCK，因为 GitHub Actions 对同仓库 PR 使用 PR 分支上的 workflow。

### 2.2 主机与版本

已在实验环境确认过的基线：

| 组件 | master `11.0.1.10` | worker `11.0.1.11` |
| --- | --- | --- |
| OS | Ubuntu 22.04.5 LTS | 同左 |
| Kubernetes | `v1.37.2` | 同左 |
| Helm | `v3.22.1` | 业务不需要 |
| kubectl | `v1.37.2` | 有二进制但无 kubeconfig |
| bubblewrap | `0.6.1` | 不要求 |
| Python | 系统 `3.10.12` | 同左 |
| Ansible（控制器） | `ansible-core 2.21.6` | — |
| CPU/内存 | 2 vCPU / 约 3.8 GiB | 4 vCPU / 约 11 GiB |

要求：

- guard 主机必须是 Debian/Ubuntu；角色里的包名和 systemd 路径按 Debian 系固定。
- 架构只支持 `amd64`、`arm64`；预装 Helm/kubectl 可执行时角色优先使用它们，
  缺失时才按固定 SHA-256 下载。
- 生产渲染必须在 Linux bubblewrap 中执行；Windows 只能跑规则/采集/预渲染测试，
  不能把 Windows 的“本地渲染成功”当成生产证据。
- 主机时间必须同步。报告、审批有效期、TokenRequest JWT 的 `exp` 都依赖时间。

### 2.3 网络

- master 外网通过 `http://11.0.1.1:7890` 代理访问 GitHub/DeepSeek。
- `NO_PROXY` 至少覆盖：
  `127.0.0.1,localhost,::1,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,.svc,.cluster.local,11.0.1.10,11.0.1.11,10.98.137.77,10.104.233.119`
- Prometheus 和 demo 的 ClusterIP 必须从 master 直连，不能被代理劫持。
- 不开放公网 webhook；guard 主动轮询 GitHub，没有监听端口。
- 如果 guard 主机不是 master，必须另外准备 TokenRequest 轮换通道；见第 8 节，
  当前 root-only 续期 helper 依赖本机 `/etc/kubernetes/admin.conf`。

### 2.4 主机依赖（角色目前没有全部安装）

角色会安装 `bubblewrap`、`ca-certificates`、`curl`、`gzip`、`python3`、
`python3-pip`、`python3-requests`、`python3-setuptools`、`python3-venv`、
`python3-yaml`、`tar`，并优先使用已安装的 Helm/kubectl。

但受信合并命令还需要：

```sh
# guard 主机上确认存在；角色不会替你安装
command -v git
command -v ssh
command -v nc
```

如果缺少，先安装 `git`、`openssh-client`、`netcat-openbsd`（或等价的 `nc`）。
`merge.py` 通过 `ssh -o ProxyCommand=nc ...` 访问 `ssh.github.com:443`，没有 `nc`
时合并会被拒绝。本文的排障命令还使用 `gh`、`jq`、`curl`；这些是运维工具，不要求
安装到 guard 服务里。

### 2.5 知识库字节与 CRLF

`knowledge/sources/` 的摘要引用校验基于**精确文件字节**。Git 在 Windows/不同
checkout 上做 CRLF 转换会改变 SHA-256，曾导致项目二 CI 失败。仓库用
`.gitattributes` 固定：

```gitattributes
* text=auto eol=lf
*.sh text eol=lf
# Knowledge hashes attest exact snapshot bytes, including source line endings.
knowledge/sources/* -text
```

部署/构建前确认：

```sh
git check-attr text -- knowledge/sources/drills.md
# 预期输出包含 "text: unset"（-text）
git ls-files --eol knowledge/sources | head
```

不要对 `knowledge/sources/` 重新规范化行尾；如果构建产物与 CI 的哈希不一致，先查
checkout 的 CRLF，而不是改知识库摘要。

## 3. 凭据准备（只记录名称和权限，不写值）

所有凭据都必须留在受信主机/控制器的受限文件里，不进入 Git、inventory、命令历史或
日志。建议在控制器上使用 `umask 077`。

### 3.1 GitHub PAT（服务身份）

服务使用一个**只限项目一仓库**的 fine-grained PAT。最小权限：

| 权限 | 级别 | 用途 |
| --- | --- | --- |
| Metadata | Read-only | GitHub 强制要求；读取仓库/PR 元数据 |
| Contents | Read-only | 读取 Git tree/blob；不写代码 |
| Pull requests | Read-only | 列出/读取 PR |
| Issues | Read-only | 读取审批评论（`/guard approve` 是 issue comment） |
| Commit statuses | **Read and write** | 发布 `change-guard/release`；这是唯一的写权限 |

不要授予：

- `Administration`（读取协作者权限端点需要它；本项目故意不需要，见下）
- `Checks` 写权限（不使用 Checks API）
- `Contents` 写权限
- `Issues` 写权限（除非你显式打开 `report_comment: true`；默认关闭）
- `Actions`、`Secrets`、`Workflows`、`Packages` 等与本服务无关的权限

经典 PAT 的等价最小范围是 `repo:status`（公开仓库也可用 `public_repo`；不要为了
方便给 `repo` 全范围，除非仓库确实需要）。`verify_credentials()` 会检查
`X-OAuth-Scopes`；fine-grained PAT 不返回该头，因此代码会检查仓库角色并显示
`statuses_write: inferred`，除非显式做状态写探测。

**已知限制**：fine-grained PAT 路径要求 token 所属账号在仓库上有 `push` 或 `admin`
角色（代码用 `GET /repos` 的 `permissions` 判断）。仓库所有者 `hey-mmm` 满足这个
条件；普通的只读协作者即使 token 只有 statuses write，也可能被启动检查拒绝。这是
“能力推断”的限制，不是让你去加 Administration 权限。

**协作者权限端点返回 403 是预期行为**：

```text
GET /repos/hey-mmm/Full-Stack-Observability-in-Kubernetes/collaborators/hey-mmm/permission
-> 403 Resource not accessible by personal access token
```

不要为了让这个端点返回 200 而加 Administration。个人仓库的审批权限按当前仓库
元数据判断：`owner.type == "User"` 且 `owner.login` 与审批人完全一致（见
`daemon._approval_permission`）。组织仓库或非 owner 协作者仍需要显式权限端点；
当前服务 PAT 没有该权限时会 fail closed（拒绝审批），这是安全行为。

### 3.2 DeepSeek API key

- 只放在 `/etc/change-guard/deepseek-token`（`0600`，`change-guard` 所有）。
- 环境变量名是 `DEEPSEEK_API_KEY`，配置文件只引用路径。
- 模型固定为 `deepseek-chat`，超时/结构错误/引用不合法都是 ERROR，不允许把
  模型失败降级成 PASS。

### 3.3 独立的 GitHub 部署密钥（只给 merge 用）

这是与 PAT 分开的信任边界：PAT 只发布状态，部署密钥只用于受信合并命令。

```sh
umask 077
mkdir -p secrets
ssh-keygen -t ed25519 -f secrets/merge-deploy-key -N '' \
  -C 'change-guard-merge-2026-11'
ssh-keygen -lf secrets/merge-deploy-key.pub
```

然后在项目一仓库 **Settings -> Deploy keys -> Add deploy key**：

- Title：例如 `change-guard-merge-2026-11`
- Key：`secrets/merge-deploy-key.pub` 的内容
- **Allow write access**：勾选
- 只给这一把写部署密钥；不要复用个人 SSH key，不要再添加第二把写部署密钥

原因见第 9 节：GitHub ruleset 的 DeployKey bypass 是仓库级开关，不能按 key ID
收窄；多一把写部署密钥就多一个能绕过更新入口的身份。

`known_hosts` 固定在控制器/主机：

```sh
ssh-keyscan -p 443 ssh.github.com > secrets/github_known_hosts
# 最好用 GitHub 公布的 SSH 主机密钥指纹人工核对后再固定
```

`merge_known_hosts` 必须和 `merge_deploy_key` 一样以 `0600` 安装到
`/etc/change-guard/`，属主 `change-guard`。私钥不要放进仓库，也不要打印。

### 3.4 Bootstrap kubeconfig（只在控制器）

- 用于应用 RBAC 和 `kubectl create token`，需要能创建 ServiceAccount token。
- 默认路径：控制器上的 `~/.kube/config`（实验中 master 上的 `myt` 用户拥有
  cluster-admin）。
- **不要**把它复制到 `/etc/change-guard/` 给服务使用；服务只拿短期 TokenRequest
  kubeconfig。
- 如果控制器就是 master，本机已经存在管理员 kubeconfig；角色不会把它复制给服务
  身份，但主机管理员凭据本身属于主机信任边界。

### 3.5 凭据文件检查

部署前确认：

```sh
stat -c '%a %U:%G %n' \
  secrets/github-token secrets/deepseek-token \
  secrets/merge-deploy-key secrets/github_known_hosts
```

预期全部是 `600`。不要用 `cat`、`echo`、`set -x` 或 `ansible -vvv` 打印内容。
`no_log: true` 只保护 Ansible 输出，不保护你自己在 shell 里的命令。

### 3.6 PAT 能力验证（不打印 token）

```sh
export GITHUB_TOKEN="$(cat secrets/github-token)"
export REPO='hey-mmm/Full-Stack-Observability-in-Kubernetes'

# 1) 当前用户
curl -sS -H "Authorization: Bearer $GITHUB_TOKEN" \
  https://api.github.com/user | jq '{login,type}'

# 2) 仓库读取
curl -sS -H "Authorization: Bearer $GITHUB_TOKEN" \
  "https://api.github.com/repos/$REPO" | jq '{full_name,private,permissions}'

# 3) PR 读取
curl -sS -H "Authorization: Bearer $GITHUB_TOKEN" \
  "https://api.github.com/repos/$REPO/pulls?state=open&per_page=1" >/dev/null
```

状态写探测必须使用**一次性/可丢弃的提交 SHA**，不要拿 `main` 的 HEAD 做实验：

```sh
export PROBE_SHA='<40-hex disposable commit>'
curl -sS -o /tmp/cg-status-probe.json -w '%{http_code}\n' \
  -X POST \
  -H "Authorization: Bearer $GITHUB_TOKEN" \
  -H 'Accept: application/vnd.github+json' \
  "https://api.github.com/repos/$REPO/statuses/$PROBE_SHA" \
  -d '{"state":"pending","context":"change-guard/credential-probe","description":"capability probe"}'
```

预期 `201`。`403` 通常表示 Commit statuses 没有 Read and write；不要用放宽
Administration/Checks 权限来“修复”。探测会产生一个非必需 context 的 pending
状态，不要把它当成 `change-guard/release`。

## 4. 本地开发与回归

在开发机/控制器仓库根目录：

```sh
python -m venv .venv
. .venv/bin/activate          # Windows: .venv\Scripts\activate
python -m pip install -e .
python -m unittest discover -s tests -v
python scripts/scenario-matrix.py --output /tmp/scenario-matrix.json
python -m change_guard verify-knowledge --knowledge-dir knowledge
```

当前版本的测试数量、CI 结果和 skip 项以 `docs/acceptance.md` 与实际运行输出为准，本文
不复制会过期的数字。Windows 下部分 symlink 测试会跳过，生产 bwrap 渲染仍需 Linux。

如果要在本地看 CLI：

```sh
python -m change_guard --help
python -m change_guard.daemon --help
python -m change_guard.postdeploy --help
```

## 5. 构建可信发布包

### 5.1 选择新版本

发布目录是不可变的，同一个版本不能换内容。把 `pyproject.toml` 的
`project.version` 和 `change_guard/__init__.py` 的 `__version__` **同时**改成同一个
`<新版本>`（当前服务版本见 `docs/acceptance.md`；发布前让 `pyproject.toml` 与
`__version__` 同时等于新版本，不要只改其中一个）：

```sh
# 示例：先编辑两处，使它们都等于 <新版本>
export VERSION='<新版本>'

python - <<'PY'
import re
from pathlib import Path
text = Path('pyproject.toml').read_text(encoding='utf-8')
match = re.search(r'^version\s*=\s*"([^"]+)"', text, re.MULTILINE)
assert match, 'pyproject version not found'
version = match.group(1)
init = Path('change_guard/__init__.py').read_text(encoding='utf-8')
assert f'__version__ = "{version}"' in init, 'pyproject/__version__ mismatch'
print('metadata version =', version)
PY

scripts/build-release.sh --version "$VERSION"
```

`build-release.sh --version` 只决定 tarball 文件名/JSON 的 `version` 字段，**不会**
修改 `pyproject.toml` 或包内 `__version__`；元数据必须由上面两处源文件提供。只传
`--version` 会造成“文件名是新版本、包内还是旧版本”的假发布。

脚本输出 JSON，包含 `artifact`、`sha256`、`bytes`、`files`。保存 SHA-256 到
部署变量，不要凭记忆手抄。

### 5.2 校验产物

```sh
sha256sum "dist/k8s-change-guard-${VERSION}.tar.gz"
tar -tzf "dist/k8s-change-guard-${VERSION}.tar.gz" | sort | head -50
```

tarball 只应包含：

- `change_guard/`（Python 包）
- `knowledge/`（受信案例和来源快照）
- `pyproject.toml`、`requirements.txt`、`config.example.yaml`

脚本使用固定的 gzip mtime、uid/gid `0`、文件模式 `0644` 和排序后的文件列表，
并拒绝 symlink；同一个输入应得到同一 tarball（仍需每次记录实际 SHA-256）。
不应包含 `tests/`、`ansible/`、`scripts/`、`.git/`、`dist/`、凭据或 `__pycache__`。
`dist/` 已在 `.gitignore` 中，不要把产物提交进仓库。

把 tarball 和 SHA-256 传到控制器；Ansible 的 `change_guard_artifact` 指向控制器
上的实际路径。

## 6. 配置 Ansible

### 6.1 Inventory

复制并修改 `ansible/inventory.example.ini`：

```ini
[change_guard]
master ansible_host=11.0.1.10 ansible_user=myt

[change_guard:vars]
ansible_python_interpreter=/usr/bin/python3
```

如果 `myt` 需要 sudo 密码，执行 playbook 时用 `--ask-become-pass`，不要把密码写进
inventory 或 group_vars。

### 6.2 group_vars

```sh
cp ansible/group_vars/all.yml.example ansible/group_vars/all.yml
```

至少设置：

```yaml
change_guard_version: "<新版本>"
change_guard_artifact: "{{ playbook_dir }}/../dist/k8s-change-guard-<新版本>.tar.gz"
change_guard_artifact_checksum: "<build-release 输出的 64 位 SHA-256>"

change_guard_repository: "hey-mmm/Full-Stack-Observability-in-Kubernetes"
change_guard_base_branch: "main"
change_guard_status_context: "change-guard/release"
change_guard_approvers:
  - "hey-mmm"

change_guard_github_token_src: "{{ playbook_dir }}/../secrets/github-token"
change_guard_deepseek_token_src: "{{ playbook_dir }}/../secrets/deepseek-token"
change_guard_merge_deploy_key_src: "{{ playbook_dir }}/../secrets/merge-deploy-key"
change_guard_merge_known_hosts_src: "{{ playbook_dir }}/../secrets/github_known_hosts"

change_guard_bootstrap_kubeconfig: "{{ lookup('env', 'HOME') }}/.kube/config"
change_guard_token_ttl: "12h"
change_guard_token_refresh_before_seconds: 7200
change_guard_force_token_rotation: false

# 必须是单个字符串，严格匹配项目一 CI 的聚合 job 名。
change_guard_merge_required_ci: "Test, lint, render"

# 操作员可信 pin；当前真实 Git blob digest，不是旧的 0b2b... 参考值。
# 更新 charts/demo 模板时必须另行审查并更新此值；guard 不自动信任新模板。
change_guard_approved_chart_digest: "194baf90afd746299e256dc0bf144a12bc6f6325bacf77b40ff01e50b0c3e05d"

change_guard_http_proxy: "http://11.0.1.1:7890"
change_guard_https_proxy: "http://11.0.1.1:7890"
change_guard_no_proxy: "127.0.0.1,localhost,::1,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,.svc,.cluster.local,11.0.1.10,11.0.1.11,10.98.137.77,10.104.233.119"
```

如果主机缺少 Helm/kubectl，再填 `change_guard_helm_checksum` /
`change_guard_kubectl_checksum`；已有可执行预装二进制时角色不会替换它们，也不要求
这两个 checksum。

### 6.3 语法检查

```sh
ansible-playbook -i ansible/inventory.example.ini ansible/site.yml --syntax-check
```

## 7. 部署 guard

```sh
ansible-playbook -i ansible/inventory.example.ini ansible/site.yml
```

如果 sudo 需要密码：

```sh
ansible-playbook -i ansible/inventory.example.ini ansible/site.yml --ask-become-pass
```

角色按以下顺序执行：

1. preflight：Debian/Ubuntu、字面版本、artifact SHA-256、凭据源存在、controller
   kubectl、unprivileged userns。
2. packages：安装 bwrap/Python 依赖；预装 Helm/kubectl 可用则复用，否则按固定
   checksum 下载。
3. user：创建 `change-guard` 系统用户、`nologin`、私有 state 目录、配置目录、
   release 根目录。
4. release：校验 tarball（控制器侧和主机侧都算 SHA-256），解压到
   `/opt/change-guard/releases/<version>`，建 venv 和 `.pth`，写
   `.artifact.sha256`、`.complete`，切换 `/opt/change-guard/current` 符号链接。
5. rbac：创建 `change-guard` namespace/ServiceAccount 和只读 RBAC。
6. token：复用未过期 TokenRequest kubeconfig，或从控制器 bootstrap 生成新的
   `12h` token，原子写入 `0600` kubeconfig。
7. configure：安装 `config.yaml`、GitHub/DeepSeek token、proxy.env、可选 merge
   deploy key/known_hosts。
8. service：安装 hardened unit，enable/start。
9. renewal：安装 root-only TokenRequest 续期 helper 和 6 小时 timer。
10. verify：服务 active、用户 `nologin`、凭据 `0600`、token 未过期、RBAC 允许
    读取、禁止 Secret/log/exec/写。

历史版本（如 0.2.1）的部署证明只能作为当时证据，已归档在上级 `work/` 和
`docs/evidence/`；当前版本的部署/幂等 recap、真实合并、回退和发布后结果以
`docs/acceptance.md` 为准，不要拿旧版本的 `changed` 数字当现状。你仍应以自己环境的
输出为准；如果第二次仍 changed，先查 handler、TokenRequest 轮换和文件 checksum，
不要直接忽略。

### 7.1 部署后人工检查

```sh
systemctl status change-guard.service --no-pager
systemctl is-enabled change-guard.service
journalctl -u change-guard.service -n 80 --no-pager

systemctl list-timers change-guard-token-renew.timer --no-pager
systemctl status change-guard-token-renew.timer --no-pager

stat -c '%a %U:%G %n' \
  /etc/change-guard/config.yaml \
  /etc/change-guard/github-token \
  /etc/change-guard/deepseek-token \
  /etc/change-guard/kubeconfig \
  /etc/change-guard/proxy.env \
  /etc/change-guard/merge-deploy-key \
  /etc/change-guard/github_known_hosts
```

预期：`config.yaml` 是 `640 root:change-guard`；其余凭据是
`600 change-guard:change-guard`。如果 merge 密钥没有安装，对应文件可以不存在，
但 `merge.py` 会拒绝合并。

```sh
python /usr/local/lib/change-guard/check-token-expiry.py \
  /etc/change-guard/kubeconfig --min-remaining 3600

sh scripts/verify-rbac.sh /etc/change-guard/kubeconfig
```

`verify-rbac.sh` 退出 0 表示允许节点、全 namespace Pod、Argo Application 读取，
且拒绝 Secret、Pod 日志、exec、Deployment 写和 Argo patch。

### 7.2 幂等

```sh
ansible-playbook -i ansible/inventory.example.ini ansible/site.yml
```

第二次预期 `changed=0`。注意：

- 如果 token 进入续期窗口，`token.yml` 会主动轮换，第二次可能仍有变化；
- 如果 merge 密钥/凭据源变化，configure 会重启服务；
- 同一 `change_guard_version` 但 tarball SHA-256 不同会被拒绝，这是有意的。

## 8. systemd、RBAC 与 6 小时 TokenRequest 续期

### 8.1 systemd 真实设置

`ansible/roles/change_guard/templates/change-guard.service.j2` 的关键点：

- `User=change-guard`、`Group=change-guard`、`nologin`；
- `ProtectSystem=strict`、`ProtectHome=yes`、`PrivateTmp=yes`、
  `NoNewPrivileges=yes`、`CapabilityBoundingSet=`（空）；
- `/etc/change-guard` 和 `/opt/change-guard` 只读；
- `/var/lib/change-guard` 可写；
- **`RestrictNamespaces=false`**：bubblewrap 必须能创建 user/mount/net/pid 等
  namespace；把这几个 namespace 禁掉会让 bwrap 在 Helm 之前失败。不要为了
  “hardening 分数”把它改成 `~user` 等；
- systemd 不设置 `RLIMIT_AS`；`MemoryHigh=1536M`、`MemoryMax=2G` 限制的是 cgroup
  常驻内存，不限制 Go 未使用的虚拟地址空间；
- `LimitNPROC=8192`、`TasksMax=8192`，避免 Go helper 起线程时被系统级 NPROC
  误杀；
- `SystemCallFilter=@system-service mount umount2 pivot_root unshare setns clone
  clone3 chroot setuid setgid`：bwrap 需要这些；这是实际隔离与可用性的折中。

渲染器本身还会在 bwrap 子进程上设置 `RLIMIT_AS`、`RLIMIT_FSIZE`、
`RLIMIT_CPU`、`RLIMIT_NOFILE`、`RLIMIT_NPROC`。`sandbox_tmpfs_bytes` 当前只是
配置项，bwrap 0.6.1 没有 `--size` 参数，实际边界主要靠输出大小、`RLIMIT_FSIZE`
和 systemd cgroup；不要把“配置了 tmpfs 大小”当成已经精确限额。

### 8.2 RBAC 允许/拒绝

允许：

- `get/list/watch nodes`（容量）；
- `get/list/watch pods`（全 namespace，容量统计）；
- `demo` namespace 的 pods/services/endpoints/deployments/replicasets 读；
- `argocd` namespace 的 applications/appprojects/applicationsets 读。

拒绝：

- Secret 读取；
- `pods/log`、`pods/exec`；
- Deployment/Service 等写、patch、delete；
- Argo Application 写/patch；
- 任何集群写操作。

服务 kubeconfig 是短期 TokenRequest token；service 不持有管理员 kubeconfig，也
不会自己 mint token。

### 8.3 续期机制（12h TTL / 6h timer）

真实实现：

- `change_guard_token_ttl` 默认 `12h`，`change_guard_token_refresh_before_seconds`
  默认 `7200`（2 小时，用于 Ansible 普通运行时判断）。
- `change-guard-token-renew.timer` 每 6 小时触发
  `change-guard-token-renew.service`。
- service 以 `root` 运行 `/usr/local/lib/change-guard/renew-service-token.py`
  （`0700 root`）。helper 只执行固定命令：

  ```text
  /usr/bin/kubectl --kubeconfig=/etc/kubernetes/admin.conf \
    --request-timeout=20s -n change-guard create token change-guard --duration=12h
  ```

- 新 token 通过临时文件 + `os.replace` 原子替换
  `/etc/change-guard/kubeconfig`，保持 `0600`，保留 server/CA，不打印 token。
- service 每次调用 kubectl 都重新读 kubeconfig，因此续期不需要重启 daemon。
- service 用户不能执行 helper、不能读 `/etc/kubernetes/admin.conf`、不能改
  timer/unit，也不能自己创建 token。

**重要边界**：

- 这不是“延长同一个 token”，而是每 6 小时生成一张新的 12 小时 TokenRequest
  凭证；Kubernetes 没有给这个 token 做 lease 续租。
- helper 依赖**guard 主机本机**的 `/etc/kubernetes/admin.conf`。实验里 guard 在
  master 上，所以存在；如果部署到独立主机，这个 timer 会失败，必须改用控制器侧
  的 `ansible/rotate-token.yml` 或 `scripts/rotate-kube-token.sh` 定期下发。
- 6h 触发、12h 有效期留有 6h 余量；如果 timer 连续失败超过余量，token 过期，
  daemon 的 Kubernetes 采集会 ERROR，不能继续合并。

手动验证/轮换：

```sh
systemctl start change-guard-token-renew.service
systemctl status change-guard-token-renew.service --no-pager
journalctl -u change-guard-token-renew.service -n 50 --no-pager

python /usr/local/lib/change-guard/check-token-expiry.py \
  /etc/change-guard/kubeconfig --min-remaining 3600

# 控制器上强制 Ansible 轮换（会重跑 role，使用 bootstrap 重新 mint）
ansible-playbook -i ansible/inventory.example.ini ansible/rotate-token.yml

# 非 Ansible 环境：在控制器生成目标 kubeconfig，再按受控方式放到主机
BOOTSTRAP_KUBECONFIG="$HOME/.kube/config" \
TARGET_KUBECONFIG=/tmp/change-guard-kubeconfig \
TOKEN_TTL=12h sh scripts/rotate-kube-token.sh
```

不要用 `kubectl create token` 的输出去打日志；不要把 admin kubeconfig 拷到
`/etc/change-guard/`。

### 8.4 关于“租约”的两个不同概念

- **合并 lease**：`merge.py` 用 `git push --force-with-lease=refs/heads/main:<旧 main SHA>`
  做 compare-and-swap。它不是 Kubernetes Lease 对象，也不会自动续期。
- **token 轮换**：6 小时 timer 生成新 token，不是 lease 续租；旧 token 到期后
  自然失效。

文档和演示中不要把两者混为一谈。

## 9. GitHub 双 ruleset

### 9.1 目标

项目一 `main` 需要两组独立规则：

1. **更新入口限制**：普通用户只能通过 PR；实际写 `main` 只允许专用部署密钥
   （受信合并命令使用）。禁止删除、非快进。
2. **必需检查**：`change-guard/release` 和项目一 CI 的聚合检查
   `Test, lint, render` 都必须成功；**没有 bypass actor**。

只有两组都生效，才能做到“旧绿色状态不能直接合并”：更新入口挡住普通 push，
必需检查挡住没有当前 guard 状态的提交。

### 9.2 Ruleset 1：更新入口

```json
{
  "name": "change-guard-main-updates",
  "target": "branch",
  "enforcement": "active",
  "conditions": {
    "ref_name": {
      "include": ["refs/heads/main"],
      "exclude": []
    }
  },
  "bypass_actors": [
    {
      "actor_type": "DeployKey",
      "actor_id": null,
      "bypass_mode": "always"
    }
  ],
  "rules": [
    {"type": "update"},
    {"type": "deletion"},
    {"type": "non_fast_forward"},
    {
      "type": "pull_request",
      "parameters": {
        "dismiss_stale_reviews_on_push": true,
        "require_code_owner_review": false,
        "require_last_push_approval": false,
        "required_approving_review_count": 0,
        "required_review_thread_resolution": true,
        "allowed_merge_methods": ["merge"]
      }
    }
  ]
}
```

说明：

- `required_approving_review_count: 0` 是有意的：Guard 的 REVIEW 审批是精确
  `/guard approve <evaluation_id>` 评论，不是 GitHub review；GitHub review 不能
  代替它。普通账号仍不能直接 push。
- `DeployKey` bypass 是**仓库级**的：GitHub API/GraphQL 不能把 bypass 收窄到某
  一把 key。仓库里只能保留这一把写部署密钥；任何新增的写部署密钥都能绕过本
  ruleset。管理员必须定期审计 Deploy keys。
- 不要给普通用户、团队或管理员加 bypass；`current_user_can_bypass` 应为
  `never`。
- `allowed_merge_methods: merge` 仍保留为 GitHub UI 的兜底形态；实际受信命令不使用
  GitHub Merge API，而是用部署密钥 fast-forward 推送已评估 head，因此不会创建
  GitHub 的两父 merge commit。

### 9.3 Ruleset 2：必需检查

```json
{
  "name": "change-guard-main-required-checks",
  "target": "branch",
  "enforcement": "active",
  "conditions": {
    "ref_name": {
      "include": ["refs/heads/main"],
      "exclude": []
    }
  },
  "bypass_actors": [],
  "rules": [
    {
      "type": "required_status_checks",
      "parameters": {
        "strict_required_status_checks_policy": true,
        "do_not_enforce_on_create": false,
        "required_status_checks": [
          {"context": "change-guard/release"},
          {"context": "Test, lint, render", "integration_id": 15368}
        ]
      }
    }
  ]
}
```

`integration_id: 15368` 是 GitHub Actions 的 app id；项目一 CI 的聚合 job 名必须
严格是 `Test, lint, render`。`bypass_actors: []` 表示没有管理员/部署密钥可以
绕过必需检查。GitHub Actions 的 `pull_request` check 绑定 PR **head**；`merge.py`
读取 head 的 check-runs，不能查 synthetic merge（真实环境中通常为空），也不能用
普通 commit status 冒充。

### 9.4 应用和读回

把 9.2 / 9.3 的 JSON 分别保存为
`/tmp/change-guard-main-updates.json` 和
`/tmp/change-guard-main-required-checks.json`，再用有 ruleset 管理权限的账号
（不要把管理 token 装到 guard 服务）应用：

```sh
gh api --method POST \
  -H 'Accept: application/vnd.github+json' \
  repos/hey-mmm/Full-Stack-Observability-in-Kubernetes/rulesets \
  --input /tmp/change-guard-main-updates.json

gh api --method POST \
  -H 'Accept: application/vnd.github+json' \
  repos/hey-mmm/Full-Stack-Observability-in-Kubernetes/rulesets \
  --input /tmp/change-guard-main-required-checks.json
```

如果同名 ruleset 已存在，用 `PUT .../rulesets/<id>` 更新，不要创建重复规则。
读回：

```sh
gh api repos/hey-mmm/Full-Stack-Observability-in-Kubernetes/rulesets |
  jq '.[] | {id,name,enforcement,target}'

gh api repos/hey-mmm/Full-Stack-Observability-in-Kubernetes/rulesets/<id> |
  jq '{name,bypass_actors,rules,current_user_can_bypass}'
```

必须核对：

- 两个 ruleset 都是 `active`；
- ruleset 1 只有 `DeployKey` bypass，`current_user_can_bypass=never`；
- ruleset 2 的 `bypass_actors` 为空；
- required contexts 精确是 `change-guard/release` 和 `Test, lint, render`；
- 普通账号对 `main` 的直接 push 被拒绝，创建 PR 仍可用。

部署密钥审计（必须只有一把写 key）：

```sh
gh api repos/hey-mmm/Full-Stack-Observability-in-Kubernetes/keys |
  jq '.[] | {id,title,read_only,created_at}'
```

GitHub 的 DeployKey bypass 不能按 key ID 收窄；任何未知的 `read_only=false` key
都按事故处理。

### 9.5 旧状态为什么仍然不能被直接使用

GitHub 的 success 状态没有本项目需要的分钟级 TTL。即使 `change-guard/release`
在某个 head 上是 success，时间过去后 GitHub 不会自动把它改成 failure。因此：

- guard daemon 在报告过期后会主动把旧状态改成 pending/error；
- 但 daemon 停机时做不到；
- 所以 `merge.py` 在推送前重新读取报告、策略绑定、审批、当前 head/base、head CI、
  synthetic 父提交/tree 和 workflow/chart pin，并用旧 `main` SHA 的 lease 做
  compare-and-swap。

不能把“ruleset 配好了”当成“状态会自动过期”。

## 10. 启动与首次状态

角色已经 `enable/start` 服务。确认：

```sh
systemctl is-active change-guard.service
journalctl -u change-guard.service -n 50 --no-pager
```

daemon 默认每 `30s` 轮询一次。首次运行会验证 GitHub 凭据、列出 open PR、对每个 PR
先发 `pending`，再渲染/采集/评估/发布状态。

手工单次运行只用于排障；不要和 systemd 服务同时长时间运行：

```sh
sudo -u change-guard \
  /opt/change-guard/current/venv/bin/python -m change_guard.daemon \
  --config /etc/change-guard/config.yaml --once
```

查看某个 PR 的状态：

```sh
gh api repos/hey-mmm/Full-Stack-Observability-in-Kubernetes/commits/<head-sha>/statuses |
  jq '.[] | select(.context=="change-guard/release") | {state,description,created_at}'
```

报告落在 `/var/lib/change-guard/reports/ev-*.json`，审批记录在
`/var/lib/change-guard/approvals/`，合并记录在 `/var/lib/change-guard/merges/`。
报告里不应有 token/Secret；如果发现凭据，按事故处理。

## 11. 精确审批与 merge 命令

### 11.1 什么时候需要审批

只有 `REVIEW` 需要人工审批。`PASS` 可以直接进入受信合并路径；`BLOCK` 和
`ERROR` 不能被审批覆盖。

审批评论必须**整条**是：

```text
/guard approve ev-xxxxxxxxxxxxxxxxxxxxxxxx
```

- 必须是配置里的 `approvers` 之一；
- 评论作者必须有当前写/管理权限；个人仓库用 `owner.type=User` +
  `owner.login` 精确匹配，非 owner/组织路径需要协作者权限端点，拿不到就拒绝；
- 评论时间必须不早于报告 `evaluated_at`，且早于 `expires_at`；
- 当前 head/base 必须仍然等于报告绑定值；
- 标签、旧评论、“LGTM”、额外文字都不算；
- 审批评论被编辑后按 `updated_at` 重新判断；过期后编辑无效。

拿到 evaluation ID 的方式：看 `change-guard/release` 的 pending 描述，或打开
`report_comment: true` 时的报告评论。默认不写评论，避免 Issues write 权限。

### 11.2 合并前检查

```sh
export REPO='hey-mmm/Full-Stack-Observability-in-Kubernetes'
export PR='<PR 编号>'

# 当前 head/base 和状态
gh pr view "$PR" --repo "$REPO" \
  --json number,state,isDraft,headRefOid,baseRefName

# 必需 CI 绑定 head，不是 synthetic merge
gh api "repos/$REPO/commits/<head-sha>/check-runs?per_page=100" |
  jq '.check_runs[] | select(.name=="Test, lint, render") |
      {name,status,conclusion,head_sha,app:.app.slug}'

gh api "repos/$REPO/commits/<head-sha>/statuses" |
  jq '.[] | select(.context=="change-guard/release") | {state,description}'
```

同时确认：

- PR 是 open、非 draft、base 是 `main`；
- 报告 schema 2、未过期、policy binding 与当前 guard/rule/policy 一致；
- decision 是 PASS 或已审批的 REVIEW；
- 报告 `chart_digest` 等于当前 head `charts/demo` 的真实 Git blob digest，且在
  `approved_chart_digest` 白名单内；
- base/head 的 `.github/workflows/` tree 完全一致（`workflow_changed=false`）；
- `merge_required_ci` 是单个字符串 `Test, lint, render`；
- head 上的 `Test, lint, render` 是 GitHub Actions 的 completed/success；
- base 是 head 祖先（PR 已包含当前 main，`compare.merge_base_commit.sha == base`）；
- synthetic merge 的 parents 是 `[base, head]`，且 synthetic tree == head tree；
- 受信主机有 merge deploy key、known_hosts、`git`、`ssh`、`nc`；
- 代理环境变量可用。

检查配置（在 guard 主机上）：

```sh
sudo -u change-guard /opt/change-guard/current/venv/bin/python - <<'PY'
import yaml
c = yaml.safe_load(open('/etc/change-guard/config.yaml', encoding='utf-8'))
ci = c.get('merge_required_ci', 'Test, lint, render')
assert isinstance(ci, str), f"merge_required_ci must be a string, got {type(ci)}"
pin = c.get('approved_chart_digest')
assert pin, "approved_chart_digest is required"
print('merge_required_ci =', ci)
print('approved_chart_digest =', pin)
print('merge_fetch_depth =', c.get('merge_fetch_depth', 128))
PY
```

`approved_chart_digest` 缺失/不匹配、workflow 变更、policy binding 不一致时，
merge 会 fail closed；不要用管理员 push 或 GitHub UI Merge 绕过。

### 11.3 执行受信合并（fast-forward head）

推荐使用 root 运行的包装脚本（本机受信部署目录中的 `scripts/merge-release.sh`）：

```sh
sudo scripts/merge-release.sh "$PR"
```

它会：

1. 校验以 root 运行、参数是单个 PR 编号；
2. 暂停 `change-guard.service`，避免 daemon 的非阻塞 state lock 与 merge 争抢；
3. `trap ... EXIT` 在成功/失败后恢复原来的 polling 状态；
4. 用 `runuser -u change-guard` 降权后读取 `/etc/change-guard/proxy.env`，再执行
   `python -m change_guard.merge --config /etc/change-guard/config.yaml --pr <PR>`。

底层 Python 仍可直接运行，但**必须先停 daemon 或串行化**；否则 daemon 的非阻塞
lock 可能让 merge 以 `DaemonBusy` 失败：

```sh
sudo systemctl stop change-guard.service
sudo -u change-guard \
  env HTTP_PROXY=http://11.0.1.1:7890 \
      HTTPS_PROXY=http://11.0.1.1:7890 \
      NO_PROXY='127.0.0.1,localhost,::1,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,.svc,.cluster.local' \
  /opt/change-guard/current/venv/bin/python -m change_guard.merge \
  --config /etc/change-guard/config.yaml \
  --pr "$PR"
sudo systemctl start change-guard.service
```

`merge-release.sh` 只是操作入口；它不改变 merge 的审批/CI/tree/pin/lease 校验。

它实际做什么：

1. `guard.run_once()`：复用仍在有效期内的报告，保留已绑定审批；
2. 读取当前 index/report、PR、`main` HEAD；
3. `validate_report`：head/base、open、非 draft、decision、时间、`report_digest`，
   以及 `schema_version=2` / `policy_binding` / `guard_version` / `rule_version` /
   `policy_digest`；
4. REVIEW 时重新解析当前审批评论和当前权限；
5. 若报告记录 workflow 变更或 `workflow_changed=true`，直接拒绝；否则独立通过
   GitHub Git Trees API 重新读取 base/head，比较 `.github/workflows/` 的
   path/mode/kind/blob SHA；
6. 从 head tree 的 `charts/demo` Git blob 字节独立重算 chart digest，要求等于报告
   `chart_digest` 且在操作员白名单；
7. `compare` 确认 `merge_base_commit.sha == base`，即 base 已是 head 祖先；
8. 读取 PR 的 synthetic merge commit，确认 parents 精确 `[base, head]`，且
   synthetic tree == head commit tree；不满足则“fast-forward unsafe”；
9. 只读查询 **head SHA** 的 `Test, lint, render` check-runs，要求
   GitHub Actions、completed/success、`head_sha` 精确等于 head，且响应完整；
10. 在临时 bare repo 中 fetch head/base，核验本地 head tree 等于 GitHub head tree、
    base commit 存在、base 是 head 祖先；
11. 再次读取 fresh PR/current main，重新验证 report/审批/TTL；把
    `change-guard/release=success` 写到 **head**；
12. 用 `--force-with-lease=refs/heads/main:<旧 main SHA>` 快进推送
    `<head>:refs/heads/main`，不是 synthetic merge commit；
13. 写 `/var/lib/change-guard/merges/<head>.json`，记录 `strategy=fast-forward`、
    `merge_sha=head`、`synthetic_merge_sha`、tree、`github_merge_api_used=false` 和
    `rollback.command = git revert <head>`。

它不会 checkout、执行 PR 代码，不会调用 GitHub Merge API，也不会使用 token URL。
fast-forward 推送后 GitHub 是否自动把 PR 标记为 merged 不由 guard 保证；若未自动
标记，由 root 人工核对，不要为此增加 PR write PAT 或 merge API 权限。

合并后 PR 会变成 closed/merged，daemon 随后会撤销该 PR/旧 head 上的历史
`change-guard/release` 状态，因此 main 或旧 head 上出现 guard **error/pending** 可能
只是“评估已撤销”，不是 postdeploy 失败。门禁有效性以 merge 记录（例如
`docs/evidence/merge-pr-2.json`）和当时的报告/审批/CI 为准；不要为了保持好看而强行
维持永久绿。

输出示例：

```json
{
  "result": "MERGED",
  "strategy": "fast-forward",
  "pr": 2,
  "head_sha": "...",
  "base_sha": "...",
  "merge_sha": "...",
  "synthetic_merge_sha": "...",
  "github_merge_api_used": false,
  "rollback": {"command": "git revert <head>", "mainline": null}
}
```

失败输出 `{"result":"REFUSED","error":"..."}`，退出码 1。常见原因：

- `required GitHub Actions CI check is missing for the evaluated head`：head 上没有
  成功 check，或查了 synthetic；检查名/配置不对；
- `report policy binding does not match`：guard/rule/config 变了，重新评估；
- `candidate charts/demo digest is not operator-approved`：模板/pin 未更新；
- `.github/workflows tree differs between base and head`：workflow 变更硬阻断；
- `synthetic merge tree does not equal the evaluated head tree`：不能安全快进；
- `Git base is not an ancestor` / `update PR with current main`：main 在评估后移动；
- `report expired or insufficient validity remains`：重新评估；
- `current REVIEW approval missing`：审批评论不精确/作者不对/已过期；
- `trusted git operation failed`：deploy key、known_hosts、`nc`、代理或 443 端口
  问题；
- `missing trusted merge configuration`：merge key/known_hosts 未安装。

**不要**在失败后改用管理员 token 直接 push，或用 GitHub UI 的 Merge 按钮绕过；
那会破坏“更新入口只允许部署密钥”的模型。先修复原因。

## 12. 发布后验证

```sh
sudo -u change-guard \
  /opt/change-guard/current/venv/bin/python -m change_guard.postdeploy verify \
  --config /etc/change-guard/config.yaml \
  --expected-sha <main_head_commit> \
  --expected-app-sha <image_source_commit> \
  --report /var/lib/change-guard/reports/<evaluation_id>.json \
  --output /tmp/postdeploy.json
```

- `--expected-sha`：Argo CD 应同步的 **GitOps revision**；merge 后 `main` 的 head
  （即 merge record 的 `merge_sha`）。
- `--expected-app-sha`：`/version` 暴露的**镜像源提交**，通常是构建 GHCR 镜像的
  应用代码 commit，和 GitOps revision 通常不同。
- 两者必须同时传；不能用 `--expected-sha` 替代 `/version` 校验，也不能用
  `--expected-app-sha` 替代 Argo revision。

也可显式给镜像：

```sh
--expected-image ghcr.io/hey-mmm/observability-demo@sha256:<digest>
```

验证器是只读的，检查：

- Argo CD Application revision、`Synced`、`Healthy`；
- Deployment 副本/可用副本、目标容器镜像 digest；
- 运行中 Pod ready、`imageID` digest；多架构时 `imageID` 与 manifest digest
  可能不同，报告会保留 caveat，不能简单断言相等；containerd 的
  `status.containerStatuses[].image` 可能是 config ID，不是 manifest 引用，应使用
  Pod spec 的容器 image 和 `imageID` 判断；
- `GET /version` 的 `gitSha` 等于 `--expected-app-sha`（镜像元数据本身不等于
  provenance）；
- `GET /readyz` 和 Service ready endpoints；
- 正流量窗口中的错误率/延迟和 Prometheus 数据新鲜度。

失败时返回 `open_revert_pr` 建议，不会修改集群、不会自动回滚。

手工核对：

```sh
kubectl -n argocd get application demo -o json | jq '{revision:.status.sync.revision,sync:.status.sync.status,health:.status.health.status}'
kubectl -n demo get deployment demo -o wide
kubectl -n demo get pods -o wide
```

## 13. 回退 PR

发布后失败时，正确做法是 **Git revert PR**，不是直接改集群，也不是让模型执行回滚。
fast-forward 后 main 上是普通单父 head 提交，回退**不加** `-m 1`：

```sh
export REPO='hey-mmm/Full-Stack-Observability-in-Kubernetes'
export BAD_HEAD='<出问题的 main head sha>'
git fetch origin main
git switch -c "revert/${BAD_HEAD:0:12}" origin/main
git revert --no-edit "$BAD_HEAD"
git push origin "HEAD:revert/${BAD_HEAD:0:12}"

gh pr create --repo "$REPO" \
  --base main \
  --head "revert/${BAD_HEAD:0:12}" \
  --title "Revert ${BAD_HEAD:0:12}" \
  --body "Revert the release that failed post-deploy verification."
```

然后按正常流程等待 guard 评估、REVIEW 审批（如需要）和受信 merge。若 guard 本身
不可用，只有仓库管理员能修改 ruleset/部署密钥做 break-glass；这是事故操作，必须
记录、尽快恢复双 ruleset，不能变成日常绕过。

## 14. 复现检查清单与验收边界

### 14.1 可复现命令

```sh
# 0) 同步 metadata（两处都要改），再构建；--version 只影响文件名
# pyproject.toml: version = "<新版本>"
# change_guard/__init__.py: __version__ = "<新版本>"
python -m unittest discover -s tests -v
python scripts/scenario-matrix.py --output /tmp/scenario-matrix.json

VERSION='<新版本>'
scripts/build-release.sh --version "$VERSION"
sha256sum "dist/k8s-change-guard-${VERSION}.tar.gz"

# 1) 部署/幂等
ansible-playbook -i ansible/inventory.example.ini ansible/site.yml
ansible-playbook -i ansible/inventory.example.ini ansible/site.yml

# 2) 服务/RBAC/chart pin
systemctl status change-guard.service --no-pager
sh scripts/verify-rbac.sh /etc/change-guard/kubeconfig
python /usr/local/lib/change-guard/check-token-expiry.py /etc/change-guard/kubeconfig --min-remaining 3600
sudo -u change-guard /opt/change-guard/current/venv/bin/python - <<'PY'
import yaml
c = yaml.safe_load(open('/etc/change-guard/config.yaml', encoding='utf-8'))
assert isinstance(c['merge_required_ci'], str)
assert c.get('approved_chart_digest')
print(c['approved_chart_digest'])
PY

# 3) 审批/合并/发布后（head CI + fast-forward）
#    /guard approve ev-...
sudo scripts/merge-release.sh <N>
sudo -u change-guard /opt/change-guard/current/venv/bin/python -m change_guard.postdeploy verify \
  --config /etc/change-guard/config.yaml \
  --expected-sha <main_head_commit> \
  --expected-app-sha <image_source_commit> \
  --report /var/lib/change-guard/reports/<evaluation_id>.json
```

### 14.2 验收边界

以下项目不能由本文代填；当前版本的部署、真实合并、回退、发布后验证和最终结论以
`docs/acceptance.md` 为准：

- 部署/幂等、RBAC/续期、chart pin 与 policy binding 的当前版本实测；
- 真实 PR 的 `change-guard/release` 状态 201 与 pending/success 转换；
- 真实 BLOCK PR 被 ruleset 拒绝并关闭；
- 真实 REVIEW 审批 + `merge.py` head CI/synthetic tree/lease fast-forward；
- 发布后 Argo revision、镜像 digest、`/version`、`/readyz` 和正流量指标；
- 回退 PR 的实际运行及回退后的发布后结果；
- 原始证据和最终结论写入 `docs/acceptance.md`。

本文只说明如何做到，不复制时效数据，也不替代验收报告。

## 15. 精确文件路径速查

| 路径 | 作用 | 权限 |
| --- | --- | --- |
| `/etc/change-guard/config.yaml` | 非密配置 | `0640 root:change-guard` |
| `/etc/change-guard/github-token` | PAT | `0600 change-guard` |
| `/etc/change-guard/deepseek-token` | 模型 key | `0600 change-guard` |
| `/etc/change-guard/kubeconfig` | 短期 TokenRequest | `0600 change-guard` |
| `/etc/change-guard/proxy.env` | 代理环境 | `0600 change-guard` |
| `/etc/change-guard/merge-deploy-key` | 合并部署私钥 | `0600 change-guard` |
| `/etc/change-guard/github_known_hosts` | SSH 主机密钥 | `0600 change-guard` |
| `/opt/change-guard/releases/<version>` | 不可变 release | root 所有，目录 `0755` |
| `/opt/change-guard/current` | 指向当前 release 的符号链接 | root 所有 |
| `/var/lib/change-guard` | 状态/报告/审批/合并记录 | `0700 change-guard` |
| `/usr/local/lib/change-guard/check-token-expiry.py` | token 到期检查 | `0755 root` |
| `/usr/local/lib/change-guard/renew-service-token.py` | root-only 续期 | `0700 root` |
| `/etc/systemd/system/change-guard.service` | 主服务 | `0644 root` |
| `/etc/systemd/system/change-guard-token-renew.{service,timer}` | 续期单元 | `0644 root` |
