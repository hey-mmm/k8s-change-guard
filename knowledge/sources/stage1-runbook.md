# 阶段 1 运行与验收说明（已执行）

> 本文件保留操作顺序，并记录实际结果。阶段 1 已在目标 VM 执行并通过：**33/33 PASS**，证据见 [evidence/stage1-cluster.txt](evidence/stage1-cluster.txt)。全量 `site.yml` 最终复跑为 **master 83 / worker 62 个任务，changed=0 both**，完整日志见 [evidence/stage1-idempotency.txt](evidence/stage1-idempotency.txt)。旧 1.28 集群由操作者在 playbook 之外清理；本仓库不自动执行 `kubeadm reset`。
>
> 下面的命令用于复现和复核，不是“待执行”草稿；不要在没有逐项验收的情况下重跑会改变集群的步骤。

## 1. 前置条件

- master `11.0.1.10`，worker `11.0.1.11`，SSH 用户 `myt`。
- 操作者已完成或确认：
  - 旧 1.28 集群已按用户授权清理；
  - master 50 GB、worker 100 GB 磁盘，worker 4 vCPU / 12 GiB 内存；
  - 两台 VM 可互相访问，22 端口可达；
  - `myt` 有 sudo 权限；实施期间的临时免密规则已移除，复跑加 `--ask-become-pass`；
  - 时区和 NTP 可调整。
- inventory 只保存地址和用户名，不保存密码。执行环境必须自行提供 SSH 认证。
- 不在 Windows 上运行 Ansible。

## 2. 安装受支持的 Ansible 控制端

Ubuntu 22.04 的 Python 3.10 不能运行当前支持的 ansible-core 组合。master 已提供固定 uv `0.13.7`，不要覆盖系统 Python：

```bash
cd Full-Stack-Observability-in-Kubernetes

UV_BIN=/opt/observability-bootstrap/bin/uv
"$UV_BIN" --version   # 必须为 uv 0.13.7

"$UV_BIN" python install 3.12.9
"$UV_BIN" venv "$HOME/.venvs/ansible" --python 3.12.9
"$UV_BIN" pip install \
  --python "$HOME/.venvs/ansible/bin/python" \
  -r ansible/requirements.txt \
  kubernetes==33.1.0 jsonpatch==1.33 PyYAML==6.0.3
$HOME/.venvs/ansible/bin/ansible-galaxy collection install \
  -r ansible/requirements.yml -p ansible/collections

$HOME/.venvs/ansible/bin/ansible --version
$HOME/.venvs/ansible/bin/ansible-galaxy collection list
```

Python SDK 固定为 `kubernetes 33.1.0`、`jsonpatch 1.33`、`PyYAML 6.0.3`；不修改系统 Python。

固定版本：

- Python `3.12.9`（uv managed）
- ansible-core `2.21.6`（当前支持线；2.22 对应 Ansible 15 尚在开发）
- `ansible.posix 2.2.2`
- `community.general 14.0.1`
- `kubernetes.core 6.6.0`

collection 安装到 `ansible/collections`（已在 `.gitignore` 排除）；`ansible.cfg` 使用当前支持的 `collections_path = ./collections`。在 `ansible/` 目录执行命令，SSH 认证环境变量见 [creation-steps.md](creation-steps.md)。不要用系统 `pip install ansible` 覆盖 Ubuntu 包。

> 若 uv 安装器版本变化，应在实际 bootstrap 记录中注明。

## 3. 只读前置检查

在两台 VM 上分别执行。脚本不会安装软件、修改 sysctl、加入集群或扫描其他地址。worker 上若没有仓库副本，由操作者只复制 `scripts/preflight.sh` 到 worker 执行；脚本不依赖仓库其他文件。

```bash
chmod +x scripts/preflight.sh scripts/acceptance/cluster.sh

# master
./scripts/preflight.sh \
  --role control-plane \
  --expected-ip 11.0.1.10 \
  --peer 11.0.1.11

# worker
./scripts/preflight.sh \
  --role worker \
  --expected-ip 11.0.1.11 \
  --peer 11.0.1.10
```

必须没有 `[FAIL]`。`[WARN]` 需逐项判断；特别是旧 kubeadm 版本、已存在的 `admin.conf`/`kubelet.conf`、端口占用，不能忽略。

## 4. Ansible 连通性与语法检查

以下命令在 master 的仓库根目录执行：

```bash
cd ansible

# 只读连通性检查
$HOME/.venvs/ansible/bin/ansible all -i inventory/lab.yml -m ansible.builtin.ping

# 不执行任务，只做语法与任务枚举
$HOME/.venvs/ansible/bin/ansible-playbook -i inventory/lab.yml playbooks/site.yml --syntax-check
$HOME/.venvs/ansible/bin/ansible-playbook -i inventory/lab.yml playbooks/site.yml --list-tasks
```

说明：

- `ansible.cfg` 的 inventory 是 `inventory/lab.yml`。
- `playbooks/site.yml` 显式 `vars_files: ../group_vars/all.yml`，因为 `ansible/group_vars` 不在当前 playbook 的默认相邻目录中。
- `host_key_checking` 保持开启；不要用关闭 SSH 主机校验来“解决”连接问题。

## 5. 执行阶段 1

确认旧集群已清理后：

```bash
cd ansible
$HOME/.venvs/ansible/bin/ansible-playbook -i inventory/lab.yml playbooks/site.yml
```

执行顺序被拆成五个 play，避免 Calico 控制器在 worker 加入前等待可调度节点而死锁：

1. `common` + `containerd` + `kubernetes`：两台节点。
2. `control_plane`：仅 master，受保护地 init。
3. `calico`：仅 master，只下载、校验、渲染、apply，不等待 rollout。
4. `worker_join`：仅 worker，只 join 并确认 Node 对象注册，不等待 CNI 依赖的 Ready。
5. `verify`：仅 master，等待节点、kube-proxy、Calico、CoreDNS 收敛。

受保护行为：

- `/etc/kubernetes/admin.conf` 存在时，不再 init；先检查 `/readyz`、节点读取和 server 版本。版本不是 `v1.37.2` 或集群不健康立即 fail。
- 若只有 `kube-apiserver.yaml` 而没有 `admin.conf`，判定为部分初始化并 fail，不覆盖。
- worker 有 `kubelet.conf` 时，校验其 API server 是否为 `https://11.0.1.10:6443`，并确认目标集群中的 Node 对象和 InternalIP 匹配；不满足则 fail，不只凭文件存在就认为已加入。
- join 命令和 kubeadm init 输出使用 `no_log`；init 日志仅 root 可读。

## 6. 验收

在 master 上、使用管理 kubeconfig 执行：

```bash
cd Full-Stack-Observability-in-Kubernetes
KUBECONFIG=/etc/kubernetes/admin.conf ./scripts/acceptance/cluster.sh
```

脚本实际检查：

- API `/readyz`。
- 恰好 2 个节点，`master`/`worker` 均 Ready，InternalIP 分别为 `11.0.1.10`/`11.0.1.11`，容器运行时为 containerd。
- kubeadm `podSubnet` 与 Calico 默认 IPv4 IPPool 均为 `10.244.0.0/16`。
- kube-apiserver、controller-manager、scheduler、etcd Ready。
- kube-proxy、calico-node、calico-kube-controllers、CoreDNS Ready。
- `kubernetes` Service 为 `10.96.0.1`，`kube-dns` 为 `10.96.0.10`。
- master 的 control-plane taint 仍存在，Calico 有 `Exists` toleration。
- 创建临时 master/worker 测试 Pod（固定 `busybox:1.36.1`，无 latest），验证：
  - 两 Pod 获得不同 Pod IP；
  - 集群 DNS 解析 `kubernetes.default.svc.cluster.local`；
  - master→worker 和 worker→master 双向 ICMP 跨节点 Pod 网络。
- 退出时删除临时命名空间；不删除 taint，不执行 reset。

## 7. 幂等复跑

首次验收通过后再执行一次：

```bash
cd ansible
$HOME/.venvs/ansible/bin/ansible-playbook -i inventory/lab.yml playbooks/site.yml
```

预期：

- 不重新 `kubeadm init`；
- 已存在 `kubelet.conf` 的 worker 不生成新 token、不重新 join；
- Calico 上游文件 checksum 保持 `2de8f47595fb9c41b3f47d7b767a1f8e72ecf84057af834738ff12689a234da5`，不反复重下载；渲染文件无变化；
- 第二次运行不破坏节点 Ready、CoreDNS 或 Calico。

若复跑产生 init/join 或大范围重建，应视为 bug，停止并保留日志，不要继续下一阶段。

## 8. 常见失败与处理

| 现象 | 处理 |
| --- | --- |
| `admin.conf` 存在但版本为 1.28 或 `/readyz` 失败 | 停止。操作者在 playbook 外清理旧集群；本仓库不会自动 reset。 |
| 只有 `kube-apiserver.yaml`，无 `admin.conf` | 停止。检查部分初始化状态，不要直接删除证书或再次 init。 |
| worker `kubelet.conf` 存在但 API server/Node/IP 不匹配 | 停止。该 enrollment 不属于目标集群，按操作者流程清理后再 join。 |
| containerd 启动失败或 CRI 插件未加载 | 检查 `/etc/containerd/config.toml`（v3）和 `journalctl -u containerd`；不得回退到旧 2.2.3 配置。 |
| Calico Pod 不 Ready | 检查 `kubectl -n kube-system get pods -o wide`、Calico 日志、Pod CIDR 是否为 `10.244.0.0/16`；不要删除 master taint 来代替排查。 |
| 测试镜像拉取失败 | 记录网络/镜像仓库错误；不要改成 `latest` 或跳过跨节点网络检查来宣告通过。 |

## 9. 实际验收结果

| 项目 | 结果 |
| --- | --- |
| 执行日期 | 2026-11-11 19:15 CST |
| 命令 | `sudo env KUBECONFIG=/etc/kubernetes/admin.conf bash scripts/acceptance/cluster.sh` |
| 集群版本 | Kubernetes v1.37.2、containerd 2.3.6、Calico v3.33.0、CoreDNS |
| 退出码 / 计数 | exit 0，**33 PASS / 0 FAIL** |
| 幂等复跑 | 全量 `site.yml`：master **83**、worker **62** 个任务，changed=0 both；guest `/tmp/site-final-idempotency.log` |
| 已知修复 | 节点 resolv.conf 的 `localdomain` 搜索域导致 CoreDNS 上游 fake-IP 抢先解析；删除后 33/33，详见 `stage1-cluster.txt` |

33/33 覆盖：API `/readyz`、两节点 Ready/containerd/InternalIP、控制面四个静态 Pod、kube-proxy/calico-node/calico-kube-controllers/CoreDNS、Service CIDR、控制面 taint、Pod/Calico CIDR、临时跨节点 Pod 的双向 ICMP、集群 DNS、Service HTTP。临时 namespace 已删除，未删除 taint，未执行 reset。

阶段 1 已验收；后续阶段结果见 [implementation-journal.md](implementation-journal.md) 与 [evidence](evidence/)。
