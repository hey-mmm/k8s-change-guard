# 设计与安全边界

## 决策优先级

规则逐项产生包含 `rule_id / severity / field / message / evidence` 的发现，最终按 `BLOCK > ERROR > REVIEW > PASS` 汇总。报告同时保留渲染差异、规则版本、AI 结果、来源与时间。

副本归零、删除 Deployment/就绪探针、故障开关、非白名单镜像、非法 digest、额外容器/执行命令、envFrom、危险权限、`.github/workflows/` 变更以及 `charts/demo` 与操作员 chart pin 不一致等硬规则不可审批覆盖。资源显著缩减、容量不足、当前错误/延迟/告警、未预留资源、模板变更和 AI 新风险需人工确认。数据缺失、过期、非数、渲染失败、模型失败均拒绝自动放行。

报告 schema 2 绑定 guard 版本、规则版本、策略 schema 和策略配置 digest；批准 chart 列表、审批人、阈值、端点等策略变化会使旧报告失效。缺失或错误的策略绑定不得复用旧缓存。

## 凭据隔离

常驻用户 `change-guard` 使用短期 ServiceAccount kubeconfig。RBAC 允许容量所需的节点/Pod 读取、目标 Deployment 与 Argo Application 等读取；不允许 Secret、日志、exec、创建、patch 或删除。管理员 kubeconfig 仅用于受信安装/轮换路径，不复制给服务。

GitHub PAT 限定项目一仓库：Contents/Pull requests/Issues 只读，Commit statuses 读写；默认不写评论。人工审批由操作员在 GitHub 发出，服务读取审批。个人仓库所有者身份可通过实时仓库 owner 与 GitHub 评论 OWNER 关联核验，其他账号无法证明写权限时拒绝确认。无需为此增加 Administration 权限。

部署密钥与只读/status PAT 分开：前者只供受信显式合并程序使用，后者供采集/状态发布。GitHub ruleset 的 DeployKey bypass 是仓库级 actor，平台不能把它收窄到某一把 key；因此“独立 deploykey”必须落实为仓库实际只有一把写部署密钥，并定期审计。具备该密钥本身就是更新代码的权限，其文件、服务主机和操作员属于受信部分。

## 不执行 PR 代码

程序始终来自已安装的受信发布。GitHub 候选树必须匹配精确提交，blob 校验 Git 对象 ID，拒绝 traversal、symlink、submodule、超量数据与未知路径。只将 Chart 和 values 数据物化到临时目录。

Helm 在 Linux bubblewrap 内运行：隔离网络、PID、用户、挂载，清空环境与 Helm 插件/registry/kubeconfig；只挂只读系统运行库、固定 Helm 二进制和候选数据；有限时、文件输出与内存约束。不使用依赖下载、post-renderer 或候选命令。hook 不能从检查集合中省略，最终全部拒绝；动态/环境相关模板默认拒绝。

`charts/demo` 另受操作员 pin 约束：digest = SHA-256(canonical JSON{相对路径: SHA-256(精确 Git blob 字节)})，CRLF/LF 不同即不同 digest，`gitops/demo/values.yaml` 不纳入该 pin。候选 chart 与 `approved_chart_digest` 不匹配是 BLOCK；未配置是 ERROR/BLOCK；更新模板必须由操作员独立、受信地更新 pin，guard 不会自动信任。当前真实 pin 是 `194baf90afd746299e256dc0bf144a12bc6f6325bacf77b40ff01e50b0c3e05d`，旧 `0b2b...` 参考值不可用。merge 还会从 head tree 独立重算并拒绝伪造报告。

`.github/workflows/` 的 base/head tree 内容必须完全一致。由于 GitHub Actions 对同仓库 `pull_request` 使用 PR 分支上的 workflow，任何 workflow 变更都可能伪造同名检查，因此它是不可审批的硬 BLOCK；merge 还会独立通过 Git Trees API 复核，不依赖报告结论。

systemd 保留 bubblewrap 必须的 namespace 能力，通过独立用户、空 capabilities、NoNewPrivileges、只读系统/配置/源码、保护 home、私有临时目录与 cgroup 内存限制约束服务。过度禁止 namespaces 会导致渲染失效，不能为获得漂亮的 hardening 分数而破坏实际隔离。

## 证据与容量

请求错误率/延迟来自真实 `/work` 指标，内存采用十五分钟历史峰值与余量。另查原始 `timestamp(metric)` 与 `up`，PromQL 求值时间不能充当源样本时间。目标就绪状态与指标一起检查；空结果不能当零。低流量只在数据源存在且新鲜时进入 REVIEW。

容量按 worker allocatable 和现有 Pod requests 统计，考虑初始化容器、overhead、旧 Pod 保留与 surge。API 中缺少 requests 表示调度预留为零，同时产生资源未预留风险，不能错误地声称“证据丢失”，也不能声称无运行时内存压力。

## 提交、基线与时效绑定

每份不可变报告绑定仓库、PR、候选 head SHA、当时 main SHA、树和渲染摘要、采集时间、规则/模型信息。追加提交或基线变化会使旧评估失效；REVIEW 评论须匹配精确 `/guard approve <evaluation_id>`、允许名单、当前权限与有效期，标签或旧评论不能永久放行。

daemon 定期重评/撤销过期状态，但停机时无法撤销 GitHub 旧状态，因此另限制 main 更新入口。显式合并程序检查当前 head/base、有效报告摘要、策略绑定、审批、workflow tree、chart pin 和 head SHA 上的 GitHub Actions `Test, lint, render` 成功结果；随后读取 GitHub synthetic merge commit，独立确认其两个 parent 正好是当前基线和候选 head，且 synthetic tree 精确等于 head commit tree。只有这些条件都成立，才用旧 main SHA 的精确 lease 将**已评估的 head**快进推送到 main，而不是推送 synthetic merge commit；不会 checkout 或执行候选代码，也不使用 GitHub Merge API。

GitHub Actions 的 `pull_request` check 绑定 head SHA，synthetic merge 的 check-runs 在真实环境可能为空，因此不能用 synthetic 的成功状态冒充。成功状态写到 head，main 快进后即对应新 head。main 上因此是普通单父提交；回退使用普通 `git revert <head>`，不加 `-m 1`。

合并后 PR closed/merged，daemon 会撤销旧 head 上的历史 `change-guard/release` 状态；main/旧 head 出现 guard error/pending 可能只是评估撤销，不是 postdeploy 失败。门禁有效性由 merge 记录和合并当时的报告/审批/CI 证明，不能用永久绿状态代替证据。

合并本身存在有限网络提交时间。程序要求有效期留有余量并对 push 设置更短超时；GitHub 无事务式证据时间检查，因此不能声称绝对消除了网络延迟或远端请求完成时间的不确定性。报告/服务主机时间同步是前提。

## 发布后

核对 Argo revision/Synced/Healthy、Deployment 与运行 Pod 镜像、`/version`、健康与业务接口，再观察正流量窗口中的错误率/延迟。发布后验证的 `--expected-sha` 是 Argo 应同步的 GitOps revision，`--expected-app-sha` 是 `/version` 暴露的镜像源提交；两者通常不同（发布 PR 的 merge/head 提交 vs 构建镜像的应用代码提交），必须同时传入，不能用其中一个替代另一个。镜像 index digest 与平台 manifest digest 可能不同，校验不得简单假定两者总相等；单架构镜像可严格比较。失败报告建议 Git revert PR，不直接修改集群或让 AI 执行回滚。
