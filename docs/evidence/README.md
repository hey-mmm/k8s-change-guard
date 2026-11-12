# 证据索引

> 本目录的部署、merge、postdeploy 和 runtime proof 分为四类：
>
> - **历史 Python 0.2.x**：真实部署、门禁拒绝、发布与回退，只是历史证据。
> - **Go 0.3.0**：首次 Ansible 部署在 `check-token` 参数顺序失败并回切，属于失败历史；release 保留，不伪改。
> - **Go 0.3.1**：历史部分验收；部署和部署级 live 成功，危险 PR8 BLOCK，PR9 REVIEW 精确审批成功；正式 merge 因评估 ID 缺省和匿名 CI 403 被安全拒绝，`main` 未变。不能算完整发布成功。
> - **Go 0.3.2**：当前版本；完整构建、部署、真实门禁、发布、回退和最终清理已通过，见 [最终验收](../go-acceptance-final.md)。

以 [最终验收报告](../acceptance.md) 的分项链接为入口。`ev-*.json` 是不同时刻的不可变评估快照，包括开发中已修复错误和过期报告；不要把目录中任意历史记录当作当前状态。`approval-*.json` 是操作员动作记录，实际认可结果以对应 merge 记录为准；最早一次带说明文字的评论未满足精确命令格式而被拒绝。

- **Go 0.3.0 失败历史**：`go-0.3.0-ansible-deploy.txt`、`go-0.3.0-blocker-check-token.txt`、`go-0.3.0-deployment.json`、`go-blocked-final-state.json`、`go-check-token-bug.json`。记录 `check-token KUBECONFIG --min-remaining ...` 的 `rc=2`、回切 `0.2.3` 和 0.3.0 artifact 哈希。
- **Go 0.3.0 只读核心探测**：`go-0.3.0-probe-*.json`，在回切后用已安装 0.3.0 二进制做的 collect/render/knowledge/DeepSeek/evaluate；证明核心路径，**不是** 0.3.0 部署成功，也不是 0.3.1 证据。
- **Go 0.3.1 构建**：`dist/k8s-change-guard-0.3.1.tar.gz`（`3482084` bytes、`51c42df2...`），摘要见 `go-build-artifact-0.3.1.json`；`go-release-preflight.json` 记录发布前 CI/镜像/main 基线。
- **Go 0.3.1 部署级 live**：`go-0.3.1-preflight.json`、`go-0.3.1-ansible-deploy.txt`（`ok=85 changed=11`）、`go-0.3.1-ansible-idempotent.txt`（`changed=0`）、`go-0.3.1-deployment.json`、`go-0.3.1-runtime.txt`（服务/unit/timer）、`go-0.3.1-rbac.txt`（只读/拒绝项）、`go-0.3.1-renew-token.txt`、`go-0.3.1-check-token-*.txt`、`go-0.3.1-knowledge.json`、`go-0.3.1-collect.json`、`go-0.3.1-render.json`、`go-0.3.1-ai.json`、`go-0.3.1-final-report.json`、`go-0.3.1-daemon-once.txt`。网络恢复记录为 `go-network-restored.json`，只说明代理可达，不是门禁成功。
- **Go 0.3.1 PR 部分验收（历史）**：`go-danger-*` 记录 PR7/PR8 的 BLOCK、new-head 重评、merge 405 和直推 422；`go-release-independent-review.json`、`go-approval-ev-e941441d7a1f429dfbf37dd5.json` 记录 PR9 REVIEW 与精确审批（含 AI 脱敏 env 误报被 base/head blob 证伪）；`go-merge-0.3.1-refused.log` 和 `go-merge-eval-fallback-9.json` 记录两次安全拒绝（评估 ID 缺省、匿名 CI 403），`main` 未变；`go-ci-merge-9.json` 后续已由 0.3.2 成功合并轮次覆盖，归属当前验收；历史拒绝请使用前述独立日志。未发布、未回退，不能写 PASS。
- **Go 0.3.2（当前）**：`go-build-artifact-0.3.2.json` 记录 `3485074` bytes / `39291800...`；`go-0.3.2-preflight.json`、`go-0.3.2-ansible-deploy.txt`（`ok=84 changed=7`）、`go-0.3.2-ansible-idempotent.txt`（`changed=0`）、`go-0.3.2-deployment.json`、`go-0.3.2-runtime.txt`、`go-0.3.2-rbac.txt`、`go-0.3.2-renew-token.txt`、`go-0.3.2-check-token-*.txt`、`go-0.3.2-knowledge.json` 是部署级证据。完整 live 证据保存在部署摘要的 live 小节；发布与回退分别见 go-postdeploy-release9-032b.json 和 go-postdeploy-revert10-032.json，最终状态见 go-final-032-acceptance.json。
- `deployment-0.2.3.json`、Ansible 0.2.3 原始输出、`final-runtime-proof.json`：历史 Python 最终部署与运行。
- `deployment-0.2.1-detailed.json`：历史 Python 隔离/权限/续期详细检查，明确不是 0.2.3 全新部署报告。
- `hard-boundary-live-rejections.json`：历史 Python 的真实 GitHub BLOCK 拒绝及演练清理。
- `merge-pr-2.json` / `merge-pr-6.json`、对应 postdeploy、app acceptance：历史 Python 发布与回退。
- `isolated-live-failure-probes.json`：历史 Python 的实际采集/API 调用，隔离故障配置，无集群写入。
- `scenario-matrix.json`：合成回归与 AI stub，不是 live。
- `traffic-cleanup.json`：客户端结果与两次连接失败，不能被服务端 5xx=0 掩盖。
- `security-fix-notes.md` / `merge-runtime-fix-notes.md`：历史修复记录，最终行为以代码和验收为准。

证据未包含 token、私钥、密码或 kubeconfig 内容。`hash-index.json` 列出文件的 SHA-256 与长度，便于离线核对；它不构成第三方签名。新增 Go 证据在写入索引前应确认已脱敏，且不得修改旧 Python/0.3.0 证据的结论或哈希。

Go 迁移证据的当前 SHA-256 清单为 `go-hash-index.json`，以 Git 规范化后的归档字节计算；旧 `hash-index.json` 保留原历史范围。
