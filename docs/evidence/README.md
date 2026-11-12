# 证据索引

> 本目录的部署、merge、postdeploy 和 runtime proof 全部属于历史 **Python 0.2.x**。
> Go `0.3.0` 尚未部署，live 验收 pending；不要把这里的任意记录当作 Go 上线或当前状态。

以 [最终验收报告](../acceptance.md) 的分项链接为入口。`ev-*.json` 是不同时刻的不可变评估快照，包括开发中已修复错误和过期报告；不要把目录中任意历史记录当作当前状态。`approval-*.json` 是操作员动作记录，实际认可结果以对应 merge 记录为准；最早一次带说明文字的评论未满足精确命令格式而被拒绝。

- `deployment-0.2.3.json`、Ansible 0.2.3 原始输出、`final-runtime-proof.json`：最终部署与运行。
- `deployment-0.2.1-detailed.json`：历史隔离/权限/续期详细检查，明确不是 0.2.3 全新部署报告。
- `hard-boundary-live-rejections.json`：真实 GitHub BLOCK 拒绝及演练清理。
- `merge-pr-2.json` / `merge-pr-6.json`、对应 postdeploy、app acceptance：发布与回退。
- `isolated-live-failure-probes.json`：实际采集/API 调用，隔离故障配置，无集群写入。
- `scenario-matrix.json`：合成回归与 AI stub。
- `traffic-cleanup.json`：客户端结果与两次连接失败，不能被服务端 5xx=0 掩盖。
- `security-fix-notes.md` / `merge-runtime-fix-notes.md`：历史修复记录，最终行为以代码和验收为准。

证据未包含 token、私钥、密码或 kubeconfig 内容。`hash-index.json` 列出文件的 SHA-256 与长度，便于离线核对；它不构成第三方签名。
