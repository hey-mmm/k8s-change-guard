# k8s-change-guard merge 运行时修复记录

- 日期：2026-11-12
- 范围：`work/k8s-change-guard/change_guard/merge.py`、`change_guard/daemon.py` 的 policy key、`tests/test_merge.py`、`tests/test_daemon.py`
- 前置：0.2.1 已部署；本工作不部署、不推送、不改版本、不改 docs
- 测试状态：完成

## 1. 真实发现

PR #2 的真实数据：

- head：`e6064c5df42ab701fac6a1e1be4bfac467a0410d`
- synthetic merge：`6809c2a8ec4ec76057d06e4ef10b416eb915a1f8`
- synthetic tree：`d84a70999466951822f4f1c0a4afa0576eb3b40c`
- head tree：`d84a70999466951822f4f1c0a4afa0576eb3b40c`（相同）
- head check-runs：`Test, lint, render`（GitHub Actions，success）
- synthetic check-runs：`[]`

GitHub Actions 的 `pull_request` check 绑定 head SHA，虽然 Actions checkout 的是 synthetic merge。旧的 `merge.py` 查询 synthetic 的 check-runs，真实环境下永远缺失；向 synthetic 写 required status 也不会成为 main 上 head 的状态。

## 2. 新 merge 流程（fast-forward）

`merge.py` 现在：

1. 保留原有 report digest、policy binding、审批、TTL、head/base 校验，以及 IR-01 的 workflow tree 与 chart pin 独立复核。
2. 保留 `compare.merge_base_commit.sha == base`：即 head 已包含当前 base。
3. 新增 `validate_synthetic_merge()`：
   - 从 PR raw `merge_commit_sha` 读取 synthetic；
   - 独立核验 `synthetic.parents == [base, head]`；
   - 独立核验 `synthetic.tree.sha == head commit tree.sha`；
   - 不相等直接 `MergeRefused`，不因报告 PASS 而放行。
4. CI 改为读取 **head SHA**：
   - `validate_head_ci()` 请求 `/repos/{repo}/commits/{head}/check-runs`；
   - `validate_ci()` 只接受 `app.slug == github-actions`、名称匹配、最新一条为 `completed/success` 的 check run；
   - 指定 head 时，check run 的 `head_sha` 必须等于 head，且响应 `total_count` 大于返回列表时 fail closed；
   - 不复用 synthetic 的 check-runs，也不使用可伪造的普通 commit status 代替 GitHub Actions check run。
5. 裸 Git 本地复核：
   - `git init --bare`；
   - 按 `merge_fetch_depth`（默认 128，可配置 1..10000）分别 fetch head 与 base；
   - `rev-parse` 核验本地 head tree 与 GitHub head tree 相同；
   - 核验 base commit 存在；
   - 尝试 `git merge-base --is-ancestor base head`；shallow 无法证明时以 GitHub compare 为准，非 shallow 且不是祖先则拒绝。
6. push 前再次读取 fresh PR/base 并重新校验 report、审批和 TTL；success status 刷新到 **head SHA**。
7. 最终 exact lease 快进推送：

```text
git push --force-with-lease=refs/heads/main:<base> \
  ssh://git@ssh.github.com:443/<owner>/<repo>.git \
  <head>:refs/heads/main
```

- 不再推 synthetic merge commit。
- 不使用 GitHub merge API，不添加 PR write PAT。
- 保护规则不变：update 仅 DeployKey bypass；required checks 无 bypass。success status 已写在 head 上，main 快进后即对应新 head。

## 3. merge record

`build_merge_record()` 写入：

```json
{
  "result": "MERGED",
  "strategy": "fast-forward",
  "head_sha": "<head>",
  "evaluated_head": "<head>",
  "base_sha": "<base>",
  "merge_sha": "<head>",
  "synthetic_merge_sha": "<synthetic>",
  "synthetic_tree_sha": "<tree>",
  "head_tree_sha": "<tree>",
  "base_ancestor": true,
  "github_merge_api_used": false,
  "rollback": {
    "strategy": "git-revert",
    "commit": "<head>",
    "mainline": null,
    "command": "git revert <head>"
  }
}
```

- `merge_sha == head`，兼容 post-deploy 对真正 main commit 的校验。
- 另保留 `synthetic_merge_sha` 和 `strategy=fast-forward`、`evaluated_head`。
- 生成文件为 `state_dir/merges/<head>.json`。

## 4. rollback

main 现在是普通的单父 head commit，不再是 synthetic two-parent merge commit。因此回滚应：

```text
git revert <head>
```

不再使用 `git revert -m 1`。merge record 已明确记录 `rollback.mainline = null` 和命令。现有 `docs/` 中的 `-m 1` 示例本轮按要求未修改，部署/验收时应由 root 或文档维护方更新。

## 5. GitHub 侧注意事项

- 直接推送 head 到 main 后，GitHub 是否自动把 PR 标记为 merged 不由 guard 保证。
- 若未自动标记，由 root 检查并处理；不要为此给 guard 增加 PR write PAT 或 merge API 权限。
- required checks 无 bypass，因此只在 head 上写成功状态；不以 synthetic 状态冒充。

## 6. policy digest 补充

`daemon._POLICY_CONFIG_KEYS` 增加并纳入 digest：

- `max_error_ratio`
- `max_p95_seconds`
- `memory_headroom_factor`
- `low_traffic_rps`
- `min_request_rate`
- `prometheus_url`
- `deepseek_url`
- `deepseek_timeout_seconds`
- `deepseek_total_timeout_seconds`
- `deepseek_max_response_bytes`
- `kubectl_timeout_seconds`
- `prometheus_timeout_seconds`
- `kubectl_max_output_bytes`
- `prometheus_max_response_bytes`
- `observation_seconds`
- `postdeploy_timeout_seconds`
- `postdeploy_poll_seconds`
- `require_pod_image_id`
- `strict_image_id_digest`
- `version_path`
- `ready_path`
- `argocd_namespace`
- `argo_application`
- `container_name`
- `demo_url`

测试覆盖这些阈值/端点改动会使 `policy_digest` 变化，从而让旧报告缓存失效。

## 7. 测试

执行：

```powershell
cd work\k8s-change-guard
python -m unittest discover -s tests
```

结果：

```text
Ran 181 tests in 1.188s

OK (skipped=3)
```

新增的关键语义测试：

- `test_synthetic_tree_must_equal_head_tree`
  - synthetic tree != head tree 拒绝
  - synthetic parents 顺序错误拒绝
- `test_ci_is_read_from_head_sha_not_synthetic`
  - 断言 CI URL 使用 head，不使用 synthetic
  - 别的 head 的成功 check 不能重放
  - 非 GitHub Actions App 不能冒充
- `test_fast_forward_push_uses_head_and_exact_lease`
  - `--force-with-lease=refs/heads/main:<base>`
  - 推送目标是 `<head>:refs/heads/main`
- `test_merge_record_points_to_head_and_plain_revert`
  - `merge_sha == head`
  - `strategy == fast-forward`
  - rollback 没有 `-m/--mainline`
- `test_local_git_tree_mismatch_is_refused`
  - 本地 fetch 的 tree 与 GitHub tree 不一致时拒绝
- policy digest 阈值测试扩展到 `max_error_ratio`、`max_p95_seconds`、`memory_headroom_factor`、`low_traffic_rps`、`prometheus_url`、`deepseek_url`、超时等。

跳过 3 项仍是 Windows symlink 平台限制测试，与本次修改无关。

## 8. 只读真实环境核验

本轮没有执行 merge/push，只做了只读验证：

- 使用真实 PR #2 head/synthetic 调用了 `verify_local_fast_forward()`：
  - 本地 fetch 成功；
  - head tree = `d84a70999466951822f4f1c0a4afa0576eb3b40c`；
  - `base_ancestor = true`。
- 使用真实 head 调用 `validate_head_ci()`：
  - 读取到 2 条 check run；
  - `Test, lint, render` 为 GitHub Actions success。
- 真实 synthetic/head commit 的 tree 均为 `d84a...`，parents 为 `[base, head]`。

## 9. 部署边界

- 未改 `__version__`/`pyproject.toml`。
- 未部署、未推送、未创建 PR、未修改 docs。
- root 部署 0.2.2 后再做真实 merge 验收。
