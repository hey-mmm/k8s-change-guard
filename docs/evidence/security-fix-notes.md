# k8s-change-guard 安全修复记录

- 日期：2026-11-12
- 范围：`work/k8s-change-guard` 的 `daemon.py`、`merge.py`、相关测试、`config.example.yaml`、Ansible 配置模板
- 依据：`work/independent-review.md` IR-01，以及本轮额外要求的缓存策略绑定和 Helm chart 动态条件渲染风险
- 约束：未部署、未推送、未修改版本号、未修改项目文档

## 1. IR-01：`.github/workflows/` 修改硬 BLOCK

### daemon.py

- 新增 `WORKFLOW_PATH_PREFIX = ".github/workflows/"` 和 `is_workflow_path()`。
- `_build_context()` 同时比较 base/head 的 Git tree 中 `.github/workflows/` 条目签名（path/mode/kind/blob sha），不再只依赖可能被截断的 changed-path 列表。
- `_escalate_result()` 对任何 workflow 变更增加：
  - `rule_id: WORKFLOW_CHANGE_BLOCKED`
  - `severity: BLOCK`
- 该 BLOCK 与引擎原本的 PASS/REVIEW 无关；`_resolve_approval()` 只接受 REVIEW，因此 workflow 变更不可通过 `/guard approve` 放行。
- `report` 增加 `workflow_changed`，便于审计。
- `_load_valid_cached()` 对 PASS/REVIEW 缓存再次检查 workflow 变更，伪造的 PASS 旧报告不会被复用。

### merge.py

- 新增 `validate_workflow_snapshots()` 和 `verify_base_head_workflows()`。
- `merge_pr()` 在合并前独立调用 GitHub Git Trees API（`fetch_tree_snapshot()`，内部为 commit -> tree -> recursive tree）重新读取 base/head，比较 `.github/workflows/` 的 path/mode/kind/blob sha。
- 即使报告是签名 PASS，只要 workflow tree 不同就 `MergeRefused`。
- 另外拒绝报告中记录过 workflow 变更、`workflow_changed=true` 的报告（fail closed）。

## 2. 报告缓存绑定 guard 版本 + RULE_VERSION + 策略配置 digest

### 绑定内容

`current_policy_binding()` 生成：

```json
{
  "guard_version": "change_guard.__version__",
  "rule_version": "engine.RULE_VERSION",
  "policy_schema_version": 1,
  "policy_digest": "sha256(canonical JSON policy config)"
}
```

- `policy_config_snapshot()` 只纳入明确列出的公开安全/策略字段和路径配置。
- 不包含凭据值、凭据文件路径（如 `github_token_file`、`deepseek_token_file`、`merge_deploy_key`）。
- 排除 `state_dir`、`poll_seconds`、`max_open_prs`、报告注释开关等运行性配置。
- `approved_chart_digest`、`approvers` 等策略字段纳入；`approvers`/digest 列表排序后参与 digest，避免仅顺序变化造成误失效。
- 报告写入 `guard_version`、`rule_version`、`policy_binding`、`policy_digest`，并参与 report digest 与 evaluation id。

### 缓存与合并拒绝

- `_load_valid_cached()` 显式比较：
  - `schema_version`（本次提升为 2，旧报告自然失效）
  - `policy_binding`
  - `guard_version`
  - `rule_version`
  - `policy_digest`
  - report digest
  - 成功候选的 workflow/chart pin
- `merge.py::validate_policy_binding()` 在合并路径再次显式拒绝不匹配的报告；`validate_report(..., policy_binding=...)` 在初始校验、push 前 15 秒校验、13 秒校验均使用。
- 代码升级、RULE_VERSION 升级、策略配置变化、批准 chart 更新都会使旧报告失效。

## 3. Helm 动态条件渲染风险：charts/demo 信任白名单

### 配置

新增 `approved_chart_digest`，支持单个 SHA-256 字符串或列表（白名单）：

- `config.example.yaml` 默认给出当前 demo chart 的 digest：
  `0b2b19a416a9a59d9b89ef0b78a81f7dfa28cfc557c534e5eaaf6ed3a3b780a0`
- Ansible `config.yaml.j2` 使用 `change_guard_approved_chart_digest`，未定义时默认同上；模板升级需要操作员单独、受信地更新该变量/配置。
- 缺失 `approved_chart_digest` 时：
  - daemon 评估结果 `ERROR`（fail closed，`APPROVED_CHART_DIGEST_NOT_CONFIGURED`）
  - merge 直接拒绝

### digest 算法

```text
files = { relative_path_under_charts/demo: sha256(exact_git_blob_bytes) }
digest = sha256(canonical_json(files))
```

- 相对路径相对于 `charts/demo/`。
- 字节来自 GitHub Git blob API，不经过 checkout；不进行 CRLF/LF 归一化。CRLF 与 LF 是不同 digest。
- `gitops/demo/values.yaml` 明确不纳入 pin，仍参与渲染和全部普通规则。
- `work/approved-chart.json` 仅作参考；代码以实际 Git blob bytes 计算。

### BLOCK 语义

- 候选 chart 与白名单不匹配：`APPROVED_CHART_DIGEST_MISMATCH`，`severity: BLOCK`。
- BLOCK 不进入审批路径，merge 也拒绝。
- `merge_pr()` 还会独立从 head tree 重新计算 chart digest，校验报告记录的 `chart_digest` 与白名单，防止伪造 PASS 报告。
- 纯 mock 测试通过显式设置空 chart digest 的 fixture 绕过真实 chart bytes；生产配置不包含该空 digest。

## 4. 测试

执行：

```powershell
cd work\k8s-change-guard
python -m unittest discover -s tests
```

结果：

```text
Ran 174 tests in 1.229s

OK (skipped=3)
```

新增/更新的关键回归：

- `test_workflow_change_is_hard_block_even_when_engine_says_pass`
- `test_workflow_tree_signature_blocks_even_without_a_complete_path_list`
- `test_forged_pass_report_with_workflow_change_is_not_reused`
- `test_forged_pass_cannot_hide_a_workflow_tree_change`（merge 独立 tree 检查）
- `test_guard_rule_or_policy_upgrade_invalidates_cached_report`
- `test_code_upgrade_invalidates_old_pass_report`（merge 旧报告拒绝）
- `test_policy_binding_excludes_state_and_credentials_but_tracks_policy`
- `test_chart_digest_mismatch_is_hard_block_but_matching_pin_passes`
- `test_missing_chart_pin_is_error_and_values_are_not_pinned`
- `test_chart_pin_is_reverified_from_head_blobs`

跳过项为原有平台相关的 symlink 测试（Windows 上不允许创建 symlink），与本次修改无关。

## 5. 运行注意

- 现有 state 目录中的旧报告（schema 1、无 policy binding）在升级后会失效并重新评估，这是预期行为。
- 更新 `charts/demo` 模板时，必须由操作员独立、受信地更新 `approved_chart_digest`；guard 不会自动信任新 chart。
- merge 与 daemon 必须使用同一份受信配置；否则 policy digest 不一致，merge 会拒绝。
- 本次没有部署、没有推送、没有改版本号；部署和发布由 root 另行安排。
