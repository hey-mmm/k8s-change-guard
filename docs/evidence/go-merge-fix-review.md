# Go merge 集成修复说明

## 范围

仅修改：

- `work/k8s-change-guard/internal/guard/merge.go`
- `work/k8s-change-guard/internal/guard/merge_test.go`

未部署、未 merge、未 commit，未执行 PR 源码。其他文件由 root 负责。

## 修复 1：`cgMerge --evaluation-id` 可省略

- `MergeRelease` 不再在入口拒绝空 evaluation id。
- 显式非空 id 仍在入口做严格格式校验。
- 取得 state store 锁并读取 index 后，由新 helper
  `mergeResolveEvaluationID` 解析当前 PR 的 `evaluation_id`：
  - 省略 id：使用 index 中该 PR 的 recorded id。
  - 显式 id：必须与 recorded id 完全一致。
  - recorded id 缺失、非法，或显式指定了未索引/旧 id：全部 fail closed。
- 后续读取的报告仍按 resolved id 校验，报告 digest/policy/head/base/
  approval/CI/tree/lease 等原有边界未放宽。

## 修复 2：CI check-runs 使用现有 `github.token`

- 生产合并路径调用 `mergeValidateHeadCI(..., github.token)`，修复匿名
  共享出口额度耗尽导致的 403。
- `mergeFetchCheckRuns` 使用可选 token 参数以兼容已有测试调用；生产路径
  始终传入凭据。
- CI 请求固定走原 `api.github.com` 基址，保留：
  - 2 MiB 响应上限；
  - JSON 解析与分页完整性校验；
  - 精确 head SHA、`github-actions` app、required name、最新 run 成功校验。
- 每个 CI 请求使用显式 no-redirect 客户端；即使重定向，也会先删除
  `Authorization` 并拒绝跟随，token 不会发往重定向目标。
- 错误信息保持通用，不包含 token 或凭据内容。

## 测试

新增/覆盖：

- 省略 id 选择 recorded report；显式一致 id 通过。
- 显式旧 id、空 record、非法 recorded id、路径穿越、缺失 PR 记录均拒绝。
- CI 请求确实发送 `Authorization: Bearer <synthetic token>`。
- 403 仍 fail closed，错误不泄露 synthetic token。
- 重定向被拒绝，重定向目标零命中且不接收 Authorization。
- 原有 head/app/latest-success、分页不完整、CI digest/policy 等测试继续通过。

执行结果（`E:/Go/bin/go.exe`）：

```text
go test ./... -count=1
ok  github.com/hey-mmm/k8s-change-guard/cmd/change-guard
ok  github.com/hey-mmm/k8s-change-guard/internal/guard
?   github.com/hey-mmm/k8s-change-guard/scripts/packaging  [no test files]

go vet ./...
(no output)
```

`gofmt -w internal/guard/merge.go internal/guard/merge_test.go` 已执行。

## 交接

root 可按计划统一升版 0.3.2 并做不可变部署。PR9 的 `REVIEW` 已审批状态未改动；
本次仅修复 Go merge 的 evaluation-id 解析与 CI 认证路径。
