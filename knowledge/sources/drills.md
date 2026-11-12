# Demo 故障演练手册

本目录脚本只用于受限 namespace `demo` 中的 demo 应用演练：

- namespace：固定 `demo`
- Deployment：按标签
  `app.kubernetes.io/instance=demo,app.kubernetes.io/name=demo,app.kubernetes.io/component=demo-service`
  验证**唯一**，并要求名称为 `demo`（GitOps values 使用 `fullnameOverride: demo`）
- Argo Application：固定 `argocd/demo`，project 必须是 `demo`
- 只 patch Deployment 的 `env`，不删 Pod、不 scale、不 reset 集群、不触碰其它应用
- 所有 kubectl API 调用都带 `--request-timeout`（默认 20s），rollout/health 有总超时

**本手册已在真实集群执行**：500、3000 ms 慢请求、启动失败三项均完成注入、告警、确认与恢复，时间线见 [fault-review.md](fault-review.md) 和 `evidence/drill-events.jsonl`。下面保留可复跑的命令与边界；重跑前仍要确认 GitOps 自动同步状态和当前 demo 健康。

## 1. 前置条件

```bash
kubectl config current-context
kubectl -n demo get deploy demo
kubectl -n argocd get application demo
command -v kubectl curl python3 timeout
```

- 需要可访问 `demo` Service 的 `/healthz`、`/readyz`。默认脚本用
  `kubectl -n demo port-forward svc/demo 18081:8080`；也可用
  `DEMO_BASE_URL=http://...` 指定已有地址。
- 告警证据查询是**可选但推荐**的：设置 `ALERT_RECEIVER_URL` 为 receiver API
  URL（如 Alertmanager `/api/v2/alerts`）。不设置时 `alert_fired` 写 `null`。
- 脚本状态和 JSONL 写入 `scripts/drills/.state/`、`scripts/drills/logs/`，
  已被 `scripts/drills/.gitignore` 忽略。**不要把这些恢复文件提交或 push。**

## 2. 自动同步的受控暂停/恢复

GitOps 默认开启 `automated: {prune: true, selfHeal: true}`。若直接 patch
Deployment，Argo 会把它同步回去。因此 `inject.sh`：

1. 读取 `argocd/demo` 的 `.spec.syncPolicy.automated`；
2. 若已启用且未传 `--suspend-gitops`：**拒绝执行**；
3. 传了该参数才 merge patch 仅 `demo` 一个 Application 的 `automated: null`，
   并把原 JSON 保存到 state；
4. `recover.sh` 恢复 env 后，把原 automated 值 patch 回去并校验。

```bash
# 仅在需要临时暂停 demo 自动同步时显式加参数
scripts/drills/inject.sh --fault error --suspend-gitops
```

不要手工改其它 Application，也不要把 `.state` 加入 Git。若脚本异常退出，
trap 会尝试调用 recover；如失败，立即手工：

```bash
scripts/drills/recover.sh --state scripts/drills/.state/<drill-id>.json
```

## 3. 三种故障

### 3.1 错误率（100% /work 500）

```bash
scripts/drills/inject.sh --fault error --suspend-gitops
# 观察告警/指标/日志，例如：
#   sum(rate(demo_http_requests_total{route="/work",status=~"5.."}[5m]))
#   kubectl -n demo logs deploy/demo --tail=50
scripts/drills/recover.sh
```

env：`DEMO_ERROR_RATE=1`，并确保 latency/startup 为正常值。rollout 完成、
新 Pod Ready 后才记录 `fault_fully_effective=true`。

### 3.2 延迟

```bash
scripts/drills/inject.sh --fault latency --latency-ms 3000 --suspend-gitops
scripts/drills/recover.sh
```

env：`DEMO_LATENCY_MS=3000`。`/healthz`、`/readyz` 不注入延迟，避免探针误杀；
业务延迟看 histogram：

```promql
histogram_quantile(0.95,
  sum by (le) (rate(demo_http_request_duration_seconds_bucket{route="/work"}[5m])))
```

### 3.3 启动失败（验证发布保护，不是业务全停）

```bash
scripts/drills/inject.sh --fault startup-failure --suspend-gitops
scripts/drills/recover.sh
```

env：`DEMO_STARTUP_FAIL=true`。应用会打印明确的 `startup_failed` 日志并退出
（受 liveness/readiness 影响，新 Pod 进入 CrashLoop）。**不要**把
`kubectl rollout status` 失败直接记录成“启动故障完全生效”：

- Chart 使用 `maxUnavailable: 0` / `maxSurge: 1`；
- 新 Pod 失败时，旧 Pod 仍保持 Ready 并继续服务；
- 因此这项演练验证的是**滚动发布保护**，不是制造业务不可用；
- 脚本观察新 Pod/事件/日志，记录 `old_pod_still_serving`、
  `fault_fully_effective=false`、`release_protection_observed`。

如果确实需要验证“业务不可用”，必须另行设计**明确、可恢复**的演练（例如显式
scale deployment），并单独评审恢复步骤；本目录脚本不会偷偷删 Pod/scale 或制造
不可控中断。

## 4. 恢复语义

`recover.sh` 顺序：

1. 从 state 读取注入前的完整 container `env`，用 JSON patch 精确恢复；失败则
   回退为 `DEMO_ERROR_RATE=0 DEMO_LATENCY_MS=0 DEMO_STARTUP_FAIL=false`；
2. 等待 Deployment rollout（带总超时）；
3. 通过 port-forward 检查 `/healthz` 和 `/readyz`，记录成功 UTC；
4. 恢复 `argocd/demo` 的原 auto-sync 并校验；
5. 写 `recovered` JSONL；任何一步失败返回非 0。

```bash
# 最近一次
scripts/drills/recover.sh
# 指定状态
scripts/drills/recover.sh --state scripts/drills/.state/<drill-id>.json
# 状态丢失的兜底（只把三个 DEMO_* 设正常，无法恢复 Argo 原值）
scripts/drills/recover.sh --force-normal
```

恢复不会删除 state；需要保留证据。再次 recover 是幂等的。

## 5. JSONL 证据格式

日志：`scripts/drills/logs/drill-events.jsonl`（本地、gitignore）。每行一个事件，
示例字段：

```json
{"schema_version":1,"source":"scripts/drills","timestamp_utc":"2026-11-11T08:00:00.000Z","event":"fault_started","drill_id":"20261111T080000Z-1234-5678","fault_type":"error","namespace":"demo","deployment":"demo","fault_started_utc":"2026-11-11T08:00:01Z","gitops_suspended":true,"alert_fired":null,"root_cause_confirmed":false}
{"event":"alert_observation","alert_fired":null,"alert_http_status":"000","alert_query":"http://...","alert_evidence":"connection refused","root_cause_confirmed":false}
{"event":"recovered","recovery_started_utc":"...","rollout_completed_utc":"...","health_ok_utc":"...","gitops_restored":true,"status":"success","root_cause_confirmed":false}
```

规则：

- UTC 故障开始、alert 观测、rollout 完成、health 成功都有独立时间字段。
- `alert_fired` 仅当 receiver API 实际查询成功且能判定时是 true/false；
  未配置、不可达、非 2xx、响应无法解析时一律 `null`，**不猜测未告警**。
  receiver 支持 Alertmanager 风格 `{"alerts":[...]}`（匹配 namespace/deployment/
  app/service=demo 且 status=firing），或 `{"firing":true|false}`。
- `root_cause_confirmed` 默认始终是 `false`，脚本不会自动声称根因。
  操作者实际核对指标、日志、告警后，用：

```bash
scripts/drills/record.sh \
  --drill-id '<drill-id>' \
  --command 'sum(rate(demo_http_requests_total{route="/work",status=~"5.."}[5m])) + logs' \
  --evidence '实际观测到的数值/日志/告警 ID' \
  --confirmed
```

不加 `--confirmed` 只追加未确认的观测证据。没有实际输出不要写确认。

## 6. Git 回滚流程

演练 `recover.sh` 只恢复本地被 patch 的 env，不等于 GitOps 回滚。需要回滚发布时：

```bash
git revert <bad-desired-state-commit>
git push origin main
# 等待 Argo 同步；核对
kubectl -n demo rollout status deployment/demo --timeout=180s
```

**禁止**只执行 `argocd app rollback` 或 `kubectl rollout undo` 后就声称完成了
GitOps 回滚；Argo CD 的历史/自愈不能替代 Git desired state 的 revert commit。
GitOps 的 `targetRevision: main` 是 Git 分支，不是镜像 `latest`；镜像 tag 必须
是不可变 `sha-<commit>`。

## 7. 实际验收结果

| 故障 | 开始 UTC | 告警 UTC | 根因确认 UTC | 恢复 UTC |
| --- | --- | --- | --- | --- |
| 500 | 2026-11-11T12:16:49Z | 12:18:43.140Z | 12:20:45.460Z | 12:20:47Z |
| 慢请求 3000 ms | 2026-11-11T13:24:37Z | 13:26:43.138Z | 13:28:09.558Z | 13:28:10Z |
| 启动失败 | 2026-11-11T13:34:21Z | 13:37:27.649Z | 13:39:15.099Z | 13:39:21Z |

- 500 与慢请求均触发对应告警，恢复后收到同一 fingerprint 的 resolved；receiver 事件保存在 `evidence/demo-alerts.json`。
- 启动失败：新 Pod `startup_failed`/CrashLoop，旧 Pod 在 `maxUnavailable: 0` 下继续 Ready 并返回 200；这是发布保护，`fault_fully_effective=false`。
- 演练中修复了 port-forward 随旧 Pod 退出、Windows 复制脚本缺执行位、Shell 未赋值变量等问题；不把这些调试失败从原始 JSONL 中删除。
- 仍未做：7 天 SLO 完整窗口、业务全停类演练、邮件/短信外部通知。`ALERT_RECEIVER_URL` 已按本地 receiver 的 `{"alerts":[...]}` schema 使用；不匹配时仍写 `null`，不猜测。
