# 故障演练验收与复盘

日期：2026-11-11。以下全部为 UTC，换算北京时间加 8 小时。首次调试失败也保留在原始事件中；下表选择修复后完成的演练。

| 故障 | 开始 | 告警收到 | 根因确认 | 服务恢复 |
| --- | --- | --- | --- | --- |
| HTTP 500 | 2026-11-11T12:16:49Z | 2026-11-11T12:18:43.140Z | 2026-11-11T12:20:45.460Z | 2026-11-11T12:20:47Z |
| 慢请求 3000 ms | 2026-11-11T13:24:37Z | 2026-11-11T13:26:43.138Z | 2026-11-11T13:28:09.558Z | 2026-11-11T13:28:10Z |
| 启动失败（旧 Pod 继续服务） | 2026-11-11T13:34:21Z | 2026-11-11T13:37:27.649Z | 2026-11-11T13:39:15.099Z | 2026-11-11T13:39:21Z |

证据：`evidence/drill-events.jsonl` 保存每次注入、观察、确认和恢复；`evidence/demo-alerts.json` 保存真实 Alertmanager webhook 通知及 fingerprint。根因确认时间取操作者写入记录的时间，不倒填日志产生时间。

- 500：`DEMO_ERROR_RATE=1`，真实请求日志返回 500；触发 DemoHighErrorRate，恢复为 200 后收到同指纹 resolved。
- 慢请求：`DEMO_LATENCY_MS=3000`，请求日志耗时约 3.00–3.01 秒；触发 DemoP95LatencyHigh，恢复后收到 resolved。
- 启动失败：新 Pod 输出 StartupError/`startup_failed`、CrashLoopBackOff，旧 Pod 保持 Ready 并返回 200；触发 DemoPodCrashLooping。这是发布保护，不是全服务中断。
- 数据持久化：见 `evidence/persistence.json`。Prometheus 与 Loki Pod UID 均改变，原 PVC 相同；固定查询时间的指标值仍为 67，重建前 marker 的原时间戳和日志全文完全相同。

发现并修复：Service port-forward 随旧 Pod 退出；Windows 复制的恢复脚本缺少执行位；Shell 同一 local 声明引用未赋值变量；滚动发布时旧 Pod Ready 不能证明新版本完成。Alloy 配置先通过自身 validate，再检查实际日志流。

时间同步：worker 的 ntp.ubuntu.com 被代理 DNS 返回 fake-IP，导致约 5–6 秒偏差；改用实际 UDP 探测可达的 203.107.6.88、120.25.115.20，最终两节点 NTPSynchronized=yes。前期日志保留原时间，不修改原始记录；跨节点秒级耗时统计需考虑该偏差。

告警只验证本地 webhook 通知链路。Prometheus 7 天 SLO 目标为 99.9%，本次未积累完整 7 天窗口，不宣称 SLO 已达标，也不编造恢复效率提升百分比。
