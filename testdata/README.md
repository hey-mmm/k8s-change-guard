# Python → Go 回归基线

`python-oracle.json` 在迁移时一次性从已备份 Python 0.2.3（`d21cef4`）生成。

包含原规则测试的 101 次评估，以及 25 组场景分别启用、关闭 AI 后的 50 次评估，总计 151 份输入与预期结果。Go 测试直接读取 JSON，无需安装或运行 Python。`__migration_float__` 表示 JSON 无法直接编码的 NaN / Infinity，仅由测试加载器恢复，用于验证非有限监控值会被拒绝。

这些是合成回归证据。真实 Kubernetes、Prometheus、DeepSeek、GitHub 门禁、审批和发布验收需另行记录，不将此文件当作真实发布成功证明。
