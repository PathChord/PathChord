# 运行时可观测性

[English](observability.md)

PathChord 通过本地控制 socket 暴露运行时状态。使用具有
metrics:read 能力的 actor 运行 pathchordctl get diagnostics -o json。
响应包含进程实例、保留的 Path 终止记录、原因计数器和生产者丢失计数器。

使用 pathchordctl export-diagnostics --output /path/to/diagnostics.json
写出有界且已脱敏的 JSON 快照供离线比较。分别从 Ingress 和 Egress
收集文件，再用 session_id 和 path_id 关联已接纳的记录。每个角色
报告自己观察到的触发原因。

记录列表为空时，检查 expired、evicted 和 producer_drops。这些值
非零时，缺少记录不能证明对应阶段从未发生。启用并通过认证的 Web
Gateway 后，Prometheus 暴露 pathchord_path_terminations_total 和
pathchord_diagnostic_records_dropped_total。
