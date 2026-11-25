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

## 详细服务日志

服务启动时读取 `PATHCHORD_LOG_LEVEL`，默认值为 `info`。
每个等级都包含表中在它上方的等级。

| 等级 | 记录内容 |
| --- | --- |
| `fatal` | 导致服务异常退出的启动或运行故障 |
| `error` | 监听器故障和 Session 失败 |
| `warn` | Path 故障、建连或准入失败、DNS 和 Stream I/O 失败、刷新失败后保留旧订阅数据、日志队列丢弃 |
| `info` | 服务就绪与关闭、监听器启动与停止，以及正常结束的 Session 和 Path |
| `debug` | 路由决策、连接生命周期、准入及目标建连成功、常规 DNS 和订阅结果 |
| `trace` | 帧元数据、载体写入、调度、重传、流控及 DNS 缓存结果 |
| `off` | 关闭服务日志输出 |

使用 systemd 时，在 `[Service]`
drop-in 中设置 `Environment=PATHCHORD_LOG_LEVEL=trace`，用
`journalctl -u pathchord-ingressd -f` 或 `journalctl -u pathchord-egressd -f`
查看日志。使用 OpenRC 时，在对应的 `/etc/conf.d/pathchord-ingressd`
或 `/etc/conf.d/pathchord-egressd` 中加入
`export PATHCHORD_LOG_LEVEL=trace`，再查看对应角色的 `service.log`。

DEBUG 记录监听器、策略和 DNS 的处理结果、订阅刷新、Path 建立和终止，
以及 Stream 连接和关闭。TRACE 还记录帧号和类型、数据偏移和字节数、ACK
区间、调度选择、重传、流控上限及载体写入耗时和结果。用 Session 和 Path
ID 关联两端记录。Ingress 在信息可用时包含 Transit Proxy ID、显示名、
订阅 ID、协议和选中的 Egress 端点索引。Egress 可以标识本地监听器索引。

JSON 记录输出到 stderr。诊断摘要通过 `log_drops` 报告日志丢弃数，日志
输出可用时还会发出 `diagnostic_log_loss`。日志保留由服务的日志管理器负责。
详细日志记录元数据，并省略凭据、密钥、流量正文和对端原始错误文本。
