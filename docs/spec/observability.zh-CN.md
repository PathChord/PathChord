# Ingress 可观测性规范

[English](observability.md) | **简体中文**

Ingress 可观测性是本地控制平面的结构化查询和事件接口。它面向 Web 仪表板、CLI 诊断、
自动健康检查和事件分析。日志是补充手段；运维人员需要查询的指标或状态不得（MUST NOT）
仅存在于日志文本中。

## 与数据 Path 分离

`STATUS_REPORT` 是数据 Path 协议消息。它传达 Session 准入和调度所需的最少 Egress
容量及健康信息。它不是管理 API，也不是浏览器 API，不能替代本地指标。

可观测性服务与 Ingress 运行时并行运行，并从策略、Session、Path、目标连接、订阅和授权
组件读取类型化快照。它不得（MUST NOT）解析日志来重建主要状态。

Ingress 暴露一个有界的类型化快照/事件提供器。运行时生产者通过此提供器发布结构化观测，
外部适配器读取其快照和事件。提供器契约独立于外部 API 适配器和日志后端。

## 快照模型

`GET /api/v1/metrics/snapshot` 返回某一时刻的文档：

```json
{
  "api_version": "1",
  "snapshot_generation": 42,
  "captured_at": "2026-11-12T00:00:00Z",
  "ingress": {"state": "running", "uptime_seconds": 3600},
  "sessions": {"configured": 3, "active": 2, "degraded": 1},
  "paths": {"ready": 2, "draining": 0, "failed": 1},
  "streams": {"open": 12, "half_closed": 2, "reset": 1},
  "udp": {"associations": 4},
  "connections": {"targets": 16},
  "policy": {"generation": 18},
  "subscriptions": {"configured": 2, "healthy": 2}
}
```

确切的 JSON 名称属于适配器契约，不是线上 Path 格式。每个快照都有代次和捕获时间戳。
对于名称暗示单调性的计数器，在单个进程的整个生命周期内必须（MUST）保持单调；
仪表值可以（MAY）增大或减小。

结构化资源视图提供下钻查询：

```text
GET /api/v1/nodes
GET /api/v1/sessions
GET /api/v1/sessions/{session_id}
GET /api/v1/connections
GET /api/v1/metrics/paths
GET /api/v1/metrics/streams
```

查询必须（MUST）返回类型化字段和稳定的资源 ID。它不得（MUST NOT）要求客户端解析
供人阅读的状态字符串。

## 节点与 Path 指标

节点视图结合静态身份、导入的来源数据、管理员标签和运行时观测，同时保留各自的所有权：

```text
node.id, node.protocol, node.endpoint
source.subscription, source.imported_at
admin.labels, admin.tags
observed.connected, observed.rtt_ms, observed.jitter_ms
observed.loss_rate, observed.throughput_bps
observed.effective_capacity_bps, observed.state
quota.remaining_ratio, quota.reset_at
```

每个 Path 的视图暴露：

```text
path_id, session_id, egress_id, transit_proxy_id
state, ready_since, last_change_at
frame_sent, frame_received, frame_lost, frame_duplicate
rtt_ms, jitter_ms, loss_rate, reorder_count
throughput_bps, congestion_window, available_capacity_bps
control_pending, control_retransmissions
```

Path ID、Session ID 和 Transit Proxy ID 是基数有界的标签。原始 Transit 凭据、包含机密的
代理 URL、Noise 密钥和密文绝不作为指标字段。

## Session、Stream 与连接指标

Session 视图暴露：

```text
session_id, ingress_id, egress_id, state
admission_generation, created_at, last_change_at
ready_path_count, active_streams, active_udp_associations
control_pending, control_acked, control_retransmissions
close_reason, reconnect_attempts
```

Stream 视图暴露：

```text
stream_id, session_id, state, direction_state
target_kind, target_port, admitted_generation
bytes_sent, bytes_received, bytes_acked
reorder_buffer_bytes, receive_window, retransmissions
opened_at, closed_at, close_reason
```

目标连接视图暴露稳定的本地连接 ID、SessionID 和 StreamID、生命周期状态、字节计数器、
时间信息及规范化的关闭原因。可以（MAY）向已授权的本地管理员显示原始主机名，
但绝不得（MUST）返回原始凭据、嵌入机密的完整 URL 和载荷字节。对于非特权 Web 角色，
应当（SHOULD）根据配置的脱敏策略截断主机名或对其进行哈希处理。

## 计数器、仪表值与直方图

可观测性服务应当（SHOULD）提供以下指标族：

```text
pathchord_sessions_total
pathchord_session_closes_total{reason}
pathchord_paths_total{state}
pathchord_streams_total{state}
pathchord_udp_associations_total{state}
pathchord_target_connections_total{result}
pathchord_frames_total{direction, result}
pathchord_control_retransmissions_total{direction}
pathchord_bytes_total{direction, class}
pathchord_path_rtt_ms
pathchord_path_jitter_ms
pathchord_path_loss_ratio
pathchord_path_capacity_bps
pathchord_stream_reorder_bytes
```

直方图必须（MUST）在其适配器模式中定义单位和桶边界。比率为 `[0, 1]` 范围内的数值；
字节率和比特率使用显式的 `_bytes` 或 `_bps` 后缀。指标族必须（MUST）说明它属于计数器、
仪表值还是直方图。

## 基数控制

指标标签必须（MUST）从有界取值域中选择。不得将原始主机名、URL、RequestID、StreamID、
进程命令行、错误消息或任意管理员标记用作无界指标标签。高基数详情应放在分页资源查询或
采样事件中，而非聚合指标标签中。

服务必须（MUST）对以下内容实施限制：

- 跟踪的节点、Path、Session、Stream 和目标连接数量；
- 每个客户端保留的事件积压量；
- 不同标签/标记键和值的数量；
- 为图表保留的每个资源的历史记录。

达到限制时，快照报告带有原因的类型化 `degraded` 观测，仅丢弃可选历史记录，绝不丢弃
当前生命周期状态或安全决策所需的计数器。

## 事件与实时更新

`GET /api/v1/events` 在选定的 REST + SSE Web 适配器中使用 SSE。每个事件包含：

```text
id, type, generation, emitted_at, resource_type, resource_id, payload
```

必需的事件类型为：

```text
metrics.snapshot
node.changed
path.changed
session.changed
stream.changed
connection.changed
subscription.changed
authorization.changed
audit.notice
```

事件在每个 Ingress 进程内有序。重新连接的客户端提供 `Last-Event-ID`；服务器要么从其
有界事件缓冲区重放，要么发送新的完整快照，随后发送新事件。事件载荷使用与时点查询
相同的授权和脱敏规则。

## 脱敏与隐私

可观测性层必须（MUST）在暴露 Web 网关之前定义脱敏规则：

- 绝不暴露私钥、Noise 握手材料或持有者令牌；
- 绝不暴露订阅凭据或带签名的订阅 URL；
- 绝不暴露密文或应用载荷字节；
- 对不需要这些信息的角色，脱敏目标主机名和进程元数据；
- 在返回错误消息之前对其规范化，尽可能移除文件系统路径和对端提供的任意文本；
- 确保审计记录不包含完整请求正文和机密。

脱敏策略是操作者能力配置的一部分，并在序列化之前应用，而非仅在前端 JavaScript 中应用。

## 健康状态与新鲜度

每个快照都报告捕获时间和新鲜度。如果某个运行时生产者停止更新，可观测性服务将该
生产者报告为过期，而非将最后一个值呈现为当前值。建议阈值属于实现配置，但过期状态
必须（MUST）能够与测量值为零的情况区分。

本地控制平面将服务健康状态与 Egress 数据 Path 健康状态分别暴露：

```text
control_plane: running | degraded | stopped
runtime_snapshot: fresh | stale | unavailable
data_path_summary: connected | degraded | down
```

这些值不可互换。健康的本地控制平面可以报告 Egress 不可用，而 Egress 已连接并不意味着
Web 网关可用。

## 禁止仅依赖日志的要求

以下内容必须能作为结构化数据查询，不得仅在日志中提供：

- 当前 Session、Path、Stream、UDP 和目标连接状态；
- 策略和订阅代次；
- 节点标签/标记和运行时观测；
- 控制重传计数和待处理队列；
- 授权状态和撤销效果；
- 资源限制和生产者过期情况。

日志可以（MAY）提供解释和采样追踪，但删除或禁用日志不得（MUST NOT）导致控制平面 API
无法回答这些运维查询。
