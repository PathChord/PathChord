# Ingress 可观测性规范

[English](observability.md) | **简体中文**

Ingress 可观测性是本地控制平面的结构化查询和事件接口。日志只是补充；运维人员需要的
状态或指标不得仅存在于日志文本中。

## 与数据 Path 分离

`STATUS_REPORT` 是经过认证的数据 Path 消息。其线编码由[线协议 profile](wire-profile.zh-CN.md)
定义；语义字段是 Session 准入和调度所需的最少 Egress 信息。它不是管理 API、浏览器 API，
也不能替代本地指标。

可观测性提供器从策略、Session、Path、目标连接、订阅和授权组件读取类型化快照。它不得
解析日志来重建主要状态。运行时生产者通过一个有界提供器发布数据，该提供器独立于外部 API
适配器和日志后端。

## 快照模型

`GET /api/v1/metrics/snapshot` 返回包含控制面通用响应元数据的时点文档：

```json
{
  "api_version": "1",
  "request_id": "01JEXAMPLE",
  "observed_generation": {"scope": "observation", "value": 42},
  "snapshot_generation": 42,
  "captured_at": "2026-11-12T00:00:00Z",
  "freshness": "fresh",
  "ingress": {"state": "running", "uptime_seconds": 3600},
  "system_proxy": {"enabled": false, "listener_id": null, "platform_effect": "disabled"},
  "egress": {"configured": 3, "up": 2, "degraded": 1, "draining": 0, "down": 0},
  "egress_reports": [{
    "egress_id": "jp-1",
    "state": "up",
    "load_ratio": 0.42,
    "connection_utilization_ratio": 0.35,
    "bandwidth_utilization_ratio": 0.51,
    "active_sessions": 2,
    "active_streams": 12,
    "active_target_connections": 16,
    "capacity_bps": 180000000,
    "recommended_path_count": 2,
    "status_report_age_ms": 120
  }],
  "sessions": {"configured": 3, "active": 2, "degraded": 1, "draining": 0},
  "paths": {"ready": 2, "draining": 0, "failed": 1},
  "streams": {"open": 12, "half_closed": 2, "reset": 1},
  "udp": {"associations": 4},
  "connections": {"targets": 16},
  "policy": {"generation": 18},
  "subscriptions": {"configured": 2, "healthy": 2}
}
```

`load_ratio`、利用率和丢包率是 `[0, 1]` 中的数值；`capacity_bps` 是无符号比特率；计数
是非负整数；`status_report_age_ms` 是最新认证报告的年龄。报告超过配置的新鲜度阈值时，
相应 Egress 观测必须标记为 `stale`，不能当作当前零负载。名称表示单调性的计数器在单个
进程生命周期内必须单调；仪表值可以双向变化。本响应中的 `snapshot_generation` 与
`observed_generation` 标识同一个观测快照。
`system_proxy.platform_effect` 的值为 `disabled`、`applied` 或 `unsupported`；系统代理激活仅限 Windows，
因此 Linux 和 FreeBSD 的系统代理状态查询必须返回 `enabled: false` 和 `platform_effect: unsupported`。
其启用和关闭操作返回 `UNSUPPORTED_OPERATION`。

结构化下钻资源如下：

```text
GET /api/v1/nodes
GET /api/v1/sessions
GET /api/v1/sessions/{session_id}
GET /api/v1/connections
GET /api/v1/listeners
GET /api/v1/authorizations
GET /api/v1/system-proxy
GET /api/v1/metrics/paths
GET /api/v1/metrics/streams
```

每个查询返回类型化字段、稳定资源 ID 和通用响应元数据。列表使用控制面规范定义的有界
分页、过滤和排序合同。

## 节点与 Path 指标

节点视图组合保持所有权分离的字段：

```text
node.id, node.protocol, node.endpoint
source.subscription, source.imported_at
admin.labels, admin.tags
observed.connected, observed.state, observed.freshness
observed.rtt_ms, observed.jitter_ms, observed.loss_rate
observed.throughput_bps, observed.effective_capacity_bps
quota.remaining_ratio, quota.reset_at
```

每个 Path 视图暴露：

```text
path_id, session_id, egress_id, transit_proxy_id
state, ready_since, last_change_at, freshness
frame_sent, frame_received, frame_lost, frame_duplicate
rtt_ms, jitter_ms, loss_rate, reorder_count
throughput_bps, congestion_window, available_capacity_bps
control_pending, control_retransmissions
```

Path、Session 和 Transit Proxy ID 是基数有界的标签。原始 Transit 凭据、包含机密的代理 URL、
Noise 密钥和密文绝不作为指标字段。

## Session、Stream 与连接指标

Session 视图暴露：

```text
session_id, ingress_id, egress_id, state, freshness
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
时间信息和规范化关闭原因。已授权的本地管理员可以获得原始主机名；原始凭据、包含机密的
URL 和载荷字节绝不得返回。

## 调度和 STATUS_REPORT 观测

观测提供器必须保留调度器所需的 Egress 字段：负载、连接利用率、带宽利用率、活跃
Session/Stream/目标连接数量、聚合容量、建议 Path 数量和报告新鲜度。Ingress 的 Path 观测
必须包含 RTT、抖动、丢包、乱序、吞吐量、有效容量和连接建立质量。

调度器使用这些类型化字段，不能使用人类可读日志。报告过期时，除非策略明确允许降级运行，
否则 Egress 必须从新的准入中移除。质量下降时快速减少分配；恢复和缩容遵循状态机的排空及
稳定化规则。当 Path 因新增容量低于自身开销而被排除时，观测 API 必须暴露原因。

## 计数器、仪表值和直方图

Web Gateway 通过 `GET /metrics` 提供 Prometheus text format 0.0.4，使用
`Content-Type: text/plain; version=0.0.4; charset=utf-8`。它与 JSON metric 查询使用相同的
认证、Origin 限制和 `metrics:read` 授权，不是独立特权或未认证的监听器。响应读取同一份
规范观测快照，并提供以下聚合 gauge，不带用户控制或目标地址标签：

```text
pathchord_active_sessions
pathchord_ready_paths
pathchord_active_streams
pathchord_target_connections
pathchord_observed_nodes
pathchord_observed_connections
pathchord_observation_generation
```

这些值描述快照当前状态，不得表示为历史事件 counter 或生命周期总量；不得伪造缺失的快照
事实。高基数连接详情保留在经过授权的资源查询中。提供方 quota、到期时间和显式计费元数据
遵循[Transit Proxy 用量契约](transit-proxies.zh-CN.md#提供方用量元数据)。


服务应提供以下指标族：

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
pathchord_egress_load_ratio
pathchord_egress_connection_utilization_ratio
pathchord_egress_bandwidth_utilization_ratio
pathchord_egress_recommended_paths
pathchord_stream_reorder_bytes
```

直方图必须在其适配器 schema 中定义单位和桶边界。每个指标族必须声明自己是计数器、仪表值
还是直方图。

## 基数控制

指标标签必须来自有界域。原始主机名、URL、RequestID、StreamID、进程命令行、错误消息或
任意管理员标记不得作为无界聚合标签。高基数详情应位于分页资源查询或采样事件中。

服务必须限制跟踪资源数量、每客户端事件积压、不同 label/tag 键和值，以及每资源历史记录。
达到上限时报告带原因的类型化 `degraded` 观测，只丢弃可选历史，绝不丢弃当前生命周期状态
或安全决策所需计数器。

## 事件和实时更新

选定的 REST 适配器通过 SSE 提供 `GET /api/v1/events`。每个事件包含 `id`、`type`、
`generation`、`emitted_at`、`resource_type`、`resource_id` 和类型化 `payload`。`generation`
使用与响应元数据相同的 `{scope,value}` 形式；资源载荷可以另外携带自身的 `revision`。

规范事件注册表为：

```text
metrics.snapshot
node.changed
path.changed
session.changed
stream.changed
connection.changed
subscription.changed
authorization.changed
system_proxy.changed
audit.notice
```

事件在每个 Ingress 进程内有序。`Last-Event-ID` 要么从有界缓冲区重放，要么先发送完整快照
事件再发送新增量。事件载荷使用与时点查询相同的授权和脱敏规则。`subscription.refresh` 不
是独立事件类型；刷新结果通过带类型化结果的 `subscription.changed` 表示。

## 脱敏与隐私

暴露 Web Gateway 前，可观测性层必须定义脱敏：

- 绝不暴露私钥、Noise 握手材料、持有者令牌、订阅凭据、签名订阅 URL、密文或载荷；
- 对不需要的角色脱敏目标主机名和进程元数据；
- 规范化错误，移除文件系统路径和对端任意文本；
- 审计记录不得包含完整请求正文和机密。

脱敏属于 actor capability 配置的一部分，并在序列化前执行，而不是只在前端代码中执行。

## 健康状态和新鲜度

每个快照报告捕获时间和新鲜度。停止更新的运行时生产者标记为 `stale` 或 `unavailable`，
绝不能呈现为当前零值。阈值属于配置，但 `stale` 必须与测量值为零区分开。

本地控制平面暴露相互独立的健康值：

```text
control_plane: running | degraded | stopped
runtime_snapshot: fresh | stale | unavailable
data_path_summary: connected | degraded | down
```

这些值不可互换。健康的控制平面可以报告 Egress down，而 Egress 已连接也不代表 Web Gateway
可用。

## 禁止仅依赖日志

以下内容必须作为结构化数据可查询：当前 Session、Path、Stream、UDP 和目标连接状态；策略、
订阅、观测和授权代次；节点 label/tag 和运行时观测；控制重传计数和队列；授权清理影响；
监听器清单以及系统代理选择/效果；
资源限制或生产者过期条件。禁用日志不得导致控制面 API 无法回答这些查询。
