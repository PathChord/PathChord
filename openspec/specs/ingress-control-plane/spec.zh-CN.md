# Ingress 控制平面规范

[English](spec.md) | **简体中文**

## Purpose

定义用于操作 PathChord 的权威类型化管理服务、本地和可选 Web 适配器、资源操作、授权边界及事务式变更语义。

## Requirements

### Requirement: Detailed control-plane contract

控制平面 SHALL 遵循下文完整详细契约，包括封装格式、资源和操作注册表、限制、错误码以及 REST/SSE 映射。这些要求和场景补充该契约，不替代其字段定义或失败语义。

#### Scenario: Oversized local envelope

- **WHEN** 本地请求声明的封装长度超过 1 MiB
- **THEN** 服务在分配 JSON 对象前拒绝该请求。

### Requirement: Shared service and authenticated adapters

每个管理适配器 SHALL 调用同一个类型化 command/query service，并 SHALL 执行其 actor、capability 和脱敏规则。本地管理 SHALL 在 Linux 和 FreeBSD 上使用操作系统保护的 Unix socket，在 Windows 上使用 Named Pipe。可选 Web Gateway SHALL 默认关闭并与 Transit 和 Egress 数据 Path 隔离；非 loopback 绑定 SHALL 满足详细契约中的受保护传输、token、origin、限流和审计要求。

#### Scenario: Console assets do not authorize API access

- **WHEN** 客户端加载控制台后发起 REST 或 SSE 请求
- **THEN** 该请求仍需经过 actor 和 capability 检查；提供静态资源不会授予 API 访问权限。

### Requirement: Scoped atomic and idempotent mutations

变更 SHALL 携带所属作用域的期望代次或显式授权的 force capability，SHALL 在冲突时不发布部分变更，并 SHALL 按 `(actor.id, request_id)` 及详细保留契约实现幂等性。

#### Scenario: Stale mutation generation

- **WHEN** 变更提供过期的期望代次，且没有已授权的 force capability
- **THEN** 服务返回 `GENERATION_CONFLICT`，且不发布部分变更。

#### Scenario: Request identifier replay

- **WHEN** 原幂等记录仍在保留期内，actor 使用相同请求标识重复请求
- **THEN** 相同规范正文获得原响应，变化的规范正文返回 `IDEMPOTENCY_CONFLICT`。

### Requirement: Bounded typed resource queries

查询 SHALL 暴露稳定资源标识、类型化字段、所属代次或 revision，以及有界分页、过滤和确定性排序。未知查询或过滤键、不支持的排序字段、无效分页 token 及越界分页大小 SHALL 返回 `VALIDATION_FAILED`。Label/tag 变更 SHALL 保留 source、observed、quota 和硬状态字段的所有权。

#### Scenario: Unknown list query field

- **WHEN** 列表请求包含未注册的查询字段
- **THEN** 服务以 `VALIDATION_FAILED` 拒绝请求，不忽略该字段。

### Requirement: Durable subscription control decisions

订阅变更 SHALL 在释放或排空来源可见性前，原子提交决定及其配置代次。对于声明式 Subscription，API 的启用、禁用、删除和显式重新创建决定 SHALL 在声明不变时跨重载和重启保持权威。刷新失败 SHALL 保留上一成功快照；删除 SHALL 排空仅由该来源导入的节点。

#### Scenario: Reload preserves an administrative disable

- **WHEN** 声明式 Subscription 通过 API 禁用，随后重载其未变化的声明
- **THEN** Subscription 保持禁用，不被该声明重新启用。

### Requirement: Egress-owned authorization and cleanup

授权管理 SHALL 保持为 Egress 本地操作，使用所属持久化存储，并在持久化审计写入无法完成时失败关闭。Disable 和 revoke SHALL 拒绝新握手并终止匹配存活资源；revoke SHALL 对该记录身份为终态，删除 SHALL 等待清理。授权和 system-proxy 变更 SHALL 返回详细契约规定的非负清理计数摘要。

#### Scenario: Ingress gateway cannot administer Egress authorization

- **WHEN** Web Gateway 连接到 Ingress dispatcher
- **THEN** 它省略 `/api/v1/authorizations*`，不把 Egress 授权操作作为 Ingress 能力暴露。

#### Scenario: Revocation terminates live resources

- **WHEN** 授权成功撤销
- **THEN** 新的匹配握手被拒绝，匹配的 Path、Session、Stream、UDP Association 和目标连接被终止，并报告清理结果。

## Detailed contract

本文档定义用于操作 Ingress 的本地控制平面，以及供前端使用的可选 Web 网关。它独立于
PathChord 数据 Path。所有适配器都调用同一个类型化 command/query service；不得直接编辑
配置文件、订阅缓存或数据库。

### 架构和封装

```text
pathchord CLI --------------------+
                                   |
optional authenticated web gateway +--> typed Ingress command/query service
                                   |             |
Unix socket / named pipe ----------+             +--> atomic snapshots
                                                 +--> subscription workers
                                                 +--> authorization/policy store
                                                 +--> metrics registry
```

必需的特权本地适配器在 Linux 和 FreeBSD 上是 Unix domain socket，在 Windows 上是 Named Pipe。操作系统
所有者/ACL 是第一道授权边界。可选 Web Gateway 默认关闭，必须与数据 Path 分离，不能通过
Transit Proxy 或 Egress 数据 Path 访问。非 loopback 绑定还必须显式配置受保护通道、强身份
认证、来源允许列表、限流、脱敏和管理员可见的审计记录。
选定的 Gateway 默认绑定 loopback。非 loopback 绑定 MUST 要求显式 protected-transport 声明、
至少 32 字节的 bearer token 和非空的精确 origin allowlist。静态控制台资源不授予 API 访问；
每个 REST 和 SSE 请求都经过与本地 adapter 相同的 actor/capability 检查。

本地协议使用带长度前缀的 UTF-8 JSON 封装。长度是一个规范的 QUIC 风格无符号变长整数，
表示恰好一个 JSON 对象的 UTF-8 字节数。封装上限为 1 MiB；零长度、截断前缀、非规范变长
整数、尾随字节或超限对象必须在 JSON 分配前拒绝。

请求格式如下：

```json
{
  "api_version": "1",
  "operation": "nodes.patch_labels",
  "request_id": "01JEXAMPLE",
  "actor": {"id": "local-admin", "capabilities": ["nodes:write"]},
  "expected_generation": {"scope": "configuration", "value": 12},
  "body": {"node_id": "provider-a-node-01", "set": {"admin.region": "jp"}, "remove": []}
}
```

每个响应都包含 `api_version`、原样返回的 `request_id`、布尔 `ok` 和 `observed_generation`。
成功响应包含 `result`；失败响应包含具有 `code`、安全 `message` 和类型化 `details` 的
`error` 对象：

```json
{
  "api_version": "1",
  "request_id": "01JEXAMPLE",
  "ok": false,
  "observed_generation": {"scope": "configuration", "value": 12},
  "error": {"code": "GENERATION_CONFLICT", "message": "generation mismatch", "details": {"expected": 11, "current": 12}}
}
```

`observed_generation` 是响应采集时的观测提供器代次；资源还会暴露其拥有者的 `generation`
或 `revision`。变更前置条件使用明确的 scope/value 对象，不得从整数猜测作用域。

### 资源模型和查询

资源使用稳定的不透明 ID。列表端点支持有界的 `page_size`（默认 100，最大 1000）、不透明
`page_token`、类型化 `filter`，以及带明确升降序的有界 `sort` 字段。未知过滤器、排序字段
和查询参数必须拒绝。列表结果包含 `items`、末尾为 null 的 `next_page_token` 和响应元数据。

通用列表查询语法如下：

```text
page_size   无符号整数，1..=1000；默认 100
page_token  上一响应返回的不透明 token
filter      已注册的类型化过滤对象
sort        已注册字段名
direction   asc | desc；默认 asc
```

未知查询键、过滤字段、排序字段、无效 token 或越界 page size 必须返回
`VALIDATION_FAILED`。资源响应必须使用类型化字段，并包含所有者 generation 或 revision。注册字段包括：

```text
status:         ingress.state、control_plane.state、runtime_snapshot.state、
                data_path_summary、configuration_generation、observation_generation
listeners:      id、kind、platform、bind、allowed_sources、authentication、
                state、generation、status.reason
sessions:       session_id、egress_id、state、ready_path_count、
                admission_generation、close_reason、created_at、last_change_at
connections:    connection_id、session_id、stream_id、listener_id、protocol、
                target_kind、state、bytes_sent、bytes_received、close_reason
subscriptions:  id、source_type、enabled、revision、state、last_refresh_at、
                next_refresh_at、imported_node_count、last_error
authorizations: ingress_id、egress_id、public_key、state、generation、
                active_path_count、active_session_count
system-proxy:   enabled、listener_id、platform_effect、environment_applied、
                operating_system_applied、restoration_state、error
```

脱敏值必须使用 `null` 表示，并附带类型化脱敏原因。

已注册过滤字段必须有界且按资源区分：

```text
nodes:          namespace、state、label.<key>、source.subscription
listeners:      kind、platform、state
sessions:       egress_id、state、admission_generation
connections:    listener_id、protocol、state、session_id
subscriptions:  enabled、state、source_type
authorizations: ingress_id、egress_id、state
paths/streams:  state、session_id、egress_id
```

过滤值只能使用精确字符串、布尔值、数值相等或已注册的前缀匹配；API 不提供任意表达式或无界正则表达式。
排序字段必须来自资源列出的稳定字段，并以不透明资源 ID 作为确定性平局打破规则。

REST 查询资源如下：

```text
GET /api/v1/status
GET /api/v1/nodes
GET /api/v1/nodes/{node_id}
GET /api/v1/sessions
GET /api/v1/sessions/{session_id}
GET /api/v1/connections
GET /api/v1/listeners
GET /api/v1/subscriptions
GET /api/v1/authorizations
GET /api/v1/authorizations/{ingress_id}
GET /api/v1/system-proxy
GET /api/v1/metrics/snapshot
GET /api/v1/metrics/paths
GET /api/v1/metrics/streams
GET /api/v1/events (SSE)
```

节点响应保留所有权命名空间：

```text
node.*       static identity and protocol attributes
source.*     imported subscription attributes
admin.*      local administrator labels/tags
observed.*   runtime-owned health and quality values
quota.*      provider quota metadata
```

客户端不得通过 label/tag 操作写入 `source.*`、`observed.*`、`quota.*` 或硬状态字段。硬
状态必须作为类型化值返回，而不是可覆盖的偏好标记。

### 操作注册表

以下操作名称具有规范性；REST 适配器把资源映射到同样的操作：

```text
status.get
nodes.list             nodes.get
nodes.patch_labels     nodes.patch_tags
sessions.list          sessions.get
connections.list
listeners.list
subscriptions.list     subscriptions.create
subscriptions.delete   subscriptions.enable
subscriptions.disable  subscriptions.refresh
authorizations.list    authorizations.get
authorizations.enroll  authorizations.enable
authorizations.disable authorizations.revoke
authorizations.delete
metrics.snapshot       metrics.paths
metrics.streams         events.subscribe
system_proxy.get        system_proxy.enable
system_proxy.disable
```

节点 patch 正文是完整操作，不是任意 JSON merge patch：

```json
{
  "node_id": "provider-a-node-01",
  "set": {"admin.region": "jp"},
  "remove": ["admin.temporary"]
}
```

订阅创建/刷新正文包含来源引用、验证策略、启用状态和当前 revision。成功刷新原子发布一个
动态配置代次；失败保留最近成功快照并返回类型化失败。删除会排空仅由该来源导入的节点。

对于资源包中声明的 Subscription，通过此 API 启用、禁用、删除或显式重新创建后，只要声明未改变，
该决定必须跨重载和重启保持权威。声明改变时替换声明式 spec；移除声明时只移除该声明式资源。
该决定及其配置代次必须在数据面释放或排空来源可见性之前原子提交。

规范的 `subscriptions.create` 正文如下：

```json
{
  "id": "provider-a",
  "display_name": "Provider A",
  "enabled": true,
  "source": {
    "type": "clash",
    "url": "https://example.invalid/subscription",
    "credentials_ref": "provider-a-token"
  },
  "refresh": {
    "interval_seconds": 3600,
    "timeout_seconds": 30,
    "max_attempts": 3,
    "backoff_seconds": 5
  },
  "cache": {
    "path": "provider-a.snapshot",
    "max_age_seconds": 86400
  }
}
```

`source.type` 必须是规范[订阅类型](../transit-proxies/spec.zh-CN.md#订阅文档类型)或已定义输入别名；
`source.url` 必须是不能包含内嵌凭据的
HTTP(S) URL；`credentials_ref` 必须是不透明引用，不能是机密值。刷新和缓存字段使用配置
schema 中相同的边界；`cache` 可以为 null。列表读模型返回来源类型和凭据引用，但不解析或
返回所引用的机密值。由于 URL 路径、查询参数和片段可能包含凭据，`source.url` 返回为
`null`，`source.url_redaction_reason` 设置为 `sensitive_source`；`source.origin` 只包含
scheme、主机和端口。完整 URL 私下保留供刷新操作使用。

系统代理开关是控制面运行时 mutation，不是 YAML 资源。`system_proxy.enable` 必须包含 `listener_id`，
且该 ID 必须引用 HTTP、SOCKS 或 Mixed Listener。Windows 将其应用到环境变量和操作系统代理配置；
`system_proxy.disable` 恢复之前的值。Linux 和 FreeBSD 对启用和关闭都返回 `UNSUPPORTED_OPERATION`，并继续通过
`nodes` 和 status 展示普通 Listener。

```text
GET  /api/v1/system-proxy
POST /api/v1/system-proxy/enable
     {"listener_id":"local-http"}
POST /api/v1/system-proxy/disable
```

响应和 `system_proxy.changed` 事件包含 `enabled`、当前 `listener_id`（如有）、平台效果以及恢复/错误状态。
在 Linux 和 FreeBSD 上，GET 返回 `enabled: false` 和 `platform_effect: unsupported`。

变更成功响应使用以下结构：

```json
{
  "api_version": "1",
  "request_id": "01JEXAMPLE",
  "ok": true,
  "observed_generation": {"scope": "observation", "value": 42},
  "result": {
    "applied_generation": {"scope": "configuration", "value": 13},
    "resource": {"id": "local-http", "state": "active"},
    "cleanup": {"paths": 0, "sessions": 0, "streams": 0, "target_connections": 0}
  }
}
```

授权和 system-proxy 变更必须包含 `cleanup`，其中为非负计数；没有影响时也必须返回零值。

授权操作使用 Egress 所有的存储：

```text
POST   /api/v1/authorizations
POST   /api/v1/authorizations/{ingress_id}/enable
POST   /api/v1/authorizations/{ingress_id}/disable
POST   /api/v1/authorizations/{ingress_id}/revoke
DELETE /api/v1/authorizations/{ingress_id}
```

这些 REST 路由只在 Web Gateway 连接到 Egress 授权 dispatcher 时挂载。Ingress Web Gateway
会有意省略 `/api/v1/authorizations*`；授权是 Egress 本地操作，不得伪装成 Ingress 能力。

注册正文包含 `ingress_id`、使用无填充小写 base64url 编码的 32 字节公钥、规范
`egress_id`、可选管理员 label/limit 和 `expected_generation`。Enable 允许新 Path。
Disable 和 revoke 都会立即拒绝新握手，并终止匹配的存活 Path、Session、Stream、UDP
Association 及 Egress 目标连接。Revoke 对该记录身份是终态；delete 只有在存量资源清理完成
后才移除记录。每次授权变更都返回已应用代次、有效状态和清理摘要。

### 代次、幂等性和错误

可变代次有三个作用域：`configuration` 表示静态/动态策略快照，`observation` 表示运行时
快照，`authorization` 表示 Egress 授权存储。变更必须携带所属作用域的
`expected_generation`，或显式授权的 `force` capability。冲突不得发布部分变更。

所有变更按 `(actor.id, request_id)` 幂等。重放相同请求返回原响应；相同 request ID 携带不同
规范正文时返回 `IDEMPOTENCY_CONFLICT`。幂等记录保留到所属代次被替换且至少 24 小时，以较长
者为准。

稳定错误码如下：

```text
MALFORMED_REQUEST       invalid envelope or JSON
AUTHENTICATION_REQUIRED missing or invalid actor authentication
CAPABILITY_DENIED       actor lacks the required capability
VALIDATION_FAILED       typed field or policy validation failed
NOT_FOUND               resource does not exist
GENERATION_CONFLICT     expected generation is stale
IDEMPOTENCY_CONFLICT    request ID was reused with a different body
RESOURCE_LIMIT          a bounded service resource was exhausted
PERSISTENCE_UNAVAILABLE durable store or audit sink is unavailable
UNSUPPORTED_OPERATION   operation or API version is not supported
```

REST 按情况映射为 `400`、`401/403`、`404`、`409`、`429` 和 `500/503`；本地调用方收到相同
类型码。错误消息仅用于诊断，绝不能包含机密、文件系统路径、对端任意文本或完整请求正文。

### 身份验证和审计

本地 socket/pipe 使用操作系统所有权和 ACL 作为主要边界。服务为每个请求分配 actor 和
capability。标准 capability 为 `status:read`、`metrics:read`、`nodes:read`、`nodes:write`、
`listeners:read`、`subscriptions:write`、`authorization:write` 和 `system_proxy:write`。
显式授予的 `force` capability 可以在调用方无法提供期望代次时满足 mutation 的代次前置条件；
默认 Web actor 不会获得它。

每次变更和身份验证失败都发出包含以下字段的审计事件：

```text
event_id, timestamp, actor_id, source, operation, request_id,
target_resource, expected_generation, applied_generation, result, reason
```

审计记录包含标识符和结果元数据，不包含机密或完整请求正文。授权变更无法完成持久化审计
写入时必须失败关闭；非敏感元数据操作报告降级状态。

### 资源限制

本地服务和 Web Gateway 必须限制每个 actor 及全局并发请求数、封装/请求/响应大小、刷新频率
和工作器数量、SSE 连接数和重放积压、分页大小、label/tag 基数以及键和值长度。超限返回
`RESOURCE_LIMIT`/HTTP `429` 并附带重试提示，且不得发布任何变更。

### REST 和 SSE 合同

REST 仅对控制面载荷使用 JSON。状态映射如下：

```text
200/201  successful query or mutation
400      malformed request or validation failure
401/403  authentication or capability failure
404      unknown resource
409      generation or idempotency conflict
429      rate/resource limit
500/503  unavailable persistence, audit, or service dependency
```

以下事件注册表与可观测性规范共享：

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

每个事件包含 `id`、`type`、`generation`、`emitted_at`、`resource_type`、`resource_id` 和
类型化 `payload`。`generation` 使用与响应元数据相同的 `{scope,value}` 形式；资源载荷可以
另外携带自身的 `revision`。事件在每个 Ingress 进程内有序。`Last-Event-ID` 要么从有界缓冲区重放，
要么先发送完整快照事件再发送新的增量。查询和事件载荷使用相同的 actor 授权和脱敏策略。
SSE 连接使用独立的有界 client 预算。producer MUST 施加背压，不得为每个 client 建立无界事件
队列，并 MUST 定期发送 comment heartbeat，使失效 client 释放其预算。

### 明确边界

控制平面不替代数据 Path 的 `STATUS_REPORT`。该消息用于 Path/Session 准入和远端健康；本地
状态和指标是控制服务拥有的结构化视图。客户端绝不直接编辑数据库、配置文件或订阅缓存。

本文档中的操作注册表是权威管理操作集合。协议规范只定义传输边界和封装，不定义第二套更小的操作集合。
