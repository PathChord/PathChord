# Ingress 控制平面规范

[English](ingress-control-plane.md) | **简体中文**

本文档定义用于操作 Ingress 的本地控制平面，以及供前端使用的可选 Web 网关。
它独立于 PathChord 数据 Path，涵盖节点标签/标记编辑、订阅生命周期操作、
手动刷新，以及结构化的节点/连接查询。

控制平面是类型化内部命令/查询服务之上的适配器。CLI、本地 Web 网关和自动化客户端
使用同一服务；它们不得（MUST NOT）直接编辑配置文件、缓存或数据库。

该服务通过共享的类型化接口提供有界命令执行、原子快照、持久化、订阅工作器和授权。

## 架构

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

特权本地适配器为：

```text
Linux    Unix domain socket
Windows  named pipe
```

套接字或管道在操作系统中的所有者/ACL 是第一道授权边界。本地协议使用带长度前缀的
UTF-8 JSON 信封，其中包含 API 版本、操作名称、请求 ID 和类型化正文。

Web 网关是可选的，并且必须（MUST）与数据 Path 之间具有独立的进程/任务边界。
它可以（MAY）默认绑定到回环地址。如果绑定到回环地址以外的地址，则必须（MUST）
要求显式配置、TLS 或等效的受保护通道、强身份验证、来源允许列表，以及管理员可见的
对外开放审计记录。

Web 网关调用与 CLI 相同的类型化服务。它不得（MUST NOT）将 Unix 套接字或命名管道
直接暴露给浏览器，也不得（MUST NOT）通过 Transit Proxy 或 Egress 数据 Path 访问。

本地 Unix 套接字/命名管道适配器是必需的。可选 Web 网关必须（MUST）保留与本地
命令/查询服务相同的脱敏、审计和代次语义。

## API 适配器选择

选定的内置 Web 适配器为 REST 加服务器发送事件（Server-Sent Events，SSE）。

GraphQL 适配器可以（MAY）将同一类型化命令/查询服务映射为查询、变更和订阅。
它必须（MUST）保留此处定义的资源所有权、授权、脱敏、审计、幂等性、代次和资源限制
契约。GraphQL 错误必须（MUST）暴露对应的类型化失败；订阅必须（MUST）保留事件顺序，
并在无法重放时支持快照恢复。内部服务和代次语义必须（MUST）独立于外部适配器。

## 资源模型

所有响应都包含 `api_version`、`request_id` 和 `observed_generation`。
资源使用稳定的不透明 ID，并在更新可能发生竞争时暴露 `generation` 或 `revision`。

REST 查询资源如下：

```text
GET  /api/v1/status
GET  /api/v1/nodes
GET  /api/v1/nodes/{node_id}
GET  /api/v1/sessions
GET  /api/v1/sessions/{session_id}
GET  /api/v1/connections
GET  /api/v1/subscriptions
GET  /api/v1/metrics/snapshot
GET  /api/v1/events              (SSE)
```

节点响应区分命名空间及所有权：

```text
node.*       static identity and protocol attributes
source.*     imported subscription attributes
admin.*      local administrator labels/tags
observed.*   runtime-owned health and quality values
quota.*      provider quota metadata
```

API 必须（MUST）保留导入数据、管理员所有的数据与运行时所有的数据之间的区别。
客户端不能通过标签变更端点写入 `observed.*` 或 `quota.*`。已撤销、已禁用或已断开连接
等硬性状态以类型化状态返回，而非可覆盖的偏好标记。

## 命令与变更

变更是提交给类型化服务的命令。每个命令携带客户端 `request_id`、操作者身份和可选的
预期代次。

节点元数据：

```text
PATCH /api/v1/nodes/{node_id}/labels
PATCH /api/v1/nodes/{node_id}/tags
```

正文包含完整操作，而非任意 JSON 合并：

```json
{
  "expected_generation": 12,
  "set": {"admin.region": "jp"},
  "remove": ["admin.temporary"]
}
```

设置导入命名空间或运行时命名空间的操作会被拒绝。成功的变更以原子方式发布新的快照
代次，并返回已更改的字段。

订阅生命周期：

```text
POST   /api/v1/subscriptions
DELETE /api/v1/subscriptions/{subscription_id}
POST   /api/v1/subscriptions/{subscription_id}/refresh
```

`POST /subscriptions` 根据请求创建禁用或启用的订阅，验证其来源和策略，并发布一个代次。
删除操作会将订阅从后续刷新中移除，并使其导入的节点进入文档规定的排空行为。
刷新是显式操作，也可以（MAY）由工作器调度；刷新失败时保留上一次成功的快照。

所有变更都按 `(actor_id, request_id)` 保证幂等。重放相同请求会返回原始结果。
使用相同请求 ID 但携带不同正文会被拒绝。更改授权或硬性运行时状态的变更必须（MUST）
返回结果状态，以及受影响 Session/Path 的清理摘要。

## 代次与并发

每个可变快照都有单调递增的代次。更改快照的命令必须（MUST）包含以下任一项：

- `expected_generation`，其值必须等于当前已发布的代次；或
- 仅授予已授权管理员的显式 `force` 能力。

预期代次不匹配时，REST 返回 HTTP `409 Conflict`，本地 JSON 协议返回类型化
`GENERATION_CONFLICT` 错误。响应包含当前代次、请求代次和新的资源摘要。
发生冲突、验证失败或持久化失败时，不发布任何部分变更。

静态 Egress 拓扑和本地密钥材料仍要求重启才能生效。动态 Transit 数据、管理员标签/标记
和编译后的策略快照以原子方式发布。除硬性撤销或 Egress 故障外，现有 Session 保留其
准入代次。

## 身份验证与审计

本地套接字/管道使用操作系统所有权和 ACL 作为主要授权边界。服务仍会为每个请求分配
操作者身份和能力集。建议的能力如下：

```text
status:read
metrics:read
nodes:read
nodes:write
subscriptions:write
authorization:write
```

Web 网关必须（MUST）要求经过身份验证的管理员会话。浏览器会话必须（MUST）对变更使用
CSRF 防护、来源允许列表、有界请求正文和严格的内容类型。令牌、私钥、订阅 URL、原始
授权记录和未脱敏的目标数据不得（MUST NOT）出现在响应、SSE 事件或审计记录中。

每次变更和身份验证失败都会生成结构化审计事件：

```text
event_id, timestamp, actor_id, source, operation, request_id,
target_resource, expected_generation, applied_generation, result, reason
```

审计记录包含标识符和结果元数据，不包含机密或完整请求正文。审计写入应当（SHOULD）
在成功的变更响应之前持久化；如果审计接收端不可用，服务对授权变更遵循显式的失败关闭
策略，并对非敏感元数据操作报告降级状态。

## 速率与资源限制

网关和本地服务必须（MUST）限制：

- 每个操作者及全局的并发请求数；
- 请求正文和响应大小；
- 订阅刷新频率和并发刷新工作器数；
- SSE 连接数、事件积压量和每个客户端的重放窗口；
- 节点标签/标记的基数和键/值长度。

速率限制响应使用 HTTP `429` 并附带重试提示。本地调用方收到类型化 `RESOURCE_LIMIT`
错误。超出限制不得（MUST NOT）修改快照或静默丢弃成功的命令。

## REST 与 SSE 约定

REST 仅对控制平面载荷使用 JSON。数据 Path 继续使用专用二进制帧协议。
REST 状态映射如下：

```text
200/201  successful query or mutation
400      malformed request or validation failure
401/403  authentication or capability failure
404      unknown resource
409      generation or idempotency conflict
429      rate/resource limit
500/503  unavailable persistence or service dependency
```

SSE 先发送快照事件，然后发送带有事件 ID 和代次的有序事件。客户端使用
`Last-Event-ID` 重新连接；如果重放窗口不包含该事件，服务器会在增量之前发送新的快照。
事件采用类型化形式（`node.changed`、`subscription.refresh`、`session.changed`、
`connection.changed`、`metrics.snapshot`、`audit.notice`），并针对发出请求的操作者脱敏。

## 显式边界

控制平面不替代数据 Path 的 `STATUS_REPORT`。`STATUS_REPORT` 是用于 Path/Session
准入和远端健康状态的紧凑 Egress 到 Ingress 协议消息。控制平面状态和指标是本地结构化
视图，可以结合运行时观测、策略代次、订阅状态和连接详情。它们不得通过数据 Path 消息
隧道传输，也不得仅从数据 Path 消息推断。
