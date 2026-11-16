# PathChord 协议规范

[English](spec.md) | **简体中文**

## Purpose

定义一个 Ingress 与一个 Egress 之间经过认证的多路径行为，包括 TCP Stream、UDP Association、控制可靠性、调度、授权和故障传播。配套的线协议 profile 负责可互操作的字节表示。

## Requirements

### Requirement: Complete protocol contract

声明符合协议的实现 SHALL 同时满足完整的[详细契约](#detailed-contract)和所引用的 `wire-profile-v1` 契约。这些要求和场景补充详细不变量、消息语义及管理边界。

#### Scenario: Last ready Path is lost

- **WHEN** Session 失去最后一条 `PATH_READY` Path
- **THEN** Session 及其业务资源关闭，后续连接必须使用新 Session，不能恢复旧 Session

### Requirement: Explicit trust and independent Path admission

每条 Path SHALL 在 `PATH_READY` 之前完成全新的 `Noise_IK_25519_ChaChaPoly_SHA256` 握手，使用独立传输密钥、已配置 EgressID 的 prologue 和已启用的授权记录。实现 SHALL 保留显式注册，SHALL NOT 使用 TOFU，也不得将 Transit Proxy 视为经过认证的对等方。

#### Scenario: Authenticated key lacks authorization

- **WHEN** Noise 握手认证的 initiator 密钥没有已启用的 Egress 授权记录
- **THEN** Path 在 `PATH_READY` 之前被拒绝，且不承载业务流量

#### Scenario: Authorization is disabled or revoked

- **WHEN** 已应用的授权代次禁用或撤销某个 Ingress 的授权
- **THEN** 立即拒绝新 Path，并终止匹配的存活 Path、Session、Stream 和目标连接

### Requirement: Ordered and idempotent TCP Streams

TCP Stream SHALL 在符合条件的 Path 发生变化时保持有序字节交付、重复抑制、每方向半关闭、有界流控和目标 FIN/RST 语义。使用同一 RequestID 重试打开操作时 SHALL 最多创建一条 Egress 目标连接；未确认数据在重传时 SHALL 保留原有 Stream 偏移量。

#### Scenario: Open is retried on another Path

- **WHEN** `STREAM_OPEN` 的结果不确定，导致使用相同 RequestID 在另一条合规 Path 上重试
- **THEN** Egress 幂等应用打开操作，不创建第二条目标连接

#### Scenario: TCP ranges arrive out of order

- **WHEN** TCP 范围经不同 Path 乱序或重复到达
- **THEN** 接收方按偏移量顺序仅交付每个字节一次，并在有界缓冲区耗尽时施加背压

### Requirement: UDP socket identity and datagram boundaries

Egress UDP Association SHALL 在 Path 迁移期间保留一个 Egress 端套接字上下文，并保留应用程序数据报边界。聚合层 SHALL NOT 可靠重传普通应用数据报；可靠控制操作保持独立语义。

#### Scenario: UDP traffic moves to another Path

- **WHEN** 已打开的 UDP Association 经另一条符合条件的 Path 发送数据报
- **THEN** 不重新创建或绑定其 Egress 端套接字，目标所见的地址和端口保持不变

### Requirement: Reliable control and flow Path restrictions

Session 控制 SHALL 使用 Session 范围的序列空间、重复抑制、依赖顺序、保留和重传，直到收到确认或 Session transport 关闭。控制和数据 SHALL 使用 Egress Session 的公共 Path 池，不得按 flow 指定 Path 子集；取消 SHALL 保留不透明取消边界。

#### Scenario: Flow loses all eligible Paths

- **WHEN** 一个 flow 的公共 Session 池失去最后一条 ready Path
- **THEN** Session 和所有相关业务资源关闭，不保留另一个 flow 的私有 Path 子集

#### Scenario: One flow is cancelled while the Session remains live

- **WHEN** Session 中其他 flow 仍存活时，本地取消一个打开中或活动 flow
- **THEN** 现有不透明取消编码可以替换或推进该 flow 的控制序列，不暴露目标或业务数据，其他 flow 继续运行

### Requirement: Uniform Egress Session scheduling

所有已准入 Stream 和 UDP Association SHALL 使用其 Session 的公共 Path 池和不可变 Egress TrafficPolicy。调度 SHALL 保留关系权重、方向性有效容量与质量输入，并在有待发送 flow 之间提供有界公平服务。不得使用公开业务类别策略或逐 flow 的 Path/策略覆盖。

#### Scenario: Several rules share one Session

- **WHEN** 不同路由规则选择同一个 Egress Session
- **THEN** 两个方向都在同一合规 Path 池上使用一个策略调度，并遵循 Path 生命周期和每资源流控

#### Scenario: One Path fails

- **WHEN** 一条 Path 失败但公共池仍有另一条 ready Path
- **THEN** TCP 数据可在剩余池上重传，UDP 套接字身份保持不变，不选择另一个 Egress

### Requirement: Replication uses one shared Session allowance

每个发送方 SHALL 为所有 flow 和控制在一个 outbound Session allowance 中记账，并受协商硬上限约束。Egress 执行该上限但不接收策略身份。必要控制和普通可靠重传优先于可选副本；可选副本耗尽不得导致 flow 失败或阻止首份发送。

#### Scenario: Optional replication exhausts its budget

- **WHEN** 一个发送方没有剩余 outbound Session 复制额度
- **THEN** 首份或普通重传仍可发送，跳过可选副本，Stream 不因缺少复制单独失败

#### Scenario: More flows or Paths are admitted

- **WHEN** 另一个 flow 或 Path 加入现有 Session
- **THEN** 它共享现有额度，不提高协商上限，也不重置已用量

### Requirement: Egress hard failure closes the Session

Egress `down`、授权失败或最后一条 ready Path 丢失 SHALL 关闭相关 Session 和业务资源。替代连接必须使用新 SessionID；`degraded` 和 stale status 在没有独立硬故障时保留已有工作。

#### Scenario: Egress reports down

- **WHEN** 新鲜认证的 Egress 报告 `connected=0` 且 `service_state=down`
- **THEN** Ingress 关闭相关 Path、Session、Stream、UDP Association、本地连接和目标连接，并废弃 SessionID

### Requirement: Stale health blocks new admission only

Ingress SHALL 将 heartbeat liveness 与 Egress health freshness 分开处理。Egress health stale 或缺失时，若 Path liveness 仍健康，只拒绝新的业务准入并保留已有工作。

#### Scenario: Heartbeat is fresh but status is stale

- **WHEN** Path 仍交换 heartbeat，但最新 Egress status 超过本地新鲜度限制
- **THEN** Path 保持控制和已有工作的可用性，新的 Stream 和 UDP Association 被拒绝

### Requirement: Validated future ACKs are Session trust failures

Ingress SHALL 在应用 ACK 前按本地 emitted Stream 区间校验。认证的 future ACK SHALL 关闭 Session 的所有 Path，废弃 SessionID，并触发有界新 Session 恢复，而不是只失败一条 Path。

#### Scenario: Future ACK follows a correct local frontier

- **WHEN** 对端认证 ACK 超过本地已发送区间且本地 frontier 记账有效
- **THEN** Session 以协议信任失败关闭，ACK 不释放保留数据，后续 Session 使用新 SessionID

### Requirement: Session trust failures are circuit-broken

协议信任失败后的自动恢复 SHALL 使用有界指数退避，并在失败窗口内重复失败时打开断路器。断路器停止新尝试，但不得自动撤销授权。

#### Scenario: Repeated protocol violations occur

- **WHEN** 同一 Egress 在失败窗口内重复造成 Session 信任失败
- **THEN** Ingress 将其标记为新 Session 不可用，保留诊断，等待冷却或显式恢复

### Requirement: Candidate failover ends at business admission

选定 Egress 在 `STREAM_OPEN` 或 `UDP_OPEN` 准入前失败时，Ingress MAY 在同一捕获代次尝试下一个合规候选。目标连接准入后，Egress 故障 SHALL 关闭业务资源，不得透明重建目标连接。

#### Scenario: Path admission fails before Stream open

- **WHEN** 第一个候选在 `STREAM_OPEN` 前无法建立合规 Path
- **THEN** Ingress 尝试下一个合规候选，或返回类型化准入失败，不进入未配置 Proxy fallback

#### Scenario: Egress fails after target admission

- **WHEN** 已准入 Stream 丢失 Egress Session
- **THEN** Stream 和目标连接关闭，由应用程序重试，代理不静默拨号替代目标

### Requirement: Egress does not interpret Ingress policy

Egress SHALL 只接收 wire 所需的窄资源限制和调度数据，不得接收或求值路由规则、Egress Transit selector、TrafficPolicy identity、业务类别策略或 Ingress demand 元数据。

#### Scenario: Session carries a requested replication cap

- **WHEN** Ingress 使用请求复制上限附加 Session
- **THEN** Egress 将其作为不透明资源限制处理，不推断生成它的 Ingress 规则或策略

## Detailed contract

协议版本 1 的可互操作线字节由[线协议 profile](../wire-profile/spec.zh-CN.md)定义。
本文档负责行为和不变量，不定义第二套编码。

### 摘要

本文档定义 PathChord 协议：在一个 Ingress 与一个 Egress 之间建立经过认证的
多路径逻辑通道，并通过一个或多个 Transit Proxy Path 承载 TCP Stream、UDP
Association、控制消息和健康报告。本文档定义协议行为、生命周期不变量、故障传播、
调度职责和管理边界。规范性的 v1 字节布局及注册表由配套的[线协议 profile](../wire-profile/spec.zh-CN.md)定义。

### 本规范的状态

本文档是 PathChord 协议的最终行为契约。声明符合规范的实现 MUST 同时实现本文档
以及所引用的 `wire-profile-v1` 文档中的要求。

### 约定和要求

本文档中的 **MUST**、**MUST NOT**、**REQUIRED**、**SHALL**、**SHALL NOT**、
**SHOULD**、**SHOULD NOT**、**RECOMMENDED**、**NOT RECOMMENDED**、**MAY** 和
**OPTIONAL** 等英文大写关键词，按照
[RFC 2119](https://www.rfc-editor.org/rfc/rfc2119) 和
[RFC 8174](https://www.rfc-editor.org/rfc/rfc8174) 解释。只有英文大写形式具有规范性效力。

### 术语

* **Ingress**：本地策略和流量入口。
* **Transit Proxy**：用于到达 Egress 的非受控传输。
* **Egress**：经过认证的最终流量出口。
* **Session**：恰好由一个 Ingress 和一个 Egress 共享的逻辑通道。
* **Path**：Session 中一条经过认证的长连接物理链路。
* **Stream**：Session 中一条有序的目标 TCP 字节流。
* **UDP Association**：Session 中一个 Egress 端 UDP 套接字上下文。

### 1. 密码学

实现 MUST 通过成熟的实现使用 `Noise_IK_25519_ChaChaPoly_SHA256`。

- Ingress 和 Egress 各自拥有一对静态 Curve25519 密钥。
- Egress 公钥是 Ingress 的静态配置。
- Egress 存储已授权的 Ingress 公钥列表；注册操作会动态更改此列表。
- 每条 Path 都执行自己的 Noise 握手，并获得独立的传输密钥。
- 实现 MUST NOT 将 WireGuard 私钥复用于 PathChord。
- PathChord MUST NOT 使用 X.509 CA、PGP、TOFU 或自动的首次使用信任。
- 密码学 provider MUST 清零其拥有的全部私钥、DH 和传输密钥缓冲区，包括
  resolver 拥有的状态。无法作出该保证的 provider 不符合已部署 PathChord
  Path 的规范要求。

### 2. 协议分层

```text
Ingress adapter / local socket
        |
Flow and policy layer
        |
Session / Stream layer
        |
Path framing and scheduling
        |
Noise transport per Path
        |
Transit Proxy transport
```

### 3. 身份与附加

概念标识符：

```text
IngressID
EgressID
SessionID
PathID
StreamID
RequestID
```

新 Path 通过 Noise 完成身份认证，协商协议版本和能力，然后发送 Session 附加请求。Egress 将 Path 绑定到已认证的 Ingress 身份和选定的 Egress Session。Path 不能加入由其他身份拥有的 Session。

### 4. 控制消息

规范帧注册表由第 10 至 12 节中的生命周期、TCP Stream 和 UDP 列表定义。Session 和 Path 控制使用：

```text
PATH_HELLO
SESSION_ATTACH
SESSION_ATTACH_OK
SESSION_ATTACH_REJECT
PATH_READY
PATH_DRAIN
PATH_CLOSE
STATUS_REPORT
HEARTBEAT
CONTROL_ACK
SESSION_CONTROL
SESSION_CONTROL_ACK
SESSION_CONTROL_CANCEL
SESSION_CLOSE
```

版本和能力协商属于 `PATH_HELLO`，并遵循[线协议 profile 注册表](../wire-profile/spec.zh-CN.md#帧封装)。`STATUS_REPORT` 是 Egress 状态报告的规范名称，`HEARTBEAT` 用于 Path 存活检测。需要返回结果的操作使用各自的成功和错误帧，例如 `STREAM_OPEN_OK` 和 `STREAM_OPEN_ERR`，而不是通用 `ERROR` 帧。

控制流量拥有预留容量。一个 Session 至少需要一条活跃 Path；最后一条 Path 丢失时，Session 终止。状态报告和心跳使用各自的 Path 本地序列。Session 控制消息使用 Session 范围的控制序列号抑制重复，并 MAY 携带依赖序列号。控制和数据交换使用可用且符合策略的 Path。

当剩余 Session allowance 允许时，Session 控制消息可以在当前多条可用且符合条件的 Path 上复制；必要控制和普通重传优先于可选副本。接收方对每个 `control_seqno` 最多应用一次。`SESSION_CONTROL_ACK` 报告已应用的最高连续序列号以及 OPTIONAL 的选择性范围。发送方保留未确认的 Session 控制消息，并持续重传，直至消息得到确认或 Session transport 关闭。`CONTROL_ACK` 用于确认 Path 本地心跳。

所有存活业务 flow 共享 Egress Session Path 池。`SESSION_CONTROL_CANCEL` 仍是本地取消或超时的通用 flow 清理操作，只使用不透明 flow ID 推进或替换控制序号，不携带目标或业务 payload。它不恢复私有 flow Path 子集，也不将已准入 flow 迁移到另一个 Egress。

### 5. TCP Stream

一个 Stream 表示恰好位于一个 Ingress 到 Egress Session 中的一条目标 TCP 连接。数据使用 Stream 偏移量成帧，并可拆分到多条双向 Path 上。帧可能乱序到达；接收方按偏移量重排帧，然后将连续字节写入目标连接。Stream MAY 在 Path 之间迁移，而不改变其身份或目标连接。

REQUIRED 的语义：

- 有序字节交付；
- 每个方向均支持半关闭；
- 传播目标 FIN/RST；
- 每 Stream 和 Session 流量控制；
- ACK 范围和重复抑制；
- 对未确认数据进行跨 Path 重传；重传 MAY 使用任何当前符合要求的 Path，并且在可选复制耗尽后仍可用；
- 有界重排缓冲区；
- 使用背压，而不是静默丢弃 TCP 字节。

连接请求携带唯一的 RequestID。在另一条 Path 上重试请求时，Egress MUST 保证幂等，以免不确定的响应创建第二条目标连接。`STREAM_OPEN` 在可用时携带原始主机名，也 MAY 携带已解析的候选地址；Egress 应用其配置的 DNS 策略。如果 Session 已消失且结果不确定，则使本地连接失败，并让应用程序重试。

### 6. UDP Session

本节描述通过 PathChord Egress 承载的 UDP。普通 direct 或第三方代理 UDP 不创建 PathChord
Session，遵循[原生 UDP 适配器契约](../transit-proxies/spec.zh-CN.md#udp-路由边界)。Egress UDP Session
需要可用的字节流 Transit Path，不要求第三方节点支持原生 UDP。

一个 UDP Session 绑定到一个 Egress 和一个 Egress 端套接字上下文。TCP 和 UDP 都独立于 Path 身份。Path 迁移不会重新创建或重新绑定 Egress 端套接字，因此目标所见的地址和端口保持不变。

UDP 保留数据报边界。普通应用程序数据报不会由聚合层重传，并可能在过期或超出预算时被丢弃。控制消息仍然可靠。如果 Path 由可靠的字节流传输承载，则接受其自身的队头阻塞行为作为实现限制。

### 7. Path 调度

Ingress 负责 Path 的创建和准入。Path 状态对 Stream 和 UDP Session 透明，因此添加或移除 Path 不需要同步覆盖层 Stream 或套接字状态。每条 Path 拥有自己的拥塞控制和流量控制窗口，并向 Session 调度器报告可用容量、质量和调度状态。Ingress 调度上行数据；Egress 在任意现有且符合要求的 Path 上调度下行数据。

每 Path 调度使用有效容量加权：配置的 Proxy 到 Egress 关系权重建立基线，随后每条 Path 报告的有效容量、拥塞窗口、RTT、抖动和丢包率会调整其当前份额。通过一个 Transit Proxy 的多条 Path 共享关系权重，而各自观测到的容量决定如何分配该关系的份额。

重传复制受协商的 Session 硬上限和每个发送方在所有 flow、Path 之间共享的 outbound allowance 限制。上下行分别受已接受的标量上限约束，不存在同步的双向合并桶。必要控制和普通重传优先，可选业务和控制副本只能使用剩余 allowance。Egress 不接收或解释 TrafficPolicy、TrafficClass、规则或 demand 身份；每 flow 队列仍有界并公平服务，不再提供公开业务类别配置。

### 8. 版本控制

创建 Session 时协商 `wire-profile-v1` 及其注册能力。如果 REQUIRED 能力不匹配，则从有效规则集中排除该 Egress。 OPTIONAL 能力取交集。一个 Session 中的所有 Path 使用相同的 Session 语义。版本、能力 ID 以及拒绝行为由 [wire-profile-v1](../wire-profile/spec.zh-CN.md) 定义。

### 9. 帧格式与编号

每条加密 Path 记录包含一个 Path 帧。Noise 提供机密性和完整性。规范记录封装、帧头、帧注册表和格式错误输入的处理由 [wire-profile-v1](../wire-profile/spec.zh-CN.md#noise-记录封装) 定义；v1 只有一种布局，不允许替代的明文帧头或关联数据形式。

Path 记录使用显式 Noise 传输 nonce，因此整条记录的丢失、重复和乱序不会导致密码状态失步。记录封装携带解密前所需的 nonce。每个方向分配单调递增的出站 nonce，并将每个 nonce 与已认证的 `frame_seq` 绑定。nonce MUST NOT 回绕；耗尽时关闭 Path，并在新 Path 上重新握手。发送端 MUST NOT 在同一方向的 Path 密钥下使用相同 nonce 加密不同明文；重传同一条加密记录 MUST 复用原始密文。认证成功后，每个方向应用有界重放窗口。重复或过旧的序列号在进入 Session/控制处理前被丢弃；认证失败或 nonce 与帧头不匹配时 MUST NOT 推进窗口。重放窗口上限 MUST 与 ACK 和重传保留规则兼容。控制消息或 Stream 范围的新加密副本使用新的 Path 帧序号，同时保留 Session 级控制序列号或 Stream 范围标识。

通用帧头包含 profile 规定的字段：

~~~text
version        protocol version
type           frame type
flags          frame-specific flags
session_id     logical Session identifier
path_id        sending Path identifier
frame_seq      monotonically increasing sequence on this Path
payload_len    payload length
~~~

`session_id` 标识 Ingress 到 Egress 的逻辑通道。`path_id` 仅标识物理 Path，对 Stream 没有意义。`frame_seq` 用于 Path 级重复检测、诊断和丢失统计；它不是 Stream 字节偏移量。SessionID 和 PathID 是 128 位随机值；RequestID 是 128 位随机值；StreamID 是本地分配的 62 位值，在一个 Session 内绝不复用。

TCP 和其他可靠字节流使用单独的数据头：

```text
stream_id      Stream identifier within the Session
offset         first byte offset in this frame
data_len       number of bytes represented by the frame
stream_flags   FIN, RST, or half-close flags
```

方向由发送该 Path 帧的、经过认证的端点推导；v1 载荷不会再次编码方向。
`STREAM_ACK` 确认从对端接收的范围，因此被确认的方向是经过认证的发送端方向的
反方向。对端 MUST NOT 提供冲突的 direction 字段。

ACK 帧携带针对由经过认证的发送端角色推导出的方向的一个或多个闭区间偏移范围。
接收方 MAY 乱序确认范围。重复范围无害，也 MAY 在多条 Path 上重复发送。
发送方在释放保留字节前 MUST 将每个范围与本地已发送区间集合校验。覆盖未发送
间隙或未来偏移的认证 ACK 属于 Session 信任失败：关闭所有 Path 和业务资源，废弃
SessionID，并使用新的 SessionID 恢复。

重传不会分配新的 Stream 偏移量。重传帧携带相同的 Stream 范围，并可使用不同的 `path_id`；复制的副本按 Stream 范围去重。

Session 控制帧使用 Session 范围的 `control_seqno`。控制帧 MAY 包含 OPTIONAL 的 `depends_on` 序列号。接收方丢弃已经应用的序列号，并延迟处理其依赖尚未应用的帧。控制帧应尽可能保持幂等。

Path 管理帧使用 Path 本地管理序列号，并且仅对承载它们的 Path 有效。只要还有另一条 Path 可用，Path 管理失败就不能使 Stream 状态失效。

流量控制帧分别报告 Stream、Session 和 Path 作用域的限制。Path 级限制由 Path 拥塞控制器生成；Session 调度将这些限制视为当前可准入容量，不直接修改它们。

### 10. 控制消息序列

Noise 握手后，一条 Path 执行以下交换：

1. `PATH_HELLO`：协议版本、能力、Path 身份和传输元数据。
2. `SESSION_ATTACH`：Ingress 身份、Session 身份、选定的 Egress 身份、当前控制序列和请求的 Session 复制上限。
3. `SESSION_ATTACH_OK` 或 `SESSION_ATTACH_REJECT`。
4. `PATH_READY`：Path 级限制、观测到的地址族支持和初始调度器报告。

只有处于 `PATH_READY` 状态的 Path 才能承载业务流量。加入现有 Session 的新 Path 不会重放 Stream 状态。它接收当前 Session 策略快照，并 MAY 立即承载新调度的帧。

Path 生命周期消息为：

```text
PATH_HELLO
SESSION_ATTACH
SESSION_ATTACH_OK
SESSION_ATTACH_REJECT
PATH_READY
PATH_DRAIN       stop admitting new data, finish acknowledged work
PATH_CLOSE       close this Path
SESSION_CLOSE    close the Session and all related Streams
STATUS_REPORT    Egress capacity and health report
HEARTBEAT        liveness and control sequence exchange
CONTROL_ACK      applied Path heartbeat sequence and selective ranges
SESSION_CONTROL  Session-scoped control operation and sequence
SESSION_CONTROL_ACK  applied Session control sequence and selective ranges
SESSION_CONTROL_CANCEL  opaque cancellation of a flow's control sequence
```

`PATH_DRAIN` 是建议性的，可能被紧急故障中断。`PATH_CLOSE` 对该 Path 而言是最终状态。`SESSION_CLOSE` 对该 Session 而言是最终状态；最后一条 Path 消失或任一端点重启后，MUST 建立新 Session。载荷布局和排空原因由 [wire-profile-v1](../wire-profile/spec.zh-CN.md#path-和-session-控制) 定义。

### 11. TCP Stream 消息

```text
STREAM_OPEN      stream_id, target endpoint, transport options
STREAM_OPEN_OK   stream_id, target result metadata
STREAM_OPEN_ERR  stream_id, normalized error code
STREAM_DATA      stream_id, offset, bytes, stream flags
STREAM_ACK       stream_id, 针对对端方向的 ACK ranges
STREAM_WINDOW    stream/session receive limits
STREAM_FIN       half-close one direction
STREAM_RST       abort the Stream with error code
```

`STREAM_OPEN` 包含唯一的 RequestID。使用相同 RequestID 的重试在 Egress 处是幂等的。`STREAM_DATA` MAY 拆分到任意数量的 Path 上，并可对不重叠的偏移范围并发发送。`STREAM_FIN` 排在其方向上的所有先前字节之后；`STREAM_RST` 丢弃待处理数据并关闭目标端连接。

### 12. UDP 消息

```text
UDP_OPEN         association identifier, target endpoint, options
UDP_OPEN_OK       association metadata
UDP_OPEN_ERR      normalized error code
UDP_DATAGRAM      association identifier, datagram sequence, payload
UDP_CLOSE         close association
```

UDP 数据报保留边界并独立于 Path 身份。数据报 MAY 使用任何可用 Path，且 Path 迁移不会重新创建或重新绑定 Egress 端套接字。数据报序列号用于诊断和 OPTIONAL 的重复抑制；它们并不表示可靠重传。确切的 UDP 载荷由 [wire-profile-v1](../wire-profile/spec.zh-CN.md#udp-session) 定义。

### 13. 错误模型

错误被分为五个稳定类别：

```text
LOCAL_POLICY       rejected by Ingress rules or listener policy
PATH_FAILURE       this Path cannot carry traffic
EGRESS_FAILURE     the Egress or Session is unavailable
TARGET_FAILURE     the Egress-to-target operation failed
RESOURCE_LIMIT     a bounded Egress or local resource is exhausted
RESOURCE_LIMIT     a bounded Egress or local resource is exhausted
```

目标 FIN/RST 和目标连接错误会作为目标结果传播。只要还有另一条符合要求的 Path 可用，Path 故障就不会暴露为目标重置。Egress 或 Session 故障会关闭本地连接，以便普通应用程序重试。

### 14. 线格式编码默认值

协议使用紧凑的二进制编码，规则如下：

- 整数使用 QUIC 风格的无符号可变长度编码；
- 需要定宽整数时，使用网络字节序；
- 长度计算字节数，而不是编码元素数；
- 字符串使用 UTF-8 并带长度前缀；
- 端点地址使用显式的地址族判别字段；
- v1 不包含未注册的 OPTIONAL 字段或标志；未来扩展 MUST 由 profile 定义带长度的扩展；
- 未知的强制帧类型或格式错误的长度会终止 Path；
- 分配前检查所有长度字段；
- 实现 MUST 同时执行每帧和 Session 聚合限制；
- 每个帧都有明确边界，不能消耗属于下一帧的字节。

用于签名、哈希、RequestID 派生或控制消息幂等性的字段 MUST 使用规范编码。在这些上下文中，重复的映射键和非规范整数编码会被拒绝。

v1 的硬上限、协商限制规则和一致性测试向量由 [wire-profile-v1](../wire-profile/spec.zh-CN.md#profile-限制) 规范定义。对等方 MAY 协商不高于这些上限的值，MUST NOT 协商更高的值；每个解码器都 MUST 在分配内存前执行限制。

### 15. 协议不变量

以下不变量具有规范性：

1. 一个 Session 恰好有一个 Ingress 和一个 Egress。
2. 一个活跃 Session 始终至少有一条 `PATH_READY` Path。
3. 一个 Stream 在其整个生命周期内只属于一个 Session。
4. 一个 Stream 偏移量绝不会用于不同字节。
5. Path 故障不能改变目标套接字的身份。
6. 目标重置或 FIN MUST 传播，不能改写为 Path 错误。
7. 重复的控制消息不能执行两次其副作用。
8. 重复的数据范围不能向目标交付两次。
9. Session 关闭后禁止创建新 Stream。
10. 端点重启会使所有先前的 Session 和 Path 失效。

### 16. Path 传输抽象

PathChord 线路格式面向字节，但不要求 Path 可靠。完整编码帧是最小交付单元：Path MAY 丢失、复制或重排完整帧，但 MUST NOT 向协议核心暴露部分帧或载荷被修改的帧。Path 层使用 `frame_seq` 和帧边界检测这些情况；Session 级可靠性负责恢复控制消息和可靠 Stream 数据。

每个 Path 适配器读写其底层传输，但只向协议核心呈现完整且已认证的记录封装和解码后的 PathChord 帧。TCP 等可靠字节流上游 MAY 在内部保持顺序。不可靠或面向数据报的上游可能交付完整记录、丢失记录、复制记录或重排记录，但不能静默修改记录载荷。适配器或记录解码器执行保持完整记录所需的分段和重组；不完整或损坏的记录会在交付前被丢弃。

这样可将 TCP、TLS、WebSocket、VLESS、VMess、XTLS 和其他传输适配器统一在一个成帧模型中，同时允许直接使用不可靠传输。数据报语义只存在于成帧层之上的 `UDP_DATAGRAM` 消息中。

### 17. 注册与授权

注册是分别在 Ingress 和 Egress 上通过受信任的本地或带外通道执行的管理操作。PathChord 不使用 TOFU、自动信任发现或在线第三方 CA。

注册记录包含：

```text
IngressID
Ingress static public key
EgressID
Egress static public key
authorization state: enabled | disabled | revoked
OPTIONAL administrator labels and limits
record generation
```

Ingress 在其静态 Egress 拓扑中存储预期的 Egress 公钥和规范 EgressID。Egress 在读取 Path 握手前已知自己的规范 EgressID，并在其本地授权数据库或配置中存储已授权的 Ingress 公钥列表。在 Path MAY 进入 `PATH_READY` 状态之前，双方 MUST 各自独立完成配置。

Noise 模式为 `Noise_IK_25519_ChaChaPoly_SHA256`。每条 Path 执行全新握手并获得独立的传输密钥。双方在 responder 读取第一条 IK 消息前，将配置的非空 EgressID 绑定到 [wire-profile-v1](../wire-profile/spec.zh-CN.md#标识符和-prologue-规则) 定义的确切 v1 prologue。profile 缺失、不匹配或无效时，Path 不能通过认证，也不能承载业务流量。

第一条消息之后，Egress 验证 initiator 静态公钥，并从启用的授权记录中解析对应的 IngressID；随后 `SESSION_ATTACH` MUST 携带完全匹配的 IngressID。IngressID 不由 responder 侧的 prologue 猜测或选择。仅成功完成 Noise 握手并不足够：Egress 还 MUST 在已启用的授权列表中找到 Ingress 静态公钥。

授权变更基于代次：

- 启用 Ingress 密钥允许创建新 Path 和 Session；
- 禁用或撤销密钥会立即阻止创建新 Path，并关闭所有相关的 Path、Session、Stream 以及 Egress 到目标的连接；
- 配置写入失败后，不会静默升级现有授权状态；
- 静态密钥发生更改时，受影响的端点 MUST 重启；
- 如果仅 Egress 端列表发生变化，更新 Egress 授权列表无需重启 Ingress。

注册控制 API 位于数据 Path 协议之外。它 MAY 修改 Egress 授权数据库或配置文件，但 MUST 使用原子代次更新，并在验证或持久化失败时保留先前的有效记录。

### 18. Ingress 控制面和管理 API

Ingress 拥有一个类型化 command/query service，用于节点元数据、订阅、运行时快照、连接、metrics 和结构化事件。该 service 与二进制 data Path 分离，也是唯一 MAY 发布可变运行时快照的组件。

权威的本地管理 API 仅限本地使用：

```text
Linux   Unix domain socket
Windows named pipe
FreeBSD Unix domain socket
```

`pathchord` CLI 是受支持的本地管理客户端。API 通过操作系统对套接字或管道的所有权和权限模型来授权调用方。它不通过 Transit Proxy 或 Egress 数据 Path 暴露。

管理消息使用带长度前缀的 UTF-8 JSON 封装结构。该封装包含 API 版本、操作名称、请求 ID，以及具有类型的请求或响应正文。Command 还携带 actor、 OPTIONAL 的期望代次和幂等请求 ID。JSON 仅用于管理适配器；data Path 继续使用专用二进制帧编解码器。

Ingress 控制操作包括管理员节点 tag/label 修改、订阅创建/删除、手动订阅刷新、监听器清单查询以及
`system_proxy.get`、`system_proxy.enable` 和 `system_proxy.disable`。get 是所有平台上的结构化状态查询。
enable 和 disable 只在 Windows 上修改代理设置；Linux 和 FreeBSD 对这两个 mutation MUST 返回
`UNSUPPORTED_OPERATION`，而 get 返回 `enabled: false` 和 `platform_effect: unsupported`。完整的操作、
资源、响应、错误、分页和事件注册表由[Ingress 控制面规范](../ingress-control-plane/spec.zh-CN.md)定义；该文档
具有权威性，本节不得被解释为更小的子集。mutation 原子发布动态快照，使用代次检查处理并发更新；
刷新失败时保留最近一次成功的订阅快照，并产生结构化审计事件。`observed.*` 和运行时拥有的 quota
字段不能通过管理员元数据 command 写入。

Ingress 同时发布节点、Path、Session、Stream、目标连接、订阅和策略代次的结构化观测快照及有界事件流。当前状态和 metrics MUST 查询，不能要求解析日志。`STATUS_REPORT` 仍然是认证 data-Path 健康消息，不是管理 API 或 metrics API。

OPTIONAL 的认证 Web Gateway 为前端提供接入点。它调用同一个类型化 command/query service，默认关闭。选定的内置适配器提供 REST 资源接口和 Server-Sent Events（SSE）；替代适配器 MUST 保留相同的类型化 command/query、授权、脱敏、审计、代次和资源限制契约。Gateway MUST NOT 把本地 socket/pipe 直接暴露给浏览器，也 MUST NOT 通过 Transit Proxy 或数据 Path 访问。非 loopback 监听 MUST 显式配置，并启用强认证、来源控制、限流、脱敏和审计日志。

运行中的 Egress 进程拥有 Egress 授权存储，Ingress 控制服务拥有 Ingress 节点/订阅快照。客户端从不直接编辑数据库、配置文件或订阅缓存；它们向拥有者 service 提交类型化操作。

注册操作是事务性的：

1. CLI 提交注册、禁用、撤销或删除请求。
2. Egress 验证标识符、密钥编码、重复身份和策略约束。
3. Egress 将新的授权代次原子写入其数据库或配置存储。
4. Egress 无需重启即可替换其内存中授权快照。
5. Egress 将撤销或禁用的影响应用到活跃 Path、Session 及相关目标连接。
6. API 返回已应用的代次和有效状态。

如果持久化成功但内存更新失败，Egress MUST 尽可能回滚持久化的代次；否则，它将代次报告为 `pending_apply`，拒绝后续更改，并通过状态暴露不匹配。如果验证或持久化失败，则不发布任何代次变更。

撤销或禁用 Ingress 的授权变更会立即应用于新握手，随后根据撤销规则终止所有匹配的活跃 Path、Session、Stream 和目标连接。

### 安全考虑

Noise IK 独立认证每条 Path，并在 responder 处理握手前绑定已配置的 Egress 身份。
Noise 握手成功本身不足以完成授权；Egress MUST 根据启用的授权记录验证 initiator
密钥。实现 MUST NOT 将 Transit Proxy 视为经过认证的对等方，MUST NOT 使用 TOFU，
也 MUST NOT 通过管理 API 暴露私钥、握手材料、持有者令牌、订阅凭据、密文或应用载荷。

重放窗口、显式 nonce、帧序列绑定、有界分配和带代次检查的授权更新都是安全属性，
不是 OPTIONAL 诊断。实现 SHOULD 在进程终止和传输丢失条件下测试密钥清零及失败清理。

### 注册表和扩展策略

`wire-profile-v1` 拥有帧类型、能力、错误和数值限制注册表。实现 MUST NOT 在本地分配
未注册值。新增值或载荷字段 MUST 使用新的版本化 profile 或 profile 定义的带长度扩展；
扩展 MUST 定义协商方式、边界、未知值处理和安全影响。
