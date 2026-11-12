# PathChord 协议设计

[English](protocol.md) | **简体中文**

## 1. 密码学

通过成熟的实现使用 `Noise_IK_25519_ChaChaPoly_SHA256`。

- Ingress 和 Egress 各自拥有一对静态 Curve25519 密钥。
- Egress 公钥是 Ingress 的静态配置。
- Egress 存储已授权的 Ingress 公钥列表；注册操作会动态更改此列表。
- 每条 Path 都执行自己的 Noise 握手，并获得独立的传输密钥。
- 不要将 WireGuard 私钥复用于 PathChord。
- 不需要 X.509 CA、PGP、TOFU 或自动的首次使用信任。

## 2. 协议分层

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

## 3. 身份与附加

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

## 4. 控制消息

协议至少需要以下消息：

```text
VERSION_NEGOTIATE
SESSION_ATTACH
SESSION_ATTACH_OK
EGRESS_STATUS
PATH_PROBE
PATH_PROBE_ACK
PATH_DRAIN
PATH_CLOSE
STREAM_OPEN
STREAM_OPEN_ACK
STREAM_FIN
STREAM_RST
STREAM_DATA
STREAM_ACK
STREAM_WINDOW
SESSION_CLOSE
ERROR
```

控制流量拥有预留容量。一个 Session 至少需要一条活跃 Path；最后一条 Path 丢失时，Session 终止。状态报告、心跳和 Session 控制消息使用当前可用的 Path，并通过 Session 控制序列号抑制重复。当执行顺序很重要时，控制消息可以选择携带依赖序列号。任何可用 Path 都可以承载任何控制或数据交换。

默认情况下，控制消息会在当前多条可用 Path 上复制。接收方对每个 `control_seqno` 最多应用一次，因此复制是安全的。`CONTROL_ACK` 报告已应用的最高连续序列号以及可选的选择性范围。发送方保留未确认的控制消息，并持续重传，直至消息得到确认或 Session 关闭。

## 5. TCP Stream

一个 Stream 表示恰好位于一个 Ingress 到 Egress Session 中的一条目标 TCP 连接。数据使用 Stream 偏移量成帧，并可拆分到多条双向 Path 上。帧可能乱序到达；接收方按偏移量重排帧，然后将连续字节写入目标连接。Stream 可以在 Path 之间迁移，而不改变其身份或目标连接。

必需的语义：

- 有序字节交付；
- 每个方向均支持半关闭；
- 传播目标 FIN/RST；
- 每 Stream 和 Session 流量控制；
- ACK 范围和重复抑制；
- 对未确认数据进行跨 Path 重传；重传可以使用任何当前符合要求的 Path。重传复制由每个流量类别的策略控制，并可由 Egress 默认策略启用或禁用；
- 有界重排缓冲区；
- 使用背压，而不是静默丢弃 TCP 字节。

连接请求携带唯一的 RequestID。在另一条 Path 上重试请求时，Egress 必须保证幂等，以免不确定的响应创建第二条目标连接。`STREAM_OPEN` 在可用时携带原始主机名，也可以携带已解析的候选地址；Egress 应用其配置的 DNS 策略。如果 Session 已消失且结果不确定，则使本地连接失败，并让应用程序重试。

## 6. UDP Session

一个 UDP Session 绑定到一个 Egress 和一个 Egress 端套接字上下文。TCP 和 UDP 都独立于 Path 身份。Path 迁移不会重新创建或重新绑定 Egress 端套接字，因此目标所见的地址和端口保持不变。

UDP 保留数据报边界。普通应用程序数据报不会由聚合层重传，并可能在过期或超出预算时被丢弃。控制消息仍然可靠。如果 Path 由可靠的字节流传输承载，则接受其自身的队头阻塞行为作为实现限制。

## 7. Path 调度

Ingress 负责 Path 的创建和准入。Path 状态对 Stream 和 UDP Session 透明，因此添加或移除 Path 不需要同步覆盖层 Stream 或套接字状态。每条 Path 拥有自己的拥塞控制和流量控制窗口，并向 Session 调度器报告可用容量、质量和调度状态。Ingress 调度上行数据；Egress 在任意现有且符合要求的 Path 上调度下行数据。

每 Path 调度使用有效容量加权：配置的 Proxy 到 Egress 关系权重建立基线，随后每条 Path 报告的有效容量、拥塞窗口、RTT、抖动和丢包率会调整其当前份额。通过一个 Transit Proxy 的多条 Path 共享关系权重，而各自观测到的容量决定如何分配该关系的份额。

重传复制受两个预算限制：Session 范围的复制预算和可选的每流量类别预算。流量类别预算可以进一步限制复制，但绝不能超过 Session 范围预算的剩余额度。控制消息使用默认的控制复制策略，并计入 Session 预算。

## 8. 版本控制

创建 Session 时协商协议版本和能力。如果必需能力不匹配，则从有效规则集中排除该 Egress。可选能力取交集。一个 Session 中的所有 Path 使用相同的 Session 语义。

## 9. 帧格式与编号

每条加密 Path 记录包含一个 Path 帧。Noise 提供机密性和完整性；帧头作为关联数据进行认证，除非所选传输成帧方式要求，否则不单独加密。

通用帧头包含：

```text
version        protocol version
type           frame type
flags          frame-specific flags
session_id     logical Session identifier
path_id        sending Path identifier
frame_seq      monotonically increasing sequence on this Path
payload_len    payload length
```

`session_id` 标识 Ingress 到 Egress 的逻辑通道。`path_id` 仅标识物理 Path，对 Stream 没有意义。`frame_seq` 用于 Path 级重复检测、诊断和丢失统计；它不是 Stream 字节偏移量。SessionID 和 PathID 是 128 位随机值；RequestID 是 128 位随机值；StreamID 是本地分配的 62 位值，在一个 Session 内绝不复用。

TCP 和其他可靠字节流使用单独的数据头：

```text
stream_id      Stream identifier within the Session
direction      Ingress-to-Egress or Egress-to-Ingress
offset         first byte offset in this frame
data_len       number of bytes represented by the frame
stream_flags   FIN, RST, or half-close flags
```

ACK 帧为一个 `(stream_id, direction)` 对携带一个或多个闭区间偏移范围。接收方可以乱序确认范围。重复范围无害，也可以在多条 Path 上重复发送。

重传不会分配新的 Stream 偏移量。重传帧携带相同的 Stream 范围，并可使用不同的 `path_id`；复制的副本按 Stream 范围去重。

Session 控制帧使用 Session 范围的 `control_seqno`。控制帧可以包含可选的 `depends_on` 序列号。接收方丢弃已经应用的序列号，并延迟处理其依赖尚未应用的帧。控制帧应尽可能保持幂等。

Path 管理帧使用 Path 本地管理序列号，并且仅对承载它们的 Path 有效。只要还有另一条 Path 可用，Path 管理失败就不能使 Stream 状态失效。

流量控制帧分别报告 Stream、Session 和 Path 作用域的限制。Path 级限制由 Path 拥塞控制器生成；Session 调度将这些限制视为当前可准入容量，不直接修改它们。

## 10. 控制消息序列

Noise 握手后，一条 Path 执行以下交换：

1. `PATH_HELLO`：协议版本、能力、Path 身份和传输元数据。
2. `SESSION_ATTACH`：Ingress 身份、Session 身份、选定的 Egress 身份和当前控制序列。
3. `SESSION_ATTACH_OK` 或 `SESSION_ATTACH_REJECT`。
4. `PATH_READY`：Path 级限制、观测到的地址族支持和初始调度器报告。

只有处于 `PATH_READY` 状态的 Path 才能承载业务流量。加入现有 Session 的新 Path 不会重放 Stream 状态。它接收当前 Session 策略快照，并可以立即承载新调度的帧。

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
CONTROL_ACK      applied control sequence and selective ranges
```

`PATH_DRAIN` 是建议性的，可能被紧急故障中断。`PATH_CLOSE` 对该 Path 而言是最终状态。`SESSION_CLOSE` 对该 Session 而言是最终状态；最后一条 Path 消失或任一端点重启后，必须建立新 Session。

## 11. TCP Stream 消息

```text
STREAM_OPEN      stream_id, target endpoint, transport options
STREAM_OPEN_OK   stream_id, target result metadata
STREAM_OPEN_ERR  stream_id, normalized error code
STREAM_DATA      stream_id, offset, bytes, stream flags
STREAM_ACK       stream_id, direction, ACK ranges
STREAM_WINDOW    stream/session receive limits
STREAM_FIN       half-close one direction
STREAM_RST       abort the Stream with error code
```

`STREAM_OPEN` 包含唯一的 RequestID。使用相同 RequestID 的重试在 Egress 处是幂等的。`STREAM_DATA` 可以拆分到任意数量的 Path 上，并可对不重叠的偏移范围并发发送。`STREAM_FIN` 排在其方向上的所有先前字节之后；`STREAM_RST` 丢弃待处理数据并关闭目标端连接。

## 12. UDP 消息

```text
UDP_OPEN         association identifier, target endpoint, options
UDP_OPEN_OK       association metadata
UDP_OPEN_ERR      normalized error code
UDP_DATAGRAM      association identifier, datagram sequence, payload
UDP_CLOSE         close association
```

UDP 数据报保留边界并独立于 Path 身份。数据报可以使用任何可用 Path，且 Path 迁移不会重新创建或重新绑定 Egress 端套接字。数据报序列号用于诊断和可选的重复抑制；它们并不表示可靠重传。

## 13. 错误模型

错误被分为四个稳定类别：

```text
LOCAL_POLICY       rejected by Ingress rules or listener policy
PATH_FAILURE       this Path cannot carry traffic
EGRESS_FAILURE     the Egress or Session is unavailable
TARGET_FAILURE     the Egress-to-target operation failed
```

目标 FIN/RST 和目标连接错误会作为目标结果传播。只要还有另一条符合要求的 Path 可用，Path 故障就不会暴露为目标重置。Egress 或 Session 故障会关闭本地连接，以便普通应用程序重试。

## 14. 线格式编码默认值

协议使用紧凑的二进制编码，规则如下：

- 整数使用 QUIC 风格的无符号可变长度编码；
- 需要定宽整数时，使用网络字节序；
- 长度计算字节数，而不是编码元素数；
- 字符串使用 UTF-8 并带长度前缀；
- 端点地址使用显式的地址族判别字段；
- 当未知可选字段和标志的长度可被安全确定时，忽略它们；
- 未知的强制帧类型或格式错误的长度会终止 Path；
- 分配前检查所有长度字段；
- 实现必须同时执行每帧和 Session 聚合限制；
- 每个帧都有明确边界，不能消耗属于下一帧的字节。

用于签名、哈希、RequestID 派生或控制消息幂等性的字段必须使用规范编码。在这些上下文中，重复的映射键和非规范整数编码会被拒绝。

建议的初始限制为：

```text
maximum frame payload       64 KiB
maximum control payload      4 KiB
maximum target name          255 bytes
maximum Stream reordering   configurable, default 4 MiB
maximum Session buffering   configurable, default 32 MiB
```

这些是协议安全默认值，不是性能调优常量。协商值可以低于这些值，但不能超过实现的硬限制。

## 15. 协议不变量

以下不变量具有规范性：

1. 一个 Session 恰好有一个 Ingress 和一个 Egress。
2. 一个活跃 Session 始终至少有一条 `PATH_READY` Path。
3. 一个 Stream 在其整个生命周期内只属于一个 Session。
4. 一个 Stream 偏移量绝不会用于不同字节。
5. Path 故障不能改变目标套接字的身份。
6. 目标重置或 FIN 必须传播，不能改写为 Path 错误。
7. 重复的控制消息不能执行两次其副作用。
8. 重复的数据范围不能向目标交付两次。
9. Session 关闭后禁止创建新 Stream。
10. 端点重启会使所有先前的 Session 和 Path 失效。

## 16. Path 传输抽象

PathChord 线路格式面向字节，但不要求 Path 可靠。完整编码帧是最小交付单元：Path 可以丢失、复制或重排完整帧，但绝不能向协议核心暴露部分帧或载荷被修改的帧。Path 层使用 `frame_seq` 和帧边界检测这些情况；Session 级可靠性负责恢复控制消息和可靠 Stream 数据。

每个 Path 适配器读写字节流，但只向协议核心呈现完整的 PathChord 帧。TCP 等可靠字节流上游可以在内部保持顺序。不可靠或面向数据报的上游可能交付完整帧、丢失帧、复制帧或重排帧，但不能静默修改帧载荷。适配器或记录解码器执行保持完整帧所需的分段和重组；不完整或损坏的帧会在交付前被丢弃。

这样可将 TCP、TLS、WebSocket、VLESS、VMess、XTLS 和未来适配器统一在一个成帧模型中，同时允许直接使用不可靠传输。数据报语义只存在于成帧层之上的 `UDP_DATAGRAM` 消息中。

## 17. 注册与授权

注册是分别在 Ingress 和 Egress 上通过受信任的本地或带外通道执行的管理操作。PathChord 不使用 TOFU、自动信任发现或在线第三方 CA。

注册记录包含：

```text
IngressID
Ingress static public key
EgressID
Egress static public key
authorization state: enabled | disabled | revoked
optional administrator labels and limits
record generation
```

Ingress 在其静态 Egress 拓扑中存储预期的 Egress 公钥。Egress 在其本地授权数据库或配置中存储已授权的 Ingress 公钥列表。在 Path 可以进入 `PATH_READY` 状态之前，双方必须各自独立完成配置。

Noise 模式为 `Noise_IK_25519_ChaChaPoly_SHA256`。每条 Path 执行全新握手并获得独立的传输密钥。握手验证静态密钥，并将生成的 Path 绑定到配置的 IngressID 和 EgressID。仅成功完成 Noise 握手并不足够：Egress 还必须在已启用的授权列表中找到 Ingress 静态公钥。

授权变更基于代次：

- 启用 Ingress 密钥允许创建新 Path 和 Session；
- 禁用或撤销密钥会立即阻止创建新 Path；
- 撤销会关闭所有相关的 Path、Session、Stream 和 Egress 到目标连接；
- 配置写入失败后，不会静默升级现有授权状态；
- 静态密钥发生更改时，受影响的端点必须重启；
- 如果仅 Egress 端列表发生变化，更新 Egress 授权列表无需重启 Ingress。

注册控制 API 位于数据 Path 协议之外。它可以修改 Egress 授权数据库或配置文件，但必须使用原子代次更新，并在验证或持久化失败时保留先前的有效记录。

## 18. 本地管理 API

管理 API 仅限本地使用：

```text
Linux   Unix domain socket
Windows named pipe
```

`pathchord` CLI 是受支持的管理客户端。API 通过操作系统对套接字或管道的所有权和权限模型来授权调用方。它不通过 Transit Proxy 或 Egress 数据 Path 暴露。

管理消息使用带长度前缀的 UTF-8 JSON 封装结构。该封装包含 API 版本、操作名称、请求 ID，以及具有类型的请求或响应正文。JSON 仅用于本地管理 API；数据 Path 继续使用专用二进制帧编解码器。

运行中的 Egress 进程同时拥有管理 API 和授权存储。CLI 从不直接编辑数据库或配置文件；它向 Egress 提交操作，由 Egress 完成整个更新。

注册操作是事务性的：

1. CLI 提交注册、禁用、撤销或删除请求。
2. Egress 验证标识符、密钥编码、重复身份和策略约束。
3. Egress 将新的授权代次原子写入其数据库或配置存储。
4. Egress 无需重启即可替换其内存中授权快照。
5. Egress 将撤销或禁用的影响应用到活跃 Path 和 Session。
6. API 返回已应用的代次和有效状态。

如果持久化成功但内存更新失败，Egress 必须尽可能回滚持久化的代次；否则，它将代次报告为 `pending_apply`，拒绝后续更改，并通过状态暴露不匹配。如果验证或持久化失败，则不发布任何代次变更。

撤销或禁用 Ingress 的授权变更会立即应用于新握手，随后根据撤销规则终止所有匹配的活跃 Path 和 Session。
