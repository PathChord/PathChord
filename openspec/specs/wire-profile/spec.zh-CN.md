# PathChord wire profile v1

[English](spec.md) | **简体中文**

## Purpose

定义逐字节一致的 `wire-profile-v1` 记录和帧封装、payload 注册表、标识符、能力、限制、错误和确定性一致性测试向量，使独立实现能够互操作。

## Requirements

### Requirement: Complete canonical wire contract

v1 实现 SHALL 满足[详细契约](#detailed-contract)中的全部布局、注册表、限制、失败规则和一致性测试向量要求。未发布的 v1 注册表 SHALL 使用最终 Session budget、status 和 admission 布局，且 SHALL NOT 暴露临时 PathRebind 或 TrafficClass 扩展。

#### Scenario: Provisional frame is presented

- **WHEN** 对端提供属于已移除 `PathRebind`、`PathRebindAck`、`STREAM_OPEN_CLASS` 或 `UDP_OPEN_CLASS` 的帧编码
- **THEN** 接收方将其视为未分配的 v1 输入，并按格式错误规则只关闭承载该帧的 Path

#### Scenario: Deterministic vector round trip

- **WHEN** 实现编码和解码已发布的 v1 一致性测试向量
- **THEN** 两种操作均还原完全相同的规范字节，包括指定的 Noise 兼容向量

### Requirement: Canonical bounded decoding

解码器 SHALL 在分配前执行最短形式 QUIC 风格 varint、完整 payload 消费、已注册 flag 和强制帧类型、协商限制及 profile 硬上限。格式错误帧 SHALL 产生指定的协议错误并关闭 Path。

#### Scenario: Unknown flag or trailing bytes

- **WHEN** 解密后的帧包含未知且非零的 flag，或规范 payload 之后仍有字节
- **THEN** 接收方丢弃该帧、产生诊断事件并关闭 Path

#### Scenario: Negotiated limit exceeds hard cap

- **WHEN** 对端提出超过 profile 硬上限的 `PATH_READY` 限制
- **THEN** 拒绝该限制，不会扩大解码器允许分配的范围

### Requirement: Independent authenticated nonce and replay state

每个方向的 Path transport SHALL 使用显式 nonce 封装，将 `frame_seq` 绑定到该 nonce，并仅在认证后应用 64 条记录的重放窗口。不同明文 SHALL NOT 复用同一方向的密钥/nonce 对；格式错误或未认证的记录 SHALL NOT 推进重放状态。密钥材料 SHALL 按详细契约要求清零。

#### Scenario: Authenticated record is duplicated

- **WHEN** 已认证记录的 nonce 在其方向的重放窗口中重复或过旧
- **THEN** 该记录在 Session 处理前被丢弃，不会再次应用其 payload

#### Scenario: Nonce and frame sequence disagree

- **WHEN** 解密后的 `frame_seq` 与记录 nonce 不一致
- **THEN** 该记录不推进重放窗口，并按格式错误帧规则处理

### Requirement: Profile identity and capability negotiation

对等方 SHALL 使用协议版本 1、已配置 EgressID 的确切 prologue，以及整个 Session 共用的一组协商能力。未知 capability 位 SHALL 被忽略；配置要求的 REQUIRED capability 缺失时 SHALL 使用 `EGRESS_FAILURE` 拒绝附加。

#### Scenario: Required capability is absent

- **WHEN** 对端的 capability 集合缺少配置要求的 REQUIRED capability
- **THEN** 使用 `SESSION_ATTACH_REJECT` 和 `EGRESS_FAILURE` 拒绝附加

#### Scenario: Unsupported version is presented

- **WHEN** 对端提供非 1 的协议版本
- **THEN** 在 `PATH_READY` 之前拒绝 Path

### Requirement: Ordered Session control envelopes

Session 控制 SHALL 使用已注册封装、每发送方序列空间、依赖顺序、确认规则和不透明幂等取消编码。新操作的编码器 SHALL 发送空的 eligible Path 列表；接收方必须在目标准入前拒绝已退休的非空打开限制。复制副本 SHALL 保留控制序号和 payload，同时使用新的 Path 帧序号和 Noise nonce。

#### Scenario: Control operation is replicated

- **WHEN** 一个 `SESSION_CONTROL` 操作的副本经多条符合条件的 Path 到达
- **THEN** 接收方在应用其依赖后仅应用该控制序号一次，并通过 Session 控制序列空间确认

#### Scenario: A new open uses the Session pool

- **WHEN** 发送方在 Session 控制封装中编码 `STREAM_OPEN` 或 `UDP_OPEN`
- **THEN** 写入 `eligible_path_count=0` 且没有 PathID，已准入 flow 在两个方向使用 Session 公共池

#### Scenario: A peer supplies a retired per-flow list

- **WHEN** 有效的 Stream 或 UDP 打开携带非空且规范的 eligible Path 列表
- **THEN** 接收方以对应操作错误和 `LOCAL_POLICY` 拒绝打开，不创建目标连接，并以幂等方式处理拒绝和控制确认，不缩小公共池

### Requirement: Typed Stream and UDP payload semantics

Stream 和 UDP payload SHALL 使用已注册的字段顺序、目标形式、地址族、范围与偏移限制以及错误类别。Stream 方向 SHALL 从已认证端点角色推导；payload SHALL NOT 提供第二个冲突的 direction 字段。UDP payload SHALL 保留数据报边界，聚合层不重传应用数据报。

#### Scenario: Stream acknowledgement direction is inferred

- **WHEN** 对端经已认证 Path 发送 `STREAM_ACK`
- **THEN** 其范围确认从对端收到的字节，所确认方向与经过认证的发送端方向相反

### Requirement: Sequenced and fresh status reports

`STATUS_REPORT` SHALL 包含完整 v1 schema、一致的连接/服务状态、有界 basis-point 比率、序列和新鲜度字段。接收方 SHALL 忽略重复或更旧的报告序号，并 SHALL 禁止使用过期报告准入新流或触发缩容。

#### Scenario: Status sample is stale

- **WHEN** `sample_age_ms` 超过 `expires_after_ms`
- **THEN** Ingress 将报告视为过期，不使用它准入新流或触发缩容

### Requirement: Session replication cap is negotiated during attachment

`SESSION_ATTACH` SHALL 携带 Egress 策略请求的复制上限，`SESSION_ATTACH_OK` 携带接受值，均为 wire 字节速率。禁用复制时请求零；允许时请求策略 bit rate 除以 8 后向下取整且受 profile 限制。接受值不得超过请求值或任一端上限。每个发送方 SHALL 对其 outbound Session 流量执行该值；Session 中每条 Path 都保留该协商。

#### Scenario: Egress accepts a lower cap

- **WHEN** Egress 无法接受请求值，但可以用更低值准入 Session
- **THEN** 返回更低的有效值，双方将其作为 Session 硬上限，同时保持普通可靠性可用

#### Scenario: Replication is disabled with a positive configured budget

- **WHEN** Egress 策略设置 `retransmissionReplication: disabled` 但 `sessionReplicationBudgetBps` 为正
- **THEN** Ingress 请求零，Egress 接受零，双方不发送可选业务或控制副本，但首份数据、必要控制和普通可靠重传仍可用

#### Scenario: A later Path joins the Session

- **WHEN** 在 flow 已消耗复制额度后另一条 Path attach 到 Session
- **THEN** 它使用已捕获的请求和有效上限，不替换策略、不提高上限，也不重置记账

### Requirement: Global status carries explicit capacity and admission state

`STATUS_REPORT` SHALL 区分配置 wire 容量、有效容量、当前聚合 wire 速率、容量状态、服务状态和全局新准入状态。有效容量状态 SHALL 明确为 `unknown`、`provisional`、`measured` 或 `stale`；`admission_allowed` 独立于 `service_state`。

#### Scenario: Capacity has not been measured

- **WHEN** Egress 没有足够新鲜的有效容量测量
- **THEN** 报告 unknown 或 provisional 状态，Ingress 可以把配置硬上限作为临时调度上限

### Requirement: ACK ranges cannot confirm unsent bytes

接收方 SHALL 在释放重传数据前，将每个 `STREAM_ACK` 范围与发送方本地记录的已发送 Stream 区间集合校验。覆盖未发送间隙或未来偏移的范围 SHALL 被视为协议违规。

#### Scenario: Future ACK is authenticated

- **WHEN** 认证 ACK 覆盖本地尚未发送的偏移
- **THEN** 拒绝该 ACK，不得依据它释放任何保留范围

## Detailed contract

本文档是 wire-profile-v1 的可互操作线路合同。该 profile 使用协议版本 1。
提供任何非 1 协议版本的对端 MUST 在 PATH_READY 之前拒绝 Path。

[协议规范](../protocol/spec.zh-CN.md)定义行为模型；本文档定义实现该模型所需的字节、
注册表、限制和失败处理。

### 摘要

本文档定义 PathChord `wire-profile-v1` 的规范表示，包括记录、帧、载荷、标识符、
能力和错误，目标是使独立实现逐字节互操作。

### 本规范的状态

本文档是最终 v1 线协议契约。符合规范的实现 MUST 使用本文档中的注册表和布局，
MUST NOT 替换为实现自定义的封装、字段顺序、数字编码或扩展规则。

### 约定和要求

**MUST**、**MUST NOT**、**REQUIRED**、**SHALL**、**SHALL NOT**、**SHOULD**、
**SHOULD NOT**、**RECOMMENDED**、**NOT RECOMMENDED**、**MAY** 和 **OPTIONAL** 等
英文大写关键词按照 [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119) 和
[RFC 8174](https://www.rfc-editor.org/rfc/rfc8174) 解释，只有大写形式具有规范性效力。

### 注册表所有权

PathChord 协议注册表由 PathChord 规范维护者维护。帧类型编码、能力位、错误编码和
profile 限制只能由新的版本化 profile 分配。v1 实现 MUST 按本文档的未知值规则处理
未分配的编码和位。

### 编码原语

- 无符号整数使用规范的 QUIC 风格 62 位变长整数，MUST 使用最短表示。
- 定宽整数使用网络字节序。
- 长度以字节计数，MUST 在任何分配前检查 profile 限制。
- 字符串是前置 varint 字节长度的 UTF-8 字节。 REQUIRED 的标识符和主机名 MUST NOT 为空。
- v1 payload 没有隐式字段或尾随扩展字节。解码器 MUST 消费完整 payload。
  后续字段 MUST 使用新的 profile，或由该 profile 定义、经协商的带长度扩展。

### Noise 记录封装

每条 Path 记录恰好包含一个加密的 Path 帧。规范记录封装为：

~~~text
nonce             8 bytes, unsigned big-endian transport nonce
ciphertext_len    2 bytes, unsigned big-endian length
ciphertext        exactly ciphertext_len bytes
~~~

密文包含 16 字节 ChaCha20-Poly1305 认证标签。ciphertext_len 取值范围为
16..=65535，因此完整封装最大为 65545 字节。明文是编码后的 Path 帧，最大
为 65519 字节。nonce 不使用隐式计数器；v1 不存在明文帧头或关联数据布局的
替代方案。截断、超限或带尾随字节的封装 MUST 在分配解密缓冲区前拒绝。

Noise 模式为 Noise_IK_25519_ChaChaPoly_SHA256。握手完成后，每个方向拥有
独立的 nonce 序列并从零开始。发送方 MUST NOT 在同一方向密钥和 nonce 下加密
不同明文。同一条已封装记录的重传复用完整原始封装；语义上的重传 MAY 创建
新的帧和 nonce，但 MUST 保留其控制序列或 Stream 范围标识。

Noise provider MUST 在私钥、DH 和传输密钥离开使用状态时清零其缓冲区，
包括 resolver 拥有的状态。记录层 MUST NOT 在不同 Path 之间共享传输密码状态。

认证后，接收方对每个方向使用 64 条记录的重放窗口。重复或过旧的 nonce
MUST 在 Session 处理前丢弃。认证失败、nonce/帧序号不匹配或帧格式错误 MUST NOT
推进重放窗口。nonce 耗尽时关闭 Path，并要求在新 Path 上重新 Noise 握手。

### 帧封装

解密后的帧自定界，精确布局如下：

~~~text
version           varint, exactly 1
frame_type        varint, registered value below
flags             varint, zero in v1
session_id        16 bytes, opaque random identifier
path_id           16 bytes, opaque random identifier
frame_seq         varint, 0..=(2^62 - 1)
payload_len       varint
payload           exactly payload_len bytes
~~~

frame_seq 等于该方向对应记录的出站 nonce。session_id 和 path_id 由 Noise
及帧头认证。未知且非零的 flag、未知强制类型、非规范 varint、超过适用限制
的 payload 或尾随字节都 MUST 关闭 Path。

帧类型注册表如下：

| Code | Frame type | Payload class |
|---:|---|---|
| 1 | PATH_HELLO | control |
| 2 | SESSION_ATTACH | control |
| 3 | SESSION_ATTACH_OK | control |
| 4 | SESSION_ATTACH_REJECT | control |
| 5 | PATH_READY | control |
| 6 | PATH_DRAIN | control |
| 7 | PATH_CLOSE | control |
| 8 | SESSION_CLOSE | control |
| 9 | STATUS_REPORT | control |
| 10 | HEARTBEAT | control |
| 11 | CONTROL_ACK | control |
| 12 | PATH_READY_CAPABILITIES | control |
| 13 | SESSION_CONTROL | control |
| 14 | SESSION_CONTROL_ACK | control |
| 15 | SESSION_CONTROL_CANCEL | control |
| 32 | STREAM_OPEN | control |
| 33 | STREAM_OPEN_OK | control |
| 34 | STREAM_OPEN_ERR | control |
| 35 | STREAM_DATA | bulk |
| 36 | STREAM_ACK | control |
| 37 | STREAM_WINDOW | control |
| 38 | STREAM_FIN | control |
| 39 | STREAM_RST | control |
| 64 | UDP_OPEN | control |
| 65 | UDP_OPEN_OK | control |
| 66 | UDP_OPEN_ERR | control |
| 67 | UDP_DATAGRAM | bulk |
| 68 | UDP_CLOSE | control |

PATH_HELLO 携带的 v1 capability 位集合如下：

| Bit | Capability |
|---:|---|
| 0 | TCP_STREAM |
| 1 | UDP_SESSION |

未知 capability 位 MUST 忽略。若配置要求的 capability 缺失，则使用
EGRESS_FAILURE 拒绝 SESSION_ATTACH；OPTIONAL capability 取双方交集。一个
Session 中所有 Path 使用同一组已协商语义。

### Profile 限制

v1 硬限制和默认协商值如下：

| Name | Value | Applies to |
|---|---:|---|
| max_frame_payload | 64512 bytes | STREAM_DATA 和 UDP_DATAGRAM payload |
| max_control_payload | 4096 bytes | 所有 control payload |
| max_target_name | 255 bytes | 主机名和标识符字符串 |
| max_stream_reordering | 4194304 bytes | 单个 Stream 重排缓冲区 |
| max_session_buffering | 33554432 bytes | 单个 Session 聚合缓冲区 |
| max_endpoint_addresses | 16 | 目标地址候选 |
| max_ack_ranges | 256 | 单个 ACK payload |

对端 MAY 在 PATH_READY 中协商更低的 frame、control 和 Session 缓冲限制，
但 MUST NOT 超过上述值。control 限制 MUST NOT 超过 frame 限制，Stream 重排限制
MUST NOT 超过 Session 缓冲限制。限制 MUST 在分配前执行。限制违规属于协议错误，
关闭 Path；对合法帧的本地资源耗尽由状态机和流量控制规则处理，MUST NOT 静默
丢弃。

### 标识符和 prologue 规则

SessionID、PathID 和 RequestID 是 128 位随机值，以 16 个原始字节编码。
StreamID 是本地分配的 62 位 varint，在一个 Session 内 MUST NOT 复用。
control_seqno 是 Session 作用域内单调递增的 varint，在该 Session 内 MUST NOT
复用。新的 Session 使用新的 SessionID 和新的控制序列空间。

规范 EgressID 语法为：

~~~text
[A-Za-z0-9][A-Za-z0-9._-]{0,127}
~~~

Noise prologue 是 ASCII 字节 PathChord/wire-v1/egress/，后接按配置原样
编码的 EgressID UTF-8 字节。不进行 Unicode 规范化、大小写折叠或尾随 NUL
处理。双方 MUST 使用相同的非空 EgressID 和 profile 字符串。

### Payload 注册表

以下所有字段按列出的顺序编码。bytes(max) 表示 varint 长度后紧跟恰好
该长度的字节，并受 max 限制；id128 表示 16 个原始字节。解码器 MUST 拒绝
缺失字段、无效枚举值、无效地址族、非规范范围和尾随字节。

#### Path 和 Session 控制

PATH_HELLO：

~~~text
version              varint, exactly 1
capabilities         varint bitset
path_id              id128; MUST equal the frame header PathID
transport_metadata   bytes(max_control_payload)
~~~

SESSION_ATTACH：

~~~text
ingress_id           bytes(max_target_name), non-empty UTF-8
session_id           id128; MUST equal the frame header SessionID
egress_id            bytes(max_target_name), non-empty UTF-8
control_seqno        varint
replication_budget_bytes_per_second  varint
~~~

SESSION_ATTACH_OK：

~~~text
authorization_generation  varint
replication_budget_bytes_per_second  varint
~~~

请求的 attachment budget 是有界字节速率。Egress MAY 返回更低的有效值（包括零）。
双方将该有效值作为共享于所有 Path 的 Session 硬上限；它不是规则或 TrafficClass 标识。

SESSION_ATTACH_REJECT：

~~~text
error_class          u8, error registry below
reason               bytes(max_control_payload), diagnostic only
~~~

PATH_READY：

~~~text
max_frame_payload        varint
max_control_payload      varint
max_session_buffering    varint
~~~

每个值 MUST 为正数且不超过 profile 限制。只有接受 PATH_READY 后才允许
发送业务帧。

PATH_READY_CAPABILITIES 在 PATH_READY 后附加一个 capability 位集合：

~~~text
max_frame_payload        varint
max_control_payload      varint
max_session_buffering    varint
capabilities             varint bitset
~~~

PATH_DRAIN：

~~~text
drain_reason          varint (0=scale_in, 1=administrative, 2=transport)
deadline_ms           varint (0 means no deadline)
~~~

PATH_CLOSE：

~~~text
error_class           u8
reason                bytes(max_control_payload), diagnostic only
~~~

SESSION_CLOSE 使用与 PATH_CLOSE 相同的两个字段，并且对该 SessionID 是
最终状态。

HEARTBEAT：

~~~text
control_seqno         varint
~~~

CONTROL_ACK：

~~~text
highest_contiguous   varint
range_count          varint, at most max_ack_ranges
ranges               repeated inclusive [start, end] varint pairs
~~~

`CONTROL_ACK` 确认同一 Path 上的 Path 本地 `HEARTBEAT` 序号。其范围有序且不重叠。

SESSION_CONTROL 承载一个 Session 范围的操作：

~~~text
control_seqno         varint
dependency_present    varint（0 或 1）
depends_on            varint，仅 dependency_present = 1 时存在
inner_frame_type      varint
eligible_path_count   varint，0..=256
eligible_paths        重复的 PathID，按序排列且无重复
inner_payload         bytes(max_control_payload)
~~~

`inner_frame_type` 为 SESSION_CLOSE、STREAM_OPEN、STREAM_OPEN_OK、
STREAM_OPEN_ERR、STREAM_ACK、STREAM_WINDOW、STREAM_FIN、STREAM_RST、UDP_OPEN、
UDP_OPEN_OK、UDP_OPEN_ERR 或 UDP_CLOSE。
`inner_payload` 是该帧类型不带帧头的规范 payload。完整的 SESSION_CONTROL payload
（包括此封装）受 `max_control_payload` 限制。依赖序号 MUST 小于控制序号。
发送方 MUST 编码 `eligible_path_count=0` 且不包含 PathID。对于 STREAM_OPEN 和 UDP_OPEN，
零值表示两个方向都使用 Session 公共 Path 池，并仍受认证、ready、draining 和流控限制。
格式正确的非空列表属于已退休的逐 flow 限制；接收方 MUST 在目标拨号前返回 STREAM_OPEN_ERR
或 UDP_OPEN_ERR 和 LOCAL_POLICY，应用并确认控制序列，并对重复副本返回相同的幂等拒绝。
不得缩小公共池，也不得阻塞后续有效控制操作。
每个发送方向拥有独立的 Session 范围控制序号，从零开始。接收方按序应用操作并
丢弃重复项；应用操作前必须先应用其依赖。发送方保留并重传操作直到收到确认。
在其他符合条件的 Path 上发送副本时，使用新的 Path 帧序号和 Noise nonce，同时保留
控制序号和 payload。Path HELLO、attach、readiness、DRAIN、CLOSE、STATUS_REPORT、
HEARTBEAT 和 CONTROL_ACK 仍属于 Path 本地消息，不进行此封装。

SESSION_CONTROL_ACK 使用与 CONTROL_ACK 相同的 payload 编码，但其范围属于认证
发送方对端方向的 Session 控制序号空间。`highest_contiguous` 确认直到该值的所有序号；
选择性范围为可选项。接收方至少应用序号 0 后才发送 ACK。ACK 沿收到副本的 Path 发送。
关闭 Session 时，接收方保留足够时间，以确认重传的 SESSION_CLOSE；发起方收到该 ACK
或失去 Session transport 后关闭。

SESSION_CONTROL_CANCEL 可用相同控制序号替换 flow 尚未确认的操作；没有此类未确认操作时，
也可使用新的序号：

~~~text
control_seqno         varint
flow_kind             varint（0=TCP Stream，1=UDP Association）
flow_id               varint
~~~

它只包含 Session 内的不透明 flow ID，绝不包含目标、凭据或业务数据，并可经该 Session
任意 ready 且已认证的 Path 传递。接收方在同一序号空间内处理取消操作，并以它替换
已排队的同序号同 flow 操作。如果原操作已被应用，取消操作会清理该 flow。重复取消
操作是幂等的；ACK 对已取消序号的确认方式与其他操作相同。

#### 状态报告

STATUS_REPORT 是经过认证的 Egress 到 Ingress 健康样本。v1 payload 为：

~~~text
connected                    u8 (0 or 1)
service_state                u8 (0=down, 1=up, 2=degraded, 3=draining)
admission_allowed            u8 (0 or 1)
admission_reason             u8 (stable reason registry)
load_basis_points            u16, 0..=10000
connection_utilization_bp    u16, 0..=10000
bandwidth_utilization_bp     u16, 0..=10000
active_sessions              varint
active_streams               varint
active_target_connections    varint
configured_capacity_bps      varint
effective_capacity_bps       varint（unknown 或 stale 时可为零）
current_wire_rate_bps        varint
replication_allowance_bps    varint
capacity_state               u8（0=unknown, 1=provisional, 2=measured, 3=stale）
report_seqno                 varint
sample_age_ms                varint
expires_after_ms             varint, positive
~~~

`connected` MUST 等价于 `service_state != down`。`admission_allowed` 为真当且仅当
`admission_reason` 为 NONE（0）。接收方 MUST 拒绝在禁止准入时给出 NONE、或在允许准入时给出非零原因的报告。
比率使用 basis points，不使用浮点数。
`effective_capacity_bps` 仅在 `unknown` 或 `stale` 状态下可以为零；复制 allowance
不得超过配置容量。当 sample_age_ms > expires_after_ms 时，Ingress MUST 将报告视为
过期；过期报告不能准入新流，也不能触发缩容。报告按 report_seqno 顺序应用，重复或
更旧的报告忽略。省略容量、准入、服务状态、利用率、序列或新鲜度字段的状态 payload
不是 v1 payload，与本 profile 不互操作。

准入原因的稳定线码如下。

| 编码 | 名称 |
|---:|---|
| 0 | NONE |
| 1 | RESOURCE_LIMIT |
| 2 | CONNECTION_LIMIT |
| 3 | BANDWIDTH_LIMIT |
| 4 | ADMINISTRATIVE_DRAIN |
| 5 | AUTHORIZATION_FAILURE |

#### TCP Stream

STREAM_OPEN：

~~~text
request_id                 id128
stream_id                  varint
hostname                   bytes(max_target_name), MAY be empty
port                       u16, 1..=65535
resolved_address_count     varint, at most max_endpoint_addresses
resolved_addresses         repeated endpoint values
~~~

至少 MUST 提供 hostname 或一个地址候选。endpoint value 由 address_family
u8（4 或 6）以及 4 或 16 个地址字节组成。

STREAM_OPEN_OK 由 stream_id 后接 result_metadata 组成。STREAM_OPEN_ERR
由 stream_id、error_class 和 reason 组成。

STREAM_DATA：

~~~text
stream_id              varint
offset                 varint
stream_flags           varint (FIN=1, RST=2; other bits reserved)
data                   bytes(max_frame_payload)
~~~

offset 加 data 长度 MUST NOT 超过 62 位 Stream 偏移空间。FIN MUST 排在此前字节
之后；RST 丢弃待处理字节并关闭目标连接。

`STREAM_DATA`、`STREAM_FIN`、`STREAM_RST` 和 `STREAM_WINDOW` 的方向由 Path
经过认证的发送端方向决定，不在载荷中重复编码。`STREAM_ACK` 由 stream_id、
range_count 和针对从对端接收字节的按序闭区间偏移范围组成；因此其方向是
经过认证的发送端方向的反方向。实现 MUST 从经过认证的端点角色推导方向，不能
接受第二个可能冲突的 direction 字段。
STREAM_WINDOW 由 stream_id、绝对 stream_receive_limit 和绝对
session_receive_limit 组成。STREAM_FIN 由 stream_id 和 stream_flags 组成。
STREAM_RST 由 stream_id、error_class 和 reason 组成。

#### UDP Session

UDP_OPEN：

~~~text
association_id           varint
target_flags             varint (HOSTNAME=1, CANDIDATES=2)
hostname                 bytes(max_target_name), present when HOSTNAME set
port                     u16, 1..=65535
candidate_count          varint, at most max_endpoint_addresses
candidates               repeated endpoint values
~~~

flag 与字段 MUST 一致，且至少提供一种目标形式。UDP_OPEN_OK 由
association_id 和 target_visible_port（u16，非零）组成。UDP_OPEN_ERR 由
association_id、error_class 和 reason 组成。

UDP_DATAGRAM 由 association_id、datagram_seq（varint）和 payload
（bytes(max_frame_payload)）组成。数据报边界 MUST 保留，聚合层不重传应用
数据报。UDP_CLOSE 由 association_id、error_class 和 reason 组成。

### 错误注册表和格式错误

错误类别是稳定的 profile 值：

| Code | Name | Use |
|---:|---|---|
| 1 | LOCAL_POLICY | Ingress 监听器或规则拒绝 |
| 2 | PATH_FAILURE | 该 Path 无法承载流量 |
| 3 | EGRESS_FAILURE | Egress 或 Session 不可用，包括授权/能力拒绝 |
| 4 | TARGET_FAILURE | Egress 到目标的操作失败 |
| 5 | RESOURCE_LIMIT | 有界 Egress 或本地资源耗尽 |

reason 字节仅用于诊断，MUST NOT 作为分支 API。格式错误帧、未知强制类型、
不支持的版本、无效错误类别或限制违规都属于协议错误：丢弃该帧、产生诊断
事件并关闭 Path。合法的 STREAM_OPEN 或 UDP_OPEN 若不能准入，返回对应的
*_ERR 帧。TCP 流控耗尽时 MUST 施加背压，MUST NOT 静默丢弃字节。UDP 超出预算
的数据报 MAY 按策略过期或丢弃。

### 一致性测试向量

声称符合 v1 的实现 MUST 为通用帧头、Noise 记录封装、注册表中的每个 payload、
每个错误类别及 EgressID prologue 提供确定性向量。测试 MUST 覆盖截断、尾随
字节、非规范 varint、未知类型和 flag、无效地址族、零端口、超长字段、重放
窗口重复/过旧记录、nonce/帧序号不匹配和过期状态报告。只有编码和解码都还原
完全相同字节时，向量才有效。

规范 IK 兼容向量使用 `Noise_IK_25519_ChaChaPoly_SHA256`，prologue 为
`PathChord/wire-v1/egress/egress-id`；initiator 静态私钥为重复 32 次的 `01`，
responder 静态私钥为重复 32 次的 `02`，initiator 和 responder 临时私钥分别为
重复 32 次的 `04` 和 `05`。握手 payload 为空。传输明文为 ASCII
`PathChord transport vector`，使用 initiator 到 responder 方向的 nonce 7。

```text
message_1 = ac01b2209e86354fb853237b5de0f4fab13c7fcbf433a61c019369617fecf10b5ff672297d0d3ade1dd319d94628c4340bb85d86f62343c56fe841734b841fb6026f297def6e19ed47946e13d165de43d0225e93eb0f307b235dc8a202b3603b
message_2 = 50a61409b1ddd0325e9b16b700e719e9772c07000b1bd7786e907c653d20495dc5e12927491c58f5730f88bf3154bd48
transport_nonce_7 = d8cd46c9df78dbd4bc8cebae020320f9bde5dba394c98104938b74b93ba7c5b808580283263e7b5df5ac
```

### 安全考虑

记录 nonce 是显式的，并通过帧序列认证。发送方 MUST NOT 在同一方向密钥下使用
同一 nonce 加密不同明文。接收方 MUST 在提交重放状态前完成记录认证，并 MUST 按
profile 限制约束所有分配。实现 MUST 清零 provider 拥有的密钥材料，MUST 为每条
Path 使用独立传输状态，并 MUST 在 `PATH_READY` 之前拒绝 prologue 或授权不匹配。

### IANA 考虑

本文档不产生 IANA 操作。profile 中的私有注册表由 PathChord 维护者负责；新增分配
MUST 使用新的版本化 profile，并明确更新一致性测试向量。
