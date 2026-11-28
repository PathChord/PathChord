# Transit Proxy 适配器与订阅格式

[English](spec.md) | **简体中文**

## Purpose

定义原生 Transit Proxy 的可选条件、类型化连接参数、私有凭据、订阅规范化、有界 provider 展开、用量元数据，以及普通 UDP 与 Egress UDP 的边界。

## Requirements

### Requirement: Detailed Transit Proxy contract

Transit 适配器和订阅处理 SHALL 遵循下文完整详细契约，包括协议矩阵、选项与凭据字段、来源别名、限制、缓存行为和 UDP 语义。这些要求和场景补充这些定义，而不替代它们；入站监听器支持 SHALL NOT 表示出站节点支持。

#### Scenario: Inbound protocol has no outbound adapter

- **WHEN** 导入 `socks4` 或 `socks4a` 出站节点
- **THEN** 即使本地监听器支持这些协议，该节点仍保持不可用并带类型化诊断。

#### Scenario: Canonical native option names are authored

- **WHEN** 原生 TransitProxy 在其选项对象中使用 `hosts`、`maxEarlyDataBytes`、`certificates`、`clientCertificates`、`clientHelloFingerprint` 或 `udpOverTcpVersion`
- **THEN** 解析会保留各字段的文档化类型、值和列表顺序，并将其交给选定适配器，连接语义保持不变

#### Scenario: A retired native option name is authored

- **WHEN** 原生 TransitProxy 使用迁移表中的任意退役选项路径，包括空值或默认值字段
- **THEN** 完整配置校验会拒绝该候选，并返回有界的 `CONFIG_RETIRED_FIELD` 诊断，指出资源、准确的已输入字段路径和规范替代路径，且不暴露字段值

#### Scenario: Retired and canonical native names are combined

- **WHEN** 一个原生 TransitProxy 同时包含退役选项名及其规范替代名
- **THEN** 校验会拒绝完整候选，不合并值、不择一使用，也不把退役名当作别名

#### Scenario: Certificate pins and ClientHello profiles are configured together

- **WHEN** 原生 TLS 配置同时包含 `certificateSha256` 和 `clientHelloFingerprint`
- **THEN** 证书 pin 仍必须匹配，ClientHello profile 独立选择受支持的模拟行为

#### Scenario: A supported foreign node uses its original option names

- **WHEN** Clash、sing-box 或分享链接节点使用其来源文档规定的名称提供受支持的 TLS、HTTP Host、early-data 或 UDP-over-TCP 参数
- **THEN** 导入器接受并将这些字段规范化为原生模型，不要求外部文档改用 PathChord 原生字段名

#### Scenario: Foreign or private data contains a matching field name

- **WHEN** HTTP 头、私有凭据字段或保留的完整外部文档包含与某个退役原生选项同名的键
- **THEN** 原生键校验不会仅因键名匹配而重写或拒绝该数据

### Requirement: Native compatibility for existing proxy protocols

Transit SHALL 仅为下方详细适配器矩阵标记为支持的协议与选项组合提供原生支持。受支持的 provider 节点 SHALL 保留认证、传输、安全和数据报语义；不支持或不完整的组合保持不可用并附类型化诊断。

#### Scenario: A supported provider node uses a native adapter

- **WHEN** provider 提供的节点使用矩阵列出的受支持协议与选项组合
- **THEN** Transit 规范化并准备对应的原生适配器，不启动外部代理 core，且保留文档定义的连接语义

#### Scenario: A combination cannot be represented safely

- **WHEN** 节点包含不支持或不完整的连接选项组合
- **THEN** 节点保持不可用并附脱敏诊断，且不得降级后继续路由

### Requirement: VLESS Vision flow and datagrams

VLESS Vision SHALL 在直连 TLS 1.3 或 REALITY 上保留每个方向的 framing 状态转换；不启用 multiplex 时使用 XUDP，启用时使用所选 multiplex 的数据报 framing。`-udp443` flow 还 SHALL 允许目标 UDP 443 端口。

#### Scenario: Vision datagrams to port 443

- **WHEN** Vision 节点向 UDP 443 端口打开数据报
- **THEN** 仅 `xtls-rprx-vision-udp443` 请求成功，且线上携带基础 Vision flow 名称

#### Scenario: Peer switches a Vision direction to direct copy

- **WHEN** 对端在 framing 内容后发送有效的 Vision DIRECT 转换
- **THEN** 接收端按顺序交付已缓冲明文和之后的原始字节，且不暴露外层 TLS 记录流

### Requirement: Bounded smux sessions

smux 会话 SHALL 执行详细契约中的每会话和每流资源限制，隔离接收超限的流，并保持规定的
FIN 和载体生命周期语义。

#### Scenario: A smux stream exceeds its receive budget

- **WHEN** smux 流超过自身接收预算，或共享接收预算受压时被选中隔离
- **THEN** 该流报告资源错误并安排发送 FIN，会话继续处理其他流

#### Scenario: The last smux stream is released

- **WHEN** smux 会话的最后一个流句柄释放时仍有载体 I/O 未完成
- **THEN** 未完成的 I/O 共用十秒排空期限；打开新流会取消该期限

#### Scenario: A target responds after smux FIN

- **WHEN** 目标收到请求的 smux FIN 后发送响应
- **THEN** 客户端不承诺 TCP 半关闭行为，也不保证该后续响应能够到达

### Requirement: Hysteria2 negotiated congestion control

Hysteria2 SHALL 发送配置的接收速率提示，并在认证后按详细契约，根据对端响应和配置的
上传速率选择拥塞控制。有效目标为零或响应为 `auto` 时 SHALL 使用 BBR；有效目标为正时
SHALL 使用 Brutal 发包控制和丢包补偿。

#### Scenario: The peer requests automatic congestion control

- **WHEN** 已认证的 Hysteria2 对端响应 `Hysteria-CC-RX: auto`
- **THEN** 即使配置了非零 `up_mbps`，客户端也使用 BBR

#### Scenario: The peer supplies a numeric receive rate

- **WHEN** 对端返回数值接收速率，且客户端配置了非零 `up_mbps`
- **THEN** 响应为零时客户端采用配置的上传速率；响应为正时采用两者中较小的非零速率

#### Scenario: No upload rate is configured

- **WHEN** `up_mbps` 缺省或为零，且对端返回数值接收速率
- **THEN** 客户端使用 BBR，包括对端返回正数速率的情况

### Requirement: Validate native parameters without downgrade

节点 SHALL 仅在选定的原生适配器验证完整消费参数集合后才变为可选。未知或不支持的参数 SHALL 产生规定的配置错误或脱敏不可用节点诊断。TLS 和传输验证失败 SHALL NOT 触发明文、direct、plugin 进程或外部兼容进程回退；敏感选项和完整导入文档 SHALL 保留在私有凭据中。

#### Scenario: Requested TLS configuration fails

- **WHEN** 节点请求的 TLS 配置验证失败
- **THEN** 节点被拒绝，或保持不可用并带类型化诊断，且不会选择明文或 direct 回退。

原生 TLS 适配器 SHALL 默认加载系统根证书，应用有序 truststore 来源列表，并在任一来源无法读取或解析时拒绝准备。除非显式选择 insecure，TLS 校验必须保持开启；失败不得降级为明文或其他协议。

#### Scenario: Intrinsic TLS has no explicit TLS block

- **WHEN** Hysteria2、TUIC、AnyTLS 或其他内置 TLS 节点省略显式 TLS 选项
- **THEN** 适配器仍使用系统根证书并执行证书校验

### Requirement: Truststore source lists are atomic

适配器 SHALL 将 truststore 来源作为一个原子集合处理。来源必须是 `system` 或本地 PEM/DER 文件；相对路径从选定配置来源解析，符号链接目标必须是普通文件，任一无效来源都必须拒绝候选。

#### Scenario: One source in a list is invalid

- **WHEN** 列表中某个来源不可读、超大、格式错误或不包含有效证书
- **THEN** 适配器 fail closed，不静默移除该来源，也不恢复系统根证书

### Requirement: Explicit insecure verification is separate

适配器 SHALL 仅在 TLS 选项显式请求 insecure 时跳过证书校验。没有该选项时，空 truststore 必须 fail closed，TLS 失败不得降级为明文或 insecure TLS。

#### Scenario: Custom roots do not validate the peer

- **WHEN** 节点使用的自定义 truststore 无法锚定对端证书
- **THEN** TLS 连接以类型化适配器错误失败，不重试为明文或 insecure TLS

### Requirement: Bounded imports and source-bound caches

订阅处理 SHALL 只规范化支持的节点定义，在保留单节点诊断的同时保留有效兄弟节点，在文档格式错误时保留上一成功快照，并执行详细契约中的节点数和字节数限制。私有缓存 SHALL 保留选项与诊断，并 SHALL 绑定来源类型、URL、凭据引用和有效 User-Agent；无法验证的缓存 SHALL NOT 发布，旧来源节点 SHALL 排空而不接受新 flow。

#### Scenario: One imported node is invalid

- **WHEN** 有效订阅文档同时包含无效或不支持的节点及有效节点
- **THEN** 有效兄弟节点被保留，无效节点保持不可选并带稳定脱敏诊断。

#### Scenario: Subscription source changes

- **WHEN** 订阅的来源类型、URL、凭据引用或有效 User-Agent 改变
- **THEN** 旧来源的节点进入排空，不得被新 flow 选择。

#### Scenario: Canonical native options survive a source-bound cache roundtrip

- **WHEN** 写入并加载包含规范原生选项的已验证来源绑定缓存
- **THEN** 选项值、凭据、诊断、来源身份和重新执行适配器准备的要求均得到保留

#### Scenario: A cache uses an incompatible normalized option schema

- **WHEN** 缓存使用较旧的规范化选项 schema 版本，或包含退役的规范化原生选项字段
- **THEN** 加载会返回有界且脱敏的 `cache_incompatible` 诊断，不发布该缓存中的节点，并且只允许针对当前配置来源执行有界认证刷新

#### Scenario: An incompatible cache is found while valid nodes are active

- **WHEN** 发现不兼容缓存，且当前来源与生命周期决策下仍有独立有效的活动快照
- **THEN** 有界刷新期间可以保留该活动快照，但不得把不兼容缓存当作有效校验或复活已退役节点

#### Scenario: A cold start has an incompatible cache and no source connection

- **WHEN** 不存在独立有效的活动快照、缓存不兼容且配置来源无法刷新
- **THEN** 不发布该缓存中的节点，订阅保持不可用，并提供类型化的缓存与刷新诊断

#### Scenario: A cache conflicts with subscription lifecycle decisions

- **WHEN** 加载缓存或发布刷新结果之前，订阅已禁用、删除、替换来源或命中持久化节点 tombstone
- **THEN** 当前生命周期决策会抑制相关发布，不兼容缓存、过期刷新或保留快照均不得复活已退役节点

### Requirement: Node probe revocation follows source visibility

Ingress 应用订阅禁用、删除或来源替换时，SHALL 取消受影响节点排队中及进行中的探测，
且 SHALL NOT 发布来自已撤销准入的观测。无关节点的探测 SHALL 独立继续。

#### Scenario: Subscription changes while a probe is queued

- **WHEN** Ingress 禁用、删除或替换排队中或进行中的节点探测所使用的来源
- **THEN** 该探测被取消，过期结果不会发布，无关的探测可以继续

### Requirement: Bounded provider expansion and credential origins

HTTP(S) provider 展开 SHALL 每次刷新最多 32 个引用、深度 3、正文总量 4 MiB，拒绝本地 file/path provider，并在报告 provider 失败时不丢弃无关的成功 provider。根 bearer 凭据 SHALL 仅在相同 URL origin 内继承，包括重定向；provider 身份 SHALL 参与稳定节点标识。

#### Scenario: Provider crosses a credential origin

- **WHEN** provider 引用或重定向指向不同于根订阅的 origin
- **THEN** 该 origin 不会收到根 bearer 凭据。

### Requirement: Explicit optional provider accounting

提供方用量与流量倍率 SHALL 遵循详细契约中的解析、范围、持久化和未知值语义。到期时间 SHALL NOT 被解释为配额重置周期；缺失或无效元数据 SHALL NOT 伪造零容量或成为硬连通性限制。有效元数据可以影响选择权重，但 SHALL NOT 覆盖授权、健康或显式策略。

#### Scenario: Accounting metadata is absent

- **WHEN** provider 省略可选配额或倍率元数据
- **THEN** 这些事实保持未知，不变为伪造的零容量或硬连通性失败。

### Requirement: Separate native UDP from Egress Session datagrams

普通 UDP 路由 SHALL 要求选定适配器支持相应原生 UDP 行为，不支持时 SHALL 以类型化路由错误失败。节点 UDP 禁用、SOCKS5 relay 验证与控制连接所有权，以及 TLS 降级禁令 SHALL 遵循详细契约。由字节流 Transit Path 承载的 Egress UDP Session SHALL NOT 要求第三方节点支持原生 UDP。

#### Scenario: Egress UDP uses a TCP or TLS Transit Path

- **WHEN** Egress UDP Session 由可选的 TCP 或 TLS Transit Path 承载
- **THEN** 该 Transit 节点不支持原生 UDP 这一事实本身不会导致 Session 数据报被拒绝。

### Requirement: Subscription User-Agent identifies source content

订阅 HTTP 请求 SHALL 使用配置的来源 User-Agent，未配置时使用 `clash.meta`。根请求与嵌套 provider 请求 SHALL 使用同一值。有效 User-Agent 改变时 SHALL 使来源绑定缓存与过期刷新候选失效，同时保持凭据 origin 和下载预算边界。

#### Scenario: A subscription changes its User-Agent

- **WHEN** 订阅的有效 User-Agent 改变
- **THEN** 旧来源节点进入排空，使用旧值获取的缓存和进行中的内容不得作为新来源发布

### Requirement: AnyTLS v2 session reuse and padding

AnyTLS 适配器 SHALL 实现官方 v2 settings、填充协商、heartbeat、Stream 生命周期和
Session 复用行为，每个 Session 同时只允许一个活跃 Stream。

#### Scenario: A new Session sends the official preface

- **WHEN** 适配器使用节点当前的填充方案创建 TLS Session
- **THEN** 按照 AnyTLS v2 要求的顺序发送带填充的认证、包含客户端标识和填充摘要的 v2 settings，以及首个 Stream 的设置

#### Scenario: A healthy Stream is closed

- **WHEN** 唯一的活跃 Stream 发送或收到正常 FIN，且所属 Session 的事件循环仍然健康
- **THEN** 适配器释放 Stream 租约，并将 Session 放回该节点的空闲池

#### Scenario: An idle Session is available

- **WHEN** TCP 或 UoT v2 UDP 请求需要 AnyTLS Session，且节点有健康的空闲 Session
- **THEN** 适配器租用最近释放的空闲 Session，在其上打开一个新 Stream，无需建立新的 TLS 连接

#### Scenario: The idle pool is full

- **WHEN** 释放健康的 Session 将超过节点的空闲池上限
- **THEN** 适配器淘汰最早进入空闲池的 Session，最多保留八个空闲 Session

#### Scenario: An idle Session expires

- **WHEN** 空闲 Session 已连续 60 秒未使用
- **THEN** 适配器在其可被再次租用前关闭并移除它

#### Scenario: The server updates padding

- **WHEN** Session 收到有效的 cmdUpdatePaddingScheme
- **THEN** 适配器验证并原子发布该方案供后续 Session 使用，当前 Session 继续使用创建时采用的方案

#### Scenario: The server rejects a Stream

- **WHEN** SYNACK 含有错误 payload
- **THEN** 当前请求以脱敏的协议错误失败，适配器丢弃该 Session 且不重试该请求

#### Scenario: A peer closes a Stream

- **WHEN** Session 收到活跃 Stream 的 FIN
- **THEN** Stream 的读取端关闭，适配器不回送 FIN，仅在写入端和事件循环保持健康时才将 Session 放回空闲池

#### Scenario: A peer sends ALERT

- **WHEN** Session 收到 ALERT
- **THEN** 活跃 Stream 和 Session 以脱敏的连接错误失败，该 Session 从空闲池移除，后续请求创建新的 Session

#### Scenario: A heartbeat is received

- **WHEN** Session 收到带任意 Stream ID 的 cmdHeartRequest
- **THEN** Session 回复具有相同 Stream ID 且 payload 为空的 cmdHeartResponse

#### Scenario: A UoT v2 request uses the pool

- **WHEN** 打开 UoT v2 UDP association
- **THEN** 适配器使用与 TCP 共享的池租用或创建 AnyTLS Session，打开一个 Stream，并在等待成功的 SYNACK 前发送 UoT v2 请求

## Detailed contract

本文档定义节点连接语义、订阅规范化、provider 展开及用量元数据。
[配置 schema](../configuration-schema/spec.zh-CN.md)定义资源外壳；
[平台规范](../platform-and-dns/spec.zh-CN.md)定义本地 HTTP、SOCKS 和 Mixed 监听器。
入站协议支持不得被解释为支持同名的出站节点协议。

### 适配器选择与失败

| 节点协议 | 原生传输 | 其他参数 |
| --- | --- | --- |
| `direct` | TCP 和 UDP | 扩展拨号选项 |
| `http`、`https` | HTTP/1 CONNECT、Basic 认证、经过验证的额外头；HTTPS 使用 TLS | 支持的扩展节点选项 |
| `socks5` | CONNECT、用户名密码、UDP ASSOCIATE 或 UDP-over-TCP v1/v2；可选 TLS | 支持的扩展节点选项 |
| `ss` | 使用 AEAD、SS2022、部分旧 stream 算法及显式 `none`/`plain` 的 TCP/UDP、UDP-over-TCP v1/v2，以及 TCP 的原生 simple-obfs 或 v2ray-plugin WebSocket | 不支持的算法、插件及插件参数产生不可用诊断 |
| `socks4`、`socks4a` | 无原生出站适配器 | CONNECT |
| `vless` | 带类型化 TLS/传输校验的 TCP、TLS、WebSocket/WSS、HTTP、HTTPUpgrade、gRPC、QUIC 和 Meek 字节传输 | 扩展传输与 flow 选项 |
| `vmess` | TCP、TLS、WebSocket/WSS、HTTP、HTTPUpgrade、gRPC、QUIC、Meek、AES-128-GCM、ChaCha20-Poly1305 或 AES-128-CFB 正文记录、显式 `none`/`zero` 明文正文、单目标 UDP、有界 legacy 或 AEAD `alter_id` 握手 | 支持的 multiplex 和扩展选项按下文校验 |
| `trojan` | TLS 封装的 TCP、WebSocket/WSS、HTTP、HTTPUpgrade、gRPC 和 QUIC 字节传输，以及支持原始/TCP、WebSocket、gRPC 和 HTTPUpgrade 别名的 Trojan-Go 分享链接 | 由于参考服务端对短加密流的请求嗅探不可靠，Trojan-Go 原始/TCP 加 SS 加密不可用；其他不支持的 Trojan-Go 选项产生类型化诊断 |
| `anytls` | TLS 上的 AnyTLS v2、填充协商、可复用的单 Stream Session 及有界 UoT v2 UDP 数据报 | 单个 Session 内的并发 Stream 及其他不支持的扩展选项 |
| `hysteria2` | 原生 QUIC/TLS + HTTP/3 认证、到 IPv4 或 IPv6 目标的 TCP/UDP relay、有界 UDP 分片与重组、Salamander、Gecko 或无混淆传输、有界 server-port 跳转及协商的 BBR/Brutal 速率 | TLS 指纹和其他不支持的扩展选项 |
| `tuic` | 原生 QUIC/TLS-exporter TCP CONNECT、native DATAGRAM、QUIC stream UDP relay 或 UDP-over-stream、cubic/NewReno/BBR 拥塞控制和 heartbeat | TLS 指纹、0-RTT 及其他不支持的扩展选项 |
| `vless` + `tls.reality` | 使用 X25519 ClientHello proof、证书 proof 校验及 dae Chrome 133、iOS 14、Safari 16、Edge 85、QQ 11.1、Firefox 120 指纹 profile 的原生 VLESS over REALITY TLS | 其他指纹、证书 pin、自定义信任根和不支持的外层传输产生类型化不可用诊断 |
| `xtls` | VLESS 与明确指定的已注册 XTLS Vision flow 的别名；选择 adapter 前规范化为 `vless` | 缺失或不支持的 XTLS flow 产生类型化诊断 |
| `hysteria`、`ssh`、`shadowtls` | 无原生适配器 | 类型化不可用诊断 |
| `wireguard` | 无原生适配器 | 完整的用户态 WireGuard endpoint 文档 |
| `snell` | 无原生适配器 | 类型化不可用诊断 |
| `ssr` 及未注册协议 | 不可用 | 明确不可用 |

仅凭协议名不得将节点标为可用。原生适配器必须在发布到运行时之前校验消费的参数。不支持的
参数和未实现的协议必须产生类型化、脱敏诊断。TLS 或传输配置失败时不得回退为明文或 direct。

原生 VLESS 和 Trojan 适配器会在打开 socket 前拒绝不支持的 flow、multiplex、packet 和传输
选项。原生 VMess 支持正数 `alter_id` 的 legacy HMAC-MD5/AES-128-CFB 握手，也支持 AEAD
握手、AEAD 正文密码、保持连续流状态并逐记录校验 FNV-1a 的 AES-128-CFB，或显式配置的
`none`/`zero` 明文正文；`alter_id` 范围限制为 `0..=65535`。原生 h2mux、yamux 和 smux
可按下文使用。其 AEAD 响应头始终使用
AES-128-GCM，与所选正文密码无关。指定
`xtls-rprx-vision` 或 `xtls-rprx-vision-udp443` 的 VLESS 节点通过直连 TLS 1.3 或
REALITY 使用 Vision。未启用 multiplex 时数据报使用 XUDP；启用受支持的 multiplex 时使用其 UDP 帧。
只有后者允许访问 UDP 443 端口；两者在线上发送
`xtls-rprx-vision`。XUDP 数据报上限为 8192 字节。不可用的指纹不会用其他 ClientHello
近似替代。表中的协议行本身不表示包含不支持参数的节点可选。
数据及时到达时，第一个 Vision 请求和上行帧共用带填充的外层 TLS 记录。空闲连接在有界延迟后
发送带填充的空帧；完整 CONTINUE 帧之后的 EOF 是有效的流结束。

VMess `globalPadding` 和 `authenticatedLength` 仅在 AEAD 正文密码下接受。长度认证的线协议
以请求 key 和 IV 派生两个方向的长度密钥和 nonce 序列，因此对端会跨方向重复使用同一组
key/nonce。每个方向必须在自身记录计数器回卷前停止。
VMess 支持 `packetEncoding: xudp` 和 `packetaddr`；packetaddr 目标必须是 IP。返回数据包的
地址会与绑定目标校验，XUDP 主机名目标仅在端口匹配时接受解析后的 IP。
VLESS 在明文 TCP、TLS 或不带 Vision 的 REALITY 上也支持 IP 目标的 `packetaddr`。
与任一 Vision flow 同时配置 `packetaddr` 时会在适配器准备阶段拒绝。显式 packet encoding
也不能与 multiplex 同时配置；受支持的 multiplex 使用自身的数据报帧。

对于 REALITY，`clientHelloFingerprint: chrome` 选择 dae 2.1.2 的 Chrome 133 profile。它初次尝试
传统 X25519 形式并记住成功的形式，仅在完整 TLS 握手验证了可信的伪装站点证书后才重试另一种形式，绝不向
伪装站点发送 VLESS 数据。此 profile 不支持 TLS 1.2、HelloRetryRequest、恢复握手、真实 ECH
和服务端 ALPS 响应。
`clientHelloFingerprint: ios`、`safari`、`edge` 和 `qq` 分别选择 dae 的 iOS 14、Safari 16、
Edge 85 和 QQ 11.1 profile，使用原有 X25519 key share。`clientHelloFingerprint: firefox` 选择 dae 的
Firefox 120 profile，使用独立的 X25519 和 P-256 key share。对端的 `record_size_limit`
独立于客户端公告的接收限制约束出站 TLS 记录，且不会放宽更严格的本地限制。QQ 服务端的
ALPS 响应会被明确拒绝。普通 TLS 也支持这些 profile，并应用配置的证书校验。
`clientHelloFingerprint: android` 为不使用 ALPN 的普通 TLS 1.2 选择 dae/uTLS Android 11 OkHttp；
此 profile 不支持 REALITY、Vision 以及要求 ALPN 的传输。360 profile 所声明的密码套件
均未被当前 TLS 后端实现，因此不可用，不得用其他 profile 替代。

Gecko 接受整数 `gecko_min_packet_size` 和 `gecko_max_packet_size` 作为线上包长的填充目标。
各字段缺省或为零时分别默认为 512 或 1200 字节；最终范围 MUST 满足
`1 <= min <= max <= 2048`。这些字段要求启用 Gecko。目标适用于分片的长头包，包含
Salamander salt；短头包不填充，已超过最大值的分片也不额外填充。sing-box 的嵌套字段
`obfs.min_packet_size` 和 `obfs.max_packet_size` 被规范化为这些字段。

Hysteria2 `up_mbps` 和 `down_mbps` 是可选的非负整数 Mbps 值；无效值和转换为字节每秒时
溢出的值在准备阶段被拒绝。每 Mbps 等于 125,000 字节每秒，缺省值为零。`down_mbps` 作为
客户端接收速率提示在请求的 `Hysteria-CC-RX` 中发送；零表示未知，服务端可以忽略该提示。

Hysteria2 使用 `h3` ALPN 进行 HTTP/3 认证。显式 ALPN 列表含有其他协议时，适配器在准备阶段拒绝该配置。

QUIC 握手期间客户端使用 BBR。认证后，响应 `Hysteria-CC-RX: auto` 时，无论 `up_mbps`
如何配置都继续使用 BBR。对于数值响应，零选择配置的 `up_mbps`，正数选择该值与配置的
`up_mbps` 中较小的值。结果为零时继续使用 BBR，包括 `up_mbps` 缺省或为零而服务端返回
正数的情况。目标为正时，该连接选择 Brutal。

Brutal 使用最近五个按秒索引的时间槽计算确认包比例；确认包和丢失包总数不足 50 时比例为一，
否则该比例最低为 0.8。发包速率为目标除以该比例，拥塞窗口为该速率与平滑 RTT 乘积的两倍。
取得 RTT 样本前窗口为 10,240 字节，此后窗口至少为一字节。pacer 的令牌桶容量为十个最大
数据报或四毫秒发包预算中的较大值。因此丢包补偿可将正常经过 pacing 的 QUIC 速率提高到
目标的 1.25 倍。PTO 丢包探测包和纯 ACK 包可以绕过 pacing，MTU 和路径验证探测包也可能在
pacing 之外发送。这些例外、突发、重传、UDP/IP 及混淆开销使该目标既不是严格的物理带宽
上限，也不是吞吐保证。

Shadowsocks 的 TCP 和 UDP 支持 SIP004 `aes-192-gcm`。支持的旧式 stream 算法为
AES-128/192/256 CTR、CFB 和 OFB，Camellia-128/192/256 CFB，RC4、RC4-MD5、
ChaCha20-IETF 和 `xchacha20`。旧式 stream 算法不验证载荷的完整性。`none` 和 `plain`
明确选择不加密的 Shadowsocks 线协议模式，不使用密码；两者指定非空密码会被拒绝，
而不是丢弃该密码。其他不支持的 stream 算法不可用。

对于 `aes-192-gcm` 和 `xchacha20`，每个适配器实例在 TCP 与 UDP 之间共享一个有界窗口，
保留最近使用的 4096 个出站和入站 salt 或 IV，并拒绝窗口内的重复值。该窗口不持久化；
尤其是，它不能为 `xchacha20` 载荷提供完整性认证。

原生 Shadowsocks `v2ray-plugin` 适配器支持 SIP003 和 Clash 的 WebSocket 选项、可选
TLS、Host、path、经过验证的头、配置的证书及 pin 校验，以及默认单路 mux 或显式
`mux=0`。UDP 默认使用 Shadowsocks 数据报传输；显式选择 UDP-over-TCP 时经过配置的 TCP
插件。不支持的 mux 数量、传输模式和未消费的
选项会被拒绝。

#### AnyTLS v2

每个 AnyTLS 节点拥有一个由 TCP 和 UoT v2 UDP 共享的池。每个 TLS Session 同时承载
一个活跃 Stream。Stream 正常结束后，健康的 Session 返回池中。池优先借出最近释放的
健康 Session。超过八个时，淘汰最早释放的 Session。Session 空闲满 60 秒时关闭。
空闲 Session 继续处理对端控制帧。

在打开首个 Stream 前，Session 发送带填充的认证记录和 `cmdSettings`，其中包含协议版本
2、客户端标识以及创建 Session 时采用的填充方案的小写 MD5 摘要。初始方案为官方默认方案。
写入端按有界的分包规则使用 waste 帧进行填充。适配器验证 `cmdServerSettings`，并将有效的
`cmdUpdatePaddingScheme` 更新原子应用于后续 Session。打开 Stream 时发送 SYN 和目标
地址，随后等待成功的 SYNACK。UoT v2 还会在等待 SYNACK 前发送 association 请求。

收到对端 FIN 时结束 Stream，无需回送 FIN。解析或传输失败、无效的 settings 或填充更新、
heartbeat 回复失败、ALERT 和失败的 SYNACK 都会使 Session 退出。适配器报告错误时不泄露
对端的错误 payload，也不重试失败的请求。

### 类型化连接选项

`TransitProxy.spec.options` 默认为空对象，字段使用 camelCase。未知字段属于配置错误；
导入的未知字段必须保留为不可用节点诊断，不得静默忽略。

| 字段 | 默认值与含义 |
| --- | --- |
| `tls` | 缺省；TLS 对象，字段为 `enabled`、`serverName`、`insecure`、有序 `truststore`、`alpn`、`certificates`、`certificateSha256`、`clientCertificates`、`clientKeyField`、`clientHelloFingerprint`、`reality` |
| `transport` | 缺省；对象，字段为 `type`、`path`、`hosts`、`headers`、`serviceName`、`maxEarlyDataBytes`、`earlyDataHeaderName` |
| `headers` | `{}`；非秘密 HTTP CONNECT 头 |
| `udp` | 缺省；使用适配器能力；`false` 禁用普通 UDP 转发 |
| `udpOverTcpVersion` | 缺省；SOCKS5 或 Shadowsocks UDP-over-TCP 版本 `1` 或 `2`；与 `udp: false` 不兼容 |
| `vmess` | 缺省；`globalPadding` 和 `authenticatedLength` 布尔值，均默认 `false` |
| `multiplex` | 缺省；对象，字段为 `enabled`、`protocol`、`maxConnections`、`minStreams`、`maxStreams`、`padding` |
| `tcpFastOpen` | 缺省；可选布尔值 |
| `bindInterface` | 缺省；可选的本地接口名 |
| `routingMark` | 缺省；可选的无符号 32 位路由标记 |
| `packetEncoding` | 缺省；`xudp` 或 `packetaddr` |

PathChord 原生选项键名唯一且没有兼容别名。适配器 MUST 拒绝不支持的组合或列表元素数量，不能丢弃字段。
退役键 MUST 通过有界的 `CONFIG_RETIRED_FIELD` 诊断指出替代字段；未知键仍然无效，字段名不得递归改写。

| 退役原生字段 | 规范字段 |
| --- | --- |
| `transport.host` | `transport.hosts` |
| `transport.maxEarlyData` | `transport.maxEarlyDataBytes` |
| `tls.certificate` | `tls.certificates` |
| `tls.clientCertificate` | `tls.clientCertificates` |
| `tls.fingerprint` | `tls.clientHelloFingerprint` |
| `udpOverTcp` | `udpOverTcpVersion` |

`hosts` 是有序列表，最多 16 个非空 HTTP Host 覆盖值，每个最多 255 字节；适配器可以支持更少元素，且必须拒绝不支持的数量。
`certificates` 和 `clientCertificates` 均为有序内联 PEM 列表，最多 16 个值，每个最多 65,536 字节。前者向信任库添加信任锚，后者组成客户端认证链。
`maxEarlyDataBytes` 是范围为 `0..=65536` 的整数字节数；`udpOverTcpVersion` 是可选整数版本 `1` 或 `2`，不是启用开关。

TLS 布尔值默认 `false`；truststore 默认 `["system"]`，`certificates`、`clientCertificates` 和 `alpn` 列表默认空列表。每个 truststore
来源必须是 `system` 或本地 PEM/DER 文件；相对路径从选定配置来源解析，允许绝对路径，符号链接目标
必须是普通文件，空列表表示没有信任锚点。任一无效、超大或格式错误来源都必须原子拒绝适配器。
`https` 隐含启用 TLS。Clash HTTP
节点的 `tls: true` 必须规范化为 HTTPS CONNECT。`serverName` 独立于连接地址覆盖证书/SNI
身份。原生 HTTPS CONNECT 允许 HTTP/1.1 ALPN。HTTP/1 CONNECT 接受最终的 2xx 响应，
并跳过此前除 101 以外的信息响应。响应头大小上限适用于整次交换。
`certificates` 是添加到当前 truststore 的内联 PEM 信任锚；`clientCertificates` 是客户端认证证书链。客户端私钥只能从
`clientKeyField` 指定的 opaque credential 文档字段读取。除整个对象均为默认值外，禁用 TLS
时指定 TLS 设置无效。`certificateSha256` 是 DER 证书的十六进制 SHA-256；匹配叶证书时认证该
证书，匹配中间证书时以该证书为信任锚验证证书链、名称和有效期。即使设置 `insecure: true`，
pin 仍必须匹配。Reality 使用 `publicKey` 和 `shortId`；`clientHelloFingerprint` 需要实现所请求
ClientHello profile 的适配器。`insecure` 是显式证书验证选项，不得在验证失败后自动采用。

传输 `type` 为 `tcp`、`ws`、`grpc`、`http`、`httpupgrade`、`quic`、`meek` 或 `xhttp`；模型接受该值
不表示原生适配器支持它。普通 TCP 不接受 HTTP 传输参数。`http` 传输支持 VLESS、VMess 和 Trojan，
可配置 path、最多一个 Host 和经过验证的头。未启用 TLS 时使用 HTTP/1.1 PUT，启用 TLS 时使用
带 `h2` ALPN 的 HTTP/2 PUT；对端响应状态必须为 200。默认 path 为 `/`；未配置 Host 时，明文
传输使用端点 host，TLS 传输使用 `www.example.com`。冲突的 Host 值、多个 host、service-name
或 early-data 选项以及由帧控制的头均会被拒绝。Trojan 仍然要求 TLS。V2Ray `quic` 传输用于
VLESS、VMess 和 Trojan 时要求 TLS；未配置 ALPN 时使用 `h3`，显式配置的 ALPN 保持原样。
REALITY、Vision、ClientHello 指纹和其他未消费的传输参数会被拒绝，不会静默更改。
Meek 用于通过 HTTPS 的 VLESS 和 VMess。包含 query 的完整 URL 存储在私有 `meek_url` 凭据中；
公开的 path、Host 和 header 传输选项会被拒绝。Meek 的本地写端关闭不会向远端发出流结束信号。
HTTPUpgrade 支持在 TCP
或 TLS 上使用 path、Host 和经过验证的头。WebSocket early data 将首次写入的最多 `maxEarlyDataBytes` 字节
以无填充 Base64URL 放入路径或指定的 `earlyDataHeaderName`，其余字节通过二进制帧发送。
路径 early data 与其他 query 组合时不可用。WebSocket Host 覆盖映射为传输的
`Host` 头。冲突的别名或 Host 值必须拒绝。Multiplex 布尔值默认 `false`。原生 `h2mux`、
`yamux` 和 `smux` 支持 SS、VLESS、VMess 和 Trojan，可选择 sing-mux padding；省略协议时选择 `h2mux`。
`maxConnections` 最大为 256，`minStreams` 要求同时设置 `maxConnections`，`maxStreams`
与前两者互斥；h2mux 流数量上限为 4096，yamux 和 smux 均为 256。均未设置连接或流上限时可复用空闲连接，连接有活动流时
创建新连接。显式 packet encoding 或 UDP-over-TCP 与复用的组合保持不可用，不得静默忽略。

每个 smux 会话最多支持 256 条逻辑流，包括正在关闭的流；排队的接收载荷和发送 wire 帧
分别以 4 MiB 为上限。接收还限制为每流 256 KiB、每会话 1024 帧，发送限制为每会话 512 帧。
接收载荷在整帧分配释放前持续计入预算；这些队列预算不是进程总内存上限。流超过自身接收限制，
或共享接收预算受压时被选中隔离后，会话丢弃该流已缓冲数据、向该流返回资源错误并安排发送 FIN。
后续该流的数据会继续读取并丢弃，使其他流能够继续处理。

适配器无法观测缓冲载体内部的每次字节推进。因此存在活动流时，未完成的载体 I/O 没有 smux 驱动级
无进展超时；停滞的工作需要调用方或上层超时取消。最后一个流句柄释放后，会话的读写任务对待完成 I/O
共用一个绝对十秒排空期限。新流打开会取消期限，期限到达会终止会话；无其他工作的池内空闲会话
仍可保留至正常池回收。smux v1 FIN 遵循参考对端的整流关闭语义：收到对端 FIN 后先读尽已缓冲
数据，后续写入失败。本地 FIN 不保证目标看到 EOF 后产生的响应能够送达；smux MUST NOT 被
宣称为完全兼容 TCP 半关闭。

启用 multiplex padding 时，物理连接首先发送 sing-mux 版本 `1`、协议号（smux 为 `0`、yamux 为 `1`，
h2mux 为 `2`）、padding 标志 `1`、大端 `u16` padding 长度及相应数量的填充字节。
每个方向的前 16 条记录依次包含大端 `u16` 内容长度、大端 `u16` padding 长度、内容和
填充；该方向后续字节不再经过此 padding 层分帧。客户端为每条发出的带填充记录选择
256–767 个填充字节；截断的记录属于错误。
如果 multiplex UDP Association 在对端发送成功状态前关闭，关闭操作报告响应未确认，
不能报告成功。数据报可能已经到达目标；适配器 MUST NOT 重放它。

原生适配器凭据字段按协议区分。HTTP/SOCKS 使用 `username` 和 `password`；SS 使用 `cipher`、
`password` 和支持的插件字段，不支持的插件字段产生诊断。额外凭据键不得静默丢弃。敏感头、私钥、
密码、UUID 和完整导入文档必须保留在私有凭据中，不能成为管理员 label 或公共节点诊断。

类型化协议节点使用以下私有凭据字段；不在对应行中的字段必须拒绝，不得猜测或丢弃。
原生适配器执行最终协议验证。

| 协议 | 私有凭据字段 |
| --- | --- |
| `http`、`https` | `username`、`password`、可选私有 `http_path` |
| `socks5` | `username`、`password` |
| `vless`、`xtls` | `uuid`、`flow`、使用 Meek 时的 `meek_url` |
| `vmess` | `uuid`、`security` 或等价 `cipher`、`alter_id`、使用 Meek 时的 `meek_url` |
| `trojan`、`anytls` | `password`；Trojan-Go SS 加密还使用私有 `trojan_go_ss_method` 和 `trojan_go_ss_password` 字段 |
| `hysteria` | `auth` 或 `password`、`up_mbps`、`down_mbps`、`obfs`、`server_ports`、`hop_interval` |
| `hysteria2` | `password` 或等价的 `auth`、`obfs`、`obfs_password`、`gecko_min_packet_size`、`gecko_max_packet_size`、`server_ports`、`hop_interval`、`up_mbps`、`down_mbps` |
| `tuic` | `uuid`、`password`、`congestion_control`、`udp_relay_mode`、`heartbeat`、`zero_rtt_handshake`、`udp_over_stream` |
| `ssh` | `username`、`password`、`private_key`、`private_key_passphrase`、`host_key` |
| `shadowtls` | `password`、`version` |
| `snell` | `psk` 或等价 `password`、`userkey`、`version` |

`clientKeyField` 将引用的私有字段加入允许集合。冲突别名无效。其他协议字段在对应原生适配器
支持前保留为不可用诊断。TUIC 的 `heartbeat` 缺省时使用 10 秒间隔。

可以表示的 sing-box 代理节点会规范化为原生选项和凭据；包含无法表示
字段的节点会私下保留完整 `sing_box_outbound` 文档并带诊断保持不可用。selector、URL-test、
direct 和 block 条目不作为代理节点导入。导入文档不得触发隐式进程启动或 direct 回退。
SS 适配器原生实现 simple-obfs 的 `obfs`、`obfs-local` 和 `simple-obfs` HTTP/TLS 模式以及
v2ray-plugin WebSocket 模式；UDP 使用普通 Shadowsocks 数据报，显式启用 UDP-over-TCP 时除外。
其他插件与不支持的选项保持不可用，PathChord 不执行插件进程。

外部文档语法及私有凭据 JSON 保持来源格式。受支持的 Clash `client-fingerprint` 和 sing-box
`tls.utls.fingerprint` 规范化为原生 `tls.clientHelloFingerprint`；Clash 证书
`fingerprint` 则映射为不同的 `tls.certificateSha256`。外部 Host、early-data 和 UDP-over-TCP
字段继续由来源适配器规范化。原生键校验不得仅因某个名称与退役原生路径相同，就重写 HTTP 头、
协议标识、私有凭据字段或完整导入文档。

### 订阅文档类型

| `source.type` | 接受的文档类型 |
| --- | --- |
| `auto` | 识别下列受支持类型 |
| `clash` | Clash/Mihomo `proxies` 和 HTTP `proxy-providers` |
| `sip008` | SS JSON 数组，或包含 `servers` 的版本化对象 |
| `uri` | 明文或 Base64 编码的分享链接列表；百分号编码 URI 字段；VMess JSON 及旧版/SIP002 SS 形式 |
| `sing_box` | 原生支持的 sing-box 节点定义；不支持的文档私下保留并显示不可用诊断 |
| `surge`、`quantumult`、`loon` | 支持的节点列表及 proxy section 形式 |
| `static` | 管理员编写的节点；不进行远程订阅刷新 |

输入别名按以下方式规范化：`mihomo` 到 `clash`；`base64` 和 `v2ray` 到 `uri`；`sing-box` 和
`singbox` 到 `sing_box`；`quantumult_x` 和 `quantumult-x` 到 `quantumult`。导入只规范化节点
定义，不导入其他工具的路由规则、组、脚本或完整应用配置。识别分享链接格式不得表示其节点
协议可用。
Clash VLESS 省略 `packet-encoding` 或将其设为空，以及 sing-box VLESS 省略
`packet_encoding` 时默认使用 XUDP；启用 multiplex 时使用其 UDP 帧。sing-box 中显式空值
仅在既不使用 Vision 也不使用 multiplex 时表示普通 VLESS UDP；启用 multiplex 时使用其自身帧。
Vision 与显式空值的组合不可用。手写原生 VLESS 节点不启用 multiplex 且省略 `packetEncoding` 时，
不使用 Vision 则选择普通 VLESS UDP，使用 Vision 则选择 XUDP。V2Ray URI 的 `pinSHA256` 映射为 `certificateSha256`，`mport`
映射为 Hysteria2 端口范围；相同的 `sni`/`servername` 别名可同时使用，冲突别名无效。
默认 REALITY `spx=/` 不改变代理握手；自定义 spider 路径保持不可用，不得忽略。

格式错误的文档必须保留上一成功快照。单个节点格式错误、不受支持或不可用，不得丢弃有效的
兄弟节点。该节点必须保持不可选，并具有稳定错误码、字段名及脱敏消息。原始节点文本、包含
秘密的 URL 和凭据值不得出现在诊断中。私有缓存必须保留选项与诊断；重载不得把无效或不支持的
缓存节点变成可用节点。节点数量上限为 10,000，文档字节上限为 4 MiB。

缓存节点必须绑定订阅的来源类型、URL、凭据引用和有效 User-Agent；无法验证来源的缓存不得发布。任一来源字段
发生变化时，旧来源的节点进入排空，不得被新 flow 选择。缓存的来源标识不得暴露来源 URL 或
凭据值。根请求与所有引用的 HTTP provider 使用同一有效 User-Agent，未配置时默认为
`clash.meta`。旧版本中未绑定 User-Agent 的缓存无法证明其来源身份，不得发布。

来源绑定的规范化节点缓存使用 envelope 版本 `3` 和规范原生选项名。版本 2 的规范化缓存或包含任一退役原生选项路径的缓存都不兼容：必须返回有界、脱敏的 `cache_incompatible` 诊断，且不得从该缓存发布节点。加载器不得安装原生别名、丢弃字段、替换为默认值、部分解码节点或猜测私有凭据内容来继续使用不兼容缓存。版本 1 缓存仍属于无法验证来源的缓存，MUST NOT 发布。

拒绝不兼容缓存后，如果当前来源及生命周期下存在独立有效的活动快照，可以在有界认证刷新期间继续使用该快照。冷启动时若无该快照且来源离线，订阅保持不可用。刷新必须保留凭据 origin 和获取预算边界，并经过常规规范化、校验与适配器准备后才能发布。缓存加载、保留快照和过期刷新工作均不得复活已禁用、已删除、已替换来源或命中 tombstone 的节点。

### HTTP provider 展开

Provider 引用可以递归获取 HTTP(S) 节点文档，每次刷新最多 32 个引用、深度 3、正文总量
4 MiB。URL 不得带凭据；本地 file/path provider 必须拒绝。循环、不支持的 provider 类型、
获取失败、文档格式错误及预算耗尽必须产生 provider 诊断。Provider 刷新失败时保留它上一成功
节点；其他无关 provider 成功时仍可发布新数据。

只有 provider 与根订阅的 URL origin 相同时，才可以继承根订阅的 bearer 凭据。跨 origin
provider 不得收到该凭据。重定向处理必须保留此凭据边界。Provider 身份参与稳定节点 ID，避免
独立 provider 中相同显示名的节点彼此覆盖。

### 提供方用量元数据

`Subscription-Userinfo` 可以上报无符号的 `upload`、`download`、`total` 和 `expire`。
有效用量观测要求 upload/download；缺失或无效的可选值表示 unknown。剩余字节数为
`max(total - upload - download, 0)`；total 缺失或为零时比例未知。`expire` 是到期时间戳，
不是配额重置周期的证据。

`PathChord-Traffic-Multiplier` 是显式可选十进制数，最多四位小数，范围 `0.0001..=100`。
不得从节点名、URL、已用流量或剩余额度推断倍率。缺失或无效元数据不得伪造为零容量，也不得
成为硬连通性限制。观测与私有缓存必须跨刷新、重载保留这些事实。有效 quota/multiplier 可调整
选择权重和 Path economics，但不能覆盖授权、健康或显式策略。

### UDP 路由边界

普通 direct、SOCKS5 和 SS 路由可以使用原生 UDP 转发，包括 SS2022 数据报 Session 状态。
SOCKS5 relay 回复必须验证，TCP 控制连接必须持有到 Association 关闭。禁用节点 UDP 后必须
阻止新的普通 UDP Association。SOCKS 和 Shadowsocks UDP-over-TCP 将数据报封装在配置的代理
TCP 流中；配置 TLS 或 TCP 插件时也经过相应层。TLS SOCKS 节点不得静默发送明文 UDP；不支持的 `udp: true`
组合必须拒绝。
TUIC `udp_over_stream` 在经过认证的 QUIC stream 上使用 UoT v2，不能与显式
`udp_relay_mode` 同时配置。对端可施加小于协议 65,535 字节上限的数据包限制；不得静默截断。

通过 PathChord Egress 的 UDP 仍是 Session 数据报，由选定的字节流 Transit Path 承载。该能力
独立于第三方节点是否支持原生 UDP。仅仅在 TCP/TLS Path 上承载 Egress UDP Session，不得
要求原生 UDP 支持。不支持的普通 UDP 路由必须返回类型化路由失败，不能绕过策略。
