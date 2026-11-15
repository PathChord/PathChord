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

订阅处理 SHALL 只规范化支持的节点定义，在保留单节点诊断的同时保留有效兄弟节点，在文档格式错误时保留上一成功快照，并执行详细契约中的节点数和字节数限制。私有缓存 SHALL 保留选项与诊断，并 SHALL 绑定来源类型、URL 和凭据引用；无法验证的缓存 SHALL NOT 发布，旧来源节点 SHALL 排空而不接受新 flow。

#### Scenario: One imported node is invalid

- **WHEN** 有效订阅文档同时包含无效或不支持的节点及有效节点
- **THEN** 有效兄弟节点被保留，无效节点保持不可选并带稳定脱敏诊断。

#### Scenario: Subscription source changes

- **WHEN** 订阅的来源类型、URL 或凭据引用改变
- **THEN** 旧来源的节点进入排空，不得被新 flow 选择。

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
| `socks5` | CONNECT、用户名密码、UDP ASSOCIATE；TCP 可选 TLS | 支持的扩展节点选项 |
| `ss` | 使用 AEAD 和 SS2022 算法的 TCP/UDP；旧 stream 算法会被拒绝 | 原生 AEAD/SS2022 选项；`obfs-local`、`v2ray-plugin` 及其他 plugin 参数产生不可用诊断 |
| `socks4`、`socks4a` | 无原生出站适配器 | CONNECT |
| `vless` | 带类型化 TLS/传输校验的 TCP、TLS、WebSocket 和 WSS 字节传输 | 扩展传输与 flow 选项 |
| `vmess` | TCP、TLS、WebSocket/WSS、AES-128-GCM 或 ChaCha20-Poly1305 正文记录、单目标 UDP、`alter_id: 0` | mux、旧式非 AEAD 安全方式及其他不支持的扩展选项 |
| `trojan` | TLS 封装的 TCP、WebSocket 和 WSS 字节传输 | 扩展传输选项 |
| `anytls` | TLS 流、认证、settings、SYN/SYNACK、PUSH/FIN、heartbeat 帧及有界 UDP-over-TCP 数据报 | 原生帧契约之外的扩展 session 选项 |
| `hysteria2` | 原生 QUIC/TLS + HTTP/3 认证、TCP/UDP relay、Salamander 或无混淆传输及有界 server-port 跳转 | 带宽限制字段、Gecko 专用混淆和其他不支持的扩展选项 |
| `tuic` | 原生 QUIC/TLS-exporter TCP CONNECT、UDP DATAGRAM relay、heartbeat 及可选的有重放风险 0-RTT | 不支持的拥塞控制器、UDP-over-stream 及其他扩展选项 |
| `vless` + `tls.reality` | 使用 X25519 ClientHello proof 和证书 proof 校验的原生 VLESS over REALITY TLS | Vision flow 和不支持的外层传输 |
| `xtls`、`hysteria`、`ssh`、`shadowtls` | 无原生适配器 | 类型化不可用诊断 |
| `wireguard` | 无原生适配器 | 完整的用户态 WireGuard endpoint 文档 |
| `snell` | 无原生适配器 | 类型化不可用诊断 |
| `ssr` 及未注册协议 | 不可用 | 明确不可用 |

仅凭协议名不得将节点标为可用。原生适配器必须在发布到运行时之前校验消费的参数。不支持的
参数和未实现的协议必须产生类型化、脱敏诊断。TLS 或传输配置失败时不得回退为明文或 direct。

原生 VLESS 和 Trojan 适配器会在打开 socket 前拒绝不支持的 flow、multiplex、packet 和传输
选项。原生 VMess 只接受 AEAD 正文密码和 `alter_id: 0`；mux 仍不可用。REALITY 需要原生
ClientHello proof callback，不能单独启用 Vision flow。表中的协议行本身不表示包含不支持参数的
节点可选。

### 类型化连接选项

`TransitProxy.spec.options` 默认为空对象，字段使用 camelCase。未知字段属于配置错误；
导入的未知字段必须保留为不可用节点诊断，不得静默忽略。

| 字段 | 默认值与含义 |
| --- | --- |
| `tls` | 缺省；TLS 对象，字段为 `enabled`、`serverName`、`insecure`、有序 `truststore`、`alpn`、`certificate`、`clientCertificate`、`clientKeyField`、`fingerprint`、`reality` |
| `transport` | 缺省；对象，字段为 `type`、`path`、`host`、`headers`、`serviceName`、`maxEarlyData`、`earlyDataHeaderName` |
| `headers` | `{}`；非秘密 HTTP CONNECT 头 |
| `udp` | 缺省；使用适配器能力；`false` 禁用普通 UDP 转发 |
| `multiplex` | 缺省；对象，字段为 `enabled`、`protocol`、`maxConnections`、`minStreams`、`maxStreams`、`padding` |
| `tcpFastOpen` | 缺省；可选布尔值 |
| `bindInterface` | 缺省；可选的本地接口名 |
| `routingMark` | 缺省；可选的无符号 32 位路由标记 |
| `packetEncoding` | 缺省；`xudp` 或 `packetaddr` |

TLS 布尔值默认 `false`；truststore 默认 `["system"]`，证书和 ALPN 列表默认空列表。每个 truststore
来源必须是 `system` 或本地 PEM/DER 文件；相对路径从选定配置来源解析，允许绝对路径，符号链接目标
必须是普通文件，空列表表示没有信任锚点。任一无效、超大或格式错误来源都必须原子拒绝适配器。
`https` 隐含启用 TLS。Clash HTTP
节点的 `tls: true` 必须规范化为 HTTPS CONNECT。`serverName` 独立于连接地址覆盖证书/SNI
身份。原生 HTTPS CONNECT 允许 HTTP/1.1 ALPN。证书值是内联 PEM；客户端私钥只能从
`clientKeyField` 指定的 opaque credential 文档字段读取。除整个对象均为默认值外，禁用 TLS
时指定 TLS 设置无效。Reality 使用 `publicKey` 和 `shortId`；fingerprint/Reality 需要兼容的
原生 Reality 适配器。`insecure` 是显式证书验证选项，不得在验证失败后自动采用。

传输 `type` 为 `tcp`、`ws`、`grpc`、`http`、`httpupgrade`、`quic` 或 `xhttp`；模型接受该值
不表示原生适配器支持它。普通 TCP 不接受 HTTP 传输参数。WebSocket Host 覆盖映射为传输的
`Host` 头。冲突的别名或 Host 值必须拒绝。Multiplex 布尔值默认 `false`；协议为 `smux`、
`yamux` 或 `h2mux`。不支持的组合必须验证失败。

原生适配器凭据字段按协议区分。HTTP/SOCKS 使用 `username` 和 `password`；SS 使用 `cipher`
和 `password`。原生适配器拒绝 SS plugin 字段并报告诊断。额外凭据键不得静默丢弃。敏感头、私钥、
密码、UUID 和完整导入文档必须保留在私有凭据中，不能成为管理员 label 或公共节点诊断。

类型化协议节点使用以下私有凭据字段；不在对应行中的字段必须拒绝，不得猜测或丢弃。
原生适配器执行最终协议验证。

| 协议 | 私有凭据字段 |
| --- | --- |
| `vless`、`xtls` | `uuid`、`flow` |
| `vmess` | `uuid`、`security` 或等价 `cipher`、`alter_id` |
| `trojan`、`anytls` | `password` |
| `hysteria` | `auth` 或 `password`、`up_mbps`、`down_mbps`、`obfs`、`server_ports`、`hop_interval` |
| `hysteria2` | `password`、`obfs`、`obfs_password`、`server_ports`、`hop_interval` |
| `tuic` | `uuid`、`password`、`congestion_control`、`udp_relay_mode`、`heartbeat`、`zero_rtt_handshake`、`udp_over_stream` |
| `ssh` | `username`、`password`、`private_key`、`private_key_passphrase`、`host_key` |
| `shadowtls` | `password`、`version` |
| `snell` | `psk` 或等价 `password`、`userkey`、`version` |

`clientKeyField` 将引用的私有字段加入允许集合。冲突别名无效。其他协议字段在对应原生适配器
支持前保留为不可用诊断。完整 `sing_box_outbound` 文档
只作为导入节点的 opaque 诊断数据保留，不提供原生适配器，也不会被 PathChord 执行。导入文档
不得触发隐式进程启动或 direct 回退。SS plugin 字段会保留用于诊断，并由原生适配器拒绝；
PathChord 不执行 plugin 进程，也不提供隐式 wrapper。

### 订阅文档类型

| `source.type` | 接受的文档类型 |
| --- | --- |
| `auto` | 识别下列受支持类型 |
| `clash` | Clash/Mihomo `proxies` 和 HTTP `proxy-providers` |
| `sip008` | SS JSON 数组，或包含 `servers` 的版本化对象 |
| `uri` | 明文或 Base64 编码的分享链接列表；百分号编码 URI 字段；VMess JSON 及旧版/SIP002 SS 形式 |
| `sing_box` | 导入的 sing-box 节点文档；保留为不可用诊断 |
| `surge`、`quantumult`、`loon` | 支持的节点列表及 proxy section 形式 |
| `static` | 管理员编写的节点；不进行远程订阅刷新 |

输入别名按以下方式规范化：`mihomo` 到 `clash`；`base64` 和 `v2ray` 到 `uri`；`sing-box` 和
`singbox` 到 `sing_box`；`quantumult_x` 和 `quantumult-x` 到 `quantumult`。导入只规范化节点
定义，不导入其他工具的路由规则、组、脚本或完整应用配置。识别分享链接格式不得表示其节点
协议可用。

格式错误的文档必须保留上一成功快照。单个节点格式错误、不受支持或不可用，不得丢弃有效的
兄弟节点。该节点必须保持不可选，并具有稳定错误码、字段名及脱敏消息。原始节点文本、包含
秘密的 URL 和凭据值不得出现在诊断中。私有缓存必须保留选项与诊断；重载不得把无效或不支持的
缓存节点变成可用节点。节点数量上限为 10,000，文档字节上限为 4 MiB。

缓存节点必须绑定订阅的来源类型、URL 和凭据引用；无法验证来源的缓存不得发布。任一来源字段
发生变化时，旧来源的节点进入排空，不得被新 flow 选择。缓存的来源标识不得暴露来源 URL 或
凭据值。

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
阻止新的普通 UDP Association。TLS SOCKS 节点不得静默发送明文 UDP；不支持的 `udp: true`
组合必须拒绝。

通过 PathChord Egress 的 UDP 仍是 Session 数据报，由选定的字节流 Transit Path 承载。该能力
独立于第三方节点是否支持原生 UDP。仅仅在 TCP/TLS Path 上承载 Egress UDP Session，不得
要求原生 UDP 支持。不支持的普通 UDP 路由必须返回类型化路由失败，不能绕过策略。
