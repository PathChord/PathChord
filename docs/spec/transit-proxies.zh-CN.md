# Transit Proxy 适配器与订阅格式

[English](transit-proxies.md) | **简体中文**

本文档定义节点连接语义、订阅规范化、provider 展开及用量元数据。
[配置 schema](configuration-schema.zh-CN.md)定义资源外壳；
[平台规范](platform-and-dns.zh-CN.md)定义本地 HTTP、SOCKS 和 Mixed 监听器。
入站协议支持不得被解释为支持同名的出站节点协议。

## 适配器选择与失败

| 节点协议 | 原生传输 | 可选 sing-box 1.14.4 引擎 |
| --- | --- | --- |
| `direct` | TCP 和 UDP | 扩展拨号选项 |
| `http`、`https` | HTTP/1 CONNECT、Basic 认证、经过验证的额外头；HTTPS 使用 TLS | 支持的扩展节点选项 |
| `socks5` | CONNECT、用户名密码、UDP ASSOCIATE；TCP 可选 TLS | 支持的扩展节点选项 |
| `ss` | TCP/UDP；启用的经典 AEAD、旧 stream、扩展 AEAD 及 SS2022 算法 | 内置 `obfs-local`、`v2ray-plugin` wrapper 和支持的扩展选项 |
| `socks4`、`socks4a` | 无原生出站适配器 | CONNECT |
| `vless`、`vmess`、`xtls`、`trojan`、`hysteria`、`hysteria2`、`tuic`、`ssh`、`shadowtls`、`anytls` | 无原生适配器 | 必须通过引擎 schema 与传输验证 |
| `wireguard` | 无原生适配器 | 完整的用户态 WireGuard endpoint 文档 |
| `snell` | 无原生适配器 | 引擎支持的版本 4 和 6 |
| `ssr` 及未注册协议 | 不可用 | 未注册对应适配器时必须明确不可用 |

引擎是显式配置的本地可执行程序，固定为 sing-box 1.14.4。仅凭协议名不得将节点标为可用。
原生适配器必须校验消费的参数；引擎节点在发布到运行时之前，必须通过有界的版本与配置检查。
不支持的参数和缺失的引擎支持必须产生类型化、脱敏诊断。TLS 或传输配置失败时不得回退为
明文或 direct。

可选引擎持有一个采用随机认证的私有 loopback SOCKS 端点。节点配置通过 stdin 提供，不得
放入凭据命令参数或其他用户可读的文件。引擎输出不得泄露秘密。启动与就绪等待必须有界。
节点连接共享对应引擎进程；连接仍持有它时进程保持存活，最后一个所有者释放后必须终止并
回收进程。引擎状态目录必须为私有目录。

## 类型化连接选项

`TransitProxy.spec.options` 默认为空对象，字段使用 camelCase。未知字段属于配置错误；
导入的未知字段必须保留为不可用节点诊断，不得静默忽略。

| 字段 | 默认值与含义 |
| --- | --- |
| `tls` | 缺省；TLS 对象，字段为 `enabled`、`serverName`、`insecure`、`alpn`、`certificate`、`clientCertificate`、`clientKeyField`、`fingerprint`、`reality` |
| `transport` | 缺省；对象，字段为 `type`、`path`、`host`、`headers`、`serviceName`、`maxEarlyData`、`earlyDataHeaderName` |
| `headers` | `{}`；非秘密 HTTP CONNECT 头 |
| `udp` | 缺省；使用适配器能力；`false` 禁用普通 UDP 转发 |
| `multiplex` | 缺省；对象，字段为 `enabled`、`protocol`、`maxConnections`、`minStreams`、`maxStreams`、`padding` |
| `tcpFastOpen` | 缺省；可选布尔值 |
| `bindInterface` | 缺省；可选的本地接口名 |
| `routingMark` | 缺省；可选的无符号 32 位路由标记 |
| `packetEncoding` | 缺省；`xudp` 或 `packetaddr` |

TLS 布尔值默认 `false`；证书和 ALPN 列表默认空列表。`https` 隐含启用 TLS。Clash HTTP
节点的 `tls: true` 必须规范化为 HTTPS CONNECT。`serverName` 独立于连接地址覆盖证书/SNI
身份。原生 HTTPS CONNECT 允许 HTTP/1.1 ALPN。证书值是内联 PEM；客户端私钥只能从
`clientKeyField` 指定的 opaque credential 文档字段读取。除整个对象均为默认值外，禁用 TLS
时指定 TLS 设置无效。Reality 使用 `publicKey` 和 `shortId`；fingerprint/Reality 需要兼容的
引擎。`insecure` 是显式证书验证选项，不得在验证失败后自动采用。

传输 `type` 为 `tcp`、`ws`、`grpc`、`http`、`httpupgrade`、`quic` 或 `xhttp`；模型接受该值
不表示选定引擎支持它。普通 TCP 不接受 HTTP 传输参数。WebSocket Host 覆盖映射为传输的
`Host` 头。冲突的别名或 Host 值必须拒绝。Multiplex 布尔值默认 `false`；协议为 `smux`、
`yamux` 或 `h2mux`。不支持的组合必须验证失败。

原生适配器凭据字段按协议区分。HTTP/SOCKS 使用 `username` 和 `password`；SS 使用 `cipher`
和 `password`，plugin 字段只能由兼容引擎路径处理。额外凭据键不得静默丢弃。敏感头、私钥、
密码、UUID 和完整引擎文档必须保留在私有凭据中，不能成为管理员 label 或公共节点诊断。

类型化引擎节点使用以下私有凭据字段；不在对应行中的字段必须拒绝，不得猜测或丢弃。
选定引擎执行最终协议和版本验证。

| 协议 | 私有凭据字段 |
| --- | --- |
| `vless`、`xtls` | `uuid`、`flow` |
| `vmess` | `uuid`、`security` 或等价 `cipher`、`alter_id` |
| `trojan`、`anytls` | `password` |
| `hysteria` | `auth` 或 `password`、`up_mbps`、`down_mbps`、`obfs`、`server_ports`、`hop_interval` |
| `hysteria2` | `password`、`up_mbps`、`down_mbps`、`obfs`、`obfs_password`、`server_ports`、`hop_interval` |
| `tuic` | `uuid`、`password`、`congestion_control`、`udp_relay_mode`、`heartbeat`、`zero_rtt_handshake`、`udp_over_stream` |
| `ssh` | `username`、`password`、`private_key`、`private_key_passphrase`、`host_key` |
| `shadowtls` | `password`、`version` |
| `snell` | `psk` 或等价 `password`、`userkey`、`version` |

`clientKeyField` 将引用的私有字段加入允许集合。冲突别名无效。其他引擎字段必须使用完整
引擎节点文档，保留其自身 schema，不得将它缩减为类型化凭据子集。

凭据字段 `sing_box_outbound` 携带一份完整的引擎节点文档。它是权威源，不得与独立节点选项或
派生凭据字段混用。其类型和端点必须与规范化节点匹配。未知引擎字段必须原样进入引擎验证器。
导入文档不得引用本地文件、命令、外部 detour 或系统 WireGuard 接口；必须使用内联凭据和
用户态网络。网络传输路径仍然合法。SS plugin 名称仅限已注册的内置 wrapper；执行任意 plugin
不是节点能力。

## 订阅文档类型

| `source.type` | 接受的文档类型 |
| --- | --- |
| `auto` | 识别下列受支持类型 |
| `clash` | Clash/Mihomo `proxies` 和 HTTP `proxy-providers` |
| `sip008` | SS JSON 数组，或包含 `servers` 的版本化对象 |
| `uri` | 明文或 Base64 编码的分享链接列表；百分号编码 URI 字段；VMess JSON 及旧版/SIP002 SS 形式 |
| `sing_box` | 包含完整私有 outbound 参数的 sing-box 节点文档 |
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

## HTTP provider 展开

Provider 引用可以递归获取 HTTP(S) 节点文档，每次刷新最多 32 个引用、深度 3、正文总量
4 MiB。URL 不得带凭据；本地 file/path provider 必须拒绝。循环、不支持的 provider 类型、
获取失败、文档格式错误及预算耗尽必须产生 provider 诊断。Provider 刷新失败时保留它上一成功
节点；其他无关 provider 成功时仍可发布新数据。

只有 provider 与根订阅的 URL origin 相同时，才可以继承根订阅的 bearer 凭据。跨 origin
provider 不得收到该凭据。重定向处理必须保留此凭据边界。Provider 身份参与稳定节点 ID，避免
独立 provider 中相同显示名的节点彼此覆盖。

## 提供方用量元数据

`Subscription-Userinfo` 可以上报无符号的 `upload`、`download`、`total` 和 `expire`。
有效用量观测要求 upload/download；缺失或无效的可选值表示 unknown。剩余字节数为
`max(total - upload - download, 0)`；total 缺失或为零时比例未知。`expire` 是到期时间戳，
不是配额重置周期的证据。

`PathChord-Traffic-Multiplier` 是显式可选十进制数，最多四位小数，范围 `0.0001..=100`。
不得从节点名、URL、已用流量或剩余额度推断倍率。缺失或无效元数据不得伪造为零容量，也不得
成为硬连通性限制。观测与私有缓存必须跨刷新、重载保留这些事实。有效 quota/multiplier 可调整
选择权重和 Path economics，但不能覆盖授权、健康或显式策略。

## UDP 路由边界

普通 direct、SOCKS5 和 SS 路由可以使用原生 UDP 转发，包括 SS2022 数据报 Session 状态。
SOCKS5 relay 回复必须验证，TCP 控制连接必须持有到 Association 关闭。禁用节点 UDP 后必须
阻止新的普通 UDP Association。TLS SOCKS 节点不得静默发送明文 UDP；不支持的 `udp: true`
组合必须拒绝。

通过 PathChord Egress 的 UDP 仍是 Session 数据报，由选定的字节流 Transit Path 承载。该能力
独立于第三方节点是否支持原生 UDP。仅仅在 TCP/TLS Path 上承载 Egress UDP Session，不得
要求原生 UDP 支持。不支持的普通 UDP 路由必须返回类型化路由失败，不能绕过策略。
