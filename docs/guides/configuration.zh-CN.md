# 配置指南

[English](configuration.md) | **简体中文**

先选择最接近路由目标的示例，再根据维护需要将资源拆分到不同文件。本指南说明配置操作方法；字段、默认值和验证规则的权威定义见[配置 schema](../../openspec/specs/configuration-schema/spec.zh-CN.md)。

## 选择起始示例

| 目标 | 示例 | 需要调整的内容 |
| --- | --- | --- |
| 为本机提供 HTTP/SOCKS 代理并直连目标 | [ingress-direct.yaml](../../examples/ingress-direct.yaml) | Mixed 监听器绑定 `127.0.0.1:7890`；DNS 使用配置的本地解析器，未匹配流量直接连接。 |
| 使用订阅提供的普通代理节点 | [ingress-subscriptions.yaml](../../examples/ingress-subscriptions.yaml) | 替换 provider URL。ProxyRule 选择可用节点；回退策略拒绝未匹配流量。 |
| 经已注册的 Egress 转发 | [ingress-egress.yaml](../../examples/ingress-egress.yaml) | 设置 Egress 地址和已核验的公钥，然后按照[部署指南](deployment.zh-CN.md)完成注册。 |
| Egress 服务上限和私有路径 | [egress-service.yaml](../../examples/egress-service.yaml) | 只将此来源交给 `pathchord-egressd`；身份和数据库路径必须位于资源树之外。 |
| Linux 透明 TCP/UDP 接管 | [ingress-tproxy.yaml](../../examples/ingress-tproxy.yaml) | 检查监听地址、包标记、路由表和主机包过滤设置。 |
| 使用可选 eBPF classifier 的 Linux 接管 | [ingress-tproxy-ebpf.yaml](../../examples/ingress-tproxy-ebpf.yaml) | 将 `lan0` 和 `192.168.1.0/24` 替换为实际入口接口和允许的来源网段。 |
| 从 TUN 接口接入 TCP/UDP flow | [ingress-tun.yaml](../../examples/ingress-tun.yaml) | 检查接口名称、`198.18.0.1/30` 地址、平台支持和主机路由。 |

透明和 TUN 示例需要平台特权及主机路由设置。[部署指南](deployment.zh-CN.md)说明这些前提、服务启动和注册命令。FreeBSD 支持显式 HTTP、SOCKS 和 Mixed 监听器；其平台契约不包含透明和 TUN 监听器。

## 选择配置来源

将角色可执行文件放入 `PATH` 后，选择以下命令之一。示例路径相对于仓库根目录；目录占位路径需替换为自己的资源目录。

```sh
pathchord-ingressd --config examples/ingress-direct.yaml
pathchord-ingressd --config-dir /path/to/ingress
PATHCHORD_CONFIG_DIR=/path/to/ingress pathchord-ingressd
pathchord-egressd --config examples/egress-service.yaml
```

配置来源按以下顺序选择：

1. 显式 `--config`（`-c`）或 `--config-dir`（`-C`）。两者只能选一个：`--config` 接受文件或目录，`--config-dir` 要求目录。显式命令行来源覆盖配置环境变量，也覆盖两个环境变量之间的冲突。
2. 非空的 `PATHCHORD_CONFIG` 或 `PATHCHORD_CONFIG_DIR`，文件/目录语义与对应命令行选项相同。未提供显式来源时，只设置其中一个。
3. 角色账号默认值：Ingress 使用 `~/.config/pathchord/ingress` 或 `/etc/pathchord/ingress`，Egress 使用 `~/.config/pathchord/egress` 或 `/etc/pathchord/egress`。不会回退查找工作目录中的配置。[来源选择契约](../../openspec/specs/configuration-schema/spec.zh-CN.md#配置来源)定义账号分类和主目录解析规则。

原生服务软件包可能在服务命令中显式选择配置目录；修改已安装部署时，先检查实际服务定义。

## 组织一张资源图

一个文件可以像示例那样，用 `---` 分隔多个 YAML 文档。一个目录也可以把相同资源放入不同 `.yaml`、`.yml` 和 `.json` 文件，包括子目录。所有文件共同构成一份配置，因此每套完整部署应使用独立目录，避免把多份完整示例直接放到一起。

最基本的 direct 示例包含三个资源：

- `Listener` 决定应用如何进入 PathChord。示例中的 `mixed` 监听器在同一 TCP 端点接受 HTTP 和 SOCKS；SOCKS5 UDP 使用其协商的 relay 端点。服务本机应用时保留回环绑定；对其他主机开放前，配置合适的来源限制和认证。
- `DNSPolicy` 决定 DNS 查询如何到达解析器，独立于普通连接路由。修改 `local.servers` 可以使用自己的解析器；其他路由见[平台与 DNS 契约](../../openspec/specs/platform-and-dns/spec.zh-CN.md#dns-配置)。
- `FallbackPolicy` 决定没有前序路由胜出时如何处理。明确需要直连回退时使用 `direct`，需要拒绝未匹配 flow 时使用 `reject`。

通过订阅提供节点的普通第三方代理路由需要增加 `Subscription` 和 `ProxyRule` 资源。受控 Egress 路由需要增加 `Egress`、`EgressRule`、公共 `transit` 绑定和合适的 `TrafficPolicy`。路由先考虑有效 Egress 规则，再考虑普通 Proxy 规则，最后使用全局回退。选择同一 Egress 的 flow 共享该 Egress 的 Session Path 池和 TrafficPolicy。资源关系见[配置模型](../../openspec/specs/configuration/spec.zh-CN.md)；支持的节点选项和订阅格式见[Transit Proxy 契约](../../openspec/specs/transit-proxies/spec.zh-CN.md)。

资源通过所属 namespace 内的 `metadata.name` 相互引用。名称和显式规则顺序决定资源图；文件名不提供覆写层。重复资源身份或无法解析的引用会使候选配置被拒绝。完整资源图中保留恰好一个 `DNSPolicy` 和一个 `FallbackPolicy`。

## 使用 geosite 和 geoip 集合路由

Geosite 和 geoip 使用由运维人员提供的 V2Fly 数据库。从固定版本的
[domain-list-community 发布页](https://github.com/v2fly/domain-list-community/releases)获取
`dlc.dat`，并从 [v2fly/geoip 发布页](https://github.com/v2fly/geoip/releases)获取
`geoip.dat`。从同一发布版本下载各自的 `*.sha256sum`，在下载目录中用
`sha256sum -c` 校验。将校验成功的 `.dat` 文件放到 Ingress 服务账号可读取的位置，
并保留上一版已校验文件以便回滚。PathChord 读取本地文件，不会自动下载或更新这些数据库。

例如，将以下版本标签占位符替换为所选发布版本，并在私有暂存目录中执行：

```sh
site_tag=REPLACE_WITH_DOMAIN_LIST_RELEASE_TAG
ip_tag=REPLACE_WITH_GEOIP_RELEASE_TAG
curl -fsSLO "https://github.com/v2fly/domain-list-community/releases/download/${site_tag}/dlc.dat"
curl -fsSLO "https://github.com/v2fly/domain-list-community/releases/download/${site_tag}/dlc.dat.sha256sum"
curl -fsSLO "https://github.com/v2fly/geoip/releases/download/${ip_tag}/geoip.dat"
curl -fsSLO "https://github.com/v2fly/geoip/releases/download/${ip_tag}/geoip.dat.sha256sum"
sha256sum -c dlc.dat.sha256sum
sha256sum -c geoip.dat.sha256sum
```

在完整配置中加入以下资源和规则；该配置还应已定义 Egress `egress-jp-1`、公共 Transit
绑定和 TrafficPolicy：

```yaml
apiVersion: pathchord.io/v1
kind: GeoSiteDatabase
metadata: {name: sites}
spec: {path: /var/lib/pathchord/geodata/dlc.dat}
---
apiVersion: pathchord.io/v1
kind: GeoIpDatabase
metadata: {name: addresses}
spec: {path: /var/lib/pathchord/geodata/geoip.dat}
---
apiVersion: pathchord.io/v1
kind: EgressRule
metadata: {name: huggingface-egress}
spec:
  order: 10
  match:
    targetGeoSites: [huggingface]
  egressRef: egress-jp-1
---
apiVersion: pathchord.io/v1
kind: EgressRule
metadata: {name: geoip-example}
spec:
  order: 20
  match:
    targetGeoIps: [cn]
  egressRef: egress-jp-1
```

第一条规则覆盖上游 `huggingface` 集合中的域名，包括 `hf.co` 的子域名
`us.aws.cdn.hf.co`。第二条规则演示以 IP 为目标的 flow；请按自己的策略选择集合和
Egress。数据库与使用它的规则属于同一 namespace。Geosite 也可以使用 `set@attribute`
选择属性，例如已校验数据库中存在该属性时可使用 `google@ads`。匹配类型见
[geodata 契约](../../openspec/specs/geodata-routing/spec.zh-CN.md)，限制和字段规则见
[配置 schema](../../openspec/specs/configuration-schema/spec.zh-CN.md#geodata-数据库)。

相应字段也接受显式形式 `geosite:huggingface` 和 `geoip:cn`；它们分别引用与上述短名称
相同的集合。

Geosite 使用监听器提供的原始主机名。GeoIP 使用原始目标 IP，例如透明 flow 的目标地址。
只提供主机名的请求不会通过 DNS 查询获得 GeoIP 匹配；只提供 IP 的 flow 不会获得 geosite
匹配。同一 match 字段内的值互为备选，不同的非空 match 字段组合求值。如果主机名集合或
IP 集合任一匹配即可选路，应使用多条有序规则。`targetHosts` 保持精确匹配语义。

数据库文件应放在扫描的配置目录之外，或使用 `.dat` 等不被扫描的扩展名。相对数据库路径
从选定配置文件的父目录或选定配置目录解析。更新时，先单独下载并校验新版本，再原子替换
配置的文件。Ingress 验证完整候选后，将规则与数据一起发布。如果验证失败，检查重载状态；
上一代配置保持生效。回滚时，原子恢复上一份已校验文件及相应配置，再检查重载状态和实际路由。

## 单独存放凭据

将私有身份、节点/监听器凭据 JSON、订阅缓存和服务数据目录放在资源树外。目录加载器也会读取 JSON，因此将私有 JSON 文档混入配置资源可能使整个配置集合无效。使用不透明的 `credentialsRef` 引用本地凭据存储。不要把密码和订阅 token 写入已提交的示例；含凭据的 provider URL 应按私有配置处理。

订阅服务器可能根据 HTTP 客户端返回不同格式。可以在 Subscription 的 `spec.source.userAgent`
中设置提供方要求的值；默认值为 `clash.meta`。改变该值会触发新来源刷新，不会复用使用其他值获取的缓存。

凭据文件的设置方法见[部署指南](deployment.zh-CN.md)。[Transit Proxy 契约](../../openspec/specs/transit-proxies/spec.zh-CN.md)定义各选项由哪个适配器消费，以及如何报告不支持的节点。导入订阅后应检查单节点诊断；仅导入了协议名称并不代表节点可用。

Hysteria2 Gecko 可使用私有凭据中的可选字段 `gecko_min_packet_size` 和
`gecko_max_packet_size` 选择长头分片的填充范围；字段缺省或为零时分别使用 512 和 1200 字节。
对端需要接受所选的线上包长。本地测试中 sing-box 1.14.4 对端可以交换固定 1452 字节的
Gecko 包，但其 2048 字节设置无法完成握手；独立 sing-quic relay 可以接受 2048 字节。
所选包长还必须适合网络路径。Linux 上 PathChord 的 QUIC socket 禁止 IP 分片；在 MTU 为
1500 字节且没有额外封装时，IPv4 的 UDP 载荷超过 1472 字节或 IPv6 的 UDP 载荷超过
1452 字节就无法装入一个 IP 包。这类 Gecko 分片可能被丢弃，表现为握手超时。隧道或更小的
路径 MTU 可能要求更低的设置。本地 2048 字节 relay 测试使用回环接口，不能证明该设置适用于
1500 字节的路径。

SOCKS5 或 Shadowsocks UDP-over-TCP 可将 `spec.options.udpOverTcp` 设为 `1` 或 `2`；省略时
使用适配器的普通 UDP 传输。导入的 Clash 节点启用 UDP-over-TCP 但省略版本时使用 v1，
导入的 sing-box 节点使用 v2；还要确保节点启用了 UDP。VMess 的 `spec.options.vmess.globalPadding` 和 `authenticatedLength` 用于启用
对应的 AEAD 帧选项。Meek 节点使用 `spec.options.transport.type: meek`，完整 URL 放在凭据
JSON 的私有 `meek_url` 字段中。HTTP CONNECT 请求路径同样放在私有 `http_path` 凭据字段中。
不要将这些 URL 和路径放入公开资源文档。

Shadowsocks、VLESS、VMess 或 Trojan 节点可以将 `spec.options.multiplex.enabled` 设为
`true`，并在 `spec.options.multiplex.protocol` 中选择 `h2mux`、`yamux` 或 `smux`；省略协议时使用
`h2mux`。Multiplex 不能与显式 `packetEncoding` 或 `udpOverTcp` 同时使用；对端要求 sing-mux
padding 时，将 `spec.options.multiplex.padding` 设为 `true`。
不可用的组合会在节点诊断中说明。导入的 Clash/Mihomo 和 sing-box VLESS 节点通常默认使用 XUDP，
启用 multiplex 后使用其 UDP 帧。手写的 VLESS 节点不启用 multiplex 且省略 `packetEncoding` 时，
普通节点使用 VLESS UDP，设置 Vision flow 的节点使用 XUDP。Vision 不能使用 `packetaddr`；
节点需要承载到 UDP 443 端口的流量时，应使用 `xtls-rprx-vision-udp443` flow。
如果 multiplex UDP Association 在对端确认前关闭，关闭操作会报错，但已发送的数据报可能已经到达目标。

只有应用能够接受整流关闭语义时才使用 `smux`：FIN 不提供可靠的 TCP 写端半关闭，目标在
该 FIN 后发送的响应可能无法到达。每个 smux 会话最多支持 256 条流，接收和发送队列各有
4 MiB 预算。慢接收流可能以资源错误关闭并发送 FIN，以便其他流继续运行。活动流所在的载体
停滞时需要调用方或上层超时取消；最后一条流释放后，待完成 I/O 共用十秒的排空期限。完整限制和失败语义见
[Transit Proxy 契约](../../openspec/specs/transit-proxies/spec.zh-CN.md)。

Hysteria2 的 `up_mbps` 和 `down_mbps` 是私有凭据中可选的非负整数 Mbps 字段。
`down_mbps` 是接收速率提示，服务端可以忽略。上传设置参与认证协商：例如配置
`up_mbps: 10` 时，服务端返回数值零会选择 10 Mbps 的 Brutal 目标，返回正数则选择两者中
较小的速率。`up_mbps` 缺省或为零时，即使服务端返回正数速率，客户端也使用 BBR。服务端
返回 `auto` 时，无论 `up_mbps` 如何配置，客户端同样使用 BBR。

Trojan-Go 分享链接会规范化为原生 Trojan 适配器。原始/TCP、WebSocket、gRPC 和
HTTPUpgrade 形式在已验证的选项范围内支持。WebSocket SS 加密使用私有凭据
`trojan_go_ss_method` 和 `trojan_go_ss_password`，支持 AES-128-GCM、AES-256-GCM
和 ChaCha20-IETF-Poly1305。带此加密的原始/TCP 暂不可用：参考 Trojan-Go 服务端的
HTTP 请求嗅探在短加密流上可能无限等待。不支持的组合会保留为带诊断的不可用节点。

Brutal 会补偿丢包，正常经过 pacing 的 QUIC 发包速率最高可达目标的 1.25 倍。PTO 探测包和
纯 ACK 包可以绕过 pacing，突发和外层协议开销也会增加流量。因此该设置既不是严格的物理
带宽上限，也不是吞吐保证；极短 RTT 和 ACK 时序也可能降低实际速率。完整协商规则和选项边界
见 [Transit Proxy 契约](../../openspec/specs/transit-proxies/spec.zh-CN.md)。

## 配置 Egress 资源上限

Egress 来源必须包含恰好一个 `EgressService`，不能包含 Ingress listener、Transit Proxy、subscription、routing、DNS、fallback 或 geodata 资源。可以从 [egress-service.yaml](../../examples/egress-service.yaml) 开始。`EgressService` authored 配置只提供全局资源上限
`maxWireBandwidthBps` 和 `maxInboundTargetConnections`。Egress 运行时结合这些上限和本地
profile 计算 Path 安全上限及 pending reservation。不要再配置
`recommendedPathCount`、`maxConcurrentPaths` 或 `maxStreamsPerIngress`；Path target 属于
Ingress 规则和运行时观测。STATUS_REPORT 提供配置/有效/当前容量、容量可信度、准入状态和当前复制
allowance；公共 Path 最小值位于 Ingress 侧 Egress 的 `statusRequirements.minUsablePaths`，
target 由 Session 运行时决定，不携带规则或 TrafficClass 元数据。

`EgressService` 可以使用 `binds` 配置多个公共 Path listener，包括在不同端口上的 IPv4 和 IPv6
地址。旧的单数 `bind` 仍然是一个 listener 的简写。Ingress 侧在同一个 Egress ID 有多个可达域名或
端口时使用 `endpoints`；每项包含 `address` 和 `port`。旧的 `address`/`port` 仍然是单个 endpoint
的简写。所有 bind 和 endpoint 必须使用相同的 Egress ID、identity、公钥和授权数据库。endpoint
拓扑属于启动配置，变化后需要重启。

支持 TLS 的 Transit 节点默认使用系统根证书。需要自定义根时，将有序 `truststore` 列表设置为
`system` 和/或本地 PEM/DER 文件。相对路径从选定的配置来源解析。空列表表示明确不加载信任锚点，
只有 `insecure: true` 才能绕过证书校验。无效、过大、目录或错误符号链接来源会拒绝节点，不会降级
为其他传输方式。

## 重载配置与处理失败

服务会监听选定资源目录中的新增、编辑、移除和重命名，并在发布前验证完整候选配置。支持原子替换文件。解析、资源图验证、规则编译、持久化或缓存写入失败时，最近一次成功配置继续生效；通过结构化 status 查看失败，修正候选后等待重新加载。

订阅节点、编译后的动态规则、管理员 label/tag 和 DNS 运行时健康可以动态更新。静态 Egress 拓扑、Transit 绑定、公共 Path 要求、已解析 TrafficPolicy、本地私钥、监听器绑定设置或平台路由设置发生变化时，需要重启服务。将未改变的资源移到其他文件不会改变其身份，也不需要重启。新 flow 在完整路由决策中使用同一已发布代次；现有资源遵循准入时的契约及正常排空/失败规则。

声明式订阅通过管理操作发生的变更，在其声明未改变时会跨重载和重启继续生效。编辑或移除声明时，应用对应的新期望状态。精确的发布和所有权规则见[重载契约](../../openspec/specs/configuration-schema/spec.zh-CN.md#快照发布和重载)。
