# 配置指南

[English](configuration.md) | **简体中文**

先选择最接近路由目标的示例，再根据维护需要将资源拆分到不同文件。本指南说明配置操作方法；字段、默认值和验证规则的权威定义见[配置 schema](../../openspec/specs/configuration-schema/spec.zh-CN.md)。

## 选择起始示例

| 目标 | 示例 | 需要调整的内容 |
| --- | --- | --- |
| 为本机提供 HTTP/SOCKS 代理并直连目标 | [ingress-direct.yaml](../../examples/ingress-direct.yaml) | Mixed 监听器绑定 `127.0.0.1:7890`；DNS 使用配置的本地解析器，未匹配流量直接连接。 |
| 使用订阅提供的普通代理节点 | [ingress-subscriptions.yaml](../../examples/ingress-subscriptions.yaml) | 替换 provider URL。ProxyRule 选择可用节点；回退策略拒绝未匹配流量。 |
| 经已注册的 Egress 转发 | [ingress-egress.yaml](../../examples/ingress-egress.yaml) | 设置 Egress 地址和已核验的公钥，然后按照[部署指南](deployment.zh-CN.md)完成注册。 |
| Linux 透明 TCP/UDP 接管 | [ingress-tproxy.yaml](../../examples/ingress-tproxy.yaml) | 检查监听地址、包标记、路由表和主机包过滤设置。 |
| 使用可选 eBPF classifier 的 Linux 接管 | [ingress-tproxy-ebpf.yaml](../../examples/ingress-tproxy-ebpf.yaml) | 将 `lan0` 和 `192.168.1.0/24` 替换为实际入口接口和允许的来源网段。 |
| 从 TUN 接口接入 TCP/UDP flow | [ingress-tun.yaml](../../examples/ingress-tun.yaml) | 检查接口名称、`198.18.0.1/30` 地址、平台支持和主机路由。 |

透明和 TUN 示例需要平台特权及主机路由设置。[部署指南](deployment.zh-CN.md)说明这些前提、服务启动和注册命令。FreeBSD 支持显式 HTTP、SOCKS 和 Mixed 监听器；其平台契约不包含透明和 TUN 监听器。

## 选择配置来源

将 `pathchord` 放入 `PATH` 后，选择以下命令之一。示例路径相对于仓库根目录；目录占位路径需替换为自己的资源目录。

```sh
pathchord ingress --config examples/ingress-direct.yaml
pathchord ingress --config-dir /path/to/conf.d
PATHCHORD_CONFIG_DIR=/path/to/conf.d pathchord ingress
pathchord ingress
```

配置来源按以下顺序选择：

1. 显式 `--config`（`-c`）或 `--config-dir`（`-C`）。两者只能选一个：`--config` 接受文件或目录，`--config-dir` 要求目录。显式命令行来源覆盖配置环境变量，也覆盖两个环境变量之间的冲突。
2. 非空的 `PATHCHORD_CONFIG` 或 `PATHCHORD_CONFIG_DIR`，文件/目录语义与对应命令行选项相同。未提供显式来源时，只设置其中一个。
3. 账号默认值：普通用户使用 `~/.config/pathchord`，root/服务账号使用 `/etc/pathchord`。不会回退查找工作目录中的配置。[来源选择契约](../../openspec/specs/configuration-schema/spec.zh-CN.md#配置来源)定义账号分类和主目录解析规则。

原生服务软件包可能在服务命令中显式选择配置目录；修改已安装部署时，先检查实际服务定义。

## 组织一张资源图

一个文件可以像示例那样，用 `---` 分隔多个 YAML 文档。一个目录也可以把相同资源放入不同 `.yaml`、`.yml` 和 `.json` 文件，包括子目录。所有文件共同构成一份配置，因此每套完整部署应使用独立目录，避免把多份完整示例直接放到一起。

最基本的 direct 示例包含三个资源：

- `Listener` 决定应用如何进入 PathChord。示例中的 `mixed` 监听器在同一 TCP 端点接受 HTTP 和 SOCKS；SOCKS5 UDP 使用其协商的 relay 端点。服务本机应用时保留回环绑定；对其他主机开放前，配置合适的来源限制和认证。
- `DNSPolicy` 决定 DNS 查询如何到达解析器，独立于普通连接路由。修改 `local.servers` 可以使用自己的解析器；其他路由见[平台与 DNS 契约](../../openspec/specs/platform-and-dns/spec.zh-CN.md#dns-配置)。
- `FallbackPolicy` 决定没有前序路由胜出时如何处理。明确需要直连回退时使用 `direct`，需要拒绝未匹配 flow 时使用 `reject`。

通过订阅提供节点的普通第三方代理路由需要增加 `Subscription` 和 `ProxyRule` 资源。受控 Egress 路由需要增加 `Egress`、`EgressRule`、`TransitRule` 和合适的 `TrafficPolicy`。路由先考虑有效 Egress 规则，再考虑普通 Proxy 规则，最后使用全局回退。资源关系见[配置模型](../../openspec/specs/configuration/spec.zh-CN.md)；支持的节点选项和订阅格式见[Transit Proxy 契约](../../openspec/specs/transit-proxies/spec.zh-CN.md)。

资源通过所属 namespace 内的 `metadata.name` 相互引用。名称和显式规则顺序决定资源图；文件名不提供覆写层。重复资源身份或无法解析的引用会使候选配置被拒绝。完整资源图中保留恰好一个 `DNSPolicy` 和一个 `FallbackPolicy`。

## 单独存放凭据

将私有身份、节点/监听器凭据 JSON、订阅缓存和服务数据目录放在资源树外。目录加载器也会读取 JSON，因此将私有 JSON 文档混入配置资源可能使整个配置集合无效。使用不透明的 `credentialsRef` 引用本地凭据存储。不要把密码和订阅 token 写入已提交的示例；含凭据的 provider URL 应按私有配置处理。

凭据文件的设置方法见[部署指南](deployment.zh-CN.md)。[Transit Proxy 契约](../../openspec/specs/transit-proxies/spec.zh-CN.md)定义各选项由哪个适配器消费，以及如何报告不支持的节点。导入订阅后应检查单节点诊断；仅导入了协议名称并不代表节点可用。

## 配置 Egress 资源上限

`EgressService` authored 配置只提供全局资源上限
`maxWireBandwidthBps` 和 `maxInboundTargetConnections`。Egress 运行时结合这些上限和本地
profile 计算 Path 安全上限及 pending reservation。不要再配置
`recommendedPathCount`、`maxConcurrentPaths` 或 `maxStreamsPerIngress`；Path target 属于
Ingress 规则和运行时观测。STATUS_REPORT 提供配置/有效/当前容量、容量可信度、准入状态和当前复制
allowance，不携带规则或 TrafficClass 元数据。

支持 TLS 的 Transit 节点默认使用系统根证书。需要自定义根时，将有序 `truststore` 列表设置为
`system` 和/或本地 PEM/DER 文件。相对路径从选定的配置来源解析。空列表表示明确不加载信任锚点，
只有 `insecure: true` 才能绕过证书校验。无效、过大、目录或错误符号链接来源会拒绝节点，不会降级
为其他传输方式。

## 重载配置与处理失败

服务会监听选定资源目录中的新增、编辑、移除和重命名，并在发布前验证完整候选配置。支持原子替换文件。解析、资源图验证、规则编译、持久化或缓存写入失败时，最近一次成功配置继续生效；通过结构化 status 查看失败，修正候选后等待重新加载。

订阅节点、编译后的动态规则、管理员 label/tag 和 DNS 运行时健康可以动态更新。静态 Egress 拓扑、本地私钥、监听器绑定设置或平台路由设置发生变化时，需要重启服务。将未改变的资源移到其他文件不会改变其身份，也不需要重启。新 flow 在完整路由决策中使用同一已发布代次；现有资源遵循准入时的契约及正常排空/失败规则。

声明式订阅通过管理操作发生的变更，在其声明未改变时会跨重载和重启继续生效。编辑或移除声明时，应用对应的新期望状态。精确的发布和所有权规则见[重载契约](../../openspec/specs/configuration-schema/spec.zh-CN.md#快照发布和重载)。
