# PathChord 配置 schema

[English](configuration-schema.md) | **简体中文**

本文档是人工编写 YAML 配置的规范性版本化 schema。[配置规范](configuration.zh-CN.md)
提供示例和求值顺序；本文档定义字段、类型、默认值、验证和发布行为。运行时观测与控制面
JSON 属于独立契约。

## 对象外壳

PathChord 配置使用 Kubernetes 风格的声明式对象。推荐使用 `kind: List`，也允许单个资源对象。
对象可以通过 YAML `---` 分隔，或放在 `items` 中：

```yaml
apiVersion: pathchord.io/v1
kind: List
metadata:
  name: default
items:
  - apiVersion: pathchord.io/v1
    kind: Egress
    metadata:
      name: jp-1
      labels:
        region: jp
    spec:
      address: egress.example.net
      port: 443
      publicKey: <curve25519-public-key>
      capabilities:
        tcp: true
        udp: true
```

每个资源对象必须恰好包含 `apiVersion`、`kind`、`metadata` 和 `spec`。`kind: List` 是唯一的
外壳例外：它恰好包含 `apiVersion`、`kind`、`metadata` 和 `items`，不包含 `spec`。`apiVersion` 必须是
`pathchord.io/v1`；未知版本和 kind 必须拒绝。List 的 items 必须是资源对象，不得嵌套另一个 List。未知字段、重复 YAML 映射键、非规范数字、循环别名以及用户写入的
`status` 字段必须拒绝。

`metadata.name` 是稳定资源身份，必须匹配 `[a-z0-9]([-a-z0-9]*[a-z0-9])?`，最长 63 字节。
`metadata.namespace` 默认是 `default`；引用使用同一 namespace 中的 name。`metadata.labels` 和
`metadata.annotations` 是可选且有界的字符串映射。`metadata.uid`、`metadata.generation` 和
`metadata.resourceVersion` 由服务端生成，不能由用户写入。运行时 `status` 只读，并由控制面单独暴露。

支持的 kind 为 `Egress`、`TransitProxy`、`Subscription`、`EgressRule`、`TransitRule`、`ProxyRule`、
`TrafficPolicy`、`Listener`、`DNSPolicy` 和 `FallbackPolicy`。一个 namespace 中同一 `(kind, name)`
最多只能有一个对象。完整配置必须恰好包含一个 DNSPolicy 和一个 FallbackPolicy；其余资源按引用和
路由验证决定是否需要。没有 Listener 的 List 可以作为库快照存在，但不能启动 Ingress。

加载器按 `(namespace, kind, name)` 解析引用，验证完整对象图，然后发布一个不可变代次。同名对象的
期望 spec 原子替换；删除会从后续快照移除对象，并排空不再有有效引用的资源。验证或持久化失败时，
上一代保持生效。

## 标量类型和限制

除非字段另有说明，字符串均为 UTF-8、不做规范化，且不得包含 NUL 或控制字符。资源身份由
`metadata.name` 承载，不在 spec 中重复 id 字段。资源名必须小写且在 namespace 内唯一。端口范围是
`1..=65535`，端口 0 必须拒绝；CIDR 必须是有效 IPv4/IPv6 网络前缀；主机名最多 255 字节并按
DNS 名称验证；字节密钥使用无填充 base64url，解码后必须恰好 32 字节。

当 spec 内需要非资源标识符时，必须匹配 `[A-Za-z0-9][A-Za-z0-9._-]{0,127}`；资源引用仍然使用
前述小写的 `metadata.name` 语法。

```text
[a-z0-9]([-a-z0-9]*[a-z0-9])?
```

映射最多 256 项，键最多 64 字节，值最多 256 字节；label/tag 集合最多 256 项；权重范围为
`1..=1_000_000`，表示相对单位而非百分比。除非另有更小限制，每个序列最多 10,000 项。
重复名称、越界数字、必填空字符串或无效引用都是验证错误。错误必须保留上一代，并给出字段路径和稳定错误码。

运行时元数据使用以下所有权命名空间：

```text
node.*      静态身份和协议属性
source.*    导入的订阅来源元数据
observed.*  运行时测量值和派生状态
quota.*     可选的提供方配额参考信息
billing.*   可选的提供方计费参考信息
admin.*     本地管理员注解
```

`billing.traffic_multiplier` 是范围 `0.0001..=100` 的可选正十进制定数。存在该值时，调度器在
有效容量加权前将关系权重乘以该倍率。它不是硬配额，不会单独阻止连通性，也不能通过管理员 label
mutation 写入。导入的 source、observed、quota 和 billing 值均由运行时拥有。

## Egress

`kind: Egress` 的期望字段位于 `spec`，资源身份和运营 label 位于 metadata：

| 字段 | 必填 | 类型和语义 |
|---|---|---|
| `metadata.name` | 是 | namespace 内唯一的资源名 |
| `spec.address` | 是 | 主机名或 IP 字面量 |
| `spec.port` | 是 | 端口 |
| `spec.publicKey` | 是 | 32 字节无填充 base64url Curve25519 公钥 |
| `spec.capabilities` | 否 | `tcp`/`udp` 布尔映射，默认均为 false |
| `spec.statusRequirements` | 否 | `minUsablePaths` 和可选能力集合，默认 1 |

`capabilities.tcp` 或 `capabilities.udp` 至少一个必须为 true。所有 Egress 引用必须解析到 Egress
对象。Egress 拓扑和本地密钥属于启动配置，不能热重载。

## TransitProxy 和 Subscription

```yaml
apiVersion: pathchord.io/v1
kind: TransitProxy
metadata:
  name: provider-a-node-01
  labels:
    region: jp
spec:
  source:
    type: clash
    subscriptionRef: provider-a
  protocol: socks5
  address: proxy.example.net
  port: 443
  tags: [gaming]
  weight: 100
```

节点 protocol 遵循[适配器契约](transit-proxies.zh-CN.md#适配器选择与失败)，可执行支持必须单独验证。
`options` 默认 `{}`，包含类型化 TLS、transport、header、UDP、multiplex 和拨号选项。
`source.type` 遵循[订阅文档类型](transit-proxies.zh-CN.md#订阅文档类型)，包括 `static`、`auto`、
`clash`、`sip008`、`uri`、`sing_box`、`surge`、`quantumult` 和 `loon`；非 static 来源必须引用现有 Subscription。
导入的 source、observed 和 quota 属性由运行时拥有，不能写入 Proxy spec。`direct` 没有第三方端点，
忽略 address 和 port。

[Transit Proxy 契约](transit-proxies.zh-CN.md)定义全部类型化选项、按协议区分的凭据处理、完整
引擎节点文档、单节点诊断、有界 HTTP provider 展开、用量元数据，以及原生和 Egress 承载的 UDP。
未知 YAML 选项字段必须拒绝。适配器不得忽略不支持的连接选项或降级 TLS。

Subscription 的 spec 包含 `enabled`、`source`、`refresh` 和 `cache`：

```yaml
apiVersion: pathchord.io/v1
kind: Subscription
metadata:
  name: provider-a
spec:
  enabled: true
  source:
    type: clash
    url: https://example.invalid/subscription
    credentialsRef: provider-a-token
  refresh:
    intervalSeconds: 3600
    timeoutSeconds: 30
    maxAttempts: 3
    backoffSeconds: 5
  cache:
    path: provider-a.snapshot
    maxAgeSeconds: 86400
```

`enabled` 默认 true；intervalSeconds 默认 3600 且范围 `60..=604800`；timeoutSeconds 默认 30 且范围
`1..=300`；maxAttempts 默认 3 且范围 `1..=10`；backoffSeconds 默认 5 且范围 `1..=3600`；
maxAgeSeconds 默认 86400 且范围 `60..=2592000`。URL 不得包含凭据。刷新先验证文档与每个节点再发布；
无效或不支持节点保持可见且不可选，有效节点仍可发布；文档格式错误或获取失败保留上一快照。刷新失败
保留上一成功快照，记录类型化错误并使用有界指数退避。删除或禁用订阅会阻止后续刷新，仅由该来源导入
的节点进入排空并排除新选择。成功刷新发布一个动态代次，失败不发布代次。

## 规则和选择器

规则是资源，顺序由 `spec.order` 整数决定；同序号必须拒绝。`EgressRule`、`TransitRule` 和 `ProxyRule`
都可以有 `spec.match`。空 match 必须拒绝，除非显式设置 `catchAll: true`。字段之间为 AND，同一字段
中的多个值为 OR。支持 `flowTags`、`protocols`、`listenerRefs`、`sourceNetworks`、
`authenticationIdentities`、`processExecutables`、`targetHosts` 和 `targetPorts`。

EgressRule 的 spec 在 `egressRef`、`egressSelector` 或 `mode: none` 中选择一个。selector 至少一个条件；
mode none 是普通 Proxy 模式，不得创建 Session。TransitRule 在选定 Egress 后求值，使用 egressRef、
require、reject、weight（默认 100）和可选 trafficPolicyRef；可选 `trafficClassRef` 选择所选 TrafficPolicy 类别映射中的 key；未知 key 必须拒绝。没有准入 Proxy 时继续下一条 EgressRule，
不得隐式选择任意 Proxy。ProxyRule 的 select 默认 any，也可以使用 `proxy: direct`；proxy 与 select 互斥。
规则求值必须确定、有界且无 I/O，编译器必须拒绝未知字段、无界表达式和无效引用，编译失败保留上一快照。

## TrafficPolicy

TrafficPolicy spec 支持 `scheduler`（默认 `effectiveCapacityWeighted`）、`sessionReplicationBudgetBps`
（默认 0）、可选 `classReplicationBudgetBps`、`retransmissionReplication`（默认 disabled）以及
`classes`（priority/share 映射）。预算不得超过 `10^12`，priority 为 `0..=255`，share 为 `1..=1_000_000`。
Session 预算是硬上限且包含控制流量；调度器应用关系权重、billing 倍率、有效容量、拥塞窗口、RTT、抖动和丢包，
`TransitRule.spec.trafficClassRef` 可以将准入 flow 分配到所选 `TrafficPolicy.classes` 中的一个 key。未知类别引用属于验证错误；缺少引用时使用默认类别。

不得超过 Path 的流控上报限制。

## Listener

Listener 的完整字段见[平台和 DNS 规范](platform-and-dns.zh-CN.md)。Listener 由 metadata.name 标识，
spec 包含 type、platform（`linux`、`windows`、`freebsd` 或默认值 `any`）和 authentication（默认 disabled），还可以包含最多 256 个合法 tag
组成的 `flowTags`，以及带布尔字段 `executable`、`user`、`group` 的 `processMetadata` 请求。静态 flow
tags 会复制到每个接收的 flow；平台无法安全获取的进程事实表示 unknown。显式平台必须与实际主机匹配，
`any` 使用实际主机的平台矩阵。FreeBSD 允许 `http`、`socks5` 和 `mixed`，拒绝 `tproxy`、`redirect` 和 `tun`。
不支持的平台/type 组合必须在验证期间拒绝，不得忽略。

`spec.type` 接受 `socks` 作为规范名称 `socks5` 的输入别名；规范化序列化必须输出 `socks5`。
规范名称的监听器接受 SOCKS4/4a/5 CONNECT 和 SOCKS5 UDP ASSOCIATE。要求密码认证时必须拒绝
SOCKS4/4a，不得降级 verifier。HTTP 监听器支持普通 `http://` 转发和 CONNECT，并对每个请求独立
认证和求值策略。消息 framing、限制、凭据/头字段过滤和升级行为遵循
[HTTP 和 SOCKS 契约](platform-and-dns.zh-CN.md#http-和-socks-监听器)。

`spec.backend` 默认值为 `tproxy`。`backend: ebpf` 仅适用于 Linux 的 `type: tproxy`，必须使用
`platform: linux`、非空的 ingress `interface` 和至少一个 `allowedSources` CIDR。它在该接口上为
TCP/UDP 数据包设置现有 TPROXY 策略路由所需的标记；透明 listener、原目标处理、UDP association
以及 Path/Session 策略仍在用户态完成。其他 Listener 类型在验证期间拒绝 `backend: ebpf`。

`spec.type: mixed` 在一个 TCP 端点上共用 HTTP 和 SOCKS。其 `protocols` 默认值为
`[tcp, udp]`；TCP 必须启用，UDP 可选。两个 parser 共用相同的凭据、来源限制和 Listener 身份。

## DNSPolicy 和 FallbackPolicy

必须恰好有一个 DNSPolicy 和一个 FallbackPolicy。DNSPolicy 的字段和默认值见平台和 DNS 规范，Fake-IP 禁止。

```yaml
apiVersion: pathchord.io/v1
kind: FallbackPolicy
metadata:
  name: default-fallback
spec:
  action: reject
```

## 配置来源

Ingress 接受一个资源文件或一棵目录树。配置来源按以下优先级从高到低选择：

1. 显式 `--config`（`-c`）或 `--config-dir`（`-C`），两个选项互斥。`--config` 接受文件或
   目录；`--config-dir` 要求目录。
2. 非空的 `PATHCHORD_CONFIG` 或 `PATHCHORD_CONFIG_DIR`，两者在环境变量层互斥，文件/目录
   语义与对应命令行选项相同。显式命令行来源覆盖两个环境变量，包括它们之间的冲突。
3. 账号默认值：普通用户为 `~/.config/pathchord`，root 或服务账号为 `/etc/pathchord`。
   Unix 使用有效 UID；小于 1000 的系统 UID，以及 shell 为 `nologin` 或 `false` 的账号，
   视为服务账号。普通 Unix 用户的主目录来自 `HOME`，缺失时回退到账号数据库。Windows
   使用 `USERPROFILE`（然后回退到 `HOME`）；标准 System/Local Service/Network Service
   主体视为服务账号。无法确定用户主目录时必须报错。

目录加载器递归按相对路径顺序读取 `.yaml`、`.yml` 和 `.json` 资源文件，扩展名大小写不敏感。
隐藏路径和编辑器临时路径会被忽略；可见的子符号链接会被拒绝。所选根路径在启动时解析一次。
显式指定的单个文件仍可使用任意扩展名。没有受支持文件的目录必须拒绝。合并配置上限为
4 MiB、1024 个资源文件，子目录最多 16 层。

每个来源独立解析，包括 YAML 多文档流和 `kind: List`，然后验证完整的合并资源图。资源可以
引用其他文件中的对象。必须在整个集合内拒绝重复资源身份；文件名顺序不得实现“后文件覆盖
前文件”的语义。合并资源图仍必须恰好包含一个 DNSPolicy 和一个 FallbackPolicy。运行时数据和
私有凭据 JSON 必须放在资源树外，或使用非资源文件扩展名。
规范化资源图由资源身份和显式规则顺序决定；把未变更的资源移到其他来源文件不得要求重启。

## 快照发布和重载

加载器必须先解析、验证、规范化并编译完整对象图，再发布不可变代次。连接在 Egress/Proxy 求值前捕获一个
代次并使用到完整决策结束。运行时观测不能覆盖期望 spec。静态 Egress 拓扑、本地密钥、监听器绑定和平台
路由需要重启；订阅、导入 Proxy、管理员 label、DNS 健康和编译后的动态规则可以热重载。替换必须原子化；
解析、验证、编译、持久化或缓存失败时，上一成功代次保持生效并通过类型化 status 暴露错误。

目录中的创建、修改、删除和重命名事件触发完整候选重扫。单文件原子替换和根目录替换后必须
保留监听能力。所有文件验证通过后才发布一个快照；非法、不完整或重复的候选保留上一份有效
配置集合。只在启动时加载的字段发生变化时，继续报告需要重启。
