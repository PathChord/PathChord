# PathChord 配置 schema

[English](spec.md) | **简体中文**

## Purpose

定义人工编写配置的版本化 schema、完整配置集合验证、来源选择、资源所有权以及原子发布和重载契约。

## Requirements

### Requirement: Versioned schema conformance

v1 schema SHALL 暴露 Egress aggregate wire capacity 和全局入站目标连接限制，同时将 per-Ingress stream 配额和 Path 安全上限保留为运行时字段。每个 Ingress 侧 Egress SHALL 声明一个 Transit 绑定、一个 TrafficPolicy 引用、公共 Path 准入最小值和尽力维持的 Path 基线。原生资源键 SHALL 遵循本契约中的规范名称和旧键处理规则。

#### Scenario: Removed desired-Path fields are authored

- **WHEN** EgressService 包含 `recommendedPathCount`、`maxConcurrentPaths` 或 `maxStreamsPerIngress`
- **THEN** schema 拒绝该 server-owned 或已废弃字段，不把它当作 Ingress Path target

#### Scenario: Author runtime status in a resource

- **WHEN** 管理员提交了包含用户编写 `status` 字段的资源
- **THEN** 验证拒绝该资源，上一份已发布快照继续生效

#### 原生配置名称和字段迁移

PathChord 自有资源键 MUST 使用 lower camelCase。资源引用 MUST 使用 `Ref` 后缀并保留
namespace 解析；`egressId` 表示协议身份，不表示资源引用。时间、速率和字节上限必须标明单位。
集合名应表达集合含义，同时保留 `alpn` 等既定协议术语。远端单个 endpoint 主机 MUST 使用
`host`；HTTP Host 覆写列表 MUST 使用 `hosts`。用户 label 键、HTTP header 名、外部来源文档、
枚举值、私有凭据字段、环境变量和 CLI flag 不属于此原生键命名规则。

下表列出本次变更中全部退休的原生字段路径。路径相对于对应资源的 `spec`。

| 资源 | 退休的原生路径 | 规范路径 | 保留的含义 |
|---|---|---|---|
| Egress | `statusRequirements.minUsablePaths` | `pathPool.minUsablePaths` | 公共可用 Path 准入最小值 |
| Egress | `statusRequirements.capabilities` | `admission.requiredCapabilities` | Egress 公共能力要求 |
| Egress | `address` | `host` | 单 endpoint 简写主机 |
| Egress | `endpoints[].address` | `endpoints[].host` | 有序 endpoint 候选主机 |
| TransitProxy | `address` | `host` | 远端代理 endpoint 主机 |
| EgressService | `webBind` | `web.bind` | 可选管理服务 bind |
| EgressService | `webTokenFile` | `web.tokenFile` | 私有 bearer token 文件路径 |
| EgressService | `webOrigins` | `web.allowedOrigins` | 允许的 Web 来源 |
| EgressService | `webProtectedTransport` | `web.protectedTransport` | 现有受保护传输断言 |
| TransitProxy | `options.transport.host` | `options.transport.hosts` | 有序 HTTP Host 覆写列表 |
| TransitProxy | `options.transport.maxEarlyData` | `options.transport.maxEarlyDataBytes` | 保留原上限的字节数 |
| TransitProxy | `options.tls.certificate` | `options.tls.certificates` | 内联额外信任锚点 |
| TransitProxy | `options.tls.clientCertificate` | `options.tls.clientCertificates` | 内联客户端证书链 |
| TransitProxy | `options.tls.fingerprint` | `options.tls.clientHelloFingerprint` | ClientHello 模拟 profile |
| TransitProxy | `options.udpOverTcp` | `options.udpOverTcpVersion` | 明确的支持版本 |

资源 API 版本仍为 `pathchord.io/v1`。整个 `statusRequirements` 对象均已退休，包括空对象。
每个旧原生键都 MUST 导致完整候选配置验证失败，包括空/默认值，以及新旧键同时出现的文档。
旧键 MUST NOT 作为别名、回退值或合并输入。有限的 `CONFIG_RETIRED_FIELD` 诊断 MUST 标明资源、
确切的旧字段路径和一个或多个新字段路径，且不得返回字段值。未知字段仍然无效；不得递归转换
任意数据中的键名。

Egress 的 `host`/`port` 简写与 `endpoints: [{host, port}]` 互斥。主机名/IP、IPv6、顺序、重复
检测、namespace、公钥以及 1..=32 endpoint 限制保持不变。TransitProxy `host`/`port` 保留
`direct` 适配器的现有例外。NodeProbe target 和对象形式的 Listener bind 已使用 `host`/`port`。
Listener interface 的 `address`、CIDR、socket address 字符串和字面 HTTP `Host` header 含义不同，
不得作为远端 endpoint 主机来重命名。

EgressService 的 `web` 可选，只接受 `bind`、`tokenFile`、`allowedOrigins` 和
`protectedTransport`。省略后仍保持 Web Gateway 默认禁用；子字段默认值、校验限制、origin/token
检查和受保护传输要求不变。相对的 `web.tokenFile` 路径按现有私有路径规则相对于选定配置来源解析。
Web Gateway 沿用已有密钥存储和受保护传输边界。

规范 MUST 说明 EgressRule 和 ProxyRule 的 `catchAll`，以及 ProxyRule 的 `require`，并保持现有验证和
选择语义。本次名称整理不改变路由动作模型，也不扩展 `transit.reject` 当前仅支持 tag 的条件。

### Requirement: Whole-bundle identities and references

Ingress 必须（SHALL）跨所有来源文件验证完整资源图，按 namespace、kind 和 name
解析引用，并拒绝重复身份，不得采用后文件覆盖语义。完整 Ingress 配置必须（SHALL）
恰好包含一个 DNSPolicy 和一个 FallbackPolicy。Egress 必须（SHALL）使用下述角色专用
Egress 来源契约，不得要求 Ingress 资源图。

#### Scenario: Duplicate resources are split between files

- **WHEN** 配置目录中的两个文件声明了相同 `(namespace, kind, metadata.name)` 身份
- **THEN** 必须拒绝完整候选配置集合，不得选择文件名靠后的资源

#### Scenario: Egress does not require Ingress-only resources

- **WHEN** Egress 来源包含一个有效 `EgressService`，且没有
  `DNSPolicy`、`FallbackPolicy`、Listener 或路由资源
- **THEN** Egress 从该服务来源验证并启动，不虚构或要求 Ingress 策略资源。

### Requirement: Explicit source precedence and bounded discovery

Ingress 必须（SHALL）先选择命令行配置，再选择环境配置和账号默认值，并执行详细契约规定的来源冲突与有界目录发现规则。文件名顺序不得（SHALL NOT）成为覆写机制。

#### Scenario: Command line overrides conflicting environment variables

- **WHEN** 提供了有效的显式命令行来源，同时两个配置环境变量均非空
- **THEN** 显式来源具有优先权，并覆盖环境变量层的冲突

### Requirement: Role-specific Egress configuration source

Egress 配置来源必须（SHALL）在单个资源文件或目录树中恰好包含一个
`EgressService`，并拒绝 Ingress 专属资源类型，而不载入完整 Ingress 策略图。来源必须
（SHALL）保留现有 `EgressService` 字段验证、私有路径规则和 namespace 身份语义。

#### Scenario: Egress loads a service-only source

- **WHEN** Egress 来源恰好包含一个有效 `EgressService`
- **THEN** Egress 接受其 bind、identity、authorization database、control socket、资源限制、
  DNS 模式和可选 Web Gateway 设置，且不要求任何 Ingress 资源。

#### Scenario: Egress source contains an Ingress resource

- **WHEN** Egress 来源包含 Listener、TransitProxy、Subscription、EgressRule、ProxyRule、
  DNSPolicy、FallbackPolicy 或 geodata 资源
- **THEN** 来源验证以类型化诊断失败，指出该资源超出 Egress 配置契约。

#### Scenario: Egress source contains zero or multiple services

- **WHEN** Egress 来源不含 `EgressService`，或在所选来源中包含多个
  `EgressService` 身份
- **THEN** Egress 拒绝启动，且不打开 Path listener 或修改授权数据库。

#### Scenario: Egress private paths remain outside the resource tree

- **WHEN** `EgressService` 引用 identity、authorization database、control socket 或 bearer-token 路径
- **THEN** 相对路径从所选 Egress 来源目录解析，私有文件留在资源文档之外，且服务在启动前
  执行现有的所有权和权限检查。

### Requirement: Egress source precedence and restart boundary

Egress 必须先选择显式命令行资源来源，其次选择 `PATHCHORD_CONFIG` 或
`PATHCHORD_CONFIG_DIR`，最后使用账号默认值。`EgressService` 字段优先于角色默认值。
显式指定的控制 socket 和临时身份优先于资源值。身份、监听地址、授权存储、控制端点
或其他仅在启动时读取的服务字段发生变更时，Egress 必须重启。

#### Scenario: Egress command-line source overrides the environment

- **WHEN** 同时提供 Egress 配置环境变量及显式 `--config` 或 `--config-dir` 来源
- **THEN** Egress 只载入显式来源，不把环境来源合并进来。

#### Scenario: Egress source fails validation

- **WHEN** 所选 Egress 来源不可读、格式错误或违反角色专用资源契约
- **THEN** Egress 在绑定公共 Path listener 之前报告类型化配置错误，并保留已有服务状态。

#### Scenario: Egress startup configuration changes

- **WHEN** 后续 Egress 来源改变 identity、bind 地址、授权数据库、控制端点或其他仅启动时字段
- **THEN** 服务报告需要重启，且不把变更部分应用到活动运行时。

### Requirement: Atomic publication and resilient watching

完整候选必须（SHALL）通过解析、验证、规范化、编译及必要的持久化后，才能发布一个不可变代次。无效候选必须（SHALL）保留上一份有效配置集合；单文件和根目录的原子替换必须（SHALL）保留监听能力。Egress endpoints、准入要求、任一规范化 Path-pool 数量、引用的策略、已解析策略内容或 EgressService 启动设置发生变化时，必须报告需要重启并保留当前配置。

#### Scenario: Atomic replacement contains an invalid candidate

- **WHEN** 一个受监听的配置文件被原子替换为无效资源候选
- **THEN** 上一份有效配置集合继续生效，且继续监听后续有效替换

#### Scenario: A referenced policy changes without changing its name

- **WHEN** 重载改变 Egress 引用的 TrafficPolicy 内容但保留引用名称
- **THEN** Ingress 报告需要重启，并保留当前配置和 Session 策略快照

#### Scenario: Only Transit membership changes

- **WHEN** 订阅或授权的管理员元数据更新改变了不变 Egress 绑定下的节点
- **THEN** Ingress 发布有效动态代次并排空被移除的候选，不要求新的 Egress 策略快照

#### Scenario: Egress endpoint topology changes

- **WHEN** 候选配置新增、移除、重排或修改 Egress endpoint 或 EgressService bind
- **THEN** 完整候选仍需验证，活动运行时保持不变，重载结果报告需要重启

#### Scenario: Normalization preserves an Egress policy

- **WHEN** 重载只改变文件或 mapping 顺序，或写入等价的显式默认值
- **THEN** 规范化后的 Egress policy fingerprint 不变，不要求重启

#### Scenario: Only an unreferenced policy changes

- **WHEN** 重载改变了没有任何配置 Egress 引用的 TrafficPolicy
- **THEN** 该变化单独不触发 Egress 启动边界，也不改变存活 Session 的策略

#### Scenario: Only the configured Path baseline changes

- **WHEN** 有效候选将 `pathPool.targetUsablePaths` 改为另一已解析请求基线
- **THEN** 重载报告需要重启，并保留完整活动配置，包括其他有效动态变更

#### Scenario: An omitted target becomes an equivalent explicit value

- **WHEN** minimum 为 1，候选将省略 target 改为 `targetUsablePaths: 2`，且其他规范化值不变
- **THEN** 已解析 Path-pool fingerprint 不变，该字段变化本身不要求重启

### Requirement: Deterministic bounded rule compilation

规则必须（SHALL）使用显式且唯一的顺序值，并进行确定、有界且无 I/O 的求值。EgressRule 输出只能选择 Egress 动作并携带诊断规则身份。每个 Egress 必须在完整资源集合验证期间解析一个 TrafficPolicy，不依赖运行时候选数量。已退休的 TransitRule 和流量类别配置必须明确拒绝。

#### Scenario: Multiple Transit relationships lack a policy

- **WHEN** 一个 Egress 有多个可能 Transit 关系却省略 `trafficPolicyRef`
- **THEN** 必须在发布前拒绝完整候选，而不是等节点加入后才因单路径配置失败

#### Scenario: Only one Transit is currently available

- **WHEN** 一个 Egress 当前只有一条可用 Transit 关系却省略策略引用
- **THEN** 仍必须拒绝同一验证错误，不创建隐式的单 Transit 策略

### Requirement: Persistent subscription ownership

声明式 Subscription 通过管理操作启用、禁用、删除或显式重新创建后，其状态必须（SHALL）在声明未改变时跨重载和重启继续生效。声明变更或移除时必须（SHALL）应用相应的新期望状态，并与仅通过管理接口创建的订阅保持独立。

#### Scenario: Reload an unchanged disabled declaration

- **WHEN** 一个声明式 Subscription 通过管理接口被禁用，并在重启后重新加载未改变的声明
- **THEN** 管理接口设定的禁用状态继续生效

### Requirement: Validated adapter options

Transit Proxy 配置必须（SHALL）保留类型化连接选项，并验证所选适配器支持这些选项。支持 TLS 的适配器必须默认加载系统根证书，接受有序本地 PEM/DER truststore 来源列表，并在任一配置来源无效时原子拒绝候选；未知 YAML 选项字段必须拒绝。

#### Scenario: Custom truststore sources are configured

- **WHEN** TLS 节点将 truststore 来源配置为 `system` 和本地 PEM/DER 文件
- **THEN** 适配器使用这些来源的并集，从选定配置来源解析相对路径，并在任一来源不可读或无效时拒绝候选

#### Scenario: Adapter cannot consume a connection option

- **WHEN** 配置的节点要求所选适配器不支持的连接选项
- **THEN** 必须依照 Transit Proxy 契约拒绝节点或暴露明确诊断，不得静默丢弃该选项

### Requirement: Egress resource limits are global

EgressService SHALL 定义全局入站目标连接上限和配置的 aggregate wire 带宽上限。运行时 SHALL 在所有已授权 Ingress Session 之间执行这些全局资源上限。

#### Scenario: Global connection cap is reached

- **WHEN** 活跃目标连接加 pending reservation 达到全局上限
- **THEN** 新目标打开返回 `RESOURCE_LIMIT`，现有目标连接保持活动

### Requirement: Egress service supports one identity across multiple binds

一个 EgressService SHALL 接受有界且非空的公共 Path listener bind 列表。同一服务的所有 bind SHALL
共享 Egress ID、私有 identity、授权库和全局资源限制。

#### Scenario: Multiple address families use one Egress identity

- **WHEN** EgressService 声明了有效的 IPv4 和 IPv6 bind，包括不同端口
- **THEN** 一个 Egress runtime 暴露全部 listener，并使用同一 Egress identity 和授权代次认证 Path

#### Scenario: Duplicate listener binds are declared

- **WHEN** EgressService 规范化后声明了重复的地址和端口
- **THEN** 验证以字段诊断拒绝候选

#### Scenario: One listener cannot be bound

- **WHEN** 启动或重启时任一 bind 无法打开
- **THEN** 服务不得发布不完整 listener 集合，并报告类型化启动失败

### Requirement: Egress service bind forms normalize deterministically

EgressService schema SHALL 接受现有单数 `bind` 作为一个 listener 的简写，也接受多个 listener 的 `binds` 列表。
同时提供两种形式 SHALL 被拒绝；规范化结果保留声明顺序且不得含重复 SocketAddr。

#### Scenario: Existing singular bind is loaded

- **WHEN** EgressService 只提供 `bind`
- **THEN** 验证生成等价的单项 bind 列表

#### Scenario: Singular and plural binds conflict

- **WHEN** EgressService 同时提供 `bind` 和 `binds`
- **THEN** 验证拒绝资源，不按优先级选择一种形式

### Requirement: Ingress Egress supports bounded endpoint candidates

Ingress 侧 Egress SHALL 包含有界、非空、有序的 endpoint 列表。每个 endpoint SHALL 包含有效主机名或 IP
字面量及 `1..=65535` 端口；候选可以使用不同地址族、主机名和端口。

#### Scenario: IPv4, IPv6, and named endpoints are configured

- **WHEN** 一个 Egress 声明 IPv4、IPv6 和带独立端口的域名候选
- **THEN** 规范化策略在同一资源身份和公钥下保留全部候选

#### Scenario: An endpoint has an invalid host or port

- **WHEN** endpoint 主机为空/无效，或端口为零/越界
- **THEN** 完整配置验证拒绝 Egress 并保留上一份已发布快照

#### Scenario: Endpoint candidates are duplicated

- **WHEN** 两个候选规范化为相同主机和端口
- **THEN** 验证以重复 endpoint 诊断拒绝 Egress

### Requirement: Ingress Egress endpoint forms normalize without changing identity

Egress schema SHALL 接受 `host` 和 `port` 作为单 endpoint 简写，并接受每个候选包含 `host` 和
`port` 的 `endpoints` 列表。两种形式同时提供 SHALL 被拒绝；endpoint 规范化不得改变 Egress 资源名、
Egress ID 或公钥绑定。退休的原生 `address` 字段 SHALL 返回规范替换字段诊断。

#### Scenario: Existing address and port are loaded

- **WHEN** Egress 只提供已退休的 `address` 和 `port` 简写
- **THEN** 验证拒绝完整候选并指出 `host` 是 `address` 的替换字段

#### Scenario: Singular and plural endpoint forms conflict

- **WHEN** Egress 同时提供 `host`/`port` 和 `endpoints`
- **THEN** 验证拒绝资源，不静默合并或选择一种形式

#### Scenario: Canonical single-endpoint shorthand is loaded

- **WHEN** Egress 仅提供有效 `host` 和 `port`
- **THEN** 验证生成等价的单项规范化 endpoint 列表并保留路由身份

### Requirement: Egress Path-pool configuration

Ingress 侧 Egress SHALL 接受可选的 `pathPool.minUsablePaths` 和 `pathPool.targetUsablePaths`。
minimum 默认 1；省略 target 时请求 minimum 加一；显式 target 不额外增加备用 Path。数值范围、
准入和上限契约见下文详细契约。

#### Scenario: Path-pool configuration is omitted

- **WHEN** Egress 省略 `pathPool`
- **THEN** minimum 为 1，请求的可用 Path 基线为 2，并受运行时上限约束

#### Scenario: A larger minimum has no explicit target

- **WHEN** Egress 设置 `minUsablePaths: 3` 并省略 target
- **THEN** 应用运行时上限前，请求基线为 4

#### Scenario: An explicit target equals the minimum

- **WHEN** Egress 将两个数量都设为 2
- **THEN** 请求基线恰好为 2，不隐含增加备用 Path

#### Scenario: A Path-pool count is invalid

- **WHEN** 数值为零、负数、非整数、null、超出无符号 32 位范围，或显式 target 小于 minimum
- **THEN** 完整配置验证以资源和错误字段路径拒绝候选

#### Scenario: A target exceeds the current runtime ceiling

- **WHEN** 有效请求基线超过较低的运行时或协商 Path 上限
- **THEN** 配置保留请求值，运行时规划使用受限的有效基线，并暴露上限缺口，但不拒绝原本有效的配置

#### Scenario: The default target requires wider arithmetic

- **WHEN** minimum 是最大无符号 32 位整数且省略 target
- **THEN** 默认值解析使用更宽的无符号数表示 minimum 加一，不溢出或回绕为零

#### Scenario: Capability requirements move with their meaning intact

- **WHEN** Egress 声明 `admission.requiredCapabilities: [tcp, udp]`
- **THEN** 保留旧 capability requirement 的公共 Egress 能力检查，不增加按流或原生 UDP Transit 限制

#### Path 池字段、默认值和限制

| Egress `spec` 下的字段 | 类型 | 默认值和含义 |
|---|---|---|
| `pathPool` | 对象 | 省略或 `{}` 时使用子字段默认值 |
| `pathPool.minUsablePaths` | 整数 `1..=4294967295` | `1`；新业务准入所需的已认证、可用、非排空 Path 最小值 |
| `pathPool.targetUsablePaths` | 整数 `1..=4294967295`，且不小于 minimum | 省略时请求 `minUsablePaths + 1`；显式值为请求基线 |
| `admission` | 对象 | 省略或 `{}` 时不添加能力要求 |
| `admission.requiredCapabilities` | 有界且唯一的 `tcp`/`udp` 集合 | `[]`；公共 Egress 能力资格要求 |

Null 不等同于省略数量。未知子字段无效；现有字符串、集合、身份、namespace 和 schema 数值限制继续生效。
默认值计算 MUST 使用足以容纳 `4294967296` 的无符号类型。规范化相等性 MUST 比较解析后的请求基线，
不能只比较 target 是否显式填写，也不得依赖运行时上限或当前合格 Transit 数量。

只有已认证、符合资格、处于 `ACTIVE` 或 `DEGRADED` 且未排空的 Path 才计入数量。连接中、失败、关闭、
排空或策略排除的 Path MUST NOT 满足任一数量。单个合格 Transit 可承载多条独立 Path，并遵循既有关系权重。
target 是维护基线，不是副本数、新的准入门槛、精确连接池大小或公开最大值。状态机契约定义按容量扩张
和逐步收缩行为。

两个 Path-pool 数量和 `admission.requiredCapabilities` 都是 Egress 启动配置。EgressService MUST NOT
接收这些 Ingress 侧字段，也不得获得 Path recommendation。原生路由规则不得覆写这些字段。

### Requirement: Endpoint collections have bounded canonical values

规范化的 `binds` 和 `endpoints` SHALL 各包含 1..=32 项，保留声明顺序、拒绝重复值，且不得从 endpoint
派生新身份。bind 使用 SocketAddr 的 IPv6 方括号；Egress endpoint 主机保存无 URI 方括号的 IPv6 字面量。
endpoint 拓扑属于启动配置。

#### Scenario: Endpoint collection exceeds its bound

- **WHEN** `binds` 或 `endpoints` 超过 32 项
- **THEN** 完整配置验证以有界数量诊断拒绝候选

#### Scenario: Endpoint order changes

- **WHEN** endpoint 列表成员不变但顺序发生变化
- **THEN** 规范化拓扑发生变化，重载结果报告需要重启

### Requirement: Truststore sources are explicit and bounded

TLS truststore 来源 SHALL 默认是 `["system"]`。其他来源必须是本地 PEM/DER 文件；相对路径从选定配置来源解析，允许绝对路径，符号链接目标必须是普通文件，空列表表示没有信任锚点。

#### Scenario: Empty truststore is selected

- **WHEN** 节点显式配置空 truststore 且未启用 insecure verification
- **THEN** 普通证书校验 fail closed，不能隐式恢复系统根证书

### Requirement: Egress capacity fields have distinct meanings

Schema SHALL 区分配置的 aggregate wire 硬上限、运行时有效容量和当前负载。容量状态必须独立表示 `unknown`、`provisional`、`measured` 或 `stale`。

#### Scenario: Capacity is not yet measured

- **WHEN** Egress 启动时没有足够新鲜的容量测量
- **THEN** 配置上限仍是硬上限，有效容量报告为 provisional 或 unknown，不能伪造 measured

### Requirement: Subscription User-Agent is bounded

Subscription 来源 SHALL 接受可选 `userAgent` 字段。其值 SHALL 是非空白的可打印 ASCII HTTP header 值，最多 1024 字节。省略时 SHALL 使用 Transit 契约规定的默认值。

#### Scenario: User-Agent contains a line break

- **WHEN** Subscription 声明的 User-Agent 包含换行符
- **THEN** 配置验证拒绝候选配置集合

### Requirement: Geodata resources and references

配置 schema SHALL 支持 namespace 范围的 geosite 和 geoip 数据库资源，以及 flow match 中类型化的命名集合引用。验证 SHALL 对照完整资源图解析所有引用，并在发布前拒绝无效或歧义数据。

#### Scenario: Reference an absent database

- **WHEN** 规则引用其 namespace 中不存在的 geodata 资源或命名集合
- **THEN** 候选配置被拒绝，诊断标识字段和资源，不发布部分规则

#### Scenario: Existing exact host matches remain valid

- **WHEN** 现有配置只使用 `targetHosts`
- **THEN** 它保留原有的精确主机名或 IP 字面量匹配语义，无需 geodata 资源

### Requirement: Geodata updates publish atomically

加载器 SHALL 作为完整候选的一部分读取和验证每个被引用的数据库，并将 geodata 与规则发布为同一不可变代次。替换配置的数据库文件 SHALL 触发有界重载；候选失败时 SHALL 保留上一代有效配置。

#### Scenario: Replace a referenced database

- **WHEN** 运维人员以有效内容原子替换被引用的 geodata 文件
- **THEN** Ingress 验证完整候选，并将变更后的数据和规则一起发布为新代次

#### Scenario: Start with missing geodata

- **WHEN** 初始配置引用缺失或不可读的 geodata 数据库
- **THEN** 启动报告类型化配置失败，不静默禁用条件

### Requirement: Detailed geodata contract

Geodata 配置 SHALL 遵循完整的[详细契约](#geodata-数据库)。

#### Scenario: Apply the detailed contract

- **WHEN** 处理 geodata 配置或匹配
- **THEN** 执行详细契约中的 schema、限制和失败语义

### Requirement: Role startup settings in the selected source

所选来源必须支持声明对应角色的启动设置。私有值保存在独立文件中。
省略的私有文件路径从角色目录布局解析。

#### Scenario: Ingress startup settings are authored with its policy graph

- **WHEN** 所选 Ingress 资源包声明了服务设置
- **THEN** daemon 随完整策略图解析身份、状态目录、凭据目录、控制 socket 和 Web Gateway 设置

#### Scenario: Minimal Egress resource uses role defaults

- **WHEN** EgressService 声明名称和 Path 监听，且省略身份和私有文件路径
- **THEN** 服务以资源名称为默认 Egress ID，从角色默认值解析身份、授权库和控制 socket 路径

## Detailed contract

本文档是人工编写 YAML 配置的规范性版本化 schema。[配置规范](../configuration/spec.zh-CN.md)
提供示例和求值顺序；本文档定义字段、类型、默认值、验证和发布行为。运行时观测与控制面
JSON 属于独立契约。

### 对象外壳

PathChord 配置使用 Kubernetes 风格的声明式对象。推荐使用 `kind: List`，也允许单个资源对象。
对象可以通过 YAML `---` 分隔，或放在 `items` 中：

```yaml
apiVersion: pathchord.io/v1
kind: List
metadata:
  name: default
items:
  - apiVersion: pathchord.io/v1
    kind: FallbackPolicy
    metadata:
      name: default-fallback
    spec:
      action: reject
```

每个资源对象必须恰好包含 `apiVersion`、`kind`、`metadata` 和 `spec`。`kind: List` 是唯一的
外壳例外：它恰好包含 `apiVersion`、`kind`、`metadata` 和 `items`，不包含 `spec`。`apiVersion` 必须是
`pathchord.io/v1`；未知版本和 kind 必须拒绝。List 的 items 必须是资源对象，不得嵌套另一个 List。未知字段、重复 YAML 映射键、非规范数字、循环别名以及用户写入的
`status` 字段必须拒绝。

`metadata.name` 是稳定资源身份，必须匹配 `[a-z0-9]([-a-z0-9]*[a-z0-9])?`，最长 63 字节。
`metadata.namespace` 默认是 `default`；引用使用同一 namespace 中的 name。`metadata.labels` 和
`metadata.annotations` 是可选且有界的字符串映射。`metadata.uid`、`metadata.generation` 和
`metadata.resourceVersion` 由服务端生成，不能由用户写入。运行时 `status` 只读，并由控制面单独暴露。

每个配置来源只属于一个角色。每个 namespace 内的 `(kind, metadata.name)` 必须唯一。

| 角色 | 该角色使用的资源 | 数量要求 |
|---|---|---|
| Ingress | `DNSPolicy`、`FallbackPolicy` | 整个资源图中各恰好一个 |
| Ingress | `IngressService`、`NodeProbePolicy` | 整个资源图中各至多一个 |
| Ingress | `Listener`、`Egress`、`TransitProxy`、`Subscription`、`EgressRule`、`ProxyRule`、`TrafficPolicy`、`GeoSiteDatabase`、`GeoIpDatabase` | 按引用及路由规则验证。库快照可省略 Listener，启动 Ingress 服务至少需要一个 Listener。 |
| Egress | `EgressService` | 整个来源恰好一个，任何其他资源种类均须拒绝 |

加载器按 `(namespace, kind, name)` 解析引用，验证完整对象图，然后发布一个不可变代次。同名对象的
期望 spec 原子替换；删除会从后续快照移除对象，并排空不再有有效引用的资源。验证或持久化失败时，
上一代保持生效。

### 标量类型和限制

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

### Egress

`kind: Egress` 的期望字段位于 `spec`，资源身份和运营 label 位于 metadata：

| 字段 | 必填 | 类型和语义 |
|---|---|---|
| `metadata.name` | 是 | namespace 内唯一的资源名 |
| `spec.host` | 条件 | 主机名或 IP 字面量；没有 `endpoints` 时必须与 `port` 一起提供 |
| `spec.port` | 条件 | endpoint 端口；没有 `endpoints` 时必须与 `host` 一起提供 |
| `spec.endpoints` | 条件 | 1..=32 个有序 `{host, port}` 候选；与 `host`/`port` 互斥 |
| `spec.publicKey` | 是 | 32 字节无填充 base64url Curve25519 公钥 |
| `spec.capabilities` | 否 | `tcp`/`udp` 布尔映射，默认均为 false |
| `spec.pathPool` | 否 | `minUsablePaths` 和 `targetUsablePaths`；默认 minimum 为 1，请求基线为 2 |
| `spec.admission` | 否 | `requiredCapabilities`；默认没有额外公共能力要求 |
| `spec.transit` | 是 | 同一 namespace 的公共 Transit 绑定，可选 `require` 和 `reject` 选择器 |
| `spec.trafficPolicyRef` | 是 | 每个使用该 Egress 的 Session 所用的同 namespace TrafficPolicy |

单数 `host`/`port` 简写与 `endpoints` 互斥。target 默认请求公共 minimum 加一；显式 target
不额外增加备用 Path。`pathPool.minUsablePaths` 控制基于数量的准入；
`pathPool.targetUsablePaths` 是尽力维持的空闲基线，本身不改变健康状态或新业务准入。数量范围、
默认值宽算术、运行时限幅以及请求值与有效值的区别见上方 Path-pool 规范。
`capabilities.tcp` 或 `capabilities.udp` 至少一个必须为 true。所有 Egress 引用必须解析到 Egress
对象。`transit: {}` 明确允许同 namespace 中其他条件合格的 Transit 节点；`require` 使用 label、tag
和 capability，`reject.tags` 排除匹配节点。绑定不能包含 flow match、order、第二个 weight、Path 子集
或 desired Path 数量。Egress 拓扑、Path-pool 数量、admission 要求、绑定和已解析 TrafficPolicy
属于启动配置，不能热重载。

### IngressService

每个 Ingress 资源包最多可声明一个 `IngressService`，其 `spec` 接受
`ingressId`、`identity`、`dataDir`、`credentialsDir`、`controlSocket` 和 `web`。
默认 Ingress ID 为 `local-ingress`。`web` 接受 `bind`、`tokenFile`、
`allowedOrigins` 和 `protectedTransport`。相对路径以所选配置来源为基准解析。
私有文件和状态保存在扫描目录之外。这些设置变更后需重启。

### EgressService 和 NodeProbePolicy

`EgressService.spec` 接受 `bind` 或 `binds`、`egressId`、`identity`、`authorizationDb`、
`controlSocket`、`maxWireBandwidthBps`、`maxInboundTargetConnections`、
`quotaRemaining`、`trafficMultiplierBasisPoints`、
`remoteDnsOnly` 和可选的 `web` 设置。`web` 接受 `bind`、`tokenFile`、`allowedOrigins` 和
`protectedTransport`。`bind` 是单项简写，
`binds` 是 1..=32 个唯一 SocketAddr 的有序列表，两种形式互斥。
Ingress Path-pool 数量、per-Ingress stream 配额和 Path 安全上限不属于 EgressService 字段，不得写入
该资源。
资源中的相对路径相对于所选配置来源解析。一个 Egress 进程必须从该来源选择恰好一个此类资源。
缺少 `egressId` 时使用资源名。身份、授权库和控制 socket 路径从角色目录布局解析默认值。
`remoteDnsOnly` 默认 false。设为 true 且存在原始主机名时，Egress 对 TCP 和 UDP 使用自身系统
解析器解析该名称，不使用 Ingress 提供的地址候选。没有主机名的字面 IP 仍是有效目标。
该选项作用于目标名称，不改变独立的 Ingress DNS 路由策略。

Egress 来源不得包含 IngressService、Listener、TransitProxy、Subscription、EgressRule、ProxyRule、TrafficPolicy、
DNSPolicy、FallbackPolicy、GeoSiteDatabase、GeoIpDatabase 或 NodeProbePolicy。私有身份、授权库、
控制 socket 和 bearer token 密钥内容位于用户资源文档之外。相对 `web.tokenFile` 路径从所选 Egress
配置来源根解析。
EgressService 字段属于启动配置；来源变化时报告需要重启，活动 Egress 运行时保留原值。

`NodeProbePolicy.spec.target` 是包含 `host` 和 `port` 的对象。`intervalSeconds` 默认 30、
范围为 1..=86400；`timeoutSeconds` 默认 5、范围为 1..=30；`maxConcurrency`、`windowSize` 和
`maxNodesPerBatch` 分别默认 8、32 和 128，范围分别为 1..=64、1..=128 和 1..=1024。
资源包中最多允许一个 NodeProbePolicy。

### TransitProxy 和 Subscription

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
  host: proxy.example.net
  port: 443
  tags: [gaming]
  weight: 100
```

节点 protocol 遵循[适配器契约](../transit-proxies/spec.zh-CN.md#适配器选择与失败)，可执行支持必须单独验证。
`options` 默认 `{}`，包含类型化 TLS、transport、header、UDP、SOCKS5/SS `udpOverTcpVersion`、
VMess 帧、multiplex 和拨号选项。
`source.type` 遵循[订阅文档类型](../transit-proxies/spec.zh-CN.md#订阅文档类型)，包括 `static`、`auto`、
`clash`、`sip008`、`uri`、`sing_box`、`surge`、`quantumult` 和 `loon`；非 static 来源必须引用现有 Subscription。
导入的 source、observed 和 quota 属性由运行时拥有，不能写入 Proxy spec。`direct` 没有第三方端点，
忽略 host 和 port。

[Transit Proxy 契约](../transit-proxies/spec.zh-CN.md)定义全部类型化选项、按协议区分的凭据处理、完整
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
    userAgent: clash.meta
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
maxAgeSeconds 默认 86400 且范围 `60..=2592000`。`source.userAgent` 可选，默认 `clash.meta`，
必须是非空白且不超过 1024 字节的可打印 ASCII 值。URL 不得包含凭据。刷新先验证文档与每个节点再发布；
无效或不支持节点保持可见且不可选，有效节点仍可发布；文档格式错误或获取失败保留上一快照。刷新失败
保留上一成功快照，记录类型化错误并使用有界指数退避。删除或禁用订阅会阻止后续刷新，仅由该来源导入
的节点进入排空并排除新选择。成功刷新发布一个动态代次，失败不发布代次。

### Geodata 数据库

`kind: GeoSiteDatabase` 或 `kind: GeoIpDatabase` 资源包含共同的 `apiVersion`、
`metadata.name`、可选 namespace，以及指向本地 V2Fly protobuf 文件的 `spec.path` 字符串。
每个 namespace 的每种 kind MUST 至多有一个资源。文件是只读输入；匹配时不下载或修改文件。
相对路径基于选定配置文件的父目录或选定配置目录根目录解析。数据库文件是外部输入，不是资源
文档，MUST 放在被扫描的配置目录之外，或使用不被扫描的扩展名。

`targetGeoSites` 和 `targetGeoIps` 是 EgressRule 或 ProxyRule 的 `match` 中
可选的非空序列，每个最多 256 个字符串。Geosite 引用使用 `set` 或 `set@attribute`，可选
`geosite:` 前缀；geoip 引用使用 `set`，可选 `geoip:` 前缀。对应前缀在规范化时移除；不兼容的
前缀必须拒绝。集合和属性名称使用非空 ASCII 字母、数字、`.`、`_`、`-` 和 `!`，大小写不敏感。
被引用的对应数据库资源 MUST 存在于规则的
namespace 中。归一化后重复的引用无效。同一字段中的值为 OR；非空匹配字段之间为 AND，
包括 `targetHosts`、`targetGeoSites` 和 `targetGeoIps`。原始目标事实不可用时，相应条件
为 false。同一规则同时配置 geosite 和 geoip 时要求两个事实都存在；两者任选其一时使用
独立有序规则。

外部数据库路径与内容参与候选验证、重载观测、代次标识和有界诊断。被引用文件发生变化，
包括原子替换时，会触发完整资源图验证。发布前须解码、验证并建立数据索引；flow 不得看到
旧规则与新数据的混合。启动时没有有效候选则启动失败；后续失败保留上一代有效配置。更新和
数据文件读取限制遵循 [geodata 路由契约](../geodata-routing/spec.zh-CN.md)。没有 geodata
引用的配置无需数据库文件。

### 规则和选择器

规则是资源，顺序由 `spec.order` 整数决定；同序号必须拒绝。`EgressRule` 和 `ProxyRule`
都可以有可选的 `spec.match`。显式提供 `match: {}` 必须拒绝；只有确实需要显式全匹配规则时才省略 `match`。字段之间为 AND，同一字段
中的多个值为 OR。支持 `flowTags`、`protocols`、`listenerRefs`、`sourceNetworks`、
`authenticationIdentities`、`processExecutables`、`targetHosts`、`targetGeoSites`、
`targetGeoIps` 和 `targetPorts`。

EgressRule 的 spec 在 `egressRef`、`egressSelector` 或 `mode: none` 中选择一个。selector 至少一个条件；
mode none 是普通 Proxy 模式，不得创建 Session。EgressRule 不接受 requirements、Transit selector、策略覆盖或业务类别字段；选定 Egress 的绑定提供公共 Transit 候选、Path-pool minimum 和基线，以及 TrafficPolicy。绑定没有准入 Transit 时继续下一条 EgressRule，不得隐式选择任意 Proxy。

ProxyRule 的 `require` 使用相同的 label/tag/capability 选择器语义过滤普通 Proxy。`select` 默认是
`any`，也可指定选择器。将符合条件的候选节点按加权分数降序排列，同分时按规范 ID 升序排列，先尝试第一项。
准入前的失败重试遵循[普通 Proxy 故障转移契约](../configuration/spec.zh-CN.md#requirement-bounded-ordinary-proxy-pre-admission-failover)。
规则也可使用 `proxy: direct` 选择 direct 适配器。`proxy` 与 `select` 互斥。
EgressRule 和 ProxyRule 均可用 `catchAll` 显式标记全匹配规则；全匹配规则不得同时提供 `match`。
规则求值必须确定、有界且无 I/O，编译器必须拒绝未知字段、无界表达式和无效引用，编译失败保留上一快照。

### TrafficPolicy

TrafficPolicy spec 支持 `scheduler`（默认 `effectiveCapacityWeighted`）、`sessionReplicationBudgetBps`
（默认 0）和 `retransmissionReplication`（默认 disabled）。预算不得超过 `10^12`。
Session 预算在每个发送方向是硬上限且包含控制流量；`disabled` 即使配置正预算也请求零，`allowed`
请求预算除以 8 后向下取整的 wire bytes/s。零上限禁用可选业务和控制副本，但保留首份、必要控制和普通可靠重传。
调度器应用关系权重、billing 倍率、有效容量、拥塞窗口、RTT、抖动和丢包，
不得超过 Path 的流控上报限制。

`classes`、`classReplicationBudgetBps` 和 `trafficClassRef` 已退休并拒绝，包括空值或零值。策略每个 Session
只捕获一次；后续 Path attach 不能替换策略或提高协商上限。

### Listener

Listener 的完整字段见[平台和 DNS 规范](../platform-and-dns/spec.zh-CN.md)。Listener 由 metadata.name 标识，
spec 包含 type、platform（`linux`、`windows`、`freebsd` 或默认值 `any`）和 authentication（默认 disabled），还可以包含最多 256 个合法 tag
组成的 `flowTags`，以及带布尔字段 `executable`、`user`、`group` 的 `processMetadata` 请求。静态 flow
tags 会复制到每个接收的 flow；平台无法安全获取的进程事实表示 unknown。显式平台必须与实际主机匹配，
`any` 使用实际主机的平台矩阵。FreeBSD 允许 `http`、`socks5` 和 `mixed`，拒绝 `tproxy`、`redirect` 和 `tun`。
不支持的平台/type 组合必须在验证期间拒绝，不得忽略。

`spec.type` 接受 `socks` 作为规范名称 `socks5` 的输入别名；规范化序列化必须输出 `socks5`。
规范名称的监听器接受 SOCKS4/4a/5 CONNECT 和 SOCKS5 UDP ASSOCIATE。要求密码认证时必须拒绝
SOCKS4/4a，不得降级 verifier。HTTP 监听器支持普通 `http://` 转发和 CONNECT，并对每个请求独立
认证和求值策略。消息 framing、限制、凭据/头字段过滤和升级行为遵循
[HTTP 和 SOCKS 契约](../platform-and-dns/spec.zh-CN.md#http-和-socks-监听器)。

`spec.backend` 默认值为 `tproxy`。`backend: ebpf` 仅适用于 Linux 的 `type: tproxy`，必须使用
`platform: linux`、非空的 ingress `interface` 和至少一个 `allowedSources` CIDR。它在该接口上为
TCP/UDP 数据包设置现有 TPROXY 策略路由所需的标记；透明 listener、原目标处理、UDP association
以及 Path/Session 策略仍在用户态完成。其他 Listener 类型在验证期间拒绝 `backend: ebpf`。

`spec.type: mixed` 在一个 TCP 端点上共用 HTTP 和 SOCKS。其 `protocols` 默认值为
`[tcp, udp]`；TCP 必须启用，UDP 可选。两个 parser 共用相同的凭据、来源限制和 Listener 身份。

### DNSPolicy 和 FallbackPolicy

完整 Ingress 资源图必须恰好有一个 DNSPolicy 和一个 FallbackPolicy。DNSPolicy 的字段和默认值见平台和 DNS 规范，Fake-IP 禁止。

```yaml
apiVersion: pathchord.io/v1
kind: FallbackPolicy
metadata:
  name: default-fallback
spec:
  action: reject
```

### 配置来源

Ingress 接受一个资源文件或一棵目录树；Egress 接受包含一个 EgressService 的来源。每个角色按以下优先级从高到低选择：

1. 显式 `--config`（`-c`）或 `--config-dir`（`-C`），两个选项互斥。`--config` 接受文件或
   目录；`--config-dir` 要求目录。
2. 非空的 `PATHCHORD_CONFIG` 或 `PATHCHORD_CONFIG_DIR`，两者在环境变量层互斥，文件/目录
   语义与对应命令行选项相同。显式命令行来源覆盖两个环境变量，包括它们之间的冲突。
3. 账号默认值：Ingress 普通用户为 `~/.config/pathchord/ingress`、服务账号为 `/etc/pathchord/ingress`；
   Egress 使用 `~/.config/pathchord/egress` 或 `/etc/pathchord/egress`。
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
前文件”的语义。合并后的 Ingress 资源图必须恰好包含一个 DNSPolicy 和一个 FallbackPolicy。运行时数据和
私有凭据 JSON 必须放在资源树外，或使用非资源文件扩展名。
规范化资源图由资源身份和显式规则顺序决定；把未变更的资源移到其他来源文件不得要求重启。

### 快照发布和重载

加载器必须先解析、验证、规范化并编译完整对象图，再发布不可变代次。连接在 Egress/Proxy 求值前捕获一个
代次并使用到完整决策结束。运行时观测不能覆盖期望 spec。静态 Egress 拓扑、Path-pool 数量、准入要求、
Transit 绑定、引用的 TrafficPolicy 内容、本地密钥、EgressService 启动设置、监听器绑定和平台路由需要重启；订阅、导入 Proxy、管理员 label、DNS
健康和编译后的动态规则可以热重载。替换必须原子化；
解析、验证、编译、持久化或缓存失败时，上一成功代次保持生效并通过类型化 status 暴露错误。

对于声明式 Subscription，管理接口的启用、禁用、删除或显式重新创建在声明未改变时必须跨重载
和重启持续生效。修改声明会应用新的 spec；移除声明会移除该声明式订阅，并排空其导入的节点。
仅通过管理接口创建的订阅独立于无关声明。这些决定及其配置代次必须原子持久化。

目录中的创建、修改、删除和重命名事件触发完整候选重扫。单文件原子替换和根目录替换后必须
保留监听能力。所有文件验证通过后才发布一个快照；非法、不完整或重复的候选保留上一份有效
配置集合。只在启动时加载的字段发生变化时，继续报告需要重启。未被任何 Egress 引用的 TrafficPolicy
变化不触发 Egress 启动边界；等价默认值和文件/映射顺序变化也不触发重启。
