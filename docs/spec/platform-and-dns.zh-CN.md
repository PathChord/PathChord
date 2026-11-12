# PathChord 平台与 DNS 规范

[English](platform-and-dns.md) | **简体中文**

本文档定义平台专用监听器契约以及[配置 schema](configuration-schema.zh-CN.md)引用的独立 DNS
策略。平台适配器在 Linux 和 Windows 上暴露相同的策略上下文和失败类别，不改变 PathChord
Session 或线协议。

## 平台矩阵

| 监听器类型 | Linux | Windows | 地址语义 |
|---|---|---|---|
| `http` | 必须支持 | 必须支持 | 显式 HTTP 主机名或地址 |
| `socks5` | 必须支持 | 必须支持 | 显式 SOCKS5 主机名或地址 |
| `tproxy` | 必须支持 | 必须不支持 | 透明 TCP/UDP IP 流 |
| `redirect` | 必须支持 | 必须不支持 | 透明 TCP 流 |
| `tun` | 可以支持 | 必须支持 | 通过 TUN 适配器传输的 IP 包 |

不支持的类型/平台组合属于配置错误。平台适配器必须将不可用监听器报告为类型化本地失败，
不得静默替换为另一种监听器类型。

## 通用监听器 schema

每个监听器使用以下结构：

```yaml
apiVersion: pathchord.io/v1
kind: Listener
metadata:
  name: lan-socks
spec:
  type: socks5
  platform: linux
  bind: 0.0.0.0:1080
  allowedSources: [192.168.1.0/24]
  authentication:
    mode: required
    credentialsRef: lan-socks-users
```

`metadata.name` 是唯一资源名。`spec.type` 为矩阵中的一种类型，`spec.platform` 为 `linux`、`windows` 或 `any`
（默认 `any`）。`bind` 是套接字地址，对 `http`、`socks5`、`tproxy` 和 `redirect` 必填；对 `tun`
和 `tun` 禁止。系统代理集成由仅限 Windows 的控制面开关管理，不增加 Listener 类型。`spec.allowedSources` 是最多 256 个 CIDR 的列表；回环绑定默认只允许本机，
显式非回环监听器的空列表表示“所有来源地址”。非回环绑定应当使用显式列表。

认证可以是标量 `disabled`，也可以是映射：

```yaml
authentication:
  mode: required # disabled | required
  credentialsRef: listener-users
```

`mode: required` 时必须提供 `credentialsRef`；该引用只能通过本地秘密存储解析，绝不能通过 data
Path 发送或由控制 API 返回。监听器认证独立于 Ingress 到 Egress 的 Noise 认证。认证失败属于
`LOCAL_POLICY`，且必须只关闭或拒绝受影响的本地连接。

可选的 `processMetadata` 块请求进程可执行文件、用户或进程组元数据用于策略求值。缺失元数据
表示 unknown；不得从日志行伪造，也不得因此隐式放行。

## HTTP 和 SOCKS 监听器

HTTP 和 SOCKS 监听器终止本地代理协议，并将显式主机名、地址候选和端口交给策略求值。由于请求
携带主机名，它们可以按主机名路由。格式错误、未支持命令或监听器认证失败必须返回适配器的正常
本地错误，不得创建 Session 或目标连接。

HTTP CONNECT 和 SOCKS5 CONNECT 使用 TCP Stream 契约。SOCKS5 UDP ASSOCIATE 使用 UDP Association
契约并保留数据报边界。监听器必须保留原始主机名，即使同时解析了本地候选地址；不得仅为绕过配置的
DNS 路由而解析名称。

## Linux 透明监听器

### TPROXY

```yaml
apiVersion: pathchord.io/v1
kind: Listener
metadata:
  name: lan-tproxy
spec:
  type: tproxy
  platform: linux
  bind: 0.0.0.0:15001
  allowedSources: [192.168.1.0/24]
  mark: 0x1
  routeTable: 100
  protocols: [tcp, udp]
```

`mark` 是无符号 32 位包标记，`routeTable` 是 `1..=4294967295` 的整数；两者对 `tproxy` 都必填。
适配器保留原始目标地址和端口，并使用内核透明套接字元数据。TCP 和 UDP 按 `protocols` 独立准入，
默认值为 `[tcp, udp]`。

### REDIRECT

```yaml
apiVersion: pathchord.io/v1
kind: Listener
metadata:
  name: lan-redirect
spec:
  type: redirect
  platform: linux
  bind: 0.0.0.0:15002
  allowedSources: [192.168.1.0/24]
  protocols: [tcp]
```

`redirect` 仅支持 TCP，必须从平台套接字元数据取得原始目标。如果原始目标不可用，连接以
`LOCAL_POLICY` 失败；适配器不得把监听器地址当作目标。

透明监听器不执行域名路由。仅含 IP 的流按照地址、端口、协议和可用进程元数据匹配。如果策略
要求缺失的主机名，则条件不匹配。

## Windows TUN 和系统代理控制面开关

系统代理是 Windows 的控制面开关，不是 Listener 类型。启用时必须按 ID 指定现有 HTTP 或 SOCKS Listener：

```text
POST /api/v1/system-proxy/enable
{"listener_id":"local-http"}
```

Linux 调用该操作必须返回平台不支持。Windows 必须拒绝缺失、未知、TUN、TPROXY、REDIRECT 或其他
不兼容的 Listener 引用。关闭时不得修改环境变量或操作系统代理设置。Windows 必须将引用的 Listener
应用到 `HTTP_PROXY`、`HTTPS_PROXY` 和 `ALL_PROXY` 环境变量（在支持时也设置对应的小写别名）以及 Windows
操作系统代理配置，并在关闭或退出时恢复之前的精确值。所选 Listener 和当前效果必须
可通过控制面 status 和结构化事件查看。Linux 用户应通过普通 Listener 资源和控制面查询查看可用监听器；
Linux 不暴露系统代理激活状态。

```yaml
apiVersion: pathchord.io/v1
kind: Listener
metadata:
  name: windows-tun
spec:
  type: tun
  platform: windows
  interface: PathChord
  address: 198.18.0.1/30
  mtu: 1500
  protocols: [tcp, udp]
```

`tun.interface` 是适配器名称，`tun.address` 是 IPv4 或 IPv6 前缀，`tun.mtu` 在 `576..=65535`
范围内（默认 `1500`）。TUN 监听器接收 IP 包，并通过相同策略上下文暴露 TCP/UDP 流；不支持的
IP 协议被拒绝，因为任意 IP 隧道不在协议范围内。

Windows 代理设置恢复失败必须作为类型化平台健康错误出现在结构化状态中，不得只写入日志。

## 环路防护和受保护目标

每个平台适配器必须绕过自身透明拦截，至少包括：

- Ingress Unix socket 或 Named Pipe 以及 Web Gateway 监听器；
- 配置的 Transit Proxy 端点；
- 配置的 Egress 端点；
- 配置的 DNS 上游端点；
- 维护这些连接所需的平台控制流量。

绕过集合由已发布的静态和动态快照派生，并与快照原子替换。规则不能把受保护的控制流量重新
路由回同一 Ingress。如果无法排除端点而不形成环路，受影响监听器进入 `degraded`，新流以
`LOCAL_POLICY` 失败；现有控制连接不得静默改道。

## DNS 配置

DNS 是独立策略，不创建 Fake-IP 映射。schema 如下：

```yaml
apiVersion: pathchord.io/v1
kind: DNSPolicy
metadata:
  name: default-dns
spec:
  defaultRoute: local # local | transit | egress | blocked
  local:
    servers: [192.168.1.1:53, "[2001:db8::53]:53"]
  transit:
    proxySelector: {tags: [dns]}
  egress:
    egressSelector: {labels: {region: jp}}
  blockedResponse: refused # nxdomain | refused | servfail
  timeoutSeconds: 5
  maxInflight: 1024
  cache:
    enabled: true
    maxEntries: 100000
    maxTtlSeconds: 86400
```

`defaultRoute` 默认 `local`。路由为 `local` 时必须提供 `local.servers`；每个端点在未指定端口
时使用 53。路由为 `transit` 时必须提供 `transit.proxySelector`，路由为 `egress` 时必须提供
`egress.egressSelector`。`blockedResponse` 默认 `refused`。`timeoutSeconds` 范围 `1..=60`，
默认 `5`；`maxInflight` 范围 `1..=100000`，默认 `1024`；缓存 `maxEntries` 范围 `0..=1000000`，
默认 `100000`，`maxTtlSeconds` 范围 `1..=604800`，默认 `86400`。缓存仅作参考，不能覆盖硬性
阻止路由。

四种路由语义如下：

| 路由 | 行为 |
|---|---|
| `local` | 将 DNS 查询发送给配置的本地解析器 |
| `transit` | 通过一个准入的 Transit Proxy 发送查询；不创建 Egress Session |
| `egress` | 通过选定的 Egress Session 及其 DNS 策略发送查询 |
| `blocked` | 不发送查询；返回 `blockedResponse` |

在任何普通流规则之前先按 DNS 策略匹配查询。路由失败返回类型化 DNS 失败（`timeout`、
`unavailable` 或 `blocked`），不得静默回退到另一条路由。Schema 版本 1 没有隐式 DNS 回退；
只尝试已配置的路由。

## 主机名和地址候选

对于 HTTP/SOCKS 请求以及 `STREAM_OPEN`/`UDP_OPEN`，如果提供原始主机名必须保留。解析出的地址
候选是可选的，并按照选定 Egress 的 DNS 策略尝试；要求远程解析的策略不会被候选地址覆盖。既无
主机名也无地址候选的请求无效。端口 0 无效。

DNS 响应绝不生成 Fake-IP 地址。需要字面 IP 的调用方必须显式提供，否则得到类型化解析失败。
IPv4/IPv6 选择考虑能力：选定监听器、Transit Proxy 或 Egress 不支持的地址族会被跳过，所有候选
耗尽时返回 `TARGET_FAILURE`。

## 重载和失败行为

监听器绑定/路由设置和 DNS 路由拓扑属于启动字段，变更需要重启。解析器健康、缓存内容、订阅节点
和运行时路由可用性属于动态观测，可以在不替换静态监听器配置的情况下更新。

监听器失去平台资源时停止接受新连接并报告 `degraded`；现有 Session 按正常故障规则继续。DNS
路由或解析器不可用不会改变已配置路由。所有限制必须在分配前执行；资源耗尽返回类型化本地/资源
错误，而不是静默丢弃 TCP 字节或创建未跟踪流。

应用到 `HTTP_PROXY`、`HTTPS_PROXY` 和 `ALL_PROXY` 环境变量（在支持时也设置对应的小写别名）以及 Windows
操作系统代理配置，并在关闭或退出时恢复之前的精确值。
