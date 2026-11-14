# PathChord 部署与本地操作

[English](deployment.md) | **简体中文**

本指南介绍本地代理设置、Linux 特权监听器，以及 Ingress/Egress 的显式登记。请先阅读[配置指南](configuration.zh-CN.md)以选择资源和路由。服务行为要求由[部署规范](../../openspec/specs/deployment/spec.zh-CN.md)定义。

`pathchord` 可执行文件提供 Ingress、Egress 服务子命令和本地管理命令。每次服务调用拥有独立
进程。普通示例使用显式代理监听器，不需要流量拦截或 TUN 权限。Linux 透明代理和 TUN 示例
单独提供，需要下面描述的平台权限和路由设置。

## 配置目录与覆写

没有显式配置选项时，Ingress 为普通账号加载 `~/.config/pathchord`，为 root/服务账号加载
`/etc/pathchord`。显式命令行来源覆盖环境变量，环境变量覆盖账号默认值。例如：

```sh
pathchord ingress
PATHCHORD_CONFIG_DIR=/opt/pathchord/conf.d pathchord ingress
pathchord ingress --config-dir /opt/pathchord/conf.d
pathchord ingress --config /opt/pathchord/single.yaml
```

`PATHCHORD_CONFIG` 也接受文件或目录。未指定命令行来源时，只能设置一个非空配置环境变量。
`--config`/`-c` 与 `--config-dir`/`-C` 互斥。精确的账号分类和优先级由
[配置来源契约](../../openspec/specs/configuration-schema/spec.zh-CN.md#配置来源)定义。

可以把资源拆到所选树中的 `.yaml`、`.yml` 或 `.json` 文件，子目录也会载入。所有资源组成一张
经过统一验证的资源图，因此 Listener、DNSPolicy、FallbackPolicy、节点和路由规则可以放在
不同文件中。私钥/凭据 JSON 和 `--data-dir` 应放在该树外。文件新增、修改、删除和重命名后，
只在完整资源图有效时原子替换；候选失败时保留原配置。

## 本地显式代理

构建可执行文件并运行直接路由示例：

```sh
cargo build --locked --release -p pathchord-cli
./target/release/pathchord ingress --config examples/ingress-direct.yaml
```

普通 Unix 用户的 Ingress 控制 socket 默认使用
`$XDG_RUNTIME_DIR/pathchord/ingress.sock`（该目录可用时），否则使用
`~/.config/pathchord/ingress.sock`。root 和软件包服务账号使用
`/run/pathchord/ingress.sock`；服务包会在启动前创建该运行目录。需要其他本地端点时，
可以显式传入 `--socket`。`enroll` 命令默认使用对应的 `egress.sock` 端点；显式指定的
socket 优先。

Mixed 监听器绑定 `127.0.0.1:7890`。无认证示例限制在回环地址。应用可以对同一个地址选择
HTTP 或 SOCKS：

```sh
curl -x http://127.0.0.1:7890 https://example.com
curl -x socks5h://127.0.0.1:7890 https://example.com
```

直接路由示例把流量直接发送到目标。订阅示例使用普通第三方 Proxy 路由，并明确拒绝没有可用
匹配节点的 flow。使用前必须替换其 provider URL：

```sh
pathchord ingress --config examples/ingress-subscriptions.yaml
```

## Linux 透明代理与 TUN 监听器

[`ingress-tproxy.yaml`](../../examples/ingress-tproxy.yaml) 示例在 Linux 上启动
`0.0.0.0:15001` 的 TPROXY TCP/UDP 接管，使用包标记 `1` 和策略路由表 `100`。把流量发送到
监听器并设置标记的主机 packet-filter 规则仍由管理员负责，必须使用相同的 bind 地址、标记和
路由表。PathChord 只拥有匹配的策略路由对象，并且只删除仍与其 journal 匹配的对象。服务需要
创建透明 socket 和管理路由所需的权限，例如 root 或等效的 `CAP_NET_ADMIN` 与 `CAP_NET_RAW`。

[`ingress-tproxy-ebpf.yaml`](../../examples/ingress-tproxy-ebpf.yaml) 示例选择
`backend: ebpf`，并把一个 Linux TC classifier 挂载到管理员指定的 `lan0` ingress 接口。它只为
TCP/UDP 数据包设置现有 TPROXY 策略路由所需的标记；透明 listener、原目标处理、UDP association
以及 Path/Session 策略仍在用户态完成。eBPF 后端构建时需要 `clang`，运行时需要 `bpftool`、`tc`、
BPF/BTF 内核支持和网络管理特权。该后端刻意绑定单个接口并要求 `allowedSources`；主机无法提供这些
能力时应使用普通 TPROXY 后端。

[`ingress-tun.yaml`](../../examples/ingress-tun.yaml) 示例创建名为 `PathChord`、地址为
`198.18.0.1/30`、MTU 为 1500 的 TUN 接口，并通过相同的策略和 fallback 路由承载 TCP 与 UDP
数据包。运行 Ingress 的账号必须有权限创建和配置 TUN 设备。把所需的主机路由添加到该接口，
并在把主机流量导入之前保留规范中描述的受保护端点旁路。FreeBSD 拒绝透明监听器和 TUN；
Windows 通过原生适配器提供 TUN 支持。

显式指定任一示例启动，避免特权配置被账号默认配置意外加载：

```sh
sudo ./target/release/pathchord ingress --config examples/ingress-tproxy.yaml
sudo ./target/release/pathchord ingress --config examples/ingress-tun.yaml
```

TPROXY 和 TUN 监听器接收 IP flow，因此路由匹配原始 IP 地址、端口、协议和可用的进程元数据。
原始数据包不包含 hostname 时，要求域名的策略条件不会匹配。

未实现的 Transit 协议和参数会保持为类型化节点诊断，直到对应的 PathChord 原生适配器完成。
PathChord 不启动或嵌入外部代理进程作为兼容后端。见
[Transit Proxy 契约](../../openspec/specs/transit-proxies/spec.zh-CN.md)。

## Ingress 与 Egress 登记

在各自对应的机器上生成私有身份。命令只打印公钥；私有文件必须保留在其所有者本地：

```sh
pathchord keygen --output ingress.key.json
pathchord keygen --output egress.key.json
```

在独立终端中启动 Egress。Unix 控制 socket 位于 Egress 本机：

```sh
pathchord egress --egress-id exit --identity egress.key.json \
  --bind 127.0.0.1:9443 --control-socket /tmp/pathchord-egress.sock
```

在 Egress 机器上显式登记 Ingress 公钥。把 `INGRESS_PUBLIC_KEY` 替换为 Ingress 身份生成命令
打印的公钥。代次 0 适用于新授权数据库；后续变更必须使用其观测到的代次：

```sh
pathchord --socket /tmp/pathchord-egress.sock enroll add \
  --ingress-id entry --egress-id exit --public-key INGRESS_PUBLIC_KEY \
  --expected-generation 0
```

在 `examples/ingress-egress.yaml` 中，把 `REPLACE_WITH_EGRESS_PUBLIC_KEY` 替换为 Egress 公钥。
示例使用回环 Egress 地址；跨机器部署必须设置可达的 Egress bind/address，并保留相同的、
已经显式核验的公钥和规范 Egress ID。在另一个独立终端中启动 Ingress：

```sh
pathchord --socket /tmp/pathchord-ingress.sock ingress \
  --ingress-id entry --identity ingress.key.json \
  --config examples/ingress-egress.yaml
pathchord --socket /tmp/pathchord-ingress.sock status
pathchord --socket /tmp/pathchord-egress.sock enroll list
```

示例的 `direct-path` 是到经过认证的 Egress 的直接传输。将它替换为 HTTP、HTTPS、SOCKS5、
Shadowsocks Transit 时，只改变传输，端到端 Noise 和显式登记契约保持一致。
经由 Egress 的 UDP flow 要求 Egress 具有 UDP 能力，并具有 TCP Transit Path；普通第三方 UDP
路由还要求所选节点自身支持原生 UDP。

## 凭据、管理与关停

监听器和节点秘密存储在 `--credentials-dir` 指定目录的私有 JSON 文件中，文件以不透明的
`credentialsRef` 值命名。Basic 或 SOCKS5 凭据文档包含 `username` 和 `password`，不得提交到
仓库。要求监听器认证时必须拒绝 SOCKS4/4a。

Unix socket 的所有权/权限和 Windows Named Pipe ACL 保护本地管理接口。Socket 路径位于服务
所在机器。Windows 对应控制端点使用 Named Pipe 名称。Web Gateway 通过 `--web-bind` 显式
启用，并共用本地 dispatcher；配置的 `--web-token-file` 提供 bearer token。Prometheus 在
`/metrics` 抓取，使用相同的认证、Origin 检查和 `metrics:read` 能力。

每个服务接受 Ctrl-C 关停，在 Unix 上也接受 SIGTERM，并拥有任务和连接清理责任。持久配置变更遵循重载契约；身份、
监听器拓扑和其他只在启动时加载的设置，在重载响应明确要求时需要重启服务。
