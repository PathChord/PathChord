# PathChord geodata 路由规范

[English](spec.md) | **简体中文**

## Purpose

定义 Ingress 路由决策中有界、确定的 geosite 和 geoip 数据集加载与匹配行为。

## Requirements

### Requirement: V2Fly geodata compatibility

Ingress SHALL 加载运维人员提供的 V2Fly `GeoSiteList` 和 `GeoIPList` protobuf 数据库，并在发布所属配置代次前解析命名集合。它 SHALL 按详细契约实现匹配类型和属性。

#### Scenario: Use the upstream Hugging Face set

- **WHEN** 有效的 domain-list-community 数据库包含 `huggingface` 集合，且规则引用该集合
- **THEN** `huggingface.co`、`hf.co` 及 `us.aws.cdn.hf.co` 等符合标签边界的子域名按照发布的集合匹配

#### Scenario: Load a V2Fly GeoIP set

- **WHEN** 有效的 v2fly/geoip 数据库在引用的集合中包含 IPv4 或 IPv6 CIDR
- **THEN** 可用的目标地址属于该 CIDR 时，按集合声明的反向匹配语义进行匹配

### Requirement: Hostname and IP facts remain distinct

Geosite SHALL 匹配可用的原始主机名。GeoIP SHALL 匹配可用的原始目标 IP。两种条件均不得（SHALL NOT）触发名称解析，也不得虚构地址或主机名。

#### Scenario: IP-only transparent destination

- **WHEN** 透明 flow 具有 IP 目标而没有原始主机名
- **THEN** geosite 条件不匹配未知主机名，geoip 条件对原始 IP 求值

#### Scenario: Hostname-only explicit destination

- **WHEN** 显式代理请求具有主机名但没有原始目标 IP
- **THEN** geosite 条件对该主机名求值，geoip 条件不会匹配虚构地址

### Requirement: Geodata validation is bounded and atomic

数据库读取、解码条目、编译后的正则表达式和索引 SHALL 具有明确的实现限制。被引用的数据缺失、格式错误、不受支持、超限或无法解析时 SHALL 拒绝候选代次，并在不暴露私有路径或无关数据的情况下标识数据库及集合。

#### Scenario: Invalid replacement database

- **WHEN** 被引用的数据库在重载时被替换为格式错误或超限的文件
- **THEN** 候选以有界诊断失败，之前发布的配置与 geodata 代次继续生效

#### Scenario: Unknown set or unsupported regular expression

- **WHEN** 规则引用不存在的集合，或所选集合含无法安全编译的正则表达式
- **THEN** 发布明确失败，不静默丢弃规则或将集合当成空集合

### Requirement: Geodata matching is deterministic

Geodata 条件 SHALL 使用路由代次捕获的数据库快照，且匹配时不得（SHALL NOT）执行网络 I/O。主机名 SHALL 规范化为小写，根域名匹配 SHALL 遵守 DNS 标签边界；正则表达式保留显式区分大小写的语义。

#### Scenario: Root-domain boundary

- **WHEN** 集合包含根域名 `hf.co`
- **THEN** `hf.co` 和 `us.aws.cdn.hf.co` 匹配，`nothf.co` 不匹配

#### Scenario: Database changes during a decision

- **WHEN** 一个 flow 正在评估有序规则时发布新的数据库代次
- **THEN** 该 flow 使用已捕获的代次完成整个决策

### Requirement: Detailed geodata contract

Geodata 处理 SHALL 遵守完整的[详细契约](#detailed-contract)。

#### Scenario: Apply the detailed contract

- **WHEN** 处理 geodata 配置或匹配
- **THEN** 执行下列 schema、限制和失败语义

## Detailed contract

Geosite 数据库使用 V2Fly router 的 `GeoSiteList` protobuf 结构：包含重复的 `GeoSite` 条目，
每条包含大小写不敏感的集合名称及重复的 `Domain` 条目。`Domain.type` 的值为
`Plain = 0`、`Regex = 1`、`RootDomain = 2`、`Full = 3`；`value` 是 UTF-8 模式，
`attribute` 是带布尔值或整数类型值的重复键。`Plain` 为大小写不敏感的子串匹配；`Regex`
对规范化为小写的主机名进行区分大小写的正则表达式搜索，并遵循显式内联标志；`RootDomain` 匹配该域名本身或以 `.` 分隔的子域名；
`Full` 匹配完整主机名。带 `@attribute` 的引用只选择携带该 true 布尔属性的规则；引用所请求的
类型化属性或模式不受支持时，验证失败。名称和属性均为 ASCII 大小写不敏感。主机名末尾如有
DNS 根点，匹配前移除一个末尾点；连接和观测仍保留原始目标。IP 字面量永不匹配 geosite。

GeoIP 数据库使用 `GeoIPList`，内含重复的 `GeoIP` 条目，每条包含大小写不敏感的集合名称、
CIDR 条目和 `inverse_match`。每条 CIDR 含 4 字节 IPv4 或 16 字节 IPv6 地址，以及分别属于
`0..=32` 或 `0..=128` 范围的前缀。成员关系是前缀的并集，仅在 `inverse_match` 为 true
且原始 IP 存在时取反。IP 缺失表示未知，不能通过取反变成匹配。无效长度或前缀导致发布失败。
IPv4 与 IPv6 地址族保持区分，包括 IPv4 映射 IPv6 地址。

加载器对每个数据库接受最多 64 MiB、3,000,000 条解码条目、4,096 个命名集合，每个域名模式
最多 16,384 字节。它 MUST 限制编译后索引的总大小，并以类型化限制诊断拒绝超过实现上限的
候选。大小写归一后集合名称重复、集合或属性未知、schema 值不受支持、模式无效或记录格式错误
均导致候选发布失败。未引用数据仍进行结构验证；只需为所选集合编译模式。路由期间不会自动
联网获取数据，也不会原位修改已发布索引。
