# PathChord Configuration Model

**English** | [简体中文](configuration.zh-CN.md)

This is a conceptual model. Exact serialization is not fixed.

## Static Egress topology

```yaml
egresses:
  - id: jp-1
    address: egress.example.net
    port: 443
    public_key: <curve25519-public-key>
    labels:
      region: jp
      role: egress
    capabilities:
      tcp: true
      udp: true
```

## Dynamic Transit Proxy data

```yaml
transit_proxies:
  - id: provider-a-node-01
    source:
      type: clash
      subscription: provider-a
    protocol: vless
    address: proxy.example.net
    port: 443
    labels:
      region: jp
      provider: provider-a
    tags: [gaming]
    weight: 100
```

Runtime fields are maintained separately:

```yaml
observed:
  connected: true
  rtt_ms: 42
  jitter_ms: 5
  loss_rate: 0.002
  effective_capacity_bps: 180000000
quota:
  remaining_ratio: 0.42
  reset_at: 2026-12-01T00:00:00Z
billing:
  traffic_multiplier: 2.0
```

## Ordered Egress rules

```yaml
egress_rules:
  - id: jp-gaming
    match:
      flow_tags: [gaming]
      protocol: [tcp, udp]
    egress: jp-1
    requirements:
      min_usable_paths: 1
```

The first rule whose conditions match and whose Egress is currently usable wins. Egress usability is precomputed by the runtime state manager.

## Egress-specific Proxy rules

```yaml
transit_rules:
  - id: jp-1-gaming
    egress: jp-1
    match:
      flow_tags: [gaming]
    require:
      labels:
        region: jp
      capabilities: [udp]
    reject:
      tags: [quota-exhausted]
    weight: 100
    traffic_policy: gaming-default
```

Rules are ordered. The first matching rule determines admission and base relationship weight.

Traffic policies may define multipath scheduling and replication budgets:

```yaml
traffic_policies:
  gaming-default:
    scheduler: effective_capacity_weighted
    session_replication_budget_bps: 2000000
    class_replication_budget_bps: 1000000
    retransmission_replication: allowed
```

The Session budget is the hard upper bound. A traffic-class budget can reduce the allocation for that class but cannot exceed the remaining Session budget.

## Ordinary Proxy rules and fallback

```yaml
proxy_rules:
  - id: direct-jp
    match:
      flow_tags: [web]
    require:
      labels:
        region: jp
    select: any

fallback:
  action: reject # or direct
```

Selection order is:

```text
ordered effective Egress rules
→ ordered ordinary Proxy rules
→ mandatory global fallback
```

## Listeners

```yaml
listeners:
  - id: lan-socks
    type: socks5
    bind: 0.0.0.0:1080
    allowed_sources: [192.168.1.0/24]
    authentication: required

  - id: local-http
    type: http
    bind: 127.0.0.1:8080
    authentication: disabled
```

`listener_id`, source address, authentication identity, process metadata, protocol, and target address are available to rules.

## Runtime snapshots

Configuration is evaluated through immutable snapshots:

```text
Static Egress topology
        +
Dynamic Transit Proxy snapshot
        +
Compiled rule snapshot
        +
Observed node and Egress state
        = effective runtime snapshot
```

Each snapshot has a monotonically increasing generation. A new connection captures one generation at the beginning of rule evaluation and uses that snapshot for the complete Egress and Proxy selection. Existing Sessions, Streams, and Paths continue using the generation under which they were admitted unless a hard revocation or Egress failure closes them.

Rule evaluation produces only policy data:

```yaml
decision:
  egress_selector: { labels: { region: jp } }
  proxy_selector: { tags: [gaming] }
  traffic_policy: gaming-default
```

Rules do not embed a concrete dynamic Proxy identity. The scheduler resolves selectors against the current runtime state and applies health, capacity, weight, quota metadata, and Path policy.

## Label and tag namespaces

The internal node model uses namespaced attributes:

```text
node.*      static identity and protocol attributes
admin.*     local administrator annotations
source.*    subscription source and imported metadata
observed.*  runtime measurements and derived state
quota.*     optional provider quota metadata
```

Local administrator attributes override imported source attributes. Observed attributes are owned by the runtime and cannot be overridden by subscription data. Hard runtime states such as revoked, disabled, or disconnected always exclude a node regardless of labels.

## Dynamic update rules

- Static Egress topology changes require an Ingress restart.
- Transit Proxy subscription updates replace the dynamic snapshot atomically.
- A failed subscription refresh retains the last successful snapshot.
- Removed Transit Proxies enter draining and are excluded from new selections.
- Existing Paths using a removed Transit Proxy remain until drain completion or failure.
- Compiled rules are replaced atomically; a failed compilation retains the previous rule snapshot.
- Runtime observations update independently from configuration generations.

Ingress administrator label/tag edits are dynamic mutations owned by the
control plane. They update only the `admin.*` namespace, require an expected
generation (or an explicitly authorized force capability), and publish a new
snapshot atomically. They do not overwrite `source.*`, `observed.*`, or
`quota.*` values.

Subscriptions are control-plane resources with create, delete, enable/disable,
and manual-refresh operations. A refresh runs against the current subscription
revision; success publishes one new dynamic generation and failure retains the
last successful node snapshot. Deletion removes the subscription from future
refreshes and drains nodes imported solely from that source. Every mutation is
idempotent by actor and request ID and produces an audit event.

The control plane exposes structured snapshots and bounded change events for
nodes, Paths, Sessions, Streams, target connections, subscriptions, and policy
generations. These views are the source for the frontend and metrics endpoint;
logs are not the authoritative state store.

## Session maintenance

Ingress maintains one Session slot per configured Egress. When Ingress starts, it attempts to establish Sessions for Egresses whose current effective state is online. A Session remains alive while idle and is reused by subsequent Streams and UDP Associations. When an Egress becomes offline or enters hard failure, its Session and all related business connections are destroyed. When the Egress becomes online again, Ingress creates a new Session and Path set.
