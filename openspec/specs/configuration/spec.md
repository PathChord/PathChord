# PathChord configuration specification

**English** | [简体中文](spec.zh-CN.md)

## Purpose

Define PathChord's declarative resource model, ordered routing decisions, immutable runtime snapshots, and dynamic configuration ownership independently of management and data-Path encodings.

## Requirements

### Requirement: Declarative configuration contract

Configuration processing SHALL conform to the complete [detailed contract](#detailed-contract), including its object model, examples, listener references, namespace ownership, and update rules. Desired configuration and read-only runtime status SHALL remain separate.

#### Scenario: Publish validated desired resources

- **WHEN** a configuration bundle is accepted for publication
- **THEN** its complete object graph is validated and converted into a typed immutable snapshot, with runtime observations exposed separately through read-only `status` views

### Requirement: Ordered routing and explicit fallback

Ingress SHALL evaluate effective Egress rules before ordinary Proxy rules and the mandatory global fallback. Ordered Egress and Transit rules SHALL select the first admissible match, and an unsupported ordinary UDP route SHALL fail according to policy without a direct bypass.

#### Scenario: No effective Egress route is selected

- **WHEN** ordered effective Egress rules do not select an admissible route for a new flow
- **THEN** Ingress evaluates ordinary Proxy rules and then the configured global fallback in that order

### Requirement: Immutable decision generation

A new connection SHALL capture one monotonically numbered snapshot generation before rule evaluation and use it for the complete Egress and Proxy decision. Existing Sessions, Streams, and Paths SHALL retain their admission generation unless hard revocation or Egress failure closes them.

#### Scenario: Publish configuration during route evaluation

- **WHEN** a new snapshot is published while a connection is evaluating its route
- **THEN** that connection completes its Egress and Proxy selection using the generation it already captured

### Requirement: Bounded replication policy

The Session replication budget SHALL be the hard upper bound; a class budget SHALL NOT exceed its remaining Session budget. A `trafficClassRef` SHALL resolve within the selected TrafficPolicy, and an absent reference SHALL use the default class.

#### Scenario: Unknown traffic class is configured

- **WHEN** a TransitRule names a class that does not exist in its selected TrafficPolicy
- **THEN** validation rejects the reference instead of admitting the flow under an arbitrary class

### Requirement: Atomic dynamic updates and draining

Subscription and compiled-rule updates SHALL replace their snapshots atomically, and failed refresh or compilation SHALL retain the last successful snapshot. Removed Transit Proxies SHALL be excluded from new selections while existing Paths drain or fail.

#### Scenario: Remove a Transit Proxy with an existing Path

- **WHEN** a subscription update removes a Transit Proxy that carries an existing Path
- **THEN** the node enters draining, new selections exclude it, and the existing Path remains until drain completion or failure

### Requirement: Owned metadata mutations

Administrator label/tag edits SHALL modify only `admin.*`, require the expected generation or an explicitly authorized force capability, and publish atomically. Runtime observations SHALL remain runtime-owned, and hard revoked, disabled, or disconnected states SHALL exclude a node regardless of labels.

#### Scenario: Labels are present on a revoked node

- **WHEN** a node's labels satisfy a selector but its hard runtime state is revoked
- **THEN** the selector cannot make that node eligible for selection

### Requirement: Session maintenance per Egress

Ingress SHALL maintain one Session slot per configured Egress, reuse live idle Sessions for subsequent Streams and UDP Associations, and destroy the Session and related business connections when that Egress goes offline or suffers a hard failure.

#### Scenario: Egress recovers after hard failure

- **WHEN** an Egress becomes online after its previous Session was destroyed by hard failure
- **THEN** Ingress creates a new Session and Path set instead of resurrecting the old Session

## Detailed contract

This document explains the Kubernetes-style configuration objects and evaluation order. The
normative field, type, default, and validation contract is the
[versioned configuration schema](../configuration-schema/spec.md); platform listeners
and independent DNS are defined in the [platform and DNS specification](../platform-and-dns/spec.md).
Configuration uses `apiVersion: pathchord.io/v1`, `kind`, `metadata`, and
`spec` objects. A `kind: List` object is the normal multi-resource form; the
snippets below show either complete objects or `spec` fragments as labeled.
Configuration adapters validate the complete object graph and convert it into
typed immutable snapshots before publication. Runtime observations are exposed
as read-only `status` views and are never mixed into desired `spec`. Management
operations use the JSON envelopes defined in the [protocol specification](../protocol/spec.md);
configuration YAML is not a management-message or data-Path wire encoding.

### Canonical object set

Configuration may be a single resource file or a recursively loaded resource
directory. Ingress selects command-line configuration before environment
configuration and account defaults. The complete bundle is validated together;
see [configuration sources](../configuration-schema/spec.md#configuration-sources)
for directory discovery, defaults, limits, and reload semantics.

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
  - apiVersion: pathchord.io/v1
    kind: DNSPolicy
    metadata:
      name: default-dns
    spec:
      defaultRoute: local
      local:
        servers: [192.168.1.1:53]
  - apiVersion: pathchord.io/v1
    kind: FallbackPolicy
    metadata:
      name: default-fallback
    spec:
      action: reject
```

Resource references use `metadata.name` (for example, `egressRef: jp-1`),
never collection-local `id` fields. `metadata.generation` and a read-only
`status` are produced by the control plane after publication.

### Static Egress topology

```yaml
apiVersion: pathchord.io/v1
kind: Egress
metadata:
  name: jp-1
  labels:
    region: jp
    role: egress
spec:
  address: egress.example.net
  port: 443
  publicKey: <curve25519-public-key>
  capabilities:
    tcp: true
    udp: true
```

### Dynamic Transit Proxy data

Node protocols, typed `options`, import formats, credential boundaries, and
provider accounting follow the [Transit Proxy contract](../transit-proxies/spec.md).
Subscription formats and executable node protocols are independent capabilities.

```yaml
apiVersion: pathchord.io/v1
kind: TransitProxy
metadata:
  name: provider-a-node-01
  labels:
    region: jp
    provider: provider-a
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

The following is a read-only runtime `status` view, not administrator-authored desired YAML:

```yaml
status:
  observed:
    connected: true
    rttMs: 42
    jitterMs: 5
    lossRate: 0.002
    effectiveCapacityBps: 180000000
  quota:
    remainingRatio: 0.42
    resetAt: 2026-12-01T00:00:00Z
  billing:
    trafficMultiplier: 2.0
```

### Ordered Egress rules

```yaml
apiVersion: pathchord.io/v1
kind: EgressRule
metadata:
  name: jp-gaming
spec:
  order: 10
  match:
    flowTags: [gaming]
    protocols: [tcp, udp]
  egressRef: jp-1
  requirements:
    minUsablePaths: 1
```

The first rule whose conditions match and whose Egress is currently usable wins. Egress usability is precomputed by the runtime state manager.

### Egress-specific Proxy rules

```yaml
apiVersion: pathchord.io/v1
kind: TransitRule
metadata:
  name: jp-1-gaming
spec:
  order: 20
  egressRef: jp-1
  match:
    flowTags: [gaming]
  require:
    labels:
      region: jp
    capabilities: [udp]
  reject:
    tags: [quota-exhausted]
  weight: 100
  trafficPolicyRef: gaming-default
```

Rules are ordered. The first matching rule determines admission and base relationship weight.

Traffic policies may define multipath scheduling and replication budgets:

```yaml
apiVersion: pathchord.io/v1
kind: TrafficPolicy
metadata:
  name: gaming-default
spec:
  scheduler: effectiveCapacityWeighted
  sessionReplicationBudgetBps: 2000000
  classReplicationBudgetBps: 1000000
  retransmissionReplication: allowed
```

`TransitRule.spec.trafficClassRef` optionally assigns admitted flows to a class in the selected `TrafficPolicy`. Unknown references are rejected during validation; a missing reference uses the default class.

The Session budget is the hard upper bound. A traffic-class budget can reduce the allocation for that class but cannot exceed the remaining Session budget.

### Ordinary Proxy rules and fallback

Ordinary routes support native UDP through direct, SOCKS5, and SS adapters
when the selected node permits UDP. Egress UDP Session traffic is independent
of a Transit node's native UDP capability. Unsupported ordinary UDP routes
fail according to policy without a direct bypass.

```yaml
apiVersion: pathchord.io/v1
kind: ProxyRule
metadata:
  name: direct-jp
spec:
  order: 30
  match:
    flowTags: [web]
  require:
    labels:
      region: jp
  select: any

---
apiVersion: pathchord.io/v1
kind: FallbackPolicy
metadata:
  name: default-fallback
spec:
  action: reject # or direct
```

`TransitRule.spec.trafficClassRef` optionally selects the class snapshot used by the Session scheduler.

Selection order is:

```text
ordered effective Egress rules
→ ordered ordinary Proxy rules
→ mandatory global fallback
```

### Listeners

The complete listener schema, including mandatory ordinary HTTP forwarding,
HTTP CONNECT, SOCKS4/4a/5 CONNECT, and SOCKS5 UDP ASSOCIATE support on Linux,
Windows, and FreeBSD, Linux transparent
modes and optional TUN, Windows TUN and the control-plane system-proxy switch,
authentication references, source restrictions, and loop prevention is defined in
[the platform and DNS specification](../platform-and-dns/spec.md).
`spec.platform` accepts `linux`, `windows`, `freebsd`, and `any`; `any` uses the
actual host's platform matrix. FreeBSD rejects `tproxy`, `redirect`, and `tun`.
`spec.type: socks` is an input alias for canonical `socks5`; normalized output
uses `socks5`, and either spelling accepts SOCKS4/4a/5. HTTP requests on a
persistent client connection are authenticated and routed independently. Full
request framing, header filtering, upgrade, and version-specific authentication
contracts are defined in the linked platform specification.

```yaml
apiVersion: pathchord.io/v1
kind: Listener
metadata:
  name: lan-socks
spec:
  type: socks5
  bind: 0.0.0.0:1080
  allowedSources: [192.168.1.0/24]
  flowTags: [interactive]
  processMetadata:
    executable: true
  authentication:
    mode: required
    credentialsRef: lan-socks-users
```

`listener_id`, source address, authentication identity, process metadata, protocol, and target address are available to rules.

DNS is an independent policy. Its `local`, `transit`, `egress`, and `blocked`
routes, resolver limits, cache behavior, hostname/candidate handling, and
Fake-IP prohibition are normative in
[the platform and DNS specification](../platform-and-dns/spec.md).

`spec.type: mixed` binds one TCP port for the HTTP and SOCKS contracts above.
Its `protocols` default to `[tcp, udp]` and MUST include TCP. SOCKS5 UDP uses
the negotiated relay endpoint. See [mixed dispatch](../platform-and-dns/spec.md#mixed-listener-dispatch)
for protocol detection and shared authentication semantics.

### Runtime snapshots

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
  egressSelector: { labels: { region: jp } }
  proxySelector: { tags: [gaming] }
  trafficPolicyRef: gaming-default
```

Rules do not embed a concrete dynamic Proxy identity. The scheduler resolves selectors against the current runtime state and applies health, capacity, weight, quota metadata, and Path policy.

### Label and tag namespaces

The internal node model uses namespaced attributes:

```text
node.*      static identity and protocol attributes
admin.*     local administrator annotations
source.*    subscription source and imported metadata
observed.*  runtime measurements and derived state
quota.*     optional provider quota metadata
billing.*   optional provider billing metadata
```

Local administrator attributes override imported source attributes. Observed attributes are owned by the runtime and cannot be overridden by subscription data. Hard runtime states such as revoked, disabled, or disconnected always exclude a node regardless of labels.

### Dynamic update rules

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

### Session maintenance

Ingress maintains one Session slot per configured Egress. When Ingress starts, it attempts to establish Sessions for Egresses whose current effective state is online. A Session remains alive while idle and is reused by subsequent Streams and UDP Associations. When an Egress becomes offline or enters hard failure, its Session and all related business connections are destroyed. When the Egress becomes online again, Ingress creates a new Session and Path set.
