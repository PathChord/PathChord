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

Ingress SHALL evaluate effective Egress rules before ordinary Proxy rules and the mandatory global fallback. An Egress rule SHALL select an Egress reference or selector, or explicitly enter ordinary Proxy mode with `mode: none`; Transit selection SHALL come from the selected Egress binding. An unsupported ordinary UDP route SHALL fail according to policy without a direct bypass.

#### Scenario: No effective Egress route is selected

- **WHEN** ordered effective Egress rules do not select an admissible route for a new flow
- **THEN** Ingress evaluates ordinary Proxy rules and then the configured global fallback in that order

#### Scenario: Different rules select the same Egress

- **WHEN** two flows match different Egress rules that select the same Egress
- **THEN** both use that Egress's Session Path pool and TrafficPolicy without deriving different Transit candidates or Path requirements from their rules

### Requirement: Bounded ordinary Proxy pre-admission failover

An ordinary Proxy rule SHALL try eligible Transit nodes in stable score and ID order, with at most eight attempts sharing the configured connection timeout and the same policy generation. Once an adapter returns a stream or datagram handle, later failures SHALL NOT trigger replacement or retry.

#### Scenario: The preferred ordinary Transit node fails before admission

- **WHEN** the highest-scoring eligible node fails while opening a new TCP or UDP flow before any application data is admitted
- **THEN** Ingress tries the next eligible node in the compiled order within the bounded limit, without selecting Direct or changing the policy generation

### Requirement: Immutable decision generation

A new connection SHALL capture one monotonically numbered snapshot generation before rule evaluation and use it for the complete Egress and Proxy decision. Existing Sessions, Streams, and Paths SHALL retain their admission generation unless hard revocation or Egress failure closes them.

#### Scenario: Publish configuration during route evaluation

- **WHEN** a new snapshot is published while a connection is evaluating its route
- **THEN** that connection completes its Egress and Proxy selection using the generation it already captured

### Requirement: Bounded replication policy

Each Session SHALL capture the TrafficPolicy selected by its Egress and share one replication allowance per sending direction, bounded by the negotiated Session cap. All admitted Streams and UDP Associations SHALL use that immutable policy without rule, flow, or business-class budget overrides. Separate Sessions SHALL account independently even when they reference the same TrafficPolicy.

#### Scenario: Two flows use different Egress policies

- **WHEN** two flows select Egresses with different TrafficPolicies
- **THEN** each uses the policy and shared allowance of its own Session, without changing the other Session's budget

#### Scenario: Two flows use different policies

- **WHEN** two flows select Egresses with different TrafficPolicies
- **THEN** each uses the policy and shared allowance of its own Session, without changing the other Session's budget

#### Scenario: Unknown traffic class is configured

- **WHEN** a configuration contains a traffic-class reference or retired class policy field
- **THEN** validation rejects that field instead of admitting the flow under a default or arbitrary business class

#### Scenario: Several flows share the replication allowance

- **WHEN** Streams and UDP Associations in one Session request optional copies concurrently in the same sending direction
- **THEN** their combined accounting stays within that direction's remaining Session allowance, after required control reservations, without multiplying it by the number of flows

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

Ingress SHALL maintain one Session slot per configured Egress, best-effort maintain its requested usable-Path baseline without business connections, reuse live idle Sessions for subsequent Streams and UDP Associations, and destroy the Session and related business connections when that Egress goes offline or suffers a hard failure. Baseline shortfall alone SHALL NOT degrade service or deny admission while the common minimum is met.

#### Scenario: Egress recovers after hard failure

- **WHEN** an Egress becomes online after its previous Session was destroyed by hard failure
- **THEN** Ingress creates a new Session and Path set instead of resurrecting the old Session

#### Scenario: Egress warms before a business match

- **WHEN** Ingress starts with a valid Egress binding and no business flow has matched a route
- **THEN** it can establish that Egress's initial Paths without synthesizing a target, listener, flow tag, or geodata match

#### Scenario: Only destination-specific routing rules exist

- **WHEN** Ingress starts with a valid Egress binding and no business flow has matched a rule
- **THEN** it can establish that Egress's initial Paths without synthesizing a target, listener, flow tag, or geodata match

#### Scenario: An idle Egress has an unmet usable-Path baseline

- **WHEN** an eligible Egress has no business connections and usable Paths are below its effective baseline
- **THEN** Ingress makes bounded background establishment attempts toward that baseline without waiting for a route match

#### Scenario: The minimum is met while the baseline is short

- **WHEN** the common minimum is one, the requested baseline is three, and two usable Paths remain
- **THEN** Ingress continues best-effort baseline recovery without degrading service or denying new business solely because the third Path is missing

#### Detailed contract

Egress `pathPool.minUsablePaths` is the common count-based admission
minimum. `pathPool.targetUsablePaths` sets the requested steady-state usable-Path
baseline; omission resolves to the minimum plus one, and an explicit target
receives no additional implicit reserve. The baseline belongs to the
Ingress-side Egress configuration, not an EgressService recommendation or a
routing-rule requirement.

Maintenance operates on each configured Egress binding independently of
listeners, business matches, active Streams, UDP Associations, and DNS traffic.
It best-effort establishes Paths toward the runtime-bounded baseline with
bounded backoff and the existing eligibility, authorization, capacity,
incremental-overhead, and lifecycle guards. Unavailable candidates and
establishment failures SHALL NOT trigger unbounded retries, an implicit Direct
route, or a different Egress.

A baseline shortfall is desired-state information. It SHALL NOT independently
change service health, admission permission, or the common minimum. Existing
capability, authorization, resource, freshness, and hard-failure checks remain
independent and can still deny admission. A shortfall below the common minimum
continues to deny new business while preserving existing work on remaining
ready Paths; loss of the last ready Path retires the Session.

### Requirement: Ingress owns Path target decisions

Ingress SHALL derive one bounded target Path count per Session from the Egress's requested usable-Path baseline and minimum, eligible Transit relationships, aggregate directional demand, Path quality, and hard resource ceilings. Route identities and flow matches SHALL NOT define additional Path targets, and Egress recommendations SHALL NOT override the Ingress decision. Capacity-driven expansion SHALL be allowed above the baseline, with gradual drain-aware contraction when demand subsides.

#### Scenario: Egress has no Path recommendation

- **WHEN** Egress reports capacity and admission state without a recommended Path count
- **THEN** Ingress computes one bounded Session target from its Egress configuration and runtime observations

#### Scenario: An omitted baseline preserves the default reserve

- **WHEN** an Egress configures a minimum of two and omits the target
- **THEN** its requested baseline is three before runtime ceilings are applied

#### Scenario: An explicit baseline adds no hidden reserve

- **WHEN** an Egress explicitly configures a minimum of one and a target of three
- **THEN** its requested baseline is exactly three rather than four

#### Scenario: Capacity demand exceeds the baseline

- **WHEN** fresh directional demand requires five usable Paths while the requested baseline is three and the runtime ceiling permits five
- **THEN** Ingress can expand toward five under the existing scale-out guards without treating the baseline as a maximum

#### Scenario: An expanded Session becomes idle

- **WHEN** an expanded Session's demand subsides and surplus persists through the scale-in stabilization window
- **THEN** Ingress gradually drains excess Paths toward the effective baseline under the existing cooldown and drain guards instead of retaining its historical demand peak

#### Detailed contract

Let `R` be the requested baseline resolved from Egress configuration and
`H` the current hard runtime Path ceiling. The effective baseline is
`B = min(R, H)`. The current physical target covers the larger of the
effective baseline and the independent upstream/downstream capacity
requirements, bounded by `H`. The current target is recomputed from current
observations and SHALL NOT become a monotonic record of the largest historical
load. Unknown demand remains unknown; it SHALL NOT become a fabricated measured
zero or unbounded demand.

The requested baseline SHALL remain observable when a hard ceiling prevents
reaching it. Runtime clamping SHALL NOT rewrite configuration or lower the
common admission minimum. If `H` prevents meeting the minimum, the existing
minimum-shortfall failure and admission semantics apply.

Planned scale-in SHALL preserve the effective baseline and common minimum,
subject to independent hard-failure and lifecycle transitions. Scale-in remains
slow, hysteretic, and drain-aware; it SHALL NOT cut accepted traffic solely to
reach the idle baseline. Expansion, draining, and recovery share the same
eligible Session Path pool and preserve one immutable TrafficPolicy.

### Requirement: Egress Session Path eligibility

All Streams and UDP Associations in one Session SHALL share the Path eligibility defined by its Egress Transit binding, authenticated Path readiness, health, and lifecycle state. The flow's route, target, listener, or business protocol SHALL NOT narrow the Transit set. Egress protocol capability and per-resource flow control SHALL remain enforced. Only eligible authenticated non-draining usable Paths SHALL count toward the minimum and baseline.

#### Scenario: Warmup finds an ineligible Transit

- **WHEN** a ready Transit adapter does not satisfy the Egress Transit binding
- **THEN** it is excluded from the Session pool and does not count toward the Egress minimum

#### Scenario: TCP-only Transit carries Egress UDP

- **WHEN** a Transit provides an eligible byte stream and the selected Egress supports UDP
- **THEN** UDP Associations can use the shared Path pool without requiring the Transit to support native UDP

#### Scenario: One Transit carries several Paths

- **WHEN** one eligible Transit relationship carries several independently authenticated Paths
- **THEN** its non-draining `ACTIVE` or `DEGRADED` Paths can satisfy the Egress Path minimum while sharing that relationship's configured weight

#### Scenario: A draining Path does not satisfy the baseline

- **WHEN** a Session has two eligible authenticated usable Paths and another Path is draining
- **THEN** the usable count for its minimum and baseline is two and maintenance does not use the draining Path to justify another planned drain

#### Detailed contract

The count shared by minimum admission, baseline maintenance, and planned
scale-in is the number of eligible independently authenticated ready Paths in
`ACTIVE` or `DEGRADED` state that are not draining. Connecting, closed,
failed, ineligible, and draining Paths SHALL NOT satisfy either threshold.
Separate independently authenticated Paths can count even when they share one
Transit relationship; the relationship's configured weight remains shared
rather than multiplied by its Path count.

The former `statusRequirements.capabilities` requirement is preserved as
`admission.requiredCapabilities` in native configuration. Moving the key
SHALL NOT weaken capability checks, identity binding, or authorization.

### Requirement: Resource failure does not fall through silently

When a candidate Egress rejects a pre-admission open with `RESOURCE_LIMIT`, Ingress SHALL try another compliant Egress candidate in the captured generation when one exists. If none succeeds, it SHALL return the typed resource failure without silently selecting direct or an unrelated Proxy rule.

#### Scenario: All candidates are saturated

- **WHEN** every compliant Egress candidate reports a resource limit before Stream admission
- **THEN** the local flow fails with a retryable resource error and no unconfigured fallback is used

### Requirement: Session demand aggregation is bounded

Ingress SHALL aggregate upstream and downstream demand once per Session using bounded counters and low-frequency windows. Route identities, policy IDs, and business classes SHALL NOT partition Path demand. A replacement Session SHALL start with empty counters and observations while retaining the configured Egress baseline; no unbounded per-flow demand history or local policy metadata SHALL be sent to Egress.

#### Scenario: A Session reconnects

- **WHEN** a new SessionID replaces a failed Session
- **THEN** its demand counters and EWMA start empty while prior values remain only in bounded observations

#### Scenario: Many matching rules share an Egress

- **WHEN** many routing rules send traffic to the same Egress
- **THEN** their traffic contributes to the same Session directional demand windows without allocating a separate Path requirement or demand-history entry per rule

#### Scenario: A replacement Session restores its configured baseline

- **WHEN** a Session with requested baseline three and a prior demand-driven target of six is retired and replaced
- **THEN** the new Session retains the requested baseline of three, applies its current hard ceiling, and starts with fresh demand state instead of inheriting the old target of six

### Requirement: Geodata predicates participate in ordered routing

EgressRule and ProxyRule flow matches SHALL evaluate configured geosite and geoip predicates using the same immutable geodata generation as the rest of the routing decision. These predicates SHALL follow the [geodata routing contract](../geodata-routing/spec.md) without changing rule order or implicit fallback behavior, and SHALL NOT select Transit relationships within an Egress.

#### Scenario: Hugging Face redirect uses the same Egress policy

- **WHEN** an explicit proxy flow targets a hostname in a configured `huggingface` geosite set, including a CDN subdomain
- **THEN** the matching Egress rule selects its configured Egress and the flow uses that Egress's common Path pool

#### Scenario: GeoIP predicate receives an original destination address

- **WHEN** an IP-targeted TCP or UDP flow reaches a rule with a matching geoip set
- **THEN** the rule evaluates the original destination IP under its captured generation before selecting an Egress, Proxy, or configured fallback

#### Scenario: Geodata fact is unavailable

- **WHEN** a rule needs a hostname or IP that the listener did not provide
- **THEN** the corresponding geodata predicate does not match and Ingress proceeds through the configured ordered rules and fallback without resolving through another DNS route

### Requirement: Egress Paths select endpoint candidates independently

For one configured Egress, Ingress SHALL maintain one Session Path pool while selecting one normalized endpoint candidate for each Path establishment. Endpoint selection SHALL use a deterministic bounded order and SHALL not create a separate Session, policy, or Egress identity per endpoint.

#### Scenario: One Session uses IPv4 and IPv6 endpoints

- **WHEN** an Egress has ready endpoint candidates in different address families and the Session requires multiple Paths
- **THEN** separate Paths may connect through different candidates while remaining in the same authenticated Session Path pool

#### Scenario: Endpoint candidate order is reused

- **WHEN** a Path establishment starts with an ordered endpoint list
- **THEN** the selection cursor and bounded wraparound preserve the configured candidate order and do not retry one candidate indefinitely

### Requirement: Endpoint attempts use one static bounded sequence

Each Egress Path establishment SHALL start from the per-Egress endpoint selection cursor, visit each normalized candidate at most once with wraparound, and use one shared deadline for the sequence. The cursor advances after successful admission or exhaustion; endpoint failover applies only before Path admission.

#### Scenario: A Path sequence reaches a successful candidate

- **WHEN** a candidate succeeds and Noise admission reaches readiness
- **THEN** the Path records that candidate, the cursor advances, and no later Stream or UDP retry changes the Path's transport

#### Scenario: A Path sequence is exhausted

- **WHEN** every candidate fails or times out before readiness
- **THEN** the operation returns the existing typed Path connection failure without extending its deadline or bypassing the Egress Transit binding and TrafficPolicy

### Requirement: Endpoint failure uses bounded pre-admission failover

Before a Path reaches authenticated readiness, Ingress SHALL try eligible Egress endpoint candidates within the Path connection deadline and a finite attempt bound. If every candidate fails, the Path attempt SHALL return a typed connection failure without selecting Direct, an unrelated Egress, or an ordinary Proxy route.

#### Scenario: The preferred endpoint is unavailable

- **WHEN** the first endpoint candidate fails before Noise admission completes and another candidate remains
- **THEN** Ingress tries the next candidate within the same bounded Path establishment operation

#### Scenario: All endpoint candidates fail

- **WHEN** every candidate fails before Path admission
- **THEN** the Egress Path attempt fails with the normalized Egress/Transit connection error and no target Stream or UDP Association is created

### Requirement: Established Paths retain endpoint ownership

After a Path reaches readiness, its endpoint candidate SHALL remain associated with that Path until the Path drains or fails. Endpoint failure SHALL affect Paths using that candidate and SHALL not migrate an established Path by silently changing its peer socket.

#### Scenario: One endpoint fails while another Path is ready

- **WHEN** a transport failure closes a Path using one endpoint while another non-draining ready Path uses a different endpoint
- **THEN** the Session remains eligible according to its existing minimum and only the failed Path enters recovery or replacement

#### Scenario: A Path endpoint is drained

- **WHEN** an administrator removes an endpoint from the next static configuration or the endpoint is administratively drained
- **THEN** new Paths exclude it and existing Paths follow the normal Path drain deadline before closure

### Requirement: Hostname candidates preserve family and port semantics

An Egress endpoint hostname SHALL be resolved by the selected Transit Adapter using its configured port; a hostname's IPv4 and IPv6 address results are alternatives for that same port. Different ports SHALL be represented by distinct endpoint candidates rather than inferred from DNS address records.

#### Scenario: One hostname returns A and AAAA records

- **WHEN** a hostname candidate resolves to both IPv4 and IPv6 addresses for port 7443
- **THEN** the adapter may try either family for port 7443 within the bounded connection attempt, while the Egress identity remains unchanged

#### Scenario: IPv4 and IPv6 use different ports

- **WHEN** IPv4 uses port 7443 and IPv6 uses port 8443
- **THEN** Ingress treats them as two explicit candidates and can select either candidate independently for a Path

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
      endpoints:
        - host: egress.example.net
          port: 443
      publicKey: <curve25519-public-key>
      capabilities:
        tcp: true
        udp: true
      pathPool:
        minUsablePaths: 2
        targetUsablePaths: 3
      admission:
        requiredCapabilities: [tcp]
      transit:
        require:
          labels:
            region: jp
        reject:
          tags: [quota-exhausted]
      trafficPolicyRef: jp-default
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
  endpoints:
    - host: egress-v4.example.net
      port: 7443
    - host: egress-v6.example.net
      port: 8443
    - host: egress.example.net
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
  host: proxy.example.net
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
```

The first Egress rule whose conditions match and whose selected Egress is
currently usable wins. Egress usability is precomputed by the runtime state
manager. Geosite and geoip predicates use the flow's original hostname or
original destination IP and the immutable [geodata routing](../geodata-routing/spec.md)
generation; missing facts do not match or trigger DNS. The rule selects an
Egress only; it does not select a Transit relationship, Path subset, minimum,
or TrafficPolicy.

Traffic policies may define multipath scheduling and replication budgets:

```yaml
apiVersion: pathchord.io/v1
kind: TrafficPolicy
metadata:
  name: gaming-default
spec:
  scheduler: effectiveCapacityWeighted
  sessionReplicationBudgetBps: 2000000
  retransmissionReplication: allowed
```

`retransmissionReplication: disabled` requests a zero Session replication cap
even when the authored budget is positive. `allowed` requests the policy bit
rate divided by eight, rounded down to wire bytes per second, and Egress may
accept a lower value. A zero cap disables optional business and control copies
in both directions while preserving primary traffic, necessary control, and
ordinary reliable retransmission. `TrafficPolicy.classes`,
`classReplicationBudgetBps`, and rule-level `trafficClassRef` are retired.

The Session budget is the hard upper bound in each sending direction. All
Streams and UDP Associations in one Session share the Egress policy and its
allowance; route identities do not partition demand or replication accounting.
Ingress computes one Session Path target from the effective configured baseline
and current upstream/downstream capacity needs under the hard runtime ceiling.
Demand expansion is permitted above the baseline; contraction is gradual and
drain-aware. Egress status has no recommended Path count and cannot override
this decision. Only an eligible non-draining `ACTIVE` or `DEGRADED` Path
counts toward admission and the baseline; a draining Path only completes
existing work. A baseline shortfall alone does not degrade service or deny
business while the common admission minimum is met.

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
```

Rules do not embed a concrete dynamic Proxy identity, Transit selector, Path
minimum, or TrafficPolicy. The scheduler resolves the selected Egress binding
against current runtime state and applies health, capacity, relationship weight,
quota metadata, and the immutable Session policy. The Egress binding and its
resolved policy contents are startup configuration; subscription membership and
administrator metadata remain dynamic and drain removed Paths.

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

- Static Egress topology, Transit binding, common Path requirements, and the referenced resolved TrafficPolicy require an Ingress restart when their normalized values change.
- Transit Proxy subscription updates replace the dynamic snapshot atomically.
- A failed subscription refresh retains the last successful snapshot.
- Removed Transit Proxies enter draining and are excluded from new selections.
- Existing Paths using a removed Transit Proxy remain until drain completion or failure.
- Changes to Transit membership under an unchanged Egress binding publish dynamically and drain removed relationships.
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

Ingress maintains one Session slot per configured Egress and can warm or refill
that slot from its binding without a matched business flow. A Session captures
one immutable TrafficPolicy and negotiated replication cap, owns one common
Path pool, and remains alive while idle for reuse by subsequent Streams, UDP
Associations, and Egress-routed DNS. Ingress best-effort maintains the
effective baseline \`min(requested target, hard runtime ceiling)\`; the requested
target defaults to the common minimum plus one, while an explicit target adds
no implicit reserve. A baseline shortfall alone does not degrade service or
deny new business while the common minimum is met. Falling below the minimum
continues to deny new business while ready Paths remain; loss of the last ready
Path or a hard Egress failure destroys the Session and related business
connections. When the Egress becomes online again, Ingress creates a new
Session and Path set and restores the configured baseline without inheriting
an old load-expanded target.

Capacity-driven scale-out can exceed the baseline. When demand subsides,
Ingress recomputes the target from current directional requirements and
gradually drains surplus Paths toward the effective baseline, preserving
current capacity, lifecycle, and drain guards. Baseline refill is bounded and
independent of business route matches.
