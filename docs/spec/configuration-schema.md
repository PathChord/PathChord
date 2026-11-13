# PathChord configuration schema

**English** | [简体中文](configuration-schema.zh-CN.md)

This document is the normative versioned schema for the human-authored YAML
configuration. The [configuration specification](configuration.md) provides
examples and evaluation order; this document defines field names, types,
defaults, validation, and publication behavior. Runtime observations and
control-plane JSON are separate contracts.

## Object envelope

PathChord configuration uses Kubernetes-style declarative objects. The
recommended document is a `List`; a single resource object is also valid.
Objects are separated with YAML `---` documents or placed in `items`:

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

Every resource object MUST contain exactly `apiVersion`, `kind`, `metadata`,
and `spec`. `kind: List` is the one envelope exception: it contains exactly
`apiVersion`, `kind`, `metadata`, and `items`, with no `spec`. `apiVersion` MUST
be `pathchord.io/v1`; unknown versions and kinds are rejected. List items MUST
be resource objects, never another List. Unknown fields, duplicate
YAML mapping keys, non-canonical numbers, cyclic aliases, and an authored
`status` field are rejected.

`metadata.name` is the stable resource identity and MUST match
`[a-z0-9]([-a-z0-9]*[a-z0-9])?`, with a maximum length of 63 bytes.
`metadata.namespace` defaults to `default`; references use `name` within the
same namespace. `metadata.labels` and `metadata.annotations` are optional
bounded string maps. `metadata.uid`, `metadata.generation`, and
`metadata.resourceVersion` are server-owned response fields and MUST NOT be
authored. Runtime `status` is read-only and is exposed separately by the
control plane.

The supported resource kinds are `Egress`, `TransitProxy`, `Subscription`,
`EgressRule`, `TransitRule`, `ProxyRule`, `TrafficPolicy`, `Listener`,
`DNSPolicy`, and `FallbackPolicy`. A namespace MUST contain at most one object
for each `(kind, metadata.name)`. A complete configuration MUST contain exactly
one `DNSPolicy` and one `FallbackPolicy`; all other kinds are optional subject
to reference and routing validation. A `List` with no listener is valid as a
library snapshot but cannot start an Ingress service.

The loader resolves references by `(namespace, kind, name)`, validates the
complete object graph, then publishes one immutable generation. Applying an
object with the same name replaces its desired `spec` atomically; deletion
removes it from future snapshots and drains resources whose references are no
longer valid. Failed validation or persistence leaves the previous generation
active.

## Scalar types and common limits

Unless a field says otherwise, strings are UTF-8, are not normalized, and may
not contain NUL or control characters. Resource identity is carried by
`metadata.name`; it is not repeated as an `id` field in `spec`.

```text
[A-Za-z0-9][A-Za-z0-9._-]{0,127}
```

Resource names are unique within a namespace and are lowercase. Ports are
integers in `1..=65535`; port `0` is rejected. CIDRs MUST be valid IPv4 or IPv6
network prefixes. Hostnames are at most 255 bytes and are validated as DNS
names when used as hostnames. Byte keys use unpadded base64url and MUST decode
to exactly 32 bytes.

When a non-resource identifier is required inside `spec`, it MUST match
`[A-Za-z0-9][A-Za-z0-9._-]{0,127}`; resource references still use the lowercase
`metadata.name` grammar above.

Maps contain at most 256 entries; map keys are at most 64 bytes and values are
at most 256 bytes. A label or tag set contains at most 256 entries. A weight is
an integer in `1..=1_000_000`; weights are relative units, not percentages.

Every sequence has a bounded maximum of 10,000 entries unless a smaller limit
is stated. A duplicate ID, an out-of-range number, an empty required string, or
an invalid cross-reference is a validation error. Validation errors retain the
previous published snapshot and MUST identify the field path and stable error
code.

Runtime metadata uses these ownership namespaces:

```text
node.*      static identity and protocol attributes
source.*    imported subscription source metadata
observed.*  runtime measurements and derived state
quota.*     optional provider quota reference
billing.*   optional provider billing reference
admin.*     local administrator annotations
```

`billing.traffic_multiplier` is an optional positive decimal in `0.001..=1000`.
When present, the scheduler multiplies the configured relationship weight by
this reference value before effective-capacity weighting. It is never a hard
quota, never blocks connectivity by itself, and cannot be written by an
administrator label mutation. Imported `source.*`, `observed.*`, `quota.*`, and
`billing.*` values are runtime-owned.

## Egress

Each `kind: Egress` object has the following `spec` fields. Its identity and
operator labels are carried by `metadata`:

| Field | Required | Type and semantics |
|---|---|---|
| `metadata.name` | yes | resource name; unique in the namespace |
| `address` | yes | hostname or IP literal |
| `port` | yes | port |
| `publicKey` | yes | 32-byte unpadded base64url Curve25519 public key |
| `capabilities` | no | mapping `tcp`/`udp` to booleans; both default `false` |
| `statusRequirements` | no | `minUsablePaths` and optional capability set; default `minUsablePaths: 1` |

At least one of `capabilities.tcp` or `capabilities.udp` MUST be true. An
Egress reference MUST resolve to an Egress object. Egress topology and local key
material are startup configuration and are not hot-reloaded.

## TransitProxy and Subscription

Each `kind: TransitProxy` object has:

| Field | Required | Type and semantics |
|---|---|---|
| `metadata.name` | yes | resource name; unique in the namespace |
| `source` | no | `{type, subscription}`; default `{type: static}` |
| `protocol` | yes | built-in v1 adapter: `direct`, `http`, `https`, `socks5`, or `ss` |
| `address` | yes except `direct` | hostname or IP literal |
| `port` | yes except `direct` | port |
| `tags` | no | sequence of IDs; default `[]` |
| `weight` | no | integer weight; default `100` |
| `credentialsRef` | no | opaque local secret reference; never a secret value |

`source.type` is `static`, `clash`, or `sip008`. A non-static source MUST name
an existing `Subscription` object. Imported `source.*`, `observed.*`, and
`quota.*` attributes are runtime-owned and cannot be authored inside a proxy
object. Labels belong in `metadata.labels`.
`direct` has no third-party endpoint and ignores `address` and `port`.

The `kind: Subscription` object has this shape:

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

`enabled` defaults to `true`; `intervalSeconds` defaults to `3600` and is in
`60..=604800`; `timeoutSeconds` defaults to `30` and is in `1..=300`;
`maxAttempts` defaults to `3` and is in `1..=10`; `backoffSeconds` defaults to
`5` and is in `1..=3600`; `maxAgeSeconds` defaults to `86400` and is in
`60..=2592000`. URLs MUST NOT contain credentials. `cache.path` is relative to
the service data directory unless an administrator explicitly supplies an
absolute path. The cache is written atomically with restrictive permissions.

Refresh validates the complete candidate before publication. A failed refresh
keeps the last successful snapshot, records a typed failure, and retries with
bounded exponential backoff. Deleting or disabling a subscription prevents
future refreshes; nodes imported solely from it enter `draining`, are excluded
from new selections, and remain until their Paths drain or fail. A successful
refresh publishes one dynamic generation. A failed refresh publishes no
configuration generation.

## Rules and selectors

Rules are ordered by the REQUIRED `spec.order` integer; List item order has no
semantic meaning and ties are rejected. Each `EgressRule`,
`TransitRule`, and `ProxyRule` has an optional `match` and an action-specific
selector. A present `match: {}` is invalid; omit `match`
only when an explicit catch-all rule is intended. Match fields are ANDed, and
multiple values within one field are ORed. Supported match fields are
`flowTags`, `protocols`, `listenerRefs`, `sourceNetworks`,
`authenticationIdentities`, `processExecutables`, `targetHosts`, and
`targetPorts`.

An Egress target is exactly one of:

```yaml
egressRef: egress-name
egressSelector: {labels: {region: jp}, tags: [gaming], capabilities: [tcp]}
mode: none
```

The mapping selector MUST contain at least one criterion. `mode: none` is
ordinary Proxy mode and MUST NOT create a PathChord Session. `proxy: direct` is
the built-in direct Transit adapter and is not an Egress selector.

`EgressRule.spec` accepts `requirements.minUsablePaths` (default `1`) and an
optional capability set. The first rule whose match, selector, capability, and
current Egress usability all pass wins. `TransitRule` objects are evaluated after an
Egress is selected; `egressRef` is an Egress name, `require` and `reject` are
selectors, `weight` defaults to `100`, and `trafficPolicyRef` is required when
more than one admitted relationship can carry the flow. A rule with no admitted
Transit Proxy causes the next Egress rule to be considered; it does not silently
fall through to an arbitrary Proxy.

`ProxyRule` objects select an ordinary Proxy. `select` is `any` or a selector; the
default is `any`. `any` chooses uniformly among the highest-scoring usable
Proxies after filtering by selector and weight; ties are broken by ascending
canonical ID. A rule may instead set `proxy: direct`, which selects the direct
Transit adapter without a third-party node; `proxy` and `select` are mutually
exclusive. The global `fallback.action` is required and is `reject` or `direct`.

Rule evaluation is deterministic, bounded, and I/O-free. It may inspect only
the connection context, listener/process metadata, target metadata, labels, and
published observations. It emits policy selectors and traffic parameters, never
a socket or arbitrary node object. Compilation rejects unbounded expressions,
unknown fields, unknown policy IDs, and references to missing resources. The
compiled rule snapshot is immutable and replaced atomically; a failed compile
keeps the previous snapshot.

## TrafficPolicy

Each `kind: TrafficPolicy` object has the following `spec` fields:

| Field | Required | Default and limits |
|---|---|---|
| `scheduler` | no | `effectiveCapacityWeighted` |
| `sessionReplicationBudgetBps` | no | `0` (no replication) |
| `classReplicationBudgetBps` | no | absent; bounded by Session budget |
| `retransmissionReplication` | no | `disabled` |
| `classes` | no | `{}`; map of class to `{priority, share}` |

Budgets are non-negative integers no greater than `10^12`. A class `priority`
is `0..=255` and a `share` is `1..=1_000_000`. The Session budget is the hard
upper bound; control traffic is accounted against it. The scheduler applies
relationship weight first and then effective capacity, congestion window, RTT,
jitter, and loss. A policy cannot grant a Path more than its advertised flow
control limit.

## Listener

Listener fields are defined in the [platform and DNS specification](platform-and-dns.md).
Every `kind: Listener` object has a `metadata.name`, a `spec.type`, a
`spec.platform` (default `any`), and
an optional `authentication` block (default `disabled`). It may also contain
`flowTags` (at most 256 valid tags) and `processMetadata` with boolean
`executable`, `user`, and `group` requests. Static flow tags are copied into
every accepted flow. Process facts are best-effort and unknown when the
platform provider cannot safely obtain them. Listener IDs are available to
rules. A listener that is unsupported on the selected platform is rejected
during validation rather than ignored.

## DNSPolicy and FallbackPolicy

`kind: DNSPolicy` is defined normatively in [platform-and-dns.md](platform-and-dns.md).
DNS is independent from Egress selection and exactly one DNSPolicy object MUST
be present, even when its route is `local`. Fake-IP is forbidden. The fallback
resource has this shape:

```yaml
apiVersion: pathchord.io/v1
kind: FallbackPolicy
metadata:
  name: default-fallback
spec:
  action: reject # or direct
```

## Snapshot publication and reload

The adapter parses, validates, normalizes, and compiles the complete document
before publication. Each published snapshot has a monotonically increasing
generation. A connection captures one generation before Egress and Proxy
selection and uses that generation for the complete decision. Runtime
observations are updated independently and never overwrite administrator-owned
fields.

Static Egress topology, local private keys, listener bind mode, and platform
routing settings require restart. Subscription data, imported Transit Proxies,
administrator labels/tags, DNS runtime health, and compiled dynamic rules may
be hot-reloaded. Snapshot replacement is atomic. On any parse, validation,
compilation, persistence, or cache-write failure, the last successful snapshot
remains active and the failure is exposed through structured status.

