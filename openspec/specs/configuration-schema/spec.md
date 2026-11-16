# PathChord configuration schema

**English** | [简体中文](spec.zh-CN.md)

## Purpose

Define the versioned human-authored configuration schema, complete-bundle validation, source selection, resource ownership, and atomic publication/reload contract.

## Requirements

### Requirement: Versioned schema conformance

The v1 schema SHALL expose Egress aggregate wire capacity and global inbound target-connection limits while keeping desired Path count, per-Ingress stream quotas, and Path safety ceilings outside the authored Egress policy surface. Each Ingress-side Egress SHALL declare one Transit binding and one TrafficPolicy reference for its Session Path pool.

#### Scenario: Removed desired-Path fields are authored

- **WHEN** an EgressService contains `recommendedPathCount`, `maxConcurrentPaths`, or `maxStreamsPerIngress`
- **THEN** schema validation rejects the server-owned or retired field instead of treating it as an Ingress Path target

#### Scenario: Author runtime status in a resource

- **WHEN** an administrator supplies a resource containing an authored `status` field
- **THEN** validation rejects the resource and leaves the previously published snapshot active

### Requirement: Whole-bundle identities and references

The loader SHALL validate the complete resource graph across all source files, resolve references by namespace, kind, and name, and reject duplicate identities without last-file-wins semantics. A complete configuration SHALL contain exactly one DNSPolicy and one FallbackPolicy.

#### Scenario: Duplicate resources are split between files

- **WHEN** two files in a configuration directory declare the same `(namespace, kind, metadata.name)` identity
- **THEN** the complete candidate bundle is rejected rather than selecting the later filename

### Requirement: Explicit source precedence and bounded discovery

Ingress SHALL select command-line configuration before environment configuration and account defaults, applying the source conflicts and bounded directory-discovery rules in the detailed contract. It SHALL NOT use filename order as an override mechanism.

#### Scenario: Command line overrides conflicting environment variables

- **WHEN** an explicit valid command-line source is supplied while both configuration environment variables are non-empty
- **THEN** the explicit source takes precedence, including over the environment-tier conflict

### Requirement: Atomic publication and resilient watching

The complete candidate SHALL pass parsing, validation, normalization, compilation, and required persistence before one immutable generation is published. Invalid candidates SHALL retain the last good bundle; atomic file and root-directory replacement SHALL preserve watching. Changes to an Egress binding, common admission minimum, referenced policy, or resolved policy contents SHALL report restart required and retain the active bundle.

#### Scenario: Atomic replacement contains an invalid candidate

- **WHEN** a watched configuration file is atomically replaced by an invalid resource candidate
- **THEN** the last good bundle remains active and watching continues for subsequent valid replacements

#### Scenario: A referenced policy changes without changing its name

- **WHEN** a reload changes the contents of a TrafficPolicy referenced by an Egress while retaining the same reference name
- **THEN** Ingress reports restart required and retains the active configuration and Session policy snapshots

#### Scenario: Only Transit membership changes

- **WHEN** a subscription or authorized administrator-metadata update changes nodes under an unchanged Egress binding
- **THEN** Ingress publishes the valid dynamic generation and drains removed candidates without requiring a new Egress policy snapshot

### Requirement: Deterministic bounded rule compilation

Rules SHALL use explicit unique order values and deterministic, bounded, I/O-free evaluation. EgressRule output SHALL select only an Egress action and diagnostic rule identity. Each Egress SHALL resolve one TrafficPolicy during complete-bundle validation, independent of runtime candidate cardinality. Retired TransitRule and traffic-class configuration SHALL be rejected explicitly.

#### Scenario: Multiple Transit relationships lack a policy

- **WHEN** an Egress with several possible Transit relationships omits `trafficPolicyRef`
- **THEN** complete-bundle validation rejects the missing reference before publication rather than admitting a single-path configuration that fails after nodes are added

#### Scenario: Only one Transit is currently available

- **WHEN** an Egress has only one currently available Transit relationship but omits its policy reference
- **THEN** the same validation failure occurs without creating an implicit single-Transit policy

### Requirement: Persistent subscription ownership

Management enable, disable, deletion, and explicit re-creation of declared Subscriptions SHALL remain effective across reload and restart while their declarations are unchanged. Changed or removed declarations SHALL apply their corresponding new desired state, independently of management-only subscriptions.

#### Scenario: Reload an unchanged disabled declaration

- **WHEN** a declared Subscription was disabled through management and its unchanged declaration is reloaded after restart
- **THEN** the disabled management state remains effective

### Requirement: Validated adapter options

Transit Proxy configuration SHALL preserve typed connection options and validate their selected adapter support. TLS-capable adapters SHALL load system roots by default, accept an ordered local PEM/DER truststore source list, and fail the candidate atomically when any configured truststore source is invalid; unknown YAML option fields SHALL be rejected.

#### Scenario: Custom truststore sources are configured

- **WHEN** a TLS node sets truststore sources to `system` and local PEM/DER files
- **THEN** the adapter uses the union of those sources, resolves relative paths from the selected configuration source, and rejects the candidate if any source is unreadable or invalid

#### Scenario: Adapter cannot consume a connection option

- **WHEN** a configured node requires a connection option that its selected adapter does not support
- **THEN** the node is rejected or exposes an explicit diagnostic under the Transit Proxy contract instead of silently discarding the option

### Requirement: Egress resource limits are global

An EgressService SHALL define a global maximum inbound target-connection count and a configured aggregate wire bandwidth cap. The runtime SHALL enforce these as global resource ceilings across all authorized Ingress Sessions.

#### Scenario: Global connection cap is reached

- **WHEN** active target connections plus pending reservations reach the global limit
- **THEN** new target opens return `RESOURCE_LIMIT` while existing target connections remain active

### Requirement: Truststore sources are explicit and bounded

TLS truststore sources SHALL default to `["system"]`. Each additional source SHALL be a local PEM/DER file path; relative paths resolve from the selected configuration source, absolute paths are allowed, symlink targets SHALL be regular files, and an empty list SHALL mean no trust anchors.

#### Scenario: Empty truststore is selected

- **WHEN** a node explicitly configures an empty truststore source list without insecure verification
- **THEN** ordinary certificate validation fails closed and the adapter does not restore system roots implicitly

### Requirement: Egress capacity fields have distinct meanings

The schema SHALL distinguish the configured aggregate wire hard cap from runtime effective capacity and current load. Runtime capacity state SHALL be represented separately from the authored configured cap and SHALL support unknown/provisional/measured/stale values.

#### Scenario: Capacity is not yet measured

- **WHEN** Egress starts without enough fresh measurements
- **THEN** the configured cap remains the hard upper bound, while effective capacity is exposed as provisional or unknown rather than authored as a measured value

### Requirement: Subscription User-Agent is bounded

A Subscription source SHALL accept an optional `userAgent` field. Its value SHALL be a nonblank printable ASCII HTTP header value of at most 1024 bytes. An omitted field SHALL use the default specified by the Transit contract.

#### Scenario: User-Agent contains a line break

- **WHEN** a Subscription declares a User-Agent containing a line break
- **THEN** configuration validation rejects the candidate bundle

### Requirement: Geodata resources and references

The configuration schema SHALL support namespace-scoped geosite and geoip database resources and typed named-set references in flow matches. Validation SHALL resolve every reference against the complete resource graph and reject invalid or ambiguous data before publication.

#### Scenario: Reference an absent database

- **WHEN** a rule refers to a geodata resource or named set absent from its namespace
- **THEN** the candidate configuration is rejected with a diagnostic identifying the field and resource rather than publishing a partial rule

#### Scenario: Existing exact host matches remain valid

- **WHEN** an existing configuration uses only `targetHosts`
- **THEN** it retains its existing exact hostname or IP-literal matching semantics without requiring geodata resources

### Requirement: Geodata updates publish atomically

The loader SHALL read and validate each referenced database as part of the complete candidate and publish geodata and rules in one immutable generation. Replacing a configured database file SHALL trigger a bounded reload, and a failed candidate SHALL retain the previous generation.

#### Scenario: Replace a referenced database

- **WHEN** an operator atomically replaces a referenced geodata file with valid content
- **THEN** Ingress validates the complete candidate and publishes the changed data and rules together as a new generation

#### Scenario: Start with missing geodata

- **WHEN** initial configuration references a missing or unreadable geodata database
- **THEN** startup reports a typed configuration failure and does not silently disable that predicate

### Requirement: Detailed geodata contract

Geodata configuration SHALL follow the complete [detailed contract](#geodata-databases).

#### Scenario: Apply the detailed contract

- **WHEN** geodata configuration or matching is processed
- **THEN** the schema, limits, and failure semantics in the detailed contract are enforced

## Detailed contract

This document is the normative versioned schema for the human-authored YAML
configuration. The [configuration specification](../configuration/spec.md) provides
examples and evaluation order; this document defines field names, types,
defaults, validation, and publication behavior. Runtime observations and
control-plane JSON are separate contracts.

### Object envelope

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
`EgressRule`, `ProxyRule`, `TrafficPolicy`, `Listener`,
`DNSPolicy`, `FallbackPolicy`, `GeoSiteDatabase`, `GeoIpDatabase`,
`EgressService`, and `NodeProbePolicy`. The last two are role-specific service resources: `EgressService` selects the
Egress identity, listener, authorization store, and service limits for one
Egress process; `NodeProbePolicy` configures the optional bounded Transit node
probe. Ingress consumes `NodeProbePolicy` and the complete policy graph;
Egress consumes an Egress-only source containing exactly one `EgressService`.
Ingress and Egress sources MUST NOT be treated as one shared resource bundle.
A namespace MUST contain at most one object
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

### Scalar types and common limits

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

`billing.traffic_multiplier` is an optional positive decimal in `0.0001..=100`.
When present, the scheduler multiplies the configured relationship weight by
this reference value before effective-capacity weighting. It is never a hard
quota, never blocks connectivity by itself, and cannot be written by an
administrator label mutation. Imported `source.*`, `observed.*`, `quota.*`, and
`billing.*` values are runtime-owned.

### Egress

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
| `transit` | yes | common same-namespace Transit binding with optional `require` and `reject` selectors |
| `trafficPolicyRef` | yes | exactly one same-namespace TrafficPolicy for every Session using this Egress |

At least one of `capabilities.tcp` or `capabilities.udp` MUST be true. An
Egress reference MUST resolve to an Egress object. `transit: {}` explicitly
admits all otherwise eligible same-namespace Transit nodes. Its `require`
selector uses labels, tags, and capabilities; `reject.tags` excludes matching
nodes. The binding cannot contain flow matches, order, a second weight, a Path
subset, or a desired Path count. Egress topology, the binding, and its resolved
TrafficPolicy are startup configuration and are not hot-reloaded.

### EgressService and NodeProbePolicy

`EgressService.spec` accepts `bind`, `egressId`, `identity`,
`authorizationDb`, `controlSocket`, `maxWireBandwidthBps`,
`maxInboundTargetConnections`, `quotaRemaining`,
`trafficMultiplierBasisPoints`, `remoteDnsOnly`, `webBind`, `webTokenFile`,
`webOrigins`, and `webProtectedTransport`. Desired Path counts, per-Ingress
stream quotas, and Path safety ceilings are runtime-owned and MUST NOT be
authored. Paths in the resource are resolved
relative to the selected configuration source. An Egress process selects at
most one such resource. `identity` and an Egress ID are required after command
line overrides; the resource name supplies the ID when `egressId` is absent.
`remoteDnsOnly` defaults to false. When true and an original hostname is
present, Egress resolves it using its own system resolver for TCP and UDP and
does not use Ingress-provided candidates. A literal IP without a hostname is
still a valid target. The option applies to target names, not the independent
Ingress DNS routing policy.

An Egress source MUST reject Listener, TransitProxy, Subscription, EgressRule,
ProxyRule, TrafficPolicy, DNSPolicy, FallbackPolicy, GeoSiteDatabase,
GeoIpDatabase, and NodeProbePolicy resources. Relative private paths resolve
from the selected Egress source root and identity, authorization database,
control socket, and bearer token remain outside authored resource documents.
EgressService fields are startup-only; a changed source is reported as restart
required while the active Egress runtime retains its previous values.

`NodeProbePolicy.spec.target` is an object containing `host` and `port`.
`intervalSeconds` defaults to 30 and is bounded by 1..=86400;
`timeoutSeconds` defaults to 5 and is bounded by 1..=30; `maxConcurrency`,
`windowSize`, and `maxNodesPerBatch` default to 8, 32, and 128 and are bounded
by 1..=64, 1..=128, and 1..=1024 respectively. At most one NodeProbePolicy
may be present in the bundle.

### TransitProxy and Subscription

Each `kind: TransitProxy` object has:

| Field | Required | Type and semantics |
|---|---|---|
| `metadata.name` | yes | resource name; unique in the namespace |
| `source` | no | `{type, subscriptionRef}`; default `{type: static}` |
| `protocol` | yes | node protocol from the [adapter contract](../transit-proxies/spec.md#adapter-selection-and-failure); executable support is validated separately |
| `address` | yes except `direct` | hostname or IP literal |
| `port` | yes except `direct` | port |
| `tags` | no | sequence of IDs; default `[]` |
| `weight` | no | integer weight; default `100` |
| `credentialsRef` | no | opaque local secret reference; never a secret value |
| `options` | no | typed TLS, transport, header, UDP, SOCKS5/SS `udpOverTcp`, VMess framing, multiplex, and dialer options; default `{}` |

`source.type` is one of the [subscription document types](../transit-proxies/spec.md#subscription-document-families),
including `static`, `auto`, `clash`, `sip008`, `uri`, `sing_box`, `surge`,
`quantumult`, and `loon`. A non-static source MUST name
an existing `Subscription` object. Imported `source.*`, `observed.*`, and
`quota.*` attributes are runtime-owned and cannot be authored inside a proxy
object. Labels belong in `metadata.labels`.
`direct` has no third-party endpoint and ignores `address` and `port`.

The [Transit Proxy contract](../transit-proxies/spec.md) defines every typed option,
protocol-specific credential handling, complete engine node documents,
per-node diagnostics, bounded HTTP provider expansion, accounting metadata,
and native versus Egress-carried UDP. Unknown YAML option fields are rejected.
An adapter MUST NOT ignore unsupported connection options or downgrade TLS.
TLS options include an ordered `truststore` list whose default is `["system"]`.
Each non-system entry is a local PEM or DER file; relative paths resolve from
the selected configuration source, and symlink targets MUST be regular files.
An empty list means no trust anchors. Any invalid or oversized source rejects
the complete adapter candidate.

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

`enabled` defaults to `true`; `intervalSeconds` defaults to `3600` and is in
`60..=604800`; `timeoutSeconds` defaults to `30` and is in `1..=300`;
`maxAttempts` defaults to `3` and is in `1..=10`; `backoffSeconds` defaults to
`5` and is in `1..=3600`; `maxAgeSeconds` defaults to `86400` and is in
`60..=2592000`. `source.userAgent` is optional, defaults to `clash.meta`, and
must be a nonblank printable ASCII value of at most 1024 bytes. URLs MUST NOT
contain credentials. `cache.path` is relative to
the service data directory unless an administrator explicitly supplies an
absolute path. The cache is written atomically with restrictive permissions.

Refresh validates the document and each node before publication. Invalid or
unsupported nodes remain visible and unselectable alongside valid nodes; a
malformed document or failed fetch retains the previous snapshot. A failed refresh
keeps the last successful snapshot, records a typed failure, and retries with
bounded exponential backoff. Deleting or disabling a subscription prevents
future refreshes; nodes imported solely from it enter `draining`, are excluded
from new selections, and remain until their Paths drain or fail. A successful
refresh publishes one dynamic generation. A failed refresh publishes no
configuration generation.

### Geodata databases

A `kind: GeoSiteDatabase` or `kind: GeoIpDatabase` resource has the common
`apiVersion`, `metadata.name`, optional namespace, and a `spec.path` string
naming a local V2Fly protobuf file. A namespace MUST contain at most one
resource of each kind. Files are read-only inputs; matching never downloads or
modifies them. Relative paths resolve against the selected configuration file's
parent directory or the selected configuration directory root. Database files
are external inputs, not resource documents, and MUST be outside a scanned
configuration directory or use an unscanned extension.

`targetGeoSites` and `targetGeoIps` are optional non-empty sequences of at most
256 strings on an EgressRule or ProxyRule `match`. A geosite
reference is `set` or `set@attribute`, optionally prefixed `geosite:`; a geoip
reference is `set`, optionally prefixed `geoip:`. The appropriate prefix is
normalized away; an incompatible prefix is rejected. Set and attribute names use
nonempty ASCII letters, digits, `.`, `_`, `-`, and `!`, and are interpreted
case-insensitively. Each referenced database resource MUST exist in the rule's
namespace. Duplicate references after normalization are invalid. Values within
one field are ORed; populated match fields, including `targetHosts`,
`targetGeoSites`, and `targetGeoIps`, are ANDed. An unavailable original
target fact makes its predicate false. A rule combining geosite and geoip
requires both facts; separate ordered rules express an OR between them.

External database paths and contents participate in candidate validation,
reload observation, generation identity, and bounded diagnostics. Changing a
referenced file, including atomic replacement, triggers complete graph
validation. Decode, validate and index data before publication; no flow may
observe old rules mixed with new data. Startup without a valid candidate fails;
a later failure retains the last good generation. Update and data-file read
limits follow the [geodata routing contract](../geodata-routing/spec.md).
Configurations without geodata references require no database files.

### Rules and selectors

Rules are ordered by the REQUIRED `spec.order` integer; List item order has no
semantic meaning and ties are rejected. Each `EgressRule` and `ProxyRule` has
an optional `match` and an action-specific
selector. A present `match: {}` is invalid; omit `match`
only when an explicit catch-all rule is intended. Match fields are ANDed, and
multiple values within one field are ORed. Supported match fields are
`flowTags`, `protocols`, `listenerRefs`, `sourceNetworks`,
`authenticationIdentities`, `processExecutables`, `targetHosts`, `targetGeoSites`,
`targetGeoIps`, and `targetPorts`.

An Egress target is exactly one of:

```yaml
egressRef: egress-name
egressSelector: {labels: {region: jp}, tags: [gaming], capabilities: [tcp]}
mode: none
```

The mapping selector MUST contain at least one criterion. `mode: none` is
ordinary Proxy mode and MUST NOT create a PathChord Session. `proxy: direct` is
the built-in direct Transit adapter and is not an Egress selector.

`EgressRule.spec` has no `requirements`, Transit selector, policy override, or
traffic-class field. The first rule whose match, selector, capability, and
current Egress usability all pass wins. The selected Egress binding supplies
the common Transit candidates, Path minimum, and TrafficPolicy for every flow.
If the binding has no admitted Transit Proxy, the next Egress rule is
considered; evaluation does not silently fall through to an arbitrary Proxy.

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

### TrafficPolicy

Each `kind: TrafficPolicy` object has the following `spec` fields:

| Field | Required | Default and limits |
|---|---|---|
| `scheduler` | no | `effectiveCapacityWeighted` |
| `sessionReplicationBudgetBps` | no | `0` (no replication) |
| `retransmissionReplication` | no | `disabled` |

Budgets are non-negative integers no greater than `10^12`. The Session budget is
the hard upper bound per sending direction; control traffic is accounted
against it. `retransmissionReplication: disabled` requests zero even when the
budget is positive; `allowed` requests the budget divided by eight, rounded
down to wire bytes per second, within profile hard caps. A zero cap disables
optional business and control copies while preserving primary traffic,
necessary control, and ordinary reliable retransmission. The scheduler considers
relationship weight, the optional billing multiplier, effective capacity,
congestion window, RTT, jitter, and loss. A policy cannot grant a Path more than
its advertised flow control limit.

`classes`, `classReplicationBudgetBps`, and `trafficClassRef` are retired and
rejected, including empty or zero values. The policy is captured once per
Session; a later Path attachment cannot replace it or raise its negotiated cap.

### Listener

Listener fields are defined in the [platform and DNS specification](../platform-and-dns/spec.md).
Every `kind: Listener` object has a `metadata.name`, a `spec.type`, a
`spec.platform` (`linux`, `windows`, `freebsd`, or default `any`), and
an optional `authentication` block (default `disabled`). It may also contain
`flowTags` (at most 256 valid tags) and `processMetadata` with boolean
`executable`, `user`, and `group` requests. Static flow tags are copied into
every accepted flow. Process facts are best-effort and unknown when the
platform provider cannot safely obtain them. Listener IDs are available to
rules. An explicit platform MUST match the actual host; `any` uses the actual
host's platform matrix. FreeBSD permits `http`, `socks5`, and `mixed` and rejects
`tproxy`, `redirect`, and `tun`. A listener that is unsupported on the selected
platform is rejected during validation rather than ignored.

`spec.type` accepts `socks` as an input alias for canonical `socks5`; normalized
serialization MUST emit `socks5`. The canonical listener accepts SOCKS4/4a/5
CONNECT and SOCKS5 UDP ASSOCIATE. Required password authentication rejects
SOCKS4/4a rather than downgrading the verifier. An HTTP listener supports
ordinary `http://` forwarding and CONNECT with per-request authentication and
policy evaluation. Message framing, limits, credential/header filtering, and
upgrade behavior follow the [HTTP and SOCKS contract](../platform-and-dns/spec.md#http-and-socks-listeners).

`spec.backend` defaults to `tproxy`. `backend: ebpf` is a Linux-only backend
for `type: tproxy`; it requires `platform: linux`, a non-empty ingress
`interface`, and at least one `allowedSources` CIDR. It marks TCP/UDP packets
on that interface for the existing TPROXY policy route. The transparent
listener, original-target handling, UDP associations, and Path/Session policy
remain in userspace. Other listener kinds reject `backend: ebpf` during
validation.

`spec.type: mixed` shares one TCP endpoint between HTTP and SOCKS. Its default
`protocols` are `[tcp, udp]`; TCP is required and UDP is optional. Both parsers
share the same credentials, source restrictions, and listener identity.

### DNSPolicy and FallbackPolicy

`kind: DNSPolicy` is defined normatively in [platform-and-dns.md](../platform-and-dns/spec.md).
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

### Configuration sources

Ingress accepts one resource file or one directory tree. Egress accepts one
EgressService resource file or directory tree. Each role selects its source
using the following priority, from highest to lowest:

1. Explicit `--config` (`-c`) or `--config-dir` (`-C`). The options are mutually
   exclusive. `--config` accepts a file or directory; `--config-dir` requires a
   directory.
2. Non-empty `PATHCHORD_CONFIG` or `PATHCHORD_CONFIG_DIR`. These are mutually
   exclusive at the environment tier and have the same file/directory meaning
   as their corresponding command-line options. An explicit command-line
   source overrides both environment variables, including their conflict.
3. The account default: Ingress uses `~/.config/pathchord/ingress` for a
   regular user and `/etc/pathchord/ingress` for a service account; Egress uses
   `~/.config/pathchord/egress` or `/etc/pathchord/egress`. Unix uses the effective UID;
   system UIDs below 1000 and accounts with `nologin` or `false` shells are
   classified as service accounts. A regular Unix user's home comes from
   `HOME`, falling back to the account database. Windows uses `USERPROFILE`
   (then `HOME`); its standard System/Local Service/Network Service principals
   are service accounts. An unavailable user home is an error.

The directory loader recursively reads `.yaml`, `.yml`, and `.json` resource
files, with case-insensitive extensions, in relative-path order. Hidden and
editor temporary paths are ignored; visible child symlinks are rejected.
The selected root is resolved once at startup. A single explicitly selected
file retains support for any filename extension. A directory with no supported
files is rejected. The combined bound is 4 MiB and 1024 resource files, with
at most 16 levels of subdirectories.

Each source is parsed independently, including YAML multi-document streams
and `kind: List`; the complete combined resource graph is then validated.
Resources may reference objects in other files. Duplicate resource identities
are rejected across the whole bundle; filename order MUST NOT implement a
last-file-wins override. Exactly one DNSPolicy and one FallbackPolicy remain
required in the combined graph. Runtime data and private credential JSON MUST
be kept outside the resource tree or use a non-resource file extension.
Resource identity and explicit rule order determine the normalized graph;
moving unchanged resources between source files MUST NOT require a restart.

### Snapshot publication and reload

The adapter parses, validates, normalizes, and compiles the complete source bundle
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

For a declared Subscription, management enable, disable, deletion, or explicit
re-creation remains effective across reload and restart while its declaration is
unchanged. Changing that declaration applies the new spec; removing it removes
that declared subscription and drains its imported nodes. Subscriptions created
only through management remain independent of unrelated declarations. These
decisions and their configuration generation are persisted atomically.

Directory create, modify, remove, and rename events trigger a full candidate
rescan. Atomic file replacement and root-directory replacement MUST preserve
watching. All files pass validation before one snapshot is published; an
invalid, incomplete, or duplicate candidate retains the last good bundle.
Startup-only changes continue to report restart required.
