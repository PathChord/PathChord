# Configuration schema delta

## MODIFIED Requirements

### Requirement: Versioned schema conformance

The v1 schema SHALL expose global Egress service ceilings while keeping per-Ingress stream quotas and Path safety ceilings runtime-owned. Each Ingress-side Egress SHALL declare one Transit binding and one TrafficPolicy reference, and SHALL configure its admission minimum and best-effort Path baseline through `pathPool`. Native configuration SHALL use the canonical names and retirement rules below.

#### Scenario: Removed desired-Path fields are authored

- **WHEN** an EgressService contains `recommendedPathCount`, `maxConcurrentPaths`, or `maxStreamsPerIngress`
- **THEN** schema validation rejects the server-owned or retired field instead of treating it as an Ingress Path target

#### Scenario: Author runtime status in a resource

- **WHEN** an administrator supplies a resource containing an authored `status` field
- **THEN** validation rejects the resource and leaves the previously published snapshot active

#### Detailed contract

##### Canonical native naming and field migration

PathChord-owned resource keys MUST use lower camelCase. Resource references
MUST use the `Ref` suffix and retain namespace resolution; `egressId` remains
a protocol identity rather than a resource reference. Numeric time, rate, and
byte limits MUST identify their units. Collection names MUST identify a
collection, subject to established protocol terms such as `alpn`. A scalar
remote endpoint host MUST use `host`; a list of HTTP Host overrides MUST use
`hosts`. User label keys, HTTP header names, foreign source documents, enum
values, private credential fields, environment variables, and CLI flags are
outside this native-key spelling rule.

The following table is exhaustive for retired native paths in this change.
Paths are relative to the named resource's `spec`.

| Resource | Retired native path | Canonical native path | Preserved meaning |
|---|---|---|---|
| Egress | `statusRequirements.minUsablePaths` | `pathPool.minUsablePaths` | common usable-Path admission minimum |
| Egress | `statusRequirements.capabilities` | `admission.requiredCapabilities` | common Egress capability requirement |
| Egress | `address` | `host` | single-endpoint shorthand host |
| Egress | `endpoints[].address` | `endpoints[].host` | ordered endpoint candidate host |
| TransitProxy | `address` | `host` | remote proxy endpoint host |
| EgressService | `webBind` | `web.bind` | optional management bind |
| EgressService | `webTokenFile` | `web.tokenFile` | private bearer-token file path |
| EgressService | `webOrigins` | `web.allowedOrigins` | allowed Web origins |
| EgressService | `webProtectedTransport` | `web.protectedTransport` | existing protected-transport assertion |
| TransitProxy | `options.transport.host` | `options.transport.hosts` | ordered HTTP Host override list |
| TransitProxy | `options.transport.maxEarlyData` | `options.transport.maxEarlyDataBytes` | byte limit with the existing bound |
| TransitProxy | `options.tls.certificate` | `options.tls.certificates` | inline additional trust anchors |
| TransitProxy | `options.tls.clientCertificate` | `options.tls.clientCertificates` | inline client certificate chain |
| TransitProxy | `options.tls.fingerprint` | `options.tls.clientHelloFingerprint` | ClientHello impersonation profile |
| TransitProxy | `options.udpOverTcp` | `options.udpOverTcpVersion` | explicit supported wire version |

The resource API version remains `pathchord.io/v1`. The `statusRequirements`
object is retired in its entirety, including an empty object. Each retired
native key MUST fail complete-bundle validation, including empty/default
values and documents containing both old and new forms. It MUST NOT act as
an alias, a fallback, or a merge input. A bounded `CONFIG_RETIRED_FIELD`
diagnostic MUST identify the resource, exact authored field path, and canonical
replacement path or paths without returning field values. Unrecognized fields
remain invalid; no recursive spelling conversion applies to arbitrary data.

The Egress `host`/`port` shorthand and `endpoints: [{host, port}]` form remain
mutually exclusive. Existing hostname/IP, IPv6, ordering, duplicate detection,
namespace, public-key, and 1..=32 endpoint limits remain in force. TransitProxy
`host`/`port` retain the existing direct-adapter exception. NodeProbe targets
and object-form Listener binds already use `host`/`port`. Listener interface
`address`, CIDRs, socket-address strings, and literal HTTP `Host` headers have
different meanings and MUST NOT be renamed as remote endpoint hosts.

EgressService `web` is optional and accepts only `bind`, `tokenFile`,
`allowedOrigins`, and `protectedTransport`. Omission retains the existing
disabled-by-default Web Gateway behavior; child defaults, validation limits,
origin/token checks, and protected-transport requirements are unchanged.
Relative `web.tokenFile` paths resolve from the selected configuration source
under the existing private-path rules. Existing CLI flags override the
corresponding nested resource fields using the existing source precedence;
grouping does not change secret storage or enable TLS termination.

The published schema MUST document `catchAll` on EgressRule and ProxyRule and
`require` on ProxyRule, retaining their existing validation and selection
semantics. This naming contract does not change the current routing action
model or expand `transit.reject` beyond its documented tag conditions.

### Requirement: Atomic publication and resilient watching

The complete candidate SHALL pass parsing, validation, normalization, compilation, and required persistence before one immutable generation is published. Invalid candidates SHALL retain the last good bundle; atomic file and root-directory replacement SHALL preserve watching. Changes to Egress endpoints, admission requirements, either resolved Path-pool count, referenced policy, resolved policy contents, or EgressService startup settings SHALL report restart required and retain the active bundle.

#### Scenario: Atomic replacement contains an invalid candidate

- **WHEN** a watched configuration file is atomically replaced by an invalid resource candidate
- **THEN** the last good bundle remains active and watching continues for subsequent valid replacements

#### Scenario: A referenced policy changes without changing its name

- **WHEN** a reload changes the contents of a TrafficPolicy referenced by an Egress while retaining the same reference name
- **THEN** Ingress reports restart required and retains the active configuration and Session policy snapshots

#### Scenario: Only Transit membership changes

- **WHEN** a subscription or authorized administrator-metadata update changes nodes under an unchanged Egress binding
- **THEN** Ingress publishes the valid dynamic generation and drains removed candidates without requiring a new Egress policy snapshot

#### Scenario: Egress endpoint topology changes

- **WHEN** a candidate adds, removes, reorders, or changes an Egress endpoint or EgressService bind
- **THEN** the candidate is validated as a complete snapshot, the active runtime remains unchanged, and the reload result reports restart required

#### Scenario: Normalization preserves an Egress policy

- **WHEN** a reload changes only file or mapping order or writes equivalent explicit defaults
- **THEN** the normalized Egress policy fingerprint is unchanged and does not require a restart

#### Scenario: Only an unreferenced policy changes

- **WHEN** a reload changes a TrafficPolicy that no configured Egress references
- **THEN** that change alone does not trigger the Egress startup boundary or alter any live Session policy

#### Scenario: Only the configured Path baseline changes

- **WHEN** a valid candidate changes `pathPool.targetUsablePaths` to a different resolved requested baseline
- **THEN** reload reports restart required and retains the entire active bundle, including otherwise valid dynamic changes

#### Scenario: An omitted target becomes an equivalent explicit value

- **WHEN** the minimum is one and a valid candidate changes an omitted target to `targetUsablePaths: 2` without changing other normalized values
- **THEN** the resolved Path-pool fingerprint is unchanged and this edit alone does not require a restart

### Requirement: Ingress Egress endpoint forms normalize without changing identity

The Egress schema SHALL accept `host` and `port` as a one-element endpoint shorthand and a plural `endpoints` list whose entries contain `host` and `port`. Supplying both forms SHALL be rejected, and endpoint normalization SHALL not change the Egress resource name, Egress ID, or public-key binding. Retired native `address` fields SHALL fail with the canonical replacement diagnostic.

#### Scenario: Existing address and port are loaded

- **WHEN** an Egress supplies the retired native `address` and `port` shorthand
- **THEN** validation rejects the complete candidate and identifies `host` as the replacement for `address`

#### Scenario: Singular and plural endpoint forms conflict

- **WHEN** an Egress supplies `host`/`port` together with `endpoints`
- **THEN** validation rejects the resource instead of silently merging or selecting one form

#### Scenario: Canonical single-endpoint shorthand is loaded

- **WHEN** an Egress supplies only valid `host` and `port` endpoint fields
- **THEN** validation produces the equivalent one-element normalized endpoint list and preserves its routing identity

## ADDED Requirements

### Requirement: Egress Path-pool configuration

Each Ingress-side Egress SHALL accept optional `pathPool.minUsablePaths` and `pathPool.targetUsablePaths`. The minimum SHALL default to one; an omitted target SHALL request the minimum plus one, while an explicit target SHALL receive no implicit reserve. Values SHALL follow the detailed count, admission, and ceiling contract below.

#### Scenario: Path-pool configuration is omitted

- **WHEN** an Egress omits `pathPool`
- **THEN** its minimum is one and its requested usable-Path baseline is two, subject to runtime ceilings

#### Scenario: A larger minimum has no explicit target

- **WHEN** an Egress sets `minUsablePaths: 3` and omits the target
- **THEN** its requested baseline is four before runtime ceiling application

#### Scenario: An explicit target equals the minimum

- **WHEN** an Egress sets both counts to two
- **THEN** its requested baseline is exactly two and no additional spare is implied

#### Scenario: A Path-pool count is invalid

- **WHEN** a count is zero, negative, non-integral, null, outside its unsigned 32-bit range, or an explicit target is below the minimum
- **THEN** complete-bundle validation rejects the candidate with the resource and offending field path

#### Scenario: A target exceeds the current runtime ceiling

- **WHEN** a valid requested baseline exceeds a lower runtime or negotiated Path ceiling
- **THEN** configuration retains the requested baseline, runtime planning uses the bounded effective baseline, and the ceiling shortfall remains observable without rejecting otherwise valid configuration

#### Scenario: The default target requires wider arithmetic

- **WHEN** the minimum is the largest unsigned 32-bit integer and the target is omitted
- **THEN** default resolution uses a wider unsigned value for minimum plus one and does not wrap or turn the request into zero

#### Scenario: Capability requirements move with their meaning intact

- **WHEN** an Egress authors `admission.requiredCapabilities: [tcp, udp]`
- **THEN** the same common Egress capability eligibility checks apply as the retired capability requirement, without adding per-flow or native-UDP Transit restrictions

#### Detailed contract

| Field relative to Egress `spec` | Type | Default and meaning |
|---|---|---|
| `pathPool` | object | omitted or `{}` resolves its child defaults |
| `pathPool.minUsablePaths` | integer `1..=4294967295` | `1`; minimum authenticated usable non-draining Paths for new business admission |
| `pathPool.targetUsablePaths` | integer `1..=4294967295`, at least the minimum | omitted requests `minUsablePaths + 1`; explicit value is the requested baseline |
| `admission` | object | omitted or `{}` supplies no extra capability requirements |
| `admission.requiredCapabilities` | bounded unique `tcp`/`udp` set | `[]`; common Egress capability eligibility requirement |

Null is not an omitted count. Unknown child fields are invalid. The existing
common string, set, identity, namespace, and schema numeric rules remain in
force. Default arithmetic MUST use an unsigned representation wide enough to
hold `4294967296`. Normalized equality MUST compare the resolved requested
baseline, not merely whether the target was explicit, and MUST NOT depend on
the runtime ceiling or the current number of eligible Transit relationships.

Only authenticated `ACTIVE` or `DEGRADED`, otherwise eligible, non-draining
Paths count toward either count. Connecting, failed, closed, draining, and
policy-excluded Paths MUST NOT satisfy them. A single eligible Transit may
carry multiple independent Paths under the existing relationship weighting.
The target is a maintenance baseline, not a copy count, a new admission gate,
an exact pool size, or a public maximum. The state-machine contract defines
capacity-driven expansion and gradual contraction.

Both Path-pool counts and `admission.requiredCapabilities` are Egress startup
configuration. EgressService MUST NOT accept these Ingress-side fields or
gain a recommended Path count. No native routing rule may override them.
