# Configuration schema delta

## MODIFIED Requirements

### Requirement: Versioned schema conformance

The v1 schema SHALL expose Egress aggregate wire capacity and global inbound target-connection limits while keeping desired Path count, per-Ingress stream quotas, and Path safety ceilings outside the authored Egress service policy. Ingress-side Egress resources SHALL carry the explicit Transit binding, common admission minimum, and one TrafficPolicy reference defined in the detailed contract.

#### Scenario: Removed desired-Path fields are authored

- **WHEN** an EgressService contains `recommendedPathCount`, `maxConcurrentPaths`, or `maxStreamsPerIngress`
- **THEN** schema validation rejects the server-owned or retired field instead of treating it as an Ingress Path target

#### Scenario: Author runtime status in a resource

- **WHEN** an administrator supplies a resource containing an authored `status` field
- **THEN** validation rejects the resource and leaves the previously published snapshot active

#### Detailed contract

##### Egress Path fields

The existing Egress identity, endpoint, key, capabilities, and namespace rules
remain in force. The Ingress-side Egress schema includes:

| Field | Required | Type and semantics |
|---|---|---|
| `transit` | yes | object containing only optional `require` and `reject` fields; `{}` explicitly admits all otherwise eligible same-namespace nodes |
| `transit.require` | no | selector using the existing `labels`, `tags`, and `capabilities` matching rules; omitted or empty means no positive filter |
| `transit.reject` | no | object containing only `tags`; a node matching any listed tag is excluded |
| `trafficPolicyRef` | yes | name of exactly one same-namespace TrafficPolicy; no runtime-dependent implicit policy |
| `statusRequirements.minUsablePaths` | no | positive unsigned 32-bit integer, default `1`; shared business-admission minimum, not an Egress-service recommendation or exact target |
| `statusRequirements.capabilities` | no | existing common Egress capability requirement; not a per-flow Transit capability filter |

Selectors and tag lists retain the common string, collection, identity, and
namespace bounds. A configured Transit capability selector remains an explicit
administrator condition; Ingress MUST NOT add native UDP as a Transit condition
merely because a business flow uses Egress UDP. Candidates MUST support the
Path's byte-stream transport and all explicitly configured adapter options.

`transit` does not accept `match`, `order`, `weight`, `trafficClassRef`, a second
policy reference, or a desired Path count. Node weights remain configured on
TransitProxy objects; all Paths of one relationship share its weight rather
than multiplying it. Direct Transit requires an explicit node admitted by the
binding. A zero-candidate runtime set is an unavailable Egress condition, not a
configuration-driven direct bypass.

EgressRule retains `order`, optional `match`, exactly one existing Egress
action, and the existing catch-all rules. Its `requirements` object and all
Transit/policy/class overrides are invalid. Supported resource kinds exclude
TransitRule; geodata flow predicates apply to EgressRule and ProxyRule only.
No compatibility translator silently combines retired resources.

##### TrafficPolicy fields

| Field | Required | Default and limits |
|---|---|---|
| `scheduler` | no | `effectiveCapacityWeighted` |
| `sessionReplicationBudgetBps` | no | `0`; non-negative integer no greater than `10^12` |
| `retransmissionReplication` | no | `disabled`; existing supported replication values |

`classes`, `classReplicationBudgetBps`, and rule-level `trafficClassRef` are
retired and rejected even when their values are empty or zero. The effective
policy is captured once for each Session, and the requested replication cap
uses this one policy subject to attachment negotiation. The same policy may
be referenced by several Egresses, but its budget is accounted independently
by their Sessions and by each sending direction. A single negotiated scalar
cap bounds each sender's outbound copies; it is not a synchronized allowance
combining upstream and downstream traffic.

`retransmissionReplication: disabled` requests a zero Session replication cap
even when `sessionReplicationBudgetBps` is positive. `allowed` requests
`floor(sessionReplicationBudgetBps / 8)` wire bytes per second, bounded by the
existing profile hard cap. Egress may accept a lower value. A zero cap disables
optional business and control copies in both directions while preserving
primary traffic, necessary control operations, and ordinary reliable
retransmission. Later Path attachments use the existing Session negotiation.

##### Publication and restart boundary

The normalized startup fingerprint covers each Egress's endpoint, identity,
capabilities, admission requirements, Transit binding, policy reference, and
resolved policy contents. A semantically changed fingerprint requires an
Ingress restart. Reordering source files or mapping keys, or retaining the same
normalized values, does not constitute a change. A reload that mixes a startup
change with dynamic changes MUST retain the complete previous bundle.

Subscription refresh, dynamic node membership and authorized administrator
metadata continue to publish atomically under the unchanged binding and
policy. Failed refresh retains the last successful nodes. This boundary
prevents old and new flows in one live Session from using different policy
definitions or changing its negotiated cap through a later Path attachment.

These Path and policy fields are interpreted by Ingress. EgressService retains
its global wire/connection ceilings and MUST NOT acquire Transit selectors,
TrafficPolicy identities, rule demand, or business-class policy fields.

### Requirement: Atomic publication and resilient watching

The complete candidate SHALL pass parsing, validation, normalization, compilation, and required persistence before one immutable generation is published. Invalid candidates SHALL retain the last good bundle. Atomic file and root-directory replacement SHALL preserve watching. Changes to an Egress Path binding, admission minimum, policy reference, or resolved TrafficPolicy definition SHALL report restart required without partially publishing the candidate.

#### Scenario: Atomic replacement contains an invalid candidate

- **WHEN** a watched configuration file is atomically replaced by an invalid resource candidate
- **THEN** the last good bundle remains active and watching continues for subsequent valid replacements

#### Scenario: A referenced policy changes without changing its name

- **WHEN** a reload changes the contents of a TrafficPolicy referenced by a configured Egress while retaining the same reference name
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

### Requirement: Deterministic bounded rule compilation

Rules SHALL use explicit unique order values and deterministic, bounded, I/O-free evaluation. EgressRule output SHALL select only an Egress action and diagnostic rule identity. Each Egress SHALL resolve one TrafficPolicy during complete-bundle validation, independent of runtime candidate cardinality. Retired TransitRule and traffic-class configuration SHALL be rejected explicitly.

#### Scenario: Multiple Transit relationships lack a policy

- **WHEN** an Egress with several possible Transit relationships omits `trafficPolicyRef`
- **THEN** complete-bundle validation rejects the missing reference before publication rather than admitting a single-path configuration that fails after nodes are added

#### Scenario: Only one Transit is currently available

- **WHEN** an Egress has only one currently available Transit relationship but omits its policy reference
- **THEN** the same validation failure occurs without creating an implicit single-Transit policy

## ADDED Requirements

### Requirement: Egress Path binding schema

Each Egress SHALL declare `spec.transit` and `spec.trafficPolicyRef` under the existing namespaced resource graph. The binding SHALL follow the detailed selector and exclusion contract. `statusRequirements.minUsablePaths` SHALL be the only configured Path admission minimum; a binding SHALL NOT contain flow matches, rule order, business protocol overrides, or desired Path counts.

#### Scenario: Transit conditions are independent of business context

- **WHEN** an Egress declares Transit label requirements and rejected tags
- **THEN** those conditions determine one candidate set for that Egress without accepting target, listener, source, process, or flow-tag predicates

#### Scenario: An Egress policy reference is missing or cross-namespace

- **WHEN** `trafficPolicyRef` does not resolve to a TrafficPolicy in the Egress namespace
- **THEN** the complete candidate is rejected with the offending field and resource identity, retaining the prior published generation

#### Scenario: Transit binding is explicitly unrestricted

- **WHEN** an Egress declares `transit: {}` with a valid policy reference
- **THEN** all same-namespace Transit nodes are candidates subject to adapter support, authentication, health, and hard administrative exclusions

### Requirement: Retired routing and class fields fail validation

The schema SHALL reject TransitRule resources, EgressRule `requirements`, traffic-policy or traffic-class overrides on routing rules, and TrafficPolicy `classes` or `classReplicationBudgetBps`. It SHALL NOT merge old rules, ignore retired fields, or infer a policy from whichever Transit is available.

#### Scenario: Legacy Transit rules disagree

- **WHEN** a configuration contains two old TransitRule resources that select different nodes for different business flows
- **THEN** the candidate is rejected and no guessed union, first-match binding, or business-class policy is published

#### Scenario: A class budget is authored

- **WHEN** a TrafficPolicy contains `classReplicationBudgetBps` or `classes`, including an empty class map
- **THEN** validation identifies the retired field instead of accepting an inert budget or class definition
