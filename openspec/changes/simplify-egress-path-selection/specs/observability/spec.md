# Observability delta

## MODIFIED Requirements

### Requirement: Detailed observability contract

The observation service SHALL conform to the complete detailed contract, including the common Session Path-pool and policy fields below, metric types, event registries, units, bounds, and health semantics. Session and Stream observations SHALL NOT expose retired business traffic-class fields. Requirements and scenarios supplement rather than replace the complete schemas.

#### Scenario: Snapshot generation identity

- **WHEN** `GET /api/v1/metrics/snapshot` returns a snapshot
- **THEN** `snapshot_generation` and `observed_generation` identify that same observation snapshot, with capture time and freshness included

#### Scenario: A Stream is inspected

- **WHEN** an authorized client queries a Stream using the shared Egress Session pool
- **THEN** the view links it to its Session and admission generation without `traffic_class_name`, `traffic_class_priority`, or `traffic_class_share` fields

#### Detailed contract

##### Session pool schema

Session resources retain their stable Session, Ingress and Egress identities,
lifecycle timestamps, admission generation, business-resource counts, control
state, close reasons, and reconnect observations. Their scheduling fields are:

| Field | Meaning |
|---|---|
| `minimum_usable_paths` | configured common Egress admission minimum |
| `target_path_count` | current bounded Ingress target for this Session |
| `ready_path_count` | authenticated ready Path count under the existing lifecycle contract; draining state remains separately observable |
| `usable_path_count` | non-draining ready Paths that count toward new-business admission |
| `eligible_transit_count` | current eligible same-namespace Transit relationships under the fixed Egress binding |
| `traffic_policy_id` | canonical namespaced TrafficPolicy resource identity selected by the Egress |
| `traffic_policy_generation` | configuration generation from which the immutable Session policy was captured |
| `demand_upstream_bps` | bounded aggregate upstream demand estimate, nullable before a valid window |
| `demand_downstream_bps` | bounded aggregate downstream demand estimate, nullable before a valid window |
| `replication_cap_bps` | negotiated Session hard cap, nullable before attachment negotiation |
| `replication_upstream_used_bps` | authoritative local outbound replication accounting rate, nullable before a valid window |
| `replication_downstream_used_bps` | peer outbound replication accounting rate, null unless an authoritative Session-scoped producer exists |

Counts are non-negative integers and bit rates use bits per second. Policy
snapshot generation and flow routing/admission generation have distinct
meanings; a dynamic node update MUST NOT relabel an existing Session policy
with a new generation. Query response generations still identify the current
observation snapshot, independently of those captured generations.

Pool shortfall and new-admission denial remain inspectable through typed
Session/Egress state and reason fields. Configured minimum, target count,
usable count, and hard ceiling MUST NOT be substituted for each other. Local
Session policy identity and demand fields MUST NOT be added to Egress's
authenticated global STATUS_REPORT. The global Egress replication allowance
MUST NOT be substituted for this Session's downstream accounting, and the two
directional usage fields MUST NOT imply a combined bidirectional bucket.

##### Retired class fields and metrics

Session and Stream views do not contain `traffic_class_name`,
`traffic_class_priority`, or `traffic_class_share`. A Stream's policy is
identified through its owning Session. There is no public rule/class Path
deficit map or demand history.

The optional `pathchord_bytes_total` metric uses the bounded `direction` label
without a business `class` label. Existing authentication, Origin checks,
redaction, declared metric types, and gauge-versus-counter distinctions remain
required. Policy IDs, routing-rule identities, target data, and administrator
tags MUST NOT become unbounded aggregate metric labels.

### Requirement: Egress status is global and policy-free

Egress status reports SHALL describe global Egress resource facts and SHALL NOT contain routing rules, Egress Transit selectors, TrafficPolicy identity, business-class policy, or Ingress demand metadata. Path-local quality observations SHALL be owned by Ingress and derived from local Path traffic and control feedback.

#### Scenario: Egress reports shared capacity

- **WHEN** an Egress serves multiple Ingress Sessions
- **THEN** its status reports aggregate wire rate, capacity, active target connections, service state, and global admission state without exposing per-rule information

### Requirement: Directional Path observations remain Ingress-owned

Ingress SHALL publish bounded upstream and downstream Path observations and use them for Session-scoped scheduling and autoscaling under the Egress binding. Egress status SHALL NOT duplicate those Path-local observations as a second authoritative source. Rule identity or business class SHALL NOT partition the common Path target.

#### Scenario: Path capacity is asymmetric

- **WHEN** upstream and downstream observations differ for one Path
- **THEN** Ingress retains separate directional values and computes the physical Path target from the larger directional requirement

## ADDED Requirements

### Requirement: Session Path-pool observations

Session observations SHALL identify the owning Egress, common minimum, current target, eligible Transit count, immutable policy snapshot, aggregate directional demand, and negotiated shared replication allowance. These fields SHALL follow the detailed schema and existing authorization, generation, cardinality, and unknown-value rules without allocating per-rule or per-business-class observations.

#### Scenario: Different routing rules use one Egress

- **WHEN** flows selected by several routing rules share a Session
- **THEN** queries expose one Session pool target, one policy snapshot, and aggregate directional demand rather than separate rule-specific targets or policies

#### Scenario: The minimum cannot be met

- **WHEN** at least one authenticated ready Path remains but usable non-draining Paths are below the minimum, or a negotiated ceiling prevents reaching that minimum
- **THEN** observations show the minimum, bounded target, ready count, usable count, and a typed admission or shortfall reason, retaining degraded service while a ready Path remains and no separate hard failure occurs

#### Scenario: A measurement is not available

- **WHEN** a Session has no accepted replication negotiation or an aggregate demand window has no authoritative sample
- **THEN** the corresponding field is null or explicitly unknown rather than a fabricated measured zero, and configured values remain distinguishable from negotiated or measured ones
