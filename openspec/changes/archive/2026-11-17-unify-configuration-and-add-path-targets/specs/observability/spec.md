# Observability delta

## MODIFIED Requirements

### Requirement: Session Path-pool observations

Session observations SHALL identify the owning Egress, common minimum, requested baseline, effective bounded baseline, current demand-derived target, actual ready and usable counts, typed target shortfall, eligible Transit count, immutable policy, directional demand, and replication allowance. These fields SHALL preserve authorization, generation, cardinality, and unknown-value rules without per-rule or per-class observations. Baseline shortfall alone SHALL NOT change health or admission.

#### Scenario: Different routing rules use one Egress

- **WHEN** flows selected by several routing rules share a Session
- **THEN** queries expose one Session pool target, one policy snapshot, and aggregate directional demand rather than separate rule-specific targets or policies

#### Scenario: The minimum cannot be met

- **WHEN** at least one authenticated ready Path remains but usable non-draining Paths are below the minimum, or a negotiated ceiling prevents reaching that minimum
- **THEN** observations show the minimum, bounded target, ready count, usable count, and a typed admission or shortfall reason, retaining degraded service while a ready Path remains and no separate hard failure occurs

#### Scenario: A measurement is not available

- **WHEN** a Session has no accepted replication negotiation or an aggregate demand window has no authoritative sample
- **THEN** the corresponding field is null or explicitly unknown rather than a fabricated measured zero

#### Scenario: Runtime ceiling clamps the baseline

- **WHEN** the requested baseline is six, the hard runtime ceiling is four, and four Paths are usable
- **THEN** the requested baseline remains six, the effective baseline is four, target shortfall is two, and its reason is `runtime_limit` without baseline shortfall independently degrading health or denying admission

#### Scenario: Partial baseline recovery remains healthy

- **WHEN** the minimum is one, the requested baseline is three, two Paths are usable, and a bounded background recovery is in progress
- **THEN** observations retain the minimum, requested baseline, effective baseline, and actual counts, report a shortfall of one with the dominant typed reason, and do not derive degraded health or denied admission from that shortfall alone

#### Scenario: Load expansion does not change the configured baseline

- **WHEN** requested and effective baselines are three and current directional demand requires five Paths within the runtime ceiling
- **THEN** observations retain both baselines at three while `target_path_count` reflects the current bounded demand target of five

#### Scenario: A Session exceeds its idle baseline

- **WHEN** five Paths are usable for a requested baseline of three
- **THEN** `target_shortfall` is zero and `target_shortfall_reason` is null even while demand or gradual draining keeps the actual count above the baseline

#### Scenario: Several shortfall causes apply

- **WHEN** a baseline shortfall has more than one applicable registered cause
- **THEN** observations select the deterministic dominant reason in the documented precedence rather than varying by producer or adapter

#### Scenario: Prometheus reads live Path-planning totals

- **WHEN** an authorized client reads `/metrics`
- **THEN** the four registered Path-planning gauges sum the same live Session snapshot without new labels, report zero for an empty live set, and do not include retired Session history or represent lifetime counters

#### Detailed contract

##### Session Path planning fields

The authorized Session read model and `session.changed` payload SHALL expose
the following count and planning fields from one bounded observation snapshot:

| Field | Type and meaning |
|---|---|
| `minimum_usable_paths` | configured common count-based admission minimum |
| `requested_target_usable_paths` | unsigned 64-bit value in `1..=4294967296`: requested baseline resolved from explicit target or the minimum-plus-one default, before runtime clamping |
| `effective_target_usable_paths` | requested baseline clamped to the current hard runtime Path ceiling |
| `target_path_count` | current runtime-bounded physical target covering the effective baseline and directional capacity need; not the historical peak |
| `ready_path_count` | authenticated ready Path count under the lifecycle contract, with draining separately observable |
| `usable_path_count` | eligible independently authenticated non-draining ready `ACTIVE` or `DEGRADED` Paths |
| `target_shortfall` | `max(requested_target_usable_paths - usable_path_count, 0)`, computed without unsigned underflow |
| `target_shortfall_reason` | null when there is no baseline shortfall; otherwise one stable reason from the registry below |

The requested value SHALL retain the wider minimum-plus-one default without
overflow at the maximum authored unsigned 32-bit minimum. A runtime clamp
SHALL NOT rewrite that requested value or hide an unmet baseline. The minimum,
requested baseline, effective baseline, current demand target, ready count,
and usable count SHALL NOT substitute for each other.

Unknown demand SHALL remain null or explicitly unknown until a valid window
exists; these planning fields SHALL NOT turn missing demand into a measured
zero. Configured Egress resources without a live Session SHALL NOT create
fabricated authenticated Session rows merely to display a desired baseline.
Their desired configuration remains available through the existing configured
resource observations without claiming Path readiness.

Existing eligible Transit count, captured TrafficPolicy identity and
generation, authoritative aggregate directional demand, per-sender replication
allowance/usage, lifecycle timestamps, and owning identities remain present
under their existing null, generation, and authorization rules. A replacement
Session clears old demand and hysteresis while exposing the same configured
baseline resolved against its current runtime ceiling.

##### Baseline shortfall reasons

For a positive `target_shortfall`, select the first applicable reason in this
order:

| Precedence | Reason | Applicability |
|---|---|---|
| 1 | `runtime_limit` | a current hard runtime Path ceiling is below the requested baseline |
| 2 | `admission_blocked` | an independent admission constraint prevents Path establishment |
| 3 | `no_eligible_transit` | the Egress binding has no eligible Transit candidate for an establishment attempt |
| 4 | `connect_failed` | the latest bounded establishment attempt failed, including its retry backoff |
| 5 | `recovering` | a baseline shortfall remains and no preceding reason applies, including bounded establishment or stabilization in progress |

`target_shortfall_reason` SHALL be null if and only if
`target_shortfall == 0`. Reasons are bounded identifiers, not raw error text.
A baseline shortfall SHALL NOT be serialized as an admission-denial reason or
independently change Session/Egress service health, admission state, or aggregate
connected/degraded summaries. Independent minimum, freshness, capability,
authorization, resource, and lifecycle failures keep their existing effects.

The shortfall compares the requested idle baseline with actual usable count;
it SHALL NOT be computed from an enlarged demand target. Directional demand
can therefore require more Paths while baseline shortfall remains zero.

##### Query, event, and metric consistency

Session list/detail queries, snapshot-backed drill-down views, and
`session.changed` events SHALL preserve the same field meanings, dominant
reason, redaction, and observation generation. Changes in any planning field
remain observable even when health and business-connection counts do not change.
SSE recovery snapshots SHALL carry the current planning state before later
deltas.

Path planning stays Ingress-owned. These local fields SHALL NOT be added to
authenticated Egress `STATUS_REPORT`, turned into Egress Path recommendations,
or used as raw endpoint/user-controlled aggregate metric labels. The stale
`pathchord_egress_recommended_paths` family is retired and SHALL NOT be emitted
or reused for these distinct local counts. Existing aggregate
gauge/counter typing, bounded cardinality, authentication, Origin checks, and
unknown-value handling remain in force.

The Prometheus registry SHALL add these aggregate gauges without introducing
new labels:

| Gauge | Value from the current live Session snapshot |
|---|---|
| `pathchord_session_requested_target_usable_paths` | sum of `requested_target_usable_paths` |
| `pathchord_session_effective_target_usable_paths` | sum of `effective_target_usable_paths` |
| `pathchord_session_target_paths` | sum of `target_path_count` |
| `pathchord_session_target_shortfall` | sum of `target_shortfall` |

Each value SHALL use the same live Session set from one canonical observation
snapshot, exclude closed or retired Session history, and be zero when that
live set is empty. These gauges MAY increase or decrease with current planning
state and SHALL NOT be represented as lifetime counters. Existing ready-Path,
Session, minimum, and actual-count observations retain their meanings; a
requested target SHALL NOT substitute for an actual ready count.

The reason remains a bounded typed query/event field. Raw reason text, endpoint
hosts, resource IDs, administrator data, or other new label values SHALL NOT
be added to these aggregate gauges.
