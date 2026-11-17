# Spec Delta

## MODIFIED Requirements

### Requirement: Freshness and independent health states

Snapshots and authenticated status reports SHALL distinguish configured capacity, effective capacity, current wire rate, capacity confidence, service state, and new-admission state. Stale Egress reports SHALL exclude new admission while preserving existing work when heartbeat liveness remains healthy.

#### Scenario: Status is stale but the Path is alive

- **WHEN** heartbeat liveness is fresh but the newest Egress status exceeds the local freshness limit
- **THEN** the observation is marked stale, new business admission is denied, and existing work is not converted to a hard failure solely by report age

#### Scenario: Egress report exceeds its freshness threshold

- **WHEN** the newest authenticated Egress report is older than the configured freshness threshold
- **THEN** its observation is marked `stale`, is not interpreted as zero load, and does not permit new admission unless policy explicitly allows degraded operation

## ADDED Requirements

### Requirement: Egress status is global and policy-free

Egress status reports SHALL describe global Egress resource facts and SHALL NOT contain IngressRule, TransitRule, TrafficPolicy, rule demand, or class policy metadata. Path-local quality observations SHALL be owned by Ingress and derived from local Path traffic and control feedback.

#### Scenario: Egress reports shared capacity

- **WHEN** an Egress serves multiple Ingress Sessions
- **THEN** its status reports aggregate wire rate, capacity, active target connections, service state, and global admission state without exposing per-rule information

### Requirement: Capacity state is explicit

Observations SHALL expose configured capacity, effective capacity, current wire rate, and a capacity state of `unknown`, `provisional`, `measured`, or `stale`. Unknown values SHALL remain unknown and SHALL NOT be serialized as zero measurements.

#### Scenario: Provisional scheduling is active

- **WHEN** Egress has only its configured hard cap and no stable measured effective capacity
- **THEN** the observation marks capacity provisional, and Ingress may use the configured cap as a provisional scheduling ceiling

### Requirement: Admission state is explicit

Egress observations SHALL expose `admission_allowed` and a stable non-sensitive `admission_reason` independently of `service_state`. Resource exhaustion SHALL be observable as a degraded service with denied admission rather than as an implicit down state.

#### Scenario: Target connection resources are exhausted

- **WHEN** active connections and pending reservations reach the global Egress limit
- **THEN** observations report `admission_allowed=false` with a resource-limit reason while existing connections remain queryable

### Requirement: Directional Path observations remain Ingress-owned

Ingress SHALL publish bounded upstream and downstream Path observations and SHALL use them for rule-specific scheduling and autoscaling. Egress status SHALL not duplicate those Path-local observations as a second authoritative source.

#### Scenario: Path capacity is asymmetric

- **WHEN** upstream and downstream observations differ for one Path
- **THEN** Ingress retains separate directional values and computes the physical Path target from the larger directional requirement
