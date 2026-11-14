# Spec Delta

## ADDED Requirements

### Requirement: One owner validates lifecycle transitions

One Session/Path lifecycle owner SHALL validate every Path and Session transition, update the state, and emit its transition event. Protocol handlers, schedulers, and control adapters SHALL request transitions through that owner and SHALL NOT mutate lifecycle state directly.

#### Scenario: A peer requests an invalid transition

- **WHEN** a peer message would move a draining Session back to active
- **THEN** the lifecycle owner rejects the request, preserves the current state, and emits a typed diagnostic rather than applying a direct assignment

### Requirement: Service state and admission state are independent

The Egress service state SHALL express lifecycle and health, while a separate admission state SHALL express whether new target connections are currently accepted. `degraded` MAY allow or deny new work; `draining` and `down` SHALL deny it, with `down` closing related resources.

#### Scenario: Capacity is exhausted while a Session remains healthy

- **WHEN** Egress has ready Paths but no target-connection headroom
- **THEN** it reports `service_state=degraded` and `admission_allowed=false`, retains existing work, and returns a typed resource-limit result for new opens

### Requirement: Reconnected Sessions start fresh

When a Session closes because of Egress failure, Path loss, authorization failure, or protocol trust failure, the replacement Session SHALL use a new SessionID and SHALL reset demand, Path targets, replication usage, and lifecycle observations.

#### Scenario: Egress recovers after Session closure

- **WHEN** Ingress reconnects to the same configured Egress after the old Session was retired
- **THEN** the new Session starts from its rule minimums and fresh observations and does not reuse old Session state

### Requirement: Rule-specific Path targets share Path instances

Ingress SHALL calculate Path requirements independently for each matching EgressRule while allowing one compliant Path instance to satisfy multiple rules. A Path SHALL count toward a rule only when its relationship, capabilities, health, and policy eligibility satisfy that rule.

#### Scenario: Two rules share a Session

- **WHEN** one rule requires three compliant Paths and another requires one, with two Paths compliant with both rules
- **THEN** the Session maintains the minimum physical Path set that satisfies each rule independently and does not count an ineligible Path for either rule

### Requirement: Directional Path capacity drives scaling

Ingress SHALL maintain upstream and downstream Path observations separately. A bidirectional Session target SHALL cover the larger of the direction-specific Path requirements, while each direction SHALL use its own scheduler inputs.

#### Scenario: Downstream is the bottleneck

- **WHEN** upstream demand fits one Path but downstream demand requires three
- **THEN** the physical Path target is at least three and the upstream and downstream schedulers use their respective observations

### Requirement: Autoscaling remains bounded and low-frequency

Path health sampling and rule demand aggregation SHALL use bounded counters and low-frequency windows. Autoscaling SHALL use independent hysteresis for scale-out and scale-in, retain a compliant Path during scale-in, and exclude a candidate whose incremental capacity is below its scheduling overhead.

#### Scenario: Unknown capacity at startup

- **WHEN** a Session has not collected enough fresh measurements for effective capacity
- **THEN** Ingress uses the configured Egress cap as a provisional scheduling ceiling, marks the observation provisional, and does not create unbounded extra Paths
