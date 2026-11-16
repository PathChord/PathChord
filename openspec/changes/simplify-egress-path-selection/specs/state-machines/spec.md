# State machines delta

## MODIFIED Requirements

### Requirement: Complete lifecycle and admission contract

Lifecycle owners SHALL enforce all state graphs, guards, actions, failure reasons, timers, and retry rules in the [detailed contract](#detailed-contract). A Path SHALL become ready only after authentication, identity/authorization checks, capability negotiation, and limit negotiation; internal connecting or closed records SHALL NOT be exposed as usable resources.

#### Scenario: Path has not completed admission

- **WHEN** a Path has not completed the checks and negotiation required for `PATH_READY`
- **THEN** it is not reported as ready or admitted for business traffic

#### Detailed contract

##### Admission and degraded service

New Streams and UDP Associations require the common Egress minimum of
`ACTIVE` or `DEGRADED` ready Paths, a fresh admissible Egress report, and the
required Egress business-protocol capability. `DRAINING` Paths remain eligible
only to complete already admitted work under their drain rules. A degraded
Path-count shortfall does not itself reset existing Streams or Associations.
The last ready Path loss, Egress hard failure, authorization disable/revoke,
endpoint restart, or protocol trust failure retains its existing terminal
Session cleanup semantics.

##### Session target and scheduling guards

The physical target covers the common minimum and the larger of the
upstream/downstream demand-derived requirements, bounded by negotiated and
global safety ceilings. Several Path instances through one Transit can count
toward that minimum; their relationship allocation is weighted once before
sharing it among the instances. No count promises Transit-provider diversity.

Demand counters and EWMA windows are Session-scoped. The owner does not keep
rule/policy/class deficit maps or grow demand history with rule cardinality.
Each direction retains its own quality and capacity observations. Unknown
measurements remain unknown; a configured hard cap is only a provisional
scheduling ceiling, not fabricated measured idle capacity.

Scale-out requires the configured consecutive shortfall window, and scale-in
requires its separate non-zero surplus window. Planned scale-in MUST count
only ready non-draining Paths that will remain after removing every selected
drain candidate. That remaining count MUST meet the common minimum and leave
a ready compliant Path. Emergency failure and hard
revocation are not delayed by that scale-in guard. A Path excluded for
insufficient incremental capacity exposes its reason. Opposite-direction
counters reset after a state change or failed probe.

##### Uniform policy and fair service

One Session policy snapshot applies to every Stream and UDP Association.
Business traffic classes and their priority/share configuration are absent;
bounded fair service and rotation among backlogged flows remain required.
Required control and ordinary reliable retransmission take priority over
optional copies. Each sender's optional business/control copies share its
outbound negotiated Session allowance, without granting a new allowance for
each flow or relationship or combining both directions into one counter.
Exhaustion skips optional copies but does not prevent a primary transmission
or ordinary reliable retransmission.

### Requirement: Bounded scheduling and autoscaling guards

Scheduling SHALL preserve the immutable Egress Session policy, fair bounded service among backlogged flows, relationship and directional quality weighting, and shared replication accounting. Autoscaling SHALL apply one Session Path target with hysteresis, common-minimum retention, draining, incremental-capacity exclusion, and counter resets. Route or business-class identity SHALL NOT partition the Path pool or demand.

#### Scenario: Autoscaler scales a Path in

- **WHEN** surplus persists for the configured non-zero scale-in window and removing a Path preserves the Egress common minimum and another compliant Path
- **THEN** the selected Path enters `DRAINING` before removal, preserving the documented hysteresis and budget guards

#### Scenario: A draining Path cannot justify another drain

- **WHEN** the common minimum is two, two Paths are usable, and one additional Path is already draining
- **THEN** the owner rejects a planned drain of either usable Path and also subtracts concurrently selected drain candidates when checking the minimum

### Requirement: Reconnected Sessions start fresh

When a Session closes because of Egress failure, Path loss, authorization failure, or protocol trust failure, the replacement Session SHALL use a new SessionID and reset aggregate demand, Path targets, replication usage, and lifecycle observations. It SHALL capture the configured Egress policy and begin from the common minimum within hard safety ceilings.

#### Scenario: Egress recovers after Session closure

- **WHEN** Ingress reconnects to the same configured Egress after the old Session was retired
- **THEN** the new Session starts from its Egress minimum and fresh observations without reusing the retired Session's demand, budget usage, or Path identities

### Requirement: Autoscaling remains bounded and low-frequency

Path health sampling and Session demand aggregation SHALL use bounded counters and low-frequency windows. Autoscaling SHALL use independent hysteresis for scale-out and scale-in, preserve the common Egress minimum during planned scale-in, and exclude candidates whose incremental capacity is below scheduling overhead. Unknown capacity SHALL NOT cause unbounded speculative Paths.

#### Scenario: Unknown capacity at startup

- **WHEN** a Session has not collected enough fresh measurements for effective capacity
- **THEN** Ingress uses the configured Egress cap as a provisional scheduling ceiling, marks the observation provisional, and does not create unbounded extra Paths

## REMOVED Requirements

### Requirement: Rule-specific Path targets share Path instances

**Reason**: There is one Path target and one eligibility pool per Ingress-to-Egress Session; routing rules no longer define independent Path targets.

**Migration**: Move the common minimum to the Egress admission requirements and aggregate all of the Session's directional demand without solving a rule-specific Path union.

## ADDED Requirements

### Requirement: Egress Session Path pool lifecycle

The Ingress Session owner SHALL maintain one authenticated Path pool for an Egress relationship, independently of matched routing rules. Planned expansion and draining SHALL preserve common eligibility and hard safety ceilings. Falling below the common minimum SHALL deny new business admission without closing existing work solely for that shortfall; losing the last ready Path SHALL retire the Session.

#### Scenario: Ready Paths fall below the configured minimum

- **WHEN** an Egress requires two usable Paths and a failure leaves one authenticated non-draining ready Path
- **THEN** the Session is degraded, new Streams and UDP Associations are denied, existing work can continue on the remaining Path, and bounded recovery attempts restore the common minimum

#### Scenario: Only draining Paths remain

- **WHEN** a Session has only authenticated draining Paths
- **THEN** existing work follows drain deadlines, new business admission is denied, and no draining Path counts toward the minimum for new admission

#### Scenario: Last ready Path is lost

- **WHEN** the last ready Path in the common pool fails
- **THEN** all related business resources close and the retired SessionID is not reused

### Requirement: Session policy remains uniform across Path changes

A live Session SHALL retain one immutable Egress TrafficPolicy snapshot and negotiated replication cap. Adding a Path or admitting a flow SHALL use that snapshot without replacing or broadening it. Dynamic Transit membership SHALL change the pool under the existing binding, with removed Paths draining and hard authorization failures taking their existing immediate effect.

#### Scenario: A new Path joins a busy Session

- **WHEN** another authenticated Path joins a Session containing Streams and UDP Associations
- **THEN** it joins their common pool with the existing policy and cap, without replaying target opens or introducing a per-flow policy version

#### Scenario: A subscription removes a relationship

- **WHEN** a successful subscription update removes a Transit used by the Session
- **THEN** Ingress stops creating Paths through that relationship, drains existing Paths within their deadlines, and keeps admitted flows on the same Egress
