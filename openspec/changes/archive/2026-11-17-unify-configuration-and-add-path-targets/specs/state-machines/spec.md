# State-machine delta

## MODIFIED Requirements

### Requirement: Bounded scheduling and autoscaling guards

Scheduling SHALL preserve one immutable Egress Session policy, bounded fair service, relationship and directional quality weighting, and per-sender replication accounting. Capacity autoscaling SHALL use hysteresis, incremental-capacity exclusion, and counter resets. Planned capacity scale-in SHALL preserve the effective baseline and common minimum after all selected drains; every Path removed by planned capacity scale-in SHALL enter `DRAINING` first.

#### Scenario: Autoscaler scales a Path in

- **WHEN** surplus persists for the configured non-zero scale-in window and removing every selected drain candidate preserves sufficient capacity, another compliant usable Path, the effective baseline, and the Egress minimum
- **THEN** the selected Path enters `DRAINING` before removal, preserving the documented hysteresis and budget guards

#### Scenario: A draining Path cannot justify another drain

- **WHEN** the common minimum is two, two Paths are usable, and one additional Path is already draining
- **THEN** the owner rejects a planned drain of either usable Path and subtracts concurrently selected drain candidates when checking the minimum

#### Scenario: Spare capacity still belongs to the baseline

- **WHEN** the minimum is one, the effective baseline is three, three usable Paths remain, and business demand is zero
- **THEN** capacity scale-in retains all three Paths rather than shrinking to the admission minimum

#### Scenario: Several drains would cross the baseline

- **WHEN** the effective baseline is three and four usable Paths plus one draining Path exist
- **THEN** at most one additional usable Path may be selected for capacity scale-in and the already draining Path cannot justify a second selection

#### Detailed contract

Each admitted Stream and UDP Association retains the immutable TrafficPolicy
snapshot captured by its Egress Session. Business-class priority/share is not a
public configuration surface. The scheduler gives bounded fair service and
rotates among backlogged Streams. FIN follows queued and acknowledged DATA;
closed observations may remain in bounded history.

The existing eligible-Path score remains:

```text
score(path) = relationship_weight
              * billing_multiplier
              * advertised_effective_capacity
              * quality_factor
```

The bounded quality factor is monotonic in congestion window, RTT, jitter,
loss, and reordering. One relationship's weight is shared across its Paths.
Required control and ordinary retransmission precede optional copies; each
sender remains independently bounded by its accepted Session allowance.

Capacity-driven expansion MUST wait for its configured consecutive shortfall
window. Capacity scale-in MUST wait for a separate non-zero low-utilization
window, stabilized recovery, and cooldown. It MUST drain at most one Path per
completed scale-in decision and MUST verify that all concurrent selected
drains leave the effective baseline, the common admission minimum, and enough
capacity for current directional demand. Draining Paths are excluded before
this calculation. Removal completes through existing acknowledgement and drain
deadline rules; it MUST NOT reset otherwise healthy admitted flows.

A candidate with known incremental capacity below scheduling overhead remains
excluded with a typed observation. Unknown capacity MUST NOT be represented as
measured zero, and zero business demand MUST NOT by itself exclude an otherwise
eligible baseline Path. Mandatory administrative, trust, authorization,
resource-limit, and transport-failure transitions retain their existing
priority even when they leave fewer Paths than the requested baseline.

Baseline refill and failed-Path recovery are bounded maintenance operations
under the following requirement, not evidence of sustained business demand.
They MAY start without waiting for the capacity shortfall window, but MUST
respect admission, hard ceilings, candidate exclusions, and retry backoff.
The owner MUST reserve occupied and in-flight attachment capacity, including
draining Paths that still consume a slot, before starting another attachment.
Opposite-direction counters reset after a scaling transition or failed probe.
The baseline does not create a replication budget or an independent standby
Path class.

### Requirement: Reconnected Sessions start fresh

When a Session closes because of Egress failure, Path loss, authorization failure, or protocol trust failure, its replacement SHALL use a new SessionID and capture the configured Egress policy. It SHALL recompute the requested and effective Path baselines from configuration and current ceilings while resetting demand targets, replication usage, retry/hysteresis state as allowed by trust guards, and Session lifecycle observations.

#### Scenario: Egress recovers after Session closure

- **WHEN** Ingress reconnects to the same configured Egress after the old Session was retired
- **THEN** the new Session uses its configured minimum and requested baseline with fresh demand observations, does not inherit the old load-expanded target, and does not reuse old Session state

#### Scenario: A busy Session reconnects while idle

- **WHEN** a Session previously expanded to six Paths with a configured baseline of three closes and its replacement starts without business demand
- **THEN** the replacement attempts to maintain the bounded baseline of three rather than inheriting six or falling back to one

### Requirement: Egress Session Path pool lifecycle

The Ingress owner SHALL maintain one authenticated Path pool per Egress relationship, independently of routing matches or business connections. Planned maintenance SHALL preserve eligibility and hard ceilings. A shortfall below the requested baseline SHALL not alone degrade service or deny admission while the minimum is met. Falling below the minimum SHALL deny new work without closing existing work solely for that shortfall; loss of the last ready Path SHALL retire the Session.

#### Scenario: Ready Paths fall below the configured minimum

- **WHEN** an Egress requires two usable Paths and a failure leaves one authenticated non-draining ready Path
- **THEN** the Session is degraded, new Streams and UDP Associations are denied, existing work can continue on the remaining Path, and bounded recovery attempts restore the common minimum

#### Scenario: Only draining Paths remain

- **WHEN** a Session has only authenticated draining Paths
- **THEN** existing work follows drain deadlines, new business admission is denied, and no draining Path counts toward the minimum for new admission

#### Scenario: Last ready Path is lost

- **WHEN** the last ready Path in the common pool fails
- **THEN** all related business resources close and the retired SessionID is not reused

#### Scenario: A baseline Path fails above the minimum

- **WHEN** the minimum is one, the requested baseline is three, and a failure leaves two otherwise healthy usable Paths
- **THEN** existing and new business work remain permitted by the count guard while bounded maintenance attempts to replenish the third Path

#### Scenario: No business resources are open

- **WHEN** a configured Egress has an eligible candidate and permits new Path attachment but no Stream or UDP Association exists
- **THEN** the owner establishes or refills the bounded baseline without waiting for a business open or synthesizing a target connection

### Requirement: Directional Path capacity drives scaling

Ingress SHALL maintain upstream and downstream Path observations separately. The current Session target SHALL cover the effective baseline and the larger direction-specific Path requirement, bounded by hard resource ceilings. Each direction SHALL retain its own scheduler inputs, and demand changes SHALL recompute the target without making a past expansion the new baseline.

#### Scenario: Downstream is the bottleneck

- **WHEN** upstream demand fits one Path but downstream demand requires three
- **THEN** the physical Path target is at least three within hard ceilings and the upstream and downstream schedulers use their respective observations

#### Scenario: Capacity demand exceeds the baseline

- **WHEN** the effective baseline is three, fresh downstream capacity observations require five Paths, and the hard ceiling permits five
- **THEN** sustained demand can expand the pool to five without changing the configured baseline of three

#### Scenario: Demand falls after expansion

- **WHEN** a five-Path pool has a baseline of three and fresh directional observations show sustained spare capacity
- **THEN** the computed demand target can fall to three and the owner gradually drains surplus Paths subject to the scale-in guards

### Requirement: Autoscaling remains bounded and low-frequency

Path sampling, Session demand aggregation, and baseline maintenance SHALL use bounded counters and low-frequency work. Capacity expansion and contraction SHALL use independent hysteresis, and planned contraction SHALL preserve the effective baseline and common minimum. A known candidate capacity below scheduling overhead SHALL remain excluded; unknown capacity SHALL not prevent bounded baseline maintenance by being treated as zero.

#### Scenario: Unknown capacity at startup

- **WHEN** a Session has not collected enough fresh measurements for effective capacity
- **THEN** Ingress uses the configured Egress cap as a provisional scheduling ceiling, marks the observation provisional, and does not create unbounded extra Paths

#### Scenario: Idle startup has no measured Path capacity

- **WHEN** business demand is zero and Path capacity is unknown at startup
- **THEN** Ingress can establish the bounded configured baseline without fabricating a zero-capacity or measured-capacity sample and without repeatedly expanding beyond it

#### Scenario: No candidate can satisfy the target

- **WHEN** a requested baseline cannot be reached because every eligible attachment attempt fails
- **THEN** maintenance retains surviving Paths, exposes the shortfall, and uses bounded retries with backoff rather than a busy loop or repeated target connections
