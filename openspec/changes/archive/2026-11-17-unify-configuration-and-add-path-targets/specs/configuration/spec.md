# Configuration delta

## MODIFIED Requirements

### Requirement: Session maintenance per Egress

Ingress SHALL maintain one Session slot per configured Egress, best-effort maintain its requested usable-Path baseline without business connections, reuse live idle Sessions for subsequent Streams and UDP Associations, and destroy the Session and related business connections when that Egress goes offline or suffers a hard failure. Baseline shortfall alone SHALL NOT degrade service or deny admission while the common minimum is met.

#### Scenario: Egress recovers after hard failure

- **WHEN** an Egress becomes online after its previous Session was destroyed by hard failure
- **THEN** Ingress creates a new Session and Path set instead of resurrecting the old Session

#### Scenario: Egress warms before a business match

- **WHEN** Ingress starts with a valid Egress binding and no business flow has matched a route
- **THEN** it can establish that Egress's initial Paths without synthesizing a target, listener, flow tag, or geodata match

#### Scenario: Only destination-specific routing rules exist

- **WHEN** Ingress starts with a valid Egress binding and no business flow has matched a rule
- **THEN** it can establish that Egress's initial Paths without synthesizing a target, listener, flow tag, or geodata match

#### Scenario: An idle Egress has an unmet usable-Path baseline

- **WHEN** an eligible Egress has no business connections and usable Paths are below its effective baseline
- **THEN** Ingress makes bounded background establishment attempts toward that baseline without waiting for a route match

#### Scenario: The minimum is met while the baseline is short

- **WHEN** the common minimum is one, the requested baseline is three, and two usable Paths remain
- **THEN** Ingress continues best-effort baseline recovery without degrading service or denying new business solely because the third Path is missing

#### Detailed contract

Egress `pathPool.minUsablePaths` is the common count-based admission
minimum. `pathPool.targetUsablePaths` sets the requested steady-state usable-Path
baseline; omission resolves to the minimum plus one, and an explicit target
receives no additional implicit reserve. The baseline belongs to the
Ingress-side Egress configuration, not an EgressService recommendation or a
routing-rule requirement.

Maintenance operates on each configured Egress binding independently of
listeners, business matches, active Streams, UDP Associations, and DNS traffic.
It best-effort establishes Paths toward the runtime-bounded baseline with
bounded backoff and the existing eligibility, authorization, capacity,
incremental-overhead, and lifecycle guards. Unavailable candidates and
establishment failures SHALL NOT trigger unbounded retries, an implicit Direct
route, or a different Egress.

A baseline shortfall is desired-state information. It SHALL NOT independently
change service health, admission permission, or the common minimum. Existing
capability, authorization, resource, freshness, and hard-failure checks remain
independent and can still deny admission. A shortfall below the common minimum
continues to deny new business while preserving existing work on remaining
ready Paths; loss of the last ready Path retires the Session.

### Requirement: Ingress owns Path target decisions

Ingress SHALL derive one bounded target Path count per Session from the Egress's requested usable-Path baseline and minimum, eligible Transit relationships, aggregate directional demand, Path quality, and hard resource ceilings. Route identities and flow matches SHALL NOT define additional Path targets, and Egress recommendations SHALL NOT override the Ingress decision. Capacity-driven expansion SHALL be allowed above the baseline, with gradual drain-aware contraction when demand subsides.

#### Scenario: Egress has no Path recommendation

- **WHEN** Egress reports capacity and admission state without a recommended Path count
- **THEN** Ingress computes one bounded Session target from its Egress configuration and runtime observations

#### Scenario: An omitted baseline preserves the default reserve

- **WHEN** an Egress configures a minimum of two and omits the target
- **THEN** its requested baseline is three before runtime ceilings are applied

#### Scenario: An explicit baseline adds no hidden reserve

- **WHEN** an Egress explicitly configures a minimum of one and a target of three
- **THEN** its requested baseline is exactly three rather than four

#### Scenario: Capacity demand exceeds the baseline

- **WHEN** fresh directional demand requires five usable Paths while the requested baseline is three and the runtime ceiling permits five
- **THEN** Ingress can expand toward five under the existing scale-out guards without treating the baseline as a maximum

#### Scenario: An expanded Session becomes idle

- **WHEN** an expanded Session's demand subsides and surplus persists through the scale-in stabilization window
- **THEN** Ingress gradually drains excess Paths toward the effective baseline under the existing cooldown and drain guards instead of retaining its historical demand peak

#### Detailed contract

Let `R` be the requested baseline resolved from Egress configuration and
`H` the current hard runtime Path ceiling. The effective baseline is
`B = min(R, H)`. The current physical target covers the larger of the
effective baseline and the independent upstream/downstream capacity
requirements, bounded by `H`. The current target is recomputed from current
observations and SHALL NOT become a monotonic record of the largest historical
load. Unknown demand remains unknown; it SHALL NOT become a fabricated measured
zero or unbounded demand.

The requested baseline SHALL remain observable when a hard ceiling prevents
reaching it. Runtime clamping SHALL NOT rewrite configuration or lower the
common admission minimum. If `H` prevents meeting the minimum, the existing
minimum-shortfall failure and admission semantics apply.

Planned scale-in SHALL preserve the effective baseline and common minimum,
subject to independent hard-failure and lifecycle transitions. Scale-in remains
slow, hysteretic, and drain-aware; it SHALL NOT cut accepted traffic solely to
reach the idle baseline. Expansion, draining, and recovery share the same
eligible Session Path pool and preserve one immutable TrafficPolicy.

### Requirement: Egress Session Path eligibility

All Streams and UDP Associations in one Session SHALL share the Path eligibility defined by its Egress Transit binding, authenticated Path readiness, health, and lifecycle state. The flow's route, target, listener, or business protocol SHALL NOT narrow the Transit set. Egress protocol capability and per-resource flow control SHALL remain enforced. Only eligible authenticated non-draining usable Paths SHALL count toward the minimum and baseline.

#### Scenario: Warmup finds an ineligible Transit

- **WHEN** a ready Transit adapter does not satisfy the Egress Transit binding
- **THEN** it is excluded from the Session pool and does not count toward the Egress minimum

#### Scenario: TCP-only Transit carries Egress UDP

- **WHEN** a Transit provides an eligible byte stream and the selected Egress supports UDP
- **THEN** UDP Associations can use the shared Path pool without requiring the Transit to support native UDP

#### Scenario: One Transit carries several Paths

- **WHEN** one eligible Transit relationship carries several independently authenticated Paths
- **THEN** its non-draining `ACTIVE` or `DEGRADED` Paths can satisfy the Egress Path minimum while sharing that relationship's configured weight

#### Scenario: A draining Path does not satisfy the baseline

- **WHEN** a Session has two eligible authenticated usable Paths and another Path is draining
- **THEN** the usable count for its minimum and baseline is two and maintenance does not use the draining Path to justify another planned drain

#### Detailed contract

The count shared by minimum admission, baseline maintenance, and planned
scale-in is the number of eligible independently authenticated ready Paths in
`ACTIVE` or `DEGRADED` state that are not draining. Connecting, closed,
failed, ineligible, and draining Paths SHALL NOT satisfy either threshold.
Separate independently authenticated Paths can count even when they share one
Transit relationship; the relationship's configured weight remains shared
rather than multiplied by its Path count.

The former `statusRequirements.capabilities` requirement is preserved as
`admission.requiredCapabilities` in the native configuration. Moving the key
SHALL NOT weaken capability checks, identity binding, or authorization.

### Requirement: Session demand aggregation is bounded

Ingress SHALL aggregate upstream and downstream demand once per Session using bounded counters and low-frequency windows. Route identities, policy IDs, and business classes SHALL NOT partition Path demand. A replacement Session SHALL start with empty counters and observations while retaining the configured Egress baseline; no unbounded per-flow demand history or local policy metadata SHALL be sent to Egress.

#### Scenario: A Session reconnects

- **WHEN** a new SessionID replaces a failed Session
- **THEN** its demand counters and EWMA start empty while prior values remain only in bounded observations

#### Scenario: Many matching rules share an Egress

- **WHEN** many routing rules send traffic to the same Egress
- **THEN** their traffic contributes to the same Session directional demand windows without allocating a separate Path requirement or demand-history entry per rule

#### Scenario: A replacement Session restores its configured baseline

- **WHEN** a Session with requested baseline three and a prior demand-driven target of six is retired and replaced
- **THEN** the new Session retains the requested baseline of three, applies its current hard ceiling, and starts with fresh demand state instead of inheriting the old target of six
