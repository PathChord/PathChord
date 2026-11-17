# Protocol delta

## MODIFIED Requirements

### Requirement: Complete protocol contract

Implementations claiming protocol conformance SHALL satisfy the complete [detailed contract](#detailed-contract) and the referenced `wire-profile-v1` contract together. These requirements and scenarios supplement the detailed invariants, message semantics, and management boundaries.

#### Scenario: Last ready Path is lost

- **WHEN** a Session loses its last `PATH_READY` Path
- **THEN** the Session and its business resources close, and a subsequent connection requires a new Session rather than resuming the old one

#### Detailed contract

##### Common Path eligibility and reliable control

A Session remains bound to one Ingress and one Egress. Its ready Path pool is
derived from the Egress binding and authenticated lifecycle state. No Stream
or UDP Association installs a bidirectional allowed-Path subset. New Path
attachments use the existing Session policy snapshot and cap; they do not
replay Stream state or renegotiate a different policy for existing flows.

`STREAM_OPEN` and `UDP_OPEN` use the whole Session pool through the canonical
empty eligible-Path list defined by the wire profile. Subsequent business and
control frames follow the same pool, with draining, flow-control, and required
capability checks still enforced. Removing a Path does not change target
identity or create another target connection. Losing the last ready Path
closes all Session business resources and retires its SessionID.

`SESSION_CONTROL_CANCEL` remains a general flow teardown/control-sequence
operation for local cancellation or timeout. Its existing same-sequence
replacement, fresh-sequence case, idempotency, dependency processing, and
opaque `flow_kind`/`flow_id` encoding remain in force. It does not carry a
target or payload, grant cross-Egress migration, or resurrect a closed flow.
All live business flows share Session Path eligibility.

##### Scheduling and replication

Ingress schedules upstream and Egress schedules downstream over the common
pool. Transit node weight supplies the configured relationship baseline;
multiple Path instances share that baseline before their directional capacity
and quality determine allocation. Per-flow bounded queues and fairness remain
required, without configurable business-class priority/share.

Ingress captures one Egress TrafficPolicy and requests its Session cap during
attachment. The negotiated value is the immutable hard upper bound. Optional
copies share bounded Session accounting within each sending direction rather
than independent per-flow or class allowances. Each sender enforces the
negotiated scalar cap against its own outbound copies; the cap does not imply
a synchronized sum of upstream and downstream usage. Required control and
ordinary reliable retransmissions
receive priority; optional copies can consume only residual allowance. The
Egress enforces the negotiated resource value and never receives the policy
identity, rule identities, Transit selectors, or demand windows.

Session-control sequence numbers, RequestID idempotency, Stream offsets,
half-close behavior, UDP datagram boundaries, authorization, Noise state, and
pre-admission-only Egress failover retain their existing contracts. Egress UDP
requires a byte-stream Path, not a third-party node's native UDP capability.

### Requirement: Reliable control and flow Path restrictions

Session control SHALL retain its Session-wide sequence space, duplicate suppression, dependencies, retention, acknowledgements, and retransmission. Control and data SHALL use the common Egress Session Path pool without per-flow eligible subsets. Flow cancellation SHALL preserve opaque identity and sequence semantics without disclosing target or business data.

#### Scenario: Flow loses all eligible Paths

- **WHEN** the last ready Path in a flow's common Session pool is lost
- **THEN** the Session and all related business resources close instead of retaining another rule's private Path subset

#### Scenario: One flow is cancelled while the Session remains live

- **WHEN** an opening or active flow is locally cancelled while other flows remain in the Session
- **THEN** the existing opaque cancellation encoding can replace or advance that flow's control sequence without revealing its target or business data, and other flows continue

### Requirement: Egress does not interpret Ingress policy

Egress SHALL receive only the narrow Session resource limits and scheduler data required by the wire contract. It SHALL NOT receive or evaluate routing rules, Egress Transit selectors, TrafficPolicy identity, business-class policy, or Ingress demand metadata. A shared Path pool SHALL NOT transfer Ingress policy ownership to the Egress service.

#### Scenario: Session carries a requested replication cap

- **WHEN** Ingress attaches a Session with a requested replication cap
- **THEN** Egress treats the value as an opaque resource limit and does not infer the Ingress rule or policy that produced it

## REMOVED Requirements

### Requirement: Policy compliant scheduling and replication

**Reason**: One Egress policy and shared Session pool replace local per-business-class scheduling and stricter class replication budgets.

**Migration**: Apply the uniform Egress scheduling contract below, retaining relationship weights, quality inputs, fairness, and resource priority without accepting business-class configuration.

### Requirement: Replication uses independent flow budgets under a Session cap

**Reason**: Independent per-flow policy scopes would reintroduce multiple effective policies or allowances within one Egress Session.

**Migration**: Account optional copies against the shared Session allowance selected by its Egress policy and bounded by the negotiated cap.

## ADDED Requirements

### Requirement: Uniform Egress Session scheduling

All admitted Streams and UDP Associations SHALL use their Session's common Path pool and immutable Egress TrafficPolicy. Scheduling SHALL preserve relationship weights, directional effective capacity and quality inputs, and fair bounded service among backlogged flows. Public business-class policy and per-flow Path or policy overrides SHALL NOT be used.

#### Scenario: Several rules share one Session

- **WHEN** flows selected by different routing rules use the same Egress Session
- **THEN** both directions can schedule them over the same eligible pool under one policy, subject to Path lifecycle and per-resource flow control

#### Scenario: One Path fails

- **WHEN** a Path fails while another common ready Path remains
- **THEN** affected TCP data can be retransmitted over the remaining pool and UDP socket identity is preserved without selecting a different Egress

### Requirement: Replication uses one shared Session allowance

Each sender SHALL account optional copies for all flows and control against one outbound Session allowance bounded by the negotiated hard cap. Egress SHALL enforce that cap without policy identity. Required control and ordinary reliable retransmission SHALL take priority over optional copies. Optional-copy exhaustion SHALL NOT fail a flow or prevent its primary transmission.

#### Scenario: Optional replication exhausts its budget

- **WHEN** a sender has no remaining outbound Session replication allowance for an extra copy
- **THEN** the primary or ordinary retransmission remains eligible, the optional copy is skipped, and the Stream is not failed solely for lacking replication

#### Scenario: More flows or Paths are admitted

- **WHEN** another flow or Path is admitted to an existing Session
- **THEN** it shares the existing allowance without increasing the negotiated cap or resetting consumed usage

#### Scenario: Separate Sessions reference the same policy

- **WHEN** two Egress Sessions reference the same TrafficPolicy resource
- **THEN** each enforces its own negotiated cap and accounting window without sharing usage across their distinct SessionIDs
