# Spec Delta

## MODIFIED Requirements

### Requirement: Complete canonical wire contract

A v1 implementation SHALL satisfy every layout, registry, limit, failure rule, and conformance-vector obligation in the detailed contract. The unreleased v1 registry SHALL use the finalized Session budget, status, and admission layouts and SHALL NOT expose provisional PathRebind or TrafficClass extensions.

#### Scenario: Provisional frame is presented

- **WHEN** a peer presents a frame code reserved for the removed `PathRebind`, `PathRebindAck`, `STREAM_OPEN_CLASS`, or `UDP_OPEN_CLASS` extensions
- **THEN** the receiver treats the code as unassigned v1 input and closes only the carrying Path according to malformed-frame rules

#### Scenario: Deterministic vector round trip

- **WHEN** an implementation encodes and decodes a published v1 conformance vector
- **THEN** both operations reproduce the exact canonical bytes, including the specified Noise compatibility vector

## ADDED Requirements

### Requirement: Session replication cap is negotiated during attachment

`SESSION_ATTACH` SHALL carry an Ingress requested Session replication cap, and `SESSION_ATTACH_OK` SHALL carry the Egress accepted effective cap. Both values SHALL be bounded wire byte rates; the effective cap SHALL be no greater than either peer's accepted hard limit and SHALL apply to every Path in the Session.

#### Scenario: Egress accepts a lower cap

- **WHEN** the Egress cannot accept the requested cap but can admit the Session with a lower cap
- **THEN** it returns the lower effective cap, and both peers use that value as the Session hard ceiling while ordinary reliability remains available

### Requirement: Global status carries explicit capacity and admission state

`STATUS_REPORT` SHALL distinguish configured wire capacity, effective capacity, current aggregate wire rate, capacity state, service state, and global new-admission state. Effective capacity SHALL be explicitly unknown, provisional, measured, or stale; `admission_allowed` SHALL be independent of `service_state`.

#### Scenario: Capacity has not been measured

- **WHEN** Egress has insufficient fresh measurements for effective capacity
- **THEN** it reports an unknown or provisional capacity state while Ingress may use the configured hard cap as a provisional scheduling ceiling

### Requirement: ACK ranges cannot confirm unsent bytes

A receiver of `STREAM_ACK` SHALL validate every acknowledged range against the sender's locally recorded set of emitted Stream offset intervals before releasing retransmission data. A range covering an unsent gap or future offset SHALL be a protocol violation.

#### Scenario: Future ACK is authenticated

- **WHEN** an authenticated ACK range covers an offset that the local sender has not emitted
- **THEN** the receiver rejects the ACK as a Session semantic violation and does not release any retained range based on it

## REMOVED Requirements

### Requirement: Provisional Path replacement frames

**Reason**: Path replacement is fully represented by a new PathID joining the existing Session through the normal admission exchange; the provisional frames were unregistered and unused.

**Migration**: Remove codes 16 and 17, payloads, codec variants, and vectors. Use `PATH_HELLO`, `SESSION_ATTACH`, and `PATH_READY` for every new Path.

### Requirement: TrafficClass wire extensions

**Reason**: Rule and TrafficClass policy remain Ingress-owned; Egress uses uniform downstream scheduling and must not receive policy metadata.

**Migration**: Remove the traffic-classes capability and class-specific open frames from v1. Keep class accounting and upstream scheduling local to Ingress.
