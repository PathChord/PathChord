# Spec Delta

## ADDED Requirements

### Requirement: Egress hard failure closes the Session

An Egress `down` state, authorization failure, or loss of the last ready Path SHALL close the related Session and business resources. A replacement connection SHALL use a new SessionID; `degraded` and stale status SHALL retain existing work unless a separate hard failure occurs.

#### Scenario: Egress reports down

- **WHEN** a fresh authenticated Egress report says `connected=0` and `service_state=down`
- **THEN** Ingress closes the related Paths, Session, Streams, UDP Associations, local connections, and target connections, then retires the SessionID

### Requirement: Stale health blocks new admission only

Ingress SHALL treat heartbeat liveness and Egress health freshness as independent. A Session with stale or missing Egress health SHALL reject new business admissions while retaining existing work when Path liveness remains healthy.

#### Scenario: Heartbeat is fresh but status is stale

- **WHEN** a Path continues to exchange heartbeat traffic but the newest Egress status exceeds the local freshness limit
- **THEN** the Path remains available for control and existing work, while new Streams and UDP Associations are rejected until a fresh status is accepted

### Requirement: Validated future ACKs are Session trust failures

Ingress SHALL validate ACK ranges against its own emitted Stream intervals before applying them. After that local invariant is verified, an authenticated future ACK SHALL close every Path in the Session, retire the SessionID, and trigger bounded new-Session recovery rather than only failing one Path.

#### Scenario: Future ACK follows a correct local frontier

- **WHEN** a peer sends an authenticated ACK beyond the locally recorded emitted intervals and local frontier accounting is valid
- **THEN** the Session is closed as a protocol trust failure, retained data is not released by the ACK, and a later Session uses a new SessionID

### Requirement: Session trust failures are circuit-broken

Automatic Session recovery after a protocol trust failure SHALL use bounded exponential backoff and SHALL open a circuit breaker after repeated failures within the configured failure window. The breaker SHALL stop new attempts without revoking authorization automatically.

#### Scenario: Repeated protocol violations occur

- **WHEN** the same Egress repeatedly causes Session trust failures inside the failure window
- **THEN** Ingress marks the Egress unavailable for new Sessions, preserves the diagnostic, and waits for cooldown or explicit recovery before retrying

### Requirement: Candidate failover ends at business admission

When a selected Egress candidate fails before `STREAM_OPEN` or `UDP_OPEN` is admitted, Ingress MAY try the next compliant candidate from the same generation. Once a target connection is admitted, Egress failure SHALL close the business resource and SHALL NOT transparently recreate the target connection.

#### Scenario: Path admission fails before Stream open

- **WHEN** the first Egress candidate cannot establish a compliant Path before `STREAM_OPEN`
- **THEN** Ingress tries the next compliant candidate or returns the typed admission failure without falling through to an unconfigured Proxy

#### Scenario: Egress fails after target admission

- **WHEN** an admitted Stream loses its Egress Session
- **THEN** the Stream and target connection close, and the application may retry; the proxy does not silently dial a replacement target

### Requirement: Egress does not interpret Ingress policy

Egress SHALL receive only the narrow Session resource limits and scheduler data required by the wire contract. It SHALL NOT receive or evaluate EgressRule, TransitRule, selector, TrafficPolicy identity, or rule-level demand metadata.

#### Scenario: Session carries a requested replication cap

- **WHEN** Ingress attaches a Session with a requested replication cap
- **THEN** Egress treats the value as an opaque resource limit and does not infer the Ingress rule or policy that produced it

### Requirement: Replication uses independent flow budgets under a Session cap

Ingress SHALL account replication per Stream/UDP policy scope while enforcing one negotiated Session hard cap. Control copies SHALL share that cap and take priority over optional business copies; ordinary reliable retransmission SHALL remain available when optional replication is exhausted.

#### Scenario: Optional replication exhausts its budget

- **WHEN** a Session has no remaining replication allowance for an extra copy
- **THEN** the primary or ordinary retransmission remains eligible, the optional copy is skipped, and the Stream is not failed solely for lacking replication
