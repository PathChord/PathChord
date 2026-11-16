# Wire profile delta

## MODIFIED Requirements

### Requirement: Ordered Session control envelopes

Session control SHALL use the registered envelope, per-sender sequence space, dependencies, acknowledgements, and idempotent opaque cancellation encoding. Encoders SHALL emit an empty eligible-Path list; receivers SHALL enforce the whole-pool and retired-list behavior in the detailed contract. Replicated copies SHALL preserve their control sequence and payload while using new Path frame sequences and Noise nonces.

#### Scenario: Control operation is replicated

- **WHEN** copies of one `SESSION_CONTROL` operation arrive over multiple eligible Paths
- **THEN** the receiver applies its control sequence once, after its dependency, and acknowledges it through the Session control sequence space

#### Scenario: A new open uses the Session pool

- **WHEN** a sender encodes `STREAM_OPEN` or `UDP_OPEN` in a Session-control envelope
- **THEN** it writes `eligible_path_count=0` with no PathID entries and the admitted flow uses the Session pool in both directions

#### Scenario: A peer supplies a retired per-flow list

- **WHEN** an otherwise valid Stream or UDP open carries a non-empty canonical eligible-Path list
- **THEN** the receiver rejects that open with the operation-specific error and `LOCAL_POLICY`, creates no target connection, and processes the rejection and control acknowledgement idempotently without narrowing the pool

#### Scenario: A cancelled flow has a pending control operation

- **WHEN** a locally cancelled flow has an unacknowledged Session-control operation
- **THEN** `SESSION_CONTROL_CANCEL` can replace that operation at its existing sequence using only the opaque flow kind and ID, retaining the registered cancellation and dependency rules

#### Detailed contract

##### Session-control layout and whole-pool semantics

The registered Session-control encoding is retained:

```text
control_seqno         varint
dependency_present    varint (0 or 1)
depends_on            varint, present only when dependency_present = 1
inner_frame_type      varint
eligible_path_count   varint
eligible_paths        repeated PathID
inner_payload         bytes(max_control_payload)
```

Senders MUST encode `eligible_path_count` as zero and include no PathID entries
for every inner operation. For STREAM_OPEN and UDP_OPEN, zero means the common
Session Path pool in both directions, subject to authentication, readiness,
draining, and flow-control constraints. It does not create a policy-free Path
or permit a Path belonging to another Session.

The existing bounded parser contract remains: a declared list has at most 256
entries, is sorted and unique, and fits within `max_control_payload` together
with the envelope and inner payload. A well-formed non-empty list on
STREAM_OPEN or UDP_OPEN is a retired policy restriction. The receiver MUST
process it as a rejected open, returning STREAM_OPEN_ERR or UDP_OPEN_ERR with
LOCAL_POLICY before target dialing, reserving no lasting target resource, and
acknowledging the applied control sequence. Retried copies produce the same
rejection and MUST NOT block later valid control operations. Other live flows
and the Session remain usable unless a separate failure closes them.

A non-empty list on another inner operation remains invalid under its
existing canonical envelope rules. Non-canonical integers, invalid dependency
flags, unsorted or duplicate entries, more than 256 entries, oversized
payloads, and unknown inner types remain malformed and follow the existing
bounded decoding failure rules. The retired-list handling MUST NOT relax
those structural checks.

Allowed inner types remain SESSION_CLOSE, STREAM_OPEN, STREAM_OPEN_OK,
STREAM_OPEN_ERR, STREAM_ACK, STREAM_WINDOW, STREAM_FIN, STREAM_RST, UDP_OPEN,
UDP_OPEN_OK, UDP_OPEN_ERR, and UDP_CLOSE. Path HELLO, attach, readiness, DRAIN,
CLOSE, STATUS_REPORT, HEARTBEAT, and CONTROL_ACK remain Path-local. Each sender
retains its independent Session-control sequence, dependency ordering,
duplicate suppression, retransmission, and Session-control ACK encoding.

##### Opaque cancellation

The registered SESSION_CONTROL_CANCEL payload is retained:

```text
control_seqno         varint
flow_kind             varint (0=TCP Stream, 1=UDP Association)
flow_id               varint
```

Local cancellation or timeout can replace an unacknowledged operation for the
flow at the same control sequence. If no operation for it remains
unacknowledged, cancellation can use a new sequence. Existing idempotency,
closed-flow handling, sequence replacement, acknowledgement, and dependency
semantics remain required. Cancellation carries no target or application data
and does not depend on separate flow-specific Path sets.

No frame code, capability identifier, error code, profile hard cap, Noise
prologue, or Session-attachment field is added or renumbered. The negotiated
Session replication cap retains its existing wire layout and meaning as an
immutable resource ceiling.

### Requirement: Session replication cap is negotiated during attachment

`SESSION_ATTACH` SHALL carry the Egress policy's requested replication cap and `SESSION_ATTACH_OK` its accepted cap as wire byte rates. Disabled replication SHALL request zero; allowed replication SHALL request the policy bit rate divided by eight and rounded down within profile limits. The accepted cap SHALL NOT exceed the request or either peer's limit. Each sender SHALL enforce it across outbound Session traffic; every Path SHALL retain that negotiation.

#### Scenario: Egress accepts a lower cap

- **WHEN** Ingress requests a replication cap above the Egress accepted limit
- **THEN** `SESSION_ATTACH_OK` returns the lower effective cap and both endpoints enforce it for the Session

#### Scenario: Replication is disabled with a positive configured budget

- **WHEN** the Egress policy sets `retransmissionReplication: disabled` and a positive `sessionReplicationBudgetBps`
- **THEN** Ingress requests zero, Egress accepts zero, and neither sender emits optional business or control copies while primary traffic, necessary control, and ordinary reliable retransmission remain available

#### Scenario: A later Path joins the Session

- **WHEN** another Path attaches after flows have consumed replication allowance
- **THEN** it uses the Session's captured request and effective cap without replacing the policy, broadening the cap, or resetting accounting
