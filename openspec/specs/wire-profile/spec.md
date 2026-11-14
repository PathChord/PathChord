# PathChord wire profile v1

**English** | [简体中文](spec.zh-CN.md)

## Purpose

Define the byte-exact `wire-profile-v1` record and frame envelopes, payload registries, identifiers, capabilities, limits, errors, and deterministic conformance vectors needed for independent interoperability.

## Requirements

### Requirement: Complete canonical wire contract

A v1 implementation SHALL satisfy every layout, registry, limit, failure rule, and conformance-vector obligation in the [detailed contract](#detailed-contract). It SHALL NOT replace registered bytes, field order, numeric codes, or extension rules with an implementation-specific alternative.

#### Scenario: Deterministic vector round trip

- **WHEN** an implementation encodes and decodes a published v1 conformance vector
- **THEN** both operations reproduce the exact canonical bytes, including the specified Noise compatibility vector

### Requirement: Canonical bounded decoding

Decoders SHALL enforce shortest-form QUIC-style varints, complete payload consumption, registered flags and mandatory frame types, negotiated limits, and profile hard caps before allocation. Malformed frames SHALL produce the specified protocol error and close the Path.

#### Scenario: Unknown flag or trailing bytes

- **WHEN** a decrypted frame has a non-zero unknown flag or bytes beyond its canonical payload
- **THEN** the receiver discards the frame, emits a diagnostic event, and closes the Path

#### Scenario: Negotiated limit exceeds hard cap

- **WHEN** a peer proposes a `PATH_READY` limit above the profile hard cap
- **THEN** the limit is rejected rather than increasing the decoder's allocation allowance

### Requirement: Independent authenticated nonce and replay state

Each directional Path transport SHALL use the explicit nonce envelope, bind `frame_seq` to that nonce, and apply the 64-record replay window only after authentication. Different plaintexts SHALL NOT reuse a directional key/nonce pair; malformed or unauthenticated records SHALL NOT advance replay state. Key material SHALL be zeroized as required by the detailed contract.

#### Scenario: Authenticated record is duplicated

- **WHEN** an authenticated record nonce is duplicate or stale in its directional replay window
- **THEN** the record is discarded before Session processing without applying its payload again

#### Scenario: Nonce and frame sequence disagree

- **WHEN** the decrypted `frame_seq` disagrees with the record nonce
- **THEN** the record does not advance the replay window and the malformed-frame rules apply

### Requirement: Profile identity and capability negotiation

Peers SHALL use protocol version 1, the exact configured EgressID prologue, and one negotiated capability set across a Session. Unknown capability bits SHALL be ignored; an absent configured REQUIRED capability SHALL reject attachment with `EGRESS_FAILURE`.

#### Scenario: Required capability is absent

- **WHEN** the peer's capability set omits a configured REQUIRED capability
- **THEN** the attachment is rejected with `SESSION_ATTACH_REJECT` and `EGRESS_FAILURE`

#### Scenario: Unsupported version is presented

- **WHEN** a peer presents a protocol version other than 1
- **THEN** the Path is rejected before `PATH_READY`

### Requirement: Ordered Session control envelopes

Session control SHALL use the registered envelope, per-sender sequence space, dependency ordering, eligible Path list, acknowledgement rules, and idempotent cancellation encoding. Replicated copies SHALL preserve their control sequence and payload while using new Path frame sequences and Noise nonces.

#### Scenario: Control operation is replicated

- **WHEN** copies of one `SESSION_CONTROL` operation arrive over multiple eligible Paths
- **THEN** the receiver applies its control sequence once, after its dependency, and acknowledges it through the Session control sequence space

### Requirement: Typed Stream and UDP payload semantics

Stream and UDP payloads SHALL use the registered field order, target forms, address families, range and offset bounds, and error classes. Stream direction SHALL derive from the authenticated endpoint role; the payload SHALL NOT supply a second conflicting direction field. UDP payloads SHALL retain datagram boundaries without aggregation-layer application retransmission.

#### Scenario: Stream acknowledgement direction is inferred

- **WHEN** a peer sends `STREAM_ACK` on an authenticated Path
- **THEN** its ranges acknowledge bytes received from the peer, in the direction opposite to the authenticated sender direction

### Requirement: Sequenced and fresh status reports

`STATUS_REPORT` SHALL include the complete v1 schema, consistent connection/service state, bounded basis-point ratios, sequencing, and freshness fields. Receivers SHALL ignore duplicate or older report sequences and SHALL prevent stale reports from admitting new flows or triggering scale-in.

#### Scenario: Status sample is stale

- **WHEN** `sample_age_ms` exceeds `expires_after_ms`
- **THEN** Ingress treats the report as stale and does not use it to admit a new flow or trigger scale-in

## Detailed contract

This document is the interoperable wire contract for wire-profile-v1. The
profile uses protocol version 1. A peer that presents any protocol version
other than 1 MUST reject the Path before PATH_READY.

The [protocol specification](../protocol/spec.md) defines the behavioral model. This
document defines the bytes, registries, limits, and failure handling needed to
implement that model.

### Abstract

This document defines the canonical `wire-profile-v1` representation of a
PathChord record, frame, payload, identifier, capability, and error. It is
intended to make independent implementations byte-for-byte interoperable.

### Status of This Specification

This document is the final v1 wire contract. A conforming implementation MUST
use the registries and layouts here; it MUST NOT substitute an implementation-
specific envelope, field order, numeric code, or extension rule.

### Conventions and Requirements

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHALL**, **SHALL NOT**,
**SHOULD**, **SHOULD NOT**, **RECOMMENDED**, **NOT RECOMMENDED**, **MAY**, and
**OPTIONAL** are to be interpreted as described in
[RFC 2119](https://www.rfc-editor.org/rfc/rfc2119) and
[RFC 8174](https://www.rfc-editor.org/rfc/rfc8174). They have normative force
only when written in uppercase.

### Registry Ownership

The PathChord protocol registry is maintained by the PathChord specification
maintainer. Frame type codes, capability bits, error codes, and profile limits
are assigned only by a new versioned profile. A v1 implementation MUST treat
unassigned codes and bits according to the unknown-value rules in this document.

### Encoding primitives

- Unsigned integers use the canonical QUIC-style 62-bit variable-length
  integer. The shortest representation is REQUIRED.
- Fixed-width integers use network byte order.
- Lengths count bytes. A length is checked against its profile limit before any
  allocation.
- Strings are UTF-8 bytes preceded by a varint byte length. REQUIRED
  identifiers and hostnames are non-empty.
- A v1 payload has no implicit fields or trailing extension bytes. A decoder
  MUST consume the complete payload. Future fields require a new profile or a
  negotiated, length-delimited extension defined by that profile.

### Noise record envelope

Every Path record contains exactly one encrypted Path frame. The canonical
record envelope is:

~~~text
nonce             8 bytes, unsigned big-endian transport nonce
ciphertext_len    2 bytes, unsigned big-endian length
ciphertext        exactly ciphertext_len bytes
~~~

The ciphertext includes the 16-byte ChaCha20-Poly1305 authentication tag.
ciphertext_len is in 16..=65535; the complete envelope is therefore at most
65545 bytes. The plaintext is the encoded Path frame and is at most 65519
bytes. The nonce is not implicit, and the record envelope has no alternative
clear-header or associated-data layout in v1. A truncated, oversized, or
trailing-byte envelope is rejected before decryption allocation.

The Noise pattern is Noise_IK_25519_ChaChaPoly_SHA256. Each direction owns an
independent nonce sequence beginning at zero after the handshake. A sender MUST
never encrypt two different plaintexts with the same directional key and nonce.
A retransmission of the same sealed record reuses the complete original
envelope. A semantic retransmission MAY create a new frame and nonce while
retaining its control sequence or Stream range identity.

The Noise provider MUST zeroize private-key, DH, and traffic-key buffers,
including resolver-owned state, when those values leave active use. The record
layer MUST NOT share transport cipher state between Paths.

After authentication, a receiver applies a 64-record replay window per
direction. Duplicate or stale nonces are discarded before Session processing.
Authentication failure, a nonce/frame mismatch, or a malformed frame MUST NOT
advance the replay window. Nonce exhaustion closes the Path and requires a new
Noise handshake.

### Frame envelope

The decrypted frame is self-delimiting and has this exact layout:

~~~text
version           varint, exactly 1
frame_type        varint, registered value below
flags             varint, zero in v1
session_id        16 bytes, opaque random identifier
path_id           16 bytes, opaque random identifier
frame_seq         varint, 0..=(2^62 - 1)
payload_len       varint
payload           exactly payload_len bytes
~~~

frame_seq equals the outbound record nonce for the same direction. session_id
and path_id are authenticated by Noise and the frame header. A frame with a
non-zero unknown flag, an unknown mandatory type, a non-canonical varint, a
payload over the applicable limit, or trailing bytes MUST close the Path.

The frame type registry is:

| Code | Frame type | Payload class |
|---:|---|---|
| 1 | PATH_HELLO | control |
| 2 | SESSION_ATTACH | control |
| 3 | SESSION_ATTACH_OK | control |
| 4 | SESSION_ATTACH_REJECT | control |
| 5 | PATH_READY | control |
| 6 | PATH_DRAIN | control |
| 7 | PATH_CLOSE | control |
| 8 | SESSION_CLOSE | control |
| 9 | STATUS_REPORT | control |
| 10 | HEARTBEAT | control |
| 11 | CONTROL_ACK | control |
| 12 | PATH_READY_CAPABILITIES | control |
| 13 | SESSION_CONTROL | control |
| 14 | SESSION_CONTROL_ACK | control |
| 15 | SESSION_CONTROL_CANCEL | control |
| 32 | STREAM_OPEN | control |
| 33 | STREAM_OPEN_OK | control |
| 34 | STREAM_OPEN_ERR | control |
| 35 | STREAM_DATA | bulk |
| 36 | STREAM_ACK | control |
| 37 | STREAM_WINDOW | control |
| 38 | STREAM_FIN | control |
| 39 | STREAM_RST | control |
| 40 | STREAM_OPEN_CLASS | control |
| 64 | UDP_OPEN | control |
| 65 | UDP_OPEN_OK | control |
| 66 | UDP_OPEN_ERR | control |
| 67 | UDP_DATAGRAM | bulk |
| 68 | UDP_CLOSE | control |
| 69 | UDP_OPEN_CLASS | control |

The v1 capability bitset carried by PATH_HELLO assigns bits as follows:

| Bit | Capability |
|---:|---|
| 0 | TCP_STREAM |
| 1 | UDP_SESSION |
| 2 | TRAFFIC_CLASSES |
| 3 | CONTROL_REPLICATION |
| 4 | ADDRESS_CANDIDATES |
| 5 | EXTENDED_STATUS_REPORT |

Unknown capability bits are ignored. A configured REQUIRED capability that is
absent causes SESSION_ATTACH_REJECT with EGRESS_FAILURE; OPTIONAL capabilities
are the intersection of both peers. All Paths in a Session use the same
negotiated set.

### Profile limits

The v1 hard limits and default negotiated values are:

| Name | Value | Applies to |
|---|---:|---|
| max_frame_payload | 64512 bytes | STREAM_DATA and UDP_DATAGRAM payloads |
| max_control_payload | 4096 bytes | all control payloads |
| max_target_name | 255 bytes | hostname and identifier strings |
| max_stream_reordering | 4194304 bytes | one Stream reorder buffer |
| max_session_buffering | 33554432 bytes | one Session aggregate buffer |
| max_endpoint_addresses | 16 | target address candidates |
| max_ack_ranges | 256 | one ACK payload |

Peers MAY negotiate lower frame, control, and Session buffering limits in
PATH_READY; they MUST NOT exceed these values. The control limit MUST NOT
exceed the frame limit, and Stream reordering MUST NOT exceed Session
buffering. Limits are enforced before allocation. A limit violation is a
protocol error and closes the Path; a local resource limit on a valid frame is
handled by the state-machine and flow-control rules rather than silent drop.

### Identifier and prologue rules

SessionID, PathID, and RequestID are 128-bit random values encoded as 16 raw
bytes. StreamID is a locally allocated 62-bit varint and is never reused in a
Session. control_seqno is a Session-scoped monotonically increasing varint and
is never reused in that Session. A new Session uses a new SessionID and a new
control sequence space.

The canonical EgressID grammar is:

~~~text
[A-Za-z0-9][A-Za-z0-9._-]{0,127}
~~~

The Noise prologue is the ASCII bytes
PathChord/wire-v1/egress/, followed by the EgressID UTF-8 bytes exactly as
configured. No Unicode normalization, case folding, or trailing NUL is applied.
Both peers MUST use the same non-empty EgressID and profile string.

### Payload registry

All fields below are encoded in the listed order. bytes(max) means a varint
length followed by exactly that many bytes, bounded by max. id128 is 16 raw
bytes. A decoder rejects missing fields, invalid enum values, invalid address
families, non-canonical ranges, or trailing bytes.

#### Path and Session control

PATH_HELLO:

~~~text
version              varint, exactly 1
capabilities         varint bitset
path_id              id128; MUST equal the frame header PathID
transport_metadata   bytes(max_control_payload)
~~~

SESSION_ATTACH:

~~~text
ingress_id           bytes(max_target_name), non-empty UTF-8
session_id           id128; MUST equal the frame header SessionID
egress_id            bytes(max_target_name), non-empty UTF-8
control_seqno        varint
~~~

SESSION_ATTACH_OK:

~~~text
authorization_generation  varint
~~~

SESSION_ATTACH_REJECT:

~~~text
error_class          u8, error registry below
reason               bytes(max_control_payload), diagnostic only
~~~

PATH_READY:

~~~text
max_frame_payload        varint
max_control_payload      varint
max_session_buffering    varint
~~~

Each value is positive and no greater than the profile limit. PATH_READY is the
first state in which business frames are permitted.

PATH_READY_CAPABILITIES extends PATH_READY with one capability bitset:

~~~text
max_frame_payload        varint
max_control_payload      varint
max_session_buffering    varint
capabilities             varint bitset
~~~

When `TRAFFIC_CLASSES` is negotiated, `STREAM_OPEN_CLASS` and `UDP_OPEN_CLASS`
carry the legacy open payload followed by:

~~~text
class_name               bytes(256), non-empty UTF-8
class_priority           varint, 0..=255
class_share              varint, 1..=1000000
~~~

PATH_DRAIN:

~~~text
drain_reason          varint (0=scale_in, 1=administrative, 2=transport)
deadline_ms           varint (0 means no deadline)
~~~

PATH_CLOSE:

~~~text
error_class           u8
reason                bytes(max_control_payload), diagnostic only
~~~

SESSION_CLOSE has the same two fields as PATH_CLOSE. It is final for the
SessionID.

HEARTBEAT:

~~~text
control_seqno         varint
~~~

CONTROL_ACK:

~~~text
highest_contiguous   varint
range_count          varint, at most max_ack_ranges
ranges               repeated inclusive [start, end] varint pairs
~~~

`CONTROL_ACK` acknowledges the Path-local `HEARTBEAT` sequence on the same
Path. Its ranges are ordered and non-overlapping.

SESSION_CONTROL carries one Session-scoped operation:

~~~text
control_seqno         varint
dependency_present    varint (0 or 1)
depends_on            varint, present only when dependency_present = 1
inner_frame_type      varint
eligible_path_count   varint, 0..=256
eligible_paths        repeated PathID, sorted and unique
inner_payload         bytes(max_control_payload)
~~~

`inner_frame_type` is one of SESSION_CLOSE, STREAM_OPEN, STREAM_OPEN_CLASS,
STREAM_OPEN_OK, STREAM_OPEN_ERR, STREAM_ACK, STREAM_WINDOW, STREAM_FIN,
STREAM_RST, UDP_OPEN, UDP_OPEN_CLASS, UDP_OPEN_OK, UDP_OPEN_ERR, or UDP_CLOSE.
`inner_payload` is its canonical payload without a frame header. The complete
SESSION_CONTROL payload, including this envelope, is bounded by
`max_control_payload`. A dependency MUST be less than the control sequence.
Only STREAM_OPEN, STREAM_OPEN_CLASS, UDP_OPEN, and UDP_OPEN_CLASS may carry a
non-empty eligible Path list. An empty list means no explicit Path restriction;
otherwise the Path carrying the opening operation MUST be in the list. The
Egress applies the list to both directions of that flow. A listed Path must
still have been independently admitted to the same Session before it is used.
Each sender has an independent Session-wide control sequence starting at zero.
The receiver applies operations in sequence order and discards duplicates;
an operation is not applied before its dependency. The sender retains and
retransmits the operation until acknowledged. Copies on other eligible Paths
use new Path frame sequences and Noise nonces, while preserving the control
sequence and payload. Path HELLO, attach, readiness, DRAIN, CLOSE, STATUS_REPORT,
HEARTBEAT, and CONTROL_ACK remain Path-local and are never wrapped.

SESSION_CONTROL_ACK has the same payload encoding as CONTROL_ACK, but ranges
refer to the authenticated sender's peer direction and Session control sequence
space. `highest_contiguous` acknowledges all sequences through that value;
selective ranges are optional. A receiver does not send an ACK before it has
applied at least sequence 0. ACKs are sent on a Path on which a copy arrived.
Closing a Session retains the receiver long enough to acknowledge a retried
SESSION_CLOSE, and the initiating endpoint closes after receiving its ACK or
losing the Session transport.

If a flow loses all its eligible Paths, SESSION_CONTROL_CANCEL may replace an
unacknowledged operation for that flow at the same control sequence. It may also
use a new sequence when no operation for that flow remains unacknowledged:

~~~text
control_seqno         varint
flow_kind             varint (0=TCP Stream, 1=UDP Association)
flow_id               varint
~~~

It contains only the Session-local opaque flow ID, never a target, credentials,
or business bytes, and may travel on any ready authenticated Path of that
Session. A receiver processes the cancellation in the same sequence space,
replacing a queued operation of the same sequence and flow. If the original
operation was already applied, cancellation tears down that flow. Duplicates
are idempotent; ACKs cover canceled sequences just as for other operations.

#### Status report

STATUS_REPORT is an authenticated Egress-to-Ingress health sample. Its v1
payload is:

~~~text
connected                    u8 (0 or 1)
service_state                u8 (0=down, 1=up, 2=degraded, 3=draining)
load_basis_points            u16, 0..=10000
connection_utilization_bp    u16, 0..=10000
bandwidth_utilization_bp     u16, 0..=10000
active_sessions              varint
active_streams               varint
active_target_connections    varint
capacity_bps                 varint
recommended_path_count       varint
report_seqno                 varint
sample_age_ms                varint
expires_after_ms             varint, positive
~~~

`connected` MUST be equivalent to `service_state != down`: `connected=0` iff
`service_state=down`, and every other service state MUST use `connected=1`.
Ratios are basis points, not floating-point values. Ingress treats a report as
stale when sample_age_ms > expires_after_ms; stale reports cannot admit a new
flow or trigger scale-in. Reports are applied in report_seqno order and
duplicate or older reports are ignored. A status payload that omits the v1
service state, utilization, sequencing, and freshness fields is not a v1
payload and is not interoperable with this profile.

#### TCP Stream

STREAM_OPEN:

~~~text
request_id                 id128
stream_id                  varint
hostname                   bytes(max_target_name), MAY be empty
port                       u16, 1..=65535
resolved_address_count     varint, at most max_endpoint_addresses
resolved_addresses         repeated endpoint values
~~~

At least a hostname or one address candidate is REQUIRED. An endpoint value is
address_family u8 (4 or 6) followed by 4 or 16 address bytes.

STREAM_OPEN_OK is stream_id followed by result_metadata.
STREAM_OPEN_ERR is stream_id, error_class, and reason.

STREAM_DATA:

~~~text
stream_id              varint
offset                 varint
stream_flags           varint (FIN=1, RST=2; other bits reserved)
data                   bytes(max_frame_payload)
~~~

offset + data length MUST NOT exceed the 62-bit Stream offset space. FIN is
ordered after preceding bytes; RST discards pending bytes and closes the target
connection.

The direction of STREAM_DATA, STREAM_FIN, STREAM_RST, and STREAM_WINDOW is the
authenticated sender direction of the Path and is not duplicated in the
payload. STREAM_ACK is stream_id, range_count, and ordered inclusive offset
ranges for bytes received from the peer; its direction is therefore the
opposite of the authenticated sender direction. Implementations MUST derive
direction from the authenticated endpoint role and MUST NOT accept a second,
conflicting direction field.
STREAM_WINDOW is stream_id, absolute stream_receive_limit, and absolute
session_receive_limit. STREAM_FIN is stream_id and stream_flags. STREAM_RST is
stream_id, error_class, and reason.

#### UDP Session

UDP_OPEN:

~~~text
association_id           varint
target_flags             varint (HOSTNAME=1, CANDIDATES=2)
hostname                 bytes(max_target_name), present when HOSTNAME set
port                     u16, 1..=65535
candidate_count          varint, at most max_endpoint_addresses
candidates               repeated endpoint values
~~~

The flags and fields MUST agree, and at least one target form is REQUIRED.
UDP_OPEN_OK is association_id and target_visible_port (u16, non-zero).
UDP_OPEN_ERR is association_id, error_class, and reason.

UDP_DATAGRAM is association_id, datagram_seq (varint), and payload
(bytes(max_frame_payload)). Datagram boundaries are preserved; the aggregation
layer does not retransmit application datagrams. UDP_CLOSE is association_id,
error_class, and reason.

### Error registry and malformed input

Error classes are stable profile values:

| Code | Name | Use |
|---:|---|---|
| 1 | LOCAL_POLICY | Ingress listener or rule rejection |
| 2 | PATH_FAILURE | This Path cannot carry traffic |
| 3 | EGRESS_FAILURE | Egress or Session unavailable, including authorization/capability rejection |
| 4 | TARGET_FAILURE | Egress-to-target operation failed |

The reason bytes are diagnostic and MUST NOT be used as a branching API. A
malformed frame, unknown mandatory type, unsupported version, invalid error
class, or limit violation is a protocol error: discard the frame, emit a
diagnostic event, and close the Path. A valid STREAM_OPEN or UDP_OPEN that
cannot be admitted returns its corresponding *_ERR frame. TCP flow-control
exhaustion applies backpressure; it never silently drops bytes. UDP over-budget
datagrams MAY expire or be dropped according to policy.

### Conformance vectors

An implementation claiming v1 conformance MUST publish deterministic vectors for
the common frame header, the Noise record envelope, every payload in the
registry, each error class, and the EgressID prologue. Tests MUST cover
truncated input, trailing bytes, non-canonical varints, unknown types and flags,
invalid address families, zero ports, oversized lengths, replay-window
duplicates/stale records, nonce/frame-sequence mismatch, and stale status
reports. A vector is valid only when both encoding and decoding reproduce the
exact bytes.

The canonical IK compatibility vector uses
`Noise_IK_25519_ChaChaPoly_SHA256`, prologue
`PathChord/wire-v1/egress/egress-id`, initiator static private key `01` repeated
32 times, responder static private key `02` repeated 32 times, and initiator
and responder ephemeral private keys `04` and `05` repeated 32 times. Handshake
payloads are empty. The transport plaintext is ASCII
`PathChord transport vector` under initiator-to-responder nonce 7.

```text
message_1 = ac01b2209e86354fb853237b5de0f4fab13c7fcbf433a61c019369617fecf10b5ff672297d0d3ade1dd319d94628c4340bb85d86f62343c56fe841734b841fb6026f297def6e19ed47946e13d165de43d0225e93eb0f307b235dc8a202b3603b
message_2 = 50a61409b1ddd0325e9b16b700e719e9772c07000b1bd7786e907c653d20495dc5e12927491c58f5730f88bf3154bd48
transport_nonce_7 = d8cd46c9df78dbd4bc8cebae020320f9bde5dba394c98104938b74b93ba7c5b808580283263e7b5df5ac
```

### Security Considerations

The record nonce is explicit and authenticated through the frame sequence. A
sender MUST NOT reuse a nonce with a different plaintext under the same
directional key. A receiver MUST authenticate a record before committing replay
state, and MUST bound every allocation by the profile limits. Implementations
MUST zeroize provider-owned key material, MUST use independent transport state
per Path, and MUST reject a prologue or authorization mismatch before
`PATH_READY`.

### IANA Considerations

This document has no IANA actions. The PathChord maintainer owns the private
registries in this profile; new assignments require a new versioned profile and
an explicit update to the conformance vectors.

