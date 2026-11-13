# PathChord wire profile v1

**English** | [简体中文](wire-profile.zh-CN.md)

This document is the interoperable wire contract for wire-profile-v1. The
profile uses protocol version 1. A peer that presents any protocol version
other than 1 MUST reject the Path before PATH_READY.

The [protocol specification](protocol.md) defines the behavioral model. This
document defines the bytes, registries, limits, and failure handling needed to
implement that model.

## Abstract

This document defines the canonical `wire-profile-v1` representation of a
PathChord record, frame, payload, identifier, capability, and error. It is
intended to make independent implementations byte-for-byte interoperable.

## Status of This Specification

This document is the final v1 wire contract. A conforming implementation MUST
use the registries and layouts here; it MUST NOT substitute an implementation-
specific envelope, field order, numeric code, or extension rule.

## Conventions and Requirements

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHALL**, **SHALL NOT**,
**SHOULD**, **SHOULD NOT**, **RECOMMENDED**, **NOT RECOMMENDED**, **MAY**, and
**OPTIONAL** are to be interpreted as described in
[RFC 2119](https://www.rfc-editor.org/rfc/rfc2119) and
[RFC 8174](https://www.rfc-editor.org/rfc/rfc8174). They have normative force
only when written in uppercase.

## Registry Ownership

The PathChord protocol registry is maintained by the PathChord specification
maintainer. Frame type codes, capability bits, error codes, and profile limits
are assigned only by a new versioned profile. A v1 implementation MUST treat
unassigned codes and bits according to the unknown-value rules in this document.

## Encoding primitives

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

## Noise record envelope

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

## Frame envelope

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
| 32 | STREAM_OPEN | control |
| 33 | STREAM_OPEN_OK | control |
| 34 | STREAM_OPEN_ERR | control |
| 35 | STREAM_DATA | bulk |
| 36 | STREAM_ACK | control |
| 37 | STREAM_WINDOW | control |
| 38 | STREAM_FIN | control |
| 39 | STREAM_RST | control |
| 64 | UDP_OPEN | control |
| 65 | UDP_OPEN_OK | control |
| 66 | UDP_OPEN_ERR | control |
| 67 | UDP_DATAGRAM | bulk |
| 68 | UDP_CLOSE | control |

The v1 capability bitset carried by PATH_HELLO assigns bits as follows:

| Bit | Capability |
|---:|---|
| 0 | TCP_STREAM |
| 1 | UDP_SESSION |
| 2 | MULTIPATH |
| 3 | CONTROL_REPLICATION |
| 4 | ADDRESS_CANDIDATES |
| 5 | EXTENDED_STATUS_REPORT |

Unknown capability bits are ignored. A configured REQUIRED capability that is
absent causes SESSION_ATTACH_REJECT with EGRESS_FAILURE; OPTIONAL capabilities
are the intersection of both peers. All Paths in a Session use the same
negotiated set.

## Profile limits

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

## Identifier and prologue rules

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

## Payload registry

All fields below are encoded in the listed order. bytes(max) means a varint
length followed by exactly that many bytes, bounded by max. id128 is 16 raw
bytes. A decoder rejects missing fields, invalid enum values, invalid address
families, non-canonical ranges, or trailing bytes.

### Path and Session control

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

Ranges are ordered, non-overlapping, and in the Session control sequence
space. A sender retains a control message until its sequence is covered by an
ACK or the Session closes.

### Status report

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

### TCP Stream

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

### UDP Session

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

## Error registry and malformed input

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

## Conformance vectors

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

## Security Considerations

The record nonce is explicit and authenticated through the frame sequence. A
sender MUST NOT reuse a nonce with a different plaintext under the same
directional key. A receiver MUST authenticate a record before committing replay
state, and MUST bound every allocation by the profile limits. Implementations
MUST zeroize provider-owned key material, MUST use independent transport state
per Path, and MUST reject a prologue or authorization mismatch before
`PATH_READY`.

## IANA Considerations

This document has no IANA actions. The PathChord maintainer owns the private
registries in this profile; new assignments require a new versioned profile and
an explicit update to the conformance vectors.

