# Phase 1 provisional wire contract

This progress document freezes the payload contract used by the Phase 1
single-path fixture. It supplements the final-state
[protocol specification](../spec/protocol.md) with the temporary boundaries of
the implemented slice. The numeric frame codes are deterministic within Phase 1
but remain provisional until a compatibility registry is published. In
particular, the fixture-specific EgressID prologue is not a final registry
entry; see [implementation status](status.md#known-implementation-constraints).

## Common encoding

All multi-byte fixed-width integers use network byte order. Unsigned integers
use the canonical QUIC-style 62-bit varint already implemented by
`pathchord-core`. A varint MUST use the shortest representation.

Strings are UTF-8 with a varint byte length followed by exactly that many bytes.
An empty string is invalid for identifiers and hostnames unless a field below
explicitly marks it optional. Byte strings use the same length prefix. A field
whose length is known MUST be checked against the negotiated and hard limits
before allocation.

The common frame header is:

```text
version        varint
type           varint
flags          varint
session_id     16 bytes, big-endian identifier
path_id        16 bytes, big-endian identifier
frame_seq      varint, 0 <= value <= 2^62 - 1
payload_len    varint
payload        exactly payload_len bytes
```

Phase 1 uses the following existing `FrameType` codes:

```text
1   PATH_HELLO              2   SESSION_ATTACH
3   SESSION_ATTACH_OK       4   SESSION_ATTACH_REJECT
5   PATH_READY              6   PATH_DRAIN
7   PATH_CLOSE              8   SESSION_CLOSE
9   STATUS_REPORT          10   HEARTBEAT
11  CONTROL_ACK
32  STREAM_OPEN            33   STREAM_OPEN_OK
34  STREAM_OPEN_ERR         35   STREAM_DATA
36  STREAM_ACK              37   STREAM_WINDOW
38  STREAM_FIN              39   STREAM_RST
64  UDP_OPEN                65   UDP_OPEN_OK
66  UDP_OPEN_ERR            67   UDP_DATAGRAM
68  UDP_CLOSE
```

The Phase 0 codec rejects unknown frame types and malformed lengths before
payload allocation. A Phase 1 peer MUST close the Path on an unknown mandatory
type, unsupported version, non-canonical varint, malformed length, or payload
that exceeds the negotiated limit.

## Identifier fixtures

SessionID, PathID, and RequestID are 16 random bytes and are encoded in network
byte order. StreamID and frame sequence values are canonical 62-bit varints.
Ingress allocates StreamIDs monotonically in Phase 1; Egress does not initiate
business Streams.

The Phase 1 EgressID fixture uses an ASCII-compatible identifier grammar:

```text
[A-Za-z0-9][A-Za-z0-9._-]{0,127}
```

The canonical EgressID prologue bytes are the UTF-8 bytes of the identifier
exactly as configured, prefixed by the ASCII domain separator:

```text
PathChord/phase1/egress/ + egress_id_utf8
```

No Unicode normalization, case folding, or trailing NUL is applied. This is a
Phase 1 interoperability fixture, not the final public identifier registry.
IngressID uses the same grammar and length-prefixed UTF-8 representation in
`SESSION_ATTACH`. The authenticated Noise initiator key is mapped to the
authorized IngressID before the attach is accepted.

## Payload field rules

The following payloads use ordered fields. Phase 1 does not use arbitrary maps
inside data frames. Future optional fields require a new capability and a
length-delimited extension section; an implementation MUST NOT silently infer
missing required fields.

### PATH_HELLO

```text
version                varint
capabilities           varint bitset
path_id                16 bytes
transport_metadata     length-prefixed bytes
```

The header PathID and payload PathID MUST match. Transport metadata is opaque to
the core codec and is limited by the control-payload limit. EgressID is carried
in `SESSION_ATTACH`, not in this payload. Capability bit assignments are
experimental in Phase 1.

### SESSION_ATTACH

```text
ingress_id             string
session_id             16 bytes
egress_id              string
control_seqno          varint
```

The payload SessionID and header SessionID MUST match. Egress verifies the
IngressID against the authenticated Noise static key, and verifies EgressID
against its own configured identity. The first attach for a Session creates the
Session; a later Path may attach only to the same Ingress/Egress pair.

### SESSION_ATTACH_OK

```text
authorization_generation  varint
```

The generation identifies the authorization snapshot used for the decision.
Capability and limit negotiation is represented by `PATH_HELLO` and
`PATH_READY` in the current Phase 1 core; a future revision may add explicit
selected-capability fields here.

### SESSION_ATTACH_REJECT

```text
error_class            u8
reason                 length-prefixed bytes
```

`error_class` uses the experimental `ErrorClass` values from `pathchord-core`.
The reason is diagnostic only and MUST NOT be used for branching.

### PATH_READY

```text
max_frame_payload         varint
max_control_payload       varint
max_session_buffering     varint
```

Only after this frame is accepted may business frames be sent. Each limit MUST
be positive and MUST NOT exceed the Phase 0 hard limit. The current core keeps
the Stream reorder limit at its local Phase 0 default rather than encoding it
in this payload.

### STATUS_REPORT

```text
connected                  u8, 0 or 1
active_streams             varint
active_target_connections  varint
capacity_bps               varint
```

Phase 1 uses the report for observability and admission checks only. It does not
automatically add or remove Paths. UDP association counts and recommended Path
counts are deferred fields.

### HEARTBEAT

```text
control_seq               varint
```

Heartbeats carry the sender's control sequence in the current core schema.

### CONTROL_ACK

```text
highest_contiguous       varint
range_count              varint
ranges                   repeated inclusive [start, end] varint pairs
```

Ranges MUST be ordered, non-overlapping, and within the sender's sequence space.
A sender may discard a retained control frame only after its sequence is covered
by the peer ACK. Sender-role tagging is a Session-layer association in this
single-path fixture and is not encoded in the current payload.

### SESSION_CLOSE

The current core payload is:

```text
error_class               u8
reason                    length-prefixed bytes
```

`SESSION_CLOSE` is final for the SessionID and prevents new Streams. `PATH_DRAIN`
and `PATH_CLOSE` remain registry entries without Phase 1 payload codecs; the
single-path implementation closes the Path through the Session/transport owner.

## TCP Stream payloads

### STREAM_OPEN

```text
stream_id                 varint
request_id                16 bytes
hostname                  length-prefixed bytes
port                      u16, big-endian
resolved_address_count    varint, maximum 16
resolved_addresses        repeated address values
```

An endpoint candidate is:

```text
address_family            u8 (IPv4=1, IPv6=2)
address_bytes             4 or 16 bytes
```

Hostname bytes are UTF-8 when non-empty and may be empty when resolved
candidates are supplied. Port zero is invalid. The original hostname is
retained by Egress even when candidates are supplied. Each address value is:

```text
address_family            u8 (4=IPv4, 6=IPv6)
address_bytes             4 or 16 bytes
```

RequestID idempotency is scoped to `(SessionID, RequestID)`.

### STREAM_OPEN_OK

```text
stream_id                 varint
result_metadata           length-prefixed bytes
```

Result metadata is opaque to the Phase 1 core codec and is limited by the
control-payload limit. It does not replace the original hostname in the request
cache.

### STREAM_OPEN_ERR

```text
stream_id                 varint
error_class               u8
reason                    length-prefixed bytes
```

### STREAM_DATA

```text
stream_id                 varint
offset                    varint
flags                     varint
data                      length-prefixed bytes
```

`offset + data_len` MUST not overflow the implementation's 62-bit stream
offset. A FIN flag is ordered after all preceding bytes. RST discards pending
data and terminates the target connection.

### STREAM_ACK

```text
stream_id                 varint
ranges                    count varint, maximum 256
                          repeated inclusive [start, end] varint pairs
```

Ranges MUST be valid inclusive `AckRange` values and are limited to 256 items.
The current payload does not encode a direction; direction is associated with
the Session/Stream sender role in Phase 1.

### STREAM_WINDOW

```text
stream_id                 varint
stream_receive_limit      varint
session_receive_limit     varint
```

The limits are absolute received-byte offsets, not increments. A sender MUST
apply backpressure when either limit is reached.

### STREAM_FIN and STREAM_RST

`STREAM_FIN` contains `stream_id` and a flags varint. `STREAM_RST` contains
`stream_id`, an error class byte, and a length-prefixed reason. FIN is ordered;
RST is terminal and may arrive before all pending data.

## UDP payloads

UDP frame types are part of the Phase 1 registry, but the current core message
codec intentionally returns `UnsupportedFrameType` for `UDP_OPEN`,
`UDP_OPEN_OK`, `UDP_OPEN_ERR`, `UDP_DATAGRAM`, and `UDP_CLOSE`. The UDP payload
schema below is the next implementation slice and MUST be added before UDP
acceptance criteria are enabled.

### UDP_OPEN

```text
association_id          varint
target_flags             varint (hostname=1, candidates=2)
hostname                 string, present when hostname flag is set
candidate_count          varint
candidates               repeated endpoint values
port                     u16, big-endian
```

`UDP_OPEN_OK` returns the association ID and a target-visible port. `UDP_OPEN_ERR`
uses the same error fields as `STREAM_OPEN_ERR`.

### UDP_DATAGRAM and UDP_CLOSE

```text
association_id          varint
datagram_seq             varint
payload_len              varint
payload                  exactly payload_len bytes
```

`UDP_CLOSE` contains only the association ID. Datagram sequence values are for
diagnostics and optional duplicate suppression; they do not cause aggregation-
layer retransmission.

## Error mapping

Error classes are the Phase 1 stable categories; numeric subcodes below are
reserved fixture values. The current core payload codec carries the class byte
and a reason only; subcode fields are deferred until the Session error layer is
implemented.

```text
class          code  meaning
LOCAL_POLICY   1     rule or listener rejection
LOCAL_POLICY   2     local resource limit
LOCAL_POLICY   3     capability mismatch
PATH_FAILURE   1     malformed frame or record
PATH_FAILURE   2     authentication failure
PATH_FAILURE   3     replay or stale record
PATH_FAILURE   4     Transit transport failure
EGRESS_FAILURE 1     Session closed or unavailable
EGRESS_FAILURE 2     authorization denied or revoked
EGRESS_FAILURE 3     endpoint restart
EGRESS_FAILURE 4     Egress resource limit
TARGET_FAILURE 1     DNS failure
TARGET_FAILURE 2     target connect failure
TARGET_FAILURE 3     target reset or timeout
```

The receiver MUST close a Path for malformed or unauthenticated records. It
MUST NOT translate a target FIN/RST into PATH_FAILURE. A missing compliant Path
for a Stream is an EGRESS_FAILURE to the local connection; a target dial error
is TARGET_FAILURE.

## Phase 0 implementation limits

The following hard limits are inherited from `pathchord-core`:

```text
frame payload             63 KiB
control payload            4 KiB
target hostname           255 bytes
Stream reorder buffer      4 MiB
Session buffer             32 MiB
Noise replay window        64 records
```

The Noise Phase 0 envelope is `u64_be nonce + u16_be ciphertext length +
ciphertext`. `NoiseTransport::seal_frame` requires the owned outbound nonce to
equal `PathFrame.header.frame_seq`. `open_encoded_frame` authenticates, decodes,
checks the same equality, and only then commits replay-window state. A sender
retains the sealed record for retransmission; it does not encrypt a different
plaintext under a reused nonce.
