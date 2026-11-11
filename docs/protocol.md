# PathChord Protocol Design

## 1. Cryptography

Use `Noise_IK_25519_ChaChaPoly_SHA256` through a mature implementation.

- Ingress and Egress each have a static Curve25519 key pair.
- The Egress public key is static Ingress configuration.
- Egress stores the authorized Ingress public-key list; enrollment changes this list dynamically.
- Every Path performs its own Noise handshake and receives independent transport keys.
- Do not reuse WireGuard private keys for PathChord.
- No X.509 CA, PGP, TOFU, or automatic first-use trust is required.

## 2. Protocol layers

```text
Ingress adapter / local socket
        |
Flow and policy layer
        |
Session / Stream layer
        |
Path framing and scheduling
        |
Noise transport per Path
        |
Transit Proxy transport
```

## 3. Identity and attachment

Conceptual identifiers:

```text
IngressID
EgressID
SessionID
PathID
StreamID
RequestID
```

A new Path authenticates with Noise, negotiates protocol version and capabilities, then sends a session-attach request. Egress binds the Path to the authenticated Ingress identity and the selected Egress Session. A Path cannot join a Session owned by another identity.

## 4. Control messages

The protocol needs at least:

```text
VERSION_NEGOTIATE
SESSION_ATTACH
SESSION_ATTACH_OK
EGRESS_STATUS
PATH_PROBE
PATH_PROBE_ACK
PATH_DRAIN
PATH_CLOSE
STREAM_OPEN
STREAM_OPEN_ACK
STREAM_FIN
STREAM_RST
STREAM_DATA
STREAM_ACK
STREAM_WINDOW
SESSION_CLOSE
ERROR
```

Control traffic has reserved capacity. A Session requires at least one active Path; loss of the last Path terminates the Session. Status reports, heartbeats, and Session control messages use the currently available Paths, with a Session control sequence number for duplicate suppression. Control messages may optionally carry a dependency sequence number when execution order matters. Any available Path may carry any control or data exchange.

Control messages are replicated across multiple currently available Paths by default. The receiver applies each `control_seqno` at most once, so replication is safe. `CONTROL_ACK` reports the highest contiguous applied sequence and optional selective ranges. The sender retains unacknowledged control messages and retransmits them until acknowledged or until the Session closes.

## 5. TCP Streams

A Stream represents one target TCP connection inside exactly one Ingress-to-Egress Session. Data is framed with a Stream offset and can be split across multiple bidirectional Paths. Frames may arrive out of order; the receiver reorders them by offset before writing contiguous bytes to the target connection. A Stream may migrate between Paths without changing its identity or target connection.

Required semantics:

- ordered byte delivery;
- half-close in each direction;
- target FIN/RST propagation;
- per-Stream and Session flow control;
- ACK ranges and duplicate suppression;
- cross-Path retransmission for unacknowledged data; retransmission may use any currently compliant Path. Replication of retransmissions is policy-controlled per traffic class and may be enabled or disabled by the Egress default policy;
- bounded reordering buffers;
- backpressure instead of silently dropping TCP bytes.

A connect request carries a unique RequestID. Retrying the request on another Path must be idempotent at Egress so an uncertain response cannot create a second target connection. `STREAM_OPEN` carries the original hostname when available and may also carry resolved address candidates; Egress applies its configured DNS policy. If the Session is gone and the result is uncertain, fail the local connection and let the application retry.

## 6. UDP sessions

A UDP session is bound to one Egress and one Egress-side socket context. TCP and UDP are both independent of Path identity. Path migration does not recreate or rebind the Egress-side socket, so the target-visible address and port remain unchanged.

UDP preserves datagram boundaries. Ordinary application datagrams are not retransmitted by the aggregation layer and may be dropped when expired or over budget. Control messages remain reliable. If a reliable byte-stream transport carries the Path, its own head-of-line behavior is accepted as an implementation limitation.

## 7. Path scheduling

Ingress owns Path creation and admission. Path state is transparent to Streams and UDP sessions, so adding or removing a Path does not require overlay stream or socket-state synchronization. Each Path owns its congestion control and flow-control window and reports available capacity, quality, and scheduling state to the Session scheduler. Ingress schedules upstream data; Egress schedules downstream data over any existing compliant Paths.

Per-Path scheduling uses configured relationship weight plus observed effective capacity. Multiple Paths through one Transit Proxy share the Proxy-to-Egress relationship weight.

## 8. Versioning

Session creation negotiates protocol version and capabilities. Required capability mismatch rejects the Egress from the effective rule set. Optional capabilities are selected by intersection. All Paths in one Session use the same Session semantics.

## 9. Frame format and numbering

Each encrypted Path record contains one Path frame. Noise provides confidentiality and integrity; the frame header is authenticated as associated data and is not independently encrypted unless required by the selected transport framing.

The common frame header contains:

```text
version        protocol version
type           frame type
flags          frame-specific flags
session_id     logical Session identifier
path_id        sending Path identifier
frame_seq      monotonically increasing sequence on this Path
payload_len    payload length
```

`session_id` identifies the Ingress-to-Egress logical channel. `path_id` identifies only the physical Path and has no meaning to Streams. `frame_seq` is used for Path-level duplicate detection, diagnostics, and loss accounting; it is not a Stream byte offset. SessionID and PathID are 128-bit random values; RequestID is a 128-bit random value; StreamID is a 62-bit locally allocated value and is never reused within a Session.

TCP and other reliable byte streams use a separate data header:

```text
stream_id      Stream identifier within the Session
direction      Ingress-to-Egress or Egress-to-Ingress
offset         first byte offset in this frame
data_len       number of bytes represented by the frame
stream_flags   FIN, RST, or half-close flags
```

ACK frames carry one or more inclusive offset ranges for a `(stream_id, direction)` pair. A receiver may acknowledge ranges out of order. Duplicate ranges are harmless and may be repeated on multiple Paths.

Retransmission does not allocate a new Stream offset. A retransmitted frame carries the same Stream range and may use a different `path_id`; replicated copies are deduplicated by the Stream range.

Session control frames use a Session-wide `control_seqno`. A control frame may include an optional `depends_on` sequence number. Receivers discard an already applied sequence number, and defer a frame whose dependency has not been applied. Control frames are idempotent wherever possible.

Path management frames use a Path-local management sequence and are valid only for the Path that carries them. A Path management failure cannot invalidate Stream state while another Path remains available.

Flow-control frames report independent limits for Stream, Session, and Path scopes. Path-level limits are generated by the Path congestion controller; Session scheduling treats them as current admissible capacity and does not modify them directly.

## 10. Control message sequence

After the Noise handshake, a Path performs the following exchange:

1. `PATH_HELLO`: protocol version, capabilities, Path identity, and transport metadata.
2. `SESSION_ATTACH`: Ingress identity, Session identity, selected Egress identity, and current control sequence.
3. `SESSION_ATTACH_OK` or `SESSION_ATTACH_REJECT`.
4. `PATH_READY`: Path-level limits, observed address-family support, and initial scheduler report.

Only `PATH_READY` Paths can carry business traffic. A new Path joining an existing Session does not replay Stream state. It receives the current Session policy snapshot and can immediately carry newly scheduled frames.

Path lifecycle messages are:

```text
PATH_HELLO
SESSION_ATTACH
SESSION_ATTACH_OK
SESSION_ATTACH_REJECT
PATH_READY
PATH_DRAIN       stop admitting new data, finish acknowledged work
PATH_CLOSE       close this Path
SESSION_CLOSE    close the Session and all related Streams
STATUS_REPORT    Egress capacity and health report
HEARTBEAT        liveness and control sequence exchange
CONTROL_ACK      applied control sequence and selective ranges
```

`PATH_DRAIN` is advisory and may be interrupted by an urgent failure. `PATH_CLOSE` is final for that Path. `SESSION_CLOSE` is final for the Session; a new Session is required after the last Path disappears or either endpoint restarts.

## 11. TCP Stream messages

```text
STREAM_OPEN      stream_id, target endpoint, transport options
STREAM_OPEN_OK   stream_id, target result metadata
STREAM_OPEN_ERR  stream_id, normalized error code
STREAM_DATA      stream_id, offset, bytes, stream flags
STREAM_ACK       stream_id, direction, ACK ranges
STREAM_WINDOW    stream/session receive limits
STREAM_FIN       half-close one direction
STREAM_RST       abort the Stream with error code
```

`STREAM_OPEN` contains a unique RequestID. Retries with the same RequestID are idempotent at Egress. `STREAM_DATA` may be split across any number of Paths and may be sent concurrently for non-overlapping offsets. `STREAM_FIN` is ordered after all preceding bytes in its direction; `STREAM_RST` discards pending data and closes the target-side connection.

## 12. UDP messages

```text
UDP_OPEN         association identifier, target endpoint, options
UDP_OPEN_OK       association metadata
UDP_OPEN_ERR      normalized error code
UDP_DATAGRAM      association identifier, datagram sequence, payload
UDP_CLOSE         close association
```

UDP datagrams preserve boundaries and are independent of Path identity. A datagram may use any available Path, and Path migration does not recreate or rebind the Egress-side socket. Datagram sequence numbers are for diagnostics and optional duplicate suppression; they do not imply reliable retransmission.

## 13. Error model

Errors are classified into four stable classes:

```text
LOCAL_POLICY       rejected by Ingress rules or listener policy
PATH_FAILURE       this Path cannot carry traffic
EGRESS_FAILURE     the Egress or Session is unavailable
TARGET_FAILURE     the Egress-to-target operation failed
```

Target FIN/RST and target connection errors are propagated as target results. A Path failure is not exposed as a target reset while another compliant Path remains available. An Egress or Session failure closes local connections so ordinary applications can retry.

## 14. Wire encoding defaults

The protocol uses a compact binary encoding with the following rules:

- integers use unsigned QUIC-style variable-length encoding;
- fixed-width integers, when required, use network byte order;
- lengths count bytes, not encoded elements;
- strings are UTF-8 and are length-prefixed;
- endpoint addresses use an explicit address-family discriminator;
- unknown optional fields and flags are ignored when their length is safely known;
- unknown mandatory frame types or malformed lengths terminate the Path;
- all length fields are checked before allocation;
- implementations must enforce both per-frame and aggregate Session limits;
- each frame is self-delimiting and cannot consume bytes belonging to the next frame.

Canonical encoding is required for fields used in signatures, hashes, RequestID derivation, or control-message idempotency. Duplicate map keys and non-canonical integer encodings are rejected in those contexts.

Recommended initial limits are:

```text
maximum frame payload       64 KiB
maximum control payload      4 KiB
maximum target name          255 bytes
maximum Stream reordering   configurable, default 4 MiB
maximum Session buffering   configurable, default 32 MiB
```

These are protocol safety defaults, not performance tuning constants. Negotiated values may reduce them, but cannot exceed the implementation's hard limits.

## 15. Protocol invariants

The following invariants are normative:

1. A Session has exactly one Ingress and one Egress.
2. A live Session always has at least one `PATH_READY` Path.
3. A Stream belongs to exactly one Session for its entire lifetime.
4. A Stream offset is never reused for different bytes.
5. A Path failure cannot change a target socket's identity.
6. A target reset or FIN is propagated without being rewritten as a Path error.
7. A duplicate control message cannot execute its side effect twice.
8. A duplicate data range cannot be delivered twice to the target.
9. Session close prevents creation of new Streams.
10. Endpoint restart invalidates all prior Sessions and Paths.

## 16. Path transport abstraction

The PathChord wire format is byte-oriented, but a Path is not required to be reliable. The complete encoded frame is the minimum delivery unit: a Path may lose, duplicate, or reorder whole frames, but it must never expose a partial frame or a frame with modified payload to the protocol core. The Path layer uses `frame_seq` and frame boundaries to detect these conditions; Session-level reliability handles recovery for control messages and reliable Stream data.

Each Path adapter reads and writes a byte stream but presents only complete PathChord frames to the protocol core. A reliable byte-stream upstream such as TCP may preserve ordering internally. An unreliable or datagram-oriented upstream may deliver complete frames, lose frames, duplicate frames, or reorder frames, but must not silently modify a frame payload. The adapter or record decoder performs segmentation and reassembly needed to preserve complete frames; incomplete or damaged frames are discarded before delivery.

This keeps TCP, TLS, WebSocket, VLESS, VMess, XTLS, and future adapters within one framing model while allowing direct use of unreliable transports. Datagram semantics exist only above the framing layer in `UDP_DATAGRAM` messages.

## 17. Enrollment and authorization

Enrollment is an administrative operation performed separately on Ingress and Egress through a trusted local or out-of-band channel. PathChord does not use TOFU, automatic trust discovery, or an online third-party CA.

The enrollment record contains:

```text
IngressID
Ingress static public key
EgressID
Egress static public key
authorization state: enabled | disabled | revoked
optional administrator labels and limits
record generation
```

The Ingress stores the expected Egress public key in its static Egress topology. The Egress stores the authorized Ingress public-key list in its local authorization database or configuration. Both sides must be configured independently before a Path can become `PATH_READY`.

The Noise pattern is `Noise_IK_25519_ChaChaPoly_SHA256`. Each Path performs a fresh handshake and obtains independent transport keys. The handshake authenticates the static keys and binds the resulting Path to the configured IngressID and EgressID. A successful Noise handshake alone is insufficient: the Egress must also find the Ingress static public key in its enabled authorization list.

Authorization changes are generation-based:

- enabling an Ingress key permits new Paths and Sessions;
- disabling or revoking a key prevents new Paths immediately;
- revocation closes all related Paths, Sessions, Streams, and Egress-to-target connections;
- existing authorization state is not silently upgraded after a failed configuration write;
- a changed static key requires the affected endpoint to restart;
- an Egress authorization-list update does not require Ingress restart when only the Egress-side list changes.

The enrollment control API is outside the data Path protocol. It may modify the Egress authorization database or configuration file, but must use atomic generation updates and preserve the previous valid record if validation or persistence fails.

## 18. Local management API

The management API is local-only:

```text
Linux   Unix domain socket
Windows named pipe
```

The `pathchord` CLI is the supported management client. The API authorizes callers through the operating-system ownership and permission model of the socket or pipe. It is not exposed through the Transit Proxy or Egress data Paths.

The running Egress process owns both the management API and the authorization store. The CLI never edits the database or configuration file directly; it submits an operation to Egress, and Egress performs the complete update.

Enrollment operations are transactional:

1. CLI submits an enrollment, disable, revoke, or delete request.
2. Egress validates identifiers, key encoding, duplicate identities, and policy constraints.
3. Egress writes the new authorization generation atomically to its database or configuration store.
4. Egress replaces its in-memory authorization snapshot without restarting.
5. Egress applies revocation or disable effects to live Paths and Sessions.
6. The API returns the applied generation and effective state.

If persistence succeeds but the in-memory update fails, Egress must roll back the persistent generation where possible; otherwise it reports the generation as `pending_apply`, rejects further mutations, and exposes the mismatch through status. If validation or persistence fails, no generation change is published.

Authorization changes that revoke or disable an Ingress are applied to new handshakes immediately and then terminate all matching live Paths and Sessions according to the revocation rules.
