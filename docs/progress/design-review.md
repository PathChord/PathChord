# PathChord design review record

This historical review compares the architecture, protocol, configuration,
state-machine, implementation, and technology-selection documents. Its issue
wording records the state at review time; the current final-state contracts are
under `docs/design/` and `docs/spec/`.

## Review status

The Session lifecycle, control ACK, identifier, DNS, naming, and frame-boundary
issues from this review have been applied to the main design and specification
documents and the Phase 1 tracking documents under `docs/progress/`. The Ingress control-plane and
observability specifications now define typed mutations, subscription refresh,
structured snapshots, and an optional authenticated Web Gateway. Remaining
items are implementation specifications for later subsystems, not permission
to invent a different contract in code.

Phase 1A is intentionally TCP-only. UDP payload codecs, Path drain/close
payloads, multipath scheduling, management API implementation, and persistent
SQLite operations remain explicitly deferred.

## Must fix before implementation

### 1. Session cardinality and Path cardinality conflict

The architecture currently says a Session contains “zero or more” Paths, while the protocol invariant says a live Session always has at least one `PATH_READY` Path. The intended rule should be:

- a Session record may exist internally while connecting;
- a live or usable Session must have at least one `PATH_READY` Path;
- business Streams may only use a usable Session;
- losing the last Path closes business Streams and moves the Session into reconnecting state;
- the reconnecting record is not a live Session from the protocol perspective.

The wording should be made consistent across all documents.

### 2. Last-Path behavior is described in two ways

Some sections say the last Path terminates the Session immediately. Other sections say the Session transitions to `CONNECTING` and a replacement Session may be created. These should be separated into two layers:

- protocol layer: `SESSION_CLOSE` is final and the old Session ID cannot be reused;
- Ingress session manager: after closure, it may create a new Session for the same Egress.

This preserves the “no Session without a Path” invariant while allowing automatic recovery.

### 3. Control-message reliability is incomplete for a lossy Path

Control messages are replicated by default, but the acknowledgement and retransmission rule is not yet explicit. The design needs a Session-level control ACK or cumulative applied sequence report. Replication alone cannot guarantee delivery when all copies are lost.

Recommended rule: every control message is retained until acknowledged by the peer; ACKs report the highest contiguous applied sequence plus selective ranges for dependencies.

### 4. Frame integrity and loss model need one clear boundary

The protocol is byte-oriented, but complete frames are the minimum delivery unit. The adapter contract must explicitly state whether a lossy byte-stream adapter performs frame recovery, or whether the Path framing layer does it. The recommended boundary is:

- adapter delivers complete authenticated records;
- record loss, duplication, and reordering are visible;
- incomplete records are discarded inside the adapter or record decoder;
- Session reliability never operates on partial bytes.

### 5. Session control sequence lifetime is unspecified

`control_seqno` must be scoped to a Session and never reused within that Session. A new Session gets a new random SessionID and a new sequence space. Persistent sequence storage is unnecessary.

## Important missing specifications

### 6. Stream ID and request ID allocation

The documents define the identifiers but not allocation direction, width, or collision handling. Recommended defaults:

- StreamID: 62-bit locally allocated monotonic counter per direction;
- RequestID: 128-bit random value;
- SessionID and PathID: 128-bit random values;
- IDs are never reused within a live Session.

### 7. ACK and retransmission ownership

The design should state which endpoint owns retransmission timers, how duplicate ACKs are handled, and when an unacknowledged range expires. The recommended model is sender-owned retransmission state with receiver-generated ACK ranges and a bounded retransmission queue.

### 8. Target dialing and DNS timing

The protocol does not yet specify whether Egress receives a hostname, resolved address, or both for `STREAM_OPEN`. This affects DNS policy and IPv4/IPv6 selection. The recommended model is to carry the original hostname when available and let the selected Egress apply its configured DNS policy.

### 9. Management API schema

The transport is chosen, but request/response operations are not defined. The API still needs operation names, response envelopes, generation conflict handling, status output, and authorization error codes.

### 10. Resource exhaustion behavior

Hard limits are mentioned but not mapped to protocol behavior. Each limit needs a defined response: reject new Stream, apply backpressure, drain Path, or close Session.

## Documentation consistency issues

- The CLI example uses `anasto` while the project name is PathChord.
- The architecture document refers to “Stream data can only use Paths admitted for that stream”, while the current design says Streams are Path-transparent. This should describe scheduler eligibility rather than Stream-owned Path state.
- The protocol uses both `SESSION_ATTACH_ACK` and `SESSION_ATTACH_OK`; one name should be selected.
- The protocol lists `DATA`, `ACK`, and `WINDOW_UPDATE`, while later sections use `STREAM_DATA`, `STREAM_ACK`, and `STREAM_WINDOW`; the latter names should become canonical.
- The state machine uses `CONNECTED`/`DOWN` for Egress and `ACTIVE`/`CLOSED` for Session without a cross-reference table.

## Can remain implementation-stage decisions

- exact Rust crate versions;
- SQLite schema indexes;
- Tokio task topology;
- TPROXY and Wintun wrapper details;
- probe intervals and autoscaler constants, provided the metric semantics are fixed first.

