# Phase 1 single-path implementation scope

This progress document tracks the normative acceptance scope for the first
runnable PathChord slice. It is not the final product specification; durable
behavior is defined in the [protocol specification](../spec/protocol.md) and
[state-machine specification](../spec/state-machines.md).

Phase 1A defines one Ingress, one Egress, one authenticated Path, and one TCP
Stream. A subsequent Phase 1B adds one UDP association after the TCP slice is
stable. Both build on the Phase 0 frame and Noise primitives.

The key words MUST, MUST NOT, SHOULD, SHOULD NOT, and MAY are requirements for
the Phase 1 implementation. The frame discriminants in this document are frozen
for the Phase 1 fixture only; they are not yet a cross-version registry.

## Scope

Phase 1A implements the following TCP vertical slice:

```text
local test connection
        |
single Ingress flow context
        |
one authenticated Noise Path
        |
one Transit adapter (direct or deterministic fake)
        |
one Egress target connector
        |
one TCP target connection
```

Ingress selects one configured Egress before opening a Path. The Egress identity
is fixed for the lifetime of a Session. A Session has one Ingress, one Egress,
and a SessionID that is never reused. A live Session has at least one
`PATH_READY` Path.

The first runnable endpoint MAY use an in-process fake listener and fake Transit
adapter. A real local SOCKS5 listener is the first platform adapter target, but
TPROXY, REDIRECT, TUN, Windows system-proxy integration, and subscription
parsing are outside this slice.

## Roles and ownership

Ingress owns:

- the configured Egress public key and canonical EgressID;
- SessionID, PathID, StreamID, RequestID, and outbound frame sequence allocation;
- Path creation, Session replacement, control retransmission timers, and upstream
  TCP scheduling;
- the local connection and the policy snapshot used when it is admitted.

Egress owns:

- the static private key and enabled Ingress authorization snapshot;
- authorization of the authenticated initiator key before `PATH_READY`;
- target TCP dialing and UDP socket contexts;
- RequestID idempotency state for `STREAM_OPEN` and target connection cleanup;
- downstream scheduling over the one available Path.

Transit is only a byte transport. It is never an authenticated PathChord peer.
The Path/record layer MUST expose complete authenticated records or complete
`PathFrame` values to Session logic; no Session code may process partial bytes.

## Session and Path establishment

The following sequence is required for every new Path:

1. Ingress allocates a fresh SessionID if the Egress has no live Session, and a
   fresh PathID for the physical Path.
2. Ingress opens the configured Transit connection.
3. Both endpoints perform a fresh `Noise_IK_25519_ChaChaPoly_SHA256` handshake.
   The prologue contains the canonical non-empty EgressID fixture defined in
   [phase-1-wire.md](phase-1-wire.md).
4. Egress obtains the authenticated initiator static public key and maps it to
   exactly one enabled IngressID. Noise authentication alone does not authorize
   the Path.
5. Ingress sends `PATH_HELLO`.
6. Ingress sends `SESSION_ATTACH` with the IngressID, SessionID, and EgressID.
7. Egress sends `SESSION_ATTACH_OK` or `SESSION_ATTACH_REJECT`.
8. Ingress sends `PATH_READY` after it has accepted the negotiated limits.
9. Egress accepts business frames only after it has validated `PATH_READY`.

`PATH_HELLO`, `SESSION_ATTACH`, and their responses use the allocated SessionID
and PathID in the common frame header. A rejected attach MUST close the Path and
MUST NOT create a live Session. A Path that never reaches `PATH_READY` cannot
carry Stream or UDP business traffic.

The Egress MUST reject an attach when any of these checks fail:

- Noise peer key is absent, disabled, or revoked in the authorization snapshot;
- EgressID does not match the configured Egress;
- IngressID does not match the authorization record selected by the peer key;
- SessionID is already owned by a different Ingress or was previously closed;
- required protocol version or capability is not supported;
- a declared limit exceeds a Phase 0 hard limit.

## Session lifecycle

The protocol Session states are:

```text
CONFIGURED -> CONNECTING -> ACTIVE
ACTIVE -> DEGRADED
DEGRADED -> ACTIVE
ACTIVE/DEGRADED -> DRAINING
CONFIGURED/CONNECTING/ACTIVE/DEGRADED -> CLOSED
DRAINING -> CLOSED
```

`ACTIVE` and `DEGRADED` require at least one `PATH_READY` Path. `DRAINING`
does not admit new Streams but lets acknowledged work finish. `SESSION_CLOSE`
is final for the SessionID.

When the last Path disappears, Ingress MUST close all Streams and local target
connections associated with that Session, retire the SessionID, and create a
new SessionID before reconnecting. A reconnecting Session slot is an Ingress
manager record, not a live protocol Session. Egress restart, authorization
revocation, or hard failure closes the Session and all related target resources;
the old SessionID is never resumed.

Control frames are sender-owned and retained until acknowledged. Phase 1 uses a
sender-direction control sequence space: each endpoint allocates a monotonic
`control_seqno` for its own control frames, and `CONTROL_ACK` identifies the
sender role plus the highest contiguous sequence and optional selective ranges.
Duplicate control sequences are applied at most once. A retransmission reuses
the original encoded frame and sealed Noise ciphertext. If the Phase 0 replay
window has made an old record stale, the sender MAY issue a fresh Path frame
sequence carrying the same Session-level control sequence; it MUST NOT execute
the control side effect twice.

## TCP Stream

Ingress allocates all Phase 1 StreamIDs from a monotonic 62-bit Session-local
counter. Egress does not initiate business Streams in this slice. StreamIDs and
RequestIDs are never reused within a live Session.

`STREAM_OPEN` contains a RequestID, StreamID, target hostname when available,
zero or more resolved address candidates, and a target port. Egress applies its
own DNS policy and retains the original hostname. Repeating the same
`(SessionID, RequestID)` with identical fields MUST return the original result
without opening a second target connection. Reusing a RequestID with different
fields MUST be rejected.

After `STREAM_OPEN_OK`, data uses ordered byte offsets. The implementation may
use half-open ranges internally, but the Phase 1 wire ACK representation is
inclusive. `STREAM_DATA` frames with duplicate bytes MUST be delivered to the
target at most once. Missing bytes are buffered up to the negotiated reorder
limit; TCP bytes are never silently dropped.

`STREAM_FIN` half-closes one direction after all preceding bytes. `STREAM_RST`
discards pending bytes, closes the target connection, and carries a normalized
error. A target FIN/RST is reported as a target result, not as a Path failure.

With one Path there is no path migration to exercise, but Stream state MUST NOT
contain a PathID. This preserves the Phase 4 migration contract.

## Phase 1B UDP association

This section defines the follow-up UDP slice. It is not a Phase 1A acceptance
gate and must not block the first TCP implementation.

Ingress allocates an association identifier and sends `UDP_OPEN`. Egress creates
one target-visible UDP socket context for that association. `UDP_DATAGRAM`
preserves datagram boundaries and may be sent only while the association and
Session are usable. The aggregation layer does not retransmit ordinary UDP
datagrams. `UDP_CLOSE`, Session close, target failure, or endpoint restart
closes the socket context.

Path replacement is not implemented in Phase 1, but the Egress socket context
MUST be modeled independently of Path identity so a later multipath adapter does
not silently rebind the target-visible port.

## Explicitly deferred

The following are not Phase 1A acceptance requirements:

- Linux TPROXY/REDIRECT, TUN, Windows Wintun, and system-proxy integration;
- multiple Paths, effective-capacity scheduling, congestion control, and
  cross-Path data retransmission;
- subscription refresh, Clash/SIP008 normalization, YAML serialization, and
  compiled rule evaluation;
- transport adapters for the Unix-socket/Named-Pipe control API and optional
  Web Gateway; the typed service foundation is present, while the control-plane
  contract is defined separately in the
  [Ingress control-plane specification](../spec/ingress-control-plane.md) and
  [Ingress observability specification](../spec/observability.md);
- SQLite persistence;
- dynamic enrollment mutation and production crash/network restoration logic;
- production-grade Noise key-buffer zeroization beyond the documented `snow`
  limitation;
- stable public wire discriminants and cross-version compatibility.

UDP association acceptance is Phase 1B and follows the TCP slice; it is not a
prerequisite for the first local SOCKS5-to-TCP demonstration.
