# Design

## Context

The proposal establishes the AnyTLS v2 compatibility target. The current
adapter owns one TLS byte stream per call, builds the authentication record and
initial frames inline, and exposes a duplex relay. The official protocol adds a
padding scheme, settings negotiation, server updates, and reusable Sessions.

## Goals / Non-Goals

**Goals:**

- Keep one active logical Stream per AnyTLS Session.
- Share healthy idle Sessions between TCP and UoT v2 UDP calls for one node.
- Implement the official default padding scheme and bounded server updates.
- Preserve cancellation-safe frame parsing, FIN and ALERT errors, and no-retry
  behavior after a failed open.
- Keep existing TransitAdapter and TransitDatagram APIs stable.

**Non-Goals:**

- Multiple active Streams on one Session.
- AnyTLS-specific active-session quotas beyond existing PathChord resource limits.
- A user-configurable padding scheme in this change.
- Transparent retry of a failed current request.
- Changes to PathChord wire framing or the Egress Session protocol.

## Decisions

### Session ownership and leasing

AnyTlsAdapter owns a bounded pool of Session records. Each record contains the
TLS transport, the AnyTLS event loop, negotiated protocol state, padding state,
health state, and an active-stream lease. Acquisition removes the newest
healthy idle Session from the pool. If none exists, acquisition creates one TLS
Session with the node's current padding scheme.

A successful Stream close releases the lease. The Session enters the idle pool
only when the event loop is healthy, no protocol error was observed, the writer
has completed its FIN, and the underlying transport remains usable. The pool
retains at most eight idle Sessions. It evicts the oldest idle records when the
limit is exceeded and reaps records idle for 60 seconds.

### Padding state

The codec parses the official default scheme into bounded packet rules and
computes its lowercase MD5 digest. Authentication sends the default padding0.
The first Session settings frame includes version 2, a PathChord client name,
and the digest. A valid update replaces the node-level scheme atomically. The
Session that received the update continues using its captured scheme. New
Sessions capture the newest scheme.

Padding is applied by the Session writer before TLS writes. The writer keeps a
packet counter, emits bounded waste frames, stops at the scheme's stop count,
and preserves queued application bytes. The reader accepts waste frames and
rejects malformed commands or oversized lengths before allocation.

### Event loop and stream relay

One Session reader task parses all incoming frames and dispatches them to the
single active Stream. A writer task serializes settings, SYN, destination PUSH,
application PUSH, heartbeat responses, and FIN. The public Stream is backed by
bounded queues. A peer FIN closes the Stream without sending a reciprocal FIN.
An ALERT records a sanitized connection error and closes the Session. A
heartbeat response keeps the request Stream ID and has an empty payload.

The TCP open path waits for a successful SYNACK. A non-empty SYNACK is a
sanitized open failure. The UoT v2 open path sends its association request as
the first Stream payload before waiting for SYNACK. Both paths use the same
Session lease and release rules.

### Failure and cancellation

A parser error, transport error, invalid update, failed SYNACK, or failed
heartbeat marks the Session unhealthy and removes it from the idle pool. The
current operation receives the error. No retry is performed by the AnyTLS
adapter. Cancellation retains already-read bytes in the Session reader buffer
and releases the lease through the Session close path.

### Compatibility and limits

The pool and padding scheme are private adapter state. No new public
configuration fields are introduced. Session count is controlled by existing
Transit and Ingress resource limits. The idle pool limit and timeout are fixed
at eight and 60 seconds for the first implementation so cache and control-plane
schemas do not need a migration.

## Risks / Trade-offs

- Padding adds CPU and wire overhead. The fixed official default preserves peer
  compatibility and avoids a new configuration surface.
- A single active Stream per Session creates more TLS connections under load.
  This follows the confirmed product decision and keeps failure ownership clear.
- A malformed server update retires the Session. This fails closed and prevents
  an unvalidated padding scheme from reaching a new connection.
- Idle reaping can close a Session between acquisition and stream opening. The
  lease operation must atomically remove the record from the pool and verify
  health before sending SYN.

## Migration Plan

Existing AnyTLS nodes continue to use the same protocol and credential fields.
The first implementation publishes the new Session behavior atomically when
an adapter is rebuilt. Existing active connections finish under their current
adapter instance. A failed Session is discarded and the next independent
request creates a new Session.
