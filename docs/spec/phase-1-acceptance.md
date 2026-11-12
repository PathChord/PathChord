# Phase 1 acceptance criteria

Phase 1 is complete only when the following behaviors are reproducible with a
deterministic fake Transit/Egress harness and, for the TCP path, a local SOCKS5
or equivalent test listener. Tests MUST assert protocol results and cleanup,
not only that a task returned without an error.

## Build and fixture gates

The repository MUST pass:

```text
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked --workspace --all-targets
```

The Phase 1 test suite MUST include fixed byte vectors for the common frame
header and each handshake/attach payload, plus malformed, truncated, trailing,
non-canonical, and over-limit inputs.

## Handshake and attachment

1. A fresh initiator and responder complete the IK handshake with the configured
   EgressID prologue and obtain independent transport keys.
2. A wrong Egress static key fails before `PATH_READY`.
3. A mismatched EgressID prologue fails before attach.
4. A Noise-authenticated but disabled or revoked Ingress key receives
   `SESSION_ATTACH_REJECT` and cannot create a live Session.
5. An enabled key whose `SESSION_ATTACH` IngressID does not match the
   authorization mapping is rejected.
6. The valid exchange is exactly `PATH_HELLO -> SESSION_ATTACH ->
   SESSION_ATTACH_OK -> PATH_READY`; business frames sent before `PATH_READY`
   are rejected.
7. A required capability mismatch rejects the attach. Optional capabilities are
   selected by intersection.
8. A declared limit above a Phase 0 hard limit is rejected before allocation.

## Record and frame integrity

1. `NoiseTransport::seal_frame` rejects a frame whose `frame_seq` is not the
   sender's next owned nonce.
2. `open_encoded_frame` rejects a truncated, trailing, oversized, malformed,
   or unauthenticated record.
3. A valid record is accepted only when the decoded frame sequence equals the
   authenticated record nonce.
4. Duplicate authenticated records are rejected by the bounded replay window
   before Session/control processing.
5. Records that arrive out of order inside the 64-record replay window are
   accepted; records outside the window are reported stale.
6. A Path transport never delivers partial bytes or a corrupted frame to core.
   Drop, duplicate, reorder, and corruption faults are observable in the fake
   transport statistics.

## Session lifecycle

1. A valid attach creates exactly one live Session slot with one SessionID and
   one `PATH_READY` Path.
2. A duplicate or delayed attach for the same Session is accepted only after
   identity and Egress checks pass; Phase 1A does not require opening a second
   physical Path, so the harness may exercise this as an attach validation
   case rather than a second live transport.
3. Losing the only Path closes all Streams and target resources, retires the old
   SessionID, and reconnects only with a newly allocated SessionID.
4. A delayed frame for a closed Session cannot create a Stream or redial a
   target.
5. Egress-unavailable, authorization-revoked, endpoint-restart, and intentional
   drain causes enter their distinct Session-manager phases. Revocation and
   restart do not immediately create a replacement Session.
6. Control frames are applied at most once. Dropping the first copy and
   delivering a later retransmission produces one side effect after ACK.
7. A Session close prevents new Stream opens. Any Phase 1B UDP association
   owned by that Session is also closed.

## TCP Stream

1. A valid `STREAM_OPEN` creates exactly one target connection and returns
   `STREAM_OPEN_OK`.
2. Repeating the same RequestID and identical request after a lost response
   returns the cached result without a second target dial.
3. Reusing a RequestID with different fields is rejected.
4. Cancelling an in-flight target dial does not leave a Stream tombstone that
   prevents a valid retry.
5. `STREAM_DATA` arrives out of order, is reordered by offset, and delivers
   each target byte exactly once.
6. Duplicate data ranges are harmless and do not duplicate target bytes.
7. Receive-window exhaustion applies backpressure; it does not silently drop
   TCP bytes.
8. FIN is delivered after preceding bytes and half-closes only one direction.
9. RST closes the target connection, discards pending bytes, and reports the
   normalized target result.
10. Target FIN/RST is not reported as PATH_FAILURE.

## UDP association (Phase 1B)

These criteria apply after the Phase 1A TCP slice is stable. They are not gates
for the first TCP-only vertical integration.

1. `UDP_OPEN` creates one Egress-side socket context and returns
   `UDP_OPEN_OK`.
2. Hostname and address candidates are retained according to the DNS policy;
   port zero is rejected.
3. `UDP_DATAGRAM` preserves datagram boundaries and does not receive reliable
   aggregation-layer retransmission.
4. Repeated datagrams are either delivered according to the configured
   duplicate policy or discarded diagnostically; they are never interpreted as
   TCP byte ranges.
5. `UDP_CLOSE`, target failure, Session close, and endpoint restart release the
   socket context.

## Fault and restart matrix

The harness MUST exercise each event at least once for both TCP and control
traffic where applicable:

```text
drop one complete record
duplicate one complete record
reorder two complete records
corrupt or truncate a record
lose the first STREAM_OPEN response
cancel a pending target dial
lose the only Path
close the Egress process/session
revoke the Ingress authorization
restart an endpoint
```

Expected outcomes are explicit: control is deduplicated and retried until ACK,
TCP bytes are preserved or the local connection is closed with an Egress
failure, UDP datagrams may expire/drop, and no old SessionID or RequestID retry
may create a second target resource.

## Deferred acceptance

The following are deliberately not gates for this document:

- real Linux/Windows interception adapters;
- multiple-Path effective-capacity scheduling;
- subscription normalization and hot reload;
- implementation of the local control API, Web Gateway, and SQLite persistence
  (their contracts are defined in the Ingress control-plane and observability
  specifications);
- autoscaling, quotas, and production key-buffer zeroization;
- stable cross-version wire compatibility beyond the Phase 1 fixture.
