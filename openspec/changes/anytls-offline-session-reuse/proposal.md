# Proposal

## Why

The current native AnyTLS adapter opens one TLS connection for each logical
Stream and sends a minimal session preface without the protocol's padding
negotiation. The official AnyTLS v2 client contract requires a default padding
scheme, server-driven scheme updates, and reuse of healthy idle Sessions.

## What Changes

- Add the official AnyTLS v2 default padding to authentication and Session writes.
- Advertise the client protocol version, client identity, and padding scheme
  digest in cmdSettings.
- Accept and validate cmdServerSettings and cmdUpdatePaddingScheme, applying
  a new scheme only to Sessions created after the update.
- Reuse one healthy idle AnyTLS Session for one new logical Stream at a time.
- Share one bounded idle Session pool between TCP and UoT v2 UDP flows.
- Keep at most eight idle Sessions per AnyTLS node and retire idle Sessions after
  60 seconds.
- Preserve one active Stream per Session and reject new Streams on failed or
  unhealthy Sessions.
- Drop failed Sessions without retrying the current request.
- Preserve Stream and Session error semantics for FIN, ALERT, heartbeat, and
  padding failures.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- transit-proxies: AnyTLS Session lifecycle, padding negotiation, stream
  admission, idle pooling, UoT reuse, and failure semantics.

## Impact

- crates/pathchord-transit/src/anytls_adapter.rs gains a node-owned Session
  pool, a protocol event loop, padding state, and one-active-Stream leasing.
- crates/pathchord-transit/src/anytls_codec.rs gains bounded padding scheme
  parsing, digest handling, and command validation.
- AnyTLS TCP and UoT UDP callers share Session acquisition and release logic.
- Existing Transit adapter preparation remains native and process-free.
- The Transit Proxy specification and its Simplified Chinese counterpart
  receive synchronized AnyTLS lifecycle requirements.
