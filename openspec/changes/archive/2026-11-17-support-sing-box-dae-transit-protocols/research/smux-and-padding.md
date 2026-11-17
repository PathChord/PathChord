# sing-box smux and multiplex padding investigation

Date: 2026-11-16. This is a non-normative investigation, not a claim that
PathChord supports these options. It examines sing-box 1.14.4 at
`c005f35300ce76427dc285481ec5695f5b179cd2`, its pinned sing-mux
`v0.3.10-0.20260929204512-caf09fe32475`, and the sing-mux dependency
`github.com/sagernet/smux v1.5.50-sing-box-mod.1`. At the time of this
investigation, unpadded h2mux had been independently tested, yamux integration
was being handled separately, and smux and padding were unimplemented. No
dependency was added and no new external-peer test was run for this note.
Subsequent h2mux/yamux/smux and padding implementation and test evidence is
recorded in the [implementation status](../../../../implementation-status.md).
The implementation follow-up below distinguishes completed local evidence
from the original investigation and its proposed validation plan.

## Implementation follow-up

PathChord now implements smux v1 without the candidate Rust smux crates below.
The shared adapter supports optional sing-mux padding. Six local independent
sing-box 1.14.4 cases covered SS, VLESS, VMess and Trojan TCP/UDP, both Vision
flows, connection reuse, padding, and subscription revocation. The FIN case
confirmed that a response generated after the target observed EOF did not
arrive; smux therefore retains full-close rather than TCP half-close semantics.
An independent Go smux peer also exercised concurrent streams and the FIN
boundary. These are local peer results, not deployed or WAN evidence.

The implementation caps each smux session at 256 streams, 4 MiB of queued
receive payload, 4 MiB of queued transmit wire frames, 256 KiB per receiving
stream, 1024 queued receive frames and 512 queued transmit frames. Budgets
cover queued data and frame counts, not all process allocations. A full or
partially read frame remains charged until its allocation is released. Under
receive pressure the driver isolates the over-limit or selected buffered
stream, discards its buffered data, returns a resource error and schedules
FIN; it consumes later payload for that stream without blocking other streams.

The caller or a higher-level timeout must cancel active stalled carrier I/O:
generic buffered streams do not reveal enough progress to impose an accurate
smux-driver deadline. Once
the final stream handle is released, pending reader and writer I/O shares an
absolute ten-second drain deadline; reopening a stream cancels it. The deadline
is not restarted for each frame, and an idle pooled session can remain until
normal pool reclamation. Local tests exercise cancellation, slow buffered I/O,
resource isolation, and the release/open deadline race. These limits and the
full-close boundary are part of the current Transit contract; further platform,
failure and deployed evidence remains separate.

## Layering and wire format

The mux client first establishes an ordinary TCP connection through the
selected SS, VLESS, VMess, or Trojan adapter to `sp.mux.sing-box.arpa:444`.
The sing-mux session header precedes the selected stream protocol. With
padding disabled, its v0 header is two bytes: `00 00` for smux, `00 01` for
yamux, or `00 02` for h2mux. With padding enabled, the client sends v1:
`01 | protocol | 01 | initial_padding_len:u16be | initial_padding`, where the
Go client chooses 256 through 767 padding bytes. A server configured to
require padding rejects an unpadded session. See the pinned
[session protocol](https://github.com/SagerNet/sing-mux/blob/caf09fe32475/protocol.go),
[client setup](https://github.com/SagerNet/sing-mux/blob/caf09fe32475/client.go),
and [server setup](https://github.com/SagerNet/sing-mux/blob/caf09fe32475/server.go).

Padding is **below the selected multiplexer**, on the whole proxy connection;
it is not an independent padding header on each logical target stream. In
each direction, the first 16 framed writes are encoded as
`data_len:u16be | padding_len:u16be | data | padding`; the Go writer chooses
256 through 767 padding bytes per record and splits payloads larger than
65,535 bytes. The ordinary `Write` method emits no record for empty input;
the vectorized and buffer entry points need separate zero-length tests.
Subsequent bytes are unframed. The reader must maintain header,
payload, and discard progress across fragmentation and cancellation, including
the transition after the sixteenth record. The protocol declares a u16 padding
length; the receiver cannot assume every peer chooses the writer's usual
range. The reference code chooses the padding length, while its padding bytes
are simply extended buffers. An implementation can initialize those bytes
without treating their content as authentication or a secret. See
[padding.go](https://github.com/SagerNet/sing-mux/blob/caf09fe32475/padding.go).

After the session layer, sing-mux uses the same logical stream request for all
three protocols: a u16be flags field followed by a SOCKS address and port. The
UDP bit is 1; the address-carrying packet mode uses bit 2. The connected UDP
mode relevant to PathChord uses the target from the stream request, followed by
u16be length-prefixed datagrams. An initial per-stream mux status precedes
response data; HTTP/2 status 200 alone is not that confirmation. The
[protocol](https://github.com/SagerNet/sing-mux/blob/caf09fe32475/protocol.go)
and [client stream implementation](https://github.com/SagerNet/sing-mux/blob/caf09fe32475/client_conn.go)
define the exact fields. Failure text received from a peer should remain
sanitized rather than be copied into logs or public diagnostics.

## smux behavior and resource boundaries

The reference sing-mux explicitly selects `smux.DefaultConfig()` and disables
its keepalive. That default uses smux **version 1**, a 32,768-byte write
frame, a 4 MiB session receive budget, and a 64 KiB configured stream buffer;
version 2's `UPD` command and window protocol are not the sing-box default.
The v1 frame header is `version:u8 | command:u8 | length:u16le | stream_id:u32le`.
Commands are `SYN=0`, `FIN=1`, `PSH=2`, and `NOP=3`; stream ID 0 is reserved
for NOP. The Go client starts its sequence at 1 and increments before use, so
its first locally opened stream is 3; odd nonzero client IDs are the relevant
parity invariant. See
[sing-mux session selection](https://github.com/SagerNet/sing-mux/blob/caf09fe32475/session.go),
the pinned [smux defaults](https://github.com/SagerNet/smux/blob/v1.5.50-sing-box-mod.1/mux.go),
[frame codec](https://github.com/SagerNet/smux/blob/v1.5.50-sing-box-mod.1/frame.go),
and [session implementation](https://github.com/SagerNet/smux/blob/v1.5.50-sing-box-mod.1/session.go).

**Half-close is an interoperability constraint.** The reference sing-mux
exports a `CloseWrite` wrapper for h2mux and yamux but not smux. Its smux
stream `Close` sends FIN and closes the local stream; after receiving FIN,
the Go smux v1 writer observes the FIN event and returns EOF. Therefore a
Rust crate describing FIN as an independently usable TCP write half does not
establish that a sing-box smux peer can read a request EOF and then send a
delayed response. The subsequent independent-peer test described above observed
that limitation, so PathChord exposes the full-close behavior rather than
claiming complete TCP half-close compatibility or substituting a different mux
protocol. See [sing-mux session.go](https://github.com/SagerNet/sing-mux/blob/caf09fe32475/session.go)
and the pinned [smux stream.go](https://github.com/SagerNet/smux/blob/v1.5.50-sing-box-mod.1/stream.go).

## Rust candidates

| Candidate | Evidence and assessment |
| --- | --- |
| [`async_smux` 0.4.0](https://docs.rs/crate/async_smux/0.4.0/source/) | MIT; Tokio `AsyncRead`/`AsyncWrite`, v1 frame format, configurable frame-count queues and an explicit worker. A promising prototype candidate, not yet independently verified against the pinned Go fork. Its advertised half-close semantics differ from the Go peer evidence above. Its manifest declares no Rust MSRV, so supported Rust and target-platform builds need verification. |
| [`tokio_smux` 0.2.0](https://docs.rs/crate/tokio_smux/0.2.0/source/) | MIT; v1 only, and its README says its public Stream is frame-oriented rather than directly implementing Tokio `AsyncRead`/`AsyncWrite`. Additional adaptation and task/queue-lifetime auditing are required. |
| [`smux` 0.2.0](https://docs.rs/crate/smux/0.2.0/source/) | MIT; claims Go compatibility and exposes Tokio streams, but its source creates unbounded per-stream channels and treats `max_receive_buffer` as a bounded channel capacity. Its stream code contains v1 hard-coding marked TODO. It needs a resource and wire audit before consideration. |
| [`yamux` 0.14.1](https://docs.rs/crate/yamux/0.14.1/source/) / [`tokio-yamux` 0.3.20](https://docs.rs/crate/tokio-yamux/0.3.20/source/) | Yamux candidates, not smux implementations. The former uses `futures::io` and defaults to 512 streams and a 1 GiB aggregate receive window; the latter exposes Tokio-facing APIs but uses unbounded internal event channels. These defaults and adaptation costs require separate review. |

`async_smux`'s limits are counts of frames, not a complete byte budget. Its
defaults permit 1,024 queued transmit frames **per stream** and 1,024 queued
receive frames per session; a frame can carry 65,535 bytes. Dropping a stream
moves its accepted pending transmit frames to a connection-wide `VecDeque`
with no explicit global byte bound. Repeated open/write/drop or peer SYN/FIN
churn while the carrier is blocked therefore needs a targeted audit and a
bounded global queue or a patched implementation; reducing the documented
per-stream queue alone does not prove a global bound. Its drop and graceful
close paths claim to drain previously accepted writes, which is useful but
must be tested under cancellation, connection failure, and the local resource
budget. See its [builder](https://docs.rs/crate/async_smux/0.4.0/source/src/builder.rs),
[frame codec](https://docs.rs/crate/async_smux/0.4.0/source/src/frame.rs), and
[session/stream implementation](https://docs.rs/crate/async_smux/0.4.0/source/src/mux.rs).
No crate is recommended for inclusion without the independent tests and
resource audit below.

## Original implementation proposal

The following proposal is retained as historical design context; the
implementation follow-up above records the result.

1. Extract the shared sing-mux stream request, status filtering, connected UDP
   framing, admission token, and pool accounting from the h2-specific I/O.
   Keep HTTP/2 transport handling separate from the common status reader so an
   HTTP 200 followed by EOF before a mux status remains an error.
2. Add a session backend with explicit `open`, capacity, closed, and shutdown
   operations. Preserve the current `maxConnections`, `minStreams`,
   `maxStreams`, 256-connection and 4096-stream bounds, idle expiry, and
   source-revocation behavior. h2 uses the peer's SETTINGS limit; smux has no
   equivalent advertised stream limit and therefore needs an explicit local
   bound. Existing active streams retain their session when an adapter/source
   is retired; new selections remain fenced.
3. For padding, write the v1 session header on the original Transit stream,
   then place a bounded, cancellation-safe bidirectional padding codec between
   that stream and the chosen session driver. Keep it independent of the
   logical mux stream and preserve the base adapter's TLS/REALITY semantics.
   A partial failed write cannot be replayed as a fresh target open.
4. For smux, start a bounded session driver only after the base adapter and
   prefix are ready. Bound total queued bytes, active streams, pending opens,
   peer-initiated streams, timers, and physical sessions; do not allow an
   unchecked library-global queue to outlive source revocation. On cancelled
   opening or sending, release reservations exactly once, retain or abort
   partially accepted data according to the chosen close contract, and keep
   unrelated streams alive. Return an explicit diagnostic for any unsupported
   smux behavior, padding option, or resource configuration.

An adapter-level timeout alone cannot prove a byte bound inside a library's
background queue. The first implementation should use a demonstrably bounded
backend or patch/audit its internal queues, rather than depending only on
configured stream counts. The existing session pool's lock-free dial
reservation and peer-capacity fixes must remain intact when adding a backend.

## Original independent verification plan

These were investigation targets. The implementation follow-up identifies
the local cases subsequently exercised; the list does not itself assert that
every proposed platform, packet size, or failure case was validated.

- Exercise sing-box 1.14.4 as the real server with smux, first without padding
  and then with required padding; separately test padded h2mux. Use SS, VLESS
  (including both Vision flows), VMess, and Trojan where their combinations are
  valid. Count physical connections to prove actual concurrent multiplexing.
- Transfer concurrent TCP and UDP, multiple address families, empty and large
  datagrams, and verify byte-for-byte results and stream isolation. Probe the
  peer's packet-size boundary and record peer limitations rather than silently
  truncating. Test authentication failure and a rejected destination without
  exposing credentials or impacting other streams.
- Split session and padding headers one byte at a time; test partial writes,
  cancellation at every frame transition, an invalid version/command/length,
  missing mux status, RST/EOF, source disable/replacement, stalled readers and
  writers, exhaustion/recovery of all resource limits, idle reap, and driver
  termination. Confirm slow physical dials do not hold the pool lock and
  concurrent reservations never exceed the configured connection limit.
- Test request EOF followed by a delayed response in both directions against
  the Go peer, rather than inferring half-close behavior from the Rust library's
  own tests. Record a failing or unsupported result if the peer closes both
  directions; do not mark the combination complete on TCP echo alone.

The source investigation and original proposal do not by themselves establish
interoperability. The independently exercised cases are identified in the
implementation follow-up and the implementation status.
