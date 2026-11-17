# Hysteria2 Brutal pacing and Quinn

This non-normative research note records source inspection and a limited local
experiment on 2026-11-16. It investigates the missing Hysteria2 upload-rate
behavior in [task 3.4](../tasks.md); it does not mark that task complete or
establish a final implementation design.

## Current boundary and protocol semantics

At the time of the initial investigation, the
[Hysteria2 adapter](../../../../../crates/pathchord-transit/src/hysteria2_adapter.rs)
used Quinn BBR, sent the configured `down_mbps` as a receive-rate hint, and
rejected nonzero `up_mbps` or server receive rates. A server can ignore the
download hint. See the implementation follow-up below and the
[implementation status](../../../../implementation-status.md) for the current
snapshot and validation evidence.

The protocol uses the same `Hysteria-CC-RX` name in two directions, both in
bytes per second:

- The request contains the **client's receive rate**; zero means unknown.
  This informs the server's sending behavior.
- The response contains the **server's receive rate**; zero means unlimited.
  `auto` asks the client to use congestion control to determine its own sending
  rate. It does not establish whether an arbitrary server honors the request's
  separate downlink hint.

These meanings and their special cases are described in the upstream
[authentication headers](https://github.com/apernet/hysteria/blob/c2b181e0b0e72b077e4b0b7297735af14d1f9929/PROTOCOL.md#L23-L55)
and [congestion-control section](https://github.com/apernet/hysteria/blob/c2b181e0b0e72b077e4b0b7297735af14d1f9929/PROTOCOL.md#L119-L127).
In the inspected upstream server, the
[`IgnoreClientBandwidth` branch](https://github.com/apernet/hysteria/blob/c2b181e0b0e72b077e4b0b7297735af14d1f9929/core/server/server.go#L177-L206)
does ignore the client's hint. The inspected upstream client handles `auto` by
using its configured congestion controller and ignoring local bandwidth
settings; for a numeric response it computes `actualTx` from the server and
local values, uses Brutal when that result is nonzero, and otherwise uses its
configured controller. In particular, a local transmit setting of zero with a
nonzero server response yields the configured controller, rather than Brutal.
See the [client decision](https://github.com/apernet/hysteria/blob/c2b181e0b0e72b077e4b0b7297735af14d1f9929/core/client/client.go#L148-L165).
The initial PathChord rejection of a nonzero server response was a deliberately
stricter compatibility boundary than that particular upstream choice.

## Brutal has a separate pacer

The following describes sing-quic `v0.7.2-0.20261020082049-7e0a5869a5f4`,
not every possible Hysteria implementation. Its
[Brutal sender](https://github.com/SagerNet/sing-quic/blob/7e0a5869a5f4/hysteria/congestion/brutal.go#L12-L76)
uses a target in bytes per second and, once a smoothed RTT exists, computes:

```text
congestion window = 2 * target_bytes_per_second * smoothed_RTT / ack_rate
pacing rate       = target_bytes_per_second / ack_rate
```

Before a positive smoothed RTT, the sender returns a 10,240-byte window. It
counts acknowledged and lost packets in five second-indexed slots. Below 50
total samples it uses an ACK rate of 1; otherwise it clamps the observed ACK
ratio to at least 0.8. See the
[sampling code](https://github.com/SagerNet/sing-quic/blob/7e0a5869a5f4/hysteria/congestion/brutal.go#L97-L158).
The [independent token-bucket pacer](https://github.com/SagerNet/sing-quic/blob/7e0a5869a5f4/hysteria/congestion/pacer.go#L10-L76)
initializes its stored budget to ten maximum-sized datagrams and caps a burst
at the larger of ten such datagrams and four milliseconds of the current
pacing rate. Before the first send, its budget query returns that burst cap.

Loss compensation means that the nominal target is not a strict physical
line-rate ceiling: the normally paced QUIC rate can reach `target / 0.8`, or
1.25 times the target. PTO probes, ACK-only packets, MTU probes and path
validation can also bypass normal pacing; finite bursts and UDP, IP or
obfuscation add further overhead. In the `sagernet/quic-go` version used by
sing-box 1.14.4, the send-mode decision prioritizes PTO before checking pacing
budget. Any strict physical cap would need its own definition and validation;
it cannot be described as unchanged upstream Brutal behavior.

## Quinn integration constraints

The workspace resolves `quinn` 0.11.12 and `quinn-proto` 0.11.19. Source links
below use their corresponding release tags.

1. A Quinn [`Controller`](https://github.com/quinn-rs/quinn/blob/quinn-proto-0.11.19/quinn-proto/src/congestion.rs#L16-L102)
   supplies `window()` and a `ControllerMetrics.pacing_rate`, but that metric
   is for trace statistics. The actual
   [pacer](https://github.com/quinn-rs/quinn/blob/quinn-proto-0.11.19/quinn-proto/src/connection/pacing.rs#L41-L112)
   replenishes tokens at approximately `1.25 * window / RTT`; the
   [send path](https://github.com/quinn-rs/quinn/blob/quinn-proto-0.11.19/quinn-proto/src/connection/mod.rs#L603-L640)
   passes the controller's window to it. Substituting the Brutal window alone
   therefore implies approximately `2.5 * target / ack_rate` for Quinn's
   token replenishment, not Brutal's separate rate. Quinn also bypasses that
   pacing calculation for zero RTT or very large windows. Timers, bursts and
   other send-path conditions affect observed throughput.
2. Quinn invokes
   [`on_ack` for individual acknowledged ACK-eliciting packets](https://github.com/quinn-rs/quinn/blob/quinn-proto-0.11.19/quinn-proto/src/connection/mod.rs#L1611-L1624)
   subject to its path-validation condition. The
   [loss callback](https://github.com/quinn-rs/quinn/blob/quinn-proto-0.11.19/quinn-proto/src/connection/mod.rs#L1721-L1812)
   exposes aggregated lost bytes, not the precise number of lost packets needed
   for the upstream sample. ECN congestion events report zero lost bytes and
   must not be counted as packet losses. Packet eligibility and MTU-probe
   treatment also need explicit comparison with the reference implementation.
3. The controller factory is configured before the connection is dialed.
   [`Connection::congestion_state()`](https://github.com/quinn-rs/quinn/blob/quinn-0.11.12/quinn/src/connection.rs#L558-L565)
   returns a clone for inspection; the inspected public API has no setter for
   replacing the live controller after Hysteria authentication. A preinstalled,
   per-connection delegating controller with independently owned state is a
   possible transition point from BBR to Brutal, subject to correct timer and
   wakeup behavior.
4. Delaying or queueing sends solely in an `AsyncUdpSocket` wrapper needs
   careful validation. Quinn's
   [packet tracking](https://github.com/quinn-rs/quinn/blob/quinn-proto-0.11.19/quinn-proto/src/connection/packet_builder.rs#L205-L249)
   records the send time and arms loss detection while constructing the
   transmit, before the runtime
   [polls socket readiness and sends](https://github.com/quinn-rs/quinn/blob/quinn-0.11.12/quinn/src/connection.rs#L1025-L1068).
   Long additional delays may distort RTT and loss recovery. Existing Gecko
   segmentation and queuing make the interaction worth measuring. This is a
   risk to test, not a claim that ordinary socket backpressure is always wrong.

## Local metric experiment

A temporary standalone loopback probe used Rust 1.100.0, `quinn` 0.11.12
with default features disabled and `runtime-tokio` and `rustls-aws-lc-rs`
enabled, `quinn-proto` 0.11.19, Tokio 1.54.1, the workspace-patched
`rustls` 0.23.46 with AWS-LC, and `rcgen` 0.14.10 for a self-signed test
certificate. The probe source was temporary and is not a checked-in script.

To reconstruct the experiment, create a custom controller with a constant
131,072-byte congestion window and expose a `ControllerMetrics.pacing_rate`.
For each of two independent short-lived QUIC connections, complete the TLS
handshake before starting the timer; then send 524,288 bytes, read them at the
server, and stop timing after the end notification. Keep the controller and
connection conditions fixed except for changing the metric from 8,000 to
800,000,000 bits per second. Each run took approximately 9 ms. At 8,000 bits
per second the payload alone corresponds to approximately 524 seconds at a
steady rate, before accounting for any initial burst or protocol overhead.
This limited comparison supports the source reading that changing the metric
alone does not set the pacer; it is neither a WAN test nor a performance claim.

## Candidate implementation and validation

Prefer an upstream Quinn change, or a narrowly maintained `quinn-proto` patch
if necessary, over introducing a second broad runtime dependency. A candidate
would extend `src/congestion.rs` with a default-off independent pacing policy
and an exact lost-packet-count callback, then update `src/connection/pacing.rs`
and `src/connection/mod.rs` to apply it during normal transmission. Preserve
the existing policy for all controllers that do not opt in. An Hysteria2-only
per-connection delegating controller could start with BBR and transition after
authentication. The implementation must define token accounting across that
transition, MTU and rate changes, and connection wakeups. Determine whether a
small Quinn runtime-facade change is also needed to update and wake the live
connection safely; do not assume that a shared variable alone handles timers.
An upstream contribution or patch requires review for API compatibility and
correctness before adoption.

Validation should include:

- Deterministic virtual-time token-bucket cases for initial budget, burst cap,
  timer rounding, rate and MTU changes, arithmetic saturation, and the
  BBR-to-Brutal transition; five-slot aging, fewer than 50 samples, the
  50-sample boundary, the 0.8 floor, ECN and packet eligibility.
- A controlled UDP relay with repeatable RTT, loss and reordering. Record QUIC
  bytes separately from outer UDP/IP and obfuscation bytes, and inspect GSO,
  bursts, timers and retransmission behavior, including any wrapper queues.
- Independent sing-box Hysteria2 TCP and UDP peers covering authentication,
  response `0`, `auto` and nonzero rates, local settings and server settings,
  cancellation, IPv4 and IPv6, Salamander, Gecko and port hopping. Check that
  the emitted hint and the selected upload behavior match the chosen policy.
- Regression checks for Quinn's unmodified default controllers and the other
  protocols using them. Compare the numeric and `auto` branches against the
  inspected upstream client. If PathChord retains a stricter server-rate
  policy or chooses BBR with a separately verified cap, document and diagnose
  that difference explicitly.

## Implementation follow-up

The local implementation now vendors `quinn-proto` 0.11.19 with opt-in
controller hooks for an independent pacer, exact ACK-eliciting loss counts,
the send-window test, and a per-packet switch marker. The marker prevents ACKs
or losses from packets sent before the BBR-to-Brutal switch entering the new
controller's sample. This matches the switch fence in the `sagernet/quic-go`
version used by sing-box 1.14.4. The default methods retain Quinn's normal
pacer and window behavior. See [the patch record](../../../../../vendor/quinn-proto/PATHCHORD-PATCH.md)
and [the Brutal controller](../../../../../crates/pathchord-transit/src/hysteria2_brutal.rs).
The Hysteria2 connection begins with BBR and switches after authentication to
the negotiated nonzero Brutal target. Numeric response `0` uses the configured
upload rate; a positive response uses the smaller of that value and the
configured rate; a configured rate of zero, or an `auto` response, keeps BBR.
This follows the inspected sing-box behavior and makes `up_mbps` a negotiated
input, not a guaranteed cap when the server requests `auto`.

The local validation on 2026-11-16 used sing-box 1.14.4 as an independent
server. A six-case authentication matrix covered `auto`, zero and nonzero
rates on both sides. TCP and UDP exchanges also passed with Brutal selected
and each of Salamander and Gecko. A pinned UDP association remained usable
across two hopping relays in both BBR and Brutal modes. A separate loopback
UDP relay added 10 ms in each direction: at a negotiated 1 Mbps, a 512 KiB
transfer took 4.22 seconds without induced loss and 4.29 seconds with every 17th outgoing datagram
dropped and every 23rd delayed by an additional 25 ms. The latter recorded 40
QUIC losses, observed actual relay reordering and delivered the complete data.
The controller's sample state included those losses. A no-added-delay
loopback run took approximately 9.4 seconds at an RTT near 0.4 ms, illustrating
the effect of a very small calculated window and ACK scheduling. These timings
are local experiments, not WAN or deployed performance claims.

Deterministic controller tests cover initial burst, minimum timer delay, idle
and MTU changes, bounded arithmetic, per-connection switching, packet sample
aging and the 50-sample threshold, the 0.8 ACK floor, and ECN exclusion. A
standalone copy of the patched Quinn crate passed 305 upstream library tests
and two additional virtual-network tests covering a delayed pre-switch ACK and
pre-switch loss after a reordering event. Both added tests fail when their
respective old packets are incorrectly tagged as post-switch. The copy used the
workspace-patched rustls and its own resolved test dependencies. The sing-box
TUIC fixture also passed for its cubic, NewReno, and BBR variants. These checks
do not establish every possible interaction with
the patch. In particular, a controller switch without a subsequent application
write, live QUIC path migration or reset, WAN scheduling, and all custom
controller integrations have not been independently verified. The packet marker
distinguishes the initial BBR-to-Brutal switch; it is not a separate generation
for a later path reset.
