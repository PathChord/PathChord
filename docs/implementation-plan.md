# PathChord Implementation Plan

## Phase 0: protocol and test fixtures

- Freeze frame/state-machine specifications.
- Define deterministic test vectors for Noise handshakes and framing.
- Define error mapping for HTTP, SOCKS, TUN, TCP, and UDP.
- Build a fake Transit transport and fake Egress for fault injection.

## Phase 1: single-path Egress

- Ingress/Egress Noise connection.
- Session attach and status reporting.
- One TCP Stream and one UDP session.
- Correct FIN/RST, half-close, reset, and restart semantics.

## Phase 2: adapters

- Linux HTTP/SOCKS.
- Linux TPROXY/REDIRECT.
- Windows TUN.
- Windows system-proxy integration.
- Internal outbound loop prevention.

## Phase 3: dynamic data and rules

- Static Egress topology.
- Subscription cache and Clash/SIP008 normalization.
- Name-based tag/label annotations.
- Compiled ordered Egress and Proxy rules.
- Runtime snapshots and listener IDs.

## Phase 4: multipath

- Multiple Paths per Proxy and Egress.
- Stream offsets, ACK ranges, reordering, and cross-Path retransmission.
- Egress downstream scheduling.
- Drain and per-Stream path admission.

## Phase 5: observation and autoscaling

- Path RTT/jitter/loss/throughput observations.
- Egress status reports and per-Ingress limits.
- Effective-capacity calculation.
- Aggressive path admission, fast quality downgrade, stabilized recovery, cautious scale-in.
- Quota and traffic-multiplier metadata.

## Phase 6: control and operations

- Manual public-key enrollment on both ends.
- Dynamic Egress authorization list.
- Status and diagnostics CLI.
- Crash cleanup and network restoration.
- Compatibility, restart, partition, proxy deletion, and quota tests.

## Deferred implementation choices

The design does not yet select the implementation language, Noise library, rule VM, control-plane encoding, database format, proxy adapter libraries, exact probe intervals, buffer sizes, or autoscaler constants.
