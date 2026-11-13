# PathChord implementation plan

This document tracks the remaining implementation and validation sequence.
Final-state requirements remain under `docs/design/` and `docs/spec/`.

## Current focus

Prioritize HTTP forwarding/CONNECT, SOCKS4/4a/5, and same-port mixed listeners
on Linux, Windows, and FreeBSD. SOCKS5 UDP includes ordinary native Proxy and
direct forwarding as well as Session UDP through a controlled Egress.
Transparent interception and TUN work follow this explicit-listener baseline.

| Platform | Explicit listeners | Local control | Remaining platform validation |
| --- | --- | --- | --- |
| Linux | HTTP, SOCKS, mixed | Unix socket | Cross-machine and long-running failure/provider tests. |
| Windows | HTTP, SOCKS, mixed | Named Pipe | Native forwarding, ACLs, configuration watcher, and system-proxy recovery. |
| FreeBSD | HTTP, SOCKS, mixed | Unix socket | Native forwarding, SQLite/socket permissions, watcher, and signals. |

The [Transit Proxy contract](../spec/transit-proxies.md) owns the exact native
and optional engine parameter/format boundaries. The
[deployment guide](../spec/deployment.md) and `examples/` provide direct,
subscription, and enrolled Egress entry points. Portable regressions run in
the existing Rust CI job; target compilation/linking and native host execution
are recorded separately in [status](status.md).

## Current sequence

1. Complete native Windows and FreeBSD explicit-listener validation. Cover
   authentication, source restrictions, IPv4/IPv6 and domain targets, DNS,
   reload, bounded resources, shutdown, and local management. Validate Windows
   Named Pipe ACLs, WinINet refresh, and crash recovery on a real host.
2. Exercise real provider exports across URI/Base64, Clash HTTP providers,
   SIP008, sing-box, and supported text node formats. Extend interoperability
   fixtures for the remaining protocol/TLS/Reality/transport combinations and
   different engine build feature sets; unsupported options must remain
   explicit per-node diagnostics.
3. Run long-lived failure and restart tests for Path churn, authorization
   revoke, provider failures, node draining, DNS route failure, configuration
   reload, and external engine restart/cleanup. Verify cache and accounting
   metadata remain consistent without leaking credentials.
4. Define explicit flow-to-class selection and negotiated bidirectional class
   metadata before implementing complete TrafficPolicy priority/share
   scheduling. Preserve independent control sending, bounded per-stream FIFO,
   FIN ordering, low-priority progress, and loss/retransmission behavior.
5. Connect the Prometheus endpoint and structured observations to deployed
   monitoring, alerts, and dashboards. Keep live gauges distinct from
   historical counters, and measure production probe/autoscaler constants.

## Deferred work

- TPROXY, REDIRECT, transparent UDP interception, and TUN integration follow
  explicit-listener validation. Privileged route validation, journal recovery,
  and Wintun packaging are outside the active acceptance scope.
- Additional FreeBSD transparent interception or TUN support needs a separate
  platform assessment.
- Further native protocol implementations need maintained libraries and
  protocol-specific interoperability evidence. SSR and unregistered protocols
  remain explicitly unavailable. Third-party policy groups, routes, scripts,
  external detour graphs, and local-file providers are outside node import.
