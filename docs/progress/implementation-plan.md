# PathChord implementation plan

This document tracks the remaining implementation and validation sequence.
Final-state requirements remain under `docs/design/` and `docs/spec/`.

## Current focus

Prioritize explicit HTTP CONNECT and SOCKS5 listeners on Linux, Windows, and
FreeBSD.
SOCKS5 includes CONNECT and UDP ASSOCIATE; deferring transparent UDP does not
defer SOCKS5 UDP forwarding. FreeBSD uses the same listener surface and Unix
local control.

| Platform | Listener target | Local control | Validation state |
| --- | --- | --- | --- |
| Linux | HTTP CONNECT; SOCKS5 CONNECT and UDP ASSOCIATE | Unix socket | Automated loopback coverage exists; continue end-to-end and soak validation. |
| Windows | HTTP CONNECT; SOCKS5 CONNECT and UDP ASSOCIATE | Named Pipe | Cross-checks and fake adapters exist; native listener, ACL, and system-proxy validation remain. |
| FreeBSD | HTTP CONNECT; SOCKS5 CONNECT and UDP ASSOCIATE | Unix socket | Target compilation and CLI linking pass; native host validation remains. |

The explicit-listener baseline covers authentication, source restrictions,
IPv4/IPv6 and domain targets, policy and DNS routing, authenticated Egress
forwarding, bounded resources, cancellation, configuration reload, and local
control. Windows system-proxy integration selects one of these listeners.
FreeBSD explicit listeners do not require system-proxy integration or process
discovery; unavailable process facts remain unknown.

## Current sequence

1. Verify the Linux and Windows explicit-listener baseline, including SOCKS5
   UDP ASSOCIATE, listener credentials, source restrictions, failure replies,
   DNS, shutdown, and control-plane operations. Validate Windows Named Pipe
   ACLs, WinINet refresh, and system-proxy crash recovery on a real host.
2. Validate HTTP/SOCKS5 forwarding, Unix
   socket permissions, persistence, configuration watching, and signal behavior
   on FreeBSD. Platform validation accepts `freebsd` and enforces the explicit
   listener matrix for both explicit platform selection and `any`. Record
   target build evidence separately from native runtime tests; cross-compiling
   native dependencies needs a target toolchain and sysroot. Portable listener
   regressions run in the existing Rust CI job; native FreeBSD validation is a
   separate host exercise.
3. Run long-lived failure and restart tests through HTTP/SOCKS5 for Path churn,
   authorization revoke, subscription draining, DNS route failure, and
   configuration reload on the validated platforms.
4. Complete the shared runtime gaps after the listener baseline: TrafficPolicy
   class priority/share scheduling, subscription quota/billing ingestion and
   publication, and production metric export and monitoring integration.
5. Define and review a final transport schema plus interoperability fixtures
   before enabling VLESS, VMess, or XTLS adapters.

## Completed foundations

- Protocol and wire-profile vectors.
- Noise admission and zeroization migration.
- Single- and multi-Path TCP/UDP Session runtime.
- Ordered policy compilation and dynamic subscription normalization.
- Durable Ingress/Egress control planes and local/Web adapters.
- FreeBSD explicit-listener configuration, platform identity, unsupported
  system-proxy behavior, target compilation/linking, and portable regression
  coverage.
- Linux transparent/TUN platform modules and supervised node assembly.

## Deferred work

- TPROXY, REDIRECT, transparent UDP interception, and TUN integration follow
  the explicit-listener baseline. Their privileged routing validation, route
  journal recovery, and Wintun packaging are outside the active acceptance
  scope, even where implementation modules already exist.
- Additional FreeBSD transparent interception or TUN support needs a separate
  platform assessment after HTTP/SOCKS5 portability is established.
- VLESS/VMess/XTLS transport fields and external interoperability profiles
  follow the explicit-listener baseline and require the schema and fixtures
  above. Production probe intervals and deployed autoscaler constants still
  require operational evidence.
