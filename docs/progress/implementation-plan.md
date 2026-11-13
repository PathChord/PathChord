# PathChord implementation plan

This document tracks the remaining implementation and validation sequence.
Final-state requirements remain under `docs/design/` and `docs/spec/`.

## Current focus

Prioritize HTTP forwarding/CONNECT and SOCKS listeners on Linux, Windows, and
FreeBSD.
The SOCKS listener accepts SOCKS4/4a/5 CONNECT and SOCKS5 UDP ASSOCIATE;
deferring transparent UDP does not defer SOCKS5 UDP forwarding. FreeBSD uses
the same listener surface and Unix local control. `type: mixed` shares one TCP
endpoint across HTTP and SOCKS with the same authentication and flow context.

| Platform | Listener target | Local control | Validation state |
| --- | --- | --- | --- |
| Linux | HTTP forwarding/CONNECT; SOCKS4/4a/5 CONNECT; SOCKS5 UDP ASSOCIATE | Unix socket | Automated loopback coverage exists; continue end-to-end and soak validation. |
| Windows | HTTP forwarding/CONNECT; SOCKS4/4a/5 CONNECT; SOCKS5 UDP ASSOCIATE | Named Pipe | Cross-checks and fake adapters exist; native listener, ACL, and system-proxy validation remain. |
| FreeBSD | HTTP forwarding/CONNECT; SOCKS4/4a/5 CONNECT; SOCKS5 UDP ASSOCIATE | Unix socket | Target compilation and CLI linking pass; native host validation remains. |

The explicit-listener baseline covers authentication, source restrictions,
IPv4/IPv6 and domain targets, policy and DNS routing, authenticated Egress
forwarding, bounded resources, cancellation, configuration reload, and local
control. Windows system-proxy integration selects one of these listeners.
FreeBSD explicit listeners do not require system-proxy integration or process
discovery; unavailable process facts remain unknown.

## Explicit proxy compatibility

Use the stable `sing-box` v1.14.4 source at
[`c005f35300ce76427dc285481ec5695f5b179cd2`](https://github.com/SagerNet/sing-box/tree/c005f35300ce76427dc285481ec5695f5b179cd2)
as the compatibility reference. Its
[`sing` dependency](https://github.com/SagerNet/sing-box/blob/c005f35300ce76427dc285481ec5695f5b179cd2/go.mod#L48)
is pinned to `5dc452e537bf75c5c51c54c8c4a4be1d19d85c4f`.

- Validate ordinary HTTP forwarding alongside CONNECT. The reference parses each
  request, requires an absolute URL for ordinary forwarding, routes the target
  through its connection handler, streams the request/response bodies, returns
  upstream redirects to the client, and maps transport failure to `502`.
  Cover HTTP/1.0 and HTTP/1.1, methods with bodies, chunked messages, early
  upstream responses, and sequential requests to different targets on one
  client connection. Sources:
  [request dispatch](https://github.com/SagerNet/sing/blob/5dc452e537bf75c5c51c54c8c4a4be1d19d85c4f/protocol/http/handshake.go#L32-L134),
  [forwarding and body lifecycle](https://github.com/SagerNet/sing/blob/5dc452e537bf75c5c51c54c8c4a4be1d19d85c4f/protocol/http/handshake.go#L137-L251),
  [early-response regression](https://github.com/SagerNet/sing/blob/5dc452e537bf75c5c51c54c8c4a4be1d19d85c4f/protocol/http/handshake_test.go#L67-L165).
- Validate stripping proxy credentials and hop-by-hop fields, including fields named by
  `Connection`, from forwarded ordinary requests and responses. Authenticate
  HTTP requests through the existing local credential verifier and preserve
  bounded parsing and credential redaction. The reference enables local
  keep-alive through `Proxy-Connection: keep-alive`; explicit message framing
  and per-request policy evaluation remain required. Sources:
  [Basic authentication](https://github.com/SagerNet/sing/blob/5dc452e537bf75c5c51c54c8c4a4be1d19d85c4f/protocol/http/handshake.go#L37-L65),
  [header filtering](https://github.com/SagerNet/sing/blob/5dc452e537bf75c5c51c54c8c4a4be1d19d85c4f/protocol/http/handshake.go#L254-L274).
- Validate SOCKS4 and SOCKS4a CONNECT compatibility while retaining
  SOCKS5 CONNECT, username/password authentication, and UDP ASSOCIATE. The
  reference's `socks` inbound includes all three versions; its handlers reject
  BIND. SOCKS4/4a encode a bounded NUL-terminated user ID and optional domain,
  but carry no password. Reject them when PathChord listener authentication is
  required, and do not treat an unverified user ID as an authenticated identity.
  Sources:
  [SOCKS inbound](https://github.com/SagerNet/sing-box/blob/c005f35300ce76427dc285481ec5695f5b179cd2/docs/configuration/inbound/socks.md),
  [command and authentication handling](https://github.com/SagerNet/sing/blob/5dc452e537bf75c5c51c54c8c4a4be1d19d85c4f/protocol/socks/handshake.go#L140-L289),
  [SOCKS4a address and string bounds](https://github.com/SagerNet/sing/blob/5dc452e537bf75c5c51c54c8c4a4be1d19d85c4f/protocol/socks/socks4/protocol.go#L47-L80).
- Retain PathChord's successful-open-before-CONNECT-response, trusted socket
  peer identity, UDP peer/port binding, and strict reserved/fragment validation.
  The reference is an interoperability guide, not a requirement to reproduce
  its early CONNECT success, header-derived source identity, error credential
  formatting, or unchecked UDP reserved/fragment fields. Sources:
  [CONNECT dispatch](https://github.com/SagerNet/sing/blob/5dc452e537bf75c5c51c54c8c4a4be1d19d85c4f/protocol/http/handshake.go#L68-L98),
  [source address handling](https://github.com/SagerNet/sing/blob/5dc452e537bf75c5c51c54c8c4a4be1d19d85c4f/protocol/http/addr.go#L10-L22),
  [UDP decoding](https://github.com/SagerNet/sing/blob/5dc452e537bf75c5c51c54c8c4a4be1d19d85c4f/protocol/socks/packet.go#L75-L89).

Mixed-protocol port detection reuses ordinary HTTP/SOCKS handling on one TCP
listener. Validate the same authentication and UDP boundaries on the shared
endpoint. TLS termination and automatic system-proxy configuration remain
separate listener/platform options; preserve the existing platform boundaries. Sources:
[HTTP options](https://github.com/SagerNet/sing-box/blob/c005f35300ce76427dc285481ec5695f5b179cd2/docs/configuration/inbound/http.md),
[mixed options](https://github.com/SagerNet/sing-box/blob/c005f35300ce76427dc285481ec5695f5b179cd2/docs/configuration/inbound/mixed.md).

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
