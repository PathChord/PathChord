# Proposal

## Why

Provider nodes use protocol and transport combinations beyond the current
native Transit adapters. A supported protocol name alone does not establish
interoperability with sing-box and dae nodes or ensure that all imported
parameters are honored.

## What changes

- Complete compatibility with sing-box 1.14.4 and dae 2.1.2 connection
  options for protocols that already have native Transit adapters.
- Complete VLESS Vision flows, including direct TLS and REALITY transports,
  directional framing transitions and XUDP behavior.
- Normalize provider nodes without losing supported connection options, and
  keep unsupported or incomplete combinations unavailable with diagnostics.
- Verify each supported combination against an independent server where one
  exists, without importing a third-party proxy core into runtime, source
  dependencies, or release artifacts.
- Keep new outbound protocols, SSR, SOCKS4/4a, and layer-three VPN endpoints
  out of this change. Route selectors are local policy constructs.

## Capabilities

### New capabilities

None.

### Modified capabilities

- `transit-proxies`: Expand native outbound protocol, transport, credential,
  and subscription option behavior while retaining explicit diagnostics.
- `configuration-schema`: Add a bounded per-subscription HTTP User-Agent.
- `ingress-control-plane`: Preserve the configured User-Agent through control
  requests and durable subscription state.
- `configuration`: Allow bounded pre-admission failover among eligible
  ordinary Transit nodes while preserving policy generation and fallback rules.

## Impact

Transit adapters, typed options, subscription import and private credentials,
provider refresh, user guides, protocol fixtures, and implementation status.
External server binaries remain test-only; Egress deployment and builds stay
independent of the proxy engines.
