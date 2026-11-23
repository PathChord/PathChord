# Design

## Context

The [status snapshot](../../implementation-status.md) distinguishes local fixtures, ignored external-peer tests, and missing cross-machine/soak coverage. Exact format and parameter boundaries belong to the [Transit Proxy contract](../../specs/transit-proxies/spec.md); backend source comparisons are [research evidence](research/rust-outbound-backends.md).

## Goals / non-goals

Validate existing native adapters and fill incomplete combinations against the established contract. SSR stays explicitly retired. Do not import third-party policy groups, routes, scripts, detour graphs or local-file providers. A new behavior or protocol contract requires its own delta before implementation.

## Decisions

Start from native platform/listener smoke evidence, then expand provider/peer cases and run long-lived failure tests. Capture sanitized provider exports for URI/Base64, inline Clash, SIP008, sing-box, Surge and Loon. Use a fixture based on the Mihomo documentation for referenced HTTP providers. Quantumult X falls outside this release acceptance matrix. Verify bounded fetch expansion, credential origin boundaries, redaction, source metadata, cache state and unsupported-node diagnostics.

Independent sing-box, Mihomo, Xray and V2Fly binaries are test-only server peers, each limited to its native server protocols; they never enter the runtime or Cargo dependency graph. Keep local fixtures, cross-machine sessions and prolonged soak results separate. Extend REALITY, Hysteria2, TUIC, AnyTLS and VMess parameter coverage through narrow native adapters with exact validation.

## Risks / trade-offs

- Provider exports contain credentials → sanitize retained fixtures and verify all diagnostics and read APIs redact private material.
- Unsupported options can appear to work through a downgrade → require the adapter to consume each option or expose a typed node diagnostic.
