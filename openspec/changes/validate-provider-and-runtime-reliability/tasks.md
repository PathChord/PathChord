# Tasks

These pending tasks were carried over from the implementation plan during the
2026-11-14 documentation migration; their presence supplies no completion evidence.

## 1. Provider and peer matrix

- [ ] 1.1 Collect sanitized real-provider cases for URI/Base64, Clash/Mihomo HTTP providers, SIP008, sing-box and supported Surge/Quantumult X/Loon text nodes; verify successful siblings, unsupported-node diagnostics, fetch budgets and credential origin boundaries.
- [x] 1.2 Extend independent peer fixtures for the remaining native protocol/TLS/REALITY/transport combinations using test-only sing-box, Mihomo, Xray and V2Fly servers where supported; verify no peer binary becomes a runtime or Cargo dependency.
- [x] 1.3 Exercise cross-machine native REALITY, Hysteria2, TUIC, AnyTLS and VMess TCP/UDP cases; verify incomplete parameter combinations remain explicitly unavailable and preserve SSR retirement.

## 2. Long-lived failure and restart checks

- [x] 2.1 Run Path churn, endpoint restart, authorization revoke and node-draining soak tests through explicit listeners; verify Session/resource closure, bounded task/buffer growth and correct replacement identities.
- [x] 2.2 Inject provider fetch/parse failures, DNS route failures and configuration reloads during live traffic; verify last-good snapshots, generation barriers, cache/accounting consistency and credential redaction.
- [x] 2.3 Record local-fixture, external-peer, cross-machine and long-running evidence separately in openspec/implementation-status.md with revisions and reproducible commands; verify unresolved matrix entries remain explicit.
