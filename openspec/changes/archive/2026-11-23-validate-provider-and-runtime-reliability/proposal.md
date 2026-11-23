# Proposal

## Why

Local protocol fixtures do not cover the complete real-provider parameter matrix or long-lived failures and restarts. Collect the remaining interoperability and reliability evidence without introducing a compatibility runtime.

## What changes

Exercise real provider exports, independent protocol server peers, cross-machine flows, and failure/restart soak tests. Extend native coverage one protocol/parameter combination at a time while retaining explicit unavailable-node diagnostics.

## Capabilities

### New capabilities

None. This change carries over implementation/validation work for existing contracts.

### Modified capabilities

None. `skip_specs: true` applies while normative behavior is unchanged; add the relevant deltas before any required contract change.

## Impact

Existing transit-proxies, protocol, state-machines and configuration contracts; test-only peer harnesses, fixtures and status evidence. SSR stays retired and third-party policy graphs are outside node import.
