# Proposal

## Why

Cross-compilation and portable listener fixtures do not establish native operating-system behavior. Complete the outstanding Windows, FreeBSD, and privileged Linux evidence for the existing platform contract.

## What changes

Validate ordinary HTTP forwarding/CONNECT, SOCKS4/4a/5, Mixed and SOCKS5 UDP, platform control, and privileged transparent/TUN operation. Preserve the optional eBPF boundary and ordinary TPROXY fallback.

## Capabilities

### New capabilities

None. This change carries over implementation/validation work for existing contracts.

### Modified capabilities

None. `skip_specs: true` applies while normative behavior is unchanged; add the relevant deltas before any required contract change.

## Impact

Existing platform-and-dns, deployment, and state-machines contracts; platform harnesses and the implementation-status snapshot. Native-host execution remains unchecked until evidence is collected.
