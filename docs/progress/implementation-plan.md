# PathChord implementation plan

This document tracks the remaining implementation and validation sequence.
Final-state requirements remain under `docs/design/` and `docs/spec/`.

## Current sequence

1. Validate the assembled Ingress platform runtime on privileged Linux and on
   Windows hosts, including TPROXY/TUN, Named Pipe ACL, WinINet refresh, and
   crash recovery.
2. Run long-lived failure and restart tests for Path churn, authorization
   revoke, subscription draining, DNS route failure, and configuration reload.
3. Exercise real subscription providers and publish operational metrics and
   structured dashboards.
4. Define and review a final transport schema plus interoperability fixtures
   before enabling VLESS, VMess, or XTLS adapters.

## Completed foundations

- Protocol and wire-profile vectors.
- Noise admission and zeroization migration.
- Single- and multi-Path TCP/UDP Session runtime.
- Ordered policy compilation and dynamic subscription normalization.
- Durable Ingress/Egress control planes and local/Web adapters.
- Linux transparent/TUN platform modules and supervised node assembly.

## Deferred by design

VLESS/VMess/XTLS transport fields, external interoperability profiles,
platform-specific packaging details, production probe intervals, and deployed
autoscaler constants remain deferred until the validation sequence supplies
the required evidence.
