# Proposal

## Why

PathChord's first wire profile has not been released, but its current design still mixes Ingress policy decisions with Egress resource policy and contains several contract gaps around Session trust, Path ownership, capacity status, and replication budgets. Finalize these v1 semantics now so the first released implementation has one coherent ownership model instead of preserving incompatible provisional behavior.

## What Changes

- **BREAKING** Remove the unused `PathRebind`/`PathRebindAck` and TrafficClass wire extensions from v1; keep rule and class policy interpretation inside Ingress.
- **BREAKING** Negotiate a mandatory Session replication hard cap in `SESSION_ATTACH`/`SESSION_ATTACH_OK`; permit Egress to return a lower effective cap and publish a dynamic global replication allowance.
- **BREAKING** Replace the ambiguous status capacity and Path recommendation fields with explicit configured capacity, measured capacity state, current wire rate, and global admission fields.
- Define hard `down` Session failure, independent heartbeat/status freshness, stale-status admission blocking, Session trust failure for validated future ACKs, bounded Session rebuild, and circuit breaking.
- Separate Transit relationships from Path instances, support multiple Paths through one Transit relationship, and make rule-specific Path targets and bidirectional Path observations Ingress-owned.
- Make Egress a resource and forwarding owner with global wire bandwidth and inbound target-connection caps, internal Path safety ceilings, pending-open reservations, typed resource errors, and no cross-Ingress fairness promise.
- Remove Egress desired-Path and per-Ingress connection policy fields; derive Path targets from Ingress rules, demand windows, Path quality, and Egress hard ceilings.
- Define bounded per-Session Ingress demand aggregation and low-frequency hysteretic autoscaling without per-flow history or Egress rule knowledge.
- Make TLS truststore sources explicit (`system` by default plus local PEM/DER files), keep custom sources atomic and fail-closed, and add bounded local-control request deadlines.
- Synchronize the durable bilingual architecture and technology-selection documents with the finalized ownership and v1 resource model.

## Capabilities

### New Capabilities

None. This change finalizes and modifies existing PathChord capability contracts before the first release.

### Modified Capabilities

- `protocol`: Session failure, ACK validation, candidate failover, replication, and ownership behavior.
- `wire-profile`: v1 registry, Session budget negotiation, status schema, admission state, and removal of unused extensions.
- `state-machines`: lifecycle ownership, hard failure, degraded admission, PathSet behavior, and autoscaling guards.
- `configuration`: Ingress-owned rule/Path targets and explicit fallback/admission behavior.
- `configuration-schema`: Egress resource fields, truststore sources, global connection limits, and removal of desired-Path/per-Ingress fields.
- `observability`: global Egress resource status, capacity confidence, admission reasons, and bounded freshness.
- `ingress-control-plane`: local transport deadlines and resource-limit behavior.
- `transit-proxies`: intrinsic TLS roots, explicit truststore source handling, and fail-closed adapter preparation.

## Impact

The change affects `pathchord-core` wire/message codecs, `pathchord-path` Session/Path ownership and scheduling, `pathchord-policy` configuration and compiled routing, `pathchord-ingress` rule demand/Path management/control transport, `pathchord-egress` resource accounting and status production, `pathchord-transit` TLS construction, CLI configuration/reload wiring, bilingual design documents, and protocol/configuration/observability regression fixtures. It changes the unreleased v1 wire and configuration contracts, so no compatibility shim for an older PathChord implementation is required.
