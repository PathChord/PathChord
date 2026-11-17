# Proposal

## Why

PathChord's public configuration uses a consistent casing style but scatters related Path settings and mixes endpoint names, option units, and service-field grouping. Its runtime also maintains an implicit one-Path reserve that operators cannot configure independently of the admission minimum.

## What changes

- **BREAKING**: Group Ingress-side Egress Path settings under `pathPool.minUsablePaths` and `pathPool.targetUsablePaths`; move the existing capability requirement to `admission.requiredCapabilities` and reject the retired `statusRequirements` object with replacement diagnostics.
- Add a best-effort usable-Path baseline that is maintained without business connections. An omitted target requests the minimum plus one, subject to runtime ceilings; an explicit target receives no extra reserve. Target shortfall alone does not degrade service or deny new work while the minimum is met.
- Permit capacity-driven expansion above the baseline and gradual, drain-aware contraction back to it, preserving directional demand, health, backoff, resource ceilings, and Session restart semantics.
- **BREAKING**: Standardize remote endpoint hosts on `host`, group EgressService Web settings under `web`, and give selected native Transit option keys explicit collection, byte-unit, version, and ClientHello meanings. Backward compatibility with old native configuration is not required: publish an exhaustive migration table and reject retired YAML keys without aliases or an automatic compatibility translator.
- Distinguish requested baseline, effective bounded baseline, current demand target, and actual usable Paths in authorized Session queries, events, and monitoring, including typed target-shortfall reasons that do not alter health by themselves.
- Establish naming rules and reconcile field documentation, normalized output, examples, and diagnostics. Preserve foreign subscription syntax, protocol identities, private credential formats, routing action semantics, and existing CLI flags.

## Capabilities

### New capabilities

None. The change extends existing configuration, lifecycle, adapter, and observation capabilities.

### Modified capabilities

- `configuration-schema`: Canonical native key names, grouped Egress Path and admission settings, target defaults and validation, native-key retirement, and normalized restart behavior.
- `configuration`: Egress-owned best-effort Path baselines independent of business matches and admission minima.
- `state-machines`: Idle maintenance, bounded recovery, capacity expansion, gradual contraction, and reset behavior for the configured baseline.
- `transit-proxies`: Canonical public option names with unchanged transport, TLS, import, credential, and UDP semantics.
- `observability`: Distinct baseline, effective target, usable count, and non-health-affecting target-shortfall observations.
- `ingress-control-plane`: Typed query and event exposure of the same Session Path-pool planning state.

## Impact

Implementation will span `pathchord-policy` parsing, domain models, validation and normalization; `pathchord-ingress` startup, reload, Path maintenance, queries and events; `pathchord-path` scaling and snapshots; native `pathchord-transit` adapters and import normalization; and Egress service configuration resolution. Both current role binaries and legacy workspace CLI consumers must consume the same canonical configuration.

Existing native YAML files containing retired keys require edits before startup or reload. The resource API remains `pathchord.io/v1`; wire layouts, credentials, protocol identifiers, CLI flag spellings, route actions, and trust boundaries do not change. Implementation must update bilingual main specifications, affected design and user guides, examples, packaging fixtures, and the implementation-status snapshot. This change contains planning only and adds no dependency or deployment requirement.
