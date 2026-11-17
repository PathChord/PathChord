# Design

## Context

See [the proposal](proposal.md) for the motivation and scope. The current
Ingress implementation already has unconditional Egress warmup and a
`reserved_path_target` helper that adds one Path to the minimum. The
autoscaler accepts a target separate from its minimum and can drain one Path
after stabilization and cooldown. Configuration exposes only the minimum,
and Session observations can obtain their target from a different snapshot
than the Ingress maintenance target.

Relevant implementation seams are
[native resource parsing](../../../crates/pathchord-policy/src/config.rs),
[service settings](../../../crates/pathchord-policy/src/service_config.rs),
[typed options](../../../crates/pathchord-policy/src/transit_options.rs),
[Ingress maintenance](../../../crates/pathchord-ingress/src/data_plane.rs), and
[capacity scaling](../../../crates/pathchord-path/src/autoscale.rs).
Both role binaries and the workspace CLI contain service configuration and
observation consumers. Subscription caches embed serialized native options,
so changing their public serde names also changes the normalized cache format.

## Goals / non-goals

Goals are a single canonical native configuration shape, a configurable idle
Path baseline independent of admission, one authoritative runtime planning
snapshot, and deterministic validation and migration evidence. Keep default
idle behavior equivalent to the existing minimum-plus-one reserve.

This change does not redesign route actions or selector expressiveness, move
ordinary protocol parameters out of private credentials, change credential
JSON or foreign subscription syntax, rename CLI flags, add a public Path
maximum, add a separate standby Path class, or change wire layouts. The
remaining routing vocabulary and credential-layout work require separate
behavioral designs. Existing `bind`/`binds` forms retain their current
mutual-exclusion contract.

## Decisions

### Use a grouped Egress Path pool

Use `Egress.spec.pathPool.minUsablePaths` and `targetUsablePaths`, and move the
existing capability requirement to `admission.requiredCapabilities`. The
complete field table and retirement mappings are in the
[configuration-schema delta](specs/configuration-schema/spec.md).

```yaml
apiVersion: pathchord.io/v1
kind: Egress
metadata:
  name: exit
spec:
  endpoints:
    - host: egress.example.net
      port: 7443
  publicKey: REPLACE_WITH_EGRESS_PUBLIC_KEY
  capabilities: {tcp: true, udp: true}
  pathPool:
    minUsablePaths: 1
    targetUsablePaths: 3
  admission:
    requiredCapabilities: [tcp]
  transit:
    require:
      capabilities: [tcp]
  trafficPolicyRef: default
```

`requiredCapabilities` retains the existing common Egress eligibility check;
it does not imply that the Transit adapter must provide native UDP. `pathPool`
makes the count relationship visible while the two names explicitly count
the same eligible authenticated non-draining `ACTIVE`/`DEGRADED` Paths. Keeping
`statusRequirements` and adding a top-level `targetPathCount` was rejected
because it separates the related counts and leaves their counted population
ambiguous. A single minimum-and-target field was rejected because it would
make optional warm redundancy an admission requirement.

Explicit counts are positive unsigned 32-bit integers, and an explicit target
must be at least the minimum. Resolve an omitted target with wider unsigned
arithmetic, preserving `4294967296` for the extreme default case rather than
overflowing. Preserve the authored optional value where useful for config
roundtripping, but compare normalized policy fingerprints using the resolved
requested baseline. Explicitly writing the default does not change policy.

### Bound a baseline without turning it into a maximum

Use the following values in one Egress-owned planning state:

| Symbol | Meaning |
|---|---|
| `M` | configured minimum for count-based business admission |
| `R` | requested baseline: explicit target, otherwise `M + 1` |
| `H` | most restrictive known runtime/negotiated Path ceiling |
| `B` | effective baseline, `min(R, H)` |
| `D_up`, `D_down` | current direction-specific capacity requirements when known |
| `T` | current bounded demand target, `min(H, max(B, D_up, D_down))` |
| `U` | current usable non-draining Path count |

Unknown demand is not a measured zero. During idle startup without capacity
evidence, maintain `B` and retain the existing provisional/unknown capacity
contract. Do not fabricate a capacity estimate to justify baseline Paths or
unbounded load-driven expansion. The local runtime maximum remains finite;
peer resource failures do not grant permission to increase it.

`R` remains visible when `H < R`; do not silently rewrite configuration to
`B`. Count-based admission depends on `M`, not `R` or `T`. A ceiling below
`M` retains the existing minimum-shortfall behavior. Optional extra-copy
budgets remain independent of Path count. All admitted Paths use the common
pool and existing relationship weights; several Paths through one Transit
can satisfy the counts without claiming independent failure domains.

The alternative of treating the target as a maximum would prevent useful
capacity expansion. Replacing it with a spare-count setting was rejected
because operators asked to configure the total desired idle pool directly.

### Reuse bounded maintenance and gradual draining

Replace all minimum-plus-reserve calculations in Session creation, warmup,
failure recovery, adapter retirement, and Session reset with the same resolved
baseline. Recompute `T` from current demand instead of retaining its historical
peak. One planning owner supplies both maintenance decisions and observations;
an actor snapshot initialized to a constant target must not overwrite it.

Warmup and refill remain independent of business route matches. Try eligible
Transit and endpoint candidates under existing dial timeouts, bounded work,
backoff, authorization/trust guards, admission state, and hard limits. Pending
attachments and still-open draining Paths consume their resource slots. A
failed or no-longer-eligible Path is removed from usable counting before a
replacement is planned. Prefer existing candidate balancing without requiring
a different Transit relationship for every Path.

Baseline refill can start before the capacity shortfall hysteresis window;
it is maintenance, not evidence of demand. Capacity expansion still uses the
configured consecutive-sample guard. A known marginal capacity below overhead
remains an exclusion; zero idle throughput alone is not such evidence.

Capacity contraction uses its separate surplus window, recovery stabilization,
and cooldown and drains at most one Path per decision. Recheck all selected
drains against `B`, `M`, and remaining directional capacity. Use the existing
drain deadline and ordinary reliability machinery for accepted traffic. Hard
failure, resource enforcement, administrative drain, and authorization revoke
retain their own precedence and can reduce the pool below its baseline.

Both Path-pool counts and capability requirements are startup settings. A
semantic change reports restart required and retains the entire active bundle.
Hot target updates were considered but would add a new live reconfiguration
contract to a change focused on naming and idle maintenance.

### Make native names precise and reject retired keys

Apply the exhaustive mapping in the schema delta: endpoint `address` becomes
`host`; EgressService `web...` fields move into `web`; native option names
identify list cardinality, bytes, version, and ClientHello profile. The
[Transit delta](specs/transit-proxies/spec.md) preserves complete option
semantics. TLS `certificates` remain extra trust anchors, while
`clientCertificates` remain the client-authentication chain.

Keep the resource API version at `pathchord.io/v1` for this repository cleanup
and publish a breaking migration. Backward compatibility with the old native
configuration is not required; do not add aliases, legacy schema readers, or
an automatic compatibility translator for retired fields.
Reject retired keys even alongside their canonical replacement or when empty.
Provide `CONFIG_RETIRED_FIELD`, exact resource field path, and replacement path
without values. Implement this as structural native-resource validation or
equivalent typed error mapping; the current generic YAML error mapped to `$`
is insufficient. Never recursively rewrite strings, maps, private documents,
HTTP headers, labels, protocol tokens, or imported source syntax.

Move Web children without changing precedence, defaults, token/origin checks,
or relative-path resolution. For example, `--web-token-file` still overrides
`web.tokenFile`. Update both the current role binaries and legacy workspace
CLI resolvers; preserving flags does not preserve retired YAML aliases.

### Version normalized subscription caches explicitly

The current version-2 cache embeds `TransitProxyConfig.options`, and typed
payload deserialization precedes its version check. Write a new version-3
normalized cache and inspect the bounded envelope/version before interpreting
its payload. Version-2 caches are incompatible with this native schema and
must return a sanitized `cache_incompatible` diagnostic. Do not add native
serde aliases just to deserialize an old cache.

Never publish nodes from an incompatible cache. Retain only an independently
valid active snapshot for the same subscription source, and perform the
existing bounded authenticated refresh when management state permits it.
Cold offline startup cannot promote incompatible cached nodes. Disabled or
deleted subscriptions remain disabled or deleted; refreshing does not erase
their durable decisions, bypass source fingerprints, expand download budgets,
or cross credential origins. Private credential documents are unchanged and
remain private in the new cache.

### Publish baseline intent and current target separately

The [observation delta](specs/observability/spec.md) and
[control delta](specs/ingress-control-plane/spec.md) define one coherent field
set. Keep existing `minimum_usable_paths`, `usable_path_count`, and
`target_path_count`; add `requested_target_usable_paths`,
`effective_target_usable_paths`, `target_shortfall`, and a nullable typed
`target_shortfall_reason`. The requested field is the resolved configured
baseline, so another raw nullable configured-target field is unnecessary.

`target_shortfall = max(R - U, 0)` measures baseline shortfall, not an unmet
load target. When it is positive, choose the first applicable reason in this
order: `runtime_limit`, `admission_blocked`, `no_eligible_transit`,
`connect_failed`, `recovering`. The reason is null when the shortfall is zero.
Failure reasons come from the current refill/backoff state and reset after
successful recovery or Session replacement; arbitrary transport messages do
not become metrics labels. These fields never mutate health or admission.

Supply query rows, events, drill-down views, and low-cardinality metrics from
the same bounded planning snapshot. Keep control-plane snake_case naming
separate from resource YAML camelCase. No fake authenticated Session is
created to show a configured Egress with no live Session. Existing configured
resource observations can show configuration without claiming readiness.
Remove the stale Egress-recommended-Path metric from the normative registry
when reconciling the main observation contract.

## Risks / trade-offs

- Breaking YAML names interrupt old configurations on the new binary ->
  provide the exact migration table, strict retired-key diagnostics, migrated
  repository examples and packaging fixtures, and parser/reload regressions.
- Canonical option serde names also affect cached private data -> version the
  envelope before typed decoding and test cold failure, source-bound refresh,
  and preservation of durable disable/delete decisions.
- A target shortfall can be mistaken for a health failure -> separate baseline
  diagnostics from minimum, Path-quality, authorization, and admission checks.
- Repeated failed warmup can consume resources while idle -> bounded dialing,
  exponential backoff, admission guards, and in-flight slot accounting.
- Separate target copies can drift -> publish one Egress-owned planning state
  through both runtime snapshots and management producers.
- Local default timing is not production capacity evidence -> deterministic
  tests cover guards and cooldown; tuning and deployed validation remain
  separate from this implementation's local verification.

## Migration plan

1. Implement schema/model changes, migration diagnostics, and semantic
   normalization together; migrate native examples, generated fixtures, role
   resolvers, and adapter/import consumers before accepting the new surface.
2. Implement baseline maintenance and observations against the same resolved
   configuration; run deterministic no-flow, shortfall, load, drain, reset,
   resource-limit, and candidate-failure tests.
3. Write cache version 3, reject old envelopes safely, and verify bounded
   refresh/restart behavior with source and management decisions preserved.
4. Merge the English deltas into their existing capability specs, reconcile
   obsolete Detailed contract tables and examples, and synchronize Chinese
   counterparts, affected design/guides, and implementation-status evidence.
5. Validate the migrated configuration before an operator restarts either
   daemon. No live deployment is part of this planning request. Rollback pairs
   the prior binary with its prior native configuration; incompatible caches
   are refreshed under that binary's own rules. Private credentials and durable
   authorization/subscription management state require no format migration.
