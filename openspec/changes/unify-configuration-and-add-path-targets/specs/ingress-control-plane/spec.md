# Ingress control-plane delta

## MODIFIED Requirements

### Requirement: Bounded typed resource queries

Queries SHALL expose stable resource identities, typed fields, owning generations or revisions, and bounded pagination, filtering, and deterministic sorting. Unknown query or filter keys, unsupported sort fields, invalid page tokens, and out-of-range page sizes SHALL return `VALIDATION_FAILED`. Label/tag mutations SHALL preserve the ownership of source, observation, quota, and hard-state fields. Session queries and events SHALL expose the same typed Path-pool planning state.

#### Scenario: Unknown list query field

- **WHEN** a list request includes an unregistered query field
- **THEN** the service rejects the request with `VALIDATION_FAILED` instead of ignoring the field.

#### Scenario: Inspect an idle Session Path pool

- **WHEN** an authorized client reads a Session that has no active business connections
- **THEN** its list/detail representation exposes the common minimum, requested baseline, effective baseline, current demand target, ready and usable counts, and typed baseline shortfall under the observation contract

#### Scenario: A Path baseline changes without a health transition

- **WHEN** the current bounded target, usable count, runtime clamp, or dominant baseline-shortfall reason changes while the Session remains active
- **THEN** the shared observation service makes the new values queryable and emits `session.changed` with the same planning semantics instead of suppressing the change because health is unchanged

#### Scenario: An event client recovers outside the replay window

- **WHEN** an authorized SSE client reconnects with an unavailable `Last-Event-ID`
- **THEN** its complete recovery snapshot includes current Session Path-pool planning fields before later deltas under the existing bounded replay and generation contract

#### Detailed contract

##### Session Path-pool read model

The existing `sessions.list`, `sessions.get`, REST Session list/detail
resources, snapshot-backed drill-down views, and `session.changed` events
SHALL expose these additional or clarified fields:

| Field | Meaning |
|---|---|
| `minimum_usable_paths` | configured common admission minimum |
| `requested_target_usable_paths` | unsigned 64-bit value in `1..=4294967296`: requested idle baseline, including the resolved default before runtime clamping |
| `effective_target_usable_paths` | requested baseline bounded by the current hard runtime ceiling |
| `target_path_count` | current bounded demand-derived physical Path target, recomputed rather than retained as a sticky peak |
| `ready_path_count` | authenticated ready count under the existing lifecycle semantics |
| `usable_path_count` | eligible non-draining authenticated ready `ACTIVE`/`DEGRADED` Paths |
| `target_shortfall` | non-negative difference between requested baseline and actual usable count |
| `target_shortfall_reason` | null for zero shortfall; otherwise the dominant registered reason |

Reason meanings and precedence are authoritative in the [observability
contract](../observability/spec.md): `runtime_limit`, `admission_blocked`,
`no_eligible_transit`, `connect_failed`, then `recovering`.
Query and event adapters SHALL use the shared typed values and SHALL NOT
derive a separate reason from raw logs or apply health/admission side effects
when rendering a baseline shortfall. The shortfall compares the requested
baseline with actual usable count, not with an enlarged demand target. Unknown
demand SHALL remain null or explicitly unknown rather than being fabricated
as zero.

These fields remain read-only and follow existing authorization, bounded
resource retention, capture-generation, and redaction rules. Queries,
snapshot-backed metric drill-down, and event payloads SHALL preserve the same
planning values from their identified observation snapshot. Replayed events
retain their creation generation; recovery snapshots include current planning
state before later deltas under the existing SSE resynchronization contract.
A configured Egress without a live Session SHALL NOT be represented as a
fabricated authenticated Session merely to display a requested baseline. They do not create
a new Path-target mutation operation, a route-specific planning surface, or an
authenticated Egress wire field. The existing JSON management envelope and its
snake_case names remain separate from native camelCase configuration keys.
New filters or sort fields SHALL NOT become implicitly accepted merely because
a planning field is now returned.
