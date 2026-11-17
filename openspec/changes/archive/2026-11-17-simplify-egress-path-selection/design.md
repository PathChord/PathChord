# Design

## Context

See [the proposal](proposal.md#why) for the motivation and the six capability deltas under `specs/` for the behavioral changes.

The current policy model has two flow-matching stages for Egress traffic. `EgressRouteCandidate` carries a TransitRule ID, policy ID, class, and Transit candidates, while `EgressRoutePlan` adds a rule-specific minimum. Ingress keeps `RulePathRequirement` maps and computes a greedy union of their deficits before scaling a shared Session. Warmup uses a synthetic flow context to recover these rule-derived requirements.

The affected implementation is concentrated in [policy configuration](../../../../crates/pathchord-policy/src/config.rs), [compiled policy](../../../../crates/pathchord-policy/src/compiled.rs), [Ingress data plane](../../../../crates/pathchord-ingress/src/data_plane.rs), and the [Path runtime](../../../../crates/pathchord-path/src/runtime.rs). The existing Egress schema already has `statusRequirements.minUsablePaths`, and a Session already belongs to exactly one Ingress-to-Egress relationship.

The wire has an additional coupling: STREAM_OPEN and UDP_OPEN can carry eligible Path lists in the Session-control envelope. It also has only a scalar replication cap, expressed in wire bytes per second; policy/class identity is not transmitted. The current attach request uses a default cap independently of the selected local policy. This change must correct that source rather than assume that moving a configuration field makes both senders obey it.

## Goals / non-goals

**Goals:**

- Make the route-to-Session interface expose Egress selection and captured generation without Transit selectors, per-rule minimums, or policy/class overrides.
- Give each configured Egress one explicit local Path binding and one policy; give each Session one pool and one bounded directional demand model.
- Keep policy snapshots, negotiated caps, dynamic membership, and observable generations consistent through later flow admission and Path attachment.
- Make removed configuration and wire restrictions fail explicitly before target admission.

**Non-goals:**

- Add business classification, Egress groups, new adapters, or a compatibility translator for conflicting old rules.
- Share physical Paths or replication counters between different Ingresses or Sessions.
- Support live policy epochs, renegotiate an existing Session cap, or transparently migrate admitted connections across Egresses.
- Change enrollment, Noise, frame identifiers, target semantics, independent DNS routing, ordinary Proxy failover, or production-validation claims.

## Decisions

### Bind Path configuration directly to Egress

Use the existing Ingress-side `Egress` object rather than adding an EgressPathPolicy resource. Add required `transit` and `trafficPolicyRef` fields and retain `statusRequirements.minUsablePaths` as the single common admission minimum. A reference is required even for one Transit, removing the implicit-single-Transit policy and its runtime cardinality-dependent failure.

The canonical field and validation details are in the [schema delta](specs/configuration-schema/spec.md). The following resource fragments omit the envelope version, endpoint, identity, and capability fields:

```yaml
kind: Egress
metadata:
  name: jp-1
spec:
  statusRequirements:
    minUsablePaths: 2
  transit:
    require:
      labels:
        region: jp
    reject:
      tags: [quota-exhausted]
  trafficPolicyRef: jp-default
```

```yaml
kind: EgressRule
metadata:
  name: huggingface
spec:
  order: 10
  match:
    targetGeoSites: [huggingface]
  egressRef: jp-1
```

`transit: {}` is an explicit unrestricted same-namespace binding. `require` retains the existing selector semantics; `reject.tags` excludes any matching tag. The binding has no flow match, order, or second weight. TransitProxy node weights supply the relationship baseline, and multiple Paths share that baseline. Hard administrative, authorization, adapter, and health failures always override metadata preferences.

Retaining TransitRule without its match field would preserve an extra ordered rule layer without useful variation. A new policy resource would add another identity/reference despite a one-to-one owner. Both alternatives create more configuration surface than direct Egress fields.

### Narrow route output and resolve the pool through its owner

An Egress route plan contains the captured routing generation, matching rule identity for diagnostics, and compliant Egress candidates. It carries no TransitRule, concrete Transit candidate set, traffic class, TrafficPolicy ID, or per-rule Path minimum. The Session owner resolves the selected Egress's compiled binding and policy from the same validated configuration.

Egress selection still checks the business protocol and current common admission state. `mode: none`, ordinary Proxy rules, and explicit fallback retain their existing meaning. A target-open resource error can advance only through compliant Egress candidates in the captured generation, before admission; it does not initiate unrelated Proxy or Direct fallback.

Keeping unused selectors or policy fields on the route plan would allow old callers to restore per-flow behavior. Remove those fields and migrate all consumers, including TCP, UDP, HTTP request routing, listeners, DNS via Egress, and management views.

### Bootstrap and maintain one Session pool without business matches

Warmup iterates configured Egresses and their bindings directly. Eligible transports and explicit authorization permit the initial connection attempt; an existing connected or fresh resource report is not a prerequisite for obtaining the first authenticated report. Business admission still waits for ready Paths and fresh admissible status.

The pool owns relationship-to-Path instances, the common minimum, aggregate upstream/downstream demand, the current target, and lifecycle state. Replace rule deficit maps, synthetic warmup contexts, and greedy rule-union planning. Preserve directional capacity estimation, bounded windows, unknown measurements, hysteresis, marginal-capacity guards, and negotiated safety ceilings.

Only non-draining ACTIVE/DEGRADED Paths satisfy the new-business minimum. Planned scale-in subtracts already-draining Paths and every concurrently selected drain candidate. Below-minimum service denies new admission while existing work can continue; last-ready-Path loss closes the Session. One Transit may provide several Paths without promising failure-domain diversity or multiplying its weight.

### Freeze the effective policy for the Ingress lifetime

The startup fingerprint includes the Egress binding, common requirements, policy reference, and resolved normalized policy contents. A changed referenced policy is restart-required even if its name is unchanged. Normalize equivalent defaults, selectors, and source order before comparing. Unreferenced policy edits do not change an Egress fingerprint. A candidate that mixes startup changes and dynamic changes is rejected as a whole, preserving the previous bundle.

Subscription membership and authorized administrator metadata remain dynamic. Re-evaluate candidates under the fixed binding, publish valid generations atomically, and drain removed relationships. Flow routing generations and the Session's captured policy generation stay distinct in observations.

This is deliberately simpler than policy epochs or draining a Session into a second simultaneous Session for the same Egress. Live policy replacement would require new cap, budget-transfer, and admission semantics. Restarting is the chosen policy-change boundary for this change.

### Apply one policy through the existing negotiated resource cap

Retire public `trafficClassRef`, `TrafficPolicy.classes`, and `classReplicationBudgetBps`. Retain bounded per-flow queues and fair service, required-control priority, and ordinary reliability. Route identities remain diagnostic information rather than accounting keys.

Derive the attach request from the captured Egress policy, not a fixed default:

```text
disabled: requested_bytes_per_second = 0
allowed:  requested_bytes_per_second = min(floor(policy_bits_per_second / 8), profile_hard_cap)
accepted_cap <= requested_cap and each peer's applicable hard limit
```

The single existing wire cap cannot communicate a separate optional-control preference. Therefore disabled replication requests zero and disables optional business and control copies in both directions, even with a positive authored budget. First copies, necessary control, and ordinary reliable retransmission remain available. Subsequent Path attachments use the captured request/effective negotiation without resetting consumption or raising the cap.

Each sender accounts its outbound optional copies across every flow and Path in the Session. Both directions use the accepted numerical ceiling independently; there is no combined bidirectional token bucket or synchronization protocol. Different Sessions referencing the same policy keep independent accounting.

### Retire per-flow Path lists without changing the envelope layout

Keep the registered `eligible_path_count` and `eligible_paths` encoding positions. New encoders always send zero entries; an admitted open uses the whole Session pool in both directions.

A well-formed non-empty list is an explicitly rejected policy request: return the operation-specific LOCAL_POLICY error, create no target connection, apply/acknowledge the control sequence, and keep idempotent results for duplicate copies. After rejecting sequence 0, a valid empty-list operation at sequence 1 must progress normally. Cover TCP and UDP separately. Structurally malformed envelopes retain the existing bounded decoding failure behavior.

Preserve SESSION_CONTROL_CANCEL for general flow cancellation and timeout, including same-sequence replacement, the new-sequence case, acknowledgement, idempotency, and opaque IDs. No field, frame ID, capability ID, error code, or profile version is added. This is a coordinated behavioral tightening: old peers that request private Path subsets receive an explicit rejection rather than a silently broadened route.

### Expose the owner of scheduling state

Session observations carry one minimum, bounded target, usable count, eligible-relationship count, policy identity/generation, aggregate directional demand, and negotiated cap. Upstream usage comes from Ingress's authoritative sender accounting. Downstream Session usage stays null unless an authoritative producer exists; Egress global STATUS_REPORT allowance is not a substitute.

Retire Session/Stream traffic-class fields and the business-class bytes metric label. Keep authorization, redaction, bounded labels, pagination, event generations, and unknown/null values. Existing operations and routes suffice; no new control-plane capability is needed.

### Reconcile detailed contracts explicitly when synchronizing

The CLI merges requirement blocks and does not merge standalone Detailed contract sections from deltas. These deltas therefore retain detailed normative amendments as `#### Detailed contract` within existing owning requirements, with `#####` subsections. During spec synchronization, reconcile them into the main specs' authoritative `## Detailed contract`, replace the obsolete rule/class/list passages, and leave concise requirements pointing to that contract. Preserve every unrelated schema, wire layout, registry, and failure rule.

Synchronize all six English/Chinese main spec pairs, both architecture and technology-selection language pairs, affected configuration guides, READMEs, examples, and packaging defaults. Keep these planning artifacts English-only. Current progress/evidence belongs in `implementation-status.md`; historical completed changes remain historical, and unrelated deployed-monitoring tasks are not checked off.

## Risks / trade-offs

- Conflicting old TransitRule intent cannot be reconstructed automatically → reject retired input and require an explicit common binding and policy during migration.
- A shared pool removes destination-specific Transit isolation and business budgets within an Egress → document the simplification and reject fields that appear to retain those controls.
- Default attach caps or per-flow compatibility shims could bypass the new owner → trace every TCP/UDP/control consumer and verify both senders with positive-budget-disabled tests.
- Counting draining Paths or batching scale-in can break the common minimum → evaluate remaining usable Paths atomically and test concurrent drains.
- Existing peers may send private Path lists → use typed pre-admission rejection, preserve sequence progress, and coordinate upgrades rather than silently widening eligibility.
- A startup-only policy edit requires a restart and closes existing connections → report restart-required before publication and retain the current runtime until explicitly restarted.
- Archived requirement merges can leave contradictory old detailed passages → make canonical detailed-contract reconciliation and bilingual consistency explicit acceptance tasks.

## Migration plan

1. Implement the new schema and typed model together with new fixtures. Remove retired fields instead of adding dual configuration semantics.
2. For each configured Egress, choose one Transit binding, move its common minimum, and reference one policy. Rewrite flow-specific route actions to select only the Egress. Remove class fields and update examples/defaults.
3. Upgrade both endpoint roles for whole-pool open semantics and uniform cap negotiation. Drain or stop the previous Ingress and start the new configuration, creating fresh SessionIDs. Do not reinterpret live old Sessions.
4. Synchronize the capability deltas and complete detailed contracts in both languages; update durable design/guides and record actual local versus external evidence.
5. If rollback is needed, stop the new Ingress and restore both the previous binaries and its matching configuration, then create fresh Sessions. Do not roll a retired-field configuration into the new parser or reuse negotiated state across versions.
