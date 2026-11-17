# Tasks

## 1. Configuration model and migration

- [x] 1.1 Replace TransitRule and per-rule Path/policy/class fields with the Egress Transit binding, common minimum, and required namespaced TrafficPolicy reference; verify valid explicit/unrestricted bindings and invalid missing/cross-namespace references with policy configuration tests.
- [x] 1.2 Retire public class definitions/budgets, implicit single-Transit policies, and legacy resources without silent conversion; verify old TransitRules, EgressRule requirements, class fields including empty values, unknown binding fields, and conflicting legacy rules all reject the complete candidate.
- [x] 1.3 Include normalized Egress binding, admission requirements, reference and resolved policy contents in restart checks; verify unchanged-name policy edits and mixed static/dynamic candidates retain the whole prior bundle, while equivalent defaults/file order and unreferenced policy edits do not trigger an Egress restart.
- [x] 1.4 Preserve dynamic subscription and administrator-metadata updates under the fixed binding; verify failed refresh retains nodes, removed relationships drain, hard disable/revoke wins over selectors, and existing Session policy generations do not change.
- [x] 1.5 Synchronize the configuration and configuration-schema deltas into both main spec languages, reconciling their complete Detailed contract sections; update both configuration guides, active examples and packaging defaults with explicit policy references and migration instructions, and verify bilingual identities, local links, and acceptance of the updated complete configurations.

## 2. Routing and Session Path ownership

- [x] 2.1 Narrow compiled Egress route output to captured generation, Egress candidates and diagnostic rule identity, then migrate TCP, UDP, HTTP request routing and DNS consumers; verify different target/listener/geodata rules selecting one Egress produce no different Transit set, policy or Path minimum, and preserve `mode: none`, ordinary Proxy order and explicit fallback.
- [x] 2.2 Replace synthetic-flow warmup with direct Egress binding bootstrap and idle Session reuse; verify destination-specific-only rules and zero prior traffic still establish initial Paths, while business admission waits for authenticated ready Paths and fresh admissible Egress status.
- [x] 2.3 Replace rule requirement/deficit maps and greedy union planning with one bounded aggregate directional demand model and target per Session; verify asymmetric demand, hard-cap shortfall, unknown capacity, independent Sessions, marginal-capacity exclusion, and scale-out/scale-in hysteresis using deterministic transports and windows.
- [x] 2.4 Enforce the usable-Path minimum across admission and planned drain decisions; verify below-minimum service retains existing work, draining Paths cannot justify another drain, concurrent drain choices retain the minimum, multiple Paths share one Transit weight, and last-ready-Path loss retires all business resources and the SessionID.
- [x] 2.5 Synchronize the state-machines delta and its complete Detailed contract in both languages, and update both architecture and technology-selection pairs; verify diagrams and lifecycle prose consistently distinguish Egress policy, Ingress ownership, common minimum, ready/usable/draining states and fresh Session recovery.

## 3. Uniform scheduling and Session control

- [x] 3.1 Derive attachment caps from the immutable Egress policy instead of the fixed default, with bit-to-byte rounding and hard-cap bounds; verify positive-budget `disabled` negotiates zero in both directions, `allowed` respects a lower Egress acceptance, and later Path attachments neither broaden the cap nor reset accounting.
- [x] 3.2 Replace independent flow/class replication scopes with one outbound allowance per sender shared across all Session flows and Paths; verify aggregate copies stay bounded, opposite directions and distinct Sessions account independently, and exhaustion preserves first copies, required control and ordinary reliable retransmission with fair bounded flow service.
- [x] 3.3 Make TCP and UDP opens encode empty eligible-Path lists and route both directions through the common Session pool; verify TCP retransmission and UDP socket identity across Path changes, and Egress UDP over a TCP-only Transit without requiring native UDP support.
- [x] 3.4 Reject canonical non-empty open lists with operation-specific LOCAL_POLICY errors before target dialing; for both TCP and UDP verify rejected sequence 0, duplicate sequence 0 and valid empty-list sequence 1 remain idempotent and progress without blocking other flows, while structurally malformed envelopes retain bounded decoding failures.
- [x] 3.5 Preserve opaque cancellation, same-sequence replacement, new-sequence cancellation, acknowledgements, dependencies and RequestID idempotency; verify cancellation during open/timeout exposes no target or business data, duplicates never create another target, and ordinary Path loss does not migrate an admitted flow to another Egress.
- [x] 3.6 Synchronize protocol and wire-profile deltas plus their complete Detailed contract sections in both languages; verify whole-pool semantics, per-sender budgets and disabled replication are coherent while frame/field order, registries, hard caps, Noise and authorization rules remain complete.

## 4. Typed observations and user surfaces

- [x] 4.1 Publish the Session pool minimum, bounded target, ready/usable counts, eligible relationships, policy identity/generation, directional demand and cap/usage fields through existing typed queries; verify same-Egress flows share one view, dynamic routing generations do not relabel policy snapshots, and unavailable downstream usage stays null rather than borrowing global Egress allowance.
- [x] 4.2 Remove Session/Stream business-class fields, class metric labels and dependent CLI/Web Gateway presentation; verify JSON, events and Prometheus retain authentication, redaction, bounded labels, consistent generations and gauge/counter semantics without exposing inactive class settings.
- [x] 4.3 Synchronize the observability delta and its complete schemas in both languages and update affected operation/configuration guidance; verify local links, paired requirement/scenario identities and explicit distinctions between configured, negotiated, measured and unknown values.

## 5. Integrated verification and evidence

- [x] 5.1 Run the loopback TCP/UDP/HTTP/DNS suite through one Egress pool with several route matches, Transit removal, resource-limited pre-admission failover and fresh-Session recovery; verify admitted targets never reopen on another Egress and ordinary Proxy/native UDP/fallback boundaries still hold.
- [x] 5.2 Run `cargo fmt --all -- --check`, `cargo clippy --locked --workspace --all-targets -- -D warnings`, `cargo test --locked --workspace --all-targets`, `openspec validate --all --strict --no-interactive`, `git diff --check` and the repository heading/link/bilingual audits; verify all local gates pass and audit active contracts/examples for obsolete rule/class semantics without rewriting historical changes.
- [x] 5.3 Update `openspec/implementation-status.md` with the implemented model and actual verification evidence; verify local fixtures/builds remain distinct from native-host, public-provider and deployed-monitoring checks, and the unrelated open validation tasks retain their accurate state.
