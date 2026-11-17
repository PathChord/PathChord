# Tasks

## 1. Normalize the multi-endpoint configuration model

- [x] 1.1 Add typed `binds` and `endpoints` forms to the policy and service configuration models, preserve singular `bind` and `address`/`port` shorthands, and implement the 32-entry bound, conflict, host/port, duplicate, order, and identity validations; verify policy/configuration unit tests cover IPv4, IPv6, hostname, different-port, legacy, and invalid forms.
- [x] 1.2 Propagate normalized bind and endpoint lists through `pathchord-config`, CLI resolution, `pathchord-egressd`, static configuration fingerprints, and restart-required reload diagnostics; verify repeated `--bind`, source-directory resolution, unchanged legacy configs, and topology-change reload tests.
- [x] 1.3 Update `examples/egress-service.yaml`, `examples/ingress-egress.yaml`, `docs/guides/configuration.md`, and `docs/guides/configuration.zh-CN.md` with singular shorthand and IPv4/IPv6/domain multi-endpoint examples; verify YAML parsing, bilingual language switches, local links, preserved technical literals, and `git diff --check`.

## 2. Share one Egress runtime across multiple listeners

- [x] 2.1 Replace the single Egress listener ownership with an atomically bound, bounded listener collection that tags accepted streams with endpoint ordinals and shares authorization, Path admission, target limits, wire budget, runtime state, and shutdown cleanup; verify multi-bind startup accepts Paths through every listener under one Egress identity and global limits remain aggregate.
- [x] 2.2 Supervise listener acceptors independently after startup, record typed endpoint failure or drain state, keep healthy listeners serving, and join all acceptors and Path tasks on shutdown; verify one listener failure leaves another usable and a failed startup never exposes a partial listener set.
- [x] 2.3 Wire repeatable CLI binds and service startup errors through both `pathchord-cli` and `pathchord-egressd`; verify existing one-bind invocations behave identically and bind conflicts produce a typed failure without leaking the private identity or authorization details.
- [x] 2.4 Add Egress runtime regression tests for shared authorization generations, duplicate-session handling, endpoint-index propagation, global target reservations, and graceful shutdown; verify the focused Egress test suite passes serially where listener timing is involved.

## 3. Select and recover Egress endpoints per Path

- [x] 3.1 Change the normalized Ingress Egress runtime state and `SessionSlot` bookkeeping to retain an ordered endpoint snapshot, bounded selection cursor, endpoint health, and selected endpoint ordinal per Path while preserving one Session pool and one Egress policy; verify reload and Session tests retain one identity and one TrafficPolicy across all candidates.
- [x] 3.2 Implement bounded per-Path endpoint attempts in the Path dial operation with one shared deadline, declared-order wraparound, adapter-owned hostname/A/AAAA resolution, and no Direct or unrelated-Proxy fallback; verify fake Transit tests cover first-candidate failure, timeout resource release, all-candidates failure, and different explicit ports.
- [x] 3.3 Preserve selected endpoint ownership after Path admission and classify endpoint-specific transport failure separately from whole-Egress failure; verify a healthy Path keeps the Session usable while a failed endpoint Path is replaced with a fresh PathID and the last-ready-Path rule still retires the Session.
- [x] 3.4 Add loopback integration coverage for concurrent Paths using IPv4, IPv6, and hostname candidates, including a candidate with a distinct port; verify HTTP CONNECT and UDP flows continue through the shared Session and no admitted Stream or UDP Association is silently migrated.

## 4. Expose bounded endpoint-aware observations

- [x] 4.1 Extend local Egress, Session, and Path resource views with bounded endpoint inventory, endpoint state/failure reason, endpoint count, and selected endpoint ordinal under existing authorization and redaction rules; verify control-plane queries expose the correct endpoint without credentials or unbounded history.
- [x] 4.2 Keep Egress capacity, admission, target counts, and wire status aggregate across listeners, and keep endpoint host/port out of Prometheus labels and authenticated `STATUS_REPORT`; verify metrics and wire golden/regression tests show unchanged aggregate layout and no endpoint-cardinality labels.
- [x] 4.3 Add endpoint lifecycle and observation tests for configured, available, degraded, draining, failed, and unknown states, including endpoint removal/reordering restart diagnostics; verify event generations and resource IDs remain bounded and deterministic.

## 5. Complete contract and acceptance validation

- [x] 5.1 Synchronize the implemented behavior into the English main specs and matching Simplified Chinese specs for configuration-schema, configuration, state-machines, and observability, and update affected bilingual design documents and guides; verify paired requirement/scenario identities, language switches, anchors, technical examples, and no translated delta files under the change.
- [x] 5.2 Run deterministic local validation for the changed crates and focused integration suites with `cargo fmt --all -- --check`, targeted `cargo test --locked`, `cargo clippy --locked --workspace --all-targets -- -D warnings`, and `git diff --check`; record failures by scope instead of treating skipped external checks as passed.
- [x] 5.3 Run `openspec validate --all --strict --no-interactive` and the repository documentation checks (`rg -n '^#{1,6} ' README.md README.zh-CN.md docs openspec AGENTS.md` plus link/anchor and bilingual audits); verify every change task is backed by a passing check or an explicit environment-specific evidence note.
- [x] 5.4 Validate native dual-stack and multi-bind behavior on each available host separately, including IPv4/IPv6 bind conflicts and firewall reachability; report native-host evidence independently from Linux loopback tests, cross-compilation, and deployed interoperability checks.

## Workflow follow-up

- Archive the completed change after implementation evidence and review satisfy the repository workflow.
- Verify the archived delta is merged into the canonical English specs and the synchronized Chinese counterparts.
