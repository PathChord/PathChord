# Repository guidelines

## Project structure and module organization

PathChord has a runnable Rust implementation. Implementation and validation evidence is recorded in `openspec/implementation-status.md`; pending work is tracked as OpenSpec changes. `README.md` defines the project vocabulary and links the documentation sets. The `docs/design/` directory contains durable architecture and design decisions, and `docs/guides/` contains user-facing configuration and operation guides. `openspec/specs/` contains capability-based behavioral and format contracts, and `openspec/changes/` contains change proposals, designs, deltas, tasks, and supporting research. The root Cargo workspace contains protocol primitives and test fixtures under `crates/`.

The Rust layout separates `pathchord-core`, `pathchord-noise`, `pathchord-path`, `pathchord-policy`, `pathchord-transit`, `pathchord-egress`, `pathchord-ingress`, and `pathchord-cli`. Keep `pathchord-core` independent of platforms, subscription formats, and listener implementations.

## Build, test, and development commands

The CLI starts the Ingress/Egress runtimes and exposes local control commands. Run the workspace quality gates with:

```sh
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked --workspace --all-targets
```

For documentation changes, also run `openspec validate --all --strict --no-interactive`, `git diff --check`, and `rg -n '^#{1,6} ' README.md README.zh-CN.md docs openspec AGENTS.md`. Verify local links and anchors, language switches, paired requirement/scenario identities, and preservation of technical examples and registries after moving or restructuring documents.

Ingress configuration source precedence is command line, then
`PATHCHORD_CONFIG` / `PATHCHORD_CONFIG_DIR`, then the account default:
`~/.config/pathchord` for regular users and `/etc/pathchord` for root/service
accounts. Directory resource files form one validated graph; do not add
last-file-wins semantics or a working-directory default fallback.

## Documentation taxonomy

Maintain these content boundaries:

- `docs/design/` describes the intended final-state principles, architecture, and durable decisions.
- `docs/guides/` explains configuration, deployment, and local operation for users. Keep procedures, runnable examples, prerequisites, and troubleshooting here, linking to authoritative capability specs for exact schemas and protocol rules. Do not maintain a second specification collection in `docs/` or copy complete normative tables into guides.
- `openspec/specs/<capability>/spec.md` is the authoritative English behavior contract for that capability. Use `## Purpose`, `## Requirements`, `### Requirement:`, and `#### Scenario:` with explicit WHEN/THEN outcomes. Preserve complete normative wire layouts, registries, schema tables, configuration models, state transitions, and failure semantics under `## Detailed contract` where needed. Requirement summaries and scenarios do not replace those details; user procedures and deployment walkthroughs live only in `docs/guides/`.
- `openspec/changes/<change>/` owns proposals, change-specific design, requirement deltas, sequencing, and executable task checklists. Use the configured `spec-driven` schema. A change to behavior needs deltas for the existing capability paths; work that only implements, validates, or reorganizes existing contracts uses `skip_specs: true` in `.openspec.yaml` and has no fabricated delta.
- `openspec/implementation-status.md` is the single English implementation and validation snapshot. Keep current capabilities, gaps, constraints, and evidence here; put pending actions in the corresponding change tasks. Do not recreate a parallel implementation plan or progress collection in `docs/`.
- A change's `research/` directory contains its dated, non-normative investigations and source evidence. Keep historical completed changes in `openspec/changes/archive/`; superseded standalone process reports belong in Git history.

Every document under `docs/design/` and `docs/guides/` has an English `name.md` and Simplified Chinese `name.zh-CN.md` pair. Every capability has `spec.md` and `spec.zh-CN.md`. Put reciprocal language switches immediately below the H1, update both languages in the same change, and preserve equivalent meaning, technical literals, links, and code blocks. Preserve the English OpenSpec structural headings and requirement/scenario identities in both spec versions so paired edits are traceable. Planning artifacts and the status snapshot are English-only unless explicitly requested otherwise; referenced research may retain its source language. Do not translate this agent-only guide.

Design and main specifications describe only final-state contracts. Keep implementation progress, rollout order, temporary phase scope, deferred work, and validation claims in the status snapshot or change artifacts. Root READMEs and this guide may summarize repository state. When a behavior becomes durable, merge the canonical delta into its main spec, reconcile the complete Detailed contract, synchronize its Chinese counterpart and affected design documents, and validate before archiving. Repair relative links in change artifacts and research when moving a change into the archive directory. The OpenSpec CLI merges only English `spec.md` deltas; do not place translated delta files under a change's `specs/` tree. Keep architecture, protocol, configuration, state machines, and other affected capabilities mutually consistent.

Use `openspec list --specs` to discover the baseline and `openspec list` to discover changes. Read proposal/design/specs/tasks before applying a change. Mark a task complete only after its check passes, keep native-platform and deployed evidence distinct from local tests, and retain the pre-existing `skip_specs` opt-out only while normative behavior is unchanged.

## Coding style and naming conventions

Use one H1 per Markdown document, sentence-case headings, kebab-case filenames, and language-tagged fences such as `yaml` or `text`. Preserve the defined capitalization and meaning of Ingress, Transit Proxy, Egress, Session, Path, and Stream.

For future Rust code, accept `rustfmt` defaults. Use `snake_case` for modules, functions, and tests; `PascalCase` for types and traits; and kebab-case crate names.

## Testing guidelines

There is no numeric coverage target. Tests should protect protocol invariants and failure semantics using deterministic Noise/framing vectors, fake transports, property tests, packet traces, and fault injection for loss, duplication, reordering, restart, and partition behavior. Keep unit tests near their modules and integration tests under `tests/`; prefer behavioral names such as `reorders_frames_across_paths`.

## Commit and pull request guidelines

Follow the existing `type: lowercase imperative summary` pattern, for example `docs: clarify session restart semantics`. Use focused commits; introduce `feat:`, `fix:`, or `test:` when code arrives. Pull requests should explain the intent, identify affected contracts and documents, link relevant issues or decisions, and report validation performed. Include screenshots only when a user-visible interface is introduced or changed.

## Security and configuration

Never commit `.env`, `config.local.*`, private keys, certificates, or secret files. Use placeholders in examples. Preserve explicit enrollment, independent per-Path Noise state, and the documented prohibition on trust-on-first-use.

Imported connection options must be consumed by the selected adapter or produce
an explicit node diagnostic; never silently downgrade TLS or discard transport
parameters. Keep complete engine documents in private credential storage and
validate the configured backend before making a node eligible. Subscription
provider references must preserve fetch budgets and credential origin boundaries.

## Commit identity by harness

Commits must use the identity of the harness that created them so GitHub
attribution remains accurate. Codex commits use exactly `Codex
<codex@openai.com>`. Commits created by `dsh`, Claude Code, or OpenCode use
that harness's configured name and email, and the configured identity must be
recognizable on GitHub. Do not use the Codex identity for another harness.

Before committing, verify the effective repository-local `user.name` and
`user.email` values. When rewriting history, preserve Dependabot-authored
commits and their metadata.
