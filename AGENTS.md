# Repository guidelines

## Project structure and module organization

PathChord is in initial implementation. `README.md` defines the project vocabulary and links the documentation sets. The `docs/design/` directory contains final-state architecture and design decisions, `docs/spec/` contains final-state behavioral and format contracts, and `docs/progress/` contains only the current implementation status and active implementation plan. Superseded reviews, phase-specific acceptance records, temporary fixtures, and other process history belong in Git history, not in the maintained progress directory. The root Cargo workspace contains protocol primitives and test fixtures under `crates/`.

The Rust layout separates `pathchord-core`, `pathchord-noise`, `pathchord-path`, `pathchord-policy`, `pathchord-transit`, `pathchord-egress`, `pathchord-ingress`, and `pathchord-cli`. Keep `pathchord-core` independent of platforms, subscription formats, and listener implementations.

## Build, test, and development commands

The CLI exposes the planned command tree but operational commands remain bootstrap placeholders. Run the workspace quality gates with:

```sh
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked --workspace --all-targets
```

For documentation changes, also run `git diff --check` and `rg -n '^#{1,6} ' README.md README.zh-CN.md docs AGENTS.md`.

## Documentation taxonomy

Treat the three documentation sets as strict content boundaries:

- `docs/design/` describes only the intended final-state requirements, principles, overall design, architecture, and durable design decisions.
- `docs/spec/` describes only the intended final-state implementation contract: required behavior, state transitions, protocols, wire formats, configuration models, APIs, and other testable details.
- `docs/progress/` contains only implementation status and the active implementation plan. Status records current capabilities, gaps, constraints, and validation state; the plan records current sequencing and next work. Do not add historical reviews, completed acceptance reports, temporary wire fixtures, or obsolete process notes.

Every Markdown document under `docs/design/` and `docs/spec/` must have both an English `name.md` and a Simplified Chinese `name.zh-CN.md` version. Put the reciprocal language switch immediately below the H1, update both versions in the same change, and preserve equivalent normative meaning, technical literals, links, and code blocks across the pair. Progress documents under `docs/progress/` use English as their single maintained source and do not require a Chinese pair unless a task explicitly requests one.

Design and specification documents must not describe the current implementation, implementation progress, rollout order, milestones, temporary phase scope, deferred work, or future plans. Phrases such as “currently implemented,” “not yet implemented,” “Phase N,” “first/next/later implementation,” “planned,” and “deferred” normally indicate material that belongs in `docs/progress/`. Root `README` files and this `AGENTS.md` may summarize current repository state, but detailed status and plans belong in `docs/progress/`.

When a staged implementation contract becomes durable, copy its final behavior into `docs/spec/` without carrying over phase or progress language; keep the current state and active sequencing in the two maintained `docs/progress/` documents. Delete superseded process documents instead of preserving them as maintained references; Git history is the historical record. Keep related final-state claims synchronized across `docs/design/architecture*.md`, `docs/spec/protocol*.md`, `docs/spec/configuration*.md`, and `docs/spec/state-machines*.md`.

## Coding style and naming conventions

Use one H1 per Markdown document, sentence-case headings, kebab-case filenames, and language-tagged fences such as `yaml` or `text`. Preserve the defined capitalization and meaning of Ingress, Transit Proxy, Egress, Session, Path, and Stream.

For future Rust code, accept `rustfmt` defaults. Use `snake_case` for modules, functions, and tests; `PascalCase` for types and traits; and kebab-case crate names.

## Testing guidelines

There is no numeric coverage target. Tests should protect protocol invariants and failure semantics using deterministic Noise/framing vectors, fake transports, property tests, packet traces, and fault injection for loss, duplication, reordering, restart, and partition behavior. Keep unit tests near their modules and integration tests under `tests/`; prefer behavioral names such as `reorders_frames_across_paths`.

## Commit and pull request guidelines

Follow the existing `type: lowercase imperative summary` pattern, for example `docs: clarify session restart semantics`. Use focused commits; introduce `feat:`, `fix:`, or `test:` when code arrives. Pull requests should explain the intent, identify affected contracts and documents, link relevant issues or decisions, and report validation performed. Include screenshots only when a user-visible interface is introduced or changed.

## Security and configuration

Never commit `.env`, `config.local.*`, private keys, certificates, or secret files. Use placeholders in examples. Preserve explicit enrollment, independent per-Path Noise state, and the documented prohibition on trust-on-first-use.
