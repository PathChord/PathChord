# Repository Guidelines

## Project Structure & Module Organization

PathChord is in initial implementation. `README.md` defines the project vocabulary and links the design baseline. The `docs/` directory contains architecture, protocol, configuration, state-machine, implementation-plan, technology-selection, and design-review documents. The root Cargo workspace contains Phase 0 protocol primitives and test fixtures under `crates/`.

The Rust layout separates `pathchord-core`, `pathchord-noise`, `pathchord-path`, `pathchord-policy`, `pathchord-transit`, `pathchord-egress`, `pathchord-ingress`, and `pathchord-cli`. Keep `pathchord-core` independent of platforms, subscription formats, and listener implementations.

## Build, Test, and Development Commands

The CLI exposes the planned command tree but operational commands remain bootstrap placeholders. Run the workspace quality gates with:

```sh
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked --workspace --all-targets
```

For documentation changes, also run `git diff --check` and `rg -n '^#{1,6} ' README.md docs/*.md AGENTS.md`.

## Coding Style & Naming Conventions

Use one H1 per Markdown document, sentence-case headings, kebab-case filenames, and language-tagged fences such as `yaml` or `text`. Preserve the defined capitalization and meaning of Ingress, Transit Proxy, Egress, Session, Path, and Stream. Keep related claims synchronized across `architecture.md`, `protocol.md`, `configuration.md`, and `state-machines.md`.

For future Rust code, accept `rustfmt` defaults. Use `snake_case` for modules, functions, and tests; `PascalCase` for types and traits; and kebab-case crate names.

## Testing Guidelines

There is no numeric coverage target. Tests should protect protocol invariants and failure semantics using deterministic Noise/framing vectors, fake transports, property tests, packet traces, and fault injection for loss, duplication, reordering, restart, and partition behavior. Keep unit tests near their modules and integration tests under `tests/`; prefer behavioral names such as `reorders_frames_across_paths`.

## Commit & Pull Request Guidelines

Follow the existing `type: lowercase imperative summary` pattern, for example `docs: clarify session restart semantics`. Use focused commits; introduce `feat:`, `fix:`, or `test:` when code arrives. Pull requests should explain the intent, identify affected contracts and documents, link relevant issues or decisions, and report validation performed. Include screenshots only when a user-visible interface is introduced or changed.

## Security & Configuration

Never commit `.env`, `config.local.*`, private keys, certificates, or secret files. Use placeholders in examples. Preserve explicit enrollment, independent per-Path Noise state, and the documented prohibition on trust-on-first-use.
