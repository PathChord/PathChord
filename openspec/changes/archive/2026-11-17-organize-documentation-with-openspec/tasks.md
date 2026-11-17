# Tasks

## 1. Migration boundaries and workflow

- [x] 1.1 Record the ten-capability mapping and content-preservation strategy; verify every original contract and backend-research section has a destination in design.md.
- [x] 1.2 Configure OpenSpec context and contributor rules; verify the spec-driven workflow, bilingual boundaries, and documentation validation commands match the new layout.

## 2. Capability specifications

- [x] 2.1 Migrate protocol, wire-profile, and state-machines into bilingual capability specs; verify explicit requirements/scenarios and preservation of all detailed contracts.
- [x] 2.2 Migrate configuration, configuration-schema, and platform-and-dns into bilingual capability specs; verify explicit requirements/scenarios and preservation of all detailed contracts.
- [x] 2.3 Migrate ingress-control-plane, observability, transit-proxies, and deployment requirements into bilingual capability specs and keep the deployment walkthrough only in docs/guides; verify contract detail and guide content are preserved without duplicate walkthroughs.

## 3. Pending changes and navigation

- [x] 3.1 Replace the implementation plan with four focused OpenSpec changes, move status and supporting research into OpenSpec; verify all carried-over tasks remain unchecked and source references are preserved.
- [x] 3.2 Add the bilingual user configuration guide and update both READMEs, design/status links, and contract references; verify docs contains only design and user guides and all obsolete paths are removed without dangling links.

## 4. Integration verification

- [x] 4.1 Validate all specs and changes with strict OpenSpec validation; audit bilingual structure, baseline content retention, local links/anchors, headings, and git diff whitespace.
- [x] 4.2 Run the workspace formatting, Clippy, and test quality gates; report their results separately from all pending native-host and deployment evidence.

## Workflow follow-up

- Review the completed documentation migration before archiving this change.
- Continue remaining implementation and host validation through the four carried-over changes.

## Verification evidence

Verified on 2026-11-14:

- Strict OpenSpec validation: all 10 main specs and 5 changes pass, with 64 requirements and 87 scenarios per language.
- Content audit: all 20 original specification/guide bodies remain at their single destinations, allowing link/heading changes and the documented Chinese catch-all correction. Research source references and existing implementation evidence are retained.
- Documentation audit: 253 local links/anchors across 50 Markdown files pass; language switches, requirement/scenario identities, user-guide examples, headings, code fences, and `git diff --check` pass.
- An isolated temporary archive fixture applies a requirement delta while preserving the authored Purpose and complete Detailed contract.
- `cargo fmt --all -- --check` and `cargo clippy --locked --workspace --all-targets -- -D warnings` pass. `cargo test --locked --workspace --all-targets` reports 617 passed, 0 failed, and 10 ignored across 20 test binaries.
- The four carried-over changes retain all 28 unchecked tasks. Their native-host, provider, deployment, monitoring, and package acceptance evidence remains pending.
