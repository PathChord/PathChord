# Design

## Context

See [the proposal](proposal.md#why) for the migration's motivation. The existing baseline consists of ten English/Simplified Chinese specification pairs, two design pairs, an English implementation status, and one implementation plan that also contains backend research. OpenSpec already uses the `spec-driven` schema.

## Goals / non-goals

Preserve every existing contract, example, registry, and validation limitation while making capability specifications and pending tasks discoverable through the OpenSpec CLI. Runtime behavior and implementation of the carried-over backlog are outside this documentation change.

## Decisions

### Keep one authoritative document pair per capability

Represent the ten existing contract areas as `openspec/specs/<name>/spec.md` and `spec.zh-CN.md`: protocol, wire-profile, configuration, configuration-schema, platform-and-dns, state-machines, ingress-control-plane, observability, transit-proxies, and deployment. Move the nine technical contract pairs into these capability documents. Move the deployment walkthrough once to `docs/guides/deployment*.md`; its OpenSpec capability keeps the operational requirements and scenarios without copying the walkthrough.

Each canonical spec has `## Purpose`, `## Requirements`, named `### Requirement:` blocks, and `#### Scenario:` blocks with WHEN/THEN outcomes. The full technical text follows under `## Detailed contract` where needed; existing heading text and anchors remain intact. Requirements explicitly bind conformance to those details, so compact scenarios supplement rather than replace byte layouts, schema tables, and failure semantics. The Chinese document preserves the same structural keywords and requirement/scenario identities with translated prose. OpenSpec discovers only canonical `spec.md` files. Correct the inherited Chinese schema reference to the nonexistent `catchAll` field to match the English rule: omit `match` for an explicit catch-all, and reject `match: {}`.

Keeping the old `docs/spec/` collection as another authoritative source would create duplicate maintenance. Removing technical detail in favor of short scenario summaries would lose the protocol contract. Both alternatives are rejected.

### Separate user documentation from contracts and work tracking

Keep `docs/design/` for durable architecture and decisions and `docs/guides/` for bilingual user configuration and operation instructions. The configuration guide explains resource relationships and choosing examples; the deployment guide owns the full command/enrollment walkthrough. Link exact schemas and behavior to OpenSpec rather than copying normative tables into the guides.

Keep the single implementation/validation snapshot at `openspec/implementation-status.md`. Move the pinned backend-source table into the provider/reliability change's `research/` directory and the eBPF investigation into the native-platform change's `research/` directory. Research is non-normative and may retain its source language. Remove the superseded `docs/spec/`, `docs/progress/`, and `docs/research/` paths after repairing links.

### Track existing incomplete work as focused changes

Replace the old plan with four changes: `validate-native-platforms`, `validate-provider-and-runtime-reliability`, `complete-scheduling-and-observability`, and `validate-native-packages`. Each includes proposal, design, and unchecked tasks. They implement or validate existing contracts and use `skip_specs: true`; a later change to requirements must remove that opt-out and provide appropriate deltas. Preserve the old sequence, platform matrix, scope boundaries, and host-evidence requirements across their artifacts and the status snapshot. Do not execute these backlog tasks as part of documentation migration.

### Apply bilingual and workflow rules through project guidance

Configure OpenSpec context and artifact rules, update `AGENTS.md`, and describe propose/apply/validate/archive in both READMEs. Only English canonical deltas are consumed by OpenSpec's merge; synchronize translated baseline specs whenever canonical requirements or their detailed contracts change. Planning artifacts and the status snapshot remain English-only.

## Risks / trade-offs

- Moving files breaks relative links and heading anchors → map old paths to their capability locations and validate all maintained local links/anchors.
- Requirement summaries can overstate existing behavior → derive them from the preserved contract and review both languages against it.
- A specification inventory can be mistaken for implementation evidence → retain the dated status and keep all migrated backlog checkboxes unchecked.
- Detailed contracts keep the specifications large → retain them in the same authoritative document to avoid two competing contract sources.

## Migration plan

Create and validate capability pairs and user guides, migrate status, research and pending tasks, update entry points and contributor guidance, then remove superseded paths. Check baseline content retention across specs and guides (allowing the explicit Chinese correction), bilingual structure, OpenSpec validation, local links, Markdown formatting, and the repository quality gates. Git retains the original layout for rollback.
