# Proposal

## Why

PathChord's final-state contracts and implementation plan are maintained as a flat document collection, while the initialized OpenSpec tree has no capability specifications. Make existing contracts discoverable and machine-validatable through OpenSpec, and track remaining work as focused changes rather than a second implementation plan.

## What changes

- Bootstrap ten existing contract areas under `openspec/specs/<capability>/spec.md`, with matching Simplified Chinese documents, explicit requirements, and behavioral scenarios.
- Preserve complete existing normative text, registries, and tables within capability documents; retain durable architecture and decisions under `docs/design/`.
- Move the deployment walkthrough to `docs/guides/` and add a bilingual user configuration guide. Keep each procedure in one guide and link the corresponding OpenSpec requirements to it.
- Replace `docs/progress/implementation-plan.md` with focused OpenSpec changes for native platforms, provider/runtime reliability, scheduling/observability, and native packages.
- Keep supporting backend/eBPF research with the corresponding changes and the implementation/validation snapshot at `openspec/implementation-status.md`; reserve `docs/` for design and user instructions.
- Update the bilingual READMEs, cross-references, contributor rules, and OpenSpec project configuration.

## Capabilities

### New capabilities

None. The capability inventory represents pre-existing PathChord contracts; this change introduces no runtime behavior. `skip_specs: true` prevents a redundant delta from restating that baseline.

### Modified capabilities

None. Requirement and scenario summaries must preserve the meaning of the existing specifications.

## Impact

Documentation paths, OpenSpec planning artifacts, and contributor workflow change. Runtime code, protocol bytes, configuration formats, dependencies, examples, and package recipes are outside this migration. Pending native-host, provider, deployment, and monitoring checks remain pending; reorganizing their tasks supplies no new validation evidence.
