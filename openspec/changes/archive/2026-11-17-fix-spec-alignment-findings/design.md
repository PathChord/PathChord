# Design

## Context

See [the proposal](proposal.md) for the audited defects. The existing main
specifications already define the required outcomes. Changes must repair real
runtime paths, retain independent per-Path security state, and keep bounded
resources from terminating unrelated work.

## Goals / non-goals

Reproduce and repair all sixteen audited deviations with behavioral regression
coverage. Preserve existing valid configurations and public wire encodings where
the contract permits them. Native-host, cross-machine, long-running, monitoring,
and independent scheduling-accounting work remains in its existing changes.

## Decisions

- Carry namespace identity through configuration normalization, references,
  compiled policy, and runtime consumers. Keep an injective internal identity
  and resolve canonical wire/credential identities from their owning resource;
  never resolve a reference by searching other namespaces. Exercise same-name
  resources and invalid cross-namespace references at the public loader boundary.
- Validate supplied DNS route fields before conversion, including inactive
  routes. Conversion failures remain typed candidate errors, with no panic while
  holding reload state. Deserialize capability fields with explicit defaults and
  unknown-field rejection; omitted matches express the existing catch-all rule.
- Bound admission around the full Noise/HELLO/ATTACH transaction, release its
  permit on timeout, and retain cancellation during authorization cleanup.
  Handle authenticated malformed frames as Path failures while allowing healthy
  Paths and their Streams to continue. Preserve target failures as target errors.
- Preserve the complete negotiated capability intersection on both peers and
  enforce it on every attached Path. Store received drain deadlines in the Path
  owner and close expired Paths even when work remains. Generate RequestIDs from
  the existing operating-system random source.
- Treat closed connection observations as optional bounded history. Evict that
  history before rejecting current lifecycle state, expose limit degradation,
  and prevent optional observation exhaustion from terminating Ingress. Check SSE
  authorization before acquiring a streaming response and propagate typed errors.
- Validate UDP options against the adapter's actual capability, detect conflicting
  credential aliases before normalization loses them, charge unsuccessful provider
  fetches against one shared refresh budget, and parse optional usage facts
  independently of required upload/download facts.
- Add local deterministic failures and real loopback regressions close to the
  owning module. Keep external protocol-peer and native-platform evidence
  distinct, and run the workspace gates after integrating all parallel edits.

## Risks / trade-offs

- Namespace normalization can affect many consumers -> trace selectors, reload,
  subscriptions, credentials, observations, and Egress startup before completion.
- Failure handling can accidentally reset healthy work -> assert a second Path
  remains usable after malformed input or drain expiry.
- Capacity handling can erase required state -> evict only terminal history and
  exercise sustained connection churn as well as a full live observation set.
- Capability fixes can alter mixed-version exchanges -> stay within registered
  messages; add deltas first if a new wire contract proves necessary.
- Download accounting can double-charge successful data or miss failed reads ->
  share one bounded budget and test both successful and interrupted providers.
