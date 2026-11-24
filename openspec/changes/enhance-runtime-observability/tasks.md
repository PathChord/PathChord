# Implementation tasks

## 1. Diagnostic records and correlation

- [x] 1.1 Define typed records, stage and reason registries, process-scoped cursors, and ID ownership. Verify normalization, handling of unknown values, and correlation between two independently ordered role timelines.
- [x] 1.2 Implement bounded baseline history and loss accounting. Verify that terminal records remain queryable after live inventory removal, expiration and eviction are visible, and producer saturation preserves counters and forwarding.
- [x] 1.3 Record Path and Session terminal transitions at the owning runtime. Inject write timeout, read and write errors, EOF, heartbeat expiry, protocol failure, drain and shutdown. Assert one counted terminal transition per Path, including racing triggers and cascading Session cleanup.

## 2. Runtime coverage

- [ ] 2.1 Instrument listener acceptance and platform failures, policy and fallback decisions, and DNS route, cache and resolution outcomes. Verify a rejected CONNECT can be attributed to its local decision and configuration generation.
- [ ] 2.2 Instrument config activation, authorization decisions, subscription refresh and cache handling, adapter preparation, Transit dial and handshake, Noise and attachment, and retry backoff. Verify a failure before admission still has a queryable attempt and stage.
- [ ] 2.3 Instrument Path selection, eligibility and freshness, directional scheduling and retransmission, queue and window pressure, and pool recovery. Verify requested, effective and actual Path counts are independently observable and a retransmission can be attributed to its chosen Path.
- [ ] 2.4 Instrument TCP and UDP Stream and target setup, directional progress, half-close, reset, expiry, resource rejection and supervisor failures. Verify target stalls and capacity limits have distinct reasons and stable resource correlation.

## 3. Operator access

- [x] 3.1 Add role-local management queries and CLI help, filtering, pagination and structured output. Verify equivalent query and redaction behavior through local control and authorized Web Gateway reads.
- [ ] 3.2 Add scoped capture start, read and stop operations with authorization, audit, generation and idempotency handling. Verify duration and budget enforcement, expiry and restart, and denied changes from read-only actors.
- [x] 3.3 Connect existing event replay and Prometheus adapters. Verify ordered terminal updates, replay gaps, counter monotonicity across eviction, histogram units and buckets, and bounded label cardinality under high resource churn.
- [x] 3.4 Inspect outputs from both roles for blocked secret fields, target-detail authorization, and raw errors. Measure baseline and capture overhead under load and verify forwarding continues during collector backpressure.
- [x] 3.5 Add versioned diagnostic export and coverage metadata. Check an empty filtered result, partial retention, process restart, byte-limit truncation, redaction, and offline correlation across roles.

## 4. Documentation and validation

- [x] 4.1 Add paired operator instructions for local inspection, scoped capture, cross-role correlation, metric queries and interpreting gaps. Synchronize all affected English and Simplified Chinese main contracts and complete their detailed schemas when merging the deltas.
- [x] 4.2 Run workspace Rust quality gates, strict OpenSpec validation, whitespace, links, anchors and bilingual structure checks. Record the actual evidence and any unsupported producer fields in the implementation status.
- [ ] 4.3 Verify commands and diagnostics using installed Ingress and Egress packages on native hosts with the Web Gateway disabled. Check optional authenticated scrape separately.
- [ ] 4.4 On an authorized deployment, run a sustained bounded download and a controlled interruption with a known trigger. Reconstruct the first Path failure, failover or Session loss, client result, and any evidence gaps from the two roles. Keep deployed results distinct from local fault injection.
- [ ] 4.5 Verify distinct evidence for Stream/Session credit exhaustion, application queue pressure, and Path write timeout. Exercise missing OS queue support, stale producers, collector overload, and process restarts during collection.
