# Tasks

## 1. v1 wire and protocol foundation

- [ ] 1.1 Remove PathRebind/PathRebindAck and TrafficClass frame types, payload variants, capabilities, and vectors; verify `FrameType::ALL`, codec round trips, and strict wire-profile validation contain only the finalized v1 registry.
- [ ] 1.2 Add mandatory requested/effective Session replication caps to `SESSION_ATTACH`/`SESSION_ATTACH_OK`; verify lower Egress acceptance, zero-cap semantics, bounds, and exact golden vectors.
- [ ] 1.3 Replace status capacity/recommendation fields with configured/effective/current capacity, capacity state, admission flag, and stable reason; verify unknown/provisional/measured/stale encodings and global-only semantics.
- [ ] 1.4 Add Stream ACK emitted-interval validation before retained-range release; verify future ACKs, unsent gaps, duplicates, reordered valid ACKs, and ordinary retransmission behavior.
- [ ] 1.5 Implement Session trust failure, new SessionID recovery, bounded exponential backoff, and circuit breaker; verify a validated future ACK closes all Paths and repeated failures stop reconnect attempts without revoking authorization.

## 2. Lifecycle owner and PathSet

- [ ] 2.1 Introduce the single Session/Path lifecycle owner and route every Path/Session transition through validated guards; verify illegal Draining-to-Active transitions are rejected and every accepted transition emits one event.
- [ ] 2.2 Split Transit relationships from Path instances and permit multiple Path instances through one relationship; verify relationship weight is applied once and Path IDs/states remain independent.
- [ ] 2.3 Implement fresh Session reconstruction with reset demand, target, and replication state; verify reconnects use new SessionIDs and never reuse retired flow state.
- [ ] 2.4 Add directional Path observations and bounded health counters; verify upstream/downstream metrics remain separate and Path-local state is not serialized as a second Egress status authority.

## 3. Ingress rule admission and autoscaling

- [ ] 3.1 Build rule-specific eligible relationship sets and remove namespace-wide blind warmup; verify ineligible Transit adapters do not count toward any EgressRule minimum.
- [ ] 3.2 Implement Session-local bounded demand counters keyed by rule/policy/class and low-frequency EWMA snapshots; verify no per-flow history is retained and reconnects reset demand.
- [ ] 3.3 Compute per-rule directional target Paths and shared physical PathSet requirements; verify shared compliant Paths satisfy multiple rules without counting ineligible Paths.
- [ ] 3.4 Implement pre-admission Egress candidate failover for Path/resource errors; verify `STREAM_OPEN`/`UDP_OPEN` is not sent to a fallback after target admission and existing target connections are never transparently recreated.
- [ ] 3.5 Implement bounded 1-second health/demand sampling and 5-second autoscaler decisions with independent hysteresis, drain, incremental-capacity exclusion, and provisional configured-cap scheduling; verify no hot-path autoscaler work.

## 4. Egress resource and status runtime

- [ ] 4.1 Replace Egress desired-Path/per-Ingress configuration with global aggregate wire capacity and global inbound target-connection cap; verify removed fields are rejected and the internal Path safety ceiling is read-only.
- [ ] 4.2 Compute startup Path safety ceiling from profile/resource limits with a conservative fallback; verify runtime pressure stops new Path admission and drains without force-closing healthy Paths.
- [ ] 4.3 Implement global wire token accounting with strict priority for primary traffic, ordinary retransmission, and required control; verify optional replication uses only residual capacity and can fall to zero.
- [ ] 4.4 Implement active target connection reservations and bounded pending opens; verify `active + pending <= cap`, pending limits release on all terminal outcomes, and active connections survive saturation.
- [ ] 4.5 Produce global status reports with configured/effective/current capacity, capacity state, admission flag/reason, service state, and current replication allowance; verify no rule/class/Path-local metadata crosses the report.
- [ ] 4.6 Distinguish `RESOURCE_LIMIT`, `TARGET_FAILURE`, `PATH_FAILURE`, and `EGRESS_FAILURE` end to end; verify Ingress retries only compliant candidates and does not silently select direct/Proxy fallback.
- [ ] 4.7 Add aggregate passive capacity measurement with fast degradation/slow recovery hysteresis; verify low-load capacity remains unknown/provisional and configured cap is never presented as measured without evidence.

## 5. TLS and local control boundaries

- [ ] 5.1 Update all intrinsic TLS adapter construction paths to load system roots by default; verify Hysteria2/TUIC/AnyTLS and explicit TLS nodes validate peers without a `tls` block.
- [ ] 5.2 Implement ordered truststore sources (`system`, PEM, DER), relative/absolute path resolution, symlink-to-regular-file checks, bounded reads, empty-list fail-closed behavior, and explicit insecure verification; verify any invalid source rejects the adapter candidate.
- [ ] 5.3 Add prefix/payload/dispatch/response deadlines to Unix socket and Named Pipe control servers; verify slow clients release permits, emit diagnostics, and cannot block later requests.
- [ ] 5.4 Add typed resource-limit handling and retry hints to local control and data-plane admission; verify no unbounded queue or implicit fallback is created.

## 6. Durable design and user-facing contracts

- [ ] 6.1 Synchronize `docs/design/architecture.md` and `architecture.zh-CN.md` with Egress/Ingress ownership, Session failure, PathSet, capacity/admission, and no-cross-Ingress-fairness decisions; verify reciprocal structure and technical literal parity.
- [ ] 6.2 Synchronize `docs/design/technology-selection.md` and `technology-selection.zh-CN.md` with the new wire/session budget, Egress resource, Path observation, TLS truststore, and performance boundaries; verify bilingual links and terminology.
- [ ] 6.3 Update configuration and deployment guides for global Egress limits, truststore sources, removed desired-Path/per-Ingress fields, and status semantics; verify examples parse and no guide duplicates normative tables.
- [ ] 6.4 Update `openspec/implementation-status.md` with implementation gaps and evidence boundaries after code lands; keep local tests, native hosts, cross-machine, and soak evidence distinct.

## 7. Integrated verification

- [ ] 7.1 Run focused core/path/Ingress/Egress/Transit tests for each preceding task group and verify deterministic failure semantics before broad tests.
- [ ] 7.2 Run `cargo fmt --all -- --check`, locked workspace Clippy, locked workspace tests, strict OpenSpec validation, bilingual/documentation checks, and `git diff --check`.
- [ ] 7.3 Add loopback tests for multi-Path-per-Transit, rule-specific Path targets, pre-admission candidate failover, global connection reservations, dynamic capacity states, and Session trust recovery.
- [ ] 7.4 Keep native Windows/FreeBSD, privileged Linux, cross-machine, external-peer, and prolonged-soak checks separate; record unresolved host evidence without claiming local tests prove it.

## Workflow follow-up

- Apply this change only after the planning artifacts and synchronized design documents are reviewed.
- Archive the change only after all tracked implementation and validation tasks are complete and the main English/Chinese specs have been reconciled.
