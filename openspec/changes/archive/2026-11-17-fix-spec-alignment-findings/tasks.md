# Tasks

## 1. Configuration graph and validation

- [x] 1.1 Preserve namespace-qualified resource identities and references through all consumers; verify same-name resources coexist, cross-namespace references fail, and normal runtime/reload consumers resolve their owning resources.
- [x] 1.2 Validate every supplied DNS route endpoint without panics; verify inactive-route errors retain the previous reload snapshot and a subsequent valid candidate applies.
- [x] 1.3 Apply capability boolean defaults and reject unknown capability fields; verify TCP-only mappings load and misspelled fields fail.
- [x] 1.4 Accept omitted-match catch-all rules under the existing schema; verify omitted matches load and explicit empty match objects remain invalid.

## 2. Path admission and Session behavior

- [x] 2.1 Bound Egress Noise/HELLO/ATTACH admission; verify idle and incomplete handshakes release Path permits and do not block later valid admission.
- [x] 2.2 Isolate malformed authenticated frames to their Path; verify another ready Path and existing Stream remain usable.
- [x] 2.3 Preserve the complete negotiated capability set on both peers and subsequent Paths; verify TCP-only, UDP, class, and mismatched attachment cases.
- [x] 2.4 Preserve Egress target I/O failures as TARGET_FAILURE; verify failure frames distinguish target and Path errors.
- [x] 2.5 Honor received PATH_DRAIN deadlines; verify deadline expiry closes the Path despite outstanding work while healthy Paths remain usable.
- [x] 2.6 Generate random 128-bit RequestIDs; verify opens use distinct random identifiers and retry/idempotency behavior is preserved.

## 3. Transit adapters and subscription accounting

- [x] 3.1 Validate explicit UDP enablement against native Hysteria2/TUIC capabilities; verify udp:true nodes construct and udp:false still disables ordinary datagrams.
- [x] 3.2 Reject conflicting credential aliases before canonicalization; verify invalid nodes retain sanitized diagnostics and valid siblings still publish.
- [x] 3.3 Charge failed provider downloads to the shared aggregate refresh budget; verify interrupted chunked providers cannot exceed 4 MiB across a refresh and credential boundaries remain intact.
- [x] 3.4 Preserve required usage and independent billing metadata when optional total/expire fields are malformed; verify field-level unknown semantics and cache/query regressions.

## 4. Observation bounds and SSE authorization

- [x] 4.1 Bound terminal connection history without terminating Ingress or discarding current lifecycle state; verify sustained churn beyond 16,384 completed connections, shared admission across listener runtimes, live-record retention, and typed resource-limit degradation.
- [x] 4.2 Reject unauthorized SSE before establishing an event response; verify metrics capability failures return 403 and permitted streams retain bounded replay/client behavior.
- [x] 4.3 Fail SSE gap recovery when required snapshot queries fail; verify no incomplete recovery event or advanced cursor is emitted and the stream/client permit closes, while capability-hidden resources remain redacted.

## 5. Integration and implementation evidence

- [x] 5.1 Update openspec/implementation-status.md with the repaired behavior and current evidence while retaining outstanding native/deployed validation; verify local documentation links and paired structural identities.
- [x] 5.2 Run cargo fmt, workspace Clippy and tests, strict OpenSpec validation, documentation checks, and git diff --check; resolve integration regressions and verify every audited deviation has regression coverage.

## Workflow follow-up

- Commit the verified changes and push the current branch as requested; verify the remote revision and clean synchronization.
