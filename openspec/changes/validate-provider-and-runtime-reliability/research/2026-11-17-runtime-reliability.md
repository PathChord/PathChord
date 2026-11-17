# Local runtime reliability validation

This is non-normative local validation evidence recorded on 2026-11-17 for
tasks 2.1 and 2.2 of `validate-provider-and-runtime-reliability`. The source base
is `9caf37278a61e28c6c5c1669eb793eb2b5ba33df`, with the accompanying runtime
fixes and regression tests in the working tree. Exact executable and harness
SHA-256 values are recorded in the
[machine-readable run](2026-11-17-runtime-soak.jsonl).

## Reproduce the process run

```sh
cargo build --locked -p pathchord-ingressd -p pathchord-egressd -p pathchordctl
python3 -B scripts/test-runtime-reliability.py \
  --cycles 12 --duration-seconds 300
```

The Python standard-library harness starts two real Ingress processes, one real
Egress process, local HTTP CONNECT relays, a local subscription HTTP server,
TCP echo, and a controlled DNS UDP responder. Both explicit Mixed listeners
receive background HTTP CONNECT traffic. Each successful exchange verifies all
8192 payload bytes. A persistent foreground tunnel independently checks
continuity during provider and configuration failures. SOCKS5 UDP ASSOCIATE
enters the product DNS runtime and verifies DNS query IDs, answer count, and
response codes.

The test copies each executable into a private temporary directory before
launching it; restarts use those exact immutable copies even if another build
updates `target/debug`. Identities, authorization database, private fixture
credentials, configuration, cache, and process logs remain in that temporary
directory. No real provider credentials or remote machine are used. The
directory, processes and control sockets are cleaned up on completion or error.

The configured 300 seconds begin after both background traffic workers have
made successful exchanges. Twelve complete fault cycles are spread across that
interval, with resource sampling at one-second cadence during stable windows.
Longer runs can increase the duration and cycle count. Each polling operation,
socket exchange, process startup and shutdown also has a finite deadline.

## Fault matrix and checks

| Repeated fault | Observable completion check |
| --- | --- |
| Provider HTTP 503 | Refresh reports failure, private cache SHA-256 remains unchanged, the foreground tunnel and background new flows continue without additional failures |
| Malformed provider document | Same last-good and traffic checks; a later valid refresh restores healthy refresh state without revoking unchanged usable node admissions |
| Unsupported SSR sibling | A usable HTTP sibling remains available, while the unsupported sibling retains a sanitized diagnostic and receives no runtime fallback |
| DNS responder drops packets | A port-53 flow through SOCKS5 receives SERVFAIL, while ordinary foreground and background traffic continue; restoring the responder returns a valid answer to a new query |
| Malformed configuration containing a private sentinel | Reload is rejected, active configuration generation is retained, diagnostics expose no sentinel, and admitted and new traffic continue |
| Valid mutable rule change | A later complete candidate publishes a higher reload generation and existing traffic continues; the changed rule is deliberately outside the fixture target port |
| Subscription disable and re-enable | After successful disable, new CONNECT is rejected and no new relay connection is made; an old tunnel can finish; an old-generation enable is rejected with `GENERATION_CONFLICT`; explicit re-enable/refresh permits new work |
| Cut every established Transit relay connection | Traffic recovers with new Path IDs; retired Path and Session identities are not reused |
| Restart the Egress process on the same endpoint | The old tunnel closes, the authorization database and Egress identity remain usable, and new traffic uses a fresh Session |
| Revoke the Ingress authorization | Egress active Path, Session, Stream and target counts reach zero, an old client observes closure, and enabling the revoked record fails; deleting that record and enrolling a newly generated Ingress identity permits a fresh Session and Paths |

The source-disable, path-cut, endpoint-restart and revocation windows deliberately
interrupt work. Their failed background exchanges are counted separately and
are never reported as successful transfers. The provider HTTP/parse, DNS and
configuration-reload windows require no additional background failures. Stable
windows require no uninjected failures. Payload mismatch always fails the run.

The long-lived provider Ingress spans the entire run. Egress is deliberately
restarted each cycle. The Path Ingress is restarted after terminal revocation
with a fresh enrolled identity, so its process-memory evidence covers each
identity lifetime rather than an uninterrupted five-minute instance.

## Resource envelope

The harness fixes `TOKIO_WORKER_THREADS=2` and samples each role process through
Linux `/proc`. It rejects more than 128 file descriptors, 16 OS threads,
256 MiB RSS, or 64 MiB RSS growth from that process's first warm sample.
Management snapshots reject more than one active Session, eight ready Paths,
eight Streams or targets, 128 observed Path records, or 4 MiB retained Session
outbound bytes for this small fixture load. At quiescence Streams and targets
must reach zero. Every role must complete SIGTERM shutdown successfully and
remove its control socket.

The fixture requests a two-Path baseline, which permits demand-driven expansion
up to the existing `SessionSlot` ceiling of eight for its minimum of one.
A separate [failed oracle attempt](2026-11-17-runtime-soak-attempt-2.jsonl)
incorrectly treated the baseline as a hard maximum and stopped when normal
autoscaling exceeded two. The corrected check uses that existing runtime
ceiling and makes no product change.

These are validation envelopes for the stated workload, not new product
configuration limits. `/proc` threads are not Tokio task counts. The separate
revoke regression runs the real Ingress/Egress Session actors and verifies that
`RuntimeMetrics::num_alive_tasks()` returns to its initial count after cleanup,
with zero Sessions, Streams and retained bytes. That direct task-lifetime check
complements the repeated process resource measurements.

## Failures found and regression loops

The initial process run reproduced a shutdown error twice after authorization
revocation: `pathchord-ingressd` exited with status 1 and reported
`Ingress data plane failed: Session failed: Session Path closed`. A minimized
real Noise Session regression reproduced it in 0.26 seconds:

```sh
cargo test --locked -p pathchord-cli --test pathchord_tcp \
  revoked_session_does_not_fail_ingress_shutdown -- --exact --nocapture
```

The actor and its command channel had already closed normally. The data-plane
shutdown boundary now accepts `SessionRuntimeError::PathClosed` for that
terminal Session while preserving other errors. The regression passes and also
checks protocol buffers and Tokio task cleanup.

The [first longer attempt](2026-11-17-runtime-soak-attempt-1.jsonl) completed ten
fault cycles and then correctly failed on an unexpected provider flow loss.
Additional [bounded diagnostics](2026-11-17-refresh-admission-gap.jsonl) narrowed
it to HTTP 403 during recovery to a valid provider document, before any DNS or
configuration failure. A successful refresh had unconditionally fenced its
whole source and revoked even unchanged admissions while awaiting publication.
An unchanged unsupported sibling also appeared in the raw invalidation list,
despite having no admitted adapter.

```sh
cargo test --locked -p pathchord-cli --lib \
  unchanged_refresh_keeps_verified_siblings_selectable_before_republication \
  -- --nocapture
```

This minimized regression failed in 0.01 seconds before the fix. A source is
now fenced on refresh only when an actually admitted adapter is replaced or
removed. Unchanged source/configuration/credential identities keep their exact
validated adapter, while changed credentials, deletion and rejected-commit
restoration retain their existing fencing and regression coverage. All seven
node-observation tests pass after the fix.

The existing provider-boundary suite also passes all 10 tests, and all 55
subscription-import tests pass. Their commands are recorded in the
[acceptance matrix](2026-11-17-acceptance-matrix.md). They independently exercise
aggregate fetch budgets, interrupted downloads, origin isolation, sibling
diagnostics, format normalization and credential redaction.

## Final bounded run

The final run passed all twelve complete cycles, with **300.24 seconds of
continuous traffic** and 302.24 seconds total elapsed time. Each of the eight
counted fault families completed twelve times. The Path listener completed
3122 verified 8192-byte echo exchanges and the provider listener completed
5877; no payload corruption occurred. Provider HTTP/parse failures, DNS faults,
configuration reloads and stable windows introduced no additional failed
background exchanges. Fifty local provider fetches were observed.

The intentionally destructive windows interrupted 577 Path exchanges
(171 during relay churn, 280 during endpoint restart, 126 during authorization
revocation) and 122 ordinary-proxy exchanges during source disablement/drain.
Those counters account for all reported background interruptions.

| Process | Peak file descriptors | Peak OS threads | Peak RSS, KiB | Largest observed RSS growth within one process lifetime, KiB |
| --- | ---: | ---: | ---: | ---: |
| Egress | 17 | 1 | 17556 | 232 |
| Path Ingress | 20 | 3 | 51316 | 2132 |
| Provider Ingress | 18 | 3 | 53252 | 7744 |

All sampled protocol/resource bounds passed. Streams and Egress targets reached
zero at quiescence, all three role processes exited successfully on SIGTERM,
their control sockets disappeared, and service-log and management redaction
checks passed. The source and binary checksums in the JSONL identify the exact
tested local artifacts. Workspace-format checks, the scoped CLI all-targets
Clippy check, all five Path integration tests and all seven node-observation
tests also passed for the accompanying fixes.

## Evidence limits

The machine-readable run reports the observed duration, all completed fault
counts, full-payload successes, expected interruptions, binary checksums, and
resource peaks. It supplies bounded local-process evidence. It does not prove
WAN performance, arbitrary real-provider availability, native Windows or
FreeBSD behavior, or endurance beyond the measured interval. Cross-kernel
QEMU protocol evidence belongs to its own matrix, and real-provider sample
provenance remains the separate task 1.1 requirement.
