# Tasks

## 1. AnyTLS protocol codec

- [x] 1.1 Add bounded official default padding-scheme parsing, MD5 digest generation, packet rules, waste frames, and settings validation, and verify codec tests cover malformed rules and bounded output.
- [x] 1.2 Extend AnyTLS command decoding for server settings, padding updates, heartbeats, FIN, ALERT, and waste frames, and verify command-specific payload and Stream ID rules.

## 2. Session pool and protocol runtime

- [x] 2.1 Replace per-request AnyTLS transport creation with a node-owned Session pool that leases one active Stream, retains at most eight idle Sessions, and reaps Sessions idle for 60 seconds. Verify concurrent TCP requests create independent active Sessions and sequential requests reuse a healthy Session.
- [x] 2.2 Implement the Session reader and writer event loops with captured padding state, node-level padding updates, bounded queues, heartbeat responses, and no reciprocal FIN. Verify update and failure state transitions with deterministic in-memory peers.
- [x] 2.3 Route TCP and UoT v2 UDP opens through the same pool and release healthy Sessions only after normal Stream completion. Verify UoT request ordering and no-retry behavior after SYNACK failure.

## 3. Error, cancellation, and interoperability coverage

- [x] 3.1 Preserve partial frame bytes across cancelled reads and close unhealthy Sessions on parser, transport, ALERT, invalid update, or heartbeat failures. Verify errors are sanitized and failed Sessions are never reused.
- [x] 3.2 Add sing-box 1.14.4 and current pinned source-peer tests for padding, update negotiation, Session reuse, TCP, UoT UDP, FIN, ALERT, and heartbeat behavior. Verify the release and source matrices separately.
- [ ] 3.3 Run cargo fmt, workspace Clippy, Transit and workspace tests, OpenSpec strict validation, bilingual requirement identity checks, and git diff --check. Record local and external peer evidence separately in implementation-status.md.
