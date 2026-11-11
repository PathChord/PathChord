# PathChord Protocol Design

## 1. Cryptography

Use `Noise_IK_25519_ChaChaPoly_SHA256` through a mature implementation.

- Ingress and Egress each have a static Curve25519 key pair.
- The Egress public key is static Ingress configuration.
- Egress stores the authorized Ingress public-key list; enrollment changes this list dynamically.
- Every Path performs its own Noise handshake and receives independent transport keys.
- Do not reuse WireGuard private keys for PathChord.
- No X.509 CA, PGP, TOFU, or automatic first-use trust is required.

## 2. Protocol layers

```text
Ingress adapter / local socket
        |
Flow and policy layer
        |
Session / Stream layer
        |
Path framing and scheduling
        |
Noise transport per Path
        |
Transit Proxy transport
```

## 3. Identity and attachment

Conceptual identifiers:

```text
IngressID
EgressID
SessionID
PathID
StreamID
RequestID
```

A new Path authenticates with Noise, negotiates protocol version and capabilities, then sends a session-attach request. Egress binds the Path to the authenticated Ingress identity and the selected Egress Session. A Path cannot join a Session owned by another identity.

## 4. Control messages

The protocol needs at least:

```text
VERSION_NEGOTIATE
SESSION_ATTACH
SESSION_ATTACH_ACK
EGRESS_STATUS
PATH_PROBE
PATH_PROBE_ACK
PATH_DRAIN
PATH_CLOSE
STREAM_OPEN
STREAM_OPEN_ACK
STREAM_FIN
STREAM_RESET
DATA
ACK
WINDOW_UPDATE
SESSION_CLOSE
ERROR
```

Control traffic has reserved capacity. Status reports and heartbeats are carried by existing Paths; no separate reverse connection is created.

## 5. TCP Streams

A Stream represents one target TCP connection. Data is framed with a Stream offset and can be split across multiple Paths. Egress reassembles bytes before writing to the target connection.

Required semantics:

- ordered byte delivery;
- half-close in each direction;
- target FIN/RST propagation;
- per-Stream and Session flow control;
- ACK ranges and duplicate suppression;
- cross-Path retransmission for unacknowledged data;
- bounded reordering buffers;
- backpressure instead of silently dropping TCP bytes.

A connect request carries a unique RequestID. Retrying the request on another Path must be idempotent at Egress so an uncertain response cannot create a second target connection. If the Session is gone and the result is uncertain, fail the local connection and let the application retry.

## 6. UDP sessions

A UDP session is bound to one Egress and one Egress-side socket context. Paths may change, but the protocol does not promise stable public IP/port after the session is recreated.

UDP preserves datagram boundaries. Ordinary application datagrams are not retransmitted by the aggregation layer and may be dropped when expired or over budget. Control messages remain reliable. If a reliable byte-stream transport carries the Path, its own head-of-line behavior is accepted as an implementation limitation.

## 7. Path scheduling

Ingress owns Path creation and admission. Ingress sends the current per-Stream allowed-Path set and scheduling constraints to Egress. Ingress schedules upstream data; Egress schedules downstream data over the existing Paths within those constraints.

Per-Path scheduling uses configured relationship weight plus observed effective capacity. Multiple Paths through one Transit Proxy share the Proxy-to-Egress relationship weight.

## 8. Versioning

Session creation negotiates protocol version and capabilities. Required capability mismatch rejects the Egress from the effective rule set. Optional capabilities are selected by intersection. All Paths in one Session use the same Session semantics.
