# VMess legacy alter-ID interoperability

This note records the implementation and local peer checks for the existing
VMess protocol family. sing-box 1.14.4 pins sing-vmess
`v0.2.9-0.20261019223527-a0c58542bd9d`; the source inspected is
[`client.go`](https://github.com/SagerNet/sing-vmess/blob/a0c58542bd9d/client.go)
and [`protocol.go`](https://github.com/SagerNet/sing-vmess/blob/a0c58542bd9d/protocol.go).
V2Fly 5.53.0 served as a second independent peer.

For `alter_id > 0`, sing-vmess selects the first derived alternative UUID,
regardless of the positive configured count. It authenticates the Unix-second
timestamp with HMAC-MD5 using that UUID and encrypts the request header with
AES-128-CFB using the primary UUID's command key and
`MD5(timestamp_be || timestamp_be || timestamp_be || timestamp_be)` as IV.
The alternate UUID is derived with `MD5(uuid ||
16167dc8-16b6-4e6d-b8bb-65dd68113a81)` and the upstream retry constant in the
exceptional case of equality. The header retains its version, random request
key/IV, response byte, options, address and FNV-1a checksum.

Legacy responses use `MD5(request_key)` and `MD5(request_iv)` as the response
key and IV. Their first four bytes are AES-CFB encrypted. For an AES-CFB body,
the response cipher continues from that header rather than restarting at the
IV; other body methods use their existing independent record codecs. PathChord
rejects nonzero legacy response commands explicitly instead of silently
discarding a requested account switch. The adapter accepts decimal `alter_id`
values from 0 through 65535; zero keeps the existing AEAD header, while a
positive value selects the legacy header. Negative, malformed and overflowing
values are rejected during adapter preparation. This upper bound matches the
`uint16` alternative-ID count used by V2Fly's
[`NewAlterIDs`](https://github.com/v2fly/v2ray-core/blob/v5.56.0/common/protocol/id.go).

The legacy header uses MD5, HMAC-MD5 and CFB for interoperability; it does not
have the authenticated header guarantees of the `alter_id: 0` AEAD mode. It
requires reasonably synchronized client/server clocks and is selected only
when the configuration explicitly contains a positive `alter_id`.

Local tests exercised sing-box 1.14.4 and V2Fly 5.53.0 servers, each with a
four-ID account, using client values 1 and 4. V2Fly was configured to accept
legacy VMess headers. TCP and UDP exchanges covered AES-128-GCM,
ChaCha20-Poly1305, AES-128-CFB, `none` and `zero`, plus global-padding and
authenticated-length combinations for the AEAD body ciphers. sing-box also
covered XUDP, packetaddr, and TLS/WebSocket TCP and UDP with both AEAD and
legacy header modes. The test sent 2048-byte UDP payloads with
sing-box and 1024-byte UDP payloads with V2Fly. In the V2Fly fixture a
2048-byte request reached the target, but its response did not arrive; this
does not establish a general maximum for that peer. A wrong UUID was rejected
by the sing-box fixture before its target received a packet. Deterministic
tests cover a fixed timestamp/ID vector, bounds, response token and command
failures delivered to the TCP reader, and cancelled partial UDP response
parsing with continuous CFB state.
These are local interoperability checks, not WAN or deployment evidence.

TCP response handling also has a deterministic distinction between normal
half-close and protocol failure. After a complete response record, a clean
peer EOF reaches the reader as ordinary EOF. A truncated AEAD record, invalid
AEAD tag/length, truncated CFB body, or failed CFB checksum is retained by the
background relay and returned as an invalid-data read error; the relay no
longer converts it into a successful EOF. The local tests cover complete,
truncated and tampered AEAD records and both CFB truncation and checksum
failures.
