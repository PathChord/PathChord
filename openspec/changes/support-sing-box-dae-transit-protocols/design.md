# Design

## Context

The current adapters and typed node options cover only a subset of the
upstream client matrix. See the proposal for the versioned scope. Existing
subscription caches and the control plane already preserve node diagnostics
and credential boundaries; new adapters must use those same paths.

## Goals / non-goals

**Goals:** Complete the existing native proxy client implementations with
independently verified wire compatibility, preserving all accepted node
parameters and per-protocol failure semantics.

**Non-goals:** Embedding or launching a third-party proxy core at runtime,
importing third-party route graphs, adding new proxy protocols or layer-three
VPN endpoints, and adding SSR or SOCKS4/4a outbound adapters. Inbound listener
behavior is unaffected.

## Decisions

Maintain a versioned protocol and parameter matrix based on the upstream
registries and documentation. Treat a protocol as complete only after its
TCP, UDP, authentication, transport, encryption and subscription variants
have a supported implementation or an explicitly documented, scoped
diagnostic. Protocol labels cannot replace per-option validation.

Vision framing uses independently tracked upload and download states. A
specialized TLS stream must prevent reads crossing the final TLS record and
must drain buffered plaintext before reading raw bytes after DIRECT; the TLS
close notification must not be written into a raw stream. XUDP carries Vision
datagrams, with the `-udp443` switch applied locally and the base flow sent on
the wire.

Adapters receive only validated typed options and private credentials. A
parameter is removed before byte-transport validation only when the adapter
actually implements it. ClientHello fingerprints require the specified wire
profile; selecting a similar cipher order alone does not satisfy that option.

Use independent server fixtures and malformed/fragmented/cancelled I/O
tests. Third-party executables are supplied by the test environment and are
never runtime or release dependencies. Local and deployed evidence remain
distinct. The existing Alpine Egress server receives only binaries or
packages built locally.

## Risks / trade-offs

- Protocols that reuse names for incompatible versions can cause false
  eligibility → validate exact versions, transport combinations and options.
- TLS/raw transitions can corrupt or leak bytes across boundaries → test
  fragmented records, buffered handoff, half-close and independent directions.
- Provider data can contain secrets → retain private storage, sanitized
  diagnostics and credential origin boundaries throughout normalization.
