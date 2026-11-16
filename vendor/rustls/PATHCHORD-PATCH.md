# PathChord rustls patch

This directory vendors rustls 0.23.46 from crates.io. The original registry
archive SHA-256 is
`48e13bd8c0e9365c43cfa5c9e8f9ad49d3c8444926c9aac819e0e4dc503c8fdf`.
The upstream licenses remain in this directory.

PathChord adds a narrow REALITY ClientHello callback and key-exchange hook,
then extends them with independent X25519 and X25519MLKEM768 shares and the
Chrome 133, iOS 14, Safari 16, Edge 85, QQ 11.1, Firefox 120 and Android 11
ClientHello profiles matching dae 2.1.2's
uTLS 1.8.2 behavior. The profiles freeze the encoded ClientHello before
computing the REALITY proof and entering the TLS transcript. Ordinary TLS
supports P-256/P-384 HelloRetryRequest; REALITY rejects it explicitly.
Unsupported resumption, real ECH and ALPS combinations fail explicitly.
Brotli and zlib certificate decompression are enabled by the Transit crate.
Firefox supplies independent X25519 and P-256 key shares and advertises the
maximum receive limit permitted by RFC 8449. A valid peer receive limit caps
protected outbound records without changing the independently advertised
inbound limit or increasing a stricter configured fragment limit.
Android 11 is TLS 1.2 only and advertises no ALPN; a peer choosing an
advertised cipher unsupported by rustls fails explicitly. The 360 7.5 preset
has no cipher suite supported by rustls and is rejected before dialing.

When a fingerprint emits ECH GREASE, rustls records the actual offer as GREASE
and handles retry configurations without enabling real ECH. Fingerprints that
request SCTs accept a structurally valid SCT list only on the end-entity X.509
certificate; unsolicited, duplicate, malformed and raw-public-key SCT
extensions are rejected. This does not add certificate-transparency log
verification or change certificate chain, handshake signature, or Finished
verification.

Regression coverage lives in `crates/pathchord-transit/src/reality_tls.rs`
and `reality_adapter.rs`. The ignored fixtures compare actual ClientHellos
with dae's uTLS and run local Xray and sing-box servers; those executables are
test-only. `crates/pathchord-transit/tests/tls_ech_external.rs` additionally
exercises ECH GREASE and compressed SCT certificates against OpenSSL 4 with
Brotli certificate compression. `tls_alps_external.rs` checks both advertised
ALPS code points against an independent OpenSSL peer, and
`tls_record_limit_external.rs` covers TLS 1.2/1.3 limit negotiation and
malformed, duplicate, unsolicited and out-of-range responses. When upgrading
rustls, rebase and review this patch against the upstream handshake state
machine, rerun key-share and certificate-proof fixtures, and do not remove the
patch until an equivalent supported upstream interface exists.
