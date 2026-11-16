# Tasks

## 1. Versioned compatibility inventory

- [x] 1.1 Record the supported options and known gaps for existing protocol families in sing-box 1.14.4 and dae 2.1.2, excluding new protocols and VPN endpoints; verify against upstream code and documentation.

## 1A. Provider-specific acceptance

- [x] 1A.1 Normalize every node and connection option in both supplied subscriptions, including Clash and sing-box forms, without retaining provider secrets in source, logs or reports; verify the imported node counts, option diagnostics and cache reload.
- [x] 1A.2 Implement and independently verify VLESS Vision REALITY with Chrome, iOS and Safari ClientHello profiles, and VLESS WebSocket/TLS with Chrome and iOS profiles, including both TCP and UDP paths where configured.
- [x] 1A.3 Implement and independently verify the supplied Hysteria2 certificate SHA-256 pin, explicit insecure combination, SNI and matching `ports`/`mport` hopping ranges, plus the supplied Shadowsocks cipher.
- [x] 1A.4 Run the current local Ingress without Egress against every provider node; record anonymized end-to-end TCP/UDP successes and failures separately from equivalent independent-client results, and distinguish unavailable servers from unsupported options.

## 2. VLESS, Vision and shared transports

- [x] 2.1 Complete Vision framing and directional DIRECT handoff, both registered flows and XUDP, and verify fragmentation, cancellation, half-close and real TLS traffic with independent peers.
- [x] 2.2 Implement supported VLESS REALITY ClientHello fingerprints and options without silent substitution; verify accepted and rejected profiles against independent peers.
- [x] 2.3 Complete TCP, WebSocket early data, HTTP, gRPC, HTTPUpgrade, QUIC and Meek transport combinations used by existing protocol families; verify each applicable combination against a server peer.
- [ ] 2.4 Implement applicable packet encodings, multiplex and proxy-chain options for existing protocols and verify failure and TCP/UDP behavior with independent peers.

## 3. Other existing protocol families

- [x] 3.1 Complete HTTP/HTTPS and SOCKS5 authentication, TLS, TCP and UDP options with peer and error-path tests.
- [ ] 3.2 Complete Shadowsocks ciphers and applicable native plugins and Trojan-go combinations without adding excluded protocols; verify TCP/UDP against independent peers.
- [ ] 3.3 Complete VMess authentication, body-security, transport and datagram options supported by the selected upstream versions; verify with independent peers.
- [ ] 3.4 Complete Hysteria2, TUIC and AnyTLS transport, congestion, obfuscation, authentication and datagram options; verify against independent peers.

## 4. Import, documentation and integrated validation

- [ ] 4.1 Normalize supported subscription forms and options end to end, preserving credential boundaries, cache behavior and explicit diagnostics; verify provider and control-plane tests.
- [x] 4.2 Synchronize the bilingual Transit contract and affected guides with the accepted option matrix; verify translations, local links and strict OpenSpec validation.
- [ ] 4.3 Run workspace format, Clippy and tests, the applicable independent-peer matrix and a locally built binary through the existing Egress server; record each evidence level separately.
- [x] 4.4 Bind subscription selection and runtime publication to the exact prepared adapter, source and generation; revalidate cache loads and cover capabilities, stale results, cancellation, failures and registration conflicts as described in [verified subscription nodes](research/verified-subscription-nodes.md).
