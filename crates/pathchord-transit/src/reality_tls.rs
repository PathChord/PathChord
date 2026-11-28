//! Safe rustls key-exchange seam for REALITY.
//!
//! Offers X25519MLKEM768 and an independent X25519 share so the REALITY
//! callback can derive its proof from the latter.

use std::fmt;
use std::sync::Arc;

use rustls::crypto::{ActiveKeyExchange, CryptoProvider, SharedSecret, SupportedKxGroup};
use rustls::{Error, NamedGroup, PeerMisbehaved, ProtocolVersion};
use x25519_dalek::{PublicKey, StaticSecret};

#[derive(Debug)]
pub(crate) struct RealityX25519Group;

pub(crate) static REALITY_X25519_GROUP: RealityX25519Group = RealityX25519Group;

#[derive(Debug)]
struct RealityHybridGroup;

static REALITY_HYBRID_GROUP: RealityHybridGroup = RealityHybridGroup;

#[derive(Debug)]
struct RealityFirefoxGroup;

static REALITY_FIREFOX_GROUP: RealityFirefoxGroup = RealityFirefoxGroup;

impl SupportedKxGroup for RealityFirefoxGroup {
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, Error> {
        Ok(Box::new(RealityFirefoxExchange {
            x25519: REALITY_X25519_GROUP.start()?,
            p256: rustls::crypto::aws_lc_rs::kx_group::SECP256R1.start()?,
        }))
    }

    fn name(&self) -> NamedGroup {
        NamedGroup::X25519
    }

    fn fips(&self) -> bool {
        false
    }
}

struct RealityFirefoxExchange {
    x25519: Box<dyn ActiveKeyExchange>,
    p256: Box<dyn ActiveKeyExchange>,
}

impl ActiveKeyExchange for RealityFirefoxExchange {
    fn extract_reality_key(&self, server_pub_key: &[u8]) -> Option<Vec<u8>> {
        self.x25519.extract_reality_key(server_pub_key)
    }

    fn complete(self: Box<Self>, peer_pub_key: &[u8]) -> Result<SharedSecret, Error> {
        self.x25519.complete(peer_pub_key)
    }

    fn alternate_key_share(&self) -> Option<(NamedGroup, &[u8])> {
        Some((NamedGroup::secp256r1, self.p256.pub_key()))
    }

    fn complete_alternate_key_share(
        self: Box<Self>,
        peer_pub_key: &[u8],
    ) -> Result<SharedSecret, Error> {
        self.p256.complete(peer_pub_key)
    }

    fn pub_key(&self) -> &[u8] {
        self.x25519.pub_key()
    }

    fn group(&self) -> NamedGroup {
        NamedGroup::X25519
    }
}

impl SupportedKxGroup for RealityHybridGroup {
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, Error> {
        let hybrid = rustls::crypto::aws_lc_rs::kx_group::X25519MLKEM768.start()?;
        let x25519 = REALITY_X25519_GROUP.start()?;
        Ok(Box::new(RealityActiveHybrid { hybrid, x25519 }))
    }

    fn name(&self) -> NamedGroup {
        NamedGroup::X25519MLKEM768
    }

    fn usable_for_version(&self, version: ProtocolVersion) -> bool {
        version == ProtocolVersion::TLSv1_3
    }

    fn fips(&self) -> bool {
        false
    }
}

struct RealityActiveHybrid {
    hybrid: Box<dyn ActiveKeyExchange>,
    // REALITY authenticates against this independently generated X25519 share,
    // which follows the hybrid share in ClientHello.
    x25519: Box<dyn ActiveKeyExchange>,
}

impl ActiveKeyExchange for RealityActiveHybrid {
    fn extract_reality_key(&self, server_pub_key: &[u8]) -> Option<Vec<u8>> {
        self.x25519.extract_reality_key(server_pub_key)
    }

    fn complete(self: Box<Self>, peer_pub_key: &[u8]) -> Result<SharedSecret, Error> {
        self.hybrid.complete(peer_pub_key)
    }

    fn alternate_key_share(&self) -> Option<(NamedGroup, &[u8])> {
        Some((NamedGroup::X25519, self.x25519.pub_key()))
    }

    fn complete_alternate_key_share(
        self: Box<Self>,
        peer_pub_key: &[u8],
    ) -> Result<SharedSecret, Error> {
        self.x25519.complete(peer_pub_key)
    }

    fn pub_key(&self) -> &[u8] {
        self.hybrid.pub_key()
    }

    fn group(&self) -> NamedGroup {
        NamedGroup::X25519MLKEM768
    }
}

impl SupportedKxGroup for RealityX25519Group {
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, Error> {
        let mut secret = [0_u8; 32];
        getrandom::fill(&mut secret)
            .map_err(|_| Error::General("REALITY key generation failed".to_owned()))?;
        let secret = StaticSecret::from(secret);
        let public = PublicKey::from(&secret).to_bytes();
        Ok(Box::new(RealityActiveX25519 { secret, public }))
    }

    fn name(&self) -> NamedGroup {
        NamedGroup::X25519
    }

    fn fips(&self) -> bool {
        false
    }
}

struct RealityActiveX25519 {
    secret: StaticSecret,
    public: [u8; 32],
}

impl fmt::Debug for RealityActiveX25519 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RealityActiveX25519(..)")
    }
}

impl ActiveKeyExchange for RealityActiveX25519 {
    fn extract_reality_key(&self, server_pub_key: &[u8]) -> Option<Vec<u8>> {
        let server_pub_key: [u8; 32] = server_pub_key.try_into().ok()?;
        let shared = self.secret.diffie_hellman(&PublicKey::from(server_pub_key));
        (!shared.as_bytes().iter().all(|byte| *byte == 0)).then(|| shared.as_bytes().to_vec())
    }

    fn complete(self: Box<Self>, peer_pub_key: &[u8]) -> Result<SharedSecret, Error> {
        let peer_pub_key: [u8; 32] = peer_pub_key
            .try_into()
            .map_err(|_| Error::PeerMisbehaved(PeerMisbehaved::InvalidKeyShare))?;
        let shared = self.secret.diffie_hellman(&PublicKey::from(peer_pub_key));
        if shared.as_bytes().iter().all(|byte| *byte == 0) {
            return Err(Error::PeerMisbehaved(PeerMisbehaved::InvalidKeyShare));
        }
        Ok(SharedSecret::from(shared.as_bytes().to_vec()))
    }

    fn pub_key(&self) -> &[u8] {
        &self.public
    }

    fn group(&self) -> NamedGroup {
        NamedGroup::X25519
    }
}

pub(crate) fn provider_with_reality_x25519() -> CryptoProvider {
    let mut provider = rustls::crypto::aws_lc_rs::default_provider();
    provider.kx_groups = vec![
        &REALITY_HYBRID_GROUP as &'static dyn SupportedKxGroup,
        &REALITY_X25519_GROUP as &'static dyn SupportedKxGroup,
        rustls::crypto::aws_lc_rs::kx_group::SECP256R1,
        rustls::crypto::aws_lc_rs::kx_group::SECP384R1,
    ];
    provider
}

pub(crate) fn reality_provider_arc() -> Arc<CryptoProvider> {
    Arc::new(provider_with_reality_x25519())
}

pub(crate) fn reality_provider_classic_arc() -> Arc<CryptoProvider> {
    let mut provider = rustls::crypto::aws_lc_rs::default_provider();
    provider.kx_groups = vec![
        &REALITY_X25519_GROUP as &'static dyn SupportedKxGroup,
        rustls::crypto::aws_lc_rs::kx_group::SECP256R1,
        rustls::crypto::aws_lc_rs::kx_group::SECP384R1,
    ];
    Arc::new(provider)
}

pub(crate) fn reality_provider_firefox_arc() -> Arc<CryptoProvider> {
    let mut provider = rustls::crypto::aws_lc_rs::default_provider();
    provider.kx_groups = vec![
        &REALITY_FIREFOX_GROUP as &'static dyn SupportedKxGroup,
        rustls::crypto::aws_lc_rs::kx_group::SECP256R1,
        rustls::crypto::aws_lc_rs::kx_group::SECP384R1,
    ];
    Arc::new(provider)
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Mutex,
        atomic::{AtomicUsize, Ordering},
    };
    use std::time::Duration;

    use rustls::client::{ClientHelloProfile, EchStatus, RealityCallback, Resumption};
    use rustls::pki_types::{PrivatePkcs8KeyDer, ServerName};
    use rustls::{ClientConfig, ClientConnection, RootCertStore, ServerConfig};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio_rustls::{TlsAcceptor, TlsConnector};

    use super::*;

    static BROTLI_CALLS: AtomicUsize = AtomicUsize::new(0);
    static COUNTING_BROTLI: CountingBrotli = CountingBrotli;

    #[derive(Debug)]
    struct CountingBrotli;

    impl rustls::compress::CertDecompressor for CountingBrotli {
        fn decompress(
            &self,
            input: &[u8],
            output: &mut [u8],
        ) -> Result<(), rustls::compress::DecompressionFailed> {
            BROTLI_CALLS.fetch_add(1, Ordering::Relaxed);
            rustls::compress::BROTLI_DECOMPRESSOR.decompress(input, output)
        }

        fn algorithm(&self) -> rustls::CertificateCompressionAlgorithm {
            rustls::CertificateCompressionAlgorithm::Brotli
        }
    }

    #[derive(Debug, Default)]
    struct ChromeProbe {
        authenticated_hello: Mutex<Vec<u8>>,
    }

    impl RealityCallback for ChromeProbe {
        fn apply_reality(
            &self,
            _kx: &dyn ActiveKeyExchange,
            _random: &[u8; 32],
            session_id: &mut [u8; 32],
            raw_hello: &[u8],
        ) -> Result<(), Error> {
            *self.authenticated_hello.lock().unwrap() = raw_hello.to_vec();
            session_id.fill(0x55);
            Ok(())
        }
    }

    fn chrome_client_hello() -> (Vec<u8>, Vec<u8>) {
        chrome_client_hello_for(ClientHelloProfile::Chrome133)
    }

    fn chrome_client_hello_for(profile: ClientHelloProfile) -> (Vec<u8>, Vec<u8>) {
        let probe = Arc::new(ChromeProbe::default());
        let provider = if profile == ClientHelloProfile::Chrome133 {
            reality_provider_arc()
        } else {
            reality_provider_classic_arc()
        };
        let mut config = ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(RootCertStore::empty())
            .with_no_client_auth();
        config.resumption = Resumption::disabled();
        config.client_hello_profile = Some(profile);
        config.reality_callback = Some(probe.clone());
        let mut client = ClientConnection::new(
            Arc::new(config),
            ServerName::try_from("proxy.test").unwrap(),
        )
        .unwrap();
        let mut wire = Vec::new();
        client.write_tls(&mut wire).unwrap();
        let authenticated = probe.authenticated_hello.lock().unwrap().clone();
        (wire, authenticated)
    }

    #[test]
    fn client_hello_profiles_report_ech_grease_only_when_sent() {
        for (profile, expected_status) in [
            (Some(ClientHelloProfile::Chrome133), EchStatus::Grease),
            (
                Some(ClientHelloProfile::Chrome133Classic),
                EchStatus::Grease,
            ),
            (Some(ClientHelloProfile::Ios14), EchStatus::NotOffered),
            (Some(ClientHelloProfile::Safari16), EchStatus::NotOffered),
            (Some(ClientHelloProfile::Edge85), EchStatus::NotOffered),
            (Some(ClientHelloProfile::Qq111), EchStatus::NotOffered),
            (Some(ClientHelloProfile::Firefox120), EchStatus::Grease),
            (None, EchStatus::NotOffered),
        ] {
            let provider = if profile == Some(ClientHelloProfile::Firefox120) {
                reality_provider_firefox_arc()
            } else if profile == Some(ClientHelloProfile::Chrome133) {
                reality_provider_arc()
            } else {
                reality_provider_classic_arc()
            };
            let mut config = ClientConfig::builder_with_provider(provider)
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_root_certificates(RootCertStore::empty())
                .with_no_client_auth();
            config.client_hello_profile = profile;
            let client = ClientConnection::new(
                Arc::new(config),
                ServerName::try_from("proxy.test").unwrap(),
            )
            .unwrap();
            assert_eq!(client.ech_status(), expected_status, "profile {profile:?}");
        }
    }

    #[derive(Debug, PartialEq, Eq)]
    struct NormalizedHello {
        ciphers: Vec<u16>,
        extensions: Vec<(u16, Vec<u8>)>,
    }

    fn normalize_chrome_hello(wire: &[u8]) -> NormalizedHello {
        fn take<'a>(bytes: &'a [u8], offset: &mut usize, length: usize) -> &'a [u8] {
            let result = &bytes[*offset..*offset + length];
            *offset += length;
            result
        }
        fn number(bytes: &[u8], offset: &mut usize) -> u16 {
            u16::from_be_bytes(take(bytes, offset, 2).try_into().unwrap())
        }
        fn normalized(value: u16) -> u16 {
            if value.to_be_bytes()[0] == value.to_be_bytes()[1] && value & 0x0f0f == 0x0a0a {
                0x0a0a
            } else {
                value
            }
        }
        fn numbers(bytes: &[u8]) -> Vec<u16> {
            assert_eq!(bytes.len() % 2, 0);
            bytes
                .as_chunks::<2>()
                .0
                .iter()
                .map(|value| normalized(u16::from_be_bytes(*value)))
                .collect()
        }

        let hello = if wire[0] == 0x16 { &wire[5..] } else { wire };
        assert_eq!(hello[0], 1);
        assert_eq!(
            hello.len(),
            4 + (usize::from(hello[1]) << 16 | usize::from(hello[2]) << 8 | usize::from(hello[3]))
        );
        assert_eq!(&hello[4..6], &[3, 3]);
        let mut offset = 4 + 2 + 32;
        let session_length = usize::from(take(hello, &mut offset, 1)[0]);
        assert_eq!(session_length, 32);
        take(hello, &mut offset, session_length);
        let cipher_length = usize::from(number(hello, &mut offset));
        let ciphers = numbers(take(hello, &mut offset, cipher_length));
        let compression_length = usize::from(take(hello, &mut offset, 1)[0]);
        assert_eq!(take(hello, &mut offset, compression_length), &[0]);
        let extension_length = usize::from(number(hello, &mut offset));
        let block = take(hello, &mut offset, extension_length);
        assert_eq!(offset, hello.len());
        let mut extensions = Vec::new();
        let mut cursor = 0;
        while cursor < block.len() {
            let kind = normalized(number(block, &mut cursor));
            let length = usize::from(number(block, &mut cursor));
            let body = take(block, &mut cursor, length);
            let value = match kind {
                0x000a | 0x000d => {
                    let size = usize::from(u16::from_be_bytes(body[..2].try_into().unwrap()));
                    assert_eq!(size, body.len() - 2);
                    numbers(&body[2..])
                        .into_iter()
                        .flat_map(u16::to_be_bytes)
                        .collect()
                }
                0x002b => {
                    assert_eq!(usize::from(body[0]), body.len() - 1);
                    numbers(&body[1..])
                        .into_iter()
                        .flat_map(u16::to_be_bytes)
                        .collect()
                }
                0x0033 => {
                    let mut i = 0;
                    assert_eq!(usize::from(number(body, &mut i)), body.len() - 2);
                    let mut result = Vec::new();
                    let mut keys = Vec::new();
                    while i < body.len() {
                        let group = normalized(number(body, &mut i));
                        let size = number(body, &mut i);
                        let key = take(body, &mut i, usize::from(size));
                        if group == 0x0a0a {
                            assert_eq!(key, &[0]);
                        }
                        result.extend_from_slice(&group.to_be_bytes());
                        result.extend_from_slice(&size.to_be_bytes());
                        keys.push((group, key));
                    }
                    let lengths = keys
                        .iter()
                        .map(|(group, key)| (*group, key.len()))
                        .collect::<Vec<_>>();
                    if lengths.len() == 3 {
                        assert_eq!(lengths, [(0x0a0a, 1), (0x11ec, 1216), (0x001d, 32)]);
                        assert_ne!(&keys[1].1[1184..], keys[2].1);
                    } else {
                        assert_eq!(lengths, [(0x0a0a, 1), (0x001d, 32)]);
                    }
                    result
                }
                0xfe0d => {
                    assert_eq!(&body[..5], &[0, 0, 1, 0, 1]);
                    assert_eq!(&body[6..8], &[0, 32]);
                    let payload_length =
                        usize::from(u16::from_be_bytes(body[40..42].try_into().unwrap()));
                    assert!([144, 176, 208, 240].contains(&payload_length));
                    assert_eq!(body.len(), 42 + payload_length);
                    vec![0, 0, 1, 0, 1, 0, 32]
                }
                _ => body.to_vec(),
            };
            extensions.push((kind, value));
        }
        assert_eq!(
            extensions
                .first()
                .map(|value| (&value.0, value.1.as_slice())),
            Some((&0x0a0a, &[][..]))
        );
        assert_eq!(
            extensions
                .last()
                .map(|value| (&value.0, value.1.as_slice())),
            Some((&0x0a0a, &[0][..]))
        );
        extensions.sort();
        NormalizedHello {
            ciphers,
            extensions,
        }
    }

    #[test]
    fn chrome_profile_keeps_reality_authenticated_bytes_stable() {
        for profile in [
            ClientHelloProfile::Chrome133,
            ClientHelloProfile::Chrome133Classic,
        ] {
            let (wire, authenticated) = chrome_client_hello_for(profile);
            let encoded = &wire[5..];
            assert_eq!(&authenticated[39..71], &[0; 32]);
            assert_eq!(&encoded[39..71], &[0x55; 32]);
            assert_eq!(&authenticated[..39], &encoded[..39]);
            assert_eq!(&authenticated[71..], &encoded[71..]);
            let normalized = normalize_chrome_hello(&wire);
            assert_eq!(
                normalized.ciphers,
                [
                    0x0a0a, 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8,
                    0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035
                ]
            );
            assert_eq!(normalized.extensions.len(), 18);
            let mut expected = vec![
                (0x0000, b"\0\r\0\0\x0aproxy.test".to_vec()),
                (0x0005, vec![1, 0, 0, 0, 0]),
                (0x000b, vec![1, 0]),
                (0x000d, vec![4, 3, 8, 4, 4, 1, 5, 3, 8, 5, 5, 1, 8, 6, 6, 1]),
                (0x0010, b"\0\x0c\x02h2\x08http/1.1".to_vec()),
                (0x0012, vec![]),
                (0x0017, vec![]),
                (0x001b, vec![2, 0, 2]),
                (0x0023, vec![]),
                (0x002b, vec![0x0a, 0x0a, 3, 4, 3, 3]),
                (0x002d, vec![1, 1]),
                (0x0a0a, vec![]),
                (0x0a0a, vec![0]),
                (0x44cd, vec![0, 3, 2, b'h', b'2']),
                (0xfe0d, vec![0, 0, 1, 0, 1, 0, 32]),
                (0xff01, vec![0]),
            ];
            if profile == ClientHelloProfile::Chrome133 {
                expected.push((
                    0x000a,
                    vec![0x0a, 0x0a, 0x11, 0xec, 0, 0x1d, 0, 0x17, 0, 0x18],
                ));
                expected.push((
                    0x0033,
                    vec![0x0a, 0x0a, 0, 1, 0x11, 0xec, 4, 0xc0, 0, 0x1d, 0, 32],
                ));
            } else {
                expected.push((0x000a, vec![0x0a, 0x0a, 0, 0x1d, 0, 0x17, 0, 0x18]));
                expected.push((0x0033, vec![0x0a, 0x0a, 0, 1, 0, 0x1d, 0, 32]));
            }
            expected.sort();
            assert_eq!(normalized.extensions, expected);
        }
    }

    #[test]
    #[ignore = "requires PATHCHORD_TEST_DAE_CHROME_HELLO captured from dae's uTLS 1.8.2 Chrome133 preset"]
    fn chrome_profile_matches_dae_utls_client_hello() {
        let reference =
            std::fs::read(std::env::var_os("PATHCHORD_TEST_DAE_CHROME_HELLO").unwrap()).unwrap();
        let (wire, _) = chrome_client_hello();
        assert_eq!(
            normalize_chrome_hello(&wire),
            normalize_chrome_hello(&reference)
        );
        let reference =
            std::fs::read(std::env::var_os("PATHCHORD_TEST_DAE_CHROME_CLASSIC_HELLO").unwrap())
                .unwrap();
        let (wire, _) = chrome_client_hello_for(ClientHelloProfile::Chrome133Classic);
        assert_eq!(
            normalize_chrome_hello(&wire),
            normalize_chrome_hello(&reference)
        );
    }

    #[test]
    fn chrome_profile_rejects_missing_brotli_support() {
        let mut config = ClientConfig::builder_with_provider(reality_provider_arc())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(RootCertStore::empty())
            .with_no_client_auth();
        config.resumption = Resumption::disabled();
        config.client_hello_profile = Some(ClientHelloProfile::Chrome133);
        config.cert_decompressors.clear();
        config.reality_callback = Some(Arc::new(ChromeProbe::default()));
        assert!(matches!(
            ClientConnection::new(Arc::new(config), ServerName::try_from("proxy.test").unwrap()),
            Err(Error::General(message)) if message.contains("certificate decompression")
        ));
    }

    fn normalize_apple_hello(wire: &[u8]) -> (Vec<u16>, Vec<(u16, Vec<u8>)>) {
        fn number(bytes: &[u8], position: &mut usize) -> u16 {
            let value = u16::from_be_bytes([bytes[*position], bytes[*position + 1]]);
            *position += 2;
            value
        }
        fn grease(value: u16) -> u16 {
            if value.to_be_bytes()[0] == value.to_be_bytes()[1] && value & 0x0f0f == 0x0a0a {
                0x0a0a
            } else {
                value
            }
        }
        fn normalize_pairs(bytes: &mut [u8]) {
            for value in bytes.as_chunks_mut::<2>().0 {
                *value = grease(u16::from_be_bytes(*value)).to_be_bytes();
            }
        }
        let hello = if wire[0] == 0x16 { &wire[5..] } else { wire };
        assert_eq!(hello[0], 1);
        let mut pos = 4 + 2 + 32;
        let session = usize::from(hello[pos]);
        pos += 1 + session;
        let cipher_len = usize::from(number(hello, &mut pos));
        let ciphers = hello[pos..pos + cipher_len]
            .as_chunks::<2>()
            .0
            .iter()
            .map(|x| grease(u16::from_be_bytes(*x)))
            .collect();
        pos += cipher_len;
        pos += 1 + usize::from(hello[pos]);
        let ext_len = usize::from(number(hello, &mut pos));
        let end = pos + ext_len;
        assert_eq!(end, hello.len());
        let mut extensions = Vec::new();
        while pos < end {
            let kind = grease(number(hello, &mut pos));
            let len = usize::from(number(hello, &mut pos));
            let mut body = hello[pos..pos + len].to_vec();
            pos += len;
            match kind {
                0x000a => normalize_pairs(&mut body[2..]),
                0x002b => normalize_pairs(&mut body[1..]),
                0x0033 => {
                    let mut at = 2;
                    while at < body.len() {
                        let group = grease(number(&body, &mut at));
                        let n = usize::from(number(&body, &mut at));
                        let offset = at - 4;
                        body[offset..offset + 2].copy_from_slice(&group.to_be_bytes());
                        if group == 0x001d {
                            body[at..at + n].fill(0);
                        }
                        at += n;
                    }
                }
                _ => {}
            }
            extensions.push((kind, body));
        }
        (ciphers, extensions)
    }

    #[test]
    #[ignore = "requires PATHCHORD_TEST_DAE_IOS_HELLO and PATHCHORD_TEST_DAE_SAFARI_HELLO"]
    fn apple_profiles_match_dae_utls_client_hello() {
        for (profile, variable) in [
            (ClientHelloProfile::Ios14, "PATHCHORD_TEST_DAE_IOS_HELLO"),
            (
                ClientHelloProfile::Safari16,
                "PATHCHORD_TEST_DAE_SAFARI_HELLO",
            ),
        ] {
            let reference = std::fs::read(std::env::var_os(variable).unwrap()).unwrap();
            let (wire, authenticated) = chrome_client_hello_for(profile);
            assert_eq!(&authenticated[..39], &wire[5..44]);
            assert_eq!(&authenticated[71..], &wire[76..]);
            assert_eq!(
                normalize_apple_hello(&wire),
                normalize_apple_hello(&reference)
            );
        }
    }

    static ZLIB_CALLS: AtomicUsize = AtomicUsize::new(0);
    static COUNTING_ZLIB: CountingZlib = CountingZlib;

    #[derive(Debug)]
    struct CountingZlib;

    impl rustls::compress::CertDecompressor for CountingZlib {
        fn decompress(
            &self,
            input: &[u8],
            output: &mut [u8],
        ) -> Result<(), rustls::compress::DecompressionFailed> {
            ZLIB_CALLS.fetch_add(1, Ordering::Relaxed);
            rustls::compress::ZLIB_DECOMPRESSOR.decompress(input, output)
        }

        fn algorithm(&self) -> rustls::CertificateCompressionAlgorithm {
            rustls::CertificateCompressionAlgorithm::Zlib
        }
    }

    #[tokio::test]
    async fn safari_negotiates_and_decompresses_zlib_certificate() {
        let rcgen::CertifiedKey { cert, signing_key } =
            rcgen::generate_simple_self_signed(vec!["proxy.test".into()]).unwrap();
        let mut server = ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.der().clone()],
            PrivatePkcs8KeyDer::from(signing_key.serialize_der()).into(),
        )
        .unwrap();
        server.cert_compressors = vec![rustls::compress::ZLIB_COMPRESSOR];
        let mut roots = RootCertStore::empty();
        roots.add(cert.der().clone()).unwrap();
        let mut client = ClientConfig::builder_with_provider(reality_provider_classic_arc())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        client.resumption = Resumption::disabled();
        client.client_hello_profile = Some(ClientHelloProfile::Safari16);
        client.cert_decompressors = vec![&COUNTING_ZLIB];
        let before = ZLIB_CALLS.load(Ordering::Relaxed);
        let (client_io, server_io) = tokio::io::duplex(65536);
        let peer = tokio::spawn(async move {
            let mut stream = TlsAcceptor::from(Arc::new(server))
                .accept(server_io)
                .await
                .unwrap();
            stream.write_all(b"ok").await.unwrap();
            stream.flush().await.unwrap();
        });
        let mut stream = TlsConnector::from(Arc::new(client))
            .connect(ServerName::try_from("proxy.test").unwrap(), client_io)
            .await
            .unwrap();
        let mut output = [0; 2];
        stream.read_exact(&mut output).await.unwrap();
        assert_eq!(&output, b"ok");
        peer.await.unwrap();
        assert_eq!(ZLIB_CALLS.load(Ordering::Relaxed), before + 1);
    }

    #[test]
    fn custom_group_matches_x25519_and_rejects_bad_peer_keys() {
        let active = REALITY_X25519_GROUP.start().unwrap();
        assert_eq!(active.group(), NamedGroup::X25519);
        assert_eq!(active.pub_key().len(), 32);
        assert!(matches!(
            active.complete(&[0; 31]),
            Err(Error::PeerMisbehaved(PeerMisbehaved::InvalidKeyShare))
        ));
    }

    #[test]
    fn provider_offers_independent_hybrid_and_x25519_shares() {
        let provider = provider_with_reality_x25519();
        assert_eq!(
            provider
                .kx_groups
                .iter()
                .map(|group| group.name())
                .collect::<Vec<_>>(),
            [
                NamedGroup::X25519MLKEM768,
                NamedGroup::X25519,
                NamedGroup::secp256r1,
                NamedGroup::secp384r1,
            ]
        );
        let active = REALITY_HYBRID_GROUP.start().unwrap();
        let hybrid = active.pub_key();
        let (group, standalone) = active.alternate_key_share().unwrap();
        assert_eq!(group, NamedGroup::X25519);
        assert_eq!(hybrid.len(), 1184 + 32);
        assert_eq!(standalone.len(), 32);
        assert_ne!(&hybrid[1184..], standalone);

        let server_secret = StaticSecret::from([7_u8; 32]);
        let server_public = PublicKey::from(&server_secret);
        let client_public = PublicKey::from(<[u8; 32]>::try_from(standalone).unwrap());
        let expected = server_secret.diffie_hellman(&client_public);
        assert_eq!(
            active
                .extract_reality_key(server_public.as_bytes())
                .unwrap(),
            expected.as_bytes()
        );
        assert!(active.extract_reality_key(&[0; 32]).is_none());
    }

    #[test]
    fn client_hello_contains_both_shares_in_order() {
        fn take<'a>(data: &'a [u8], offset: &mut usize, size: usize) -> &'a [u8] {
            let bytes = &data[*offset..*offset + size];
            *offset += size;
            bytes
        }
        fn u16_field(data: &[u8], offset: &mut usize) -> usize {
            usize::from(u16::from_be_bytes(
                take(data, offset, 2).try_into().unwrap(),
            ))
        }

        let config = ClientConfig::builder_with_provider(Arc::new(provider_with_reality_x25519()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(RootCertStore::empty())
            .with_no_client_auth();
        let mut connection = ClientConnection::new(
            Arc::new(config),
            ServerName::try_from("proxy.test").unwrap(),
        )
        .unwrap();
        let mut hello = Vec::new();
        connection.write_tls(&mut hello).unwrap();
        let mut offset = 5 + 4 + 2 + 32;
        let session_length = usize::from(take(&hello, &mut offset, 1)[0]);
        take(&hello, &mut offset, session_length);
        let cipher_length = u16_field(&hello, &mut offset);
        take(&hello, &mut offset, cipher_length);
        let compression_length = usize::from(take(&hello, &mut offset, 1)[0]);
        take(&hello, &mut offset, compression_length);
        let extensions_length = u16_field(&hello, &mut offset);
        let extensions = take(&hello, &mut offset, extensions_length);
        let mut extension_offset = 0;
        let mut shares = None;
        while extension_offset < extensions.len() {
            let kind = u16_field(extensions, &mut extension_offset);
            let length = u16_field(extensions, &mut extension_offset);
            let body = take(extensions, &mut extension_offset, length);
            if kind == 0x0033 {
                shares = Some(body);
            }
        }
        let shares = shares.expect("key_share extension");
        let mut share_offset = 0;
        let list_length = u16_field(shares, &mut share_offset);
        assert_eq!(list_length, shares.len() - 2);
        let hybrid_group = u16_field(shares, &mut share_offset);
        let hybrid_length = u16_field(shares, &mut share_offset);
        let hybrid = take(shares, &mut share_offset, hybrid_length);
        let x25519_group = u16_field(shares, &mut share_offset);
        let x25519_length = u16_field(shares, &mut share_offset);
        let x25519 = take(shares, &mut share_offset, x25519_length);
        assert_eq!((hybrid_group, hybrid_length), (0x11ec, 1216));
        assert_eq!((x25519_group, x25519_length), (0x001d, 32));
        assert_eq!(share_offset, shares.len());
        assert_ne!(&hybrid[1184..], x25519);
    }

    #[tokio::test]
    async fn negotiates_either_offered_share() {
        let groups = [
            (
                rustls::crypto::aws_lc_rs::kx_group::X25519MLKEM768,
                ClientHelloProfile::Chrome133,
            ),
            (
                rustls::crypto::aws_lc_rs::kx_group::X25519,
                ClientHelloProfile::Chrome133,
            ),
            (
                rustls::crypto::aws_lc_rs::kx_group::X25519,
                ClientHelloProfile::Chrome133Classic,
            ),
        ];
        for (group, profile) in groups {
            let rcgen::CertifiedKey { cert, signing_key } =
                rcgen::generate_simple_self_signed(vec!["proxy.test".into()]).unwrap();
            let mut server_provider = rustls::crypto::aws_lc_rs::default_provider();
            server_provider.kx_groups = vec![group];
            let server_config = ServerConfig::builder_with_provider(Arc::new(server_provider))
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_no_client_auth()
                .with_single_cert(
                    vec![cert.der().clone()],
                    PrivatePkcs8KeyDer::from(signing_key.serialize_der()).into(),
                )
                .unwrap();
            let mut roots = RootCertStore::empty();
            roots.add(cert.der().clone()).unwrap();
            let provider = if profile == ClientHelloProfile::Chrome133 {
                reality_provider_arc()
            } else {
                reality_provider_classic_arc()
            };
            let mut client_config = ClientConfig::builder_with_provider(provider)
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_root_certificates(roots)
                .with_no_client_auth();
            client_config.resumption = Resumption::disabled();
            client_config.client_hello_profile = Some(profile);
            client_config.reality_callback = Some(Arc::new(ChromeProbe::default()));
            client_config.cert_decompressors = vec![&COUNTING_BROTLI];
            let decompressions_before = BROTLI_CALLS.load(Ordering::Relaxed);
            let (client, server) = tokio::io::duplex(131_072);
            let server = tokio::spawn(async move {
                let mut stream = TlsAcceptor::from(Arc::new(server_config))
                    .accept(server)
                    .await
                    .unwrap();
                let selected = stream
                    .get_ref()
                    .1
                    .negotiated_key_exchange_group()
                    .unwrap()
                    .name();
                let mut request = [0; 4];
                stream.read_exact(&mut request).await.unwrap();
                stream.write_all(&request).await.unwrap();
                stream.flush().await.unwrap();
                selected
            });
            let mut client = TlsConnector::from(Arc::new(client_config))
                .connect(ServerName::try_from("proxy.test").unwrap(), client)
                .await
                .unwrap();
            assert_eq!(
                client
                    .get_ref()
                    .1
                    .negotiated_key_exchange_group()
                    .unwrap()
                    .name(),
                group.name()
            );
            client.write_all(b"test").await.unwrap();
            client.flush().await.unwrap();
            let mut response = [0; 4];
            client.read_exact(&mut response).await.unwrap();
            assert_eq!(&response, b"test");
            assert_eq!(server.await.unwrap(), group.name());
            assert_eq!(
                BROTLI_CALLS.load(Ordering::Relaxed),
                decompressions_before + 1
            );
        }
    }

    #[tokio::test]
    async fn firefox_negotiates_either_independent_key_share_without_retry() {
        for group in [
            rustls::crypto::aws_lc_rs::kx_group::X25519,
            rustls::crypto::aws_lc_rs::kx_group::SECP256R1,
        ] {
            let rcgen::CertifiedKey { cert, signing_key } =
                rcgen::generate_simple_self_signed(vec!["proxy.test".into()]).unwrap();
            let mut server_provider = rustls::crypto::aws_lc_rs::default_provider();
            server_provider.kx_groups = vec![group];
            let server = ServerConfig::builder_with_provider(Arc::new(server_provider))
                .with_protocol_versions(&[&rustls::version::TLS13])
                .unwrap()
                .with_no_client_auth()
                .with_single_cert(
                    vec![cert.der().clone()],
                    PrivatePkcs8KeyDer::from(signing_key.serialize_der()).into(),
                )
                .unwrap();
            let mut roots = RootCertStore::empty();
            roots.add(cert.der().clone()).unwrap();
            let mut client = ClientConfig::builder_with_provider(reality_provider_firefox_arc())
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_root_certificates(roots)
                .with_no_client_auth();
            client.resumption = Resumption::disabled();
            client.client_hello_profile = Some(ClientHelloProfile::Firefox120);
            client.reality_callback = Some(Arc::new(ChromeProbe::default()));
            let (client_io, server_io) = tokio::io::duplex(65_536);
            let peer = tokio::spawn(async move {
                let mut stream = TlsAcceptor::from(Arc::new(server))
                    .accept(server_io)
                    .await
                    .unwrap();
                let mut bytes = [0; 2];
                stream.read_exact(&mut bytes).await.unwrap();
                stream.write_all(&bytes).await.unwrap();
                stream.flush().await.unwrap();
            });
            let mut stream = TlsConnector::from(Arc::new(client))
                .connect(ServerName::try_from("proxy.test").unwrap(), client_io)
                .await
                .unwrap();
            assert_eq!(
                stream
                    .get_ref()
                    .1
                    .negotiated_key_exchange_group()
                    .unwrap()
                    .name(),
                group.name()
            );
            assert_eq!(
                stream.get_ref().1.handshake_kind(),
                Some(rustls::HandshakeKind::Full)
            );
            stream.write_all(b"ok").await.unwrap();
            stream.flush().await.unwrap();
            let mut response = [0; 2];
            stream.read_exact(&mut response).await.unwrap();
            assert_eq!(&response, b"ok");
            peer.await.unwrap();
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    #[ignore = "requires a C compiler and OpenSSL development headers and libraries"]
    async fn firefox_peer_limit_never_increases_a_stricter_configured_fragment_limit() {
        use std::process::Stdio;
        use tokio::io::{AsyncBufReadExt, BufReader};
        use tokio::process::Command;

        struct Directory(std::path::PathBuf);
        impl Drop for Directory {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        tokio::time::timeout(Duration::from_secs(15), async {
            let mut random = [0; 8];
            getrandom::fill(&mut random).unwrap();
            let directory = Directory(std::env::temp_dir().join(format!(
                "pathchord-firefox-rsl-{}-{:016x}",
                std::process::id(),
                u64::from_ne_bytes(random)
            )));
            std::fs::create_dir(&directory.0).unwrap();
            let binary = directory.0.join("peer");
            let source = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/tls_record_limit_server.c");
            let status = Command::new("cc")
                .arg(source)
                .arg("-o")
                .arg(&binary)
                .args(["-lssl", "-lcrypto"])
                .status()
                .await
                .unwrap();
            assert!(status.success());
            let rcgen::CertifiedKey { cert, signing_key } =
                rcgen::generate_simple_self_signed(vec!["tls.pathchord.test".into()]).unwrap();
            let cert_path = directory.0.join("certificate.pem");
            let key_path = directory.0.join("key.pem");
            std::fs::write(&cert_path, cert.pem()).unwrap();
            std::fs::write(&key_path, signing_key.serialize_pem()).unwrap();
            let mut peer = Command::new(binary)
                .arg(cert_path)
                .arg(key_path)
                .args(["13", "200", "2"])
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .kill_on_drop(true)
                .spawn()
                .unwrap();
            let mut output = BufReader::new(peer.stdout.take().unwrap());
            let mut line = String::new();
            output.read_line(&mut line).await.unwrap();
            let port: u16 = line.trim().parse().unwrap();
            let mut roots = RootCertStore::empty();
            roots.add(cert.der().clone()).unwrap();
            let mut config = ClientConfig::builder_with_provider(reality_provider_firefox_arc())
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_root_certificates(roots)
                .with_no_client_auth();
            config.client_hello_profile = Some(ClientHelloProfile::Firefox120);
            config.resumption = Resumption::disabled();
            config.max_fragment_size = Some(70);
            let socket = tokio::net::TcpStream::connect(("127.0.0.1", port))
                .await
                .unwrap();
            let mut stream = TlsConnector::from(Arc::new(config))
                .connect(ServerName::try_from("tls.pathchord.test").unwrap(), socket)
                .await
                .unwrap();
            stream.write_all(&vec![0; 5026]).await.unwrap();
            stream.flush().await.unwrap();
            let mut response = vec![0; 20002];
            stream.read_exact(&mut response).await.unwrap();
            line.clear();
            output.read_line(&mut line).await.unwrap();
            let fields: Vec<usize> = line
                .split_whitespace()
                .map(|s| s.parse().unwrap())
                .collect();
            assert_eq!(&fields[..2], &[1, 1]);
            // max_fragment_size includes the five-byte header; TLS 1.3 adds
            // an inner content type and a 16-byte GCM tag on the wire.
            assert!(fields[2] <= (70 - 5) + 1 + 16);
            assert!(fields[3] > 10);
            assert!(peer.wait().await.unwrap().success());
        })
        .await
        .expect("configured fragment limit test timed out");
    }

    struct RecordingIo {
        inner: tokio::net::TcpStream,
        received: Arc<Mutex<Vec<u8>>>,
    }

    impl tokio::io::AsyncRead for RecordingIo {
        fn poll_read(
            mut self: std::pin::Pin<&mut Self>,
            context: &mut std::task::Context<'_>,
            output: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            let before = output.filled().len();
            match std::pin::Pin::new(&mut self.inner).poll_read(context, output) {
                std::task::Poll::Ready(Ok(())) => {
                    self.received
                        .lock()
                        .unwrap()
                        .extend_from_slice(&output.filled()[before..]);
                    std::task::Poll::Ready(Ok(()))
                }
                other => other,
            }
        }
    }

    impl tokio::io::AsyncWrite for RecordingIo {
        fn poll_write(
            mut self: std::pin::Pin<&mut Self>,
            context: &mut std::task::Context<'_>,
            bytes: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            std::pin::Pin::new(&mut self.inner).poll_write(context, bytes)
        }
        fn poll_flush(
            mut self: std::pin::Pin<&mut Self>,
            context: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::pin::Pin::new(&mut self.inner).poll_flush(context)
        }
        fn poll_shutdown(
            mut self: std::pin::Pin<&mut Self>,
            context: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::pin::Pin::new(&mut self.inner).poll_shutdown(context)
        }
    }

    // Return the stable fields, ordered extensions excluding key_share, and
    // the key_share body. The peer captures actual TLS records on TCP.
    fn retry_hello_fields(hello: &[u8]) -> (Vec<u8>, Vec<Vec<u8>>, Vec<u8>) {
        let mut position = 4 + 2 + 32;
        let session_length = usize::from(hello[position]);
        position += 1 + session_length;
        let cipher_length = usize::from(u16::from_be_bytes([hello[position], hello[position + 1]]));
        position += 2 + cipher_length;
        position += 1 + usize::from(hello[position]);
        let stable = hello[4..position].to_vec();
        let extensions_length =
            usize::from(u16::from_be_bytes([hello[position], hello[position + 1]]));
        position += 2;
        let end = position + extensions_length;
        assert_eq!(end, hello.len());
        let mut extensions = Vec::new();
        let mut key_share = Vec::new();
        while position < end {
            let kind = u16::from_be_bytes([hello[position], hello[position + 1]]);
            let length = usize::from(u16::from_be_bytes([
                hello[position + 2],
                hello[position + 3],
            ]));
            let next = position + 4 + length;
            if kind == 0x0033 {
                key_share = hello[position + 4..next].to_vec();
            } else {
                extensions.push(hello[position..next].to_vec());
            }
            position = next;
        }
        (stable, extensions, key_share)
    }

    fn captured_client_hellos(wire: &[u8]) -> Vec<Vec<u8>> {
        let mut records = 0;
        let mut handshake = Vec::new();
        while records + 5 <= wire.len() {
            let kind = wire[records];
            let length = usize::from(u16::from_be_bytes([wire[records + 3], wire[records + 4]]));
            let end = records + 5 + length;
            if end > wire.len() {
                break;
            }
            if kind == 22 {
                handshake.extend_from_slice(&wire[records + 5..end]);
            }
            records = end;
        }
        let mut hellos = Vec::new();
        let mut position = 0;
        while position + 4 <= handshake.len() {
            let length = (usize::from(handshake[position + 1]) << 16)
                | (usize::from(handshake[position + 2]) << 8)
                | usize::from(handshake[position + 3]);
            let end = position + 4 + length;
            if end > handshake.len() {
                break;
            }
            if handshake[position] == 1 {
                hellos.push(handshake[position..end].to_vec());
            }
            position = end;
        }
        hellos
    }

    #[tokio::test]
    async fn fingerprint_profiles_negotiate_nist_groups_with_tls12_and_tls13_retry() {
        let profiles = [
            ClientHelloProfile::Chrome133,
            ClientHelloProfile::Chrome133Classic,
            ClientHelloProfile::Ios14,
            ClientHelloProfile::Safari16,
            ClientHelloProfile::Edge85,
            ClientHelloProfile::Qq111,
            ClientHelloProfile::Firefox120,
        ];
        let groups = [
            rustls::crypto::aws_lc_rs::kx_group::SECP256R1,
            rustls::crypto::aws_lc_rs::kx_group::SECP384R1,
        ];
        for profile in profiles {
            for group in groups {
                for version in [&rustls::version::TLS12, &rustls::version::TLS13] {
                    tokio::time::timeout(Duration::from_secs(5), async {
                        let rcgen::CertifiedKey { cert, signing_key } =
                            rcgen::generate_simple_self_signed(vec!["proxy.test".into()]).unwrap();
                        let mut server_provider = rustls::crypto::aws_lc_rs::default_provider();
                        server_provider.kx_groups = vec![group];
                        let server = ServerConfig::builder_with_provider(Arc::new(server_provider))
                            .with_protocol_versions(&[version])
                            .unwrap()
                            .with_no_client_auth()
                            .with_single_cert(
                                vec![cert.der().clone()],
                                PrivatePkcs8KeyDer::from(signing_key.serialize_der()).into(),
                            )
                            .unwrap();
                        let mut roots = RootCertStore::empty();
                        roots.add(cert.der().clone()).unwrap();
                        let provider = if profile == ClientHelloProfile::Firefox120 {
                            reality_provider_firefox_arc()
                        } else if profile == ClientHelloProfile::Chrome133 {
                            reality_provider_arc()
                        } else {
                            reality_provider_classic_arc()
                        };
                        let mut client = ClientConfig::builder_with_provider(provider)
                            .with_safe_default_protocol_versions()
                            .unwrap()
                            .with_root_certificates(roots)
                            .with_no_client_auth();
                        client.resumption = Resumption::disabled();
                        client.client_hello_profile = Some(profile);
                        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                        let address = listener.local_addr().unwrap();
                        let captured = Arc::new(Mutex::new(Vec::new()));
                        let recording = Arc::clone(&captured);
                        let peer = tokio::spawn(async move {
                            let (socket, _) = listener.accept().await.unwrap();
                            let socket = RecordingIo {
                                inner: socket,
                                received: recording,
                            };
                            let mut tls = TlsAcceptor::from(Arc::new(server))
                                .accept(socket)
                                .await
                                .unwrap();
                            let mut request = [0; 4];
                            tls.read_exact(&mut request).await.unwrap();
                            tls.write_all(&request).await.unwrap();
                            tls.flush().await.unwrap();
                        });
                        let socket = tokio::net::TcpStream::connect(address).await.unwrap();
                        let mut tls = TlsConnector::from(Arc::new(client))
                            .connect(ServerName::try_from("proxy.test").unwrap(), socket)
                            .await
                            .unwrap_or_else(|error| {
                                panic!(
                                    "{profile:?} {:?} {:?}: {error}",
                                    group.name(),
                                    version.version
                                )
                            });
                        assert_eq!(tls.get_ref().1.protocol_version(), Some(version.version));
                        assert_eq!(
                            tls.get_ref()
                                .1
                                .negotiated_key_exchange_group()
                                .unwrap()
                                .name(),
                            group.name()
                        );
                        let retry = version.version == ProtocolVersion::TLSv1_3
                            && !(profile == ClientHelloProfile::Firefox120
                                && group.name() == NamedGroup::secp256r1);
                        if retry {
                            assert_eq!(
                                tls.get_ref().1.handshake_kind(),
                                Some(rustls::HandshakeKind::FullWithHelloRetryRequest)
                            );
                        }
                        tls.write_all(b"test").await.unwrap();
                        tls.flush().await.unwrap();
                        let mut response = [0; 4];
                        tls.read_exact(&mut response).await.unwrap();
                        assert_eq!(&response, b"test");
                        peer.await.unwrap();
                        let hellos = captured_client_hellos(&captured.lock().unwrap());
                        if retry {
                            assert_eq!(hellos.len(), 2, "{profile:?} {:?}", group.name());
                            let first = retry_hello_fields(&hellos[0]);
                            let second = retry_hello_fields(&hellos[1]);
                            assert_eq!(first.0, second.0, "ClientHello fields changed on retry");
                            assert_eq!(
                                first.1, second.1,
                                "extension bytes or order changed on retry"
                            );
                            assert_ne!(first.2, second.2);
                            assert_eq!(&second.2[2..4], &u16::from(group.name()).to_be_bytes());
                        } else {
                            assert_eq!(hellos.len(), 1);
                        }
                    })
                    .await
                    .expect("bounded TLS peer test");
                }
            }
        }
    }

    #[derive(Debug, Default)]
    struct CountingRealityProof(AtomicUsize);

    impl RealityCallback for CountingRealityProof {
        fn apply_reality(
            &self,
            _exchange: &dyn ActiveKeyExchange,
            _random: &[u8; 32],
            session_id: &mut [u8; 32],
            _hello: &[u8],
        ) -> Result<(), Error> {
            self.0.fetch_add(1, Ordering::SeqCst);
            session_id.fill(0x55);
            Ok(())
        }
    }

    #[tokio::test]
    async fn reality_rejects_tls_retry_without_regenerating_proof() {
        for profile in [
            None,
            Some(ClientHelloProfile::Ios14),
            Some(ClientHelloProfile::Firefox120),
        ] {
            tokio::time::timeout(Duration::from_secs(5), async {
                let rcgen::CertifiedKey { cert, signing_key } =
                    rcgen::generate_simple_self_signed(vec!["proxy.test".into()]).unwrap();
                let mut provider = rustls::crypto::aws_lc_rs::default_provider();
                provider.kx_groups = vec![if profile == Some(ClientHelloProfile::Firefox120) {
                    rustls::crypto::aws_lc_rs::kx_group::SECP384R1
                } else {
                    rustls::crypto::aws_lc_rs::kx_group::SECP256R1
                }];
                let server = ServerConfig::builder_with_provider(Arc::new(provider))
                    .with_protocol_versions(&[&rustls::version::TLS13])
                    .unwrap()
                    .with_no_client_auth()
                    .with_single_cert(
                        vec![cert.der().clone()],
                        PrivatePkcs8KeyDer::from(signing_key.serialize_der()).into(),
                    )
                    .unwrap();
                let mut roots = RootCertStore::empty();
                roots.add(cert.der().clone()).unwrap();
                let provider = if profile == Some(ClientHelloProfile::Firefox120) {
                    reality_provider_firefox_arc()
                } else if profile.is_some() {
                    reality_provider_classic_arc()
                } else {
                    reality_provider_arc()
                };
                let mut client = ClientConfig::builder_with_provider(provider)
                    .with_safe_default_protocol_versions()
                    .unwrap()
                    .with_root_certificates(roots)
                    .with_no_client_auth();
                let proof = Arc::new(CountingRealityProof::default());
                client.resumption = Resumption::disabled();
                client.client_hello_profile = profile;
                client.reality_callback = Some(proof.clone());
                let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                let address = listener.local_addr().unwrap();
                let peer = tokio::spawn(async move {
                    let (socket, _) = listener.accept().await.unwrap();
                    TlsAcceptor::from(Arc::new(server)).accept(socket).await.is_err()
                });
                let socket = tokio::net::TcpStream::connect(address).await.unwrap();
                let result = TlsConnector::from(Arc::new(client))
                    .connect(ServerName::try_from("proxy.test").unwrap(), socket)
                    .await;
                assert!(matches!(result, Err(error) if error.to_string().contains("REALITY does not support TLS HelloRetryRequest")));
                assert_eq!(proof.0.load(Ordering::SeqCst), 1);
                assert!(peer.await.unwrap());
            })
            .await
            .expect("bounded REALITY retry test");
        }
    }

    #[tokio::test]
    async fn cookie_only_retry_preserves_the_first_profile_and_key_shares() {
        async fn next_client_hello(socket: &mut tokio::net::TcpStream) -> Vec<u8> {
            loop {
                let mut header = [0; 5];
                socket.read_exact(&mut header).await.unwrap();
                let length = usize::from(u16::from_be_bytes([header[3], header[4]]));
                let mut record = vec![0; length];
                socket.read_exact(&mut record).await.unwrap();
                if header[0] == 22 && record.first() == Some(&1) {
                    return record;
                }
            }
        }

        for profile in [
            ClientHelloProfile::Chrome133,
            ClientHelloProfile::Chrome133Classic,
            ClientHelloProfile::Ios14,
            ClientHelloProfile::Safari16,
            ClientHelloProfile::Edge85,
            ClientHelloProfile::Qq111,
            ClientHelloProfile::Firefox120,
        ] {
            tokio::time::timeout(Duration::from_secs(5), async {
                let provider = if profile == ClientHelloProfile::Firefox120 {
                    reality_provider_firefox_arc()
                } else if profile == ClientHelloProfile::Chrome133 {
                    reality_provider_arc()
                } else {
                    reality_provider_classic_arc()
                };
                let mut config = ClientConfig::builder_with_provider(provider)
                    .with_safe_default_protocol_versions()
                    .unwrap()
                    .with_root_certificates(RootCertStore::empty())
                    .with_no_client_auth();
                config.resumption = Resumption::disabled();
                config.client_hello_profile = Some(profile);
                let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                let address = listener.local_addr().unwrap();
                let client = tokio::spawn(async move {
                    let socket = tokio::net::TcpStream::connect(address).await.unwrap();
                    let _ = TlsConnector::from(Arc::new(config))
                        .connect(ServerName::try_from("proxy.test").unwrap(), socket)
                        .await;
                });
                let (mut socket, _) = listener.accept().await.unwrap();
                let first = next_client_hello(&mut socket).await;
                let session_offset = 4 + 2 + 32;
                let session_length = usize::from(first[session_offset]);
                let session = &first[session_offset + 1..session_offset + 1 + session_length];
                let mut hrr = vec![3, 3];
                hrr.extend_from_slice(&[
                    0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e,
                    0x65, 0xb8, 0x91, 0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e,
                    0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
                ]);
                hrr.push(session_length as u8);
                hrr.extend_from_slice(session);
                hrr.extend_from_slice(&[
                    0x13, 0x01, 0, // TLS_AES_128_GCM_SHA256, no compression
                    0, 16, // extensions length
                    0, 43, 0, 2, 3, 4, // supported_versions
                    0, 44, 0, 6, 0, 4, 1, 2, 3, 4, // cookie
                ]);
                let length = hrr.len();
                let mut handshake =
                    vec![2, (length >> 16) as u8, (length >> 8) as u8, length as u8];
                handshake.extend_from_slice(&hrr);
                let mut record = vec![22, 3, 3];
                record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
                record.extend_from_slice(&handshake);
                socket.write_all(&record).await.unwrap();
                let second = next_client_hello(&mut socket).await;
                let first = retry_hello_fields(&first);
                let mut second = retry_hello_fields(&second);
                let cookies: Vec<_> = second
                    .1
                    .iter()
                    .filter(|item| item.starts_with(&[0, 44]))
                    .cloned()
                    .collect();
                assert_eq!(cookies, vec![vec![0, 44, 0, 6, 0, 4, 1, 2, 3, 4]]);
                second.1.retain(|item| !item.starts_with(&[0, 44]));
                assert_eq!(first, second, "cookie-only retry changed the ClientHello");
                client.abort();
            })
            .await
            .expect("bounded cookie-only retry test");
        }
    }

    #[tokio::test]
    #[ignore = "requires PATHCHORD_TEST_XRAY pointing to Xray 26.11.9"]
    async fn reality_vless_vision_interoperates_with_xray_for_both_shares() {
        let binary = std::env::var_os("PATHCHORD_TEST_XRAY").expect("Xray executable");
        external_reality_roundtrips(binary, true).await;
    }

    #[tokio::test]
    #[ignore = "requires PATHCHORD_TEST_SING_BOX"]
    async fn reality_vless_vision_interoperates_with_sing_box_for_both_shares() {
        let binary = std::env::var_os("PATHCHORD_TEST_SING_BOX").expect("sing-box executable");
        external_reality_roundtrips(binary, false).await;
    }

    #[tokio::test]
    #[ignore = "requires PATHCHORD_TEST_SING_BOX"]
    async fn sing_box_reality_combined_decoy_flight_boundary() {
        let binary = std::env::var_os("PATHCHORD_TEST_SING_BOX").expect("sing-box executable");
        let mut selected = None;
        for _ in 0..512 {
            let rcgen::CertifiedKey { cert, signing_key } =
                rcgen::generate_simple_self_signed(vec!["d.test".into()]).unwrap();
            // This TLS 1.3 flight adds 89 bytes to the certificate and
            // CertificateVerify signature lengths.
            let length = 512_usize.checked_sub(cert.der().len() + 89);
            if let Some(length) = length.filter(|length| (69..=71).contains(length)) {
                selected = Some((cert.der().clone(), signing_key.serialize_der(), length));
                break;
            }
        }
        let (certificate, private_key, signature_length) =
            selected.expect("generate a certificate suitable for both boundary records");
        for extra in 0..=1 {
            let boundary = RealityBoundary {
                record_length: 512 + extra,
                certificate: certificate.clone(),
                private_key: private_key.clone(),
                signature_length: signature_length + extra,
            };
            external_reality_roundtrips_with_boundary(binary.clone(), false, Some(boundary)).await;
        }
    }

    struct RealityBoundary {
        record_length: usize,
        certificate: rustls::pki_types::CertificateDer<'static>,
        private_key: Vec<u8>,
        signature_length: usize,
    }

    async fn external_reality_roundtrips(binary: std::ffi::OsString, xray: bool) {
        external_reality_roundtrips_with_boundary(binary, xray, None).await;
    }

    async fn external_reality_roundtrips_with_boundary(
        binary: std::ffi::OsString,
        xray: bool,
        boundary: Option<RealityBoundary>,
    ) {
        use std::collections::{BTreeMap, BTreeSet};
        use std::process::Stdio;
        use std::time::Duration;

        use pathchord_policy::{
            Endpoint as PolicyEndpoint, TransitOptions, TransitProxyConfig, TransitProxyId,
            TransitReality, TransitTls,
        };
        use tokio::net::{TcpListener, TcpStream, UdpSocket};
        use tokio::process::Command;
        use tokio::time::{Instant, sleep, timeout};

        use crate::{ConnectRequest, Endpoint, TransitAdapter, TransitCredential};

        // Capture record lengths only: no TLS payload or credentials are retained.
        #[derive(Default)]
        struct Trace {
            header: [u8; 5],
            header_len: usize,
            body_left: usize,
            lengths: Vec<usize>,
        }
        impl Trace {
            fn observe(&mut self, mut data: &[u8]) {
                while !data.is_empty() {
                    if self.body_left != 0 {
                        let count = self.body_left.min(data.len());
                        self.body_left -= count;
                        data = &data[count..];
                    } else {
                        let count = (5 - self.header_len).min(data.len());
                        self.header[self.header_len..self.header_len + count]
                            .copy_from_slice(&data[..count]);
                        self.header_len += count;
                        data = &data[count..];
                        if self.header_len == 5 {
                            self.body_left =
                                usize::from(u16::from_be_bytes([self.header[3], self.header[4]]));
                            self.lengths.push(self.body_left + 5);
                            self.header_len = 0;
                        }
                    }
                }
            }
        }
        struct TraceIo {
            inner: TcpStream,
            trace: Arc<Mutex<Trace>>,
        }
        impl tokio::io::AsyncRead for TraceIo {
            fn poll_read(
                mut self: std::pin::Pin<&mut Self>,
                cx: &mut std::task::Context<'_>,
                buf: &mut tokio::io::ReadBuf<'_>,
            ) -> std::task::Poll<std::io::Result<()>> {
                std::pin::Pin::new(&mut self.inner).poll_read(cx, buf)
            }
        }
        impl tokio::io::AsyncWrite for TraceIo {
            fn poll_write(
                mut self: std::pin::Pin<&mut Self>,
                cx: &mut std::task::Context<'_>,
                data: &[u8],
            ) -> std::task::Poll<std::io::Result<usize>> {
                let result = std::pin::Pin::new(&mut self.inner).poll_write(cx, data);
                if let std::task::Poll::Ready(Ok(count)) = result {
                    self.trace.lock().unwrap().observe(&data[..count]);
                }
                result
            }
            fn poll_flush(
                mut self: std::pin::Pin<&mut Self>,
                cx: &mut std::task::Context<'_>,
            ) -> std::task::Poll<std::io::Result<()>> {
                std::pin::Pin::new(&mut self.inner).poll_flush(cx)
            }
            fn poll_shutdown(
                mut self: std::pin::Pin<&mut Self>,
                cx: &mut std::task::Context<'_>,
            ) -> std::task::Poll<std::io::Result<()>> {
                std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
            }
        }

        // ECDSA signatures have variable DER lengths. Selecting a valid
        // signature of a requested length makes the peer boundary reproducible.
        #[derive(Debug)]
        struct LengthKey {
            inner: Arc<dyn rustls::sign::SigningKey>,
            length: usize,
        }
        impl rustls::sign::SigningKey for LengthKey {
            fn choose_scheme(
                &self,
                offered: &[rustls::SignatureScheme],
            ) -> Option<Box<dyn rustls::sign::Signer>> {
                Some(Box::new(LengthSigner {
                    inner: self.inner.choose_scheme(offered)?,
                    length: self.length,
                }))
            }
            fn algorithm(&self) -> rustls::SignatureAlgorithm {
                self.inner.algorithm()
            }
        }
        #[derive(Debug)]
        struct LengthSigner {
            inner: Box<dyn rustls::sign::Signer>,
            length: usize,
        }
        impl rustls::sign::Signer for LengthSigner {
            fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rustls::Error> {
                for _ in 0..8192 {
                    let signature = self.inner.sign(message)?;
                    if signature.len() == self.length {
                        return Ok(signature);
                    }
                }
                Err(rustls::Error::General(
                    "unable to produce a signature of the requested length".into(),
                ))
            }
            fn scheme(&self) -> rustls::SignatureScheme {
                self.inner.scheme()
            }
        }

        let groups = [
            rustls::crypto::aws_lc_rs::kx_group::X25519MLKEM768,
            rustls::crypto::aws_lc_rs::kx_group::X25519,
            rustls::crypto::aws_lc_rs::kx_group::SECP256R1,
        ];
        let profiles: &[&str] = &["chrome", "ios", "safari", "edge", "qq", "firefox"];
        for &fingerprint in profiles {
            for group in groups {
                if boundary.is_some()
                    && (fingerprint != "edge" || group.name() != NamedGroup::X25519)
                {
                    continue;
                }
                if group.name() == NamedGroup::secp256r1 && (fingerprint != "firefox" || xray)
                    || group.name() == NamedGroup::X25519MLKEM768 && fingerprint != "chrome"
                {
                    continue;
                }
                timeout(Duration::from_secs(20), async {
                // The decoy constrains the mirrored ServerHello to one of
                // the two offered groups, testing both completion paths.
                let decoy_name = if boundary.is_some() { "d.test" } else { "decoy.test" };
                let (certificate, private_key, signature_length) = if let Some(boundary) = &boundary {
                    (boundary.certificate.clone(), boundary.private_key.clone(), Some(boundary.signature_length))
                } else {
                    // A combined TLS record of at most 512 bytes makes the
                    // sing-box REALITY server wait for separate records.
                    let rcgen::CertifiedKey { cert, signing_key } = rcgen::generate_simple_self_signed(vec![
                        decoy_name.into(), "long-decoy-handshake-padding.example.invalid".into()
                    ]).unwrap();
                    (cert.der().clone(), signing_key.serialize_der(), None)
                };
                let mut decoy_roots = RootCertStore::empty();
                decoy_roots.add(certificate.clone()).unwrap();
                let decoy_verifier = rustls::client::WebPkiServerVerifier::builder_with_provider(
                    Arc::new(decoy_roots),
                    Arc::new(rustls::crypto::aws_lc_rs::default_provider()),
                )
                .build()
                .unwrap();
                let mut provider = rustls::crypto::aws_lc_rs::default_provider();
                provider.kx_groups = if xray && group.name() == NamedGroup::X25519MLKEM768 {
                    vec![group, rustls::crypto::aws_lc_rs::kx_group::X25519]
                } else {
                    vec![group]
                };
                let builder = ServerConfig::builder_with_provider(Arc::new(provider))
                    .with_safe_default_protocol_versions()
                    .unwrap()
                    .with_no_client_auth();
                let private_key = PrivatePkcs8KeyDer::from(private_key).into();
                let mut server = if let Some(length) = signature_length {
                    let key = rustls::crypto::aws_lc_rs::sign::any_supported_type(&private_key).unwrap();
                    let key = Arc::new(LengthKey { inner: key, length });
                    let cert = rustls::sign::CertifiedKey::new(vec![certificate.clone()], key);
                    builder.with_cert_resolver(Arc::new(rustls::sign::SingleCertAndKey::from(cert)))
                } else {
                    builder.with_single_cert(vec![certificate.clone()], private_key).unwrap()
                };
                server.cert_compressors.clear();
                let decoy = TcpListener::bind("127.0.0.1:0").await.unwrap();
                let decoy_port = decoy.local_addr().unwrap().port();
                let acceptor = TlsAcceptor::from(Arc::new(server));
                let authenticated_decoys = Arc::new(AtomicUsize::new(0));
                let decoy_count = Arc::clone(&authenticated_decoys);
                let decoy_payloads = Arc::new(AtomicUsize::new(0));
                let payload_count = Arc::clone(&decoy_payloads);
                let decoy_inspections = Arc::new(AtomicUsize::new(0));
                let inspections = Arc::clone(&decoy_inspections);
                let decoy_traces = Arc::new(Mutex::new(Vec::<Arc<Mutex<Trace>>>::new()));
                let traces = Arc::clone(&decoy_traces);
                let decoy_task = tokio::spawn(async move {
                    while let Ok((stream, _)) = decoy.accept().await {
                        let trace = Arc::new(Mutex::new(Trace::default()));
                        traces.lock().unwrap().push(Arc::clone(&trace));
                        let stream = TraceIo { inner: stream, trace: Arc::clone(&trace) };
                        let acceptor = acceptor.clone();
                        let decoy_count = Arc::clone(&decoy_count);
                        let payload_count = Arc::clone(&payload_count);
                        let inspections = Arc::clone(&inspections);
                        tokio::spawn(async move {
                            if let Ok(mut stream) = acceptor.accept(stream).await {
                                decoy_count.fetch_add(1, Ordering::Relaxed);
                                let mut bytes = [0; 128];
                                if let Ok(Ok(size)) = timeout(Duration::from_secs(1), stream.read(&mut bytes)).await
                                    && size != 0
                                {
                                    payload_count.fetch_add(1, Ordering::Relaxed);
                                }
                                inspections.fetch_add(1, Ordering::Relaxed);
                            }
                        });
                    }
                });
                let reservation = TcpListener::bind("127.0.0.1:0").await.unwrap();
                let port = reservation.local_addr().unwrap().port();
                let private_key = "-AxPYYdSOc0L8SVojHT0CHsejcb15DcdD2ZI8QaALlo";
                let public_key = "Q7VhOFla3pZJiGzjiNfwi3j-QfEr9FOdDpQIiDANtRM";
                let uuid = "6cbf3f72-3417-4922-bde6-67820d041f25";
                let short_id = "0123456789abcdef";
                let xray_config = serde_json::json!({
                    "log": {"loglevel": "debug"},
                    "inbounds": [{
                        "listen": "127.0.0.1", "port": port, "protocol": "vless",
                        "settings": {"clients": [{"id": uuid, "flow": "xtls-rprx-vision"}], "decryption": "none"},
                        "streamSettings": {"network": "tcp", "security": "reality", "realitySettings": {
                            "dest": format!("127.0.0.1:{decoy_port}"),
                            "serverNames": [decoy_name], "privateKey": private_key, "shortIds": [short_id]
                        }}
                    }],
                    "outbounds": [{"protocol": "freedom", "settings": {"finalRules": [{"action": "allow"}]}}]
                });
                let sing_box_config = serde_json::json!({
                    "log": {"disabled": true},
                    "inbounds": [{
                        "type": "vless", "listen": "127.0.0.1", "listen_port": port,
                        "users": [{"uuid": uuid, "flow": "xtls-rprx-vision"}],
                        "tls": {
                            "enabled": true, "server_name": decoy_name,
                            "reality": {"enabled": true,
                                "handshake": {"server": "127.0.0.1", "server_port": decoy_port},
                                "private_key": private_key, "short_id": [short_id]}
                        }
                    }],
                    "outbounds": [{"type": "direct", "tag": "direct"}],
                    "route": {"final": "direct"}
                });
                let config = if xray { xray_config } else { sing_box_config };
                drop(reservation);
                let mut peer = Command::new(&binary)
                    .arg("run")
                    .arg("-c")
                    .arg(if xray { "stdin:" } else { "stdin" })
                    .stdin(Stdio::piped())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped())
                    .kill_on_drop(true)
                    .spawn()
                    .unwrap();
                peer.stdin
                    .take()
                    .unwrap()
                    .write_all(&serde_json::to_vec(&config).unwrap())
                    .await
                    .unwrap();
                let deadline = Instant::now() + Duration::from_secs(5);
                while TcpStream::connect(("127.0.0.1", port)).await.is_err() {
                    assert!(peer.try_wait().unwrap().is_none(), "peer exited before readiness");
                    assert!(Instant::now() < deadline, "peer readiness timed out");
                    sleep(Duration::from_millis(20)).await;
                }
                let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
                let target_port = target.local_addr().unwrap().port();
                const PARALLEL: usize = 8;
                let echo = tokio::spawn(async move {
                    for _ in 0..2 + PARALLEL {
                        let (mut stream, _) = target.accept().await.unwrap();
                        let mut packet = [0; 7];
                        stream.read_exact(&mut packet).await.unwrap();
                        stream.write_all(&packet).await.unwrap();
                    }
                });
                let node = TransitProxyConfig {
                    id: TransitProxyId::new("xray-reality"),
                    source: None,
                    protocol: "vless".into(),
                    endpoint: PolicyEndpoint { host: "127.0.0.1".into(), port },
                    credentials_ref: None,
                    labels: BTreeMap::new(),
                    tags: BTreeSet::new(),
                    weight: 1,
                    options: TransitOptions {
                        tls: Some(TransitTls {
                            enabled: true,
                            server_name: Some(decoy_name.into()),
                            fingerprint: Some(fingerprint.into()),
                            reality: Some(TransitReality {
                                public_key: public_key.into(),
                                short_id: short_id.into(),
                            }),
                            ..Default::default()
                        }),
                        ..Default::default()
                    },
                };
                let credential = TransitCredential::new(BTreeMap::from([
                    ("uuid".into(), uuid.into()),
                    ("flow".into(), crate::vision::FLOW_VISION.into()),
                ]));
                let mut adapter = crate::reality_adapter::RealityVlessAdapter::from_config(
                    &node,
                    &credential,
                    Duration::from_secs(5),
                    crate::adapter_registry::native_tls_roots(),
                )
                .unwrap();
                adapter.set_decoy_verifier_for_test(decoy_verifier);
                if !xray && fingerprint == "chrome" && group.name() == NamedGroup::X25519MLKEM768 {
                    adapter.set_preferred_hybrid_for_test(true);
                }
                let adapter = Arc::new(adapter);
                if let Some(boundary) = &boundary {
                    let record_length = boundary.record_length;
                    let adapter = Arc::clone(&adapter);
                    let mut connection = tokio::spawn(async move {
                        adapter.connect(ConnectRequest {
                            destination: Endpoint { host: "127.0.0.1".into(), port: target_port },
                        }).await
                    });
                    let observed = timeout(Duration::from_secs(3), async {
                        loop {
                            let lengths = decoy_traces.lock().unwrap().iter().find_map(|trace| {
                                let trace = trace.lock().unwrap();
                                (trace.lengths.len() >= 3).then(|| trace.lengths.clone())
                            });
                            if let Some(lengths) = lengths { break lengths; }
                            assert!(!connection.is_finished(), "connection ended before the decoy flight");
                            sleep(Duration::from_millis(5)).await;
                        }
                    }).await.expect("decoy did not send a complete server flight");
                    assert_eq!(&observed[..3], &[127, 6, record_length]);
                    if record_length == 512 {
                        assert!(timeout(Duration::from_secs(1), &mut connection).await.is_err(),
                            "sing-box unexpectedly accepted a 512-byte combined flight");
                        connection.abort();
                    } else {
                        let mut stream = timeout(Duration::from_secs(3), connection).await
                            .expect("sing-box stalled on a 513-byte combined flight")
                            .expect("boundary connection task failed")
                            .expect("boundary connection failed");
                        stream.write_all(b"reality").await.unwrap();
                        stream.flush().await.unwrap();
                        let mut response = [0; 7];
                        timeout(Duration::from_secs(3), stream.read_exact(&mut response)).await.unwrap().unwrap();
                        assert_eq!(&response, b"reality");
                    }
                    echo.abort();
                    peer.kill().await.unwrap();
                    peer.wait().await.unwrap();
                    decoy_task.abort();
                    return;
                }
                if xray && fingerprint != "chrome"
                    || !xray && fingerprint == "firefox" && group.name() == NamedGroup::secp256r1
                {
                    // Xray requires a hybrid key share. sing-box only mirrors
                    // X25519 or hybrid ServerHello shares. Keep the requested
                    // profile and stop safely at the trusted decoy.
                    let result = adapter.connect(ConnectRequest {
                        destination: Endpoint { host: "127.0.0.1".into(), port: target_port },
                    }).await;
                    assert!(matches!(result, Err(crate::TransitError::Protocol(ref reason)) if reason.contains("trusted decoy certificate")));
                    timeout(Duration::from_secs(2), async {
                        while decoy_inspections.load(Ordering::Relaxed) == 0 {
                            tokio::task::yield_now().await;
                        }
                    }).await.expect("classic profile reached the decoy");
                    assert_eq!(authenticated_decoys.load(Ordering::Relaxed), 1);
                    assert_eq!(decoy_payloads.load(Ordering::Relaxed), 0);
                    echo.abort();
                    peer.kill().await.unwrap();
                    peer.wait().await.unwrap();
                    decoy_task.abort();
                    return;
                }
                for _ in 0..2 {
                    let result = adapter
                        .connect(ConnectRequest {
                            destination: Endpoint { host: "127.0.0.1".into(), port: target_port },
                        })
                        .await;
                    let mut stream = match result {
                        Ok(stream) => stream,
                        Err(error) => {
                            let _ = peer.start_kill();
                            let output = peer.wait_with_output().await.unwrap();
                            let logs = String::from_utf8_lossy(&output.stdout);
                            panic!(
                                "REALITY handshake {:?}: {error}; completed decoys: {}; inspected decoys: {}; cached hybrid: {}; peer log: {logs}",
                                group.name(),
                                authenticated_decoys.load(Ordering::Relaxed),
                                decoy_inspections.load(Ordering::Relaxed),
                                adapter.preferred_hybrid_for_test()
                            );
                        }
                    };
                    stream.write_all(b"reality").await.unwrap();
                    stream.flush().await.unwrap();
                    let mut result = [0; 7];
                    stream.read_exact(&mut result).await.unwrap();
                    assert_eq!(&result, b"reality", "group {:?}", group.name());
                }
                let barrier = Arc::new(tokio::sync::Barrier::new(PARALLEL));
                let mut clients = tokio::task::JoinSet::new();
                for _ in 0..PARALLEL {
                    let adapter = Arc::clone(&adapter);
                    let barrier = Arc::clone(&barrier);
                    let group_name = group.name();
                    clients.spawn(async move {
                        barrier.wait().await;
                        let mut stream = adapter.connect(ConnectRequest {
                            destination: Endpoint { host: "127.0.0.1".into(), port: target_port },
                        }).await.unwrap_or_else(|error| panic!("{fingerprint} {group_name:?} concurrent REALITY connection failed: {error}"));
                        stream.write_all(b"reality").await.unwrap();
                        stream.flush().await.unwrap();
                        let mut response = [0; 7];
                        stream.read_exact(&mut response).await.unwrap();
                        assert_eq!(&response, b"reality");
                    });
                }
                while let Some(result) = clients.join_next().await { result.unwrap(); }
                let udp_target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
                let udp_port = udp_target.local_addr().unwrap().port();
                let udp_echo = tokio::spawn(async move {
                    let mut buffer = [0; 1024];
                    for _ in 0..3 {
                        let (length, source) = udp_target.recv_from(&mut buffer).await.unwrap();
                        udp_target.send_to(&buffer[..length], source).await.unwrap();
                    }
                });
                let mut datagram = adapter.connect_udp(ConnectRequest {
                    destination: Endpoint { host: "127.0.0.1".into(), port: udp_port },
                }).await.unwrap_or_else(|error| panic!("{fingerprint} {:?} UDP REALITY connection failed: {error}", group.name()));
                for payload in [b"one".as_slice(), b"two", b"three"] {
                    datagram.send(payload).await.unwrap();
                    assert_eq!(timeout(Duration::from_secs(5), datagram.receive()).await.unwrap().unwrap(), payload);
                }
                datagram.close().await.unwrap();
                udp_echo.await.unwrap();
                if xray {
                    timeout(Duration::from_secs(1), async {
                        while decoy_inspections.load(Ordering::Relaxed) == 0 {
                            tokio::task::yield_now().await;
                        }
                    }).await.expect("first classic attempt completed against decoy");
                    assert_eq!(authenticated_decoys.load(Ordering::Relaxed), 1, "hybrid choice is cached");
                    assert_eq!(decoy_payloads.load(Ordering::Relaxed), 0, "no application data reaches the decoy");
                    assert!(adapter.preferred_hybrid_for_test());
                }
                echo.await.unwrap();
                peer.kill().await.unwrap();
                peer.wait().await.unwrap();
                decoy_task.abort();
            })
            .await
            .expect("bounded REALITY round trip");
            }
        }
    }
}
