//! Native VLESS + REALITY adapter.
//!
//! REALITY is a TLS ClientHello proof profile used by VLESS nodes. The local
//! rustls patch exposes only the two hooks required by the proof: the active
//! X25519 secret and a callback that runs before the ClientHello enters the
//! transcript. No proxy runtime or compatibility process is involved.

use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering},
};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use aes_gcm::aead::{AeadInPlace, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use async_trait::async_trait;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::{ClientHelloProfile, RealityCallback, WebPkiServerVerifier};
use rustls::crypto::ActiveKeyExchange;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, Error, SignatureScheme};
use sha2::{Sha256, Sha512};
use tokio::io::AsyncWriteExt;
use tokio::time::timeout;
use x509_parser::parse_x509_certificate;
use zeroize::{Zeroize, Zeroizing};

use crate::native_transport::NativeTransport;
use crate::reality_codec::RealityConfig;
use crate::{
    AdapterKind, BoxedTransitConnection, BoxedTransitDatagram, ConnectRequest, Endpoint,
    TransitAdapter, TransitCredential, TransitError, TransitMetadata,
};

pub(crate) struct RealityVlessAdapter {
    metadata: TransitMetadata,
    uuid: Zeroizing<[u8; 16]>,
    transport: NativeTransport,
    tls_hybrid: ClientConfig,
    tls_classic: Option<ClientConfig>,
    fingerprint_profile: Option<ClientHelloProfile>,
    decoy_verifier: Arc<dyn ServerCertVerifier>,
    server_public_key: [u8; 32],
    short_id: [u8; 8],
    allow_insecure: bool,
    preferred_hybrid: AtomicBool,
    retry_after: Mutex<Option<Instant>>,
    retry_generation: AtomicU64,
    retry_gate: tokio::sync::Mutex<()>,
    udp: bool,
    vision: Option<crate::vision::VisionFlow>,
    packet_encoding: crate::native_protocol::VlessPacketEncoding,
    timeout: Duration,
}

impl std::fmt::Debug for RealityVlessAdapter {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RealityVlessAdapter")
            .field("metadata", &self.metadata)
            .finish_non_exhaustive()
    }
}

impl RealityVlessAdapter {
    #[cfg(test)]
    pub(crate) fn set_decoy_verifier_for_test(&mut self, verifier: Arc<dyn ServerCertVerifier>) {
        self.decoy_verifier = verifier;
    }

    #[cfg(test)]
    pub(crate) fn set_preferred_hybrid_for_test(&self, hybrid: bool) {
        self.preferred_hybrid.store(hybrid, Ordering::Release);
    }

    #[cfg(test)]
    pub(crate) fn preferred_hybrid_for_test(&self) -> bool {
        self.preferred_hybrid.load(Ordering::Acquire)
    }

    pub fn from_config(
        config: &pathchord_policy::TransitProxyConfig,
        credential: &TransitCredential,
        timeout_duration: Duration,
        _base_tls: Arc<ClientConfig>,
    ) -> Result<Self, TransitError> {
        if config.protocol != "vless" {
            return Err(unsupported("REALITY requires a VLESS node"));
        }
        let tls_options = config
            .options
            .tls
            .as_ref()
            .filter(|value| value.enabled)
            .ok_or_else(|| unsupported("REALITY requires enabled TLS"))?;
        let reality = tls_options
            .reality
            .as_ref()
            .ok_or_else(|| unsupported("REALITY settings are missing"))?;
        let reality = RealityConfig::parse(&reality.public_key, &reality.short_id)
            .map_err(|error| unsupported(error.to_string()))?;
        let mut allowed = vec!["uuid", "flow"];
        if let Some(field) = tls_options.client_key_field.as_deref() {
            allowed.push(field);
        }
        crate::adapter_registry::validate_credentials(Some(credential), &allowed)?;
        let vision =
            crate::vision::VisionFlow::parse(credential.field("flow")).map_err(unsupported)?;
        let uuid = uuid::Uuid::parse_str(
            credential
                .field("uuid")
                .ok_or_else(|| unsupported("VLESS UUID is missing"))?,
        )
        .map_err(|_| unsupported("VLESS UUID is invalid"))?;

        if !tls_options.client_certificate.is_empty() || tls_options.client_key_field.is_some() {
            return Err(unsupported(
                "REALITY client certificate authentication is unsupported",
            ));
        }
        if !tls_options.certificate.is_empty()
            || tls_options.certificate_sha256.is_some()
            || tls_options.truststore != pathchord_policy::TransitTls::default().truststore
        {
            return Err(unsupported(
                "REALITY authenticates its proof and does not support custom trust roots",
            ));
        }
        let profile = match tls_options.fingerprint.as_deref() {
            None => None,
            Some(value) if value.eq_ignore_ascii_case("chrome") => {
                Some(ClientHelloProfile::Chrome133)
            }
            Some(value) if value.eq_ignore_ascii_case("ios") => Some(ClientHelloProfile::Ios14),
            Some(value) if value.eq_ignore_ascii_case("safari") => {
                Some(ClientHelloProfile::Safari16)
            }
            Some(value) if value.eq_ignore_ascii_case("edge") => Some(ClientHelloProfile::Edge85),
            Some(value) if value.eq_ignore_ascii_case("qq") => Some(ClientHelloProfile::Qq111),
            Some(value) if value.eq_ignore_ascii_case("firefox") => {
                Some(ClientHelloProfile::Firefox120)
            }
            Some(value)
                if value.eq_ignore_ascii_case("android") || value.eq_ignore_ascii_case("360") =>
            {
                return Err(unsupported(
                    "REALITY requires TLS 1.3 but the requested fingerprint only supports TLS 1.2",
                ));
            }
            Some(_) => {
                return Err(unsupported(
                    "REALITY ClientHello fingerprint is unsupported",
                ));
            }
        };
        let roots = Arc::new(crate::tls::load_truststore(&tls_options.truststore)?);
        let decoy_verifier: Arc<dyn ServerCertVerifier> =
            WebPkiServerVerifier::builder_with_provider(
                Arc::clone(&roots),
                Arc::new(rustls::crypto::aws_lc_rs::default_provider()),
            )
            .build()
            .map_err(|_| unsupported("REALITY decoy trust store is invalid"))?;
        let template = |provider| {
            let mut tls = crate::tls::client_builder_with_provider(provider)
                .with_root_certificates((*roots).clone())
                .with_no_client_auth();
            // A resumed TLS session could bypass the per-connection REALITY proof.
            tls.resumption = rustls::client::Resumption::disabled();
            if profile.is_none() {
                // Enabling Brotli for the Chrome profile must not change the
                // ClientHello of REALITY nodes without a fingerprint.
                tls.cert_decompressors.clear();
            }
            tls.alpn_protocols = tls_options
                .alpn
                .iter()
                .map(|protocol| protocol.as_bytes().to_vec())
                .collect();
            if tls.alpn_protocols.is_empty()
                && config.options.transport.as_ref().is_some_and(|transport| {
                    matches!(transport.kind.as_str(), "ws" | "httpupgrade")
                })
            {
                tls.alpn_protocols.push(b"http/1.1".to_vec());
            }
            tls
        };
        let supports_hybrid = matches!(profile, None | Some(ClientHelloProfile::Chrome133));
        let tls_hybrid = template(if profile == Some(ClientHelloProfile::Firefox120) {
            crate::reality_tls::reality_provider_firefox_arc()
        } else if supports_hybrid {
            crate::reality_tls::reality_provider_arc()
        } else {
            crate::reality_tls::reality_provider_classic_arc()
        });
        let tls_classic = (profile == Some(ClientHelloProfile::Chrome133))
            .then(|| template(crate::reality_tls::reality_provider_classic_arc()));
        let public_key = reality.server_public_key;
        let short_id = reality.short_id;
        let allow_insecure = tls_options.insecure;
        let (initial_tls, _) = reality_client_config(
            &tls_hybrid,
            public_key,
            short_id,
            allow_insecure,
            profile,
            Arc::clone(&decoy_verifier),
        );
        let (transport_config, packet_encoding) =
            crate::native_protocol::vless_transport_config(config, vision)?;
        let transport =
            NativeTransport::new(&transport_config, credential, initial_tls, timeout_duration)?
                .require_tls13();
        Ok(Self {
            metadata: TransitMetadata {
                adapter_id: config.id.as_str().to_owned(),
                kind: AdapterKind::ExternalProxy {
                    protocol: "vless-reality".to_owned(),
                },
                labels: config.labels.clone(),
            },
            uuid: Zeroizing::new(*uuid.as_bytes()),
            transport,
            tls_hybrid,
            tls_classic,
            fingerprint_profile: profile,
            decoy_verifier,
            server_public_key: public_key,
            short_id,
            allow_insecure,
            preferred_hybrid: AtomicBool::new(profile != Some(ClientHelloProfile::Chrome133)),
            retry_after: Mutex::new(None),
            retry_generation: AtomicU64::new(0),
            retry_gate: tokio::sync::Mutex::new(()),
            udp: config.options.udp != Some(false),
            vision,
            packet_encoding,
            timeout: timeout_duration,
        })
    }

    async fn connect_authenticated(
        &self,
    ) -> Result<
        (
            BoxedTransitConnection,
            Option<Arc<crate::vision_transport::VisionSwitch>>,
        ),
        TransitError,
    > {
        let supports_retry = self.tls_classic.is_some();
        let mut hybrid = self.preferred_hybrid.load(Ordering::Acquire);
        let mut retried = false;
        let mut retry_guard = None;
        let mut probe_generation = 0;
        loop {
            match self.connect_attempt(hybrid).await {
                RealityAttempt::Authenticated(stream, direct) => {
                    if supports_retry {
                        let mut deadline = self
                            .retry_after
                            .lock()
                            .map_err(|_| protocol("REALITY retry state is unavailable"))?;
                        self.preferred_hybrid.store(hybrid, Ordering::Release);
                        self.retry_generation.fetch_add(1, Ordering::AcqRel);
                        *deadline = None;
                    }
                    return Ok((stream, direct));
                }
                RealityAttempt::Failed(error) => return Err(error),
                RealityAttempt::TrustedDecoy => {
                    if supports_retry && !retried {
                        // Serialize alternate probes and recheck after waiting:
                        // another request may have updated the preference.
                        let guard = self.retry_gate.lock().await;
                        let state = {
                            let deadline = self
                                .retry_after
                                .lock()
                                .map_err(|_| protocol("REALITY retry state is unavailable"))?;
                            deadline
                                .is_none_or(|deadline| Instant::now() >= deadline)
                                .then(|| {
                                    (
                                        self.preferred_hybrid.load(Ordering::Acquire),
                                        self.retry_generation.load(Ordering::Acquire),
                                    )
                                })
                        };
                        if let Some((preferred, generation)) = state {
                            retried = true;
                            hybrid = if preferred == hybrid {
                                !hybrid
                            } else {
                                preferred
                            };
                            probe_generation = generation;
                            retry_guard = Some(guard);
                            continue;
                        }
                    }
                    if retried {
                        debug_assert!(retry_guard.is_some());
                        let mut deadline = self
                            .retry_after
                            .lock()
                            .map_err(|_| protocol("REALITY retry state is unavailable"))?;
                        if self.retry_generation.load(Ordering::Acquire) == probe_generation {
                            *deadline = Some(Instant::now() + Duration::from_secs(5 * 60));
                        }
                    }
                    return Err(protocol(
                        "REALITY peer returned a trusted decoy certificate",
                    ));
                }
            }
        }
    }

    async fn connect_attempt(&self, hybrid: bool) -> RealityAttempt {
        let (template, profile) = if hybrid {
            (&self.tls_hybrid, self.fingerprint_profile)
        } else if let Some(template) = &self.tls_classic {
            (template, Some(ClientHelloProfile::Chrome133Classic))
        } else {
            return RealityAttempt::Failed(protocol("REALITY classic profile is unavailable"));
        };
        let (tls, state) = reality_client_config(
            template,
            self.server_public_key,
            self.short_id,
            self.allow_insecure,
            profile,
            Arc::clone(&self.decoy_verifier),
        );
        let verified_decoy = AtomicBool::new(false);
        let authenticate = || match state.peer.load(Ordering::Acquire) {
            PEER_REALITY => Ok(()),
            PEER_TRUSTED_DECOY => {
                verified_decoy.store(true, Ordering::Release);
                Err(protocol(
                    "REALITY peer returned a trusted decoy certificate",
                ))
            }
            _ => Err(protocol("REALITY peer failed authentication")),
        };
        match self
            .transport
            .connect_reality(tls, self.vision.is_some(), &authenticate)
            .await
        {
            Ok((stream, direct)) => RealityAttempt::Authenticated(stream, direct),
            Err(_) if verified_decoy.load(Ordering::Acquire) => RealityAttempt::TrustedDecoy,
            Err(error) => RealityAttempt::Failed(error),
        }
    }

    async fn open(
        &self,
        destination: &Endpoint,
        udp: bool,
    ) -> Result<BoxedTransitConnection, TransitError> {
        if !(udp && self.packet_encoding == crate::native_protocol::VlessPacketEncoding::PacketAddr)
        {
            crate::validate_destination(destination)?;
        }
        timeout(self.timeout, async {
            let (mut stream, direct) = self.connect_authenticated().await?;
            let request = crate::native_protocol::vless_request_with_flow(
                &self.uuid,
                destination,
                udp,
                udp && self.packet_encoding == crate::native_protocol::VlessPacketEncoding::Xudp,
                self.vision.map(|_| crate::vision::FLOW_VISION),
            )?;
            let request = Zeroizing::new(request);
            if self.vision.is_some() {
                let response = Box::new(crate::native_protocol::VlessResponseIo::new(stream));
                return Ok(Box::new(
                    crate::vision::VisionStream::new(
                        response,
                        crate::vision::VisionContext::new(&self.uuid),
                    )
                    .with_request_header(request)
                    .with_direct_signal(direct.expect("Vision connection has a direct signal"))
                    .drive_request(),
                ) as BoxedTransitConnection);
            }
            stream
                .write_all(&request)
                .await
                .map_err(|_| protocol("REALITY VLESS request write failed"))?;
            stream
                .flush()
                .await
                .map_err(|_| protocol("REALITY VLESS request flush failed"))?;
            let response = Box::new(crate::native_protocol::VlessResponseIo::new(stream));
            Ok(response as BoxedTransitConnection)
        })
        .await
        .map_err(|_| TransitError::Connection("REALITY VLESS opening timed out".into()))?
    }
}

enum RealityAttempt {
    Authenticated(
        BoxedTransitConnection,
        Option<Arc<crate::vision_transport::VisionSwitch>>,
    ),
    TrustedDecoy,
    Failed(TransitError),
}

fn reality_client_config(
    template: &ClientConfig,
    public_key: [u8; 32],
    short_id: [u8; 8],
    allow_insecure: bool,
    profile: Option<ClientHelloProfile>,
    decoy_verifier: Arc<dyn ServerCertVerifier>,
) -> (Arc<ClientConfig>, Arc<RealityConnectionState>) {
    let state = Arc::new(RealityConnectionState::new(
        public_key,
        short_id,
        allow_insecure,
    ));
    let mut tls = template.clone();
    tls.client_hello_profile = profile;
    tls.reality_callback = Some(state.clone());
    tls.dangerous()
        .set_certificate_verifier(Arc::new(RealityVerifier {
            state: Arc::clone(&state),
            decoy_verifier,
        }));
    (Arc::new(tls), state)
}

#[async_trait]
impl TransitAdapter for RealityVlessAdapter {
    fn metadata(&self) -> &TransitMetadata {
        &self.metadata
    }

    fn supports_udp(&self) -> bool {
        self.udp
    }

    async fn connect(
        &self,
        request: ConnectRequest,
    ) -> Result<BoxedTransitConnection, TransitError> {
        self.open(&request.destination, false).await
    }

    async fn connect_udp(
        &self,
        request: ConnectRequest,
    ) -> Result<BoxedTransitDatagram, TransitError> {
        if !self.udp {
            return Err(unsupported("REALITY VLESS UDP is disabled"));
        }
        if self.vision.is_some_and(|flow| !flow.allow_udp_443) && request.destination.port == 443 {
            return Err(unsupported("VLESS Vision rejects UDP to port 443"));
        }
        crate::validate_destination(&request.destination)?;
        use crate::native_protocol::VlessPacketEncoding;
        let target = if self.packet_encoding == VlessPacketEncoding::PacketAddr {
            if request
                .destination
                .host
                .parse::<std::net::IpAddr>()
                .is_err()
            {
                return Err(unsupported(
                    "REALITY VLESS packetaddr requires an IP destination",
                ));
            }
            crate::native_protocol::packetaddr_magic_destination()
        } else {
            request.destination.clone()
        };
        let stream = self.open(&target, true).await?;
        match self.packet_encoding {
            VlessPacketEncoding::Xudp => crate::xudp::xudp_datagram(stream, request.destination),
            VlessPacketEncoding::PacketAddr => {
                let inner = crate::native_protocol::vless_datagram(stream, target);
                Ok(Box::new(crate::vmess::PacketAddrDatagram::new(
                    inner,
                    request.destination,
                    usize::from(u16::MAX),
                )?))
            }
            VlessPacketEncoding::Plain => Ok(crate::native_protocol::vless_datagram(
                stream,
                request.destination,
            )),
        }
    }
}

const PEER_PENDING: u8 = 0;
const PEER_REALITY: u8 = 1;
const PEER_TRUSTED_DECOY: u8 = 2;
const PEER_UNTRUSTED: u8 = 3;

#[derive(Debug)]
struct RealityConnectionState {
    auth_key: Mutex<Option<[u8; 32]>>,
    peer: AtomicU8,
    server_public_key: [u8; 32],
    short_id: [u8; 8],
    allow_insecure: bool,
}

impl RealityConnectionState {
    fn new(server_public_key: [u8; 32], short_id: [u8; 8], allow_insecure: bool) -> Self {
        Self {
            auth_key: Mutex::new(None),
            peer: AtomicU8::new(PEER_PENDING),
            server_public_key,
            short_id,
            allow_insecure,
        }
    }
}

impl Drop for RealityConnectionState {
    fn drop(&mut self) {
        let key = self
            .auth_key
            .get_mut()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(key) = key.as_mut() {
            key.zeroize();
        }
    }
}

impl RealityCallback for RealityConnectionState {
    fn apply_reality(
        &self,
        key_exchange: &dyn ActiveKeyExchange,
        random: &[u8; 32],
        session_id: &mut [u8; 32],
        raw_hello: &[u8],
    ) -> Result<(), Error> {
        let shared = key_exchange
            .extract_reality_key(&self.server_public_key)
            .ok_or_else(|| Error::General("REALITY X25519 key extraction failed".into()))?;
        let hkdf = Hkdf::<Sha256>::new(Some(&random[..20]), &shared);
        let mut auth_key = [0_u8; 32];
        hkdf.expand(b"REALITY", &mut auth_key)
            .map_err(|_| Error::General("REALITY HKDF failed".into()))?;
        *self
            .auth_key
            .lock()
            .map_err(|_| Error::General("REALITY state lock failed".into()))? = Some(auth_key);

        if raw_hello.len() < 71 {
            return Err(Error::General("REALITY ClientHello is truncated".into()));
        }
        let mut plaintext = [0_u8; 16];
        plaintext[0] = 1;
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| Error::General("REALITY clock is before Unix epoch".into()))?
            .as_secs() as u32;
        plaintext[4..8].copy_from_slice(&timestamp.to_be_bytes());
        plaintext[8..].copy_from_slice(&self.short_id);
        let mut aad = raw_hello.to_vec();
        aad[39..71].fill(0);
        let mut proof = plaintext.to_vec();
        Aes256Gcm::new_from_slice(&auth_key)
            .map_err(|_| Error::General("REALITY AES key failed".into()))?
            .encrypt_in_place(Nonce::from_slice(&random[20..]), &aad, &mut proof)
            .map_err(|_| Error::General("REALITY proof encryption failed".into()))?;
        session_id.copy_from_slice(&proof);
        Ok(())
    }
}

#[derive(Debug)]
struct RealityVerifier {
    state: Arc<RealityConnectionState>,
    decoy_verifier: Arc<dyn ServerCertVerifier>,
}

impl ServerCertVerifier for RealityVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        if let Ok((_, certificate)) = parse_x509_certificate(end_entity.as_ref()) {
            let key = self
                .state
                .auth_key
                .lock()
                .map_err(|_| Error::General("REALITY state lock failed".into()))?;
            if let Some(key) = *key
                && certificate
                    .tbs_certificate
                    .subject_pki
                    .algorithm
                    .algorithm
                    .to_id_string()
                    == "1.3.101.112"
            {
                let mut mac = <Hmac<Sha512> as Mac>::new_from_slice(&key)
                    .map_err(|_| Error::General("REALITY HMAC key failed".into()))?;
                mac.update(
                    certificate
                        .tbs_certificate
                        .subject_pki
                        .subject_public_key
                        .as_ref(),
                );
                if mac
                    .verify_slice(certificate.signature_value.as_ref())
                    .is_ok()
                {
                    self.state.peer.store(PEER_REALITY, Ordering::Release);
                    return Ok(ServerCertVerified::assertion());
                }
            }
        }
        match self.decoy_verifier.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            ocsp_response,
            now,
        ) {
            Ok(_) => {
                self.state.peer.store(PEER_TRUSTED_DECOY, Ordering::Release);
                Ok(ServerCertVerified::assertion())
            }
            Err(_) if self.state.allow_insecure => {
                // Explicitly allowing insecure TLS does not authenticate the
                // REALITY peer and must never cause VLESS data to be sent.
                self.state.peer.store(PEER_UNTRUSTED, Ordering::Release);
                Ok(ServerCertVerified::assertion())
            }
            Err(_) => Err(Error::General("REALITY certificate proof failed".into())),
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            certificate,
            signature,
            &rustls::crypto::aws_lc_rs::default_provider().signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            certificate,
            signature,
            &rustls::crypto::aws_lc_rs::default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::aws_lc_rs::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

fn unsupported(message: impl Into<String>) -> TransitError {
    TransitError::Unsupported(message.into())
}

fn protocol(message: &str) -> TransitError {
    TransitError::Protocol(message.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use pathchord_policy::{
        Endpoint as PolicyEndpoint, TransitOptions, TransitProxyId, TransitTls,
    };
    use std::collections::{BTreeMap, BTreeSet};
    use std::path::PathBuf;
    use std::process::Stdio;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};
    use tokio::process::Command;
    use tokio_rustls::TlsAcceptor;

    #[derive(Debug)]
    struct CountingVerifier {
        inner: Arc<dyn ServerCertVerifier>,
        accepted: Arc<AtomicU8>,
    }

    impl ServerCertVerifier for CountingVerifier {
        fn verify_server_cert(
            &self,
            end_entity: &CertificateDer<'_>,
            intermediates: &[CertificateDer<'_>],
            server_name: &ServerName<'_>,
            ocsp_response: &[u8],
            now: UnixTime,
        ) -> Result<ServerCertVerified, Error> {
            let result = self.inner.verify_server_cert(
                end_entity,
                intermediates,
                server_name,
                ocsp_response,
                now,
            );
            if result.is_ok() {
                self.accepted.fetch_add(1, Ordering::SeqCst);
            }
            result
        }
        fn verify_tls12_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            signature: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            self.inner.verify_tls12_signature(message, cert, signature)
        }
        fn verify_tls13_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            signature: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            self.inner.verify_tls13_signature(message, cert, signature)
        }
        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            self.inner.supported_verify_schemes()
        }
    }

    fn test_adapter(port: u16, insecure: bool, duration: Duration) -> RealityVlessAdapter {
        let config = pathchord_policy::TransitProxyConfig {
            id: TransitProxyId::new("reality-decoy-test"),
            source: None,
            protocol: "vless".into(),
            endpoint: PolicyEndpoint {
                host: "127.0.0.1".into(),
                port,
            },
            credentials_ref: None,
            labels: BTreeMap::new(),
            tags: BTreeSet::new(),
            weight: 1,
            options: TransitOptions {
                tls: Some(TransitTls {
                    enabled: true,
                    insecure,
                    server_name: Some("decoy.test".into()),
                    fingerprint: Some("chrome".into()),
                    reality: Some(pathchord_policy::TransitReality {
                        public_key: "Q7VhOFla3pZJiGzjiNfwi3j-QfEr9FOdDpQIiDANtRM".into(),
                        short_id: "0123456789abcdef".into(),
                    }),
                    ..Default::default()
                }),
                ..Default::default()
            },
        };
        let credential = TransitCredential::new(BTreeMap::from([(
            "uuid".into(),
            "6cbf3f72-3417-4922-bde6-67820d041f25".into(),
        )]));
        RealityVlessAdapter::from_config(
            &config,
            &credential,
            duration,
            crate::adapter_registry::native_tls_roots(),
        )
        .unwrap()
    }

    fn request() -> ConnectRequest {
        ConnectRequest {
            destination: Endpoint {
                host: "target.test".into(),
                port: 443,
            },
        }
    }

    async fn decoy_server(
        trusted: bool,
        insecure: bool,
        certificate_name: &str,
    ) -> (
        RealityVlessAdapter,
        Arc<std::sync::atomic::AtomicUsize>,
        Arc<std::sync::atomic::AtomicUsize>,
        Arc<std::sync::atomic::AtomicUsize>,
        tokio::task::JoinHandle<()>,
    ) {
        use std::sync::atomic::AtomicUsize;
        let rcgen::CertifiedKey { cert, signing_key } =
            rcgen::generate_simple_self_signed(vec![certificate_name.into()]).unwrap();
        let server_config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.der().clone()],
            rustls::pki_types::PrivatePkcs8KeyDer::from(signing_key.serialize_der()).into(),
        )
        .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let mut adapter = test_adapter(port, insecure, Duration::from_secs(3));
        if trusted {
            let mut roots = rustls::RootCertStore::empty();
            roots.add(cert.der().clone()).unwrap();
            adapter.decoy_verifier = WebPkiServerVerifier::builder_with_provider(
                Arc::new(roots),
                Arc::new(rustls::crypto::aws_lc_rs::default_provider()),
            )
            .build()
            .unwrap();
        }
        let connections = Arc::new(AtomicUsize::new(0));
        let application_data = Arc::new(AtomicUsize::new(0));
        let inspected = Arc::new(AtomicUsize::new(0));
        let counts = Arc::clone(&connections);
        let payloads = Arc::clone(&application_data);
        let finished = Arc::clone(&inspected);
        let task = tokio::spawn(async move {
            let acceptor = TlsAcceptor::from(Arc::new(server_config));
            while let Ok((stream, _)) = listener.accept().await {
                counts.fetch_add(1, Ordering::SeqCst);
                let acceptor = acceptor.clone();
                let payloads = Arc::clone(&payloads);
                let finished = Arc::clone(&finished);
                tokio::spawn(async move {
                    if let Ok(mut tls) = acceptor.accept(stream).await {
                        let mut data = [0; 1];
                        if let Ok(Ok(length)) =
                            timeout(Duration::from_secs(1), tls.read(&mut data)).await
                            && length > 0
                        {
                            payloads.fetch_add(1, Ordering::SeqCst);
                        }
                    }
                    finished.fetch_add(1, Ordering::SeqCst);
                });
            }
        });
        (adapter, connections, application_data, inspected, task)
    }

    #[tokio::test]
    async fn trusted_decoy_retries_once_then_respects_backoff_without_vless_data() {
        for hybrid in [false, true] {
            let (adapter, connections, payloads, inspected, task) =
                decoy_server(true, false, "decoy.test").await;
            adapter.preferred_hybrid.store(hybrid, Ordering::Release);
            assert!(matches!(
                adapter.connect(request()).await,
                Err(TransitError::Protocol(_))
            ));
            assert_eq!(connections.load(Ordering::SeqCst), 2);
            assert!(adapter.retry_after.lock().unwrap().is_some());
            assert!(matches!(
                adapter.connect(request()).await,
                Err(TransitError::Protocol(_))
            ));
            assert_eq!(connections.load(Ordering::SeqCst), 3);
            timeout(Duration::from_secs(2), async {
                while inspected.load(Ordering::SeqCst) < 3 {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .unwrap();
            assert_eq!(payloads.load(Ordering::SeqCst), 0);
            task.abort();
        }
    }

    #[tokio::test]
    async fn concurrent_decoy_connections_share_one_alternate_probe() {
        const CONCURRENCY: usize = 8;
        let (adapter, connections, payloads, inspected, task) =
            decoy_server(true, false, "decoy.test").await;
        let adapter = Arc::new(adapter);
        let barrier = Arc::new(tokio::sync::Barrier::new(CONCURRENCY));
        let mut tasks = tokio::task::JoinSet::new();
        for _ in 0..CONCURRENCY {
            let adapter = Arc::clone(&adapter);
            let barrier = Arc::clone(&barrier);
            tasks.spawn(async move {
                barrier.wait().await;
                assert!(adapter.connect(request()).await.is_err());
            });
        }
        while let Some(result) = tasks.join_next().await {
            result.unwrap();
        }
        assert_eq!(connections.load(Ordering::SeqCst), CONCURRENCY + 1);
        timeout(Duration::from_secs(2), async {
            while inspected.load(Ordering::SeqCst) < CONCURRENCY + 1 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(payloads.load(Ordering::SeqCst), 0);
        task.abort();
    }

    #[tokio::test]
    async fn untrusted_decoy_never_retries_or_receives_vless_data() {
        for (trusted, insecure, name) in [
            (false, false, "decoy.test"),
            (false, true, "decoy.test"),
            (true, false, "wrong.test"),
        ] {
            let (adapter, connections, payloads, inspected, task) =
                decoy_server(trusted, insecure, name).await;
            assert!(adapter.connect(request()).await.is_err());
            assert_eq!(connections.load(Ordering::SeqCst), 1);
            timeout(Duration::from_secs(2), async {
                while inspected.load(Ordering::SeqCst) < 1 {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .unwrap();
            assert_eq!(payloads.load(Ordering::SeqCst), 0);
            assert!(adapter.retry_after.lock().unwrap().is_none());
            task.abort();
        }
    }

    #[tokio::test]
    async fn tls_timeout_does_not_retry_an_unverified_peer() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let adapter = test_adapter(port, false, Duration::from_millis(150));
        let task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let _stream = stream;
            tokio::time::sleep(Duration::from_secs(2)).await;
        });
        assert!(matches!(
            adapter.connect(request()).await,
            Err(TransitError::Connection(_))
        ));
        assert!(adapter.retry_after.lock().unwrap().is_none());
        task.abort();
    }

    #[tokio::test]
    async fn alternate_attempt_uses_the_original_overall_deadline() {
        let rcgen::CertifiedKey { cert, signing_key } =
            rcgen::generate_simple_self_signed(vec!["decoy.test".into()]).unwrap();
        let server = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.der().clone()],
            rustls::pki_types::PrivatePkcs8KeyDer::from(signing_key.serialize_der()).into(),
        )
        .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut adapter = test_adapter(
            listener.local_addr().unwrap().port(),
            false,
            Duration::from_millis(600),
        );
        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert.der().clone()).unwrap();
        adapter.decoy_verifier = WebPkiServerVerifier::builder_with_provider(
            Arc::new(roots),
            Arc::new(rustls::crypto::aws_lc_rs::default_provider()),
        )
        .build()
        .unwrap();
        let accepted = Arc::new(AtomicU8::new(0));
        let accepted_by_peer = Arc::clone(&accepted);
        let task = tokio::spawn(async move {
            let (first, _) = listener.accept().await.unwrap();
            accepted_by_peer.fetch_add(1, Ordering::SeqCst);
            tokio::time::sleep(Duration::from_millis(400)).await;
            let _first = TlsAcceptor::from(Arc::new(server))
                .accept(first)
                .await
                .unwrap();
            let (second, _) = listener.accept().await.unwrap();
            accepted_by_peer.fetch_add(1, Ordering::SeqCst);
            let _second = second;
            tokio::time::sleep(Duration::from_secs(2)).await;
        });
        let started = Instant::now();
        assert!(matches!(
            adapter.connect(request()).await,
            Err(TransitError::Connection(_))
        ));
        assert_eq!(accepted.load(Ordering::SeqCst), 2);
        assert!(started.elapsed() < Duration::from_millis(900));
        task.abort();
    }

    #[tokio::test]
    async fn trusted_certificate_with_corrupt_finished_does_not_retry() {
        let rcgen::CertifiedKey { cert, signing_key } =
            rcgen::generate_simple_self_signed(vec!["decoy.test".into()]).unwrap();
        let mut server = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.der().clone()],
            rustls::pki_types::PrivatePkcs8KeyDer::from(signing_key.serialize_der()).into(),
        )
        .unwrap();
        server.max_fragment_size = Some(32);
        let server = Arc::new(server);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut adapter = test_adapter(
            listener.local_addr().unwrap().port(),
            false,
            Duration::from_secs(2),
        );
        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert.der().clone()).unwrap();
        let webpki = WebPkiServerVerifier::builder_with_provider(
            Arc::new(roots),
            Arc::new(rustls::crypto::aws_lc_rs::default_provider()),
        )
        .build()
        .unwrap();
        let verified_certificates = Arc::new(AtomicU8::new(0));
        adapter.decoy_verifier = Arc::new(CountingVerifier {
            inner: webpki,
            accepted: Arc::clone(&verified_certificates),
        });
        let connections = Arc::new(AtomicU8::new(0));
        let accepted = Arc::clone(&connections);
        let task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            accepted.fetch_add(1, Ordering::SeqCst);
            let mut connection = rustls::ServerConnection::new(server).unwrap();
            let mut input = [0; 8192];
            let mut flight = Vec::new();
            while flight.is_empty() {
                let size = stream.read(&mut input).await.unwrap();
                assert!(size > 0);
                let mut bytes = &input[..size];
                while !bytes.is_empty() {
                    connection.read_tls(&mut bytes).unwrap();
                    connection.process_new_packets().unwrap();
                }
                while connection.wants_write() {
                    connection.write_tls(&mut flight).unwrap();
                }
            }
            // Corrupt only the last encrypted record (Finished); certificate
            // validation runs first, but the TLS handshake cannot complete.
            *flight.last_mut().unwrap() ^= 1;
            stream.write_all(&flight).await.unwrap();
            if timeout(Duration::from_millis(100), listener.accept())
                .await
                .is_ok()
            {
                accepted.fetch_add(1, Ordering::SeqCst);
            }
        });
        assert!(adapter.connect(request()).await.is_err());
        task.await.unwrap();
        assert_eq!(connections.load(Ordering::SeqCst), 1);
        assert_eq!(verified_certificates.load(Ordering::SeqCst), 1);
        assert!(adapter.retry_after.lock().unwrap().is_none());
    }

    #[test]
    fn reality_vless_is_registered_with_the_local_tls_callback() {
        let mut config = pathchord_policy::TransitProxyConfig {
            id: TransitProxyId::new("reality-test"),
            source: None,
            protocol: "vless".into(),
            endpoint: PolicyEndpoint {
                host: "proxy.test".into(),
                port: 443,
            },
            credentials_ref: None,
            labels: BTreeMap::new(),
            tags: BTreeSet::new(),
            weight: 100,
            options: TransitOptions {
                tls: Some(TransitTls {
                    enabled: true,
                    insecure: true,
                    server_name: Some("www.example.com".into()),
                    reality: Some(pathchord_policy::TransitReality {
                        public_key: base64::Engine::encode(
                            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
                            [7_u8; 32],
                        ),
                        short_id: "0123456789abcdef".into(),
                    }),
                    ..Default::default()
                }),
                ..Default::default()
            },
        };
        let credential = TransitCredential::new(BTreeMap::from([(
            "uuid".into(),
            "6cbf3f72-3417-4922-bde6-67820d041f25".into(),
        )]));
        let adapter = RealityVlessAdapter::from_config(
            &config,
            &credential,
            Duration::from_secs(3),
            crate::adapter_registry::native_tls_roots(),
        )
        .unwrap();
        assert!(adapter.supports_tcp());
        assert!(adapter.supports_udp());
        assert_eq!(
            adapter.metadata().kind,
            AdapterKind::ExternalProxy {
                protocol: "vless-reality".into()
            }
        );
        let template = crate::adapter_registry::native_tls_roots();
        let (first, _) = reality_client_config(
            &template,
            [7; 32],
            [1; 8],
            false,
            None,
            Arc::clone(&adapter.decoy_verifier),
        );
        let (second, _) = reality_client_config(
            &template,
            [7; 32],
            [1; 8],
            false,
            None,
            Arc::clone(&adapter.decoy_verifier),
        );
        assert!(!Arc::ptr_eq(
            first.reality_callback.as_ref().unwrap(),
            second.reality_callback.as_ref().unwrap()
        ));
        config.options.tls.as_mut().unwrap().fingerprint = Some("chrome".into());
        assert!(
            RealityVlessAdapter::from_config(
                &config,
                &credential,
                Duration::from_secs(3),
                crate::adapter_registry::native_tls_roots(),
            )
            .is_ok()
        );
        for kind in ["ws", "httpupgrade"] {
            config.options.transport = Some(pathchord_policy::TransitTransport {
                kind: kind.into(),
                ..Default::default()
            });
            let adapter = RealityVlessAdapter::from_config(
                &config,
                &credential,
                Duration::from_secs(3),
                crate::adapter_registry::native_tls_roots(),
            )
            .unwrap();
            assert_eq!(adapter.tls_hybrid.alpn_protocols, [b"http/1.1".to_vec()]);
            assert_eq!(
                adapter.tls_classic.unwrap().alpn_protocols,
                [b"http/1.1".to_vec()]
            );
        }
        config.options.transport = None;
        config.options.tls.as_mut().unwrap().fingerprint = Some("unrecognized".into());
        assert!(matches!(
            RealityVlessAdapter::from_config(
                &config, &credential, Duration::from_secs(3),
                crate::adapter_registry::native_tls_roots(),
            ),
            Err(TransitError::Unsupported(reason)) if reason.contains("fingerprint")
        ));
    }

    #[tokio::test]
    #[ignore = "requires PATHCHORD_TEST_SING_BOX pointing to sing-box 1.14.4"]
    async fn native_reality_vless_interoperates_with_sing_box() {
        let binary =
            PathBuf::from(std::env::var_os("PATHCHORD_TEST_SING_BOX").expect("reference peer"));
        let uuid = "6cbf3f72-3417-4922-bde6-67820d041f25";
        let private_key = "-AxPYYdSOc0L8SVojHT0CHsejcb15DcdD2ZI8QaALlo";
        let public_key = "Q7VhOFla3pZJiGzjiNfwi3j-QfEr9FOdDpQIiDANtRM";
        let short_id = "0123456789abcdef";
        let decoy_key = rcgen::generate_simple_self_signed(vec!["decoy.test".into()]).unwrap();
        let decoy_server = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![decoy_key.cert.der().clone()],
            rustls::pki_types::PrivateKeyDer::Pkcs8(rustls::pki_types::PrivatePkcs8KeyDer::from(
                decoy_key.signing_key.serialize_der(),
            )),
        )
        .unwrap();
        let decoy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let decoy_port = decoy.local_addr().unwrap().port();
        let decoy_acceptor = TlsAcceptor::from(Arc::new(decoy_server));
        let decoy_task = tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = decoy.accept().await else {
                    break;
                };
                let acceptor = decoy_acceptor.clone();
                tokio::spawn(async move {
                    if let Ok(mut stream) = acceptor.accept(stream).await {
                        let _ = stream
                            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\nreality")
                            .await;
                        let mut buffer = [0_u8; 1024];
                        let _ = stream.read(&mut buffer).await;
                    }
                });
            }
        });
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let document = serde_json::json!({
            "log": {"disabled": true},
            "inbounds": [{
                "type": "vless",
                "listen": "127.0.0.1",
                "listen_port": port,
                "users": [{"uuid": uuid, "flow": "xtls-rprx-vision"}],
                "tls": {
                    "enabled": true,
                    "reality": {
                        "enabled": true,
                        "handshake": {"server": "127.0.0.1", "server_port": decoy_port},
                        "private_key": private_key,
                        "short_id": [short_id]
                    }
                }
            }],
            "outbounds": [{"type": "direct", "tag": "direct"}],
            "route": {"final": "direct"}
        });
        let mut peer = Command::new(binary)
            .arg("run")
            .arg("-c")
            .arg("stdin")
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        peer.stdin
            .take()
            .unwrap()
            .write_all(&serde_json::to_vec(&document).unwrap())
            .await
            .unwrap();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while TcpStream::connect(("127.0.0.1", port)).await.is_err() {
            assert!(
                tokio::time::Instant::now() < deadline,
                "Reality peer readiness"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_address = target.local_addr().unwrap();
        const PARALLEL_CONNECTIONS: usize = 16;
        let target_task = tokio::spawn(async move {
            let mut tasks = tokio::task::JoinSet::new();
            for _ in 0..=PARALLEL_CONNECTIONS {
                let (mut stream, _) = target.accept().await.unwrap();
                tasks.spawn(async move {
                    let mut payload = [0_u8; 7];
                    stream.read_exact(&mut payload).await.unwrap();
                    stream.write_all(&payload).await.unwrap();
                });
            }
            while let Some(result) = tasks.join_next().await {
                result.unwrap();
            }
        });
        let config = pathchord_policy::TransitProxyConfig {
            id: TransitProxyId::new("reality-peer-test"),
            source: None,
            protocol: "vless".into(),
            endpoint: PolicyEndpoint {
                host: "127.0.0.1".into(),
                port,
            },
            credentials_ref: None,
            labels: BTreeMap::new(),
            tags: BTreeSet::new(),
            weight: 100,
            options: TransitOptions {
                tls: Some(TransitTls {
                    enabled: true,
                    server_name: Some("127.0.0.1".into()),
                    reality: Some(pathchord_policy::TransitReality {
                        public_key: public_key.into(),
                        short_id: short_id.into(),
                    }),
                    alpn: vec!["h2".into(), "http/1.1".into()],
                    ..Default::default()
                }),
                ..Default::default()
            },
        };
        let credentials = TransitCredential::new(BTreeMap::from([
            ("uuid".into(), uuid.into()),
            ("flow".into(), crate::vision::FLOW_VISION.into()),
        ]));
        let adapter = Arc::new(
            RealityVlessAdapter::from_config(
                &config,
                &credentials,
                Duration::from_secs(5),
                crate::adapter_registry::native_tls_roots(),
            )
            .unwrap(),
        );
        let mut stream = adapter
            .connect(ConnectRequest {
                destination: Endpoint {
                    host: "127.0.0.1".into(),
                    port: target_address.port(),
                },
            })
            .await
            .unwrap();
        stream.write_all(b"reality").await.unwrap();
        stream.flush().await.unwrap();
        let mut echoed = [0_u8; 7];
        stream.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"reality");
        let barrier = Arc::new(tokio::sync::Barrier::new(PARALLEL_CONNECTIONS));
        let mut tasks = tokio::task::JoinSet::new();
        for _ in 0..PARALLEL_CONNECTIONS {
            let adapter = Arc::clone(&adapter);
            let barrier = Arc::clone(&barrier);
            tasks.spawn(async move {
                barrier.wait().await;
                let mut stream = adapter
                    .connect(ConnectRequest {
                        destination: Endpoint {
                            host: "127.0.0.1".into(),
                            port: target_address.port(),
                        },
                    })
                    .await
                    .unwrap();
                stream.write_all(b"reality").await.unwrap();
                stream.flush().await.unwrap();
                let mut echoed = [0; 7];
                stream.read_exact(&mut echoed).await.unwrap();
                assert_eq!(&echoed, b"reality");
            });
        }
        while let Some(result) = tasks.join_next().await {
            result.unwrap();
        }
        target_task.await.unwrap();
        peer.kill().await.unwrap();
        peer.wait().await.unwrap();
        decoy_task.abort();
    }
}
