//! Native VLESS + REALITY adapter.
//!
//! REALITY is a TLS ClientHello proof profile used by VLESS nodes. The local
//! rustls patch exposes only the two hooks required by the proof: the active
//! X25519 secret and a callback that runs before the ClientHello enters the
//! transcript. No proxy runtime or compatibility process is involved.

use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use aes_gcm::aead::{AeadInPlace, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use async_trait::async_trait;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rustls::client::RealityCallback;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::ActiveKeyExchange;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, Error, SignatureScheme};
use sha2::{Sha256, Sha512};
use tokio::io::AsyncWriteExt;
use tokio::time::timeout;
use x509_parser::parse_x509_certificate;
use zeroize::Zeroizing;

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
    udp: bool,
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
        if credential
            .field("flow")
            .is_some_and(|flow| !flow.is_empty())
        {
            return Err(unsupported(
                "REALITY VLESS flow requires a native Vision implementation",
            ));
        }
        let uuid = uuid::Uuid::parse_str(
            credential
                .field("uuid")
                .ok_or_else(|| unsupported("VLESS UUID is missing"))?,
        )
        .map_err(|_| unsupported("VLESS UUID is invalid"))?;

        let state = Arc::new(RealityConnectionState::new(
            reality.server_public_key,
            reality.short_id,
            tls_options.insecure,
        ));
        if !tls_options.client_certificate.is_empty() || tls_options.client_key_field.is_some() {
            return Err(unsupported(
                "REALITY client certificate authentication is unsupported",
            ));
        }
        let roots = crate::tls::load_truststore(&tls_options.truststore)?;
        let mut tls =
            crate::tls::client_builder_with_provider(crate::reality_tls::reality_provider_arc())
                .with_root_certificates(roots)
                .with_no_client_auth();
        tls.alpn_protocols = tls_options
            .alpn
            .iter()
            .map(|protocol| protocol.as_bytes().to_vec())
            .collect();
        tls.reality_callback = Some(state.clone());
        tls.dangerous()
            .set_certificate_verifier(Arc::new(RealityVerifier { state }));
        let transport = NativeTransport::new(config, credential, Arc::new(tls), timeout_duration)?;
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
            udp: config.options.udp != Some(false),
            timeout: timeout_duration,
        })
    }

    async fn open(
        &self,
        destination: &Endpoint,
        udp: bool,
    ) -> Result<BoxedTransitConnection, TransitError> {
        crate::validate_destination(destination)?;
        timeout(self.timeout, async {
            let mut stream = self.transport.connect().await?;
            let request = crate::native_protocol::vless_request(&self.uuid, destination, udp)?;
            stream
                .write_all(&request)
                .await
                .map_err(|_| protocol("REALITY VLESS request write failed"))?;
            stream
                .flush()
                .await
                .map_err(|_| protocol("REALITY VLESS request flush failed"))?;
            Ok(
                Box::new(crate::native_protocol::VlessResponseIo::new(stream))
                    as BoxedTransitConnection,
            )
        })
        .await
        .map_err(|_| TransitError::Connection("REALITY VLESS opening timed out".into()))?
    }
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
        let destination = request.destination.clone();
        let stream = self.open(&destination, true).await?;
        Ok(crate::native_protocol::vless_datagram(stream, destination))
    }
}

#[derive(Debug)]
struct RealityConnectionState {
    auth_key: Mutex<Option<[u8; 32]>>,
    server_public_key: [u8; 32],
    short_id: [u8; 8],
    allow_insecure: bool,
}

impl RealityConnectionState {
    fn new(server_public_key: [u8; 32], short_id: [u8; 8], allow_insecure: bool) -> Self {
        Self {
            auth_key: Mutex::new(None),
            server_public_key,
            short_id,
            allow_insecure,
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
}

impl ServerCertVerifier for RealityVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
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
                    return Ok(ServerCertVerified::assertion());
                }
            }
        }
        if self.state.allow_insecure {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(Error::General("REALITY certificate proof failed".into()))
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

    #[test]
    fn reality_vless_is_registered_with_the_local_tls_callback() {
        let config = pathchord_policy::TransitProxyConfig {
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
                "users": [{"uuid": uuid}],
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
        let target_task = tokio::spawn(async move {
            let (mut stream, _) = target.accept().await.unwrap();
            let mut payload = [0_u8; 7];
            stream.read_exact(&mut payload).await.unwrap();
            stream.write_all(&payload).await.unwrap();
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
        let credentials = TransitCredential::new(BTreeMap::from([("uuid".into(), uuid.into())]));
        let adapter = RealityVlessAdapter::from_config(
            &config,
            &credentials,
            Duration::from_secs(5),
            crate::adapter_registry::native_tls_roots(),
        )
        .unwrap();
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
        target_task.await.unwrap();
        peer.kill().await.unwrap();
        peer.wait().await.unwrap();
        decoy_task.abort();
    }
}
