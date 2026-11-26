//! TLS options for native proxy transports. Unsupported extensions never downgrade.

use std::fs;
use std::path::Path;
use std::sync::Arc;

use pathchord_policy::TransitTls;
use rustls::client::ClientHelloProfile;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme};
use sha2::{Digest, Sha256};

use crate::{TransitCredential, TransitError};

const MAX_TRUSTSTORE_SOURCE_BYTES: u64 = 8 * 1024 * 1024;

pub(crate) fn client_builder() -> rustls::ConfigBuilder<ClientConfig, rustls::WantsVerifier> {
    client_builder_with_provider(Arc::new(rustls::crypto::aws_lc_rs::default_provider()))
}

pub(crate) fn client_builder_with_provider(
    provider: Arc<rustls::crypto::CryptoProvider>,
) -> rustls::ConfigBuilder<ClientConfig, rustls::WantsVerifier> {
    ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("the selected AWS-LC provider supports the default TLS versions")
}

pub(crate) fn configure(
    _base: Arc<ClientConfig>,
    options: Option<&TransitTls>,
    credential: Option<&TransitCredential>,
) -> Result<Arc<ClientConfig>, TransitError> {
    let Some(options) = options else {
        return Ok(_base);
    };
    if !options.enabled {
        return Err(TransitError::Unsupported(
            "TLS options must enable TLS".into(),
        ));
    }
    if options.reality.is_some() {
        return Err(TransitError::Unsupported(
            "Reality requires a native Reality adapter".into(),
        ));
    }
    let profile = match options.fingerprint.as_deref() {
        None => None,
        Some(value) if value.eq_ignore_ascii_case("chrome") => Some(ClientHelloProfile::Chrome133),
        Some(value) if value.eq_ignore_ascii_case("ios") => Some(ClientHelloProfile::Ios14),
        Some(value) if value.eq_ignore_ascii_case("safari") => Some(ClientHelloProfile::Safari16),
        Some(value) if value.eq_ignore_ascii_case("edge") => Some(ClientHelloProfile::Edge85),
        Some(value) if value.eq_ignore_ascii_case("qq") => Some(ClientHelloProfile::Qq111),
        Some(value) if value.eq_ignore_ascii_case("firefox") => {
            Some(ClientHelloProfile::Firefox120)
        }
        Some(value) if value.eq_ignore_ascii_case("android") => Some(ClientHelloProfile::Android11),
        Some(value) if value.eq_ignore_ascii_case("360") => {
            return Err(TransitError::Unsupported(
                "360 TLS fingerprint requires legacy cipher suites unavailable in native TLS"
                    .into(),
            ));
        }
        Some(_) => {
            return Err(TransitError::Unsupported(
                "TLS ClientHello fingerprint is unsupported".into(),
            ));
        }
    };
    if profile == Some(ClientHelloProfile::Android11) && !options.alpn.is_empty() {
        return Err(TransitError::Unsupported(
            "Android TLS fingerprint cannot carry ALPN".into(),
        ));
    }
    let mut roots = load_truststore(&options.truststore)?;
    let mut config = {
        for certificate in certificates(&options.certificate)? {
            roots
                .add(certificate)
                .map_err(|_| TransitError::Unsupported("TLS CA certificate is invalid".into()))?;
        }
        let provider = match profile {
            Some(ClientHelloProfile::Chrome133) => crate::reality_tls::reality_provider_arc(),
            Some(ClientHelloProfile::Firefox120) => {
                crate::reality_tls::reality_provider_firefox_arc()
            }
            Some(
                ClientHelloProfile::Ios14
                | ClientHelloProfile::Safari16
                | ClientHelloProfile::Edge85
                | ClientHelloProfile::Qq111
                | ClientHelloProfile::Android11,
            ) => crate::reality_tls::reality_provider_classic_arc(),
            Some(_) => unreachable!("unsupported profile is never constructed"),
            None => Arc::new(rustls::crypto::aws_lc_rs::default_provider()),
        };
        let builder = if profile == Some(ClientHelloProfile::Android11) {
            ClientConfig::builder_with_provider(provider)
                .with_protocol_versions(&[&rustls::version::TLS12])
                .map_err(|_| {
                    TransitError::Unsupported("Android TLS 1.2 profile is unavailable".into())
                })?
        } else {
            client_builder_with_provider(provider)
        }
        .with_root_certificates(roots);
        if options.client_certificate.is_empty() && options.client_key_field.is_none() {
            builder.with_no_client_auth()
        } else {
            let field = options.client_key_field.as_deref().ok_or_else(|| {
                TransitError::Unsupported("TLS client key field is missing".into())
            })?;
            let pem = credential
                .and_then(|credential| credential.field(field))
                .ok_or_else(|| {
                    TransitError::Unsupported("TLS client private key is missing".into())
                })?;
            let key = PrivateKeyDer::from_pem_slice(pem.as_bytes()).map_err(|_| {
                TransitError::Unsupported("TLS client private key is invalid".into())
            })?;
            builder
                .with_client_auth_cert(certificates(&options.client_certificate)?, key)
                .map_err(|_| {
                    TransitError::Unsupported("TLS client certificate and key are invalid".into())
                })?
        }
    };
    config.alpn_protocols = options
        .alpn
        .iter()
        .map(|protocol| protocol.as_bytes().to_vec())
        .collect();
    config.client_hello_profile = profile;
    if profile.is_some() {
        config.resumption = rustls::client::Resumption::disabled();
    }
    if let Some(pin) = &options.certificate_sha256 {
        config
            .dangerous()
            .set_certificate_verifier(Arc::new(CertificatePinVerifier {
                digest: parse_certificate_pin(pin)?,
            }));
    } else if options.insecure {
        config
            .dangerous()
            .set_certificate_verifier(Arc::new(ExplicitInsecureVerifier));
    }
    Ok(Arc::new(config))
}

fn parse_certificate_pin(value: &str) -> Result<[u8; 32], TransitError> {
    pathchord_policy::parse_certificate_sha256(value)
        .ok_or_else(|| TransitError::Unsupported("TLS certificate SHA-256 pin is invalid".into()))
}

#[derive(Debug)]
struct CertificatePinVerifier {
    digest: [u8; 32],
}

impl ServerCertVerifier for CertificatePinVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        if Sha256::digest(end_entity.as_ref())[..] == self.digest {
            return Ok(ServerCertVerified::assertion());
        }
        for (index, certificate) in intermediates.iter().enumerate() {
            if Sha256::digest(certificate.as_ref())[..] != self.digest {
                continue;
            }
            let mut roots = RootCertStore::empty();
            roots
                .add(certificate.clone().into_owned())
                .map_err(|_| rustls::Error::General("TLS pinned certificate is invalid".into()))?;
            let verifier = rustls::client::WebPkiServerVerifier::builder_with_provider(
                Arc::new(roots),
                Arc::new(rustls::crypto::aws_lc_rs::default_provider()),
            )
            .build()
            .map_err(|_| rustls::Error::General("TLS pinned certificate is invalid".into()))?;
            return verifier.verify_server_cert(
                end_entity,
                &intermediates[..index],
                server_name,
                ocsp_response,
                now,
            );
        }
        Err(rustls::Error::General(
            "TLS certificate SHA-256 pin mismatch".into(),
        ))
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        ExplicitInsecureVerifier.verify_tls12_signature(message, certificate, signature)
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        ExplicitInsecureVerifier.verify_tls13_signature(message, certificate, signature)
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        ExplicitInsecureVerifier.supported_verify_schemes()
    }
}

pub(crate) fn load_truststore(sources: &[String]) -> Result<RootCertStore, TransitError> {
    let mut roots = RootCertStore::empty();
    for source in sources {
        if source == "system" {
            let system_roots = validate_system_roots(rustls_native_certs::load_native_certs())?;
            roots.roots.extend(system_roots.roots);
            continue;
        }
        let path = Path::new(source);
        let metadata = fs::symlink_metadata(path)
            .map_err(|_| TransitError::Unsupported("TLS truststore source is unreadable".into()))?;
        let target = if metadata.file_type().is_symlink() {
            let target = fs::canonicalize(path).map_err(|_| {
                TransitError::Unsupported("TLS truststore symlink target is invalid".into())
            })?;
            let target_metadata = fs::metadata(&target).map_err(|_| {
                TransitError::Unsupported("TLS truststore symlink target is unreadable".into())
            })?;
            if !target_metadata.is_file() {
                return Err(TransitError::Unsupported(
                    "TLS truststore symlink target is not a regular file".into(),
                ));
            }
            target
        } else {
            if !metadata.is_file() {
                return Err(TransitError::Unsupported(
                    "TLS truststore source is not a regular file".into(),
                ));
            }
            path.to_owned()
        };
        let metadata = fs::metadata(&target)
            .map_err(|_| TransitError::Unsupported("TLS truststore source is unreadable".into()))?;
        if metadata.len() > MAX_TRUSTSTORE_SOURCE_BYTES {
            return Err(TransitError::Unsupported(
                "TLS truststore source exceeds the size limit".into(),
            ));
        }
        let bytes = fs::read(&target)
            .map_err(|_| TransitError::Unsupported("TLS truststore source is unreadable".into()))?;
        let pem = CertificateDer::pem_slice_iter(&bytes).collect::<Result<Vec<_>, _>>();
        let certificates = match pem {
            Ok(certificates) if !certificates.is_empty() => certificates,
            Ok(_) if bytes.starts_with(b"-----BEGIN") => {
                return Err(TransitError::Unsupported(
                    "TLS truststore PEM contains no certificates".into(),
                ));
            }
            Err(_) if bytes.starts_with(b"-----BEGIN") => {
                return Err(TransitError::Unsupported(
                    "TLS truststore PEM is invalid".into(),
                ));
            }
            _ => vec![CertificateDer::from(bytes)],
        };
        for certificate in certificates {
            roots.add(certificate).map_err(|_| {
                TransitError::Unsupported("TLS truststore certificate is invalid".into())
            })?;
        }
    }
    Ok(roots)
}

fn validate_system_roots(
    loaded: rustls_native_certs::CertificateResult,
) -> Result<RootCertStore, TransitError> {
    if !loaded.errors.is_empty() || loaded.certs.is_empty() {
        return Err(TransitError::Unsupported(
            "system TLS root store is empty, unreadable, or invalid".into(),
        ));
    }
    let mut roots = RootCertStore::empty();
    for certificate in loaded.certs {
        roots.add(certificate).map_err(|_| {
            TransitError::Unsupported(
                "system TLS root store contains an invalid certificate".into(),
            )
        })?;
    }
    Ok(roots)
}

fn certificates(values: &[String]) -> Result<Vec<CertificateDer<'static>>, TransitError> {
    let mut parsed = Vec::new();
    for pem in values {
        let certificates = CertificateDer::pem_slice_iter(pem.as_bytes())
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| TransitError::Unsupported("TLS certificate PEM is invalid".into()))?;
        if certificates.is_empty() {
            return Err(TransitError::Unsupported(
                "TLS certificate PEM contains no certificates".into(),
            ));
        }
        parsed.extend(certificates);
    }
    Ok(parsed)
}

#[derive(Debug)]
struct ExplicitInsecureVerifier;

impl ServerCertVerifier for ExplicitInsecureVerifier {
    fn verify_server_cert(
        &self,
        _end: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
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
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
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

pub(crate) fn server_name(
    host: &str,
    options: Option<&TransitTls>,
) -> Result<ServerName<'static>, TransitError> {
    ServerName::try_from(
        options
            .and_then(|tls| tls.server_name.as_deref())
            .unwrap_or(host)
            .to_owned(),
    )
    .map_err(|_| TransitError::Unsupported("proxy TLS server name is invalid".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fingerprint(certificate: &CertificateDer<'_>) -> String {
        Sha256::digest(certificate.as_ref())
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }

    fn ca_params(name: &str) -> rcgen::CertificateParams {
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, name);
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::DigitalSignature,
        ];
        params
    }

    fn chain() -> (rcgen::Certificate, rcgen::Certificate, rcgen::Certificate) {
        let root = rcgen::CertifiedIssuer::self_signed(
            ca_params("root"),
            rcgen::KeyPair::generate().unwrap(),
        )
        .unwrap();
        let intermediate = rcgen::CertifiedIssuer::signed_by(
            ca_params("intermediate"),
            rcgen::KeyPair::generate().unwrap(),
            &root,
        )
        .unwrap();
        let leaf = rcgen::CertificateParams::new(vec!["pin.test".into()])
            .unwrap()
            .signed_by(&rcgen::KeyPair::generate().unwrap(), &intermediate)
            .unwrap();
        // Re-sign copies solely to return owned certificates from the issuer wrappers.
        (leaf, intermediate.as_ref().clone(), root.as_ref().clone())
    }

    #[test]
    fn certificate_pin_normalization_is_strict() {
        let plain = "ab".repeat(32);
        let colon = vec!["AB"; 32].join(":");
        assert_eq!(
            parse_certificate_pin(&plain).unwrap(),
            parse_certificate_pin(&colon).unwrap()
        );
        for bad in [
            "",
            "0",
            "g0",
            "ab:cd",
            "ab::cd",
            &"ab".repeat(31),
            &"ab".repeat(33),
        ] {
            assert!(parse_certificate_pin(bad).is_err());
        }
    }

    #[test]
    fn tls_profile_rejects_unknown_names_before_connecting() {
        let base = Arc::new(
            client_builder()
                .with_root_certificates(RootCertStore::empty())
                .with_no_client_auth(),
        );
        let options = TransitTls {
            enabled: true,
            truststore: Vec::new(),
            fingerprint: Some("unknown".into()),
            ..Default::default()
        };
        assert!(matches!(
            configure(base, Some(&options), None),
            Err(TransitError::Unsupported(_))
        ));
    }

    #[test]
    fn certificate_pin_accepts_leaf_or_valid_chain_and_rejects_mismatch_and_wrong_name() {
        let (leaf, intermediate, root) = chain();
        let name = ServerName::try_from("pin.test").unwrap();
        let wrong_name = ServerName::try_from("wrong.test").unwrap();
        let now = UnixTime::now();
        let chain = [intermediate.der().clone(), root.der().clone()];
        let leaf_verifier = CertificatePinVerifier {
            digest: parse_certificate_pin(&fingerprint(leaf.der())).unwrap(),
        };
        assert!(
            leaf_verifier
                .verify_server_cert(leaf.der(), &chain, &wrong_name, &[], now)
                .is_ok()
        );
        for pinned in [intermediate.der(), root.der()] {
            let verifier = CertificatePinVerifier {
                digest: parse_certificate_pin(&fingerprint(pinned)).unwrap(),
            };
            assert!(
                verifier
                    .verify_server_cert(leaf.der(), &chain, &name, &[], now)
                    .is_ok()
            );
            assert!(
                verifier
                    .verify_server_cert(leaf.der(), &chain, &wrong_name, &[], now)
                    .is_err()
            );
            assert!(
                verifier
                    .verify_server_cert(leaf.der(), &[], &name, &[], now)
                    .is_err()
            );
        }
        let mismatch = CertificatePinVerifier { digest: [0; 32] };
        assert!(
            mismatch
                .verify_server_cert(leaf.der(), &chain, &name, &[], now)
                .is_err()
        );
    }

    #[tokio::test]
    async fn configured_pin_is_enforced_even_with_insecure_and_real_tls() {
        use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
        use tokio::net::{TcpListener, TcpStream};
        use tokio_rustls::{TlsAcceptor, TlsConnector};

        let rcgen::CertifiedKey { cert, signing_key } =
            rcgen::generate_simple_self_signed(vec!["pin.test".into()]).unwrap();
        let server = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.der().clone()],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(signing_key.serialize_der())),
        )
        .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let acceptor = TlsAcceptor::from(Arc::new(server));
            for _ in 0..6 {
                let (stream, _) = listener.accept().await.unwrap();
                let _ = acceptor.accept(stream).await;
            }
        });
        let base = Arc::new(
            client_builder()
                .with_root_certificates(RootCertStore::empty())
                .with_no_client_auth(),
        );
        for (pin, profile, expected) in [
            (Some(fingerprint(cert.der())), None, true),
            (Some("00".repeat(32)), None, false),
            (None, None, true),
            (Some(fingerprint(cert.der())), Some("chrome"), true),
            (Some(fingerprint(cert.der())), Some("ios"), true),
            (Some(fingerprint(cert.der())), Some("safari"), true),
        ] {
            let options = TransitTls {
                enabled: true,
                insecure: true,
                truststore: Vec::new(),
                certificate_sha256: pin,
                fingerprint: profile.map(str::to_owned),
                ..Default::default()
            };
            let client = configure(Arc::clone(&base), Some(&options), None).unwrap();
            let socket = TcpStream::connect(address).await.unwrap();
            let result = TlsConnector::from(client)
                .connect(ServerName::try_from("pin.test").unwrap(), socket)
                .await;
            assert_eq!(result.is_ok(), expected);
        }
        task.await.unwrap();
    }

    #[tokio::test]
    async fn certificate_pinning_preserves_client_certificate_authentication() {
        use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
        use std::collections::BTreeMap;
        use tokio::net::{TcpListener, TcpStream};
        use tokio_rustls::{TlsAcceptor, TlsConnector};

        let server_key = rcgen::generate_simple_self_signed(vec!["pin.test".into()]).unwrap();
        let issuer = rcgen::CertifiedIssuer::self_signed(
            ca_params("client-ca"),
            rcgen::KeyPair::generate().unwrap(),
        )
        .unwrap();
        let client_key = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::new(vec!["client.test".into()]).unwrap();
        params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ClientAuth];
        let client_certificate = params.signed_by(&client_key, &issuer).unwrap();
        let mut roots = RootCertStore::empty();
        roots.add(issuer.der().clone()).unwrap();
        let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
            Arc::new(roots),
            Arc::new(rustls::crypto::aws_lc_rs::default_provider()),
        )
        .build()
        .unwrap();
        let server = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_client_cert_verifier(verifier)
        .with_single_cert(
            vec![server_key.cert.der().clone()],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                server_key.signing_key.serialize_der(),
            )),
        )
        .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let tls = TlsAcceptor::from(Arc::new(server))
                .accept(stream)
                .await
                .unwrap();
            assert_eq!(tls.get_ref().1.peer_certificates().unwrap().len(), 1);
        });
        let options = TransitTls {
            enabled: true,
            insecure: true,
            truststore: Vec::new(),
            certificate_sha256: Some(fingerprint(server_key.cert.der())),
            fingerprint: Some("chrome".into()),
            client_certificate: vec![client_certificate.pem()],
            client_key_field: Some("client_key".into()),
            ..Default::default()
        };
        let credential = TransitCredential::new(BTreeMap::from([(
            "client_key".into(),
            client_key.serialize_pem(),
        )]));
        let base = Arc::new(
            client_builder()
                .with_root_certificates(RootCertStore::empty())
                .with_no_client_auth(),
        );
        let client = configure(base, Some(&options), Some(&credential)).unwrap();
        TlsConnector::from(client)
            .connect(
                ServerName::try_from("pin.test").unwrap(),
                TcpStream::connect(address).await.unwrap(),
            )
            .await
            .unwrap();
        task.await.unwrap();
    }

    fn temp_path(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("pathchord-tls-{name}-{}", std::process::id()))
    }

    #[test]
    fn empty_truststore_is_an_empty_root_set() {
        assert!(load_truststore(&[]).unwrap().is_empty());
    }

    #[test]
    fn invalid_truststore_source_fails_closed() {
        let path = temp_path("invalid");
        std::fs::write(&path, b"not a certificate").unwrap();
        let result = load_truststore(&[path.to_string_lossy().into_owned()]);
        let _ = std::fs::remove_file(path);
        assert!(result.is_err());
    }

    #[test]
    fn system_root_load_errors_reject_even_with_a_valid_certificate() {
        let cert = rcgen::generate_simple_self_signed(vec!["root.test".into()]).unwrap();
        let mut loaded = rustls_native_certs::CertificateResult::default();
        loaded.certs.push(cert.cert.der().clone());
        loaded.errors.push(rustls_native_certs::Error {
            context: "test system root load",
            kind: rustls_native_certs::ErrorKind::Os(
                std::io::Error::from(std::io::ErrorKind::PermissionDenied).into(),
            ),
        });
        assert!(matches!(
            validate_system_roots(loaded),
            Err(TransitError::Unsupported(_))
        ));
    }

    #[cfg(unix)]
    #[test]
    fn symlink_to_a_directory_is_rejected() {
        let directory = temp_path("directory");
        let link = temp_path("directory-link");
        std::fs::create_dir_all(&directory).unwrap();
        std::os::unix::fs::symlink(&directory, &link).unwrap();
        let result = load_truststore(&[link.to_string_lossy().into_owned()]);
        let _ = std::fs::remove_file(link);
        let _ = std::fs::remove_dir(directory);
        assert!(result.is_err());
    }
}
