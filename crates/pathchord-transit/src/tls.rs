//! TLS options for native proxy transports. Unsupported extensions never downgrade.

use std::fs;
use std::path::Path;
use std::sync::Arc;

use pathchord_policy::TransitTls;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme};

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
    if options.fingerprint.is_some() || options.reality.is_some() {
        return Err(TransitError::Unsupported(
            "TLS fingerprint and Reality require a native Reality adapter".into(),
        ));
    }
    let mut roots = truststore(&options.truststore)?;
    let mut config = {
        for certificate in certificates(&options.certificate)? {
            roots
                .add(certificate)
                .map_err(|_| TransitError::Unsupported("TLS CA certificate is invalid".into()))?;
        }
        let builder = client_builder().with_root_certificates(roots);
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
    if options.insecure {
        config
            .dangerous()
            .set_certificate_verifier(Arc::new(ExplicitInsecureVerifier));
    }
    Ok(Arc::new(config))
}

fn truststore(sources: &[String]) -> Result<RootCertStore, TransitError> {
    let mut roots = RootCertStore::empty();
    for source in sources {
        if source == "system" {
            for certificate in rustls_native_certs::load_native_certs().certs {
                roots
                    .add(certificate)
                    .map_err(|_| TransitError::Unsupported("system TLS root is invalid".into()))?;
            }
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

    fn temp_path(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("pathchord-tls-{name}-{}", std::process::id()))
    }

    #[test]
    fn empty_truststore_is_an_empty_root_set() {
        assert!(truststore(&[]).unwrap().is_empty());
    }

    #[test]
    fn invalid_truststore_source_fails_closed() {
        let path = temp_path("invalid");
        std::fs::write(&path, b"not a certificate").unwrap();
        let result = truststore(&[path.to_string_lossy().into_owned()]);
        let _ = std::fs::remove_file(path);
        assert!(result.is_err());
    }

    #[cfg(unix)]
    #[test]
    fn symlink_to_a_directory_is_rejected() {
        let directory = temp_path("directory");
        let link = temp_path("directory-link");
        std::fs::create_dir_all(&directory).unwrap();
        std::os::unix::fs::symlink(&directory, &link).unwrap();
        let result = truststore(&[link.to_string_lossy().into_owned()]);
        let _ = std::fs::remove_file(link);
        let _ = std::fs::remove_dir(directory);
        assert!(result.is_err());
    }
}
