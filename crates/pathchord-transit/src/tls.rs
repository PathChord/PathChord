//! TLS options for native proxy transports. Unsupported extensions never downgrade.

use std::sync::Arc;

use pathchord_policy::TransitTls;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme};

use crate::{TransitCredential, TransitError};

pub(crate) fn configure(
    base: Arc<ClientConfig>,
    options: Option<&TransitTls>,
    credential: Option<&TransitCredential>,
) -> Result<Arc<ClientConfig>, TransitError> {
    let Some(options) = options else {
        return Ok(base);
    };
    if !options.enabled {
        return Err(TransitError::Unsupported(
            "TLS options must enable TLS".into(),
        ));
    }
    if options.fingerprint.is_some() || options.reality.is_some() {
        return Err(TransitError::Unsupported(
            "TLS fingerprint and Reality require the configured outbound engine".into(),
        ));
    }
    let mut config = if options.certificate.is_empty()
        && options.client_certificate.is_empty()
        && options.client_key_field.is_none()
    {
        (*base).clone()
    } else {
        let mut roots = RootCertStore::empty();
        for certificate in rustls_native_certs::load_native_certs().certs {
            let _ = roots.add(certificate);
        }
        for certificate in certificates(&options.certificate)? {
            roots
                .add(certificate)
                .map_err(|_| TransitError::Unsupported("TLS CA certificate is invalid".into()))?;
        }
        let builder = ClientConfig::builder().with_root_certificates(roots);
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
