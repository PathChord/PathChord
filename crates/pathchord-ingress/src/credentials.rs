//! Listener-local credential verification boundaries.

use std::sync::Arc;

use async_trait::async_trait;
use pathchord_policy::{AuthenticationMode, ListenerConfig};
use subtle::{Choice, ConstantTimeEq};
use zeroize::Zeroizing;

#[async_trait]
pub trait ListenerCredentialVerifier: std::fmt::Debug + Send + Sync {
    async fn verify(&self, username: &str, password: &[u8]) -> bool;
}

#[derive(Debug, Default)]
pub struct RejectListenerCredentials;

#[async_trait]
impl ListenerCredentialVerifier for RejectListenerCredentials {
    async fn verify(&self, _username: &str, _password: &[u8]) -> bool {
        false
    }
}

/// One listener-local username/password pair resolved from an opaque secret
/// reference. Secret values are redacted from `Debug` and zeroized on drop.
pub struct StaticListenerCredentialVerifier {
    username: Zeroizing<Vec<u8>>,
    password: Zeroizing<Vec<u8>>,
}

impl StaticListenerCredentialVerifier {
    #[must_use]
    pub fn new(username: impl AsRef<[u8]>, password: impl AsRef<[u8]>) -> Self {
        Self {
            username: Zeroizing::new(username.as_ref().to_vec()),
            password: Zeroizing::new(password.as_ref().to_vec()),
        }
    }
}

impl std::fmt::Debug for StaticListenerCredentialVerifier {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("StaticListenerCredentialVerifier")
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl ListenerCredentialVerifier for StaticListenerCredentialVerifier {
    async fn verify(&self, username: &str, password: &[u8]) -> bool {
        constant_time_eq(&self.username, username.as_bytes())
            & constant_time_eq(&self.password, password)
    }
}

fn constant_time_eq(expected: &[u8], supplied: &[u8]) -> bool {
    let length = expected.len().max(supplied.len());
    let mut difference = 0_u8;
    for index in 0..length {
        let expected = expected.get(index).copied().unwrap_or_default();
        let supplied = supplied.get(index).copied().unwrap_or_default();
        difference |= expected ^ supplied;
    }
    let lengths_match: Choice = expected.len().ct_eq(&supplied.len());
    bool::from(lengths_match & difference.ct_eq(&0))
}

#[derive(Debug, Clone, Copy, thiserror::Error, PartialEq, Eq)]
pub enum ListenerCredentialError {
    #[error("listener credential reference is unavailable")]
    Unavailable,
    #[error("listener credential document is invalid")]
    Invalid,
    #[error("listener credential provider failed")]
    Provider,
}

#[async_trait]
pub trait ListenerCredentialVerifierFactory: std::fmt::Debug + Send + Sync {
    async fn verifier_for(
        &self,
        listener: &ListenerConfig,
    ) -> Result<Arc<dyn ListenerCredentialVerifier>, ListenerCredentialError>;
}

/// Default factory for embedders that have not configured a local secret
/// provider. Disabled listeners remain usable; required listeners fail startup.
#[derive(Debug, Default)]
pub struct UnavailableListenerCredentialFactory;

#[async_trait]
impl ListenerCredentialVerifierFactory for UnavailableListenerCredentialFactory {
    async fn verifier_for(
        &self,
        listener: &ListenerConfig,
    ) -> Result<Arc<dyn ListenerCredentialVerifier>, ListenerCredentialError> {
        if listener.authentication == AuthenticationMode::Required {
            Err(ListenerCredentialError::Unavailable)
        } else {
            Ok(Arc::new(RejectListenerCredentials))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn static_verifier_matches_both_fields_and_redacts_debug() {
        let verifier = StaticListenerCredentialVerifier::new("alice", b"secret");
        assert!(verifier.verify("alice", b"secret").await);
        assert!(!verifier.verify("alice", b"wrong").await);
        assert!(!verifier.verify("other", b"secret").await);
        let debug = format!("{verifier:?}");
        assert!(!debug.contains("alice"));
        assert!(!debug.contains("secret"));
    }

    #[test]
    fn constant_time_comparison_rejects_prefixes_and_length_mismatches() {
        assert!(constant_time_eq(b"same", b"same"));
        assert!(!constant_time_eq(b"same", b"sam"));
        assert!(!constant_time_eq(b"sam", b"same"));
        assert!(!constant_time_eq(b"same", b"some"));
    }
}
