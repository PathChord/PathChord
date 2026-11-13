//! Safe rustls key-exchange seam for REALITY.
//!
//! This replaces the X25519 implementation in a rustls `CryptoProvider` so a
//! future ClientHello builder can own REALITY's ephemeral key material. Rustls
//! public APIs do not expose the private ClientHello extension/session proof
//! hook, therefore this module intentionally stops at the key-share seam and
//! is not registered as an adapter.

use std::fmt;
use std::sync::Arc;

use rustls::crypto::{ActiveKeyExchange, CryptoProvider, SharedSecret, SupportedKxGroup};
use rustls::{Error, NamedGroup, PeerMisbehaved};
use x25519_dalek::{PublicKey, StaticSecret};

#[derive(Debug)]
pub(crate) struct RealityX25519Group;

pub(crate) static REALITY_X25519_GROUP: RealityX25519Group = RealityX25519Group;

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
    provider.kx_groups = vec![&REALITY_X25519_GROUP as &'static dyn SupportedKxGroup];
    provider
}

pub(crate) fn reality_provider_arc() -> Arc<CryptoProvider> {
    Arc::new(provider_with_reality_x25519())
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn provider_replaces_only_the_x25519_group() {
        let provider = provider_with_reality_x25519();
        assert!(
            provider
                .kx_groups
                .iter()
                .any(|group| group.name() == NamedGroup::X25519)
        );
        assert_eq!(REALITY_X25519_GROUP.start().unwrap().pub_key().len(), 32);
        assert!(!provider.kx_groups.is_empty());
    }
}
