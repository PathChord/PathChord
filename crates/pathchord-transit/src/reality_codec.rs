//! Pure Rust REALITY cryptographic/session codec.
//!
//! REALITY's custom TLS ClientHello and certificate verifier require a
//! rustls handshake seam that is deliberately kept separate from this
//! protocol layer. This module owns only bounded key parsing, X25519/HKDF
//! derivation, Session ID encoding, and the AES-GCM proof field. It is not
//! registered as an outbound adapter until a native TLS handshake fixture is
//! available.

use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use base64::Engine as _;
use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

const SESSION_ID_LEN: usize = 16;
const CLIENT_RANDOM_LEN: usize = 32;
const HKDF_SALT_LEN: usize = 20;
const PROOF_NONCE_LEN: usize = 12;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RealityConfig {
    pub server_public_key: [u8; 32],
    pub short_id: [u8; 8],
    pub short_id_len: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RealitySessionId {
    pub version: [u8; 3],
    pub timestamp: u32,
    pub short_id: [u8; 8],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RealityCodecError {
    InvalidPublicKey,
    InvalidShortId,
    InvalidSessionId,
    InvalidRandom,
    InvalidProof,
    KeyDerivation,
}

impl std::fmt::Display for RealityCodecError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::InvalidPublicKey => "REALITY public key must be 32-byte hex or base64",
            Self::InvalidShortId => "REALITY short ID must contain 0..=8 bytes",
            Self::InvalidSessionId => "REALITY Session ID must contain exactly 16 bytes",
            Self::InvalidRandom => "REALITY ClientHello random must contain 32 bytes",
            Self::InvalidProof => "REALITY proof authentication failed",
            Self::KeyDerivation => "REALITY key derivation failed",
        })
    }
}

impl std::error::Error for RealityCodecError {}

impl RealityConfig {
    pub fn parse(public_key: &str, short_id: &str) -> Result<Self, RealityCodecError> {
        let public_key = parse_public_key(public_key)?;
        let short = if short_id.is_empty() {
            Vec::new()
        } else {
            decode_hex(short_id).ok_or(RealityCodecError::InvalidShortId)?
        };
        if short.len() > 8 {
            return Err(RealityCodecError::InvalidShortId);
        }
        let mut short_id = [0_u8; 8];
        short_id[..short.len()].copy_from_slice(&short);
        Ok(Self {
            server_public_key: public_key,
            short_id,
            short_id_len: short.len() as u8,
        })
    }
}

impl RealitySessionId {
    pub fn encode(self) -> [u8; SESSION_ID_LEN] {
        let mut output = [0_u8; SESSION_ID_LEN];
        output[..3].copy_from_slice(&self.version);
        output[4..8].copy_from_slice(&self.timestamp.to_be_bytes());
        output[8..].copy_from_slice(&self.short_id);
        output
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, RealityCodecError> {
        if bytes.len() != SESSION_ID_LEN {
            return Err(RealityCodecError::InvalidSessionId);
        }
        let mut version = [0_u8; 3];
        version.copy_from_slice(&bytes[..3]);
        let mut short_id = [0_u8; 8];
        short_id.copy_from_slice(&bytes[8..]);
        Ok(Self {
            version,
            timestamp: u32::from_be_bytes(bytes[4..8].try_into().unwrap()),
            short_id,
        })
    }
}

pub fn client_ephemeral_public(secret: [u8; 32]) -> [u8; 32] {
    PublicKey::from(&StaticSecret::from(secret)).to_bytes()
}

pub fn derive_auth_key(
    client_secret: [u8; 32],
    server_public_key: [u8; 32],
    client_random: &[u8],
) -> Result<[u8; 32], RealityCodecError> {
    if client_random.len() != CLIENT_RANDOM_LEN {
        return Err(RealityCodecError::InvalidRandom);
    }
    let secret =
        StaticSecret::from(client_secret).diffie_hellman(&PublicKey::from(server_public_key));
    let hkdf = Hkdf::<Sha256>::new(Some(&client_random[..HKDF_SALT_LEN]), secret.as_bytes());
    let mut key = [0_u8; 32];
    hkdf.expand(b"REALITY", &mut key)
        .map_err(|_| RealityCodecError::KeyDerivation)?;
    Ok(key)
}

pub fn encrypt_session_id(
    session_id: RealitySessionId,
    auth_key: [u8; 32],
    client_random: &[u8],
    client_hello: &[u8],
) -> Result<[u8; 32], RealityCodecError> {
    let nonce = proof_nonce(client_random)?;
    let encrypted = Aes256Gcm::new_from_slice(&auth_key)
        .map_err(|_| RealityCodecError::KeyDerivation)?
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &session_id.encode(),
                aad: client_hello,
            },
        )
        .map_err(|_| RealityCodecError::InvalidProof)?;
    encrypted
        .try_into()
        .map_err(|_| RealityCodecError::InvalidProof)
}

pub fn decrypt_session_id(
    encrypted: [u8; 32],
    auth_key: [u8; 32],
    client_random: &[u8],
    client_hello: &[u8],
) -> Result<RealitySessionId, RealityCodecError> {
    let nonce = proof_nonce(client_random)?;
    let plain = Aes256Gcm::new_from_slice(&auth_key)
        .map_err(|_| RealityCodecError::KeyDerivation)?
        .decrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &encrypted,
                aad: client_hello,
            },
        )
        .map_err(|_| RealityCodecError::InvalidProof)?;
    RealitySessionId::decode(&plain)
}

fn proof_nonce(client_random: &[u8]) -> Result<[u8; PROOF_NONCE_LEN], RealityCodecError> {
    if client_random.len() != CLIENT_RANDOM_LEN {
        return Err(RealityCodecError::InvalidRandom);
    }
    Ok(client_random[20..].try_into().unwrap())
}

fn parse_public_key(value: &str) -> Result<[u8; 32], RealityCodecError> {
    if let Some(bytes) = decode_hex(value.strip_prefix("0x").unwrap_or(value))
        && bytes.len() == 32
    {
        return Ok(bytes.try_into().unwrap());
    }
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(value)
        .or_else(|_| base64::engine::general_purpose::STANDARD.decode(value))
        .map_err(|_| RealityCodecError::InvalidPublicKey)?;
    bytes
        .try_into()
        .map_err(|_| RealityCodecError::InvalidPublicKey)
}

fn decode_hex(value: &str) -> Option<Vec<u8>> {
    if value.is_empty()
        || !value.len().is_multiple_of(2)
        || !value.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return None;
    }
    let (pairs, remainder) = value.as_bytes().as_chunks::<2>();
    debug_assert!(remainder.is_empty());
    Some(
        pairs
            .iter()
            .map(|pair| (hex_value(pair[0]) << 4) | hex_value(pair[1]))
            .collect(),
    )
}

fn hex_value(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        b'A'..=b'F' => byte - b'A' + 10,
        _ => unreachable!(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_hex_and_base64_keys_and_bounded_short_ids() {
        let key = [7_u8; 32];
        let hex = key
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let base64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(key);
        assert_eq!(RealityConfig::parse(&base64, "").unwrap().short_id, [0; 8]);
        assert_eq!(RealityConfig::parse(&hex, "abcd").unwrap().short_id_len, 2);
        assert_eq!(
            RealityConfig::parse(&base64, "abcdef0123456789")
                .unwrap()
                .short_id_len,
            8
        );
        assert!(matches!(
            RealityConfig::parse(&hex, "abc"),
            Err(RealityCodecError::InvalidShortId)
        ));
    }

    #[test]
    fn x25519_and_hkdf_are_symmetric() {
        let a = [1_u8; 32];
        let b = [2_u8; 32];
        let shared_a = derive_auth_key(a, client_ephemeral_public(b), &[3_u8; 32]).unwrap();
        let shared_b = derive_auth_key(b, client_ephemeral_public(a), &[3_u8; 32]).unwrap();
        assert_eq!(shared_a, shared_b);
    }

    #[test]
    fn session_id_proof_round_trips_and_rejects_tampering() {
        let random = [9_u8; 32];
        let key =
            derive_auth_key([1_u8; 32], client_ephemeral_public([2_u8; 32]), &random).unwrap();
        let session = RealitySessionId {
            version: [1, 8, 1],
            timestamp: 1_735_000_000,
            short_id: [0xab; 8],
        };
        let hello = b"bounded-client-hello";
        let encrypted = encrypt_session_id(session, key, &random, hello).unwrap();
        assert_eq!(
            decrypt_session_id(encrypted, key, &random, hello).unwrap(),
            session
        );
        let mut changed = encrypted;
        changed[0] ^= 1;
        assert!(matches!(
            decrypt_session_id(changed, key, &random, hello),
            Err(RealityCodecError::InvalidProof)
        ));
    }
}
