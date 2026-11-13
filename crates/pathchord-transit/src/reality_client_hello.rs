//! Bounded REALITY ClientHello proof patch seam.
//!
//! Rustls 0.23 does not expose the private ClientHello callback required by
//! REALITY. This module keeps the exact wire operation isolated: validate a
//! serialized TLS ClientHello, zero the 32-byte legacy session-id field for
//! AAD, encrypt the REALITY Session ID proof, and return the patched bytes.
//! It is intentionally not connected to a socket or registered as an adapter.

use crate::reality_codec::{
    RealityCodecError, RealitySessionId, derive_auth_key, encrypt_session_id,
};

const TLS_HANDSHAKE_RECORD: u8 = 0x16;
const CLIENT_HELLO: u8 = 0x01;
const SESSION_ID_LENGTH_OFFSET: usize = 38;
const SESSION_ID_OFFSET: usize = 39;
const SESSION_ID_LENGTH: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RealityClientHelloError {
    Malformed,
    Codec(RealityCodecError),
}

impl std::fmt::Display for RealityClientHelloError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Malformed => formatter.write_str("malformed TLS ClientHello for REALITY proof"),
            Self::Codec(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for RealityClientHelloError {}

impl From<RealityCodecError> for RealityClientHelloError {
    fn from(error: RealityCodecError) -> Self {
        Self::Codec(error)
    }
}

pub fn patch_session_id(
    client_hello: &[u8],
    client_secret: [u8; 32],
    server_public_key: [u8; 32],
    session_id: RealitySessionId,
) -> Result<Vec<u8>, RealityClientHelloError> {
    validate_client_hello(client_hello)?;
    let random = &client_hello[11..43];
    let auth_key = derive_auth_key(client_secret, server_public_key, random)?;
    let mut aad = client_hello.to_vec();
    aad[SESSION_ID_OFFSET..SESSION_ID_OFFSET + SESSION_ID_LENGTH].fill(0);
    let encrypted = encrypt_session_id(session_id, auth_key, random, &aad)?;
    let mut patched = client_hello.to_vec();
    patched[SESSION_ID_OFFSET..SESSION_ID_OFFSET + SESSION_ID_LENGTH].copy_from_slice(&encrypted);
    Ok(patched)
}

fn validate_client_hello(bytes: &[u8]) -> Result<(), RealityClientHelloError> {
    if bytes.len() < SESSION_ID_OFFSET + SESSION_ID_LENGTH
        || bytes[0] != TLS_HANDSHAKE_RECORD
        || bytes[5] != CLIENT_HELLO
        || bytes[38] != SESSION_ID_LENGTH as u8
    {
        return Err(RealityClientHelloError::Malformed);
    }
    let record_length = u16::from_be_bytes([bytes[3], bytes[4]]) as usize;
    let handshake_length =
        (usize::from(bytes[6]) << 16) | (usize::from(bytes[7]) << 8) | usize::from(bytes[8]);
    if record_length + 5 > bytes.len() || handshake_length + 4 > record_length {
        return Err(RealityClientHelloError::Malformed);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hello() -> Vec<u8> {
        let mut bytes = vec![0_u8; 5 + 4 + 2 + 32 + 1 + 32 + 2];
        bytes[0] = TLS_HANDSHAKE_RECORD;
        bytes[1] = 3;
        bytes[2] = 3;
        let record_length = (bytes.len() - 5) as u16;
        bytes[3..5].copy_from_slice(&record_length.to_be_bytes());
        bytes[5] = CLIENT_HELLO;
        let handshake_length = (bytes.len() - 9) as u32;
        bytes[6] = (handshake_length >> 16) as u8;
        bytes[7] = (handshake_length >> 8) as u8;
        bytes[8] = handshake_length as u8;
        bytes[9] = 3;
        bytes[10] = 3;
        for (index, byte) in bytes[11..43].iter_mut().enumerate() {
            *byte = index as u8;
        }
        bytes[SESSION_ID_LENGTH_OFFSET] = SESSION_ID_LENGTH as u8;
        bytes[43..75].fill(0xaa);
        bytes
    }

    #[test]
    fn proof_patch_preserves_length_and_changes_only_session_id() {
        let hello = hello();
        let patched = patch_session_id(
            &hello,
            [1; 32],
            client_ephemeral_public([2; 32]),
            RealitySessionId {
                version: [1, 8, 1],
                timestamp: 1,
                short_id: [3; 8],
            },
        )
        .unwrap();
        assert_eq!(patched.len(), hello.len());
        assert_eq!(&patched[..SESSION_ID_OFFSET], &hello[..SESSION_ID_OFFSET]);
        assert_ne!(
            &patched[SESSION_ID_OFFSET..SESSION_ID_OFFSET + SESSION_ID_LENGTH],
            &hello[SESSION_ID_OFFSET..SESSION_ID_OFFSET + SESSION_ID_LENGTH]
        );
        assert_eq!(
            &patched[SESSION_ID_OFFSET + SESSION_ID_LENGTH..],
            &hello[SESSION_ID_OFFSET + SESSION_ID_LENGTH..]
        );
    }

    #[test]
    fn malformed_hello_is_rejected_before_crypto() {
        assert_eq!(
            patch_session_id(
                &[0; 80],
                [1; 32],
                [2; 32],
                RealitySessionId {
                    version: [1, 8, 1],
                    timestamp: 1,
                    short_id: [0; 8],
                }
            ),
            Err(RealityClientHelloError::Malformed)
        );
    }

    fn client_ephemeral_public(secret: [u8; 32]) -> [u8; 32] {
        crate::reality_codec::client_ephemeral_public(secret)
    }
}
