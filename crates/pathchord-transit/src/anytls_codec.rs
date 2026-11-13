//! Pure Rust AnyTLS authentication and frame codec.
//!
//! This is deliberately a protocol layer only. It does not pull in a proxy
//! runtime, TLS implementation, session pool, or backend process. A future
//! AnyTLS adapter can place it over the existing native TLS transport.

use bytes::{Buf, BufMut, Bytes, BytesMut};
use sha2::{Digest, Sha256};

pub const MAX_FRAME_PAYLOAD: usize = u16::MAX as usize;
pub const FRAME_HEADER_LEN: usize = 7;

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnyTlsCommand {
    Waste = 0,
    Syn = 1,
    Push = 2,
    Fin = 3,
    Settings = 4,
    Alert = 5,
    UpdatePaddingScheme = 6,
    SynAck = 7,
    HeartRequest = 8,
    HeartResponse = 9,
    ServerSettings = 10,
}

impl From<u8> for AnyTlsCommand {
    fn from(value: u8) -> Self {
        match value {
            1 => Self::Syn,
            2 => Self::Push,
            3 => Self::Fin,
            4 => Self::Settings,
            5 => Self::Alert,
            6 => Self::UpdatePaddingScheme,
            7 => Self::SynAck,
            8 => Self::HeartRequest,
            9 => Self::HeartResponse,
            10 => Self::ServerSettings,
            _ => Self::Waste,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnyTlsFrame {
    pub command: AnyTlsCommand,
    pub stream_id: u32,
    pub payload: Bytes,
}

impl AnyTlsFrame {
    pub fn encode(&self, output: &mut BytesMut) -> Result<(), &'static str> {
        if self.payload.len() > MAX_FRAME_PAYLOAD {
            return Err("AnyTLS frame payload exceeds u16 length");
        }
        output.reserve(FRAME_HEADER_LEN + self.payload.len());
        output.put_u8(self.command as u8);
        output.put_u32(self.stream_id);
        output.put_u16(self.payload.len() as u16);
        output.extend_from_slice(&self.payload);
        Ok(())
    }

    pub fn decode(input: &mut BytesMut) -> Result<Option<Self>, &'static str> {
        if input.len() < FRAME_HEADER_LEN {
            return Ok(None);
        }
        let payload_len = u16::from_be_bytes([input[5], input[6]]) as usize;
        let total = FRAME_HEADER_LEN
            .checked_add(payload_len)
            .ok_or("AnyTLS frame length overflow")?;
        if input.len() < total {
            return Ok(None);
        }
        let command = AnyTlsCommand::from(input[0]);
        let stream_id = u32::from_be_bytes([input[1], input[2], input[3], input[4]]);
        input.advance(FRAME_HEADER_LEN);
        let payload = input.split_to(payload_len).freeze();
        Ok(Some(Self {
            command,
            stream_id,
            payload,
        }))
    }
}

pub fn password_hash(password: &str) -> [u8; 32] {
    Sha256::digest(password.as_bytes()).into()
}

/// AnyTLS authentication is one contiguous record: SHA256(password), a
/// big-endian u16 padding length, and exactly that many padding bytes.
pub fn authentication_record(password: &str, padding: &[u8]) -> Result<Bytes, &'static str> {
    if padding.len() > MAX_FRAME_PAYLOAD {
        return Err("AnyTLS authentication padding exceeds u16 length");
    }
    let mut output = BytesMut::with_capacity(34 + padding.len());
    output.extend_from_slice(&password_hash(password));
    output.put_u16(padding.len() as u16);
    output.extend_from_slice(padding);
    Ok(output.freeze())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_round_trip_preserves_command_stream_and_payload() {
        let frame = AnyTlsFrame {
            command: AnyTlsCommand::Push,
            stream_id: 0x0102_0304,
            payload: Bytes::from_static(b"hello"),
        };
        let mut encoded = BytesMut::new();
        frame.encode(&mut encoded).unwrap();
        assert_eq!(AnyTlsFrame::decode(&mut encoded).unwrap(), Some(frame));
        assert!(encoded.is_empty());
    }

    #[test]
    fn decoder_waits_for_the_complete_bounded_frame() {
        let frame = AnyTlsFrame {
            command: AnyTlsCommand::Syn,
            stream_id: 7,
            payload: Bytes::from_static(b"destination"),
        };
        let mut encoded = BytesMut::new();
        frame.encode(&mut encoded).unwrap();
        let tail = encoded.split_off(3);
        assert_eq!(AnyTlsFrame::decode(&mut encoded).unwrap(), None);
        encoded.extend_from_slice(&tail);
        assert_eq!(AnyTlsFrame::decode(&mut encoded).unwrap(), Some(frame));
    }

    #[test]
    fn oversized_payload_is_rejected_before_output_mutation() {
        let mut output = BytesMut::from(&b"prefix"[..]);
        let frame = AnyTlsFrame {
            command: AnyTlsCommand::Push,
            stream_id: 1,
            payload: Bytes::from(vec![0; MAX_FRAME_PAYLOAD + 1]),
        };
        assert_eq!(
            frame.encode(&mut output),
            Err("AnyTLS frame payload exceeds u16 length")
        );
        assert_eq!(&output[..], b"prefix");
    }

    #[test]
    fn authentication_is_one_contiguous_record_with_bounded_padding() {
        let record = authentication_record("secret", b"pad").unwrap();
        assert_eq!(&record[..32], &password_hash("secret"));
        assert_eq!(&record[32..34], 3_u16.to_be_bytes());
        assert_eq!(&record[34..], b"pad");
        assert!(authentication_record("secret", &vec![0; MAX_FRAME_PAYLOAD + 1]).is_err());
    }
}
