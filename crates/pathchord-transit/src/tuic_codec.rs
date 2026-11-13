//! Pure Rust TUIC v5 command and address codec.
//!
//! TUIC normally carries these commands over QUIC streams/datagrams. This
//! module deliberately owns only bounded wire encoding and credential
//! validation; QUIC connection ownership, TLS exporter authentication, and
//! relay lifecycle remain outside until an independent interop fixture exists.

use bytes::{Buf, BufMut, Bytes, BytesMut};
use uuid::Uuid;

pub const TUIC_VERSION: u8 = 5;
pub const COMMAND_AUTHENTICATE: u8 = 0;
pub const COMMAND_CONNECT: u8 = 1;
pub const COMMAND_PACKET: u8 = 2;
pub const COMMAND_DISSOCIATE: u8 = 3;
pub const COMMAND_HEARTBEAT: u8 = 4;
pub const MAX_DOMAIN_BYTES: usize = 255;
pub const MAX_PACKET_BYTES: usize = u16::MAX as usize;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TuicCodecError {
    Truncated,
    InvalidVersion,
    InvalidCommand,
    InvalidAddress,
    InvalidPayload,
    InvalidCredentials,
    VarIntOverflow,
}

impl std::fmt::Display for TuicCodecError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Truncated => "truncated TUIC command",
            Self::InvalidVersion => "invalid TUIC version",
            Self::InvalidCommand => "invalid TUIC command",
            Self::InvalidAddress => "invalid TUIC address",
            Self::InvalidPayload => "invalid TUIC payload",
            Self::InvalidCredentials => "invalid TUIC credentials",
            Self::VarIntOverflow => "QUIC variable integer exceeds 62 bits",
        })
    }
}

impl std::error::Error for TuicCodecError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TuicAddress {
    None,
    Domain(String),
    Ipv4([u8; 4]),
    Ipv6([u8; 16]),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TuicEndpoint {
    pub address: TuicAddress,
    pub port: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TuicCredentials {
    pub uuid: [u8; 16],
    pub password: String,
}

impl TuicCredentials {
    pub fn parse(uuid: &str, password: &str) -> Result<Self, TuicCodecError> {
        if password.is_empty() || password.len() > 1024 {
            return Err(TuicCodecError::InvalidCredentials);
        }
        Ok(Self {
            uuid: *Uuid::parse_str(uuid)
                .map_err(|_| TuicCodecError::InvalidCredentials)?
                .as_bytes(),
            password: password.to_owned(),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TuicPacket {
    pub association_id: u16,
    pub packet_id: u16,
    pub fragment_total: u8,
    pub fragment_id: u8,
    pub endpoint: TuicEndpoint,
    pub payload: Bytes,
}

pub fn encode_quic_varint(value: u64, output: &mut BytesMut) -> Result<(), TuicCodecError> {
    if value >= (1_u64 << 62) {
        return Err(TuicCodecError::VarIntOverflow);
    }
    match value {
        0..=63 => output.put_u8(value as u8),
        64..=16_383 => output.put_u16((value as u16) | 0x4000),
        16_384..=1_073_741_823 => output.put_u32((value as u32) | 0x8000_0000),
        _ => output.put_u64(value | 0xc000_0000_0000_0000),
    }
    Ok(())
}

pub fn decode_quic_varint(input: &mut &[u8]) -> Result<u64, TuicCodecError> {
    let first = *input.first().ok_or(TuicCodecError::Truncated)?;
    let width = 1_usize << (first >> 6);
    if input.len() < width {
        return Err(TuicCodecError::Truncated);
    }
    let mut value = 0_u64;
    for byte in input.iter().take(width) {
        value = (value << 8) | u64::from(*byte);
    }
    *input = &input[width..];
    Ok(value & ((1_u64 << (width * 8 - 2)) - 1))
}

pub fn encode_authenticate(credentials: &TuicCredentials) -> Bytes {
    encode_authenticate_token(&credentials.uuid, &[0; 32])
}

pub fn encode_authenticate_token(uuid: &[u8; 16], token: &[u8; 32]) -> Bytes {
    let mut output = BytesMut::with_capacity(50);
    output.put_u8(TUIC_VERSION);
    output.put_u8(COMMAND_AUTHENTICATE);
    output.extend_from_slice(uuid);
    output.extend_from_slice(token);
    output.freeze()
}

pub fn encode_connect(endpoint: &TuicEndpoint) -> Result<Bytes, TuicCodecError> {
    let mut output = BytesMut::new();
    output.extend_from_slice(&[TUIC_VERSION, COMMAND_CONNECT]);
    encode_address(endpoint, &mut output)?;
    Ok(output.freeze())
}

pub fn encode_dissociate(association_id: u16) -> Bytes {
    let mut output = BytesMut::with_capacity(4);
    output.extend_from_slice(&[TUIC_VERSION, COMMAND_DISSOCIATE]);
    output.put_u16(association_id);
    output.freeze()
}

pub fn encode_heartbeat() -> Bytes {
    Bytes::from_static(&[TUIC_VERSION, COMMAND_HEARTBEAT])
}

pub fn encode_packet(packet: &TuicPacket) -> Result<Bytes, TuicCodecError> {
    if packet.fragment_total == 0 || packet.fragment_id >= packet.fragment_total {
        return Err(TuicCodecError::InvalidPayload);
    }
    if packet.payload.len() > MAX_PACKET_BYTES {
        return Err(TuicCodecError::InvalidPayload);
    }
    if packet.fragment_id == 0 && matches!(packet.endpoint.address, TuicAddress::None) {
        return Err(TuicCodecError::InvalidAddress);
    }
    let mut output = BytesMut::with_capacity(10 + packet.payload.len() + 260);
    output.extend_from_slice(&[TUIC_VERSION, COMMAND_PACKET]);
    output.put_u16(packet.association_id);
    output.put_u16(packet.packet_id);
    output.put_u8(packet.fragment_total);
    output.put_u8(packet.fragment_id);
    output.put_u16(packet.payload.len() as u16);
    encode_address(&packet.endpoint, &mut output)?;
    output.extend_from_slice(&packet.payload);
    Ok(output.freeze())
}

pub fn decode_packet(mut input: &[u8]) -> Result<TuicPacket, TuicCodecError> {
    if input.len() < 10 {
        return Err(TuicCodecError::Truncated);
    }
    if input.get_u8() != TUIC_VERSION {
        return Err(TuicCodecError::InvalidVersion);
    }
    if input.get_u8() != COMMAND_PACKET {
        return Err(TuicCodecError::InvalidCommand);
    }
    let association_id = input.get_u16();
    let packet_id = input.get_u16();
    let fragment_total = input.get_u8();
    let fragment_id = input.get_u8();
    let payload_len = input.get_u16() as usize;
    let endpoint = decode_address(&mut input)?;
    let packet = TuicPacket {
        association_id,
        packet_id,
        fragment_total,
        fragment_id,
        endpoint,
        payload: Bytes::new(),
    };
    if packet.fragment_total == 0 || packet.fragment_id >= packet.fragment_total {
        return Err(TuicCodecError::InvalidPayload);
    }
    if input.len() != payload_len {
        return Err(TuicCodecError::InvalidPayload);
    }
    let mut packet = packet;
    packet.payload = Bytes::copy_from_slice(input);
    if packet.fragment_id == 0 && matches!(packet.endpoint.address, TuicAddress::None) {
        return Err(TuicCodecError::InvalidAddress);
    }
    Ok(packet)
}

fn encode_address(endpoint: &TuicEndpoint, output: &mut BytesMut) -> Result<(), TuicCodecError> {
    match &endpoint.address {
        TuicAddress::None => output.put_u8(0xff),
        TuicAddress::Domain(domain) => {
            if domain.is_empty()
                || domain.len() > MAX_DOMAIN_BYTES
                || domain.bytes().any(|b| b.is_ascii_control())
            {
                return Err(TuicCodecError::InvalidAddress);
            }
            output.put_u8(0);
            output.put_u8(domain.len() as u8);
            output.extend_from_slice(domain.as_bytes());
        }
        TuicAddress::Ipv4(address) => {
            output.put_u8(1);
            output.extend_from_slice(address);
        }
        TuicAddress::Ipv6(address) => {
            output.put_u8(2);
            output.extend_from_slice(address);
        }
    }
    if !matches!(endpoint.address, TuicAddress::None) {
        output.put_u16(endpoint.port);
    }
    Ok(())
}

fn decode_address(input: &mut &[u8]) -> Result<TuicEndpoint, TuicCodecError> {
    let kind = input.first().copied().ok_or(TuicCodecError::Truncated)?;
    *input = &input[1..];
    let address = match kind {
        0xff => {
            return Ok(TuicEndpoint {
                address: TuicAddress::None,
                port: 0,
            });
        }
        0 => {
            let length = input.first().copied().ok_or(TuicCodecError::Truncated)? as usize;
            *input = &input[1..];
            if length == 0 || input.len() < length {
                return Err(TuicCodecError::InvalidAddress);
            }
            let domain = std::str::from_utf8(&input[..length])
                .map_err(|_| TuicCodecError::InvalidAddress)?
                .to_owned();
            *input = &input[length..];
            TuicAddress::Domain(domain)
        }
        1 => {
            if input.len() < 4 {
                return Err(TuicCodecError::Truncated);
            }
            let value: [u8; 4] = input[..4].try_into().unwrap();
            *input = &input[4..];
            TuicAddress::Ipv4(value)
        }
        2 => {
            if input.len() < 16 {
                return Err(TuicCodecError::Truncated);
            }
            let value: [u8; 16] = input[..16].try_into().unwrap();
            *input = &input[16..];
            TuicAddress::Ipv6(value)
        }
        _ => return Err(TuicCodecError::InvalidAddress),
    };
    if input.len() < 2 {
        return Err(TuicCodecError::Truncated);
    }
    let port = u16::from_be_bytes([input[0], input[1]]);
    *input = &input[2..];
    Ok(TuicEndpoint { address, port })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quic_varints_round_trip_boundaries() {
        for value in [
            0,
            63,
            64,
            16_383,
            16_384,
            1_073_741_823,
            1_073_741_824,
            (1_u64 << 62) - 1,
        ] {
            let mut encoded = BytesMut::new();
            encode_quic_varint(value, &mut encoded).unwrap();
            let mut slice = encoded.as_ref();
            assert_eq!(decode_quic_varint(&mut slice).unwrap(), value);
            assert!(slice.is_empty());
        }
        assert!(matches!(
            encode_quic_varint(1_u64 << 62, &mut BytesMut::new()),
            Err(TuicCodecError::VarIntOverflow)
        ));
    }

    #[test]
    fn auth_connect_and_address_commands_encode() {
        let credentials =
            TuicCredentials::parse("6cbf3f72-3417-4922-bde6-67820d041f25", "secret").unwrap();
        let auth = encode_authenticate(&credentials);
        assert_eq!(&auth[..2], &[5, 0]);
        assert_eq!(auth.len(), 50);
        let connect = encode_connect(&TuicEndpoint {
            address: TuicAddress::Domain("example.test".into()),
            port: 443,
        })
        .unwrap();
        assert_eq!(&connect[..2], &[5, 1]);
        assert!(connect.ends_with(&443_u16.to_be_bytes()));
    }

    #[test]
    fn packet_round_trip_supports_domain_and_none_fragment_address() {
        let packet = TuicPacket {
            association_id: 1,
            packet_id: 2,
            fragment_total: 1,
            fragment_id: 0,
            endpoint: TuicEndpoint {
                address: TuicAddress::Ipv4([192, 0, 2, 1]),
                port: 53,
            },
            payload: Bytes::from_static(b"dns"),
        };
        let encoded = encode_packet(&packet).unwrap();
        assert_eq!(decode_packet(&encoded).unwrap(), packet);
        let tail = TuicPacket {
            association_id: 1,
            packet_id: 2,
            fragment_total: 2,
            fragment_id: 1,
            endpoint: TuicEndpoint {
                address: TuicAddress::None,
                port: 0,
            },
            payload: Bytes::from_static(b"tail"),
        };
        assert!(encode_packet(&tail).is_ok());
    }

    #[test]
    fn packet_rejects_bad_fragments_and_bounds() {
        let bad = TuicPacket {
            association_id: 1,
            packet_id: 1,
            fragment_total: 1,
            fragment_id: 1,
            endpoint: TuicEndpoint {
                address: TuicAddress::None,
                port: 0,
            },
            payload: Bytes::new(),
        };
        assert!(matches!(
            encode_packet(&bad),
            Err(TuicCodecError::InvalidPayload)
        ));
        assert!(TuicCredentials::parse("bad", "secret").is_err());
    }
}
