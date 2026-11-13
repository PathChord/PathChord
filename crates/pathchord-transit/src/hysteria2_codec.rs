//! Pure Rust Hysteria2 wire primitives.
//!
//! This module deliberately stops at the protocol layer. It does not own a
//! QUIC socket, TLS configuration, HTTP/3 connection, or proxy session. Those
//! pieces will be added to a native adapter only after an independent
//! Hysteria2 interoperability fixture exists.

use blake2::Blake2bVar;
use blake2::digest::{Update, VariableOutput};

pub const FRAME_TYPE_TCP_REQUEST: u64 = 0x401;
pub const MAX_ADDRESS_LENGTH: usize = 2048;
pub const MAX_MESSAGE_LENGTH: usize = 2048;
pub const MAX_PADDING_LENGTH: usize = 4096;
pub const MAX_UDP_PAYLOAD: usize = 4096;
pub const AUTH_PADDING_MIN: usize = 256;
pub const AUTH_PADDING_MAX: usize = 2048;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthHeaders {
    pub password: String,
    pub receive_bps: u64,
    pub padding: String,
}

impl AuthHeaders {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.password.is_empty() || self.password.len() > 1024 {
            return Err("Hysteria2 password length is invalid");
        }
        if self.padding.len() < AUTH_PADDING_MIN || self.padding.len() > AUTH_PADDING_MAX {
            return Err("Hysteria2 authentication padding length is invalid");
        }
        if !self
            .padding
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric())
        {
            return Err("Hysteria2 authentication padding contains invalid bytes");
        }
        Ok(())
    }

    pub fn fields(&self) -> Result<[(String, String); 3], &'static str> {
        self.validate()?;
        Ok([
            ("hysteria-auth".to_owned(), self.password.clone()),
            ("hysteria-cc-rx".to_owned(), self.receive_bps.to_string()),
            ("hysteria-padding".to_owned(), self.padding.clone()),
        ])
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UdpMessage {
    pub session_id: u32,
    pub packet_id: u16,
    pub fragment_id: u8,
    pub fragment_count: u8,
    pub address: String,
    pub payload: Vec<u8>,
}

pub fn encode_tcp_request(address: &str, payload: &[u8]) -> Result<Vec<u8>, &'static str> {
    validate_address(address)?;
    let mut output = Vec::new();
    put_varint(FRAME_TYPE_TCP_REQUEST, &mut output)?;
    put_varint(address.len() as u64, &mut output)?;
    output.extend_from_slice(address.as_bytes());
    put_varint(0, &mut output)?;
    output.extend_from_slice(payload);
    Ok(output)
}

pub fn parse_tcp_response(input: &[u8]) -> Result<Option<usize>, String> {
    let Some(&status) = input.first() else {
        return Ok(None);
    };
    let mut position = 1;
    let Some((message_length, consumed)) = read_varint_partial(&input[position..]) else {
        return Ok(None);
    };
    position += consumed;
    let message_length = usize::try_from(message_length)
        .map_err(|_| "Hysteria2 TCP response message length overflow".to_owned())?;
    if message_length > MAX_MESSAGE_LENGTH {
        return Err("Hysteria2 TCP response message is too large".to_owned());
    }
    let message_end = position
        .checked_add(message_length)
        .ok_or_else(|| "Hysteria2 TCP response length overflow".to_owned())?;
    if input.len() < message_end {
        return Ok(None);
    }
    let message = &input[position..message_end];
    position = message_end;
    let Some((padding_length, consumed)) = read_varint_partial(&input[position..]) else {
        return Ok(None);
    };
    position += consumed;
    let padding_length = usize::try_from(padding_length)
        .map_err(|_| "Hysteria2 TCP response padding length overflow".to_owned())?;
    if padding_length > MAX_PADDING_LENGTH {
        return Err("Hysteria2 TCP response padding is too large".to_owned());
    }
    let end = position
        .checked_add(padding_length)
        .ok_or_else(|| "Hysteria2 TCP response length overflow".to_owned())?;
    if input.len() < end {
        return Ok(None);
    }
    match status {
        0 => Ok(Some(end)),
        1 => Err(format!(
            "Hysteria2 remote TCP error: {}",
            String::from_utf8_lossy(message)
        )),
        _ => Err("Hysteria2 TCP response status is invalid".to_owned()),
    }
}

pub fn encode_udp_message(message: &UdpMessage) -> Result<Vec<u8>, &'static str> {
    validate_address(&message.address)?;
    if message.payload.len() > MAX_UDP_PAYLOAD {
        return Err("Hysteria2 UDP payload is too large");
    }
    let mut output = Vec::with_capacity(8 + message.address.len() + message.payload.len());
    output.extend_from_slice(&message.session_id.to_be_bytes());
    output.extend_from_slice(&message.packet_id.to_be_bytes());
    output.push(message.fragment_id);
    output.push(message.fragment_count);
    put_varint(message.address.len() as u64, &mut output)?;
    output.extend_from_slice(message.address.as_bytes());
    output.extend_from_slice(&message.payload);
    Ok(output)
}

pub fn decode_udp_message(input: &[u8]) -> Result<UdpMessage, &'static str> {
    if input.len() < 9 {
        return Err("Hysteria2 UDP message is too short");
    }
    let session_id = u32::from_be_bytes(input[0..4].try_into().expect("fixed slice"));
    let packet_id = u16::from_be_bytes(input[4..6].try_into().expect("fixed slice"));
    let fragment_id = input[6];
    let fragment_count = input[7];
    let mut position = 8;
    let address_length = usize::try_from(read_varint(input, &mut position)?)
        .map_err(|_| "Hysteria2 UDP address length overflow")?;
    if address_length == 0 || address_length > MAX_ADDRESS_LENGTH {
        return Err("Hysteria2 UDP address length is invalid");
    }
    let address_end = position
        .checked_add(address_length)
        .ok_or("Hysteria2 UDP address length overflow")?;
    if address_end > input.len() {
        return Err("Hysteria2 UDP address is truncated");
    }
    let address = std::str::from_utf8(&input[position..address_end])
        .map_err(|_| "Hysteria2 UDP address is not UTF-8")?
        .to_owned();
    let payload = input[address_end..].to_vec();
    if payload.len() > MAX_UDP_PAYLOAD {
        return Err("Hysteria2 UDP payload is too large");
    }
    Ok(UdpMessage {
        session_id,
        packet_id,
        fragment_id,
        fragment_count,
        address,
        payload,
    })
}

pub fn salamander_xor(password: &[u8], packet: &[u8], salt: &[u8; 8]) -> Vec<u8> {
    let mut hasher = Blake2bVar::new(32).expect("valid BLAKE2b output length");
    hasher.update(password);
    hasher.update(salt);
    let mut key = [0_u8; 32];
    hasher
        .finalize_variable(&mut key)
        .expect("fixed BLAKE2b output length");
    packet
        .iter()
        .enumerate()
        .map(|(index, byte)| byte ^ key[index % key.len()])
        .collect()
}

pub fn salamander_encode(password: &[u8], packet: &[u8], salt: [u8; 8]) -> Vec<u8> {
    let mut output = Vec::with_capacity(8 + packet.len());
    output.extend_from_slice(&salt);
    output.extend_from_slice(&salamander_xor(password, packet, &salt));
    output
}

pub fn salamander_decode(password: &[u8], packet: &[u8]) -> Option<Vec<u8>> {
    if packet.len() <= 8 {
        return None;
    }
    let salt: [u8; 8] = packet[..8].try_into().ok()?;
    Some(salamander_xor(password, &packet[8..], &salt))
}

fn validate_address(address: &str) -> Result<(), &'static str> {
    if address.is_empty() || address.len() > MAX_ADDRESS_LENGTH {
        return Err("Hysteria2 address length is invalid");
    }
    if address.bytes().any(|byte| byte.is_ascii_control()) {
        return Err("Hysteria2 address contains control bytes");
    }
    Ok(())
}

fn read_varint_partial(input: &[u8]) -> Option<(u64, usize)> {
    let first = *input.first()?;
    let length = 1_usize << (first >> 6);
    if input.len() < length {
        return None;
    }
    let mut value = u64::from(first & 0x3f);
    for byte in &input[1..length] {
        value = (value << 8) | u64::from(*byte);
    }
    Some((value, length))
}

fn put_varint(value: u64, output: &mut Vec<u8>) -> Result<(), &'static str> {
    match value {
        0..=63 => output.push(value as u8),
        64..=16_383 => {
            output.push(((value >> 8) as u8) | 0x40);
            output.push(value as u8);
        }
        16_384..=1_073_741_823 => {
            output.push(((value >> 24) as u8) | 0x80);
            output.push((value >> 16) as u8);
            output.push((value >> 8) as u8);
            output.push(value as u8);
        }
        1_073_741_824..=4_611_686_018_427_387_903 => {
            output.push(((value >> 56) as u8) | 0xc0);
            output.push((value >> 48) as u8);
            output.push((value >> 40) as u8);
            output.push((value >> 32) as u8);
            output.push((value >> 24) as u8);
            output.push((value >> 16) as u8);
            output.push((value >> 8) as u8);
            output.push(value as u8);
        }
        _ => return Err("Hysteria2 QUIC varint overflow"),
    }
    Ok(())
}

fn read_varint(input: &[u8], position: &mut usize) -> Result<u64, &'static str> {
    let Some((value, length)) = read_varint_partial(&input[*position..]) else {
        return Err("Hysteria2 QUIC varint is truncated");
    };
    *position += length;
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quic_varint_boundaries_round_trip() {
        for value in [0, 63, 64, 16_383, 16_384, 1_073_741_823, 1_073_741_824] {
            let mut output = Vec::new();
            put_varint(value, &mut output).unwrap();
            let mut position = 0;
            assert_eq!(read_varint(&output, &mut position).unwrap(), value);
            assert_eq!(position, output.len());
        }
    }

    #[test]
    fn tcp_request_contains_frame_type_address_and_payload() {
        let output = encode_tcp_request("example.com:443", b"hello").unwrap();
        let mut position = 0;
        assert_eq!(
            read_varint(&output, &mut position).unwrap(),
            FRAME_TYPE_TCP_REQUEST
        );
        let address_len = read_varint(&output, &mut position).unwrap() as usize;
        assert_eq!(
            &output[position..position + address_len],
            b"example.com:443"
        );
        assert!(output.ends_with(b"hello"));
    }

    #[test]
    fn udp_message_round_trip_preserves_fragments_and_address() {
        let message = UdpMessage {
            session_id: 7,
            packet_id: 8,
            fragment_id: 1,
            fragment_count: 2,
            address: "example.com:443".into(),
            payload: b"datagram".to_vec(),
        };
        assert_eq!(
            decode_udp_message(&encode_udp_message(&message).unwrap()).unwrap(),
            message
        );
    }

    #[test]
    fn authentication_headers_and_padding_are_bounded() {
        let headers = AuthHeaders {
            password: "secret".into(),
            receive_bps: 1_000_000,
            padding: "a".repeat(AUTH_PADDING_MIN),
        };
        assert_eq!(headers.fields().unwrap()[1].1, "1000000");
        assert!(
            AuthHeaders {
                padding: "x".repeat(AUTH_PADDING_MIN - 1),
                ..headers
            }
            .validate()
            .is_err()
        );
    }

    #[test]
    fn salamander_round_trip_uses_the_wire_salt() {
        let salt = [7_u8; 8];
        let encoded = salamander_encode(b"secret", b"packet", salt);
        assert_eq!(salamander_decode(b"secret", &encoded).unwrap(), b"packet");
        assert_ne!(salamander_decode(b"wrong", &encoded).unwrap(), b"packet");
    }
}
