//! Pure Rust AnyTLS authentication and frame codec.
//!
//! This is deliberately a protocol layer only. It does not pull in a proxy
//! runtime, TLS implementation, session pool, or backend process. A future
//! AnyTLS adapter can place it over the existing native TLS transport.

use std::collections::BTreeMap;

use bytes::{Buf, BufMut, Bytes, BytesMut};
use md5::Md5;
use sha2::{Digest, Sha256};

pub const MAX_FRAME_PAYLOAD: usize = u16::MAX as usize;
pub const FRAME_HEADER_LEN: usize = 7;
pub const MAX_SETTINGS_BYTES: usize = 4096;
pub const MAX_SETTINGS_ENTRIES: usize = 32;
pub const MAX_PADDING_SCHEME_BYTES: usize = 4096;
pub const MAX_PADDING_RULES: usize = 64;
pub const MAX_PADDING_SIZE: usize = 1 << 20;
pub const ANYTLS_PROTOCOL_VERSION: u32 = 2;
pub const ANYTLS_DEFAULT_CLIENT_NAME: &str = "pathchord/0.1";

pub const DEFAULT_PADDING_SCHEME: &[u8] = b"stop=8\n0=30-30\n1=100-400\n2=400-500,c,500-1000,c,500-1000,c,500-1000,c,500-1000\n3=9-9,500-1000\n4=500-1000\n5=500-1000\n6=500-1000\n7=500-1000";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnyTlsPaddingRule {
    Range { min: usize, max: usize },
    Check,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnyTlsPaddingScheme {
    raw: Bytes,
    digest: [u8; 16],
    stop: u32,
    records: BTreeMap<u32, Vec<AnyTlsPaddingRule>>,
}

impl AnyTlsPaddingScheme {
    pub fn parse(raw: &[u8]) -> Result<Self, &'static str> {
        if raw.is_empty() || raw.len() > MAX_PADDING_SCHEME_BYTES {
            return Err("AnyTLS padding scheme exceeds its size bound");
        }
        let text = std::str::from_utf8(raw).map_err(|_| "AnyTLS padding scheme is not UTF-8")?;
        let mut values = BTreeMap::new();
        for line in text.lines() {
            let Some((key, value)) = line.split_once('=') else {
                return Err("AnyTLS padding scheme line is missing '='");
            };
            if key.is_empty() || values.insert(key, value).is_some() {
                return Err("AnyTLS padding scheme contains a duplicate key");
            }
        }
        let stop = values
            .remove("stop")
            .ok_or("AnyTLS padding scheme is missing stop")?
            .parse::<u32>()
            .map_err(|_| "AnyTLS padding scheme stop is invalid")?;
        if stop == 0 {
            return Err("AnyTLS padding scheme stop is zero");
        }
        let mut records = BTreeMap::new();
        for (key, value) in values {
            let packet = key
                .parse::<u32>()
                .map_err(|_| "AnyTLS padding scheme packet index is invalid")?;
            let mut rules = Vec::new();
            for item in value.split(',') {
                if item == "c" {
                    rules.push(AnyTlsPaddingRule::Check);
                    continue;
                }
                let Some((minimum, maximum)) = item.split_once('-') else {
                    return Err("AnyTLS padding scheme range is invalid");
                };
                let minimum = minimum
                    .parse::<usize>()
                    .map_err(|_| "AnyTLS padding scheme range is invalid")?;
                let maximum = maximum
                    .parse::<usize>()
                    .map_err(|_| "AnyTLS padding scheme range is invalid")?;
                if minimum == 0 || maximum < minimum || maximum > MAX_PADDING_SIZE {
                    return Err("AnyTLS padding scheme range is invalid");
                }
                rules.push(AnyTlsPaddingRule::Range {
                    min: minimum,
                    max: maximum,
                });
            }
            if rules.len() > MAX_PADDING_RULES {
                return Err("AnyTLS padding scheme has too many rules");
            }
            if !rules.is_empty() {
                records.insert(packet, rules);
            }
        }
        let mut digest = Md5::new();
        digest.update(raw);
        Ok(Self {
            raw: Bytes::copy_from_slice(raw),
            digest: digest.finalize().into(),
            stop,
            records,
        })
    }

    #[must_use]
    pub fn default_scheme() -> Self {
        Self::parse(DEFAULT_PADDING_SCHEME).expect("official AnyTLS default padding scheme")
    }

    #[must_use]
    pub fn raw(&self) -> &[u8] {
        &self.raw
    }

    #[must_use]
    pub fn digest_hex(&self) -> String {
        self.digest
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }

    #[must_use]
    pub const fn stop(&self) -> u32 {
        self.stop
    }

    #[must_use]
    pub fn rules(&self, packet: u32) -> &[AnyTlsPaddingRule] {
        self.records.get(&packet).map_or(&[], Vec::as_slice)
    }

    pub fn sample_size(rule: AnyTlsPaddingRule) -> Result<Option<usize>, &'static str> {
        match rule {
            AnyTlsPaddingRule::Check => Ok(None),
            AnyTlsPaddingRule::Range { min, max } => {
                if max < min {
                    return Err("AnyTLS padding range is invalid");
                }
                let span = max - min + 1;
                let mut random = [0_u8; 8];
                getrandom::fill(&mut random).map_err(|_| "AnyTLS padding randomness failed")?;
                let value = (u64::from_ne_bytes(random) % span as u64) as usize;
                Ok(Some(min + value))
            }
        }
    }
}

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnyTlsState {
    Idle,
    Authenticated,
    SettingsSent,
    Opening,
    Open,
    HalfClosed,
    Closed,
    Failed,
}

impl AnyTlsState {
    pub fn transition(self, next: Self) -> Result<Self, &'static str> {
        let valid = self == next
            || matches!(
                (self, next),
                (Self::Idle, Self::Authenticated | Self::Failed)
                    | (Self::Authenticated, Self::SettingsSent | Self::Failed)
                    | (Self::SettingsSent, Self::Opening | Self::Failed)
                    | (Self::Opening, Self::Open | Self::Failed)
                    | (Self::Open, Self::HalfClosed | Self::Closed | Self::Failed)
                    | (Self::HalfClosed, Self::Closed | Self::Failed)
            );
        valid
            .then_some(next)
            .ok_or("invalid AnyTLS session transition")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnyTlsAddress {
    Ipv4([u8; 4], u16),
    Domain(String, u16),
    Ipv6([u8; 16], u16),
}

impl AnyTlsAddress {
    pub fn encode(&self, output: &mut BytesMut) -> Result<(), &'static str> {
        match self {
            Self::Ipv4(address, port) => {
                output.put_u8(1);
                output.extend_from_slice(address);
                output.put_u16(*port);
            }
            Self::Domain(host, port) => {
                if host.is_empty()
                    || host.len() > 255
                    || host.bytes().any(|byte| byte.is_ascii_control())
                {
                    return Err("AnyTLS domain address is invalid");
                }
                output.put_u8(3);
                output.put_u8(host.len() as u8);
                output.extend_from_slice(host.as_bytes());
                output.put_u16(*port);
            }
            Self::Ipv6(address, port) => {
                output.put_u8(4);
                output.extend_from_slice(address);
                output.put_u16(*port);
            }
        }
        Ok(())
    }

    pub fn decode(input: &mut BytesMut) -> Result<Option<Self>, &'static str> {
        if input.is_empty() {
            return Ok(None);
        }
        let kind = input[0];
        let needed = match kind {
            1 => 1 + 4 + 2,
            4 => 1 + 16 + 2,
            3 => {
                if input.len() < 2 {
                    return Ok(None);
                }
                1 + 1 + input[1] as usize + 2
            }
            _ => return Err("AnyTLS address type is unsupported"),
        };
        if input.len() < needed {
            return Ok(None);
        }
        input.advance(1);
        let address = match kind {
            1 => {
                let mut value = [0; 4];
                input.copy_to_slice(&mut value);
                Self::Ipv4(value, input.get_u16())
            }
            4 => {
                let mut value = [0; 16];
                input.copy_to_slice(&mut value);
                Self::Ipv6(value, input.get_u16())
            }
            3 => {
                let length = input.get_u8() as usize;
                let host = String::from_utf8(input.split_to(length).to_vec())
                    .map_err(|_| "AnyTLS domain address is not UTF-8")?;
                Self::Domain(host, input.get_u16())
            }
            _ => unreachable!(),
        };
        Ok(Some(address))
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AnyTlsSettings(pub BTreeMap<String, String>);

impl AnyTlsSettings {
    pub fn official_client(scheme: &AnyTlsPaddingScheme) -> Self {
        Self(BTreeMap::from([
            ("v".to_owned(), ANYTLS_PROTOCOL_VERSION.to_string()),
            ("client".to_owned(), ANYTLS_DEFAULT_CLIENT_NAME.to_owned()),
            ("padding-md5".to_owned(), scheme.digest_hex()),
        ]))
    }

    pub fn protocol_version(&self) -> Result<u32, &'static str> {
        self.0
            .get("v")
            .ok_or("AnyTLS settings are missing version")?
            .parse()
            .map_err(|_| "AnyTLS settings version is invalid")
    }

    pub fn padding_digest(&self) -> Result<&str, &'static str> {
        self.0
            .get("padding-md5")
            .map(String::as_str)
            .ok_or("AnyTLS settings are missing padding digest")
    }

    pub fn encode(&self) -> Result<Bytes, &'static str> {
        if self.0.len() > MAX_SETTINGS_ENTRIES {
            return Err("AnyTLS settings contain too many entries");
        }
        let mut output = BytesMut::new();
        for (key, value) in &self.0 {
            if key.is_empty()
                || key.len() > 128
                || value.len() > 512
                || key
                    .bytes()
                    .any(|byte| byte.is_ascii_control() || byte == b'=')
                || value.bytes().any(|byte| byte.is_ascii_control())
            {
                return Err("AnyTLS settings contain an invalid key or value");
            }
            output.extend_from_slice(key.as_bytes());
            output.put_u8(b'=');
            output.extend_from_slice(value.as_bytes());
            output.put_u8(b'\n');
            if output.len() > MAX_SETTINGS_BYTES {
                return Err("AnyTLS settings exceed the size bound");
            }
        }
        Ok(output.freeze())
    }

    pub fn decode(input: &[u8]) -> Result<Self, &'static str> {
        if input.len() > MAX_SETTINGS_BYTES {
            return Err("AnyTLS settings exceed the size bound");
        }
        let mut values = BTreeMap::new();
        for line in input
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
        {
            let Some(separator) = line.iter().position(|byte| *byte == b'=') else {
                return Err("AnyTLS setting is missing '='");
            };
            let key = std::str::from_utf8(&line[..separator])
                .map_err(|_| "AnyTLS setting key is not UTF-8")?;
            let value = std::str::from_utf8(&line[separator + 1..])
                .map_err(|_| "AnyTLS setting value is not UTF-8")?;
            if key.is_empty() || values.len() >= MAX_SETTINGS_ENTRIES {
                return Err("AnyTLS settings contain too many entries");
            }
            if values.insert(key.to_owned(), value.to_owned()).is_some() {
                return Err("AnyTLS settings contain a duplicate key");
            }
        }
        Ok(Self(values))
    }
}

impl AnyTlsFrame {
    pub fn syn(stream_id: u32, destination: &AnyTlsAddress) -> Result<Self, &'static str> {
        let mut payload = BytesMut::new();
        destination.encode(&mut payload)?;
        Ok(Self {
            command: AnyTlsCommand::Syn,
            stream_id,
            payload: payload.freeze(),
        })
    }

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

    pub fn validate(&self) -> Result<(), &'static str> {
        match self.command {
            AnyTlsCommand::Waste
            | AnyTlsCommand::Push
            | AnyTlsCommand::Alert
            | AnyTlsCommand::UpdatePaddingScheme => Ok(()),
            AnyTlsCommand::Syn => Ok(()),
            AnyTlsCommand::Settings | AnyTlsCommand::ServerSettings => (!self.payload.is_empty())
                .then_some(())
                .ok_or("AnyTLS command payload is missing"),
            AnyTlsCommand::Fin | AnyTlsCommand::HeartRequest | AnyTlsCommand::HeartResponse => self
                .payload
                .is_empty()
                .then_some(())
                .ok_or("AnyTLS command must not carry data"),
            AnyTlsCommand::SynAck => Ok(()),
        }
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

pub fn verify_authentication_record(password: &str, record: &[u8]) -> Result<Bytes, &'static str> {
    if record.len() < 34 || record[..32] != password_hash(password) {
        return Err("AnyTLS password authentication failed");
    }
    let padding_len = u16::from_be_bytes([record[32], record[33]]) as usize;
    if record.len() != 34 + padding_len {
        return Err("AnyTLS authentication record length is invalid");
    }
    Ok(Bytes::copy_from_slice(&record[34..]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn official_default_padding_scheme_has_stable_digest_and_bounds() {
        let scheme = AnyTlsPaddingScheme::default_scheme();
        assert_eq!(scheme.stop(), 8);
        assert_eq!(scheme.digest_hex(), "75cff2ad89aadf5e257059ee571ebe11");
        assert_eq!(
            scheme.rules(0),
            &[AnyTlsPaddingRule::Range { min: 30, max: 30 }]
        );
        assert!(matches!(scheme.rules(2)[1], AnyTlsPaddingRule::Check));
        assert!(
            AnyTlsPaddingScheme::sample_size(AnyTlsPaddingRule::Range { min: 5, max: 5 }).is_ok()
        );
    }

    #[test]
    fn padding_scheme_rejects_malformed_and_oversized_rules() {
        for input in [
            b"1=10-20".as_slice(),
            b"stop=1\n0=0-10".as_slice(),
            b"stop=1\n0=10-5".as_slice(),
            b"stop=1\n0=10-20\n0=30-40".as_slice(),
        ] {
            assert!(AnyTlsPaddingScheme::parse(input).is_err());
        }
        assert!(AnyTlsPaddingScheme::parse(&vec![b'a'; MAX_PADDING_SCHEME_BYTES + 1]).is_err());
    }

    #[test]
    fn official_settings_include_protocol_identity_and_padding_digest() {
        let settings = AnyTlsSettings::official_client(&AnyTlsPaddingScheme::default_scheme());
        let encoded = settings.encode().unwrap();
        let decoded = AnyTlsSettings::decode(&encoded).unwrap();
        assert_eq!(decoded.protocol_version().unwrap(), 2);
        assert_eq!(decoded.0["client"], ANYTLS_DEFAULT_CLIENT_NAME);
        assert_eq!(
            decoded.padding_digest().unwrap(),
            "75cff2ad89aadf5e257059ee571ebe11"
        );
    }

    #[test]
    fn command_validation_rejects_payload_on_control_commands() {
        let frame = AnyTlsFrame {
            command: AnyTlsCommand::HeartRequest,
            stream_id: 4,
            payload: Bytes::from_static(b"unexpected"),
        };
        assert!(frame.validate().is_err());
        let frame = AnyTlsFrame {
            command: AnyTlsCommand::Fin,
            stream_id: 4,
            payload: Bytes::new(),
        };
        assert!(frame.validate().is_ok());
    }

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
        assert_eq!(
            verify_authentication_record("secret", &record).unwrap(),
            Bytes::from_static(b"pad")
        );
        assert!(verify_authentication_record("wrong", &record).is_err());
    }

    #[test]
    fn address_and_syn_round_trip_preserves_domains_and_ports() {
        let address = AnyTlsAddress::Domain("example.test".into(), 443);
        let frame = AnyTlsFrame::syn(9, &address).unwrap();
        let mut encoded = BytesMut::new();
        frame.encode(&mut encoded).unwrap();
        let decoded = AnyTlsFrame::decode(&mut encoded).unwrap().unwrap();
        let mut payload = BytesMut::from(decoded.payload.as_ref());
        assert_eq!(AnyTlsAddress::decode(&mut payload).unwrap(), Some(address));
        assert!(payload.is_empty());
    }

    #[test]
    fn settings_round_trip_is_bounded_and_rejects_duplicates() {
        let settings = AnyTlsSettings(BTreeMap::from([
            ("client".into(), "pathchord".into()),
            ("version".into(), "2".into()),
        ]));
        let encoded = settings.encode().unwrap();
        assert_eq!(AnyTlsSettings::decode(&encoded).unwrap(), settings);
        assert!(AnyTlsSettings::decode(b"client=a\nclient=b\n").is_err());
    }

    #[test]
    fn state_machine_rejects_fin_before_open() {
        assert!(AnyTlsState::Opening.transition(AnyTlsState::Open).is_ok());
        assert!(
            AnyTlsState::Open
                .transition(AnyTlsState::HalfClosed)
                .is_ok()
        );
        assert!(
            AnyTlsState::Opening
                .transition(AnyTlsState::Closed)
                .is_err()
        );
    }
}
