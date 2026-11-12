use std::error::Error;
use std::fmt;

use crate::id::{PathId, SessionId};
use crate::limits::ProtocolLimits;
use crate::varint::{MAX_VARINT, VarIntError, decode_varint, encode_varint};

/// The wire value assigned to `wire-profile-v1`.
pub const WIRE_PROFILE_V1_VERSION: ProtocolVersion = ProtocolVersion(1);

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ProtocolVersion(u64);

impl ProtocolVersion {
    pub const fn try_new(value: u64) -> Result<Self, VarIntError> {
        if value <= MAX_VARINT {
            Ok(Self(value))
        } else {
            Err(VarIntError::ValueTooLarge { value })
        }
    }

    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Raw frame flags. The v1 profile reserves this field and requires zero.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct FrameFlags(u64);

impl FrameFlags {
    pub const fn empty() -> Self {
        Self(0)
    }

    pub const fn try_new(value: u64) -> Result<Self, VarIntError> {
        if value <= MAX_VARINT {
            Ok(Self(value))
        } else {
            Err(VarIntError::ValueTooLarge { value })
        }
    }

    pub const fn bits(self) -> u64 {
        self.0
    }
}

/// Stable frame kinds in the v1 registry.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u64)]
pub enum FrameType {
    PathHello = 1,
    SessionAttach = 2,
    SessionAttachOk = 3,
    SessionAttachReject = 4,
    PathReady = 5,
    PathDrain = 6,
    PathClose = 7,
    SessionClose = 8,
    StatusReport = 9,
    Heartbeat = 10,
    ControlAck = 11,

    StreamOpen = 32,
    StreamOpenOk = 33,
    StreamOpenErr = 34,
    StreamData = 35,
    StreamAck = 36,
    StreamWindow = 37,
    StreamFin = 38,
    StreamRst = 39,

    UdpOpen = 64,
    UdpOpenOk = 65,
    UdpOpenErr = 66,
    UdpDatagram = 67,
    UdpClose = 68,
}

impl FrameType {
    pub const ALL: [Self; 24] = [
        Self::PathHello,
        Self::SessionAttach,
        Self::SessionAttachOk,
        Self::SessionAttachReject,
        Self::PathReady,
        Self::PathDrain,
        Self::PathClose,
        Self::SessionClose,
        Self::StatusReport,
        Self::Heartbeat,
        Self::ControlAck,
        Self::StreamOpen,
        Self::StreamOpenOk,
        Self::StreamOpenErr,
        Self::StreamData,
        Self::StreamAck,
        Self::StreamWindow,
        Self::StreamFin,
        Self::StreamRst,
        Self::UdpOpen,
        Self::UdpOpenOk,
        Self::UdpOpenErr,
        Self::UdpDatagram,
        Self::UdpClose,
    ];

    pub const fn code(self) -> u64 {
        self as u64
    }

    pub const fn is_bulk_payload(self) -> bool {
        matches!(self, Self::StreamData | Self::UdpDatagram)
    }

    const fn payload_limit(self, limits: ProtocolLimits) -> usize {
        if self.is_bulk_payload() {
            limits.max_frame_payload()
        } else {
            limits.max_control_payload()
        }
    }
}

impl TryFrom<u64> for FrameType {
    type Error = FrameCodecError;

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        let frame_type = match value {
            1 => Self::PathHello,
            2 => Self::SessionAttach,
            3 => Self::SessionAttachOk,
            4 => Self::SessionAttachReject,
            5 => Self::PathReady,
            6 => Self::PathDrain,
            7 => Self::PathClose,
            8 => Self::SessionClose,
            9 => Self::StatusReport,
            10 => Self::Heartbeat,
            11 => Self::ControlAck,
            32 => Self::StreamOpen,
            33 => Self::StreamOpenOk,
            34 => Self::StreamOpenErr,
            35 => Self::StreamData,
            36 => Self::StreamAck,
            37 => Self::StreamWindow,
            38 => Self::StreamFin,
            39 => Self::StreamRst,
            64 => Self::UdpOpen,
            65 => Self::UdpOpenOk,
            66 => Self::UdpOpenErr,
            67 => Self::UdpDatagram,
            68 => Self::UdpClose,
            code => return Err(FrameCodecError::UnknownFrameType { code }),
        };
        Ok(frame_type)
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct PathFrameHeader {
    version: ProtocolVersion,
    frame_type: FrameType,
    flags: FrameFlags,
    session_id: SessionId,
    path_id: PathId,
    frame_seq: u64,
    payload_len: usize,
}

impl PathFrameHeader {
    pub const fn version(self) -> ProtocolVersion {
        self.version
    }

    pub const fn frame_type(self) -> FrameType {
        self.frame_type
    }

    pub const fn flags(self) -> FrameFlags {
        self.flags
    }

    pub const fn session_id(self) -> SessionId {
        self.session_id
    }

    pub const fn path_id(self) -> PathId {
        self.path_id
    }

    pub const fn frame_seq(self) -> u64 {
        self.frame_seq
    }

    pub const fn payload_len(self) -> usize {
        self.payload_len
    }
}

/// One self-delimiting PathChord frame.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PathFrame {
    header: PathFrameHeader,
    payload: Vec<u8>,
}

impl PathFrame {
    pub fn new(
        frame_type: FrameType,
        flags: FrameFlags,
        session_id: SessionId,
        path_id: PathId,
        frame_seq: u64,
        payload: Vec<u8>,
        limits: ProtocolLimits,
    ) -> Result<Self, FrameCodecError> {
        if frame_seq > MAX_VARINT {
            return Err(FrameCodecError::FrameSequenceTooLarge { frame_seq });
        }
        if flags.bits() != 0 {
            return Err(FrameCodecError::UnsupportedFlags {
                flags: flags.bits(),
            });
        }
        validate_payload(frame_type, payload.len(), limits)?;
        Ok(Self {
            header: PathFrameHeader {
                version: WIRE_PROFILE_V1_VERSION,
                frame_type,
                flags,
                session_id,
                path_id,
                frame_seq,
                payload_len: payload.len(),
            },
            payload,
        })
    }

    pub const fn header(&self) -> &PathFrameHeader {
        &self.header
    }

    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    pub fn into_payload(self) -> Vec<u8> {
        self.payload
    }

    pub fn encode(&self, limits: ProtocolLimits) -> Result<Vec<u8>, FrameCodecError> {
        validate_payload(self.header.frame_type, self.payload.len(), limits)?;

        let mut output = Vec::new();
        append_varint(self.header.version.get(), "version", &mut output)?;
        append_varint(self.header.frame_type.code(), "type", &mut output)?;
        append_varint(self.header.flags.bits(), "flags", &mut output)?;
        output.extend_from_slice(&self.header.session_id.to_be_bytes());
        output.extend_from_slice(&self.header.path_id.to_be_bytes());
        append_varint(self.header.frame_seq, "frame_seq", &mut output)?;
        append_varint(self.payload.len() as u64, "payload_len", &mut output)?;
        output.extend_from_slice(&self.payload);
        Ok(output)
    }

    pub fn decode(input: &[u8], limits: ProtocolLimits) -> Result<Self, FrameCodecError> {
        let mut cursor = 0;

        let version = read_varint(input, &mut cursor, "version")?;
        if version != WIRE_PROFILE_V1_VERSION.get() {
            return Err(FrameCodecError::UnsupportedVersion {
                found: version,
                supported: WIRE_PROFILE_V1_VERSION.get(),
            });
        }

        // Resolve the type before reading or allocating any payload.
        let frame_type_code = read_varint(input, &mut cursor, "type")?;
        let frame_type = FrameType::try_from(frame_type_code)?;
        let flags =
            FrameFlags::try_new(read_varint(input, &mut cursor, "flags")?).map_err(|source| {
                FrameCodecError::VarInt {
                    field: "flags",
                    source,
                }
            })?;
        if flags.bits() != 0 {
            return Err(FrameCodecError::UnsupportedFlags {
                flags: flags.bits(),
            });
        }
        let session_id = SessionId::from_be_bytes(read_fixed_16(input, &mut cursor, "session_id")?);
        let path_id = PathId::from_be_bytes(read_fixed_16(input, &mut cursor, "path_id")?);
        let frame_seq = read_varint(input, &mut cursor, "frame_seq")?;
        let payload_len_u64 = read_varint(input, &mut cursor, "payload_len")?;

        let maximum = frame_type.payload_limit(limits);
        if payload_len_u64 > maximum as u64 {
            return Err(FrameCodecError::PayloadTooLarge {
                frame_type,
                length: payload_len_u64,
                maximum,
            });
        }
        let payload_len = payload_len_u64 as usize;
        let remaining = input.len() - cursor;
        if remaining < payload_len {
            return Err(FrameCodecError::TruncatedPayload {
                expected: payload_len,
                actual: remaining,
            });
        }
        if remaining > payload_len {
            return Err(FrameCodecError::TrailingBytes {
                remaining: remaining - payload_len,
            });
        }

        // All type, size, and framing checks complete before this allocation.
        let payload = input[cursor..].to_vec();
        Ok(Self {
            header: PathFrameHeader {
                version: WIRE_PROFILE_V1_VERSION,
                frame_type,
                flags,
                session_id,
                path_id,
                frame_seq,
                payload_len,
            },
            payload,
        })
    }
}

fn validate_payload(
    frame_type: FrameType,
    length: usize,
    limits: ProtocolLimits,
) -> Result<(), FrameCodecError> {
    let maximum = frame_type.payload_limit(limits);
    if length > maximum {
        Err(FrameCodecError::PayloadTooLarge {
            frame_type,
            length: length as u64,
            maximum,
        })
    } else {
        Ok(())
    }
}

fn append_varint(
    value: u64,
    field: &'static str,
    output: &mut Vec<u8>,
) -> Result<(), FrameCodecError> {
    encode_varint(value, output).map_err(|source| FrameCodecError::VarInt { field, source })
}

fn read_varint(
    input: &[u8],
    cursor: &mut usize,
    field: &'static str,
) -> Result<u64, FrameCodecError> {
    let (value, consumed) = decode_varint(&input[*cursor..])
        .map_err(|source| FrameCodecError::VarInt { field, source })?;
    *cursor += consumed;
    Ok(value)
}

fn read_fixed_16(
    input: &[u8],
    cursor: &mut usize,
    field: &'static str,
) -> Result<[u8; 16], FrameCodecError> {
    let remaining = input.len() - *cursor;
    if remaining < 16 {
        return Err(FrameCodecError::TruncatedField {
            field,
            expected: 16,
            actual: remaining,
        });
    }
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&input[*cursor..*cursor + 16]);
    *cursor += 16;
    Ok(bytes)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FrameCodecError {
    VarInt {
        field: &'static str,
        source: VarIntError,
    },
    UnsupportedVersion {
        found: u64,
        supported: u64,
    },
    UnknownFrameType {
        code: u64,
    },
    FrameSequenceTooLarge {
        frame_seq: u64,
    },
    UnsupportedFlags {
        flags: u64,
    },
    PayloadTooLarge {
        frame_type: FrameType,
        length: u64,
        maximum: usize,
    },
    TruncatedField {
        field: &'static str,
        expected: usize,
        actual: usize,
    },
    TruncatedPayload {
        expected: usize,
        actual: usize,
    },
    TrailingBytes {
        remaining: usize,
    },
}

impl fmt::Display for FrameCodecError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::VarInt { field, source } => {
                write!(formatter, "invalid {field} varint: {source}")
            }
            Self::UnsupportedVersion { found, supported } => write!(
                formatter,
                "unsupported protocol version {found}; this build supports {supported}"
            ),
            Self::UnknownFrameType { code } => write!(formatter, "unknown frame type {code}"),
            Self::FrameSequenceTooLarge { frame_seq } => {
                write!(formatter, "frame sequence {frame_seq} exceeds 62 bits")
            }
            Self::UnsupportedFlags { flags } => {
                write!(
                    formatter,
                    "frame flags {flags} are not assigned in wire-profile-v1"
                )
            }
            Self::PayloadTooLarge {
                frame_type,
                length,
                maximum,
            } => write!(
                formatter,
                "{frame_type:?} payload length {length} exceeds limit {maximum}"
            ),
            Self::TruncatedField {
                field,
                expected,
                actual,
            } => write!(
                formatter,
                "truncated {field}: expected {expected} bytes, got {actual}"
            ),
            Self::TruncatedPayload { expected, actual } => write!(
                formatter,
                "truncated payload: expected {expected} bytes, got {actual}"
            ),
            Self::TrailingBytes { remaining } => {
                write!(formatter, "{remaining} trailing bytes after frame")
            }
        }
    }
}

impl Error for FrameCodecError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::VarInt { source, .. } => Some(source),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn example_frame(frame_type: FrameType, payload: Vec<u8>) -> PathFrame {
        PathFrame::new(
            frame_type,
            FrameFlags::empty(),
            SessionId::new(0x1122),
            PathId::new(0x3344),
            7,
            payload,
            ProtocolLimits::default(),
        )
        .unwrap()
    }

    #[test]
    fn every_v1_frame_type_has_a_distinct_code() {
        for (index, frame_type) in FrameType::ALL.iter().enumerate() {
            assert_eq!(FrameType::try_from(frame_type.code()), Ok(*frame_type));
            assert!(
                FrameType::ALL[index + 1..]
                    .iter()
                    .all(|other| other.code() != frame_type.code())
            );
        }
    }

    #[test]
    fn frame_round_trip_preserves_header_and_payload() {
        let frame = example_frame(FrameType::StreamData, b"path-chord".to_vec());
        let encoded = frame.encode(ProtocolLimits::default()).unwrap();
        let decoded = PathFrame::decode(&encoded, ProtocolLimits::default()).unwrap();

        assert_eq!(decoded, frame);
        assert_eq!(decoded.header().payload_len(), 10);
        assert_eq!(decoded.header().version(), WIRE_PROFILE_V1_VERSION);
    }

    #[test]
    fn framing_golden_vector_fixes_field_order_and_varint_widths() {
        let payload = vec![0xaa; 64];
        let frame = PathFrame::new(
            FrameType::StreamData,
            FrameFlags::empty(),
            SessionId::new(0x0011_2233_4455_6677_8899_aabb_ccdd_eeff),
            PathId::new(0xffee_ddcc_bbaa_9988_7766_5544_3322_1100),
            1_073_741_824,
            payload.clone(),
            ProtocolLimits::default(),
        )
        .unwrap();

        let mut expected = vec![
            0x01, // wire-profile-v1 version, one-byte varint
            0x23, // STREAM_DATA, one-byte varint
            0x00, // flags, one-byte varint
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, // SessionID
            0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa,
            0x99, 0x88, // PathID
            0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00, 0xc0, 0x00, 0x00, 0x00, 0x40, 0x00,
            0x00, 0x00, // sequence, eight-byte varint
            0x40, 0x40, // payload length, two-byte varint
        ];
        expected.extend_from_slice(&[0xaa; 64]);

        assert_eq!(frame.encode(ProtocolLimits::default()).unwrap(), expected);
        assert_eq!(
            PathFrame::decode(&expected, ProtocolLimits::default()).unwrap(),
            frame
        );
    }

    #[test]
    fn maximum_frame_fits_one_noise_message_with_its_tag() {
        const NOISE_TAG_LEN: usize = 16;
        const WORST_CASE_V1_HEADER_LEN: usize = 48;

        let limits = ProtocolLimits::default();
        let frame = PathFrame::new(
            FrameType::UdpDatagram,
            FrameFlags::empty(),
            SessionId::new(u128::MAX),
            PathId::new(u128::MAX),
            MAX_VARINT,
            vec![0; limits.max_frame_payload()],
            limits,
        )
        .unwrap();
        let encoded = frame.encode(limits).unwrap();

        assert_eq!(
            encoded.len(),
            limits.max_frame_payload() + WORST_CASE_V1_HEADER_LEN
        );
        assert!(encoded.len() + NOISE_TAG_LEN <= 65_535);
    }

    #[test]
    fn unknown_type_is_rejected_immediately() {
        let input = [1, 63];
        assert_eq!(
            PathFrame::decode(&input, ProtocolLimits::default()),
            Err(FrameCodecError::UnknownFrameType { code: 63 })
        );
    }

    #[test]
    fn nonzero_v1_flags_are_rejected() {
        assert_eq!(
            PathFrame::new(
                FrameType::Heartbeat,
                FrameFlags::try_new(1).unwrap(),
                SessionId::new(1),
                PathId::new(2),
                0,
                Vec::new(),
                ProtocolLimits::default(),
            ),
            Err(FrameCodecError::UnsupportedFlags { flags: 1 })
        );
    }

    #[test]
    fn unsupported_version_is_rejected() {
        assert_eq!(
            PathFrame::decode(&[0], ProtocolLimits::default()),
            Err(FrameCodecError::UnsupportedVersion {
                found: 0,
                supported: 1
            })
        );
    }

    #[test]
    fn non_canonical_header_varint_is_rejected() {
        assert!(matches!(
            PathFrame::decode(&[0x40, 0], ProtocolLimits::default()),
            Err(FrameCodecError::VarInt {
                field: "version",
                source: VarIntError::NonCanonical { .. }
            })
        ));
    }

    #[test]
    fn truncated_fixed_header_field_is_rejected() {
        let input = [1, FrameType::PathHello.code() as u8, 0, 1, 2];
        assert_eq!(
            PathFrame::decode(&input, ProtocolLimits::default()),
            Err(FrameCodecError::TruncatedField {
                field: "session_id",
                expected: 16,
                actual: 2
            })
        );
    }

    #[test]
    fn control_and_bulk_payloads_use_separate_limits() {
        let limits = ProtocolLimits::default();
        assert!(
            PathFrame::new(
                FrameType::StatusReport,
                FrameFlags::empty(),
                SessionId::new(1),
                PathId::new(2),
                0,
                vec![0; limits.max_control_payload() + 1],
                limits,
            )
            .is_err()
        );
        assert!(
            PathFrame::new(
                FrameType::StreamData,
                FrameFlags::empty(),
                SessionId::new(1),
                PathId::new(2),
                0,
                vec![0; limits.max_frame_payload()],
                limits,
            )
            .is_ok()
        );
    }

    #[test]
    fn oversized_declared_payload_is_rejected_before_truncation() {
        let limits = ProtocolLimits::default();
        let mut input = Vec::new();
        encode_varint(1, &mut input).unwrap();
        encode_varint(FrameType::StreamData.code(), &mut input).unwrap();
        encode_varint(0, &mut input).unwrap();
        input.extend_from_slice(&SessionId::new(1).to_be_bytes());
        input.extend_from_slice(&PathId::new(2).to_be_bytes());
        encode_varint(0, &mut input).unwrap();
        encode_varint((limits.max_frame_payload() + 1) as u64, &mut input).unwrap();

        assert!(matches!(
            PathFrame::decode(&input, limits),
            Err(FrameCodecError::PayloadTooLarge { .. })
        ));
    }

    #[test]
    fn truncated_and_trailing_payloads_are_rejected() {
        let frame = example_frame(FrameType::StreamData, vec![1, 2, 3]);
        let mut encoded = frame.encode(ProtocolLimits::default()).unwrap();
        encoded.pop();
        assert_eq!(
            PathFrame::decode(&encoded, ProtocolLimits::default()),
            Err(FrameCodecError::TruncatedPayload {
                expected: 3,
                actual: 2
            })
        );

        let mut encoded = frame.encode(ProtocolLimits::default()).unwrap();
        encoded.push(4);
        assert_eq!(
            PathFrame::decode(&encoded, ProtocolLimits::default()),
            Err(FrameCodecError::TrailingBytes { remaining: 1 })
        );
    }

    #[test]
    fn frame_sequence_is_limited_to_62_bits() {
        assert_eq!(
            PathFrame::new(
                FrameType::Heartbeat,
                FrameFlags::empty(),
                SessionId::new(1),
                PathId::new(2),
                MAX_VARINT + 1,
                Vec::new(),
                ProtocolLimits::default(),
            ),
            Err(FrameCodecError::FrameSequenceTooLarge {
                frame_seq: MAX_VARINT + 1
            })
        );
    }

    proptest! {
        #[test]
        fn arbitrary_data_frames_round_trip(
            session_id in any::<u128>(),
            path_id in any::<u128>(),
            frame_seq in 0_u64..=MAX_VARINT,
            payload in proptest::collection::vec(any::<u8>(), 0..2048),
        ) {
            let frame = PathFrame::new(
                FrameType::StreamData,
                FrameFlags::empty(),
                SessionId::new(session_id),
                PathId::new(path_id),
                frame_seq,
                payload,
                ProtocolLimits::default(),
            ).unwrap();
            let encoded = frame.encode(ProtocolLimits::default()).unwrap();
            let decoded = PathFrame::decode(&encoded, ProtocolLimits::default()).unwrap();
            prop_assert_eq!(decoded, frame);
        }
    }
}
