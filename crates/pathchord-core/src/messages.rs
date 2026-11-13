//! wire-profile-v1 payload schemas.
//!
//! The outer [`PathFrame`](crate::PathFrame) codec owns the common header. This
//! module owns the canonical payload encoding for control and stream messages.
//! Every field is length-delimited where applicable and checked before
//! allocation.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::error::ErrorClass;
use crate::frame::{FrameType, ProtocolVersion};
use crate::id::{PathId, RequestId, SessionId, StreamId};
use crate::limits::ProtocolLimits;
use crate::reliability::AckRange;
use crate::state::EgressServiceState;
use crate::varint::{MAX_VARINT, VarIntError, decode_varint, encode_varint};

const MAX_ENDPOINT_ADDRESSES: usize = ProtocolLimits::HARD_MAX_ENDPOINT_ADDRESSES;
const MAX_ACK_RANGES: usize = ProtocolLimits::HARD_MAX_ACK_RANGES;

/// A v1 target endpoint. Hostname bytes are UTF-8 by contract but remain
/// opaque here so DNS policy stays above the wire codec.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TargetEndpoint {
    pub hostname: Vec<u8>,
    pub port: u16,
    pub resolved_addresses: Vec<IpAddr>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PathHello {
    pub version: ProtocolVersion,
    pub capabilities: u64,
    pub path_id: PathId,
    pub transport_metadata: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionAttach {
    pub ingress_id: Vec<u8>,
    pub session_id: SessionId,
    pub egress_id: Vec<u8>,
    pub control_seq: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionAttachOk {
    pub authorization_generation: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionAttachReject {
    pub error: ErrorClass,
    pub reason: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PathReady {
    pub max_frame_payload: u64,
    pub max_control_payload: u64,
    pub max_session_buffering: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PathDrain {
    pub drain_reason: u64,
    pub deadline_ms: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PathClose {
    pub error: ErrorClass,
    pub reason: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StatusReport {
    pub connected: bool,
    pub service_state: EgressServiceState,
    pub load_basis_points: u16,
    pub connection_utilization_basis_points: u16,
    pub bandwidth_utilization_basis_points: u16,
    pub active_sessions: u64,
    pub active_streams: u64,
    pub active_target_connections: u64,
    pub capacity_bps: u64,
    pub recommended_path_count: u64,
    pub report_seqno: u64,
    pub sample_age_ms: u64,
    pub expires_after_ms: u64,
}

/// Result of applying one Egress status report to a monotonic observation
/// tracker.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StatusReportDisposition {
    Accepted,
    Duplicate,
    Stale,
    Expired,
}

/// Tracks report ordering and freshness independently of wire decoding.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct StatusReportTracker {
    latest: Option<StatusReport>,
}

impl StatusReportTracker {
    #[must_use]
    pub const fn new() -> Self {
        Self { latest: None }
    }

    #[must_use]
    pub fn latest(&self) -> Option<&StatusReport> {
        self.latest.as_ref()
    }

    /// Applies a report only when it is newer and within its advertised
    /// freshness window. Stale/duplicate reports do not replace current state.
    pub fn apply(&mut self, report: StatusReport) -> StatusReportDisposition {
        if report.sample_age_ms > report.expires_after_ms {
            return StatusReportDisposition::Expired;
        }
        if let Some(previous) = &self.latest {
            if report.report_seqno == previous.report_seqno {
                return StatusReportDisposition::Duplicate;
            }
            if report.report_seqno < previous.report_seqno {
                return StatusReportDisposition::Stale;
            }
        }
        self.latest = Some(report);
        StatusReportDisposition::Accepted
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Heartbeat {
    pub control_seq: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ControlAck {
    pub highest_contiguous: u64,
    pub ranges: Vec<AckRange>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionClose {
    pub error: ErrorClass,
    pub reason: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StreamOpen {
    pub stream_id: StreamId,
    pub request_id: RequestId,
    pub target: TargetEndpoint,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StreamOpenOk {
    pub stream_id: StreamId,
    pub result_metadata: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StreamOpenErr {
    pub stream_id: StreamId,
    pub error: ErrorClass,
    pub reason: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StreamData {
    pub stream_id: StreamId,
    pub offset: u64,
    pub flags: u64,
    pub data: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StreamAck {
    pub stream_id: StreamId,
    pub ranges: Vec<AckRange>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StreamWindow {
    pub stream_id: StreamId,
    pub stream_limit: u64,
    pub session_limit: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StreamFin {
    pub stream_id: StreamId,
    pub flags: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StreamRst {
    pub stream_id: StreamId,
    pub error: ErrorClass,
    pub reason: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UdpOpen {
    pub association_id: u64,
    pub target_flags: u64,
    pub target: TargetEndpoint,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UdpOpenOk {
    pub association_id: u64,
    pub target_visible_port: u16,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UdpOpenErr {
    pub association_id: u64,
    pub error: ErrorClass,
    pub reason: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UdpDatagram {
    pub association_id: u64,
    pub datagram_seq: u64,
    pub payload: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UdpClose {
    pub association_id: u64,
    pub error: ErrorClass,
    pub reason: Vec<u8>,
}

/// All v1 payloads carried by the canonical frame registry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Message {
    PathHello(PathHello),
    SessionAttach(SessionAttach),
    SessionAttachOk(SessionAttachOk),
    SessionAttachReject(SessionAttachReject),
    PathReady(PathReady),
    PathDrain(PathDrain),
    PathClose(PathClose),
    StatusReport(StatusReport),
    Heartbeat(Heartbeat),
    ControlAck(ControlAck),
    SessionClose(SessionClose),
    StreamOpen(StreamOpen),
    StreamOpenOk(StreamOpenOk),
    StreamOpenErr(StreamOpenErr),
    StreamData(StreamData),
    StreamAck(StreamAck),
    StreamWindow(StreamWindow),
    StreamFin(StreamFin),
    StreamRst(StreamRst),
    UdpOpen(UdpOpen),
    UdpOpenOk(UdpOpenOk),
    UdpOpenErr(UdpOpenErr),
    UdpDatagram(UdpDatagram),
    UdpClose(UdpClose),
}

impl Message {
    #[must_use]
    pub const fn frame_type(&self) -> FrameType {
        match self {
            Self::PathHello(_) => FrameType::PathHello,
            Self::SessionAttach(_) => FrameType::SessionAttach,
            Self::SessionAttachOk(_) => FrameType::SessionAttachOk,
            Self::SessionAttachReject(_) => FrameType::SessionAttachReject,
            Self::PathReady(_) => FrameType::PathReady,
            Self::PathDrain(_) => FrameType::PathDrain,
            Self::PathClose(_) => FrameType::PathClose,
            Self::StatusReport(_) => FrameType::StatusReport,
            Self::Heartbeat(_) => FrameType::Heartbeat,
            Self::ControlAck(_) => FrameType::ControlAck,
            Self::SessionClose(_) => FrameType::SessionClose,
            Self::StreamOpen(_) => FrameType::StreamOpen,
            Self::StreamOpenOk(_) => FrameType::StreamOpenOk,
            Self::StreamOpenErr(_) => FrameType::StreamOpenErr,
            Self::StreamData(_) => FrameType::StreamData,
            Self::StreamAck(_) => FrameType::StreamAck,
            Self::StreamWindow(_) => FrameType::StreamWindow,
            Self::StreamFin(_) => FrameType::StreamFin,
            Self::StreamRst(_) => FrameType::StreamRst,
            Self::UdpOpen(_) => FrameType::UdpOpen,
            Self::UdpOpenOk(_) => FrameType::UdpOpenOk,
            Self::UdpOpenErr(_) => FrameType::UdpOpenErr,
            Self::UdpDatagram(_) => FrameType::UdpDatagram,
            Self::UdpClose(_) => FrameType::UdpClose,
        }
    }

    /// Encodes one canonical payload under the supplied protocol limits.
    pub fn encode(&self, limits: ProtocolLimits) -> Result<Vec<u8>, MessageCodecError> {
        let mut output = Vec::new();
        self.encode_into(&mut output, limits)?;
        let maximum = if self.frame_type().is_bulk_payload() {
            limits.max_frame_payload()
        } else {
            limits.max_control_payload()
        };
        if output.len() > maximum {
            return Err(MessageCodecError::PayloadTooLarge {
                length: output.len(),
                maximum,
            });
        }
        Ok(output)
    }

    /// Decodes exactly one payload for `frame_type`.
    pub fn decode(
        frame_type: FrameType,
        input: &[u8],
        limits: ProtocolLimits,
    ) -> Result<Self, MessageCodecError> {
        let maximum = if frame_type.is_bulk_payload() {
            limits.max_frame_payload()
        } else {
            limits.max_control_payload()
        };
        if input.len() > maximum {
            return Err(MessageCodecError::PayloadTooLarge {
                length: input.len(),
                maximum,
            });
        }
        let mut reader = Reader::new(input);
        let message = match frame_type {
            FrameType::PathHello => Self::PathHello(PathHello::decode(&mut reader, limits)?),
            FrameType::SessionAttach => {
                Self::SessionAttach(SessionAttach::decode(&mut reader, limits)?)
            }
            FrameType::SessionAttachOk => {
                Self::SessionAttachOk(SessionAttachOk::decode(&mut reader)?)
            }
            FrameType::SessionAttachReject => {
                Self::SessionAttachReject(SessionAttachReject::decode(&mut reader, limits)?)
            }
            FrameType::PathReady => Self::PathReady(PathReady::decode(&mut reader)?),
            FrameType::PathDrain => Self::PathDrain(PathDrain::decode(&mut reader)?),
            FrameType::PathClose => Self::PathClose(PathClose::decode(&mut reader, limits)?),
            FrameType::StatusReport => Self::StatusReport(StatusReport::decode(&mut reader)?),
            FrameType::Heartbeat => Self::Heartbeat(Heartbeat::decode(&mut reader)?),
            FrameType::ControlAck => Self::ControlAck(ControlAck::decode(&mut reader)?),
            FrameType::SessionClose => {
                Self::SessionClose(SessionClose::decode(&mut reader, limits)?)
            }
            FrameType::StreamOpen => Self::StreamOpen(StreamOpen::decode(&mut reader, limits)?),
            FrameType::StreamOpenOk => {
                Self::StreamOpenOk(StreamOpenOk::decode(&mut reader, limits)?)
            }
            FrameType::StreamOpenErr => {
                Self::StreamOpenErr(StreamOpenErr::decode(&mut reader, limits)?)
            }
            FrameType::StreamData => Self::StreamData(StreamData::decode(&mut reader, limits)?),
            FrameType::StreamAck => Self::StreamAck(StreamAck::decode(&mut reader)?),
            FrameType::StreamWindow => Self::StreamWindow(StreamWindow::decode(&mut reader)?),
            FrameType::StreamFin => Self::StreamFin(StreamFin::decode(&mut reader)?),
            FrameType::StreamRst => Self::StreamRst(StreamRst::decode(&mut reader, limits)?),
            FrameType::UdpOpen => Self::UdpOpen(UdpOpen::decode(&mut reader, limits)?),
            FrameType::UdpOpenOk => Self::UdpOpenOk(UdpOpenOk::decode(&mut reader)?),
            FrameType::UdpOpenErr => Self::UdpOpenErr(UdpOpenErr::decode(&mut reader, limits)?),
            FrameType::UdpDatagram => Self::UdpDatagram(UdpDatagram::decode(&mut reader, limits)?),
            FrameType::UdpClose => Self::UdpClose(UdpClose::decode(&mut reader, limits)?),
        };
        reader.finish()?;
        Ok(message)
    }

    fn encode_into(
        &self,
        output: &mut Vec<u8>,
        limits: ProtocolLimits,
    ) -> Result<(), MessageCodecError> {
        match self {
            Self::PathHello(value) => value.encode(output, limits),
            Self::SessionAttach(value) => value.encode(output, limits),
            Self::SessionAttachOk(value) => value.encode(output),
            Self::SessionAttachReject(value) => value.encode(output, limits),
            Self::PathReady(value) => value.encode(output),
            Self::PathDrain(value) => value.encode(output),
            Self::PathClose(value) => value.encode(output, limits),
            Self::StatusReport(value) => value.encode(output),
            Self::Heartbeat(value) => value.encode(output),
            Self::ControlAck(value) => value.encode(output),
            Self::SessionClose(value) => value.encode(output, limits),
            Self::StreamOpen(value) => value.encode(output, limits),
            Self::StreamOpenOk(value) => value.encode(output, limits),
            Self::StreamOpenErr(value) => value.encode(output, limits),
            Self::StreamData(value) => value.encode(output, limits),
            Self::StreamAck(value) => value.encode(output),
            Self::StreamWindow(value) => value.encode(output),
            Self::StreamFin(value) => value.encode(output),
            Self::StreamRst(value) => value.encode(output, limits),
            Self::UdpOpen(value) => value.encode(output, limits),
            Self::UdpOpenOk(value) => value.encode(output),
            Self::UdpOpenErr(value) => value.encode(output, limits),
            Self::UdpDatagram(value) => value.encode(output, limits),
            Self::UdpClose(value) => value.encode(output, limits),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MessageCodecError {
    VarInt(VarIntError),
    Truncated {
        field: &'static str,
    },
    Trailing {
        remaining: usize,
    },
    PayloadTooLarge {
        length: usize,
        maximum: usize,
    },
    InvalidField {
        field: &'static str,
    },
    InvalidErrorClass {
        code: u8,
    },
    InvalidStreamId {
        value: u64,
    },
    InvalidAddressFamily {
        code: u8,
    },
    TooManyItems {
        field: &'static str,
        count: usize,
        maximum: usize,
    },
    UnsupportedFrameType {
        frame_type: FrameType,
    },
}

impl fmt::Display for MessageCodecError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::VarInt(error) => write!(formatter, "invalid message varint: {error}"),
            Self::Truncated { field } => write!(formatter, "truncated message field {field}"),
            Self::Trailing { remaining } => write!(formatter, "{remaining} trailing message bytes"),
            Self::PayloadTooLarge { length, maximum } => {
                write!(
                    formatter,
                    "message payload length {length} exceeds {maximum}"
                )
            }
            Self::InvalidField { field } => write!(formatter, "invalid message field {field}"),
            Self::InvalidErrorClass { code } => write!(formatter, "unknown error class {code}"),
            Self::InvalidStreamId { value } => write!(formatter, "invalid StreamID {value}"),
            Self::InvalidAddressFamily { code } => {
                write!(formatter, "unknown address family {code}")
            }
            Self::TooManyItems {
                field,
                count,
                maximum,
            } => {
                write!(formatter, "{field} count {count} exceeds {maximum}")
            }
            Self::UnsupportedFrameType { frame_type } => {
                write!(
                    formatter,
                    "frame type {frame_type:?} has no wire-profile-v1 payload schema"
                )
            }
        }
    }
}

impl std::error::Error for MessageCodecError {}

impl From<VarIntError> for MessageCodecError {
    fn from(error: VarIntError) -> Self {
        Self::VarInt(error)
    }
}

struct Reader<'a> {
    input: &'a [u8],
    cursor: usize,
}

impl<'a> Reader<'a> {
    const fn new(input: &'a [u8]) -> Self {
        Self { input, cursor: 0 }
    }

    fn finish(&self) -> Result<(), MessageCodecError> {
        if self.cursor == self.input.len() {
            Ok(())
        } else {
            Err(MessageCodecError::Trailing {
                remaining: self.input.len() - self.cursor,
            })
        }
    }

    fn take(&mut self, length: usize, field: &'static str) -> Result<&'a [u8], MessageCodecError> {
        let end = self
            .cursor
            .checked_add(length)
            .ok_or(MessageCodecError::Truncated { field })?;
        if end > self.input.len() {
            return Err(MessageCodecError::Truncated { field });
        }
        let bytes = &self.input[self.cursor..end];
        self.cursor = end;
        Ok(bytes)
    }

    fn byte(&mut self, field: &'static str) -> Result<u8, MessageCodecError> {
        Ok(*self.take(1, field)?.first().expect("one byte checked"))
    }

    fn bool(&mut self, field: &'static str) -> Result<bool, MessageCodecError> {
        match self.byte(field)? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(MessageCodecError::InvalidField { field }),
        }
    }

    fn u16(&mut self, field: &'static str) -> Result<u16, MessageCodecError> {
        Ok(u16::from_be_bytes(
            self.take(2, field)?.try_into().expect("two bytes checked"),
        ))
    }

    fn varint(&mut self, field: &'static str) -> Result<u64, MessageCodecError> {
        let (value, consumed) = decode_varint(&self.input[self.cursor..])?;
        self.cursor += consumed;
        let _ = field;
        Ok(value)
    }

    fn id128(&mut self, field: &'static str) -> Result<[u8; 16], MessageCodecError> {
        Ok(self
            .take(16, field)?
            .try_into()
            .expect("sixteen bytes checked"))
    }

    fn bytes(&mut self, maximum: usize, field: &'static str) -> Result<Vec<u8>, MessageCodecError> {
        let length = self.varint(field)?;
        if length > maximum as u64 {
            return Err(MessageCodecError::PayloadTooLarge {
                length: length as usize,
                maximum,
            });
        }
        Ok(self.take(length as usize, field)?.to_vec())
    }
}

fn put_varint(value: u64, output: &mut Vec<u8>) -> Result<(), MessageCodecError> {
    encode_varint(value, output)?;
    Ok(())
}

fn put_bytes(
    bytes: &[u8],
    maximum: usize,
    field: &'static str,
    output: &mut Vec<u8>,
) -> Result<(), MessageCodecError> {
    if bytes.len() > maximum {
        return Err(MessageCodecError::PayloadTooLarge {
            length: bytes.len(),
            maximum,
        });
    }
    put_varint(bytes.len() as u64, output)?;
    output.extend_from_slice(bytes);
    let _ = field;
    Ok(())
}

fn put_id128(id: [u8; 16], output: &mut Vec<u8>) {
    output.extend_from_slice(&id);
}

fn put_error(error: ErrorClass, output: &mut Vec<u8>) {
    output.push(error.code());
}

fn validate_status_report(value: &StatusReport) -> Result<(), MessageCodecError> {
    for (field, ratio) in [
        ("load_basis_points", value.load_basis_points),
        (
            "connection_utilization_basis_points",
            value.connection_utilization_basis_points,
        ),
        (
            "bandwidth_utilization_basis_points",
            value.bandwidth_utilization_basis_points,
        ),
    ] {
        if ratio > 10_000 {
            return Err(MessageCodecError::InvalidField { field });
        }
    }
    if value.expires_after_ms == 0 {
        return Err(MessageCodecError::InvalidField {
            field: "expires_after_ms",
        });
    }
    let expected_connected = !matches!(value.service_state, EgressServiceState::Down);
    if value.connected != expected_connected {
        return Err(MessageCodecError::InvalidField {
            field: "connected/service_state",
        });
    }
    Ok(())
}

fn validate_stream_flags(flags: u64) -> Result<(), MessageCodecError> {
    if flags & !0x3 != 0 {
        return Err(MessageCodecError::InvalidField {
            field: "stream_flags",
        });
    }
    Ok(())
}

fn validate_negotiated_limits(
    max_frame_payload: u64,
    max_control_payload: u64,
    max_session_buffering: u64,
) -> Result<(), MessageCodecError> {
    if max_frame_payload == 0
        || max_frame_payload > ProtocolLimits::HARD_MAX_FRAME_PAYLOAD as u64
        || max_control_payload == 0
        || max_control_payload > ProtocolLimits::HARD_MAX_CONTROL_PAYLOAD as u64
        || max_session_buffering == 0
        || max_session_buffering > ProtocolLimits::HARD_MAX_SESSION_BUFFERING as u64
        || max_control_payload > max_frame_payload
    {
        return Err(MessageCodecError::InvalidField {
            field: "negotiated_limits",
        });
    }
    Ok(())
}

fn get_error(reader: &mut Reader<'_>) -> Result<ErrorClass, MessageCodecError> {
    let code = reader.byte("error")?;
    ErrorClass::try_from(code).map_err(|_| MessageCodecError::InvalidErrorClass { code })
}

fn put_stream_id(id: StreamId, output: &mut Vec<u8>) -> Result<(), MessageCodecError> {
    put_varint(id.get(), output)
}

fn get_stream_id(reader: &mut Reader<'_>) -> Result<StreamId, MessageCodecError> {
    let value = reader.varint("stream_id")?;
    StreamId::try_from(value).map_err(|_| MessageCodecError::InvalidStreamId { value })
}

fn put_ranges(ranges: &[AckRange], output: &mut Vec<u8>) -> Result<(), MessageCodecError> {
    if ranges.len() > MAX_ACK_RANGES {
        return Err(MessageCodecError::TooManyItems {
            field: "ack_ranges",
            count: ranges.len(),
            maximum: MAX_ACK_RANGES,
        });
    }
    put_varint(ranges.len() as u64, output)?;
    let mut previous_end = None;
    for range in ranges {
        range
            .validate()
            .map_err(|_| MessageCodecError::InvalidField { field: "ack_range" })?;
        if previous_end.is_some_and(|end| range.start <= end) {
            return Err(MessageCodecError::InvalidField {
                field: "ack_range_order",
            });
        }
        previous_end = Some(range.end);
        put_varint(range.start, output)?;
        put_varint(range.end, output)?;
    }
    Ok(())
}

fn get_ranges(reader: &mut Reader<'_>) -> Result<Vec<AckRange>, MessageCodecError> {
    let count = reader.varint("ack_range_count")? as usize;
    if count > MAX_ACK_RANGES {
        return Err(MessageCodecError::TooManyItems {
            field: "ack_ranges",
            count,
            maximum: MAX_ACK_RANGES,
        });
    }
    if count > reader.input.len().saturating_sub(reader.cursor) / 2 {
        return Err(MessageCodecError::Truncated {
            field: "ack_ranges",
        });
    }
    let mut ranges = Vec::with_capacity(count);
    let mut previous_end = None;
    for _ in 0..count {
        let range = AckRange {
            start: reader.varint("ack_start")?,
            end: reader.varint("ack_end")?,
        };
        range
            .validate()
            .map_err(|_| MessageCodecError::InvalidField { field: "ack_range" })?;
        if previous_end.is_some_and(|end| range.start <= end) {
            return Err(MessageCodecError::InvalidField {
                field: "ack_range_order",
            });
        }
        previous_end = Some(range.end);
        ranges.push(range);
    }
    Ok(ranges)
}

fn put_endpoint(
    endpoint: &TargetEndpoint,
    limits: ProtocolLimits,
    output: &mut Vec<u8>,
) -> Result<(), MessageCodecError> {
    if endpoint.hostname.is_empty() && endpoint.resolved_addresses.is_empty() {
        return Err(MessageCodecError::InvalidField { field: "target" });
    }
    if !endpoint.hostname.is_empty() && std::str::from_utf8(&endpoint.hostname).is_err() {
        return Err(MessageCodecError::InvalidField { field: "hostname" });
    }
    if endpoint.port == 0 {
        return Err(MessageCodecError::InvalidField { field: "port" });
    }
    put_bytes(
        &endpoint.hostname,
        limits.max_target_name(),
        "hostname",
        output,
    )?;
    output.extend_from_slice(&endpoint.port.to_be_bytes());
    if endpoint.resolved_addresses.len() > MAX_ENDPOINT_ADDRESSES {
        return Err(MessageCodecError::TooManyItems {
            field: "resolved_addresses",
            count: endpoint.resolved_addresses.len(),
            maximum: MAX_ENDPOINT_ADDRESSES,
        });
    }
    put_varint(endpoint.resolved_addresses.len() as u64, output)?;
    for address in &endpoint.resolved_addresses {
        match address {
            IpAddr::V4(value) => {
                output.push(4);
                output.extend_from_slice(&value.octets());
            }
            IpAddr::V6(value) => {
                output.push(6);
                output.extend_from_slice(&value.octets());
            }
        }
    }
    Ok(())
}

fn get_endpoint(
    reader: &mut Reader<'_>,
    limits: ProtocolLimits,
) -> Result<TargetEndpoint, MessageCodecError> {
    let hostname = reader.bytes(limits.max_target_name(), "hostname")?;
    if !hostname.is_empty() && std::str::from_utf8(&hostname).is_err() {
        return Err(MessageCodecError::InvalidField { field: "hostname" });
    }
    let port = reader.u16("port")?;
    if port == 0 {
        return Err(MessageCodecError::InvalidField { field: "port" });
    }
    let count = reader.varint("resolved_address_count")? as usize;
    if count > MAX_ENDPOINT_ADDRESSES {
        return Err(MessageCodecError::TooManyItems {
            field: "resolved_addresses",
            count,
            maximum: MAX_ENDPOINT_ADDRESSES,
        });
    }
    if hostname.is_empty() && count == 0 {
        return Err(MessageCodecError::InvalidField { field: "target" });
    }
    let mut resolved_addresses = Vec::with_capacity(count);
    for _ in 0..count {
        let family = reader.byte("address_family")?;
        let address = match family {
            4 => IpAddr::V4(Ipv4Addr::from(
                <[u8; 4]>::try_from(reader.take(4, "ipv4")?).expect("four bytes checked"),
            )),
            6 => IpAddr::V6(Ipv6Addr::from(
                <[u8; 16]>::try_from(reader.take(16, "ipv6")?).expect("sixteen bytes checked"),
            )),
            code => return Err(MessageCodecError::InvalidAddressFamily { code }),
        };
        resolved_addresses.push(address);
    }
    Ok(TargetEndpoint {
        hostname,
        port,
        resolved_addresses,
    })
}

macro_rules! impl_simple_codec {
    ($ty:ty, $this:ident, $output:ident, $reader:ident, $encode:block, $decode:block) => {
        impl $ty {
            fn encode(&self, output: &mut Vec<u8>) -> Result<(), MessageCodecError> {
                let $this = self;
                let $output = output;
                $encode
            }

            fn decode($reader: &mut Reader<'_>) -> Result<Self, MessageCodecError> $decode
        }
    };
}

impl PathHello {
    fn encode(
        &self,
        output: &mut Vec<u8>,
        limits: ProtocolLimits,
    ) -> Result<(), MessageCodecError> {
        if self.version != crate::frame::WIRE_PROFILE_V1_VERSION {
            return Err(MessageCodecError::InvalidField { field: "version" });
        }
        put_varint(self.version.get(), output)?;
        put_varint(self.capabilities, output)?;
        put_id128(self.path_id.to_be_bytes(), output);
        put_bytes(
            &self.transport_metadata,
            limits.max_control_payload(),
            "transport_metadata",
            output,
        )
    }

    fn decode(reader: &mut Reader<'_>, limits: ProtocolLimits) -> Result<Self, MessageCodecError> {
        let version = ProtocolVersion::try_new(reader.varint("version")?)
            .map_err(MessageCodecError::VarInt)?;
        if version != crate::frame::WIRE_PROFILE_V1_VERSION {
            return Err(MessageCodecError::InvalidField { field: "version" });
        }
        let capabilities = reader.varint("capabilities")?;
        let path_id = PathId::from_be_bytes(reader.id128("path_id")?);
        let transport_metadata =
            reader.bytes(limits.max_control_payload(), "transport_metadata")?;
        Ok(Self {
            version,
            capabilities,
            path_id,
            transport_metadata,
        })
    }
}

impl SessionAttach {
    fn encode(
        &self,
        output: &mut Vec<u8>,
        limits: ProtocolLimits,
    ) -> Result<(), MessageCodecError> {
        if self.ingress_id.is_empty() {
            return Err(MessageCodecError::InvalidField {
                field: "ingress_id",
            });
        }
        if std::str::from_utf8(&self.ingress_id).is_err() {
            return Err(MessageCodecError::InvalidField {
                field: "ingress_id",
            });
        }
        if self.egress_id.is_empty() {
            return Err(MessageCodecError::InvalidField { field: "egress_id" });
        }
        if std::str::from_utf8(&self.egress_id).is_err() {
            return Err(MessageCodecError::InvalidField { field: "egress_id" });
        }
        put_bytes(
            &self.ingress_id,
            limits.max_target_name(),
            "ingress_id",
            output,
        )?;
        put_id128(self.session_id.to_be_bytes(), output);
        put_bytes(
            &self.egress_id,
            limits.max_target_name(),
            "egress_id",
            output,
        )?;
        put_varint(self.control_seq, output)
    }

    fn decode(reader: &mut Reader<'_>, limits: ProtocolLimits) -> Result<Self, MessageCodecError> {
        let ingress_id = reader.bytes(limits.max_target_name(), "ingress_id")?;
        let session_id = SessionId::from_be_bytes(reader.id128("session_id")?);
        let egress_id = reader.bytes(limits.max_target_name(), "egress_id")?;
        if ingress_id.is_empty() {
            return Err(MessageCodecError::InvalidField {
                field: "ingress_id",
            });
        }
        if std::str::from_utf8(&ingress_id).is_err() {
            return Err(MessageCodecError::InvalidField {
                field: "ingress_id",
            });
        }
        if egress_id.is_empty() {
            return Err(MessageCodecError::InvalidField { field: "egress_id" });
        }
        if std::str::from_utf8(&egress_id).is_err() {
            return Err(MessageCodecError::InvalidField { field: "egress_id" });
        }
        Ok(Self {
            ingress_id,
            session_id,
            egress_id,
            control_seq: reader.varint("control_seq")?,
        })
    }
}

impl_simple_codec!(
    SessionAttachOk,
    this,
    output,
    reader,
    { put_varint(this.authorization_generation, output) },
    {
        Ok(Self {
            authorization_generation: reader.varint("authorization_generation")?,
        })
    }
);

impl SessionAttachReject {
    fn encode(
        &self,
        output: &mut Vec<u8>,
        limits: ProtocolLimits,
    ) -> Result<(), MessageCodecError> {
        put_error(self.error, output);
        put_bytes(&self.reason, limits.max_control_payload(), "reason", output)
    }

    fn decode(reader: &mut Reader<'_>, limits: ProtocolLimits) -> Result<Self, MessageCodecError> {
        Ok(Self {
            error: get_error(reader)?,
            reason: reader.bytes(limits.max_control_payload(), "reason")?,
        })
    }
}

impl_simple_codec!(
    PathReady,
    this,
    output,
    reader,
    {
        validate_negotiated_limits(
            this.max_frame_payload,
            this.max_control_payload,
            this.max_session_buffering,
        )?;
        put_varint(this.max_frame_payload, output)?;
        put_varint(this.max_control_payload, output)?;
        put_varint(this.max_session_buffering, output)
    },
    {
        let value = Self {
            max_frame_payload: reader.varint("max_frame_payload")?,
            max_control_payload: reader.varint("max_control_payload")?,
            max_session_buffering: reader.varint("max_session_buffering")?,
        };
        validate_negotiated_limits(
            value.max_frame_payload,
            value.max_control_payload,
            value.max_session_buffering,
        )?;
        Ok(value)
    }
);

impl_simple_codec!(
    PathDrain,
    this,
    output,
    reader,
    {
        if this.drain_reason > 2 {
            return Err(MessageCodecError::InvalidField {
                field: "drain_reason",
            });
        }
        put_varint(this.drain_reason, output)?;
        put_varint(this.deadline_ms, output)
    },
    {
        let value = Self {
            drain_reason: reader.varint("drain_reason")?,
            deadline_ms: reader.varint("deadline_ms")?,
        };
        if value.drain_reason > 2 {
            return Err(MessageCodecError::InvalidField {
                field: "drain_reason",
            });
        }
        Ok(value)
    }
);

impl PathClose {
    fn encode(
        &self,
        output: &mut Vec<u8>,
        limits: ProtocolLimits,
    ) -> Result<(), MessageCodecError> {
        put_error(self.error, output);
        put_bytes(&self.reason, limits.max_control_payload(), "reason", output)
    }

    fn decode(reader: &mut Reader<'_>, limits: ProtocolLimits) -> Result<Self, MessageCodecError> {
        Ok(Self {
            error: get_error(reader)?,
            reason: reader.bytes(limits.max_control_payload(), "reason")?,
        })
    }
}

impl StatusReport {
    fn encode(&self, output: &mut Vec<u8>) -> Result<(), MessageCodecError> {
        validate_status_report(self)?;
        output.push(u8::from(self.connected));
        output.push(self.service_state.wire_code());
        output.extend_from_slice(&self.load_basis_points.to_be_bytes());
        output.extend_from_slice(&self.connection_utilization_basis_points.to_be_bytes());
        output.extend_from_slice(&self.bandwidth_utilization_basis_points.to_be_bytes());
        put_varint(self.active_sessions, output)?;
        put_varint(self.active_streams, output)?;
        put_varint(self.active_target_connections, output)?;
        put_varint(self.capacity_bps, output)?;
        put_varint(self.recommended_path_count, output)?;
        put_varint(self.report_seqno, output)?;
        put_varint(self.sample_age_ms, output)?;
        put_varint(self.expires_after_ms, output)
    }

    fn decode(reader: &mut Reader<'_>) -> Result<Self, MessageCodecError> {
        let connected = reader.bool("connected")?;
        let service_state = EgressServiceState::from_wire_code(reader.byte("service_state")?)
            .ok_or(MessageCodecError::InvalidField {
                field: "service_state",
            })?;
        let value = Self {
            connected,
            service_state,
            load_basis_points: reader.u16("load_basis_points")?,
            connection_utilization_basis_points: reader.u16("connection_utilization_bp")?,
            bandwidth_utilization_basis_points: reader.u16("bandwidth_utilization_bp")?,
            active_sessions: reader.varint("active_sessions")?,
            active_streams: reader.varint("active_streams")?,
            active_target_connections: reader.varint("active_target_connections")?,
            capacity_bps: reader.varint("capacity_bps")?,
            recommended_path_count: reader.varint("recommended_path_count")?,
            report_seqno: reader.varint("report_seqno")?,
            sample_age_ms: reader.varint("sample_age_ms")?,
            expires_after_ms: reader.varint("expires_after_ms")?,
        };
        validate_status_report(&value)?;
        Ok(value)
    }
}

impl_simple_codec!(
    Heartbeat,
    this,
    output,
    reader,
    { put_varint(this.control_seq, output) },
    {
        Ok(Self {
            control_seq: reader.varint("control_seq")?,
        })
    }
);

impl_simple_codec!(
    ControlAck,
    this,
    output,
    reader,
    {
        put_varint(this.highest_contiguous, output)?;
        put_ranges(&this.ranges, output)
    },
    {
        Ok(Self {
            highest_contiguous: reader.varint("highest_contiguous")?,
            ranges: get_ranges(reader)?,
        })
    }
);

impl SessionClose {
    fn encode(
        &self,
        output: &mut Vec<u8>,
        limits: ProtocolLimits,
    ) -> Result<(), MessageCodecError> {
        put_error(self.error, output);
        put_bytes(&self.reason, limits.max_control_payload(), "reason", output)
    }

    fn decode(reader: &mut Reader<'_>, limits: ProtocolLimits) -> Result<Self, MessageCodecError> {
        Ok(Self {
            error: get_error(reader)?,
            reason: reader.bytes(limits.max_control_payload(), "reason")?,
        })
    }
}

impl StreamOpen {
    fn encode(
        &self,
        output: &mut Vec<u8>,
        limits: ProtocolLimits,
    ) -> Result<(), MessageCodecError> {
        put_id128(self.request_id.to_be_bytes(), output);
        put_stream_id(self.stream_id, output)?;
        put_endpoint(&self.target, limits, output)
    }

    fn decode(reader: &mut Reader<'_>, limits: ProtocolLimits) -> Result<Self, MessageCodecError> {
        Ok(Self {
            request_id: RequestId::from_be_bytes(reader.id128("request_id")?),
            stream_id: get_stream_id(reader)?,
            target: get_endpoint(reader, limits)?,
        })
    }
}

impl StreamOpenOk {
    fn encode(
        &self,
        output: &mut Vec<u8>,
        limits: ProtocolLimits,
    ) -> Result<(), MessageCodecError> {
        put_stream_id(self.stream_id, output)?;
        put_bytes(
            &self.result_metadata,
            limits.max_control_payload(),
            "result_metadata",
            output,
        )
    }

    fn decode(reader: &mut Reader<'_>, limits: ProtocolLimits) -> Result<Self, MessageCodecError> {
        Ok(Self {
            stream_id: get_stream_id(reader)?,
            result_metadata: reader.bytes(limits.max_control_payload(), "result_metadata")?,
        })
    }
}

impl StreamOpenErr {
    fn encode(
        &self,
        output: &mut Vec<u8>,
        limits: ProtocolLimits,
    ) -> Result<(), MessageCodecError> {
        put_stream_id(self.stream_id, output)?;
        put_error(self.error, output);
        put_bytes(&self.reason, limits.max_control_payload(), "reason", output)
    }

    fn decode(reader: &mut Reader<'_>, limits: ProtocolLimits) -> Result<Self, MessageCodecError> {
        Ok(Self {
            stream_id: get_stream_id(reader)?,
            error: get_error(reader)?,
            reason: reader.bytes(limits.max_control_payload(), "reason")?,
        })
    }
}

impl StreamData {
    fn encode(
        &self,
        output: &mut Vec<u8>,
        limits: ProtocolLimits,
    ) -> Result<(), MessageCodecError> {
        let end = self
            .offset
            .checked_add(self.data.len() as u64)
            .ok_or(MessageCodecError::InvalidField { field: "offset" })?;
        if end > MAX_VARINT {
            return Err(MessageCodecError::InvalidField { field: "offset" });
        }
        validate_stream_flags(self.flags)?;
        put_stream_id(self.stream_id, output)?;
        put_varint(self.offset, output)?;
        put_varint(self.flags, output)?;
        put_bytes(&self.data, limits.max_frame_payload(), "data", output)
    }

    fn decode(reader: &mut Reader<'_>, limits: ProtocolLimits) -> Result<Self, MessageCodecError> {
        let stream_id = get_stream_id(reader)?;
        let offset = reader.varint("offset")?;
        let flags = reader.varint("flags")?;
        let data = reader.bytes(limits.max_frame_payload(), "data")?;
        let end = offset
            .checked_add(data.len() as u64)
            .ok_or(MessageCodecError::InvalidField { field: "offset" })?;
        if end > MAX_VARINT {
            return Err(MessageCodecError::InvalidField { field: "offset" });
        }
        validate_stream_flags(flags)?;
        Ok(Self {
            stream_id,
            offset,
            flags,
            data,
        })
    }
}

impl_simple_codec!(
    StreamAck,
    this,
    output,
    reader,
    {
        put_stream_id(this.stream_id, output)?;
        put_ranges(&this.ranges, output)
    },
    {
        Ok(Self {
            stream_id: get_stream_id(reader)?,
            ranges: get_ranges(reader)?,
        })
    }
);

impl_simple_codec!(
    StreamWindow,
    this,
    output,
    reader,
    {
        put_stream_id(this.stream_id, output)?;
        put_varint(this.stream_limit, output)?;
        put_varint(this.session_limit, output)
    },
    {
        Ok(Self {
            stream_id: get_stream_id(reader)?,
            stream_limit: reader.varint("stream_limit")?,
            session_limit: reader.varint("session_limit")?,
        })
    }
);

impl_simple_codec!(
    StreamFin,
    this,
    output,
    reader,
    {
        validate_stream_flags(this.flags)?;
        put_stream_id(this.stream_id, output)?;
        put_varint(this.flags, output)
    },
    {
        let value = Self {
            stream_id: get_stream_id(reader)?,
            flags: reader.varint("flags")?,
        };
        validate_stream_flags(value.flags)?;
        Ok(value)
    }
);

impl StreamRst {
    fn encode(
        &self,
        output: &mut Vec<u8>,
        limits: ProtocolLimits,
    ) -> Result<(), MessageCodecError> {
        put_stream_id(self.stream_id, output)?;
        put_error(self.error, output);
        put_bytes(&self.reason, limits.max_control_payload(), "reason", output)
    }

    fn decode(reader: &mut Reader<'_>, limits: ProtocolLimits) -> Result<Self, MessageCodecError> {
        Ok(Self {
            stream_id: get_stream_id(reader)?,
            error: get_error(reader)?,
            reason: reader.bytes(limits.max_control_payload(), "reason")?,
        })
    }
}

impl UdpOpen {
    fn encode(
        &self,
        output: &mut Vec<u8>,
        limits: ProtocolLimits,
    ) -> Result<(), MessageCodecError> {
        const HOSTNAME: u64 = 1;
        const CANDIDATES: u64 = 2;
        if self.target_flags & !(HOSTNAME | CANDIDATES) != 0
            || self.target_flags == 0
            || self.target.port == 0
            || (self.target_flags & HOSTNAME == 0 && !self.target.hostname.is_empty())
            || (self.target_flags & CANDIDATES == 0 && !self.target.resolved_addresses.is_empty())
            || (self.target_flags & HOSTNAME != 0 && self.target.hostname.is_empty())
            || (self.target_flags & CANDIDATES != 0 && self.target.resolved_addresses.is_empty())
        {
            return Err(MessageCodecError::InvalidField {
                field: "target_flags",
            });
        }
        if self.target.resolved_addresses.len() > MAX_ENDPOINT_ADDRESSES {
            return Err(MessageCodecError::TooManyItems {
                field: "resolved_addresses",
                count: self.target.resolved_addresses.len(),
                maximum: MAX_ENDPOINT_ADDRESSES,
            });
        }
        put_varint(self.association_id, output)?;
        put_varint(self.target_flags, output)?;
        if self.target_flags & HOSTNAME != 0 {
            put_bytes(
                &self.target.hostname,
                limits.max_target_name(),
                "hostname",
                output,
            )?;
        }
        output.extend_from_slice(&self.target.port.to_be_bytes());
        put_varint(self.target.resolved_addresses.len() as u64, output)?;
        if self.target_flags & CANDIDATES != 0 {
            for address in &self.target.resolved_addresses {
                match address {
                    IpAddr::V4(value) => {
                        output.push(4);
                        output.extend_from_slice(&value.octets());
                    }
                    IpAddr::V6(value) => {
                        output.push(6);
                        output.extend_from_slice(&value.octets());
                    }
                }
            }
        }
        Ok(())
    }

    fn decode(reader: &mut Reader<'_>, limits: ProtocolLimits) -> Result<Self, MessageCodecError> {
        const HOSTNAME: u64 = 1;
        const CANDIDATES: u64 = 2;
        let association_id = reader.varint("association_id")?;
        let target_flags = reader.varint("target_flags")?;
        if target_flags & !(HOSTNAME | CANDIDATES) != 0 || target_flags == 0 {
            return Err(MessageCodecError::InvalidField {
                field: "target_flags",
            });
        }
        let hostname = if target_flags & HOSTNAME != 0 {
            reader.bytes(limits.max_target_name(), "hostname")?
        } else {
            Vec::new()
        };
        if target_flags & HOSTNAME != 0 && hostname.is_empty() {
            return Err(MessageCodecError::InvalidField { field: "hostname" });
        }
        if !hostname.is_empty() && std::str::from_utf8(&hostname).is_err() {
            return Err(MessageCodecError::InvalidField { field: "hostname" });
        }
        let port = reader.u16("port")?;
        if port == 0 {
            return Err(MessageCodecError::InvalidField { field: "port" });
        }
        let count = reader.varint("candidate_count")? as usize;
        if count > MAX_ENDPOINT_ADDRESSES
            || (target_flags & CANDIDATES == 0 && count != 0)
            || (target_flags & CANDIDATES != 0 && count == 0)
        {
            return Err(MessageCodecError::InvalidField {
                field: "candidate_count",
            });
        }
        let mut resolved_addresses = Vec::with_capacity(count);
        for _ in 0..count {
            let family = reader.byte("address_family")?;
            let address = match family {
                4 => IpAddr::V4(Ipv4Addr::from(
                    <[u8; 4]>::try_from(reader.take(4, "ipv4")?).expect("four bytes checked"),
                )),
                6 => IpAddr::V6(Ipv6Addr::from(
                    <[u8; 16]>::try_from(reader.take(16, "ipv6")?).expect("sixteen bytes checked"),
                )),
                code => return Err(MessageCodecError::InvalidAddressFamily { code }),
            };
            resolved_addresses.push(address);
        }
        Ok(Self {
            association_id,
            target_flags,
            target: TargetEndpoint {
                hostname,
                port,
                resolved_addresses,
            },
        })
    }
}

impl_simple_codec!(
    UdpOpenOk,
    this,
    output,
    reader,
    {
        if this.target_visible_port == 0 {
            return Err(MessageCodecError::InvalidField {
                field: "target_visible_port",
            });
        }
        put_varint(this.association_id, output)?;
        output.extend_from_slice(&this.target_visible_port.to_be_bytes());
        Ok(())
    },
    {
        let value = Self {
            association_id: reader.varint("association_id")?,
            target_visible_port: reader.u16("target_visible_port")?,
        };
        if value.target_visible_port == 0 {
            return Err(MessageCodecError::InvalidField {
                field: "target_visible_port",
            });
        }
        Ok(value)
    }
);

impl UdpOpenErr {
    fn encode(
        &self,
        output: &mut Vec<u8>,
        limits: ProtocolLimits,
    ) -> Result<(), MessageCodecError> {
        put_varint(self.association_id, output)?;
        put_error(self.error, output);
        put_bytes(&self.reason, limits.max_control_payload(), "reason", output)
    }

    fn decode(reader: &mut Reader<'_>, limits: ProtocolLimits) -> Result<Self, MessageCodecError> {
        Ok(Self {
            association_id: reader.varint("association_id")?,
            error: get_error(reader)?,
            reason: reader.bytes(limits.max_control_payload(), "reason")?,
        })
    }
}

impl UdpDatagram {
    fn encode(
        &self,
        output: &mut Vec<u8>,
        limits: ProtocolLimits,
    ) -> Result<(), MessageCodecError> {
        put_varint(self.association_id, output)?;
        put_varint(self.datagram_seq, output)?;
        put_bytes(&self.payload, limits.max_frame_payload(), "payload", output)
    }

    fn decode(reader: &mut Reader<'_>, limits: ProtocolLimits) -> Result<Self, MessageCodecError> {
        Ok(Self {
            association_id: reader.varint("association_id")?,
            datagram_seq: reader.varint("datagram_seq")?,
            payload: reader.bytes(limits.max_frame_payload(), "payload")?,
        })
    }
}

impl UdpClose {
    fn encode(
        &self,
        output: &mut Vec<u8>,
        limits: ProtocolLimits,
    ) -> Result<(), MessageCodecError> {
        put_varint(self.association_id, output)?;
        put_error(self.error, output);
        put_bytes(&self.reason, limits.max_control_payload(), "reason", output)
    }

    fn decode(reader: &mut Reader<'_>, limits: ProtocolLimits) -> Result<Self, MessageCodecError> {
        Ok(Self {
            association_id: reader.varint("association_id")?,
            error: get_error(reader)?,
            reason: reader.bytes(limits.max_control_payload(), "reason")?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{FrameType, ProtocolLimits};

    fn endpoint() -> TargetEndpoint {
        TargetEndpoint {
            hostname: b"example.test".to_vec(),
            port: 443,
            resolved_addresses: vec!["192.0.2.1".parse().unwrap(), "2001:db8::1".parse().unwrap()],
        }
    }

    #[test]
    fn stream_open_payload_has_a_golden_vector() {
        let message = Message::StreamOpen(StreamOpen {
            stream_id: StreamId::new(7).unwrap(),
            request_id: RequestId::new(0x1122),
            target: endpoint(),
        });
        let encoded = message.encode(ProtocolLimits::default()).unwrap();
        let decoded =
            Message::decode(FrameType::StreamOpen, &encoded, ProtocolLimits::default()).unwrap();
        assert_eq!(decoded, message);
        assert_eq!(&encoded[..16], &RequestId::new(0x1122).to_be_bytes());
        assert_eq!(encoded[16], 7);
    }

    #[test]
    fn malformed_payloads_are_rejected_before_allocation() {
        let limits = ProtocolLimits::default();
        assert!(matches!(
            Message::decode(FrameType::Heartbeat, &[0x40], limits),
            Err(MessageCodecError::VarInt(VarIntError::Truncated { .. }))
        ));

        let mut encoded = Message::Heartbeat(Heartbeat { control_seq: 3 })
            .encode(limits)
            .unwrap();
        encoded.push(0);
        assert!(matches!(
            Message::decode(FrameType::Heartbeat, &encoded, limits),
            Err(MessageCodecError::Trailing { remaining: 1 })
        ));
    }

    #[test]
    fn target_without_hostname_or_candidates_is_rejected_on_decode() {
        let mut payload = vec![7];
        payload.extend_from_slice(&RequestId::new(1).to_be_bytes());
        payload.push(0);
        payload.extend_from_slice(&443_u16.to_be_bytes());
        payload.push(0);
        assert_eq!(
            Message::decode(FrameType::StreamOpen, &payload, ProtocolLimits::default()),
            Err(MessageCodecError::InvalidField { field: "target" })
        );
    }

    #[test]
    fn session_attach_ids_must_be_utf8() {
        let invalid = Message::SessionAttach(SessionAttach {
            ingress_id: vec![0xff],
            session_id: SessionId::new(1),
            egress_id: b"egress".to_vec(),
            control_seq: 0,
        });
        assert_eq!(
            invalid.encode(ProtocolLimits::default()),
            Err(MessageCodecError::InvalidField {
                field: "ingress_id"
            })
        );

        let mut payload = vec![1, 0xff];
        payload.extend_from_slice(&SessionId::new(1).to_be_bytes());
        payload.push(6);
        payload.extend_from_slice(b"egress");
        payload.push(0);
        assert_eq!(
            Message::decode(
                FrameType::SessionAttach,
                &payload,
                ProtocolLimits::default()
            ),
            Err(MessageCodecError::InvalidField {
                field: "ingress_id"
            })
        );
    }

    #[test]
    fn status_reports_are_monotonic_and_freshness_bounded() {
        let report = |sequence, age| StatusReport {
            connected: true,
            service_state: EgressServiceState::Up,
            load_basis_points: 0,
            connection_utilization_basis_points: 0,
            bandwidth_utilization_basis_points: 0,
            active_sessions: 0,
            active_streams: 0,
            active_target_connections: 0,
            capacity_bps: 1,
            recommended_path_count: 1,
            report_seqno: sequence,
            sample_age_ms: age,
            expires_after_ms: 100,
        };
        let mut tracker = StatusReportTracker::new();
        assert_eq!(
            tracker.apply(report(2, 10)),
            StatusReportDisposition::Accepted
        );
        assert_eq!(
            tracker.apply(report(2, 10)),
            StatusReportDisposition::Duplicate
        );
        assert_eq!(tracker.apply(report(1, 10)), StatusReportDisposition::Stale);
        assert_eq!(
            tracker.apply(report(3, 101)),
            StatusReportDisposition::Expired
        );
        assert_eq!(tracker.latest().expect("latest").report_seqno, 2);
    }

    #[test]
    fn all_v1_message_kinds_round_trip() {
        let limits = ProtocolLimits::default();
        let messages = vec![
            Message::PathHello(PathHello {
                version: ProtocolVersion::try_new(1).unwrap(),
                capabilities: 3,
                path_id: PathId::new(4),
                transport_metadata: b"direct".to_vec(),
            }),
            Message::SessionAttach(SessionAttach {
                ingress_id: b"ingress".to_vec(),
                session_id: SessionId::new(5),
                egress_id: b"egress".to_vec(),
                control_seq: 6,
            }),
            Message::SessionAttachOk(SessionAttachOk {
                authorization_generation: 7,
            }),
            Message::SessionAttachReject(SessionAttachReject {
                error: ErrorClass::LocalPolicy,
                reason: b"denied".to_vec(),
            }),
            Message::PathReady(PathReady {
                max_frame_payload: 1024,
                max_control_payload: 512,
                max_session_buffering: 4096,
            }),
            Message::PathDrain(PathDrain {
                drain_reason: 1,
                deadline_ms: 500,
            }),
            Message::PathClose(PathClose {
                error: ErrorClass::PathFailure,
                reason: b"drained".to_vec(),
            }),
            Message::StatusReport(StatusReport {
                connected: true,
                service_state: EgressServiceState::Up,
                load_basis_points: 100,
                connection_utilization_basis_points: 200,
                bandwidth_utilization_basis_points: 300,
                active_sessions: 1,
                active_streams: 2,
                active_target_connections: 3,
                capacity_bps: 4,
                recommended_path_count: 5,
                report_seqno: 6,
                sample_age_ms: 7,
                expires_after_ms: 1000,
            }),
            Message::Heartbeat(Heartbeat { control_seq: 8 }),
            Message::ControlAck(ControlAck {
                highest_contiguous: 9,
                ranges: vec![AckRange { start: 11, end: 12 }],
            }),
            Message::SessionClose(SessionClose {
                error: ErrorClass::EgressFailure,
                reason: b"offline".to_vec(),
            }),
            Message::StreamOpen(StreamOpen {
                stream_id: StreamId::new(13).unwrap(),
                request_id: RequestId::new(14),
                target: endpoint(),
            }),
            Message::StreamOpenOk(StreamOpenOk {
                stream_id: StreamId::new(13).unwrap(),
                result_metadata: b"ok".to_vec(),
            }),
            Message::StreamOpenErr(StreamOpenErr {
                stream_id: StreamId::new(13).unwrap(),
                error: ErrorClass::TargetFailure,
                reason: b"refused".to_vec(),
            }),
            Message::StreamData(StreamData {
                stream_id: StreamId::new(13).unwrap(),
                offset: 15,
                flags: 0,
                data: b"bytes".to_vec(),
            }),
            Message::StreamAck(StreamAck {
                stream_id: StreamId::new(13).unwrap(),
                ranges: vec![AckRange { start: 0, end: 4 }],
            }),
            Message::StreamWindow(StreamWindow {
                stream_id: StreamId::new(13).unwrap(),
                stream_limit: 16,
                session_limit: 17,
            }),
            Message::StreamFin(StreamFin {
                stream_id: StreamId::new(13).unwrap(),
                flags: 1,
            }),
            Message::StreamRst(StreamRst {
                stream_id: StreamId::new(13).unwrap(),
                error: ErrorClass::PathFailure,
                reason: b"reset".to_vec(),
            }),
            Message::UdpOpen(UdpOpen {
                association_id: 18,
                target_flags: 3,
                target: endpoint(),
            }),
            Message::UdpOpenOk(UdpOpenOk {
                association_id: 18,
                target_visible_port: 5353,
            }),
            Message::UdpOpenErr(UdpOpenErr {
                association_id: 18,
                error: ErrorClass::TargetFailure,
                reason: b"unreachable".to_vec(),
            }),
            Message::UdpDatagram(UdpDatagram {
                association_id: 18,
                datagram_seq: 19,
                payload: b"datagram".to_vec(),
            }),
            Message::UdpClose(UdpClose {
                association_id: 18,
                error: ErrorClass::EgressFailure,
                reason: b"closed".to_vec(),
            }),
        ];
        for message in messages {
            let frame_type = message.frame_type();
            let encoded = message.encode(limits).unwrap();
            assert_eq!(
                Message::decode(frame_type, &encoded, limits).unwrap(),
                message
            );
        }
    }

    #[test]
    fn lifecycle_payloads_are_decoded_by_the_v1_registry() {
        assert!(matches!(
            Message::decode(FrameType::PathDrain, &[], ProtocolLimits::default()),
            Err(MessageCodecError::VarInt(VarIntError::Truncated { .. }))
        ));
    }
}
