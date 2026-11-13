//! Platform-independent protocol primitives for PathChord.
//!
//! This crate deliberately contains no listener, operating-system, transport,
//! subscription, or asynchronous runtime integration. Its frame and payload
//! values implement the stable wire-profile-v1 contract.

mod error;
mod frame;
mod id;
mod limits;
mod messages;
mod reliability;
mod state;
mod varint;

pub use error::{ErrorClass, UnknownErrorClass};
pub use frame::{
    FrameCodecError, FrameFlags, FrameType, PathFrame, PathFrameHeader, ProtocolVersion,
    WIRE_PROFILE_V1_VERSION,
};
pub use id::{IdError, PathId, RequestId, SessionId, StreamId};
pub use limits::{LimitsError, ProtocolLimits};
pub use messages::{
    ControlAck, Heartbeat, Message, MessageCodecError, PathClose, PathDrain, PathHello, PathReady,
    SessionAttach, SessionAttachOk, SessionAttachReject, SessionClose, StatusReport,
    StatusReportDisposition, StatusReportTracker, StreamAck, StreamData, StreamFin, StreamOpen,
    StreamOpenErr, StreamOpenOk, StreamRst, StreamWindow, TargetEndpoint, UdpClose, UdpDatagram,
    UdpOpen, UdpOpenErr, UdpOpenOk,
};
pub use reliability::{
    AckRange, ControlReceiver, ControlSender, ReliabilityError, StreamInsertResult,
    StreamReceiveBuffer,
};
pub use state::{
    EgressRelationshipState, EgressRuntime, EgressServiceState, PathState, SessionState,
    StateTransitionError, StreamState,
};
pub use varint::{
    MAX_VARINT, VarIntError, decode_varint, decode_varint_exact, encode_varint, encoded_varint_len,
};
