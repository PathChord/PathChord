//! Platform-independent protocol primitives for PathChord.
//!
//! This crate deliberately contains no listener, operating-system, transport,
//! subscription, or asynchronous runtime integration. Its frame and payload
//! values implement wire-profile-v1; its management module defines the shared,
//! transport-independent local control envelope.

mod error;
mod frame;
mod id;
mod limits;
pub mod management;
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
    AdmissionReason, CAPABILITY_TCP_STREAM, CAPABILITY_UDP_SESSION, CapacityState, ControlAck,
    Heartbeat, Message, MessageCodecError, PathClose, PathDrain, PathHello, PathReady,
    PathReadyCapabilities, SessionAttach, SessionAttachOk, SessionAttachReject, SessionClose,
    SessionControl, SessionControlCancel, SessionControlFlow, StatusReport,
    StatusReportDisposition, StatusReportTracker, StreamAck, StreamData, StreamFin, StreamOpen,
    StreamOpenErr, StreamOpenOk, StreamRst, StreamWindow, TargetEndpoint, TrafficClassConfig,
    UdpClose, UdpDatagram, UdpOpen, UdpOpenErr, UdpOpenOk,
};
pub use reliability::{
    AckRange, ControlReceiver, ControlSender, ReliabilityError, StreamInsertResult,
    StreamReceiveBuffer,
};
pub use state::{
    EgressRelationshipState, EgressRuntime, EgressServiceState, LifecycleEntity, LifecycleState,
    LifecycleTransitionEvent, PathState, SessionPathLifecycle, SessionState, StateTransitionError,
    StreamState,
};
pub use varint::{
    MAX_VARINT, VarIntError, decode_varint, decode_varint_exact, encode_varint, encoded_varint_len,
};
