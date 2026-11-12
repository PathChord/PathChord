//! Platform-independent protocol primitives for PathChord.
//!
//! This crate deliberately contains no listener, operating-system, transport,
//! subscription, or asynchronous runtime integration. The numeric wire values
//! exposed by the bootstrap codec are experimental and are not yet a stable
//! interoperability contract.

mod error;
mod frame;
mod id;
mod limits;
mod state;
mod varint;

pub use error::{ErrorClass, UnknownErrorClass};
pub use frame::{
    EXPERIMENTAL_PROTOCOL_VERSION, FrameCodecError, FrameFlags, FrameType, PathFrame,
    PathFrameHeader, ProtocolVersion,
};
pub use id::{IdError, PathId, RequestId, SessionId, StreamId};
pub use limits::{LimitsError, ProtocolLimits};
pub use state::{
    EgressRelationshipState, EgressRuntime, EgressServiceState, PathState, SessionState,
    StateTransitionError, StreamState,
};
pub use varint::{
    MAX_VARINT, VarIntError, decode_varint, decode_varint_exact, encode_varint, encoded_varint_len,
};
