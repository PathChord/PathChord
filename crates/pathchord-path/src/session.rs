//! Asynchronous single-Path Stream session loops.
//!
//! These owners deliberately handle only one admitted Path and TCP Stream
//! control exchange. Session lifecycle replacement, retransmission timers,
//! multipath scheduling, and UDP remain above this boundary.

use pathchord_core::{
    FrameCodecError, FrameFlags, Message, MessageCodecError, PathFrame, PathId, ProtocolLimits,
    SessionId, StreamOpen,
};
use thiserror::Error;

use crate::{CompleteFrameTransport, StreamOpenDecision, StreamOpener};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PathSessionConfig {
    pub session_id: SessionId,
    pub path_id: PathId,
    pub limits: ProtocolLimits,
}

#[derive(Debug, Error)]
pub enum PathSessionError {
    #[error("Path transport failed: {0}")]
    Transport(String),
    #[error("Path frame failed: {0}")]
    Frame(#[from] FrameCodecError),
    #[error("Path message failed: {0}")]
    Message(#[from] MessageCodecError),
    #[error("Path session received a frame for another Session or Path")]
    WrongPathIdentity,
    #[error("Path session received an unexpected message")]
    UnexpectedMessage,
    #[error("Path session frame sequence is exhausted")]
    FrameSequenceExhausted,
    #[error("Stream opener failed: {0}")]
    Opener(String),
}

pub struct IngressPathSession<T> {
    transport: T,
    config: PathSessionConfig,
    next_frame_seq: u64,
}

impl<T> std::fmt::Debug for IngressPathSession<T>
where
    T: std::fmt::Debug,
{
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("IngressPathSession")
            .field("transport", &self.transport)
            .field("config", &self.config)
            .field("next_frame_seq", &self.next_frame_seq)
            .finish()
    }
}

impl<T> IngressPathSession<T>
where
    T: CompleteFrameTransport,
{
    #[must_use]
    pub const fn new(transport: T, config: PathSessionConfig, next_frame_seq: u64) -> Self {
        Self {
            transport,
            config,
            next_frame_seq,
        }
    }

    pub fn into_transport(self) -> T {
        self.transport
    }

    /// Sends one `STREAM_OPEN` and waits for its matching result.
    pub async fn open_stream(
        &mut self,
        request: StreamOpen,
    ) -> Result<StreamOpenDecision, PathSessionError> {
        let frame = self.make_frame(Message::StreamOpen(request.clone()))?;
        self.transport
            .send_frame(frame)
            .await
            .map_err(|error| PathSessionError::Transport(error.to_string()))?;
        loop {
            let Some(frame) = self
                .transport
                .receive_frame()
                .await
                .map_err(|error| PathSessionError::Transport(error.to_string()))?
            else {
                return Err(PathSessionError::Transport("Path transport closed".into()));
            };
            self.validate_identity(&frame)?;
            let message = Message::decode(
                frame.header().frame_type(),
                frame.payload(),
                self.config.limits,
            )?;
            match message {
                Message::StreamOpenOk(value) if value.stream_id == request.stream_id => {
                    return Ok(StreamOpenDecision::Opened {
                        metadata: value.result_metadata,
                    });
                }
                Message::StreamOpenErr(value) if value.stream_id == request.stream_id => {
                    return Ok(StreamOpenDecision::Rejected {
                        error: value.error,
                        reason: value.reason,
                    });
                }
                _ => return Err(PathSessionError::UnexpectedMessage),
            }
        }
    }

    fn make_frame(&mut self, message: Message) -> Result<PathFrame, PathSessionError> {
        let sequence = self.next_frame_seq;
        if sequence > pathchord_core::MAX_VARINT {
            return Err(PathSessionError::FrameSequenceExhausted);
        }
        self.next_frame_seq = self
            .next_frame_seq
            .checked_add(1)
            .ok_or(PathSessionError::FrameSequenceExhausted)?;
        let payload = message.encode(self.config.limits)?;
        Ok(PathFrame::new(
            message.frame_type(),
            FrameFlags::empty(),
            self.config.session_id,
            self.config.path_id,
            sequence,
            payload,
            self.config.limits,
        )?)
    }

    fn validate_identity(&self, frame: &PathFrame) -> Result<(), PathSessionError> {
        if frame.header().session_id() != self.config.session_id
            || frame.header().path_id() != self.config.path_id
        {
            return Err(PathSessionError::WrongPathIdentity);
        }
        Ok(())
    }
}

pub struct EgressPathSession<T, O> {
    transport: T,
    opener: O,
    config: PathSessionConfig,
    next_frame_seq: u64,
}

impl<T, O> std::fmt::Debug for EgressPathSession<T, O>
where
    T: std::fmt::Debug,
    O: std::fmt::Debug,
{
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("EgressPathSession")
            .field("transport", &self.transport)
            .field("config", &self.config)
            .field("next_frame_seq", &self.next_frame_seq)
            .finish_non_exhaustive()
    }
}

impl<T, O> EgressPathSession<T, O>
where
    T: CompleteFrameTransport,
    O: StreamOpener,
{
    #[must_use]
    pub const fn new(
        transport: T,
        opener: O,
        config: PathSessionConfig,
        next_frame_seq: u64,
    ) -> Self {
        Self {
            transport,
            opener,
            config,
            next_frame_seq,
        }
    }

    pub fn into_parts(self) -> (T, O) {
        (self.transport, self.opener)
    }

    /// Receives and serves one frame. `Ok(None)` means the transport closed.
    pub async fn serve_once(&mut self) -> Result<Option<StreamOpenDecision>, PathSessionError> {
        let Some(frame) = self
            .transport
            .receive_frame()
            .await
            .map_err(|error| PathSessionError::Transport(error.to_string()))?
        else {
            return Ok(None);
        };
        self.validate_identity(&frame)?;
        let message = Message::decode(
            frame.header().frame_type(),
            frame.payload(),
            self.config.limits,
        )?;
        let Message::StreamOpen(request) = message else {
            return Err(PathSessionError::UnexpectedMessage);
        };
        let decision = match self.opener.open_stream(request.clone()).await {
            Ok(decision) => decision,
            Err(error) => StreamOpenDecision::Rejected {
                error: pathchord_core::ErrorClass::TargetFailure,
                reason: error.to_string().into_bytes(),
            },
        };
        let response = match &decision {
            StreamOpenDecision::Opened { metadata } => {
                Message::StreamOpenOk(pathchord_core::StreamOpenOk {
                    stream_id: request.stream_id,
                    result_metadata: metadata.clone(),
                })
            }
            StreamOpenDecision::Rejected { error, reason } => {
                Message::StreamOpenErr(pathchord_core::StreamOpenErr {
                    stream_id: request.stream_id,
                    error: *error,
                    reason: reason.clone(),
                })
            }
        };
        let response_frame = self.make_frame(response)?;
        self.transport
            .send_frame(response_frame)
            .await
            .map_err(|error| PathSessionError::Transport(error.to_string()))?;
        Ok(Some(decision))
    }

    fn make_frame(&mut self, message: Message) -> Result<PathFrame, PathSessionError> {
        let sequence = self.next_frame_seq;
        if sequence > pathchord_core::MAX_VARINT {
            return Err(PathSessionError::FrameSequenceExhausted);
        }
        self.next_frame_seq = self
            .next_frame_seq
            .checked_add(1)
            .ok_or(PathSessionError::FrameSequenceExhausted)?;
        let payload = message.encode(self.config.limits)?;
        Ok(PathFrame::new(
            message.frame_type(),
            FrameFlags::empty(),
            self.config.session_id,
            self.config.path_id,
            sequence,
            payload,
            self.config.limits,
        )?)
    }

    fn validate_identity(&self, frame: &PathFrame) -> Result<(), PathSessionError> {
        if frame.header().session_id() != self.config.session_id
            || frame.header().path_id() != self.config.path_id
        {
            return Err(PathSessionError::WrongPathIdentity);
        }
        Ok(())
    }
}
