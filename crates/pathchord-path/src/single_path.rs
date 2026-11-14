//! Deterministic single-Path handshake orchestration.
//!
//! This module intentionally stops at `PATH_READY`: it combines the existing
//! Noise and wire-profile primitives so a future Transit adapter can provide
//! records without duplicating admission rules. It does not own sockets,
//! scheduling, or target Streams.

use std::collections::HashMap;

use async_trait::async_trait;
use pathchord_core::{
    ErrorClass, FrameCodecError, FrameFlags, Message, MessageCodecError, PathFrame, PathHello,
    PathId, PathReady, ProtocolLimits, RequestId, SessionAttach, SessionId, StreamId, StreamOpen,
};
use pathchord_noise::{
    InitiatorHandshake, NoiseError, NoiseTransport, ResponderHandshake, STATIC_KEY_LEN,
    WIRE_PROFILE_V1_PROLOGUE_PREFIX,
};
use thiserror::Error;

/// Authorization state visible to the Egress-side Path admission gate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthorizationState {
    Enabled,
    Disabled,
    Revoked,
}

/// One static Ingress authorization record used by the deterministic harness.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PathAuthorization {
    pub ingress_id: Vec<u8>,
    pub public_key: [u8; STATIC_KEY_LEN],
    pub state: AuthorizationState,
    pub generation: u64,
}

/// Inputs for one exact Noise -> PATH_HELLO -> SESSION_ATTACH exchange.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SinglePathHandshakeConfig {
    /// Complete `PathChord/wire-v1/egress/<id>` prologue bytes.
    pub egress_identity: Vec<u8>,
    /// Canonical EgressID carried by `SESSION_ATTACH`.
    pub egress_id: Vec<u8>,
    /// IngressID carried by `SESSION_ATTACH`.
    pub ingress_id: Vec<u8>,
    pub session_id: SessionId,
    pub path_id: PathId,
    /// Capability bits offered by the Ingress in `PATH_HELLO`.
    pub offered_capabilities: u64,
    /// Capability bits required by the selected Egress policy.
    pub required_capabilities: u64,
    /// Session-wide extra replication cap negotiated by both endpoints.
    pub replication_budget_bytes_per_second: u64,
    /// Capability bits supported by the Egress.
    pub supported_capabilities: u64,
    /// Local hard/negotiated limits used to validate the `PATH_READY` offer.
    pub local_limits: ProtocolLimits,
    /// Limits declared by the Egress in `PATH_READY`.
    pub ready_limits: PathReady,
}

/// A successfully admitted single Path. The transport pair is retained so the
/// caller can continue with frame-level tests or a real Transit adapter.
pub struct SinglePathReady {
    initiator_transport: NoiseTransport,
    responder_transport: NoiseTransport,
    session_id: SessionId,
    path_id: PathId,
    local_limits: ProtocolLimits,
    negotiated_capabilities: u64,
    authorization_generation: u64,
    replication_budget_bytes_per_second: u64,
    limits: PathReady,
    stream_requests: HashMap<RequestId, CachedStreamOpen>,
    stream_ids: HashMap<StreamId, RequestId>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CachedStreamOpen {
    request: StreamOpen,
    decision: StreamOpenDecision,
}

impl std::fmt::Debug for SinglePathReady {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SinglePathReady")
            .field("negotiated_capabilities", &self.negotiated_capabilities)
            .field("authorization_generation", &self.authorization_generation)
            .field("limits", &self.limits)
            .finish_non_exhaustive()
    }
}

impl SinglePathReady {
    #[must_use]
    pub const fn negotiated_capabilities(&self) -> u64 {
        self.negotiated_capabilities
    }

    #[must_use]
    pub const fn authorization_generation(&self) -> u64 {
        self.authorization_generation
    }

    #[must_use]
    pub const fn replication_budget_bytes_per_second(&self) -> u64 {
        self.replication_budget_bytes_per_second
    }

    #[must_use]
    pub fn limits(&self) -> PathReady {
        self.limits.clone()
    }

    /// Returns the two independent directional transports in initiator,
    /// responder order. Each transport owns its own nonce/replay state.
    pub fn into_transports(self) -> (NoiseTransport, NoiseTransport) {
        (self.initiator_transport, self.responder_transport)
    }

    /// Opens one Session Stream through an injected Egress-side opener.
    ///
    /// The request is carried over the authenticated Path only after
    /// `PATH_READY`. RequestID and StreamID ownership is retained by this
    /// harness so an identical retry is replayed locally, while conflicting
    /// reuse is rejected before invoking the opener a second time.
    pub async fn open_stream<O>(
        &mut self,
        opener: &mut O,
        request: StreamOpen,
    ) -> Result<StreamOpenDecision, SinglePathError>
    where
        O: StreamOpener,
    {
        if let Some(cached) = self.stream_requests.get(&request.request_id) {
            if cached.request == request {
                return Ok(cached.decision.clone());
            }
            return Err(SinglePathError::ConflictingRequestId {
                request_id: request.request_id,
            });
        }
        if let Some(existing) = self.stream_ids.get(&request.stream_id)
            && *existing != request.request_id
        {
            return Err(SinglePathError::StreamAlreadyOpen {
                stream_id: request.stream_id,
            });
        }

        let frame_seq = self
            .initiator_transport
            .next_send_nonce()
            .ok_or(NoiseError::NonceExhausted)?;
        let frame = make_frame(
            Message::StreamOpen(request.clone()),
            self.session_id,
            self.path_id,
            frame_seq,
            self.local_limits,
        )?;
        let sealed = self
            .initiator_transport
            .seal_frame(&frame, self.local_limits)?;
        let received = self
            .responder_transport
            .open_frame(&sealed, self.local_limits)?;
        validate_frame_ids_raw(&received, self.session_id, self.path_id)?;
        let received_request = match decode_message(&received, self.local_limits)? {
            Message::StreamOpen(value) if value == request => value,
            _ => {
                return Err(SinglePathError::Message(MessageCodecError::InvalidField {
                    field: "stream_open",
                }));
            }
        };

        let decision = match opener.open_stream(received_request).await {
            Ok(decision) => decision,
            Err(error) => StreamOpenDecision::Rejected {
                error: ErrorClass::TargetFailure,
                reason: error.to_string().into_bytes(),
            },
        };
        let response_seq = self
            .responder_transport
            .next_send_nonce()
            .ok_or(NoiseError::NonceExhausted)?;
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
        let response_frame = make_frame(
            response,
            self.session_id,
            self.path_id,
            response_seq,
            self.local_limits,
        )?;
        let sealed_response = self
            .responder_transport
            .seal_frame(&response_frame, self.local_limits)?;
        let received_response = self
            .initiator_transport
            .open_frame(&sealed_response, self.local_limits)?;
        validate_frame_ids_raw(&received_response, self.session_id, self.path_id)?;
        validate_stream_open_response(
            &received_response,
            request.stream_id,
            &decision,
            self.local_limits,
        )?;

        self.stream_ids
            .insert(request.stream_id, request.request_id);
        self.stream_requests.insert(
            request.request_id,
            CachedStreamOpen {
                request,
                decision: decision.clone(),
            },
        );
        Ok(decision)
    }
}

/// Result selected by an Egress-side Stream opener.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StreamOpenDecision {
    Opened { metadata: Vec<u8> },
    Rejected { error: ErrorClass, reason: Vec<u8> },
}

/// Injected boundary for opening one target Stream after Path admission.
#[async_trait]
pub trait StreamOpener: Send {
    type Error: std::error::Error + Send + Sync + 'static;

    async fn open_stream(&mut self, request: StreamOpen)
    -> Result<StreamOpenDecision, Self::Error>;
}

/// Admission result. Policy failures are protocol-level rejects; malformed
/// local inputs or cryptographic failures are returned as `Err`.
#[derive(Debug)]
pub enum SinglePathOutcome {
    Ready(Box<SinglePathReady>),
    Rejected { error: ErrorClass, reason: Vec<u8> },
}

#[derive(Debug, Error)]
pub enum SinglePathError {
    #[error("Noise handshake failed: {0}")]
    Noise(#[from] NoiseError),
    #[error("Path frame codec failed: {0}")]
    Frame(#[from] FrameCodecError),
    #[error("message codec failed: {0}")]
    Message(#[from] MessageCodecError),
    #[error("authorization record ingress identity is empty")]
    EmptyAuthorizationIdentity,
    #[error("single-Path identity fields are invalid")]
    InvalidIdentity,
    #[error("PATH_READY limits exceed the local negotiated limits")]
    ReadyLimitsExceedLocal,
    #[error("Stream opener failed: {0}")]
    StreamOpener(String),
    #[error("RequestID {request_id} was reused with different Stream fields")]
    ConflictingRequestId { request_id: RequestId },
    #[error("StreamID {stream_id} is already bound to another RequestID")]
    StreamAlreadyOpen { stream_id: StreamId },
    #[error("Stream opener returned an invalid response")]
    InvalidStreamOpenResponse,
}

/// Runs one deterministic, in-memory Path admission exchange.
///
/// The exchange is deliberately synchronous because all inputs are already
/// complete records. A Transit adapter can call the same helpers around its
/// record I/O without changing the admission guards.
pub fn establish_single_path(
    initiator_private: &[u8; STATIC_KEY_LEN],
    responder_private: &[u8; STATIC_KEY_LEN],
    responder_public: &[u8; STATIC_KEY_LEN],
    config: &SinglePathHandshakeConfig,
    authorization: &PathAuthorization,
) -> Result<SinglePathOutcome, SinglePathError> {
    validate_config(config, authorization)?;

    let mut initiator =
        InitiatorHandshake::new(initiator_private, responder_public, &config.egress_identity)?;
    let mut responder = ResponderHandshake::new(responder_private, &config.egress_identity)?;

    // Noise IK has two handshake messages. No application payload is accepted
    // here; the wire-profile control sequence starts only after both sides have
    // entered independent transport mode.
    let message_one = initiator.write_message(&[])?;
    if !responder.read_message(&message_one)?.is_empty() {
        return Err(SinglePathError::Message(MessageCodecError::InvalidField {
            field: "handshake_payload",
        }));
    }
    let message_two = responder.write_message(&[])?;
    if !initiator.read_message(&message_two)?.is_empty() {
        return Err(SinglePathError::Message(MessageCodecError::InvalidField {
            field: "handshake_payload",
        }));
    }

    let authenticated_key = responder.authenticated_remote_static()?;

    let mut initiator_transport = initiator.into_transport()?;
    let mut responder_transport = responder.into_transport()?;

    let hello = Message::PathHello(PathHello {
        version: pathchord_core::WIRE_PROFILE_V1_VERSION,
        capabilities: config.offered_capabilities,
        path_id: config.path_id,
        transport_metadata: Vec::new(),
    });
    let hello_frame = make_frame(
        hello,
        config.session_id,
        config.path_id,
        0,
        config.local_limits,
    )?;
    let sealed_hello = initiator_transport.seal_frame(&hello_frame, config.local_limits)?;
    let received_hello = responder_transport.open_frame(&sealed_hello, config.local_limits)?;
    validate_hello(&received_hello, config)?;

    let attach = Message::SessionAttach(SessionAttach {
        ingress_id: config.ingress_id.clone(),
        session_id: config.session_id,
        egress_id: config.egress_id.clone(),
        control_seq: 0,
        replication_budget_bytes_per_second: config.replication_budget_bytes_per_second,
    });
    let attach_frame = make_frame(
        attach,
        config.session_id,
        config.path_id,
        1,
        config.local_limits,
    )?;
    let sealed_attach = initiator_transport.seal_frame(&attach_frame, config.local_limits)?;
    let received_attach = responder_transport.open_frame(&sealed_attach, config.local_limits)?;
    validate_attach(&received_attach, config)?;

    let negotiated_capabilities = config.offered_capabilities
        & config.supported_capabilities
        & crate::admission::REGISTERED_CAPABILITIES;
    if negotiated_capabilities & config.required_capabilities != config.required_capabilities {
        return reject(
            &mut initiator_transport,
            &mut responder_transport,
            config,
            ErrorClass::EgressFailure,
            b"required capability is unavailable",
        );
    }

    let authorization_error = match authorization.state {
        AuthorizationState::Enabled if authenticated_key == authorization.public_key => None,
        AuthorizationState::Enabled => {
            Some(b"Ingress authorization key is not enrolled".as_slice())
        }
        AuthorizationState::Disabled => Some(b"Ingress authorization is disabled".as_slice()),
        AuthorizationState::Revoked => Some(b"Ingress authorization is revoked".as_slice()),
    };
    if authorization.ingress_id != config.ingress_id {
        return reject(
            &mut initiator_transport,
            &mut responder_transport,
            config,
            ErrorClass::EgressFailure,
            b"Ingress identity does not match authorization",
        );
    }
    if let Some(reason) = authorization_error {
        return reject(
            &mut initiator_transport,
            &mut responder_transport,
            config,
            ErrorClass::EgressFailure,
            reason,
        );
    }

    let attach_ok = make_frame(
        Message::SessionAttachOk(pathchord_core::SessionAttachOk {
            authorization_generation: authorization.generation,
            replication_budget_bytes_per_second: config.replication_budget_bytes_per_second,
        }),
        config.session_id,
        config.path_id,
        0,
        config.local_limits,
    )?;
    let sealed_attach_ok = responder_transport.seal_frame(&attach_ok, config.local_limits)?;
    let received_attach_ok =
        initiator_transport.open_frame(&sealed_attach_ok, config.local_limits)?;
    validate_frame_ids(&received_attach_ok, config)?;
    let accepted_replication_budget =
        match decode_message(&received_attach_ok, config.local_limits)? {
            Message::SessionAttachOk(value)
                if value.authorization_generation == authorization.generation
                    && value.replication_budget_bytes_per_second
                        <= config.replication_budget_bytes_per_second =>
            {
                value.replication_budget_bytes_per_second
            }
            _ => {
                return Err(SinglePathError::Message(MessageCodecError::InvalidField {
                    field: "session_attach_ok",
                }));
            }
        };

    let ready_frame = make_frame(
        Message::PathReadyCapabilities(pathchord_core::PathReadyCapabilities {
            limits: config.ready_limits.clone(),
            capabilities: negotiated_capabilities,
        }),
        config.session_id,
        config.path_id,
        1,
        config.local_limits,
    )?;
    let sealed_ready = responder_transport.seal_frame(&ready_frame, config.local_limits)?;
    let received_ready = initiator_transport.open_frame(&sealed_ready, config.local_limits)?;
    validate_frame_ids(&received_ready, config)?;
    let ready = match decode_message(&received_ready, config.local_limits)? {
        Message::PathReadyCapabilities(value) if value.capabilities == negotiated_capabilities => {
            value.limits
        }
        _ => {
            return Err(SinglePathError::Message(MessageCodecError::InvalidField {
                field: "path_ready",
            }));
        }
    };
    validate_ready_limits(&ready, config.local_limits)?;

    Ok(SinglePathOutcome::Ready(Box::new(SinglePathReady {
        initiator_transport,
        responder_transport,
        session_id: config.session_id,
        path_id: config.path_id,
        local_limits: config.local_limits,
        negotiated_capabilities,
        authorization_generation: authorization.generation,
        replication_budget_bytes_per_second: accepted_replication_budget,
        limits: ready,
        stream_requests: HashMap::new(),
        stream_ids: HashMap::new(),
    })))
}

fn validate_config(
    config: &SinglePathHandshakeConfig,
    authorization: &PathAuthorization,
) -> Result<(), SinglePathError> {
    if authorization.ingress_id.is_empty() {
        return Err(SinglePathError::EmptyAuthorizationIdentity);
    }
    if std::str::from_utf8(&authorization.ingress_id).is_err()
        || authorization.ingress_id.len() > ProtocolLimits::HARD_MAX_TARGET_NAME
        || !valid_identifier(&authorization.ingress_id)
    {
        return Err(SinglePathError::InvalidIdentity);
    }
    if config.ingress_id.is_empty()
        || config.egress_id.is_empty()
        || std::str::from_utf8(&config.ingress_id).is_err()
        || std::str::from_utf8(&config.egress_id).is_err()
        || config.ingress_id.len() > ProtocolLimits::HARD_MAX_TARGET_NAME
        || config.egress_id.len() > ProtocolLimits::HARD_MAX_TARGET_NAME
        || !valid_identifier(&config.ingress_id)
        || !valid_identifier(&config.egress_id)
    {
        return Err(SinglePathError::InvalidIdentity);
    }
    let mut expected_prologue = WIRE_PROFILE_V1_PROLOGUE_PREFIX.to_vec();
    expected_prologue.extend_from_slice(&config.egress_id);
    if config.egress_identity != expected_prologue {
        return Err(SinglePathError::InvalidIdentity);
    }
    validate_ready_limits(&config.ready_limits, config.local_limits)
}

fn valid_identifier(value: &[u8]) -> bool {
    let Some(first) = value.first() else {
        return false;
    };
    first.is_ascii_alphanumeric()
        && value
            .iter()
            .skip(1)
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(*byte, b'.' | b'_' | b'-'))
}

fn validate_ready_limits(
    ready: &PathReady,
    local_limits: ProtocolLimits,
) -> Result<(), SinglePathError> {
    if ready.max_frame_payload == 0
        || ready.max_control_payload == 0
        || ready.max_session_buffering == 0
        || ready.max_frame_payload > ProtocolLimits::HARD_MAX_FRAME_PAYLOAD as u64
        || ready.max_control_payload > ProtocolLimits::HARD_MAX_CONTROL_PAYLOAD as u64
        || ready.max_session_buffering > ProtocolLimits::HARD_MAX_SESSION_BUFFERING as u64
        || ready.max_control_payload > ready.max_frame_payload
        || ready.max_frame_payload > local_limits.max_frame_payload() as u64
        || ready.max_control_payload > local_limits.max_control_payload() as u64
        || ready.max_session_buffering > local_limits.max_session_buffering() as u64
    {
        return Err(SinglePathError::ReadyLimitsExceedLocal);
    }
    Ok(())
}

fn validate_hello(
    frame: &PathFrame,
    config: &SinglePathHandshakeConfig,
) -> Result<(), SinglePathError> {
    if frame.header().session_id() != config.session_id
        || frame.header().path_id() != config.path_id
    {
        return Err(SinglePathError::Message(MessageCodecError::InvalidField {
            field: "path_or_session_id",
        }));
    }
    match decode_message(frame, config.local_limits)? {
        Message::PathHello(value) if value.path_id == config.path_id => Ok(()),
        _ => Err(SinglePathError::Message(MessageCodecError::InvalidField {
            field: "path_hello",
        })),
    }
}

fn validate_frame_ids(
    frame: &PathFrame,
    config: &SinglePathHandshakeConfig,
) -> Result<(), SinglePathError> {
    validate_frame_ids_raw(frame, config.session_id, config.path_id)
}

fn validate_frame_ids_raw(
    frame: &PathFrame,
    session_id: SessionId,
    path_id: PathId,
) -> Result<(), SinglePathError> {
    if frame.header().session_id() != session_id || frame.header().path_id() != path_id {
        return Err(SinglePathError::Message(MessageCodecError::InvalidField {
            field: "path_or_session_id",
        }));
    }
    Ok(())
}

fn validate_stream_open_response(
    frame: &PathFrame,
    stream_id: StreamId,
    expected: &StreamOpenDecision,
    limits: ProtocolLimits,
) -> Result<(), SinglePathError> {
    let valid = match (decode_message(frame, limits)?, expected) {
        (Message::StreamOpenOk(value), StreamOpenDecision::Opened { metadata }) => {
            value.stream_id == stream_id && value.result_metadata == *metadata
        }
        (Message::StreamOpenErr(value), StreamOpenDecision::Rejected { error, reason }) => {
            value.stream_id == stream_id && value.error == *error && value.reason == *reason
        }
        _ => false,
    };
    if valid {
        Ok(())
    } else {
        Err(SinglePathError::InvalidStreamOpenResponse)
    }
}

fn validate_attach(
    frame: &PathFrame,
    config: &SinglePathHandshakeConfig,
) -> Result<(), SinglePathError> {
    if frame.header().session_id() != config.session_id
        || frame.header().path_id() != config.path_id
    {
        return Err(SinglePathError::Message(MessageCodecError::InvalidField {
            field: "path_or_session_id",
        }));
    }
    match decode_message(frame, config.local_limits)? {
        Message::SessionAttach(value)
            if value.session_id == config.session_id
                && value.ingress_id == config.ingress_id
                && value.egress_id == config.egress_id
                && value.control_seq == 0 =>
        {
            Ok(())
        }
        _ => Err(SinglePathError::Message(MessageCodecError::InvalidField {
            field: "session_attach",
        })),
    }
}

fn decode_message(frame: &PathFrame, limits: ProtocolLimits) -> Result<Message, SinglePathError> {
    Ok(Message::decode(
        frame.header().frame_type(),
        frame.payload(),
        limits,
    )?)
}

fn make_frame(
    message: Message,
    session_id: SessionId,
    path_id: PathId,
    frame_seq: u64,
    limits: ProtocolLimits,
) -> Result<PathFrame, SinglePathError> {
    let frame_type = message.frame_type();
    let payload = message.encode(limits)?;
    Ok(PathFrame::new(
        frame_type,
        FrameFlags::empty(),
        session_id,
        path_id,
        frame_seq,
        payload,
        limits,
    )?)
}

fn reject(
    initiator_transport: &mut NoiseTransport,
    responder_transport: &mut NoiseTransport,
    config: &SinglePathHandshakeConfig,
    error: ErrorClass,
    reason: &[u8],
) -> Result<SinglePathOutcome, SinglePathError> {
    let frame = make_frame(
        Message::SessionAttachReject(pathchord_core::SessionAttachReject {
            error,
            reason: reason.to_vec(),
        }),
        config.session_id,
        config.path_id,
        0,
        config.local_limits,
    )?;
    let sealed = responder_transport.seal_frame(&frame, config.local_limits)?;
    let received = initiator_transport.open_frame(&sealed, config.local_limits)?;
    match decode_message(&received, config.local_limits)? {
        Message::SessionAttachReject(value) => Ok(SinglePathOutcome::Rejected {
            error: value.error,
            reason: value.reason,
        }),
        _ => Err(SinglePathError::Message(MessageCodecError::InvalidField {
            field: "session_attach_reject",
        })),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pathchord_core::PathId;
    use pathchord_noise::{
        StaticKeypair, WIRE_PROFILE_V1_PROLOGUE_PREFIX, generate_static_keypair,
    };

    fn config() -> SinglePathHandshakeConfig {
        let mut prologue = WIRE_PROFILE_V1_PROLOGUE_PREFIX.to_vec();
        prologue.extend_from_slice(b"egress-a");
        SinglePathHandshakeConfig {
            egress_identity: prologue,
            egress_id: b"egress-a".to_vec(),
            ingress_id: b"ingress-a".to_vec(),
            session_id: SessionId::new(7),
            path_id: PathId::new(8),
            offered_capabilities: 0b11,
            required_capabilities: 0b01,
            replication_budget_bytes_per_second: 8 * 1024 * 1024,
            supported_capabilities: 0b01,
            local_limits: ProtocolLimits::default(),
            ready_limits: PathReady {
                max_frame_payload: 60 * 1024,
                max_control_payload: 4 * 1024,
                max_session_buffering: 16 * 1024 * 1024,
            },
        }
    }

    fn keys() -> (StaticKeypair, StaticKeypair) {
        (
            generate_static_keypair().expect("initiator key"),
            generate_static_keypair().expect("responder key"),
        )
    }

    fn authorization(key: &StaticKeypair) -> PathAuthorization {
        PathAuthorization {
            ingress_id: b"ingress-a".to_vec(),
            public_key: *key.public(),
            state: AuthorizationState::Enabled,
            generation: 9,
        }
    }

    fn ready_path() -> SinglePathReady {
        let (initiator, responder) = keys();
        let result = establish_single_path(
            initiator.private(),
            responder.private(),
            responder.public(),
            &config(),
            &authorization(&initiator),
        )
        .expect("handshake");
        let SinglePathOutcome::Ready(ready) = result else {
            panic!("expected ready path");
        };
        *ready
    }

    #[derive(Debug)]
    struct TestOpenerError;

    impl std::fmt::Display for TestOpenerError {
        fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("test opener failed")
        }
    }

    impl std::error::Error for TestOpenerError {}

    struct TestOpener {
        calls: usize,
        decision: StreamOpenDecision,
    }

    #[async_trait]
    impl StreamOpener for TestOpener {
        type Error = TestOpenerError;

        async fn open_stream(
            &mut self,
            _request: StreamOpen,
        ) -> Result<StreamOpenDecision, Self::Error> {
            self.calls += 1;
            Ok(self.decision.clone())
        }
    }

    fn stream_request(request_id: u128, stream_id: u64) -> StreamOpen {
        StreamOpen {
            request_id: RequestId::new(request_id),
            stream_id: StreamId::new(stream_id).expect("stream ID"),
            target: pathchord_core::TargetEndpoint {
                hostname: b"example.test".to_vec(),
                port: 443,
                resolved_addresses: Vec::new(),
            },
        }
    }

    #[test]
    fn admits_exact_control_sequence_and_negotiates_capabilities() {
        let (initiator, responder) = keys();
        let result = establish_single_path(
            initiator.private(),
            responder.private(),
            responder.public(),
            &config(),
            &authorization(&initiator),
        )
        .expect("handshake");
        let SinglePathOutcome::Ready(ready) = result else {
            panic!("expected ready path");
        };
        assert_eq!(ready.negotiated_capabilities(), 0b01);
        assert_eq!(ready.authorization_generation(), 9);
        assert_eq!(ready.limits().max_frame_payload, 60 * 1024);
    }

    #[test]
    fn disabled_authorization_returns_attach_reject_without_ready_path() {
        let (initiator, responder) = keys();
        let mut record = authorization(&initiator);
        record.state = AuthorizationState::Disabled;
        let result = establish_single_path(
            initiator.private(),
            responder.private(),
            responder.public(),
            &config(),
            &record,
        )
        .expect("protocol rejection");
        assert!(matches!(
            result,
            SinglePathOutcome::Rejected {
                error: ErrorClass::EgressFailure,
                ..
            }
        ));
    }

    #[test]
    fn required_capability_mismatch_returns_attach_reject() {
        let (initiator, responder) = keys();
        let mut offer = config();
        offer.required_capabilities = 0b100;
        let result = establish_single_path(
            initiator.private(),
            responder.private(),
            responder.public(),
            &offer,
            &authorization(&initiator),
        )
        .expect("protocol rejection");
        assert!(matches!(result, SinglePathOutcome::Rejected { .. }));
    }

    #[test]
    fn authorization_identity_mismatch_returns_attach_reject() {
        let (initiator, responder) = keys();
        let mut record = authorization(&initiator);
        record.ingress_id = b"other-ingress".to_vec();
        let result = establish_single_path(
            initiator.private(),
            responder.private(),
            responder.public(),
            &config(),
            &record,
        )
        .expect("protocol rejection");
        assert!(matches!(
            result,
            SinglePathOutcome::Rejected {
                error: ErrorClass::EgressFailure,
                ..
            }
        ));
    }

    #[test]
    fn authorization_key_mismatch_returns_attach_reject() {
        let (initiator, responder) = keys();
        let (other_initiator, _) = keys();
        let record = authorization(&other_initiator);
        let result = establish_single_path(
            initiator.private(),
            responder.private(),
            responder.public(),
            &config(),
            &record,
        )
        .expect("protocol rejection");
        assert!(matches!(
            result,
            SinglePathOutcome::Rejected {
                error: ErrorClass::EgressFailure,
                ..
            }
        ));
    }

    #[test]
    fn ready_limits_above_local_limits_fail_before_handshake() {
        let (initiator, responder) = keys();
        let mut offer = config();
        offer.ready_limits.max_frame_payload = (ProtocolLimits::HARD_MAX_FRAME_PAYLOAD as u64) + 1;
        assert!(matches!(
            establish_single_path(
                initiator.private(),
                responder.private(),
                responder.public(),
                &offer,
                &authorization(&initiator),
            ),
            Err(SinglePathError::ReadyLimitsExceedLocal)
        ));
    }

    #[test]
    fn wrong_responder_key_fails_before_path_ready() {
        let (initiator, responder) = keys();
        let (_, wrong_responder) = keys();
        assert!(matches!(
            establish_single_path(
                initiator.private(),
                responder.private(),
                wrong_responder.public(),
                &config(),
                &authorization(&initiator),
            ),
            Err(SinglePathError::Noise(_))
        ));
    }

    #[tokio::test]
    async fn opens_stream_after_ready_and_replays_identical_request() {
        let mut ready = ready_path();
        let request = stream_request(11, 1);
        let mut opener = TestOpener {
            calls: 0,
            decision: StreamOpenDecision::Opened {
                metadata: b"target-open".to_vec(),
            },
        };

        let first = ready
            .open_stream(&mut opener, request.clone())
            .await
            .expect("stream open");
        let replay = ready
            .open_stream(&mut opener, request)
            .await
            .expect("replayed stream open");
        assert_eq!(first, replay);
        assert_eq!(opener.calls, 1);
    }

    #[tokio::test]
    async fn rejects_conflicting_request_or_stream_id_reuse() {
        let mut ready = ready_path();
        let request = stream_request(12, 2);
        let mut opener = TestOpener {
            calls: 0,
            decision: StreamOpenDecision::Rejected {
                error: ErrorClass::TargetFailure,
                reason: b"target unavailable".to_vec(),
            },
        };
        ready
            .open_stream(&mut opener, request.clone())
            .await
            .expect("rejected open is a protocol result");

        let conflicting_request = stream_request(12, 3);
        assert!(matches!(
            ready.open_stream(&mut opener, conflicting_request).await,
            Err(SinglePathError::ConflictingRequestId { .. })
        ));

        let reused_stream = stream_request(13, 2);
        assert!(matches!(
            ready.open_stream(&mut opener, reused_stream).await,
            Err(SinglePathError::StreamAlreadyOpen { .. })
        ));
        assert_eq!(opener.calls, 1);
    }
}
