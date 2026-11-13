//! Role-separated asynchronous admission for one production byte-stream Path.

use pathchord_core::{
    ErrorClass, FrameCodecError, FrameFlags, FrameType, Message, MessageCodecError, PathFrame,
    PathHello, PathId, PathReady, ProtocolLimits, SessionAttach, SessionId,
    WIRE_PROFILE_V1_VERSION,
};
use pathchord_noise::{
    InitiatorHandshake, MAX_NOISE_MESSAGE_LEN, NoiseError, ResponderHandshake, STATIC_KEY_LEN,
    WIRE_PROFILE_V1_PROLOGUE_PREFIX,
};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::{
    AuthorizationState, CompleteFrameTransport, NoiseRecordStream, NoiseRecordStreamError,
    PathAuthorization,
};

/// Ingress-owned inputs for dialing and admitting one Path.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IngressPathAdmissionConfig {
    /// Complete `PathChord/wire-v1/egress/<id>` Noise prologue.
    pub egress_identity: Vec<u8>,
    pub egress_id: Vec<u8>,
    pub ingress_id: Vec<u8>,
    pub session_id: SessionId,
    pub path_id: PathId,
    pub offered_capabilities: u64,
    pub local_limits: ProtocolLimits,
}

/// Egress-owned inputs for accepting and admitting one Path.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EgressPathAdmissionConfig {
    /// Complete `PathChord/wire-v1/egress/<id>` Noise prologue.
    pub egress_identity: Vec<u8>,
    pub egress_id: Vec<u8>,
    pub required_capabilities: u64,
    pub supported_capabilities: u64,
    pub local_limits: ProtocolLimits,
    pub ready_limits: PathReady,
}

/// Resolves an authenticated Noise static key against an immutable Egress
/// authorization generation.
pub trait PathAuthorizer: Send + Sync {
    fn authorization_for(
        &self,
        authenticated_key: &[u8; STATIC_KEY_LEN],
    ) -> Option<PathAuthorization>;
}

impl PathAuthorizer for PathAuthorization {
    fn authorization_for(
        &self,
        authenticated_key: &[u8; STATIC_KEY_LEN],
    ) -> Option<PathAuthorization> {
        (self.public_key == *authenticated_key).then(|| self.clone())
    }
}

/// A successfully admitted Ingress-side Path.
pub struct IngressAdmittedPath<S> {
    transport: NoiseRecordStream<S>,
    session_id: SessionId,
    path_id: PathId,
    authorization_generation: u64,
    negotiated_capabilities: u64,
    limits: PathReady,
}

impl<S> std::fmt::Debug for IngressAdmittedPath<S>
where
    S: std::fmt::Debug,
{
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("IngressAdmittedPath")
            .field("transport", &self.transport)
            .field("session_id", &self.session_id)
            .field("path_id", &self.path_id)
            .field("authorization_generation", &self.authorization_generation)
            .field("limits", &self.limits)
            .finish()
    }
}

impl<S> IngressAdmittedPath<S> {
    pub const fn negotiated_capabilities(&self) -> u64 {
        self.negotiated_capabilities
    }
    pub const fn session_id(&self) -> SessionId {
        self.session_id
    }

    pub const fn path_id(&self) -> PathId {
        self.path_id
    }

    pub const fn authorization_generation(&self) -> u64 {
        self.authorization_generation
    }

    pub fn limits(&self) -> &PathReady {
        &self.limits
    }

    pub fn transport_mut(&mut self) -> &mut NoiseRecordStream<S> {
        &mut self.transport
    }

    pub fn into_transport(self) -> NoiseRecordStream<S> {
        self.transport
    }
}

/// A successfully admitted Egress-side Path.
pub struct EgressAdmittedPath<S> {
    transport: NoiseRecordStream<S>,
    ingress_id: Vec<u8>,
    session_id: SessionId,
    path_id: PathId,
    negotiated_capabilities: u64,
    authorization_generation: u64,
    limits: PathReady,
}

impl<S> std::fmt::Debug for EgressAdmittedPath<S>
where
    S: std::fmt::Debug,
{
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("EgressAdmittedPath")
            .field("transport", &self.transport)
            .field("ingress_id", &String::from_utf8_lossy(&self.ingress_id))
            .field("session_id", &self.session_id)
            .field("path_id", &self.path_id)
            .field("negotiated_capabilities", &self.negotiated_capabilities)
            .field("authorization_generation", &self.authorization_generation)
            .field("limits", &self.limits)
            .finish()
    }
}

impl<S> EgressAdmittedPath<S> {
    pub fn ingress_id(&self) -> &[u8] {
        &self.ingress_id
    }

    pub const fn session_id(&self) -> SessionId {
        self.session_id
    }

    pub const fn path_id(&self) -> PathId {
        self.path_id
    }

    pub const fn negotiated_capabilities(&self) -> u64 {
        self.negotiated_capabilities
    }

    pub const fn authorization_generation(&self) -> u64 {
        self.authorization_generation
    }

    pub fn limits(&self) -> &PathReady {
        &self.limits
    }

    pub fn transport_mut(&mut self) -> &mut NoiseRecordStream<S> {
        &mut self.transport
    }

    pub fn into_transport(self) -> NoiseRecordStream<S> {
        self.transport
    }
}

/// Protocol outcome for either side of Path admission.
#[derive(Debug)]
pub enum PathAdmissionOutcome<T> {
    Ready(T),
    Rejected { error: ErrorClass, reason: Vec<u8> },
}

#[derive(Debug, Error)]
pub enum PathAdmissionError {
    #[error("Path admission byte stream failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("Path admission Noise exchange failed: {0}")]
    Noise(#[from] NoiseError),
    #[error("Path admission record exchange failed: {0}")]
    Record(#[from] NoiseRecordStreamError),
    #[error("Path admission frame failed: {0}")]
    Frame(#[from] FrameCodecError),
    #[error("Path admission message failed: {0}")]
    Message(#[from] MessageCodecError),
    #[error("Path admission identity is invalid")]
    InvalidIdentity,
    #[error("Path authorization identity is invalid")]
    InvalidAuthorizationIdentity,
    #[error("accepted Path has no resolved authorization record")]
    MissingResolvedAuthorization,
    #[error("Noise handshake message is empty")]
    EmptyHandshakeMessage,
    #[error("Noise handshake carried an unexpected protocol payload")]
    UnexpectedHandshakePayload,
    #[error("peer closed during {stage}")]
    PeerClosed { stage: &'static str },
    #[error("expected {expected}, received {actual:?}")]
    UnexpectedMessage {
        expected: &'static str,
        actual: FrameType,
    },
    #[error("Path frame belongs to another Session or Path")]
    WrongPathIdentity,
    #[error("PATH_HELLO carries an unsupported version or mismatched PathID")]
    InvalidPathHello,
    #[error("SESSION_ATTACH fields do not match the authenticated Path")]
    InvalidSessionAttach,
    #[error("PATH_READY limits exceed local or profile limits")]
    ReadyLimitsExceedLocal,
}

/// Dials one Egress Path and completes Noise IK plus Path/Session admission.
pub async fn dial_path<S>(
    mut io: S,
    initiator_private: &[u8; STATIC_KEY_LEN],
    expected_responder_public: &[u8; STATIC_KEY_LEN],
    config: &IngressPathAdmissionConfig,
) -> Result<PathAdmissionOutcome<IngressAdmittedPath<S>>, PathAdmissionError>
where
    S: AsyncRead + AsyncWrite + Send + Unpin,
{
    validate_ingress_config(config)?;
    let mut handshake = InitiatorHandshake::new(
        initiator_private,
        expected_responder_public,
        &config.egress_identity,
    )?;
    let request = handshake.write_message(&[])?;
    write_handshake_message(&mut io, &request).await?;
    let response = read_handshake_message(&mut io).await?;
    if !handshake.read_message(&response)?.is_empty() {
        return Err(PathAdmissionError::UnexpectedHandshakePayload);
    }
    let transport = handshake.into_transport()?;
    let mut records = NoiseRecordStream::new(io, transport, config.local_limits);

    send_message(
        &mut records,
        Message::PathHello(PathHello {
            version: WIRE_PROFILE_V1_VERSION,
            capabilities: config.offered_capabilities,
            path_id: config.path_id,
            transport_metadata: Vec::new(),
        }),
        config.session_id,
        config.path_id,
        0,
        config.local_limits,
    )
    .await?;
    send_message(
        &mut records,
        Message::SessionAttach(SessionAttach {
            ingress_id: config.ingress_id.clone(),
            session_id: config.session_id,
            egress_id: config.egress_id.clone(),
            control_seq: 0,
        }),
        config.session_id,
        config.path_id,
        1,
        config.local_limits,
    )
    .await?;

    let attach_frame = receive_required(&mut records, "SESSION_ATTACH result").await?;
    validate_frame_ids(&attach_frame, config.session_id, config.path_id)?;
    let authorization_generation = match decode_message(&attach_frame, config.local_limits)? {
        Message::SessionAttachOk(value) => value.authorization_generation,
        Message::SessionAttachReject(value) => {
            return Ok(PathAdmissionOutcome::Rejected {
                error: value.error,
                reason: value.reason,
            });
        }
        other => {
            return Err(PathAdmissionError::UnexpectedMessage {
                expected: "SESSION_ATTACH_OK or SESSION_ATTACH_REJECT",
                actual: other.frame_type(),
            });
        }
    };

    let ready_frame = receive_required(&mut records, "PATH_READY").await?;
    validate_frame_ids(&ready_frame, config.session_id, config.path_id)?;
    let (limits, negotiated_capabilities) = match decode_message(&ready_frame, config.local_limits)?
    {
        Message::PathReady(value) => (value, 0),
        Message::PathReadyCapabilities(value)
            if value.capabilities & !config.offered_capabilities == 0
                && value.capabilities & pathchord_core::CAPABILITY_TRAFFIC_CLASSES != 0 =>
        {
            (value.limits, value.capabilities)
        }
        other => {
            return Err(PathAdmissionError::UnexpectedMessage {
                expected: "PATH_READY",
                actual: other.frame_type(),
            });
        }
    };
    validate_ready_limits(&limits, config.local_limits)?;
    Ok(PathAdmissionOutcome::Ready(IngressAdmittedPath {
        transport: records,
        session_id: config.session_id,
        path_id: config.path_id,
        authorization_generation,
        negotiated_capabilities,
        limits,
    }))
}

/// Accepts one Ingress Path and completes Noise IK plus authorization/admission.
pub async fn accept_path<S, A>(
    mut io: S,
    responder_private: &[u8; STATIC_KEY_LEN],
    config: &EgressPathAdmissionConfig,
    authorizer: &A,
) -> Result<PathAdmissionOutcome<EgressAdmittedPath<S>>, PathAdmissionError>
where
    S: AsyncRead + AsyncWrite + Send + Unpin,
    A: PathAuthorizer,
{
    validate_egress_config(config)?;
    let mut handshake = ResponderHandshake::new(responder_private, &config.egress_identity)?;
    let request = read_handshake_message(&mut io).await?;
    if !handshake.read_message(&request)?.is_empty() {
        return Err(PathAdmissionError::UnexpectedHandshakePayload);
    }
    let authenticated_key = handshake.authenticated_remote_static()?;
    let authorization = authorizer.authorization_for(&authenticated_key);
    let response = handshake.write_message(&[])?;
    write_handshake_message(&mut io, &response).await?;
    let transport = handshake.into_transport()?;
    let mut records = NoiseRecordStream::new(io, transport, config.local_limits);

    let hello_frame = receive_required(&mut records, "PATH_HELLO").await?;
    let session_id = hello_frame.header().session_id();
    let path_id = hello_frame.header().path_id();
    let offered_capabilities = match decode_message(&hello_frame, config.local_limits)? {
        Message::PathHello(value)
            if value.version == WIRE_PROFILE_V1_VERSION && value.path_id == path_id =>
        {
            value.capabilities
        }
        Message::PathHello(_) => return Err(PathAdmissionError::InvalidPathHello),
        other => {
            return Err(PathAdmissionError::UnexpectedMessage {
                expected: "PATH_HELLO",
                actual: other.frame_type(),
            });
        }
    };

    let attach_frame = receive_required(&mut records, "SESSION_ATTACH").await?;
    validate_frame_ids(&attach_frame, session_id, path_id)?;
    let attach = match decode_message(&attach_frame, config.local_limits)? {
        Message::SessionAttach(value)
            if value.session_id == session_id
                && value.egress_id == config.egress_id
                && value.control_seq == 0
                && valid_identifier(&value.ingress_id) =>
        {
            value
        }
        Message::SessionAttach(_) => return Err(PathAdmissionError::InvalidSessionAttach),
        other => {
            return Err(PathAdmissionError::UnexpectedMessage {
                expected: "SESSION_ATTACH",
                actual: other.frame_type(),
            });
        }
    };

    let negotiated_capabilities = offered_capabilities & config.supported_capabilities;
    let rejection_reason = if offered_capabilities & config.required_capabilities
        != config.required_capabilities
        || config.supported_capabilities & config.required_capabilities
            != config.required_capabilities
    {
        Some(b"required capability is unavailable".as_slice())
    } else {
        match authorization.as_ref() {
            None => Some(b"Ingress authorization key is not enrolled".as_slice()),
            Some(record) if !valid_identifier(&record.ingress_id) => {
                return Err(PathAdmissionError::InvalidAuthorizationIdentity);
            }
            Some(record) if record.public_key != authenticated_key => {
                Some(b"Ingress authorization key is not enrolled".as_slice())
            }
            Some(record) if record.ingress_id != attach.ingress_id => {
                Some(b"Ingress identity does not match authorization".as_slice())
            }
            Some(record) => match record.state {
                AuthorizationState::Enabled => None,
                AuthorizationState::Disabled => {
                    Some(b"Ingress authorization is disabled".as_slice())
                }
                AuthorizationState::Revoked => Some(b"Ingress authorization is revoked".as_slice()),
            },
        }
    };
    if let Some(reason) = rejection_reason {
        let error = ErrorClass::EgressFailure;
        send_message(
            &mut records,
            Message::SessionAttachReject(pathchord_core::SessionAttachReject {
                error,
                reason: reason.to_vec(),
            }),
            session_id,
            path_id,
            0,
            config.local_limits,
        )
        .await?;
        return Ok(PathAdmissionOutcome::Rejected {
            error,
            reason: reason.to_vec(),
        });
    }

    let authorization = authorization.ok_or(PathAdmissionError::MissingResolvedAuthorization)?;

    send_message(
        &mut records,
        Message::SessionAttachOk(pathchord_core::SessionAttachOk {
            authorization_generation: authorization.generation,
        }),
        session_id,
        path_id,
        0,
        config.local_limits,
    )
    .await?;
    send_message(
        &mut records,
        if negotiated_capabilities & pathchord_core::CAPABILITY_TRAFFIC_CLASSES != 0 {
            Message::PathReadyCapabilities(pathchord_core::PathReadyCapabilities {
                limits: config.ready_limits.clone(),
                capabilities: negotiated_capabilities,
            })
        } else {
            Message::PathReady(config.ready_limits.clone())
        },
        session_id,
        path_id,
        1,
        config.local_limits,
    )
    .await?;
    Ok(PathAdmissionOutcome::Ready(EgressAdmittedPath {
        transport: records,
        ingress_id: attach.ingress_id,
        session_id,
        path_id,
        negotiated_capabilities,
        authorization_generation: authorization.generation,
        limits: config.ready_limits.clone(),
    }))
}

async fn write_handshake_message<S>(io: &mut S, message: &[u8]) -> Result<(), PathAdmissionError>
where
    S: AsyncWrite + Unpin,
{
    if message.is_empty() {
        return Err(PathAdmissionError::EmptyHandshakeMessage);
    }
    let length =
        u16::try_from(message.len()).map_err(|_| NoiseError::HandshakeMessageTooLarge {
            actual: message.len(),
        })?;
    io.write_all(&length.to_be_bytes()).await?;
    io.write_all(message).await?;
    io.flush().await?;
    Ok(())
}

async fn read_handshake_message<S>(io: &mut S) -> Result<Vec<u8>, PathAdmissionError>
where
    S: AsyncRead + Unpin,
{
    let mut prefix = [0_u8; 2];
    io.read_exact(&mut prefix).await?;
    let length = usize::from(u16::from_be_bytes(prefix));
    if length == 0 {
        return Err(PathAdmissionError::EmptyHandshakeMessage);
    }
    debug_assert!(length <= MAX_NOISE_MESSAGE_LEN);
    let mut message = vec![0_u8; length];
    io.read_exact(&mut message).await?;
    Ok(message)
}

async fn send_message<S>(
    records: &mut NoiseRecordStream<S>,
    message: Message,
    session_id: SessionId,
    path_id: PathId,
    frame_seq: u64,
    limits: ProtocolLimits,
) -> Result<(), PathAdmissionError>
where
    S: AsyncRead + AsyncWrite + Send + Unpin,
{
    let frame_type = message.frame_type();
    let payload = message.encode(limits)?;
    let frame = PathFrame::new(
        frame_type,
        FrameFlags::empty(),
        session_id,
        path_id,
        frame_seq,
        payload,
        limits,
    )?;
    records.send_frame(frame).await?;
    Ok(())
}

async fn receive_required<S>(
    records: &mut NoiseRecordStream<S>,
    stage: &'static str,
) -> Result<PathFrame, PathAdmissionError>
where
    S: AsyncRead + AsyncWrite + Send + Unpin,
{
    records
        .receive_frame()
        .await?
        .ok_or(PathAdmissionError::PeerClosed { stage })
}

fn decode_message(
    frame: &PathFrame,
    limits: ProtocolLimits,
) -> Result<Message, PathAdmissionError> {
    Ok(Message::decode(
        frame.header().frame_type(),
        frame.payload(),
        limits,
    )?)
}

fn validate_frame_ids(
    frame: &PathFrame,
    session_id: SessionId,
    path_id: PathId,
) -> Result<(), PathAdmissionError> {
    if frame.header().session_id() != session_id || frame.header().path_id() != path_id {
        return Err(PathAdmissionError::WrongPathIdentity);
    }
    Ok(())
}

fn validate_ingress_config(config: &IngressPathAdmissionConfig) -> Result<(), PathAdmissionError> {
    validate_identity(&config.egress_identity, &config.egress_id)?;
    if !valid_identifier(&config.ingress_id) {
        return Err(PathAdmissionError::InvalidIdentity);
    }
    Ok(())
}

fn validate_egress_config(config: &EgressPathAdmissionConfig) -> Result<(), PathAdmissionError> {
    validate_identity(&config.egress_identity, &config.egress_id)?;
    validate_ready_limits(&config.ready_limits, config.local_limits)
}

fn validate_identity(egress_identity: &[u8], egress_id: &[u8]) -> Result<(), PathAdmissionError> {
    if !valid_identifier(egress_id) {
        return Err(PathAdmissionError::InvalidIdentity);
    }
    let mut expected = WIRE_PROFILE_V1_PROLOGUE_PREFIX.to_vec();
    expected.extend_from_slice(egress_id);
    if egress_identity != expected {
        return Err(PathAdmissionError::InvalidIdentity);
    }
    Ok(())
}

fn valid_identifier(value: &[u8]) -> bool {
    value.len() <= ProtocolLimits::HARD_MAX_TARGET_NAME
        && value.first().is_some_and(u8::is_ascii_alphanumeric)
        && value
            .iter()
            .skip(1)
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(*byte, b'.' | b'_' | b'-'))
}

fn validate_ready_limits(
    ready: &PathReady,
    local_limits: ProtocolLimits,
) -> Result<(), PathAdmissionError> {
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
        return Err(PathAdmissionError::ReadyLimitsExceedLocal);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use pathchord_core::{Heartbeat, Message};
    use pathchord_noise::{StaticKeypair, generate_static_keypair};
    use tokio::io::duplex;

    fn keys() -> (StaticKeypair, StaticKeypair) {
        (
            generate_static_keypair().expect("initiator key"),
            generate_static_keypair().expect("responder key"),
        )
    }

    fn ingress_config() -> IngressPathAdmissionConfig {
        IngressPathAdmissionConfig {
            egress_identity: b"PathChord/wire-v1/egress/egress-a".to_vec(),
            egress_id: b"egress-a".to_vec(),
            ingress_id: b"ingress-a".to_vec(),
            session_id: SessionId::new(7),
            path_id: PathId::new(9),
            offered_capabilities: 0b11,
            local_limits: ProtocolLimits::default(),
        }
    }

    fn egress_config() -> EgressPathAdmissionConfig {
        EgressPathAdmissionConfig {
            egress_identity: b"PathChord/wire-v1/egress/egress-a".to_vec(),
            egress_id: b"egress-a".to_vec(),
            required_capabilities: 0b01,
            supported_capabilities: 0b01,
            local_limits: ProtocolLimits::default(),
            ready_limits: PathReady {
                max_frame_payload: 4096,
                max_control_payload: 1024,
                max_session_buffering: 8192,
            },
        }
    }

    fn authorization(initiator: &StaticKeypair) -> PathAuthorization {
        PathAuthorization {
            ingress_id: b"ingress-a".to_vec(),
            public_key: *initiator.public(),
            state: AuthorizationState::Enabled,
            generation: 12,
        }
    }

    #[tokio::test]
    async fn admits_independently_owned_roles_over_a_byte_stream() {
        let (initiator, responder) = keys();
        let (ingress_io, egress_io) = duplex(256 * 1024);
        let ingress_config = ingress_config();
        let egress_config = egress_config();
        let authorization = authorization(&initiator);

        let (ingress, egress) = tokio::join!(
            dial_path(
                ingress_io,
                initiator.private(),
                responder.public(),
                &ingress_config,
            ),
            accept_path(
                egress_io,
                responder.private(),
                &egress_config,
                &authorization,
            ),
        );
        let PathAdmissionOutcome::Ready(mut ingress) = ingress.expect("Ingress admission") else {
            panic!("Ingress should be ready");
        };
        let PathAdmissionOutcome::Ready(mut egress) = egress.expect("Egress admission") else {
            panic!("Egress should be ready");
        };
        assert_eq!(ingress.authorization_generation(), 12);
        assert_eq!(egress.negotiated_capabilities(), 0b01);
        assert_eq!(egress.ingress_id(), b"ingress-a");

        let heartbeat = Message::Heartbeat(Heartbeat { control_seq: 44 });
        let frame_type = heartbeat.frame_type();
        let payload = heartbeat
            .encode(ProtocolLimits::default())
            .expect("heartbeat payload");
        let frame = PathFrame::new(
            frame_type,
            FrameFlags::empty(),
            ingress.session_id(),
            ingress.path_id(),
            2,
            payload,
            ProtocolLimits::default(),
        )
        .expect("heartbeat frame");
        let (sent, received) = tokio::join!(
            ingress.transport_mut().send_frame(frame.clone()),
            egress.transport_mut().receive_frame(),
        );
        sent.expect("heartbeat send");
        assert_eq!(received.expect("heartbeat receive"), Some(frame));
    }

    #[tokio::test]
    async fn authorization_rejection_is_observed_by_both_roles() {
        let (initiator, responder) = keys();
        let (ingress_io, egress_io) = duplex(256 * 1024);
        let ingress_config = ingress_config();
        let egress_config = egress_config();
        let mut authorization = authorization(&initiator);
        authorization.state = AuthorizationState::Revoked;

        let (ingress, egress) = tokio::join!(
            dial_path(
                ingress_io,
                initiator.private(),
                responder.public(),
                &ingress_config,
            ),
            accept_path(
                egress_io,
                responder.private(),
                &egress_config,
                &authorization,
            ),
        );
        assert!(matches!(
            ingress.expect("Ingress rejection"),
            PathAdmissionOutcome::Rejected {
                error: ErrorClass::EgressFailure,
                ..
            }
        ));
        assert!(matches!(
            egress.expect("Egress rejection"),
            PathAdmissionOutcome::Rejected {
                error: ErrorClass::EgressFailure,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn authorization_identity_mismatch_is_rejected() {
        let (initiator, responder) = keys();
        let (ingress_io, egress_io) = duplex(256 * 1024);
        let ingress_config = ingress_config();
        let egress_config = egress_config();
        let mut authorization = authorization(&initiator);
        authorization.ingress_id = b"another-ingress".to_vec();

        let (ingress, egress) = tokio::join!(
            dial_path(
                ingress_io,
                initiator.private(),
                responder.public(),
                &ingress_config,
            ),
            accept_path(
                egress_io,
                responder.private(),
                &egress_config,
                &authorization,
            ),
        );
        assert!(matches!(
            ingress.expect("Ingress rejection"),
            PathAdmissionOutcome::Rejected { .. }
        ));
        assert!(matches!(
            egress.expect("Egress rejection"),
            PathAdmissionOutcome::Rejected { .. }
        ));
    }

    #[tokio::test]
    async fn an_unenrolled_authenticated_key_is_rejected() {
        let (initiator, responder) = keys();
        let another_ingress = generate_static_keypair().expect("another Ingress key");
        let (ingress_io, egress_io) = duplex(256 * 1024);
        let ingress_config = ingress_config();
        let egress_config = egress_config();
        let authorization = authorization(&another_ingress);

        let (ingress, egress) = tokio::join!(
            dial_path(
                ingress_io,
                initiator.private(),
                responder.public(),
                &ingress_config,
            ),
            accept_path(
                egress_io,
                responder.private(),
                &egress_config,
                &authorization,
            ),
        );
        let PathAdmissionOutcome::Rejected { reason, .. } = ingress.expect("Ingress rejection")
        else {
            panic!("Ingress should observe a rejection");
        };
        assert_eq!(reason, b"Ingress authorization key is not enrolled");
        assert!(matches!(
            egress.expect("Egress rejection"),
            PathAdmissionOutcome::Rejected { .. }
        ));
    }

    #[tokio::test]
    async fn wrong_responder_identity_fails_the_noise_handshake() {
        let (initiator, responder) = keys();
        let wrong_responder = generate_static_keypair().expect("wrong responder key");
        let (ingress_io, egress_io) = duplex(256 * 1024);
        let ingress_config = ingress_config();
        let egress_config = egress_config();
        let authorization = authorization(&initiator);

        let (ingress, egress) = tokio::join!(
            dial_path(
                ingress_io,
                initiator.private(),
                wrong_responder.public(),
                &ingress_config,
            ),
            accept_path(
                egress_io,
                responder.private(),
                &egress_config,
                &authorization,
            ),
        );
        assert!(ingress.is_err());
        assert!(egress.is_err());
    }
}
