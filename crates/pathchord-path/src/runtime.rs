//! Long-lived, reliable TCP Stream ownership for one admitted Path.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::future::pending;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use pathchord_core::{
    AckRange, ControlAck, ControlReceiver, ControlSender, EgressServiceState, ErrorClass,
    FrameCodecError, FrameFlags, FrameType, Heartbeat, MAX_VARINT, Message, MessageCodecError,
    PathClose, PathDrain, PathFrame, PathId, ProtocolLimits, ReliabilityError, RequestId,
    SessionClose, SessionId, StatusReport, StatusReportDisposition, StreamAck, StreamData,
    StreamFin, StreamId, StreamOpen, StreamOpenErr, StreamOpenOk, StreamReceiveBuffer, StreamRst,
    StreamWindow, TargetEndpoint, UdpClose, UdpDatagram, UdpOpen, UdpOpenErr,
};
use pathchord_noise::{
    MAX_NOISE_MESSAGE_LEN, NoiseError, NoiseTransport, RECORD_ENVELOPE_HEADER_LEN,
    TRANSPORT_TAG_LEN,
};
use thiserror::Error;
use tokio::io::{
    AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf, duplex, split,
};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc, oneshot, watch};
use tokio::task::JoinHandle;
use tokio::time::{Instant, MissedTickBehavior};

use crate::{
    EgressAdmittedPath, IngressAdmittedPath, MultipathConfig, MultipathError,
    MultipathPathObservation, MultipathSession, NoiseRecordStream, PathEconomicStatus,
    ScheduleDirection, SessionUdpError, SessionUdpHandle, UdpAssociationRuntime, UdpTargetFactory,
};

const MAX_SESSION_STREAMS: usize = 256;
const COMMAND_QUEUE_CAPACITY: usize = 64;
const FRAME_QUEUE_CAPACITY: usize = 64;
const STREAM_EVENT_QUEUE_CAPACITY: usize = 256;
const STREAM_COMMAND_QUEUE_CAPACITY: usize = 64;
const FRAME_OVERHEAD_RESERVE: usize = 64;
const MAX_DATA_CHUNK: usize = 16 * 1024;
const STREAM_FLAG_FIN: u64 = 1;
const STREAM_FLAG_RST: u64 = 2;
const MIN_RETRANSMISSION_TIMEOUT: Duration = Duration::from_millis(100);
const MAX_RETRANSMISSION_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_RETRANSMISSION_ATTEMPTS: u32 = 3;
const MAX_PENDING_CONTROL_MESSAGES: usize = 32;
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(1);
const CONTROL_RETRANSMISSION_TIMEOUT: Duration = Duration::from_millis(500);
const PATH_DEGRADED_AFTER: Duration = Duration::from_secs(3);
const PATH_FAILED_AFTER: Duration = Duration::from_secs(6);
const STATUS_REPORT_INTERVAL: Duration = Duration::from_secs(2);

pub trait SessionStream: AsyncRead + AsyncWrite + Send + Unpin {}

impl<T> SessionStream for T where T: AsyncRead + AsyncWrite + Send + Unpin {}

pub type BoxedSessionStream = Box<dyn SessionStream>;

#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum OpenStreamError {
    #[error("Session is closed")]
    SessionClosed,
    #[error("Session Stream capacity is exhausted")]
    ResourceLimit,
    #[error("Egress rejected the Stream with {error:?}")]
    Rejected { error: ErrorClass, reason: Vec<u8> },
}

#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum OpenUdpError {
    #[error("Session is closed")]
    SessionClosed,
    #[error("Session UDP Association capacity is exhausted")]
    ResourceLimit,
    #[error("Egress rejected the UDP Association with {error:?}")]
    Rejected { error: ErrorClass, reason: Vec<u8> },
}

pub struct IngressUdpHandle {
    association_id: u64,
    commands: mpsc::Sender<IngressCommand>,
    datagrams: mpsc::Receiver<Vec<u8>>,
    closed: bool,
}

impl std::fmt::Debug for IngressUdpHandle {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("IngressUdpHandle")
            .field("association_id", &self.association_id)
            .field("closed", &self.closed)
            .finish_non_exhaustive()
    }
}

impl IngressUdpHandle {
    pub const fn association_id(&self) -> u64 {
        self.association_id
    }

    pub async fn send(&self, payload: Vec<u8>) -> Result<(), OpenUdpError> {
        let (reply, result) = oneshot::channel();
        self.commands
            .send(IngressCommand::SendUdp {
                association_id: self.association_id,
                payload,
                reply,
            })
            .await
            .map_err(|_| OpenUdpError::SessionClosed)?;
        result.await.map_err(|_| OpenUdpError::SessionClosed)?
    }

    pub async fn receive(&mut self) -> Option<Vec<u8>> {
        self.datagrams.recv().await
    }

    pub async fn close(mut self) -> Result<(), OpenUdpError> {
        self.closed = true;
        send_udp_close(&self.commands, self.association_id).await
    }
}

impl Drop for IngressUdpHandle {
    fn drop(&mut self) {
        if self.closed {
            return;
        }
        let (reply, _result) = oneshot::channel();
        let _ = self.commands.try_send(IngressCommand::CloseUdp {
            association_id: self.association_id,
            reply,
        });
    }
}

#[derive(Debug, Clone, Error, PartialEq, Eq)]
#[error("target Stream open failed with {error:?}")]
pub struct EgressStreamOpenError {
    pub error: ErrorClass,
    pub reason: Vec<u8>,
}

impl EgressStreamOpenError {
    #[must_use]
    pub fn new(error: ErrorClass, reason: impl Into<Vec<u8>>) -> Self {
        Self {
            error,
            reason: reason.into(),
        }
    }
}

#[async_trait]
pub trait EgressStreamFactory: Send + Sync + 'static {
    async fn open(
        &self,
        target: TargetEndpoint,
    ) -> Result<BoxedSessionStream, EgressStreamOpenError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EgressStatusConfig {
    pub capacity_bps: u64,
    pub recommended_path_count: u64,
    pub max_streams_per_ingress: usize,
    pub quota_remaining: Option<u64>,
    pub traffic_multiplier_basis_points: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EgressStatusSample {
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
    pub quota_remaining: Option<u64>,
    pub traffic_multiplier_basis_points: u32,
}

pub trait EgressStatusProvider: std::fmt::Debug + Send + Sync + 'static {
    fn sample(&self) -> EgressStatusSample;
}

#[derive(Debug)]
struct StaticEgressStatusProvider(EgressStatusConfig);

impl EgressStatusProvider for StaticEgressStatusProvider {
    fn sample(&self) -> EgressStatusSample {
        EgressStatusSample {
            connected: true,
            service_state: EgressServiceState::Up,
            load_basis_points: 0,
            connection_utilization_basis_points: 0,
            bandwidth_utilization_basis_points: 0,
            active_sessions: 1,
            active_streams: 0,
            active_target_connections: 0,
            capacity_bps: self.0.capacity_bps,
            recommended_path_count: self.0.recommended_path_count,
            quota_remaining: self.0.quota_remaining,
            traffic_multiplier_basis_points: self.0.traffic_multiplier_basis_points,
        }
    }
}

impl Default for EgressStatusConfig {
    fn default() -> Self {
        Self {
            capacity_bps: 1_000_000_000,
            recommended_path_count: 1,
            max_streams_per_ingress: MAX_SESSION_STREAMS,
            quota_remaining: None,
            traffic_multiplier_basis_points: 10_000,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionSnapshot {
    pub session_id: SessionId,
    pub path_id: PathId,
    pub ready_paths: usize,
    pub ready_path_ids: Vec<PathId>,
    pub degraded_paths: usize,
    pub effective_capacity_bps: u64,
    pub egress_aggregate_capacity_bps: u64,
    pub recommended_path_count: u64,
    pub path_quality: BTreeMap<PathId, PathQualitySnapshot>,
    pub active_streams: usize,
    pub pending_stream_opens: usize,
    pub retained_outbound_bytes: usize,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub closed: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathExclusionReason {
    HeartbeatStale,
    StatusStale,
    Draining,
    HardUnavailable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathQualitySnapshot {
    pub rtt_ms: u64,
    pub jitter_ms: u64,
    pub loss_ppm: u32,
    pub throughput_bps: u64,
    pub reordering_events: u64,
    pub exclusion_reason: Option<PathExclusionReason>,
}

#[derive(Debug, Error)]
pub enum SessionRuntimeError {
    #[error("Session byte stream failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("Session Noise record failed: {0}")]
    Noise(#[from] NoiseError),
    #[error("Session frame failed: {0}")]
    Frame(#[from] FrameCodecError),
    #[error("Session message failed: {0}")]
    Message(#[from] MessageCodecError),
    #[error("Session reliability state failed: {0}")]
    Reliability(#[from] ReliabilityError),
    #[error("Session record ciphertext length {actual} is outside {minimum}..={maximum}")]
    InvalidCiphertextLength {
        actual: usize,
        minimum: usize,
        maximum: usize,
    },
    #[error("Session Noise state lock is poisoned")]
    NoiseStatePoisoned,
    #[error("Session frame sequence is exhausted")]
    FrameSequenceExhausted,
    #[error("Session received a frame for another Session or Path")]
    WrongPathIdentity,
    #[error("Session received unexpected frame {0:?}")]
    UnexpectedFrame(FrameType),
    #[error("Session Path closed")]
    PathClosed,
    #[error(
        "Session Path closed with {bytes} unacknowledged bytes; timed retransmission is unavailable"
    )]
    UnacknowledgedData { bytes: usize },
    #[error("Session runtime limit is invalid")]
    InvalidRuntimeLimit,
    #[error("Session task failed: {0}")]
    Task(String),
    #[error("Session multipath state failed: {0}")]
    Multipath(#[from] MultipathError),
    #[error("admitted Path belongs to another Session")]
    WrongSession,
    #[error("Session UDP runtime failed: {0}")]
    Udp(#[from] crate::UdpRuntimeError),
}

pub struct IngressSessionHandle {
    commands: mpsc::Sender<IngressCommand>,
    snapshots: watch::Receiver<SessionSnapshot>,
    task: Option<JoinHandle<Result<SessionSnapshot, SessionRuntimeError>>>,
    stream_capacity: usize,
}

impl std::fmt::Debug for IngressSessionHandle {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("IngressSessionHandle")
            .field("snapshot", &self.snapshots.borrow())
            .field("stream_capacity", &self.stream_capacity)
            .finish_non_exhaustive()
    }
}

impl IngressSessionHandle {
    pub fn start<S>(path: IngressAdmittedPath<S>) -> Result<Self, SessionRuntimeError>
    where
        S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
        let session_id = path.session_id();
        let path_id = path.path_id();
        let ready = path.limits().clone();
        let records = path.into_transport();
        let buffer_limit = runtime_buffer_limit(&ready)?;
        let stream_capacity = buffer_limit.clamp(1, 64 * 1024);
        let (commands, command_rx) = mpsc::channel(COMMAND_QUEUE_CAPACITY);
        let initial = SessionSnapshot {
            session_id,
            path_id,
            ready_paths: 1,
            ready_path_ids: vec![path_id],
            degraded_paths: 0,
            effective_capacity_bps: 0,
            egress_aggregate_capacity_bps: 0,
            recommended_path_count: 1,
            path_quality: BTreeMap::new(),
            active_streams: 0,
            pending_stream_opens: 0,
            retained_outbound_bytes: 0,
            bytes_sent: 0,
            bytes_received: 0,
            closed: false,
        };
        let (snapshot_tx, snapshots) = watch::channel(initial);
        let actor = SessionActor::new(
            records,
            SessionActorInit {
                role: ActorRole::Ingress,
                udp_factory: None,
                session_id,
                path_id,
                ready,
                commands: Some(command_rx),
                snapshots: snapshot_tx,
                egress_status: EgressStatusConfig::default(),
                status_provider: None,
            },
        )?;
        let task = tokio::spawn(actor.run());
        Ok(Self {
            commands,
            snapshots,
            task: Some(task),
            stream_capacity,
        })
    }

    pub async fn open_tcp(
        &self,
        target: TargetEndpoint,
    ) -> Result<BoxedSessionStream, OpenStreamError> {
        let eligible = self
            .snapshot()
            .ready_path_ids
            .into_iter()
            .map(|path_id| (path_id, 100))
            .collect();
        self.open_tcp_routed(target, eligible).await
    }

    pub async fn open_tcp_routed(
        &self,
        target: TargetEndpoint,
        eligible_paths: BTreeMap<PathId, u32>,
    ) -> Result<BoxedSessionStream, OpenStreamError> {
        let (client, actor_io) = duplex(self.stream_capacity);
        let (reply, result) = oneshot::channel();
        self.commands
            .send(IngressCommand::OpenTcp {
                target,
                io: Box::new(actor_io),
                eligible_paths: (!eligible_paths.is_empty()).then_some(eligible_paths),
                multipath_config: None,
                reply,
            })
            .await
            .map_err(|_| OpenStreamError::SessionClosed)?;
        result.await.map_err(|_| OpenStreamError::SessionClosed)??;
        Ok(Box::new(client))
    }

    pub async fn open_tcp_routed_with_config(
        &self,
        target: TargetEndpoint,
        eligible_paths: BTreeMap<PathId, u32>,
        multipath_config: MultipathConfig,
    ) -> Result<BoxedSessionStream, OpenStreamError> {
        let (client, actor_io) = duplex(self.stream_capacity);
        let (reply, result) = oneshot::channel();
        self.commands
            .send(IngressCommand::OpenTcp {
                target,
                io: Box::new(actor_io),
                eligible_paths: (!eligible_paths.is_empty()).then_some(eligible_paths),
                multipath_config: Some(multipath_config),
                reply,
            })
            .await
            .map_err(|_| OpenStreamError::SessionClosed)?;
        result.await.map_err(|_| OpenStreamError::SessionClosed)??;
        Ok(Box::new(client))
    }

    pub async fn open_udp(&self, target: TargetEndpoint) -> Result<IngressUdpHandle, OpenUdpError> {
        let eligible = self
            .snapshot()
            .ready_path_ids
            .into_iter()
            .map(|path_id| (path_id, 100))
            .collect();
        self.open_udp_routed(target, eligible).await
    }

    pub async fn open_udp_routed(
        &self,
        target: TargetEndpoint,
        eligible_paths: BTreeMap<PathId, u32>,
    ) -> Result<IngressUdpHandle, OpenUdpError> {
        let (datagrams_tx, datagrams) = mpsc::channel(STREAM_COMMAND_QUEUE_CAPACITY);
        let (reply, result) = oneshot::channel();
        self.commands
            .send(IngressCommand::OpenUdp {
                target,
                datagrams: datagrams_tx,
                eligible_paths: (!eligible_paths.is_empty()).then_some(eligible_paths),
                multipath_config: None,
                reply,
            })
            .await
            .map_err(|_| OpenUdpError::SessionClosed)?;
        let association_id = result.await.map_err(|_| OpenUdpError::SessionClosed)??;
        Ok(IngressUdpHandle {
            association_id,
            commands: self.commands.clone(),
            datagrams,
            closed: false,
        })
    }

    pub async fn open_udp_routed_with_config(
        &self,
        target: TargetEndpoint,
        eligible_paths: BTreeMap<PathId, u32>,
        multipath_config: MultipathConfig,
    ) -> Result<IngressUdpHandle, OpenUdpError> {
        let (datagrams_tx, datagrams) = mpsc::channel(STREAM_COMMAND_QUEUE_CAPACITY);
        let (reply, result) = oneshot::channel();
        self.commands
            .send(IngressCommand::OpenUdp {
                target,
                datagrams: datagrams_tx,
                eligible_paths: (!eligible_paths.is_empty()).then_some(eligible_paths),
                multipath_config: Some(multipath_config),
                reply,
            })
            .await
            .map_err(|_| OpenUdpError::SessionClosed)?;
        let association_id = result.await.map_err(|_| OpenUdpError::SessionClosed)??;
        Ok(IngressUdpHandle {
            association_id,
            commands: self.commands.clone(),
            datagrams,
            closed: false,
        })
    }

    pub async fn add_path<S>(
        &self,
        path: IngressAdmittedPath<S>,
        observation: MultipathPathObservation,
    ) -> Result<(), SessionRuntimeError>
    where
        S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
        let path = ErasedAdmittedPath::from_ingress(path);
        let (reply, result) = oneshot::channel();
        self.commands
            .send(IngressCommand::AddPath {
                path: Box::new(path),
                observation,
                reply,
            })
            .await
            .map_err(|_| SessionRuntimeError::PathClosed)?;
        result.await.map_err(|_| SessionRuntimeError::PathClosed)?
    }

    pub async fn drain_path(&self, path_id: PathId) -> Result<(), SessionRuntimeError> {
        send_path_command(&self.commands, path_id, false).await
    }

    pub async fn close_path(&self, path_id: PathId) -> Result<(), SessionRuntimeError> {
        send_path_command(&self.commands, path_id, true).await
    }

    pub async fn update_path_economic_status(
        &self,
        path_id: PathId,
        status: PathEconomicStatus,
    ) -> Result<(), SessionRuntimeError> {
        let (reply, result) = oneshot::channel();
        self.commands
            .send(IngressCommand::PathEconomics {
                path_id,
                status,
                reply,
            })
            .await
            .map_err(|_| SessionRuntimeError::PathClosed)?;
        result.await.map_err(|_| SessionRuntimeError::PathClosed)?
    }

    pub async fn update_path_observation(
        &self,
        path_id: PathId,
        observation: MultipathPathObservation,
    ) -> Result<(), SessionRuntimeError> {
        let (reply, result) = oneshot::channel();
        self.commands
            .send(IngressCommand::PathObservation {
                path_id,
                observation,
                reply,
            })
            .await
            .map_err(|_| SessionRuntimeError::PathClosed)?;
        result.await.map_err(|_| SessionRuntimeError::PathClosed)?
    }

    pub fn try_close_path(&self, path_id: PathId) -> Result<(), SessionRuntimeError> {
        let (reply, _result) = oneshot::channel();
        self.commands
            .try_send(IngressCommand::PathControl {
                path_id,
                close: true,
                reply,
            })
            .map_err(|_| SessionRuntimeError::PathClosed)
    }

    pub async fn wait_path_closed(&self, path_id: PathId) {
        let mut snapshots = self.snapshots.clone();
        loop {
            let snapshot = snapshots.borrow().clone();
            if snapshot.closed || !snapshot.ready_path_ids.contains(&path_id) {
                return;
            }
            if snapshots.changed().await.is_err() {
                return;
            }
        }
    }

    #[must_use]
    pub fn snapshot(&self) -> SessionSnapshot {
        self.snapshots.borrow().clone()
    }

    pub async fn shutdown(mut self) -> Result<SessionSnapshot, SessionRuntimeError> {
        self.commands
            .send(IngressCommand::Shutdown)
            .await
            .map_err(|_| SessionRuntimeError::PathClosed)?;
        let task = self.task.take().ok_or(SessionRuntimeError::PathClosed)?;
        task.await
            .map_err(|error| SessionRuntimeError::Task(error.to_string()))?
    }
}

#[async_trait]
impl SessionUdpHandle for IngressSessionHandle {
    async fn exchange_datagram(
        &self,
        target: TargetEndpoint,
        payload: Vec<u8>,
        max_response_bytes: usize,
    ) -> Result<Vec<u8>, SessionUdpError> {
        let mut association = self
            .open_udp(target)
            .await
            .map_err(|_| SessionUdpError::Unavailable)?;
        association
            .send(payload)
            .await
            .map_err(|_| SessionUdpError::Exchange)?;
        let response = association
            .receive()
            .await
            .ok_or(SessionUdpError::Unavailable)?;
        let _ = association.close().await;
        if response.len() > max_response_bytes {
            return Err(SessionUdpError::ResponseTooLarge);
        }
        Ok(response)
    }
}

impl Drop for IngressSessionHandle {
    fn drop(&mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

pub async fn run_egress_session<S, F>(
    path: EgressAdmittedPath<S>,
    factory: F,
) -> Result<SessionSnapshot, SessionRuntimeError>
where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    F: EgressStreamFactory,
{
    EgressSessionHandle::start(path, factory)?.wait().await
}

pub struct EgressSessionHandle {
    controller: EgressSessionController,
    task: Option<JoinHandle<Result<SessionSnapshot, SessionRuntimeError>>>,
}

#[derive(Clone)]
pub struct EgressSessionController {
    commands: mpsc::Sender<IngressCommand>,
    snapshots: watch::Receiver<SessionSnapshot>,
}

impl std::fmt::Debug for EgressSessionController {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("EgressSessionController")
            .field("snapshot", &self.snapshots.borrow())
            .finish_non_exhaustive()
    }
}

impl EgressSessionController {
    pub async fn add_path<S>(
        &self,
        path: EgressAdmittedPath<S>,
        observation: MultipathPathObservation,
    ) -> Result<(), SessionRuntimeError>
    where
        S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
        let path = ErasedAdmittedPath::from_egress(path);
        let (reply, result) = oneshot::channel();
        self.commands
            .send(IngressCommand::AddPath {
                path: Box::new(path),
                observation,
                reply,
            })
            .await
            .map_err(|_| SessionRuntimeError::PathClosed)?;
        result.await.map_err(|_| SessionRuntimeError::PathClosed)?
    }

    pub async fn drain_path(&self, path_id: PathId) -> Result<(), SessionRuntimeError> {
        send_path_command(&self.commands, path_id, false).await
    }

    pub async fn close_path(&self, path_id: PathId) -> Result<(), SessionRuntimeError> {
        send_path_command(&self.commands, path_id, true).await
    }

    pub fn try_close_path(&self, path_id: PathId) -> Result<(), SessionRuntimeError> {
        let (reply, _result) = oneshot::channel();
        self.commands
            .try_send(IngressCommand::PathControl {
                path_id,
                close: true,
                reply,
            })
            .map_err(|_| SessionRuntimeError::PathClosed)
    }

    pub async fn wait_path_closed(&self, path_id: PathId) {
        let mut snapshots = self.snapshots.clone();
        loop {
            let snapshot = snapshots.borrow().clone();
            if snapshot.closed || !snapshot.ready_path_ids.contains(&path_id) {
                return;
            }
            if snapshots.changed().await.is_err() {
                return;
            }
        }
    }

    #[must_use]
    pub fn snapshot(&self) -> SessionSnapshot {
        self.snapshots.borrow().clone()
    }
}

impl EgressSessionHandle {
    pub fn start<S, F>(path: EgressAdmittedPath<S>, factory: F) -> Result<Self, SessionRuntimeError>
    where
        S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
        F: EgressStreamFactory,
    {
        Self::start_inner(path, factory, None, EgressStatusConfig::default(), None)
    }

    pub fn start_with_udp<S, F, U>(
        path: EgressAdmittedPath<S>,
        factory: F,
        udp_factory: U,
    ) -> Result<Self, SessionRuntimeError>
    where
        S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
        F: EgressStreamFactory,
        U: UdpTargetFactory + 'static,
    {
        Self::start_inner(
            path,
            factory,
            Some(Arc::new(udp_factory)),
            EgressStatusConfig::default(),
            None,
        )
    }

    pub fn start_with_status<S, F>(
        path: EgressAdmittedPath<S>,
        factory: F,
        status: EgressStatusConfig,
    ) -> Result<Self, SessionRuntimeError>
    where
        S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
        F: EgressStreamFactory,
    {
        if status.capacity_bps == 0
            || status.recommended_path_count == 0
            || status.max_streams_per_ingress == 0
            || status.traffic_multiplier_basis_points == 0
        {
            return Err(SessionRuntimeError::InvalidRuntimeLimit);
        }
        Self::start_inner(path, factory, None, status, None)
    }

    pub fn start_with_udp_and_status<S, F, U>(
        path: EgressAdmittedPath<S>,
        factory: F,
        udp_factory: U,
        status: EgressStatusConfig,
    ) -> Result<Self, SessionRuntimeError>
    where
        S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
        F: EgressStreamFactory,
        U: UdpTargetFactory + 'static,
    {
        if status.capacity_bps == 0
            || status.recommended_path_count == 0
            || status.max_streams_per_ingress == 0
            || status.traffic_multiplier_basis_points == 0
        {
            return Err(SessionRuntimeError::InvalidRuntimeLimit);
        }
        Self::start_inner(path, factory, Some(Arc::new(udp_factory)), status, None)
    }

    pub fn start_with_udp_and_status_provider<S, F, U>(
        path: EgressAdmittedPath<S>,
        factory: F,
        udp_factory: U,
        status: EgressStatusConfig,
        provider: Arc<dyn EgressStatusProvider>,
    ) -> Result<Self, SessionRuntimeError>
    where
        S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
        F: EgressStreamFactory,
        U: UdpTargetFactory + 'static,
    {
        Self::start_inner(
            path,
            factory,
            Some(Arc::new(udp_factory)),
            status,
            Some(provider),
        )
    }

    fn start_inner<S, F>(
        path: EgressAdmittedPath<S>,
        factory: F,
        udp_factory: Option<Arc<dyn UdpTargetFactory>>,
        egress_status: EgressStatusConfig,
        status_provider: Option<Arc<dyn EgressStatusProvider>>,
    ) -> Result<Self, SessionRuntimeError>
    where
        S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
        F: EgressStreamFactory,
    {
        if egress_status.capacity_bps == 0
            || egress_status.recommended_path_count == 0
            || egress_status.max_streams_per_ingress == 0
            || egress_status.traffic_multiplier_basis_points == 0
        {
            return Err(SessionRuntimeError::InvalidRuntimeLimit);
        }
        let session_id = path.session_id();
        let path_id = path.path_id();
        let ready = path.limits().clone();
        let records = path.into_transport();
        let initial = SessionSnapshot {
            session_id,
            path_id,
            ready_paths: 1,
            ready_path_ids: vec![path_id],
            degraded_paths: 0,
            effective_capacity_bps: 0,
            egress_aggregate_capacity_bps: 0,
            recommended_path_count: 1,
            path_quality: BTreeMap::new(),
            active_streams: 0,
            pending_stream_opens: 0,
            retained_outbound_bytes: 0,
            bytes_sent: 0,
            bytes_received: 0,
            closed: false,
        };
        let (snapshot_tx, snapshots) = watch::channel(initial);
        let (commands, command_rx) = mpsc::channel(COMMAND_QUEUE_CAPACITY);
        let actor = SessionActor::new(
            records,
            SessionActorInit {
                role: ActorRole::Egress {
                    factory: Arc::new(factory),
                },
                udp_factory,
                session_id,
                path_id,
                ready,
                commands: Some(command_rx),
                snapshots: snapshot_tx,
                egress_status,
                status_provider,
            },
        )?;
        let task = tokio::spawn(actor.run());
        Ok(Self {
            controller: EgressSessionController {
                commands,
                snapshots,
            },
            task: Some(task),
        })
    }

    #[must_use]
    pub fn controller(&self) -> EgressSessionController {
        self.controller.clone()
    }

    pub async fn wait(mut self) -> Result<SessionSnapshot, SessionRuntimeError> {
        let task = self.task.take().ok_or(SessionRuntimeError::PathClosed)?;
        task.await
            .map_err(|error| SessionRuntimeError::Task(error.to_string()))?
    }

    pub async fn shutdown(mut self) -> Result<SessionSnapshot, SessionRuntimeError> {
        self.controller
            .commands
            .send(IngressCommand::Shutdown)
            .await
            .map_err(|_| SessionRuntimeError::PathClosed)?;
        let task = self.task.take().ok_or(SessionRuntimeError::PathClosed)?;
        task.await
            .map_err(|error| SessionRuntimeError::Task(error.to_string()))?
    }
}

impl Drop for EgressSessionHandle {
    fn drop(&mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

enum ActorRole {
    Ingress,
    Egress {
        factory: Arc<dyn EgressStreamFactory>,
    },
}

struct SessionActorInit {
    role: ActorRole,
    udp_factory: Option<Arc<dyn UdpTargetFactory>>,
    session_id: SessionId,
    path_id: PathId,
    ready: pathchord_core::PathReady,
    commands: Option<mpsc::Receiver<IngressCommand>>,
    snapshots: watch::Sender<SessionSnapshot>,
    egress_status: EgressStatusConfig,
    status_provider: Option<Arc<dyn EgressStatusProvider>>,
}

enum IngressCommand {
    OpenTcp {
        target: TargetEndpoint,
        io: BoxedSessionStream,
        eligible_paths: Option<BTreeMap<PathId, u32>>,
        multipath_config: Option<MultipathConfig>,
        reply: oneshot::Sender<Result<(), OpenStreamError>>,
    },
    OpenUdp {
        target: TargetEndpoint,
        datagrams: mpsc::Sender<Vec<u8>>,
        eligible_paths: Option<BTreeMap<PathId, u32>>,
        multipath_config: Option<MultipathConfig>,
        reply: oneshot::Sender<Result<u64, OpenUdpError>>,
    },
    SendUdp {
        association_id: u64,
        payload: Vec<u8>,
        reply: oneshot::Sender<Result<(), OpenUdpError>>,
    },
    CloseUdp {
        association_id: u64,
        reply: oneshot::Sender<Result<(), OpenUdpError>>,
    },
    AddPath {
        path: Box<ErasedAdmittedPath>,
        observation: MultipathPathObservation,
        reply: oneshot::Sender<Result<(), SessionRuntimeError>>,
    },
    PathControl {
        path_id: PathId,
        close: bool,
        reply: oneshot::Sender<Result<(), SessionRuntimeError>>,
    },
    PathEconomics {
        path_id: PathId,
        status: PathEconomicStatus,
        reply: oneshot::Sender<Result<(), SessionRuntimeError>>,
    },
    PathObservation {
        path_id: PathId,
        observation: MultipathPathObservation,
        reply: oneshot::Sender<Result<(), SessionRuntimeError>>,
    },
    Shutdown,
}

struct ErasedAdmittedPath {
    session_id: SessionId,
    path_id: PathId,
    ready: pathchord_core::PathReady,
    records: NoiseRecordStream<BoxedSessionStream>,
}

impl ErasedAdmittedPath {
    fn from_ingress<S>(path: IngressAdmittedPath<S>) -> Self
    where
        S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
        let session_id = path.session_id();
        let path_id = path.path_id();
        let ready = path.limits().clone();
        let records = path.into_transport();
        let limits = records.limits();
        let (io, noise) = records.into_parts();
        Self {
            session_id,
            path_id,
            ready,
            records: NoiseRecordStream::new(Box::new(io), noise, limits),
        }
    }

    fn from_egress<S>(path: EgressAdmittedPath<S>) -> Self
    where
        S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
        let session_id = path.session_id();
        let path_id = path.path_id();
        let ready = path.limits().clone();
        let records = path.into_transport();
        let limits = records.limits();
        let (io, noise) = records.into_parts();
        Self {
            session_id,
            path_id,
            ready,
            records: NoiseRecordStream::new(Box::new(io), noise, limits),
        }
    }
}

struct PendingIngressOpen {
    io: BoxedSessionStream,
    eligible_paths: Option<BTreeMap<PathId, u32>>,
    reply: oneshot::Sender<Result<(), OpenStreamError>>,
}

struct PendingIngressUdp {
    datagrams: mpsc::Sender<Vec<u8>>,
    eligible_paths: Option<BTreeMap<PathId, u32>>,
    reply: oneshot::Sender<Result<u64, OpenUdpError>>,
}

struct IngressUdpAssociation {
    datagrams: mpsc::Sender<Vec<u8>>,
    eligible_paths: Option<BTreeMap<PathId, u32>>,
}

#[derive(Clone)]
enum CachedOpenResult {
    Pending,
    Opened { metadata: Vec<u8> },
    Rejected { error: ErrorClass, reason: Vec<u8> },
}

struct CachedEgressOpen {
    request: StreamOpen,
    result: CachedOpenResult,
    eligible_paths: BTreeMap<PathId, u32>,
}

struct FactoryCompletion {
    stream_id: StreamId,
    request_id: RequestId,
    result: Result<BoxedSessionStream, EgressStreamOpenError>,
}

enum ReaderEvent {
    Frame {
        path_id: PathId,
        frame: PathFrame,
    },
    Closed {
        path_id: PathId,
    },
    Failed {
        path_id: PathId,
        error: SessionRuntimeError,
    },
}

enum PathWriterCommand {
    Send {
        message: Message,
        reply: oneshot::Sender<Result<(), SessionRuntimeError>>,
    },
}

enum StreamEvent {
    Data {
        stream_id: StreamId,
        data: Vec<u8>,
        permit: OwnedSemaphorePermit,
    },
    LocalFin {
        stream_id: StreamId,
    },
    IoFailed {
        stream_id: StreamId,
        reason: String,
    },
    Delivered {
        stream_id: StreamId,
        bytes: usize,
    },
    Finished {
        stream_id: StreamId,
    },
}

enum StreamIoCommand {
    Data {
        bytes: Vec<u8>,
        permits: Vec<OwnedSemaphorePermit>,
    },
    Fin,
    Reset,
}

struct OutboundChunk {
    offset: u64,
    data: Vec<u8>,
    _permit: OwnedSemaphorePermit,
}

struct RetainedChunk {
    data: Vec<u8>,
    _permit: OwnedSemaphorePermit,
    last_path: PathId,
    last_sent_at: Instant,
    attempts: u32,
}

struct InboundPermit {
    end: u64,
    permit: OwnedSemaphorePermit,
}

struct ActiveStream {
    commands: mpsc::Sender<StreamIoCommand>,
    task: JoinHandle<()>,
    receive: StreamReceiveBuffer,
    inbound_permits: Vec<InboundPermit>,
    next_send_offset: u64,
    pending: VecDeque<OutboundChunk>,
    retained: BTreeMap<u64, RetainedChunk>,
    remote_receive_limit: u64,
    local_receive_limit: u64,
    local_fin: bool,
    remote_fin: bool,
    eligible_paths: Option<BTreeMap<PathId, u32>>,
}

struct ExtraPath {
    sender: mpsc::Sender<PathWriterCommand>,
    writer_task: JoinHandle<()>,
    reader_task: JoinHandle<()>,
}

#[derive(Clone, Copy)]
struct PendingHeartbeat {
    first_sent_at: Instant,
    last_sent_at: Instant,
    attempts: u32,
}

struct PathHealth {
    sender: ControlSender<PendingHeartbeat>,
    receiver: ControlReceiver,
    last_heartbeat_received: Instant,
    last_heartbeat_sent: Instant,
    last_status_received: Instant,
    last_status_sent: Instant,
    rtt_ms: u64,
    jitter_ms: u64,
    sent_controls: u64,
    retransmitted_controls: u64,
    bytes_since_observation: u64,
    last_observation_at: Instant,
    throughput_bps: u64,
    reordering_events: u64,
    data_events: u64,
    exclusion_reason: Option<PathExclusionReason>,
    relationship_weight_basis_points: u16,
}

impl PathHealth {
    fn new(now: Instant) -> Result<Self, ReliabilityError> {
        Ok(Self {
            sender: ControlSender::new(MAX_PENDING_CONTROL_MESSAGES)?,
            receiver: ControlReceiver::new(MAX_PENDING_CONTROL_MESSAGES)?,
            last_heartbeat_received: now,
            last_heartbeat_sent: now,
            last_status_received: now,
            last_status_sent: now,
            rtt_ms: 1,
            jitter_ms: 0,
            sent_controls: 0,
            retransmitted_controls: 0,
            bytes_since_observation: 0,
            last_observation_at: now,
            throughput_bps: 0,
            reordering_events: 0,
            data_events: 0,
            exclusion_reason: None,
            relationship_weight_basis_points: 10_000,
        })
    }
}

struct SessionActor<W> {
    role: ActorRole,
    writer: RecordWriter<W>,
    reader_task: JoinHandle<()>,
    frame_tx: mpsc::Sender<ReaderEvent>,
    frames: mpsc::Receiver<ReaderEvent>,
    extra_paths: HashMap<PathId, ExtraPath>,
    multipath: MultipathSession,
    path_health: HashMap<PathId, PathHealth>,
    next_status_report_seq: u64,
    egress_status: EgressStatusConfig,
    status_provider: Arc<dyn EgressStatusProvider>,
    recommended_path_count: u64,
    egress_aggregate_capacity_bps: u64,
    commands: Option<mpsc::Receiver<IngressCommand>>,
    stream_events: mpsc::Receiver<StreamEvent>,
    stream_event_tx: mpsc::Sender<StreamEvent>,
    factory_results: mpsc::Receiver<FactoryCompletion>,
    factory_result_tx: mpsc::Sender<FactoryCompletion>,
    opening_tasks: HashMap<StreamId, JoinHandle<()>>,
    streams: HashMap<StreamId, ActiveStream>,
    pending_ingress: HashMap<StreamId, PendingIngressOpen>,
    egress_requests: HashMap<RequestId, CachedEgressOpen>,
    egress_streams: HashMap<StreamId, RequestId>,
    pending_ingress_udp: HashMap<u64, PendingIngressUdp>,
    ingress_udp: HashMap<u64, IngressUdpAssociation>,
    egress_udp_paths: HashMap<u64, BTreeMap<PathId, u32>>,
    next_udp_association_id: u64,
    udp_send_sequences: HashMap<u64, u64>,
    udp_runtime: Option<UdpAssociationRuntime<Arc<dyn UdpTargetFactory>>>,
    session_id: SessionId,
    path_id: PathId,
    limits: ProtocolLimits,
    buffer_limit: usize,
    chunk_size: usize,
    next_frame_seq: u64,
    next_stream_id: u64,
    next_request_id: u128,
    send_budget: Arc<Semaphore>,
    inbound_budget: Arc<Semaphore>,
    remote_session_limit: u64,
    local_session_limit: u64,
    session_sent_total: u64,
    session_received_total: u64,
    bytes_sent: u64,
    bytes_received: u64,
    snapshots: watch::Sender<SessionSnapshot>,
}

impl<S> SessionActor<WriteHalf<S>>
where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    fn new(
        records: NoiseRecordStream<S>,
        init: SessionActorInit,
    ) -> Result<Self, SessionRuntimeError> {
        let SessionActorInit {
            role,
            udp_factory,
            session_id,
            path_id,
            ready,
            commands,
            snapshots,
            egress_status,
            status_provider,
        } = init;
        let buffer_limit = runtime_buffer_limit(&ready)?;
        let limits = records.limits();
        let chunk_limit = usize::try_from(ready.max_frame_payload)
            .map_err(|_| SessionRuntimeError::InvalidRuntimeLimit)?
            .min(limits.max_frame_payload());
        let chunk_size = chunk_limit
            .saturating_sub(FRAME_OVERHEAD_RESERVE)
            .min(MAX_DATA_CHUNK)
            .min(buffer_limit);
        if chunk_size == 0 || buffer_limit > u32::MAX as usize {
            return Err(SessionRuntimeError::InvalidRuntimeLimit);
        }
        let (io, noise) = records.into_parts();
        let next_frame_seq = noise
            .next_send_nonce()
            .ok_or(SessionRuntimeError::FrameSequenceExhausted)?;
        let noise = Arc::new(Mutex::new(noise));
        let (read, write) = split(io);
        let writer = RecordWriter {
            io: write,
            noise: Arc::clone(&noise),
            limits,
        };
        let (frame_tx, frames) = mpsc::channel(FRAME_QUEUE_CAPACITY);
        let reader = RecordReader {
            io: read,
            noise,
            limits,
        };
        let reader_task = tokio::spawn(record_reader_loop(path_id, reader, frame_tx.clone()));
        let (stream_event_tx, stream_events) = mpsc::channel(STREAM_EVENT_QUEUE_CAPACITY);
        let (factory_result_tx, factory_results) = mpsc::channel(COMMAND_QUEUE_CAPACITY);
        let mut multipath = MultipathSession::new(
            session_id,
            MultipathConfig {
                session_replication_budget_bytes: buffer_limit as u64,
                default_stream_replication_budget_bytes: buffer_limit as u64,
                ..MultipathConfig::default()
            },
        )?;
        multipath.add_path(path_id, MultipathPathObservation::default())?;
        let udp_runtime = udp_factory
            .map(|factory| {
                UdpAssociationRuntime::new(factory, limits, MAX_SESSION_STREAMS, buffer_limit)
            })
            .transpose()?;
        let now = Instant::now();
        let path_health = HashMap::from([(path_id, PathHealth::new(now)?)]);
        let status_provider: Arc<dyn EgressStatusProvider> =
            status_provider.unwrap_or_else(|| Arc::new(StaticEgressStatusProvider(egress_status)));
        Ok(Self {
            role,
            writer,
            reader_task,
            frame_tx,
            frames,
            extra_paths: HashMap::new(),
            multipath,
            path_health,
            next_status_report_seq: 0,
            egress_status,
            status_provider,
            recommended_path_count: egress_status.recommended_path_count,
            egress_aggregate_capacity_bps: 0,
            commands,
            stream_events,
            stream_event_tx,
            factory_results,
            factory_result_tx,
            opening_tasks: HashMap::new(),
            streams: HashMap::new(),
            pending_ingress: HashMap::new(),
            egress_requests: HashMap::new(),
            egress_streams: HashMap::new(),
            pending_ingress_udp: HashMap::new(),
            ingress_udp: HashMap::new(),
            egress_udp_paths: HashMap::new(),
            next_udp_association_id: 1,
            udp_send_sequences: HashMap::new(),
            udp_runtime,
            session_id,
            path_id,
            limits,
            buffer_limit,
            chunk_size,
            next_frame_seq,
            next_stream_id: 1,
            next_request_id: 1,
            send_budget: Arc::new(Semaphore::new(buffer_limit)),
            inbound_budget: Arc::new(Semaphore::new(buffer_limit)),
            remote_session_limit: buffer_limit as u64,
            local_session_limit: buffer_limit as u64,
            session_sent_total: 0,
            session_received_total: 0,
            bytes_sent: 0,
            bytes_received: 0,
            snapshots,
        })
    }
}

impl<W> SessionActor<W>
where
    W: AsyncWrite + Send + Unpin + 'static,
{
    async fn run(mut self) -> Result<SessionSnapshot, SessionRuntimeError> {
        self.publish_snapshot(false);
        let result = self.run_loop().await;
        self.cleanup().await;
        self.publish_snapshot(true);
        result.map(|()| self.current_snapshot(true))
    }

    async fn run_loop(&mut self) -> Result<(), SessionRuntimeError> {
        let mut retransmission_tick = tokio::time::interval(MIN_RETRANSMISSION_TIMEOUT);
        retransmission_tick.set_missed_tick_behavior(MissedTickBehavior::Skip);
        retransmission_tick.tick().await;
        loop {
            tokio::select! {
                command = receive_command(&mut self.commands) => {
                    match command {
                        Some(command) => {
                            if self.handle_command(command).await? {
                                return Ok(());
                            }
                        }
                        None => self.commands = None,
                    }
                }
                frame = self.frames.recv() => {
                    match frame {
                        Some(ReaderEvent::Frame { path_id, frame }) => {
                            if self.handle_frame(path_id, frame).await? {
                                return Ok(());
                            }
                        }
                        Some(ReaderEvent::Closed { path_id }) => {
                            if self.handle_path_failure(path_id).await? {
                                let retained = self.retained_outbound_bytes();
                                return if retained == 0 {
                                    Err(SessionRuntimeError::PathClosed)
                                } else {
                                    Err(SessionRuntimeError::UnacknowledgedData { bytes: retained })
                                };
                            }
                        }
                        Some(ReaderEvent::Failed { path_id, error }) => {
                            if self.handle_path_failure(path_id).await? {
                                return Err(error);
                            }
                        }
                        None => return Err(SessionRuntimeError::PathClosed),
                    }
                }
                event = self.stream_events.recv() => {
                    if let Some(event) = event {
                        self.handle_stream_event(event).await?;
                    }
                }
                completion = self.factory_results.recv() => {
                    if let Some(completion) = completion {
                        self.handle_factory_completion(completion).await?;
                    }
                }
                _ = retransmission_tick.tick() => {
                    self.handle_retransmission_timeouts().await?;
                    self.poll_udp_targets().await?;
                    if self.handle_path_health().await? {
                        return Err(SessionRuntimeError::PathClosed);
                    }
                    self.multipath.advance_status_age(
                        MIN_RETRANSMISSION_TIMEOUT.as_millis() as u64,
                    );
                }
            }
            self.publish_snapshot(false);
        }
    }

    async fn handle_command(
        &mut self,
        command: IngressCommand,
    ) -> Result<bool, SessionRuntimeError> {
        match command {
            IngressCommand::Shutdown => {
                self.send_message(Message::SessionClose(SessionClose {
                    error: ErrorClass::PathFailure,
                    reason: b"Ingress shutdown".to_vec(),
                }))
                .await?;
                Ok(true)
            }
            IngressCommand::OpenUdp {
                target,
                datagrams,
                eligible_paths,
                multipath_config,
                reply,
            } => {
                if let Some(config) = multipath_config
                    && let Err(error) = self.multipath.reconfigure(config)
                {
                    let _ = reply.send(Err(OpenUdpError::Rejected {
                        error: ErrorClass::LocalPolicy,
                        reason: error.to_string().into_bytes(),
                    }));
                    return Ok(false);
                }
                if !matches!(self.role, ActorRole::Ingress)
                    || self.pending_ingress_udp.len() + self.ingress_udp.len()
                        >= MAX_SESSION_STREAMS
                {
                    let _ = reply.send(Err(OpenUdpError::ResourceLimit));
                    return Ok(false);
                }
                let association_id = self.next_udp_association_id;
                if association_id > MAX_VARINT {
                    let _ = reply.send(Err(OpenUdpError::ResourceLimit));
                    return Ok(false);
                }
                self.next_udp_association_id = association_id
                    .checked_add(1)
                    .ok_or(SessionRuntimeError::FrameSequenceExhausted)?;
                let target_flags = target_flags(&target);
                if target_flags == 0 {
                    let _ = reply.send(Err(OpenUdpError::ResourceLimit));
                    return Ok(false);
                }
                let open = Message::UdpOpen(UdpOpen {
                    association_id,
                    target_flags,
                    target,
                });
                self.pending_ingress_udp.insert(
                    association_id,
                    PendingIngressUdp {
                        datagrams,
                        eligible_paths: eligible_paths.clone(),
                        reply,
                    },
                );
                if let Some(eligible) = eligible_paths {
                    let mut sent = false;
                    for path_id in eligible.keys().copied() {
                        if self.send_message_on(path_id, open.clone()).await.is_ok() {
                            sent = true;
                        }
                    }
                    if !sent {
                        return Err(SessionRuntimeError::PathClosed);
                    }
                } else {
                    self.send_message(open).await?;
                }
                Ok(false)
            }
            IngressCommand::SendUdp {
                association_id,
                payload,
                reply,
            } => {
                if !self.ingress_udp.contains_key(&association_id)
                    || payload.len() > self.limits.max_frame_payload()
                {
                    let _ = reply.send(Err(OpenUdpError::SessionClosed));
                    return Ok(false);
                }
                let sequence = self.udp_send_sequences.entry(association_id).or_insert(0);
                let datagram_seq = *sequence;
                *sequence = sequence
                    .checked_add(1)
                    .ok_or(SessionRuntimeError::FrameSequenceExhausted)?;
                self.send_udp_message(
                    association_id,
                    Message::UdpDatagram(UdpDatagram {
                        association_id,
                        datagram_seq,
                        payload,
                    }),
                )
                .await?;
                let _ = reply.send(Ok(()));
                Ok(false)
            }
            IngressCommand::CloseUdp {
                association_id,
                reply,
            } => {
                self.send_udp_message(
                    association_id,
                    Message::UdpClose(UdpClose {
                        association_id,
                        error: ErrorClass::PathFailure,
                        reason: b"UDP Association closed locally".to_vec(),
                    }),
                )
                .await?;
                self.pending_ingress_udp.remove(&association_id);
                self.ingress_udp.remove(&association_id);
                self.udp_send_sequences.remove(&association_id);
                let _ = reply.send(Ok(()));
                Ok(false)
            }
            IngressCommand::AddPath {
                path,
                observation,
                reply,
            } => {
                let result = self.add_erased_path(*path, observation);
                let _ = reply.send(result);
                Ok(false)
            }
            IngressCommand::PathControl {
                path_id,
                close,
                reply,
            } => {
                if close {
                    if let Err(error) = self
                        .send_message_on(
                            path_id,
                            Message::PathClose(PathClose {
                                error: ErrorClass::PathFailure,
                                reason: b"Path closed by local runtime".to_vec(),
                            }),
                        )
                        .await
                    {
                        let _ = reply.send(Err(SessionRuntimeError::PathClosed));
                        return Err(error);
                    }
                    match self.handle_path_failure(path_id).await {
                        Ok(session_closed) => {
                            let _ = reply.send(Ok(()));
                            Ok(session_closed)
                        }
                        Err(error) => {
                            let _ = reply.send(Err(SessionRuntimeError::PathClosed));
                            Err(error)
                        }
                    }
                } else {
                    if let Err(error) = self
                        .send_message_on(
                            path_id,
                            Message::PathDrain(PathDrain {
                                drain_reason: 0,
                                deadline_ms: 0,
                            }),
                        )
                        .await
                    {
                        let _ = reply.send(Err(SessionRuntimeError::PathClosed));
                        return Err(error);
                    }
                    let result = self.multipath.drain_path(path_id).map_err(Into::into);
                    if let Some(health) = self.path_health.get_mut(&path_id) {
                        health.exclusion_reason = Some(PathExclusionReason::Draining);
                    }
                    let _ = reply.send(result);
                    Ok(false)
                }
            }
            IngressCommand::PathEconomics {
                path_id,
                status,
                reply,
            } => {
                let reason =
                    (!status.hard_available).then_some(PathExclusionReason::HardUnavailable);
                let result = self
                    .multipath
                    .update_economic_status(path_id, status)
                    .map_err(Into::into);
                if let Some(health) = self.path_health.get_mut(&path_id) {
                    health.exclusion_reason = reason;
                }
                let _ = reply.send(result);
                Ok(false)
            }
            IngressCommand::PathObservation {
                path_id,
                observation,
                reply,
            } => {
                if let Some(health) = self.path_health.get_mut(&path_id) {
                    health.relationship_weight_basis_points = observation.weight_basis_points;
                }
                let result = self
                    .multipath
                    .update_observation(path_id, observation)
                    .map_err(Into::into);
                let _ = reply.send(result);
                Ok(false)
            }
            IngressCommand::OpenTcp {
                target,
                io,
                eligible_paths,
                multipath_config,
                reply,
            } => {
                if let Some(config) = multipath_config
                    && let Err(error) = self.multipath.reconfigure(config)
                {
                    let _ = reply.send(Err(OpenStreamError::Rejected {
                        error: ErrorClass::LocalPolicy,
                        reason: error.to_string().into_bytes(),
                    }));
                    return Ok(false);
                }
                if !matches!(self.role, ActorRole::Ingress)
                    || self.streams.len() + self.pending_ingress.len() >= MAX_SESSION_STREAMS
                {
                    let _ = reply.send(Err(OpenStreamError::ResourceLimit));
                    return Ok(false);
                }
                let stream_id = match StreamId::new(self.next_stream_id) {
                    Ok(value) => value,
                    Err(_) => {
                        let _ = reply.send(Err(OpenStreamError::ResourceLimit));
                        return Ok(false);
                    }
                };
                self.next_stream_id = self
                    .next_stream_id
                    .checked_add(1)
                    .ok_or(SessionRuntimeError::FrameSequenceExhausted)?;
                let request_id = RequestId::new(self.next_request_id);
                self.next_request_id = self
                    .next_request_id
                    .checked_add(1)
                    .ok_or(SessionRuntimeError::FrameSequenceExhausted)?;
                let open = Message::StreamOpen(StreamOpen {
                    stream_id,
                    request_id,
                    target,
                });
                self.pending_ingress.insert(
                    stream_id,
                    PendingIngressOpen {
                        io,
                        eligible_paths,
                        reply,
                    },
                );
                if let Some(eligible) = self
                    .pending_ingress
                    .get(&stream_id)
                    .and_then(|pending| pending.eligible_paths.clone())
                {
                    let mut sent = false;
                    for path_id in eligible.keys().copied() {
                        if self.send_message_on(path_id, open.clone()).await.is_ok() {
                            sent = true;
                        }
                    }
                    if !sent {
                        return Err(SessionRuntimeError::PathClosed);
                    }
                } else {
                    self.send_message(open).await?;
                }
                Ok(false)
            }
        }
    }

    fn add_erased_path(
        &mut self,
        path: ErasedAdmittedPath,
        observation: MultipathPathObservation,
    ) -> Result<(), SessionRuntimeError> {
        if path.session_id != self.session_id {
            return Err(SessionRuntimeError::WrongSession);
        }
        if path.records.limits() != self.limits
            || path.ready.max_frame_payload < (self.chunk_size + FRAME_OVERHEAD_RESERVE) as u64
            || path.ready.max_session_buffering < self.buffer_limit as u64
        {
            return Err(SessionRuntimeError::InvalidRuntimeLimit);
        }
        self.multipath.add_path(path.path_id, observation)?;
        let path_id = path.path_id;
        let limits = path.records.limits();
        let (io, noise) = path.records.into_parts();
        let next_frame_seq = noise
            .next_send_nonce()
            .ok_or(SessionRuntimeError::FrameSequenceExhausted)?;
        let noise = Arc::new(Mutex::new(noise));
        let (read, write) = split(io);
        let writer = RecordWriter {
            io: write,
            noise: Arc::clone(&noise),
            limits,
        };
        let reader = RecordReader {
            io: read,
            noise,
            limits,
        };
        let reader_task = tokio::spawn(record_reader_loop(path_id, reader, self.frame_tx.clone()));
        let (sender, commands) = mpsc::channel(COMMAND_QUEUE_CAPACITY);
        let writer_task = tokio::spawn(path_writer_loop(
            writer,
            commands,
            self.session_id,
            path_id,
            limits,
            next_frame_seq,
        ));
        self.extra_paths.insert(
            path_id,
            ExtraPath {
                sender,
                writer_task,
                reader_task,
            },
        );
        self.path_health
            .insert(path_id, PathHealth::new(Instant::now())?);
        Ok(())
    }

    const fn outbound_direction(&self) -> ScheduleDirection {
        match &self.role {
            ActorRole::Ingress => ScheduleDirection::Upstream,
            ActorRole::Egress { .. } => ScheduleDirection::Downstream,
        }
    }

    async fn handle_path_failure(&mut self, path_id: PathId) -> Result<bool, SessionRuntimeError> {
        if let Some(path) = self.extra_paths.remove(&path_id) {
            path.writer_task.abort();
            path.reader_task.abort();
            let _ = path.writer_task.await;
            let _ = path.reader_task.await;
        }
        self.path_health.remove(&path_id);
        let outcome = self.multipath.mark_path_failed(path_id)?;
        if !outcome.session_closed {
            let retained: Vec<_> = self
                .streams
                .iter()
                .flat_map(|(stream_id, stream)| {
                    stream.retained.iter().filter_map(|(offset, retained)| {
                        (retained.last_path == path_id).then_some((
                            *stream_id,
                            *offset,
                            stream.eligible_paths.clone(),
                        ))
                    })
                })
                .collect();
            let mut reset = Vec::new();
            for (stream_id, offset, eligible) in retained {
                let plan = self.multipath.retransmit_range(
                    stream_id,
                    offset,
                    Some(path_id),
                    self.outbound_direction(),
                    eligible.as_ref(),
                );
                let Ok(plan) = plan else {
                    reset.push(stream_id);
                    continue;
                };
                self.send_message_on(plan.path_id, Message::StreamData(plan.data.clone()))
                    .await?;
                if let Some(stream) = self.streams.get_mut(&stream_id)
                    && let Some(retained) = stream.retained.get_mut(&offset)
                {
                    retained.last_path = plan.path_id;
                    retained.last_sent_at = Instant::now();
                    retained.attempts = plan.attempt;
                }
            }
            reset.sort_unstable();
            reset.dedup();
            for stream_id in reset {
                self.reset_stream(
                    stream_id,
                    true,
                    b"no eligible Path remains for this Stream".to_vec(),
                )
                .await?;
            }
        }
        Ok(outcome.session_closed)
    }

    async fn handle_retransmission_timeouts(&mut self) -> Result<(), SessionRuntimeError> {
        let now = Instant::now();
        let mut due = Vec::new();
        let mut exhausted = Vec::new();
        for (stream_id, stream) in &self.streams {
            for (offset, retained) in &stream.retained {
                let timeout_ms = self.multipath.retransmission_timeout_ms(
                    retained.last_path,
                    MIN_RETRANSMISSION_TIMEOUT.as_millis() as u64,
                    MAX_RETRANSMISSION_TIMEOUT.as_millis() as u64,
                )?;
                if now.duration_since(retained.last_sent_at) >= Duration::from_millis(timeout_ms) {
                    if retained.attempts >= MAX_RETRANSMISSION_ATTEMPTS {
                        exhausted.push(*stream_id);
                    } else {
                        due.push((
                            *stream_id,
                            *offset,
                            retained.last_path,
                            stream.eligible_paths.clone(),
                        ));
                    }
                }
            }
        }
        exhausted.sort_unstable();
        exhausted.dedup();
        for stream_id in exhausted {
            self.reset_stream(
                stream_id,
                true,
                b"retransmission retry limit exceeded".to_vec(),
            )
            .await?;
        }
        for (stream_id, offset, last_path, eligible) in due {
            if !self.streams.contains_key(&stream_id) {
                continue;
            }
            let excluded = (self.multipath.ready_path_count() > 1).then_some(last_path);
            let plan = self.multipath.retransmit_range(
                stream_id,
                offset,
                excluded,
                self.outbound_direction(),
                eligible.as_ref(),
            )?;
            self.send_message_on(plan.path_id, Message::StreamData(plan.data.clone()))
                .await?;
            if let Some(stream) = self.streams.get_mut(&stream_id)
                && let Some(retained) = stream.retained.get_mut(&offset)
            {
                retained.last_path = plan.path_id;
                retained.last_sent_at = now;
                retained.attempts = plan.attempt;
            }
        }
        Ok(())
    }

    async fn handle_udp_message(
        &mut self,
        path_id: PathId,
        message: Message,
    ) -> Result<(), SessionRuntimeError> {
        if matches!(self.role, ActorRole::Egress { .. }) {
            if let Message::UdpOpen(open) = &message {
                self.egress_udp_paths
                    .entry(open.association_id)
                    .or_default()
                    .entry(path_id)
                    .or_insert(100);
            }
            let responses = if let Some(runtime) = self.udp_runtime.as_mut() {
                runtime.handle(message).await?
            } else {
                match message {
                    Message::UdpOpen(open) => vec![Message::UdpOpenErr(UdpOpenErr {
                        association_id: open.association_id,
                        error: ErrorClass::EgressFailure,
                        reason: b"UDP is unavailable on this Egress".to_vec(),
                    })],
                    _ => Vec::new(),
                }
            };
            for response in responses {
                self.send_udp_message(udp_association_id(&response), response)
                    .await?;
            }
            return Ok(());
        }

        match message {
            Message::UdpOpenOk(response) => {
                if let Some(pending) = self.pending_ingress_udp.remove(&response.association_id) {
                    self.ingress_udp.insert(
                        response.association_id,
                        IngressUdpAssociation {
                            datagrams: pending.datagrams,
                            eligible_paths: pending.eligible_paths,
                        },
                    );
                    self.udp_send_sequences.insert(response.association_id, 0);
                    let _ = pending.reply.send(Ok(response.association_id));
                }
            }
            Message::UdpOpenErr(response) => {
                if let Some(pending) = self.pending_ingress_udp.remove(&response.association_id) {
                    let _ = pending.reply.send(Err(OpenUdpError::Rejected {
                        error: response.error,
                        reason: response.reason,
                    }));
                }
            }
            Message::UdpDatagram(datagram) => {
                if let Some(delivery) = self.ingress_udp.get(&datagram.association_id)
                    && delivery.datagrams.try_send(datagram.payload).is_err()
                {
                    let association_id = datagram.association_id;
                    self.ingress_udp.remove(&association_id);
                    self.udp_send_sequences.remove(&association_id);
                    self.send_udp_message(
                        association_id,
                        Message::UdpClose(UdpClose {
                            association_id,
                            error: ErrorClass::PathFailure,
                            reason: b"Ingress UDP receive queue is full".to_vec(),
                        }),
                    )
                    .await?;
                }
            }
            Message::UdpClose(close) => {
                self.pending_ingress_udp.remove(&close.association_id);
                self.ingress_udp.remove(&close.association_id);
                self.egress_udp_paths.remove(&close.association_id);
                self.udp_send_sequences.remove(&close.association_id);
            }
            _ => return Err(SessionRuntimeError::UnexpectedFrame(message.frame_type())),
        }
        Ok(())
    }

    async fn poll_udp_targets(&mut self) -> Result<(), SessionRuntimeError> {
        let Some(runtime) = self.udp_runtime.as_ref() else {
            return Ok(());
        };
        let association_ids = runtime.association_ids();
        for association_id in association_ids {
            let received = {
                let runtime = self
                    .udp_runtime
                    .as_mut()
                    .expect("UDP runtime was checked above");
                tokio::time::timeout(
                    Duration::from_millis(1),
                    runtime.receive_from_target(association_id),
                )
                .await
            };
            let mut messages = match received {
                Ok(Ok(messages)) => messages,
                Ok(Err(crate::UdpRuntimeError::UnknownAssociation(_))) | Err(_) => Vec::new(),
                Ok(Err(error)) => return Err(error.into()),
            };
            if let Some(runtime) = self.udp_runtime.as_mut() {
                while let Ok(Some(message)) = runtime.dequeue(association_id) {
                    messages.push(message);
                }
            }
            for message in messages {
                self.send_udp_message(association_id, message).await?;
            }
        }
        Ok(())
    }

    async fn handle_path_health(&mut self) -> Result<bool, SessionRuntimeError> {
        let now = Instant::now();
        let ingress = matches!(self.role, ActorRole::Ingress);
        let egress = !ingress;
        let mut outgoing = Vec::new();
        let mut degraded = Vec::new();
        let mut active = Vec::new();
        let mut failed = Vec::new();
        let mut status_paths = Vec::new();

        for (path_id, health) in &mut self.path_health {
            let heartbeat_age = now.duration_since(health.last_heartbeat_received);
            let status_age = now.duration_since(health.last_status_received);
            if heartbeat_age >= PATH_FAILED_AFTER {
                failed.push(*path_id);
                continue;
            }
            if heartbeat_age >= PATH_DEGRADED_AFTER
                || (ingress && status_age >= PATH_DEGRADED_AFTER)
            {
                degraded.push(*path_id);
            } else {
                active.push(*path_id);
            }

            if now.duration_since(health.last_heartbeat_sent) >= HEARTBEAT_INTERVAL
                && health.sender.pending_len() < MAX_PENDING_CONTROL_MESSAGES
            {
                let sequence = health.sender.enqueue(PendingHeartbeat {
                    first_sent_at: now,
                    last_sent_at: now,
                    attempts: 0,
                })?;
                health.last_heartbeat_sent = now;
                health.sent_controls = health.sent_controls.saturating_add(1);
                outgoing.push((
                    *path_id,
                    Message::Heartbeat(Heartbeat {
                        control_seq: sequence,
                    }),
                ));
            }
            for (sequence, pending) in health.sender.pending_mut() {
                if now.duration_since(pending.last_sent_at) < CONTROL_RETRANSMISSION_TIMEOUT {
                    continue;
                }
                if pending.attempts >= MAX_RETRANSMISSION_ATTEMPTS {
                    continue;
                }
                pending.attempts += 1;
                pending.last_sent_at = now;
                health.retransmitted_controls = health.retransmitted_controls.saturating_add(1);
                outgoing.push((
                    *path_id,
                    Message::Heartbeat(Heartbeat {
                        control_seq: sequence,
                    }),
                ));
            }
            if egress && now.duration_since(health.last_status_sent) >= STATUS_REPORT_INTERVAL {
                health.last_status_sent = now;
                status_paths.push(*path_id);
            }
        }

        for path_id in degraded {
            self.multipath.degrade_path(path_id)?;
            if let Some(health) = self.path_health.get_mut(&path_id) {
                health.exclusion_reason = Some(
                    if now.duration_since(health.last_heartbeat_received) >= PATH_DEGRADED_AFTER {
                        PathExclusionReason::HeartbeatStale
                    } else {
                        PathExclusionReason::StatusStale
                    },
                );
            }
        }
        for path_id in active {
            self.multipath.activate_path(path_id)?;
            if self.multipath.ready_path_ids().contains(&path_id)
                && let Some(health) = self.path_health.get_mut(&path_id)
            {
                health.exclusion_reason = None;
            }
        }

        for (path_id, health) in &mut self.path_health {
            let elapsed_ms = now
                .duration_since(health.last_observation_at)
                .as_millis()
                .max(1)
                .min(u128::from(u64::MAX)) as u64;
            health.throughput_bps = health
                .bytes_since_observation
                .saturating_mul(8)
                .saturating_mul(1_000)
                / elapsed_ms;
            health.bytes_since_observation = 0;
            health.last_observation_at = now;
            let loss_ppm = health
                .retransmitted_controls
                .saturating_mul(1_000_000)
                .checked_div(health.sent_controls.max(1))
                .unwrap_or(0)
                .min(1_000_000) as u32;
            self.multipath.update_observation(
                *path_id,
                MultipathPathObservation {
                    effective_capacity_bps: health.throughput_bps.max(1),
                    weight_basis_points: health.relationship_weight_basis_points,
                    rtt_ms: health.rtt_ms.max(1),
                    jitter_ms: health.jitter_ms,
                    loss_basis_points: (loss_ppm / 100).min(10_000) as u16,
                },
            )?;
        }
        for path_id in status_paths {
            let report_seqno = self.next_status_report_seq;
            self.next_status_report_seq = self
                .next_status_report_seq
                .checked_add(1)
                .ok_or(SessionRuntimeError::FrameSequenceExhausted)?;
            let sample = self.status_provider.sample();
            let adjusted_capacity = sample
                .capacity_bps
                .saturating_mul(u64::from(sample.traffic_multiplier_basis_points))
                / 10_000;
            let quota_adjusted_capacity = if sample.quota_remaining == Some(0) {
                adjusted_capacity.saturating_mul(1_000) / 10_000
            } else {
                adjusted_capacity
            };
            outgoing.push((
                path_id,
                Message::StatusReport(StatusReport {
                    connected: sample.connected,
                    service_state: sample.service_state,
                    load_basis_points: sample.load_basis_points,
                    connection_utilization_basis_points: sample.connection_utilization_basis_points,
                    bandwidth_utilization_basis_points: sample.bandwidth_utilization_basis_points,
                    active_sessions: sample.active_sessions,
                    active_streams: sample.active_streams,
                    active_target_connections: sample.active_target_connections,
                    capacity_bps: quota_adjusted_capacity.max(1),
                    recommended_path_count: sample.recommended_path_count,
                    report_seqno,
                    sample_age_ms: 0,
                    expires_after_ms: PATH_FAILED_AFTER.as_millis() as u64,
                }),
            ));
        }
        for (path_id, message) in outgoing {
            if self.send_message_on(path_id, message).await.is_err() {
                failed.push(path_id);
            }
        }
        failed.sort_unstable();
        failed.dedup();
        for path_id in failed {
            if self.handle_path_failure(path_id).await? {
                return Ok(true);
            }
        }
        Ok(false)
    }

    async fn handle_heartbeat(
        &mut self,
        path_id: PathId,
        heartbeat: Heartbeat,
    ) -> Result<(), SessionRuntimeError> {
        let Some(health) = self.path_health.get_mut(&path_id) else {
            return Ok(());
        };
        let _new = health.receiver.apply(heartbeat.control_seq)?;
        health.last_heartbeat_received = Instant::now();
        self.multipath.activate_path(path_id)?;
        if let Some(highest_contiguous) = health.receiver.highest_contiguous() {
            let ranges = health.receiver.selective_ranges();
            self.send_message_on(
                path_id,
                Message::ControlAck(ControlAck {
                    highest_contiguous,
                    ranges,
                }),
            )
            .await?;
        }
        Ok(())
    }

    fn handle_control_ack(&mut self, path_id: PathId, ack: ControlAck) {
        if let Some(health) = self.path_health.get_mut(&path_id) {
            let now = Instant::now();
            let samples: Vec<_> = health
                .sender
                .pending()
                .filter(|(sequence, _)| {
                    *sequence <= ack.highest_contiguous
                        || ack.ranges.iter().any(|range| range.contains(*sequence))
                })
                .map(|(_, pending)| {
                    now.duration_since(pending.first_sent_at)
                        .as_millis()
                        .max(1)
                        .min(u128::from(u64::MAX)) as u64
                })
                .collect();
            for sample in samples {
                let previous = health.rtt_ms;
                health.rtt_ms = previous.saturating_mul(7).saturating_add(sample) / 8;
                let deviation = previous.abs_diff(sample);
                health.jitter_ms = health.jitter_ms.saturating_mul(3).saturating_add(deviation) / 4;
            }
            health
                .sender
                .acknowledge(ack.highest_contiguous, &ack.ranges);
        }
    }

    async fn handle_frame(
        &mut self,
        path_id: PathId,
        frame: PathFrame,
    ) -> Result<bool, SessionRuntimeError> {
        if frame.header().session_id() != self.session_id || frame.header().path_id() != path_id {
            return Err(SessionRuntimeError::WrongPathIdentity);
        }
        let message = Message::decode(frame.header().frame_type(), frame.payload(), self.limits)?;
        match message {
            Message::StreamOpen(request) => self.handle_egress_open(path_id, request).await?,
            Message::StreamOpenOk(response) => self.handle_ingress_open_ok(response).await?,
            Message::StreamOpenErr(response) => self.handle_ingress_open_err(response),
            Message::StreamData(data) => self.handle_stream_data(path_id, data).await?,
            Message::StreamAck(ack) => self.handle_stream_ack(ack).await?,
            Message::StreamWindow(window) => self.handle_stream_window(window).await?,
            Message::StreamFin(fin) => self.handle_stream_fin(fin).await?,
            Message::StreamRst(rst) => self.handle_stream_rst(rst).await,
            Message::PathDrain(_) => self.multipath.drain_path(path_id)?,
            Message::PathClose(_) => return self.handle_path_failure(path_id).await,
            Message::SessionClose(_) => return Ok(true),
            Message::StatusReport(report) => {
                let capacity_bps = report.capacity_bps;
                let recommended_path_count = report.recommended_path_count;
                if self.multipath.apply_status_report(path_id, report)?
                    == StatusReportDisposition::Accepted
                    && let Some(health) = self.path_health.get_mut(&path_id)
                {
                    health.last_status_received = Instant::now();
                    self.egress_aggregate_capacity_bps = capacity_bps.max(1);
                    self.recommended_path_count = recommended_path_count.max(1);
                }
            }
            message @ (Message::UdpOpen(_)
            | Message::UdpOpenOk(_)
            | Message::UdpOpenErr(_)
            | Message::UdpDatagram(_)
            | Message::UdpClose(_)) => self.handle_udp_message(path_id, message).await?,
            Message::Heartbeat(heartbeat) => self.handle_heartbeat(path_id, heartbeat).await?,
            Message::ControlAck(ack) => self.handle_control_ack(path_id, ack),
            other => return Err(SessionRuntimeError::UnexpectedFrame(other.frame_type())),
        }
        Ok(false)
    }

    async fn handle_egress_open(
        &mut self,
        received_path_id: PathId,
        request: StreamOpen,
    ) -> Result<(), SessionRuntimeError> {
        let ActorRole::Egress { factory } = &self.role else {
            return Err(SessionRuntimeError::UnexpectedFrame(FrameType::StreamOpen));
        };
        if let Some(cached) = self.egress_requests.get_mut(&request.request_id) {
            if cached.request != request {
                return self
                    .send_open_error(
                        request.stream_id,
                        ErrorClass::EgressFailure,
                        b"RequestID conflicts with an existing Stream".to_vec(),
                    )
                    .await;
            }
            cached.eligible_paths.entry(received_path_id).or_insert(100);
            if let Some(stream) = self.streams.get_mut(&request.stream_id)
                && let Some(eligible) = stream.eligible_paths.as_mut()
            {
                eligible.entry(received_path_id).or_insert(100);
            }
            match cached.result.clone() {
                CachedOpenResult::Pending => return Ok(()),
                CachedOpenResult::Opened { metadata } => {
                    self.send_message(Message::StreamOpenOk(StreamOpenOk {
                        stream_id: request.stream_id,
                        result_metadata: metadata,
                    }))
                    .await?;
                    return Ok(());
                }
                CachedOpenResult::Rejected { error, reason } => {
                    return self.send_open_error(request.stream_id, error, reason).await;
                }
            }
        }
        if self.egress_streams.contains_key(&request.stream_id)
            || self.streams.len() + self.opening_tasks.len()
                >= self.egress_status.max_streams_per_ingress
        {
            return self
                .send_open_error(
                    request.stream_id,
                    ErrorClass::EgressFailure,
                    b"StreamID or Session capacity is unavailable".to_vec(),
                )
                .await;
        }
        self.egress_streams
            .insert(request.stream_id, request.request_id);
        self.egress_requests.insert(
            request.request_id,
            CachedEgressOpen {
                request: request.clone(),
                result: CachedOpenResult::Pending,
                eligible_paths: BTreeMap::from([(received_path_id, 100)]),
            },
        );
        let factory = Arc::clone(factory);
        let result_tx = self.factory_result_tx.clone();
        let stream_id = request.stream_id;
        let request_id = request.request_id;
        let target = request.target;
        let task = tokio::spawn(async move {
            let result = factory.open(target).await;
            let _ = result_tx
                .send(FactoryCompletion {
                    stream_id,
                    request_id,
                    result,
                })
                .await;
        });
        self.opening_tasks.insert(stream_id, task);
        Ok(())
    }

    async fn handle_factory_completion(
        &mut self,
        completion: FactoryCompletion,
    ) -> Result<(), SessionRuntimeError> {
        if let Some(task) = self.opening_tasks.remove(&completion.stream_id) {
            task.await
                .map_err(|error| SessionRuntimeError::Task(error.to_string()))?;
        }
        let Some(cached) = self.egress_requests.get(&completion.request_id) else {
            return Ok(());
        };
        if cached.request.stream_id != completion.stream_id {
            return Ok(());
        }
        let eligible_paths = cached.eligible_paths.clone();
        match completion.result {
            Ok(io) => {
                self.spawn_active_stream(completion.stream_id, io, Some(eligible_paths))?;
                if let Some(cached) = self.egress_requests.get_mut(&completion.request_id) {
                    cached.result = CachedOpenResult::Opened {
                        metadata: Vec::new(),
                    };
                }
                self.send_stream_message(
                    completion.stream_id,
                    Message::StreamOpenOk(StreamOpenOk {
                        stream_id: completion.stream_id,
                        result_metadata: Vec::new(),
                    }),
                )
                .await?;
                self.send_window(completion.stream_id).await?;
            }
            Err(mut error) => {
                error.reason.truncate(self.limits.max_control_payload());
                if let Some(cached) = self.egress_requests.get_mut(&completion.request_id) {
                    cached.result = CachedOpenResult::Rejected {
                        error: error.error,
                        reason: error.reason.clone(),
                    };
                }
                self.send_open_error(completion.stream_id, error.error, error.reason)
                    .await?;
            }
        }
        Ok(())
    }

    async fn handle_ingress_open_ok(
        &mut self,
        response: StreamOpenOk,
    ) -> Result<(), SessionRuntimeError> {
        if !matches!(self.role, ActorRole::Ingress) {
            return Err(SessionRuntimeError::UnexpectedFrame(
                FrameType::StreamOpenOk,
            ));
        }
        let Some(pending) = self.pending_ingress.remove(&response.stream_id) else {
            if self.streams.contains_key(&response.stream_id) {
                return Ok(());
            }
            return Err(SessionRuntimeError::UnexpectedFrame(
                FrameType::StreamOpenOk,
            ));
        };
        self.spawn_active_stream(response.stream_id, pending.io, pending.eligible_paths)?;
        if let Err(error) = self.send_window(response.stream_id).await {
            let _ = pending.reply.send(Err(OpenStreamError::SessionClosed));
            return Err(error);
        }
        let _ = pending.reply.send(Ok(()));
        Ok(())
    }

    fn handle_ingress_open_err(&mut self, response: StreamOpenErr) {
        if let Some(pending) = self.pending_ingress.remove(&response.stream_id) {
            let _ = pending.reply.send(Err(OpenStreamError::Rejected {
                error: response.error,
                reason: response.reason,
            }));
        }
    }

    fn spawn_active_stream(
        &mut self,
        stream_id: StreamId,
        io: BoxedSessionStream,
        eligible_paths: Option<BTreeMap<PathId, u32>>,
    ) -> Result<(), SessionRuntimeError> {
        let receive = StreamReceiveBuffer::new(self.buffer_limit)?;
        let (commands, command_rx) = mpsc::channel(STREAM_COMMAND_QUEUE_CAPACITY);
        let events = self.stream_event_tx.clone();
        let budget = Arc::clone(&self.send_budget);
        let chunk_size = self.chunk_size;
        let task = tokio::spawn(run_stream_io(
            stream_id, io, command_rx, events, budget, chunk_size,
        ));
        self.streams.insert(
            stream_id,
            ActiveStream {
                commands,
                task,
                receive,
                inbound_permits: Vec::new(),
                next_send_offset: 0,
                pending: VecDeque::new(),
                retained: BTreeMap::new(),
                remote_receive_limit: self.buffer_limit as u64,
                local_receive_limit: self.buffer_limit as u64,
                local_fin: false,
                remote_fin: false,
                eligible_paths,
            },
        );
        Ok(())
    }

    async fn handle_stream_event(&mut self, event: StreamEvent) -> Result<(), SessionRuntimeError> {
        match event {
            StreamEvent::Data {
                stream_id,
                data,
                permit,
            } => self.queue_stream_data(stream_id, data, permit).await?,
            StreamEvent::LocalFin { stream_id } => {
                let should_send = self.streams.get_mut(&stream_id).is_some_and(|stream| {
                    if stream.local_fin {
                        false
                    } else {
                        stream.local_fin = true;
                        true
                    }
                });
                if should_send {
                    self.send_stream_message(
                        stream_id,
                        Message::StreamFin(StreamFin {
                            stream_id,
                            flags: STREAM_FLAG_FIN,
                        }),
                    )
                    .await?;
                }
            }
            StreamEvent::IoFailed { stream_id, reason } => {
                self.reset_stream(stream_id, true, reason.into_bytes())
                    .await?;
            }
            StreamEvent::Delivered { stream_id, bytes } => {
                let Some(stream) = self.streams.get_mut(&stream_id) else {
                    return Ok(());
                };
                stream.local_receive_limit = stream
                    .local_receive_limit
                    .checked_add(bytes as u64)
                    .filter(|limit| *limit <= MAX_VARINT)
                    .ok_or(SessionRuntimeError::InvalidRuntimeLimit)?;
                self.local_session_limit = self
                    .local_session_limit
                    .checked_add(bytes as u64)
                    .filter(|limit| *limit <= MAX_VARINT)
                    .ok_or(SessionRuntimeError::InvalidRuntimeLimit)?;
                self.send_window(stream_id).await?;
            }
            StreamEvent::Finished { stream_id } => {
                if let Some(stream) = self.streams.remove(&stream_id) {
                    stream
                        .task
                        .await
                        .map_err(|error| SessionRuntimeError::Task(error.to_string()))?;
                }
            }
        }
        Ok(())
    }

    async fn queue_stream_data(
        &mut self,
        stream_id: StreamId,
        data: Vec<u8>,
        permit: OwnedSemaphorePermit,
    ) -> Result<(), SessionRuntimeError> {
        let Some(stream) = self.streams.get_mut(&stream_id) else {
            return Ok(());
        };
        if stream.local_fin {
            drop(permit);
            return Ok(());
        }
        let offset = stream.next_send_offset;
        stream.next_send_offset = offset
            .checked_add(data.len() as u64)
            .filter(|end| *end <= MAX_VARINT)
            .ok_or(SessionRuntimeError::FrameSequenceExhausted)?;
        stream.pending.push_back(OutboundChunk {
            offset,
            data,
            _permit: permit,
        });
        self.flush_stream(stream_id).await
    }

    async fn flush_stream(&mut self, stream_id: StreamId) -> Result<(), SessionRuntimeError> {
        loop {
            let next = {
                let Some(stream) = self.streams.get_mut(&stream_id) else {
                    return Ok(());
                };
                let Some(front) = stream.pending.front() else {
                    return Ok(());
                };
                let end = front.offset + front.data.len() as u64;
                if end > stream.remote_receive_limit
                    || self.session_sent_total + front.data.len() as u64 > self.remote_session_limit
                {
                    return Ok(());
                }
                stream.pending.pop_front()
            };
            let Some(chunk) = next else {
                return Ok(());
            };
            let length = chunk.data.len();
            let data = StreamData {
                stream_id,
                offset: chunk.offset,
                flags: 0,
                data: chunk.data.clone(),
            };
            let eligible = self
                .streams
                .get(&stream_id)
                .and_then(|stream| stream.eligible_paths.clone());
            let path_id = match eligible.as_ref() {
                Some(eligible) => {
                    self.multipath
                        .schedule_eligible(self.outbound_direction(), length, eligible)?
                        .path_id
                }
                None => {
                    self.multipath
                        .schedule(self.outbound_direction(), length)?
                        .path_id
                }
            };
            let retain_for_retransmission = self.multipath.retransmission_replication_enabled();
            if retain_for_retransmission {
                self.multipath
                    .retain_stream_data(data.clone(), "default", path_id)?;
            }
            let send_result = self
                .send_message_on(path_id, Message::StreamData(data))
                .await;
            self.session_sent_total += length as u64;
            self.bytes_sent += length as u64;
            if retain_for_retransmission && let Some(stream) = self.streams.get_mut(&stream_id) {
                stream.retained.insert(
                    chunk.offset,
                    RetainedChunk {
                        data: chunk.data,
                        _permit: chunk._permit,
                        last_path: path_id,
                        last_sent_at: Instant::now(),
                        attempts: 0,
                    },
                );
            }
            if let Err(error) = send_result
                && self.handle_path_failure(path_id).await?
            {
                return Err(error);
            }
        }
    }

    async fn handle_stream_data(
        &mut self,
        path_id: PathId,
        data: StreamData,
    ) -> Result<(), SessionRuntimeError> {
        if data.flags & STREAM_FLAG_RST != 0 {
            self.reset_stream(data.stream_id, false, b"peer reset Stream".to_vec())
                .await?;
            return Ok(());
        }
        if data.data.is_empty() {
            if data.flags & STREAM_FLAG_FIN != 0 {
                self.handle_stream_fin(StreamFin {
                    stream_id: data.stream_id,
                    flags: data.flags,
                })
                .await?;
            }
            return Ok(());
        }
        let Some(stream) = self.streams.get_mut(&data.stream_id) else {
            self.send_message(Message::StreamRst(StreamRst {
                stream_id: data.stream_id,
                error: ErrorClass::PathFailure,
                reason: b"unknown Stream".to_vec(),
            }))
            .await?;
            return Ok(());
        };
        if let Some(health) = self.path_health.get_mut(&path_id) {
            health.data_events = health.data_events.saturating_add(1);
            if data.offset != stream.receive.next_offset() {
                health.reordering_events = health.reordering_events.saturating_add(1);
            }
        }
        let end = data
            .offset
            .checked_add(data.data.len() as u64)
            .ok_or(SessionRuntimeError::InvalidRuntimeLimit)?;
        if end > stream.local_receive_limit
            || self.session_received_total + data.data.len() as u64 > self.local_session_limit
        {
            self.reset_stream(
                data.stream_id,
                true,
                b"peer exceeded advertised receive window".to_vec(),
            )
            .await?;
            return Ok(());
        }
        let permit =
            match Arc::clone(&self.inbound_budget).try_acquire_many_owned(data.data.len() as u32) {
                Ok(permit) => permit,
                Err(_) => {
                    self.reset_stream(
                        data.stream_id,
                        true,
                        b"Session receive buffer is full".to_vec(),
                    )
                    .await?;
                    return Ok(());
                }
            };
        let result = stream.receive.insert(data.offset, &data.data)?;
        stream.inbound_permits.push(InboundPermit { end, permit });
        let next_offset = stream.receive.next_offset();
        let mut permits = Vec::new();
        let mut remaining = Vec::new();
        for entry in std::mem::take(&mut stream.inbound_permits) {
            if entry.end <= next_offset {
                permits.push(entry.permit);
            } else {
                remaining.push(entry);
            }
        }
        stream.inbound_permits = remaining;
        let commands = stream.commands.clone();
        let delivered = result.delivered;
        if result.duplicate {
            self.session_received_total += delivered.len() as u64;
            self.bytes_received += delivered.len() as u64;
        } else {
            self.session_received_total += data.data.len() as u64;
            self.bytes_received += data.data.len() as u64;
        }
        self.send_stream_message(
            data.stream_id,
            Message::StreamAck(StreamAck {
                stream_id: data.stream_id,
                ranges: vec![AckRange {
                    start: data.offset,
                    end: end - 1,
                }],
            }),
        )
        .await?;
        if delivered.is_empty() {
            drop(permits);
        } else if commands
            .try_send(StreamIoCommand::Data {
                bytes: delivered,
                permits,
            })
            .is_err()
        {
            self.reset_stream(
                data.stream_id,
                true,
                b"Stream target writer is stalled".to_vec(),
            )
            .await?;
        }
        if data.flags & STREAM_FLAG_FIN != 0 {
            self.handle_stream_fin(StreamFin {
                stream_id: data.stream_id,
                flags: data.flags,
            })
            .await?;
        }
        Ok(())
    }

    async fn handle_stream_ack(&mut self, ack: StreamAck) -> Result<(), SessionRuntimeError> {
        self.multipath.acknowledge(&ack);
        let Some(stream) = self.streams.get_mut(&ack.stream_id) else {
            return Ok(());
        };
        stream.retained.retain(|offset, chunk| {
            let end = *offset + chunk.data.len() as u64 - 1;
            !ack.ranges
                .iter()
                .any(|range| range.contains(*offset) && range.contains(end))
        });
        self.flush_stream(ack.stream_id).await
    }

    async fn handle_stream_window(
        &mut self,
        window: StreamWindow,
    ) -> Result<(), SessionRuntimeError> {
        let Some(stream) = self.streams.get_mut(&window.stream_id) else {
            return Ok(());
        };
        if window.stream_limit < stream.remote_receive_limit
            || window.session_limit < self.remote_session_limit
        {
            self.reset_stream(
                window.stream_id,
                true,
                b"peer decreased an absolute receive window".to_vec(),
            )
            .await?;
            return Ok(());
        }
        stream.remote_receive_limit = window.stream_limit;
        self.remote_session_limit = self.remote_session_limit.max(window.session_limit);
        self.flush_stream(window.stream_id).await
    }

    async fn handle_stream_fin(&mut self, fin: StreamFin) -> Result<(), SessionRuntimeError> {
        if fin.flags & STREAM_FLAG_FIN == 0 {
            return self
                .reset_stream(fin.stream_id, true, b"invalid FIN flags".to_vec())
                .await;
        }
        let Some(stream) = self.streams.get_mut(&fin.stream_id) else {
            return Ok(());
        };
        if !stream.remote_fin {
            stream.remote_fin = true;
            if stream.commands.try_send(StreamIoCommand::Fin).is_err() {
                self.reset_stream(
                    fin.stream_id,
                    true,
                    b"Stream target writer is unavailable".to_vec(),
                )
                .await?;
            }
        }
        Ok(())
    }

    async fn handle_stream_rst(&mut self, rst: StreamRst) {
        let _ = self.reset_stream(rst.stream_id, false, rst.reason).await;
    }

    async fn reset_stream(
        &mut self,
        stream_id: StreamId,
        notify_peer: bool,
        mut reason: Vec<u8>,
    ) -> Result<(), SessionRuntimeError> {
        reason.truncate(self.limits.max_control_payload());
        if notify_peer {
            self.send_stream_message(
                stream_id,
                Message::StreamRst(StreamRst {
                    stream_id,
                    error: ErrorClass::PathFailure,
                    reason: reason.clone(),
                }),
            )
            .await?;
        }
        if let Some(pending) = self.pending_ingress.remove(&stream_id) {
            let _ = pending.reply.send(Err(OpenStreamError::SessionClosed));
        }
        if let Some(stream) = self.streams.remove(&stream_id) {
            let _ = stream.commands.try_send(StreamIoCommand::Reset);
            stream.task.abort();
            let _ = stream.task.await;
        }
        Ok(())
    }

    async fn send_window(&mut self, stream_id: StreamId) -> Result<(), SessionRuntimeError> {
        let Some(stream) = self.streams.get(&stream_id) else {
            return Ok(());
        };
        self.send_stream_message(
            stream_id,
            Message::StreamWindow(StreamWindow {
                stream_id,
                stream_limit: stream.local_receive_limit,
                session_limit: self.local_session_limit,
            }),
        )
        .await
    }

    async fn send_open_error(
        &mut self,
        stream_id: StreamId,
        error: ErrorClass,
        mut reason: Vec<u8>,
    ) -> Result<(), SessionRuntimeError> {
        reason.truncate(self.limits.max_control_payload());
        self.send_message(Message::StreamOpenErr(StreamOpenErr {
            stream_id,
            error,
            reason,
        }))
        .await
    }

    async fn send_stream_message(
        &mut self,
        stream_id: StreamId,
        message: Message,
    ) -> Result<(), SessionRuntimeError> {
        let eligible = self
            .streams
            .get(&stream_id)
            .and_then(|stream| stream.eligible_paths.clone());
        if let Some(eligible) = eligible {
            let path_id = self
                .multipath
                .schedule_eligible(self.outbound_direction(), 0, &eligible)?
                .path_id;
            self.send_message_on(path_id, message).await
        } else {
            self.send_message(message).await
        }
    }

    async fn send_udp_message(
        &mut self,
        association_id: u64,
        message: Message,
    ) -> Result<(), SessionRuntimeError> {
        let eligible = self
            .ingress_udp
            .get(&association_id)
            .and_then(|association| association.eligible_paths.clone())
            .or_else(|| self.egress_udp_paths.get(&association_id).cloned());
        if let Some(eligible) = eligible {
            let bytes = match &message {
                Message::UdpDatagram(datagram) => datagram.payload.len(),
                _ => 0,
            };
            let path_id = self
                .multipath
                .schedule_eligible(self.outbound_direction(), bytes, &eligible)?
                .path_id;
            self.send_message_on(path_id, message).await
        } else {
            self.send_message(message).await
        }
    }

    async fn send_message(&mut self, message: Message) -> Result<(), SessionRuntimeError> {
        let bytes = match &message {
            Message::StreamData(data) => data.data.len(),
            Message::UdpDatagram(datagram) => datagram.payload.len(),
            _ => 0,
        };
        let direction = match &self.role {
            ActorRole::Ingress => ScheduleDirection::Upstream,
            ActorRole::Egress { .. } => ScheduleDirection::Downstream,
        };
        let path_id = self.multipath.schedule(direction, bytes)?.path_id;
        self.send_message_on(path_id, message).await
    }

    async fn send_message_on(
        &mut self,
        path_id: PathId,
        message: Message,
    ) -> Result<(), SessionRuntimeError> {
        let data_bytes = match &message {
            Message::StreamData(data) => data.data.len() as u64,
            Message::UdpDatagram(datagram) => datagram.payload.len() as u64,
            _ => 0,
        };
        if path_id != self.path_id {
            let sender = self
                .extra_paths
                .get(&path_id)
                .ok_or(MultipathError::UnknownPath(path_id))?
                .sender
                .clone();
            let (reply, result) = oneshot::channel();
            sender
                .send(PathWriterCommand::Send { message, reply })
                .await
                .map_err(|_| SessionRuntimeError::PathClosed)?;
            result
                .await
                .map_err(|_| SessionRuntimeError::PathClosed)??;
            if let Some(health) = self.path_health.get_mut(&path_id) {
                health.bytes_since_observation =
                    health.bytes_since_observation.saturating_add(data_bytes);
            }
            return Ok(());
        }
        if self.next_frame_seq > MAX_VARINT {
            return Err(SessionRuntimeError::FrameSequenceExhausted);
        }
        let payload = message.encode(self.limits)?;
        let frame = PathFrame::new(
            message.frame_type(),
            FrameFlags::empty(),
            self.session_id,
            self.path_id,
            self.next_frame_seq,
            payload,
            self.limits,
        )?;
        self.writer.send(frame).await?;
        self.next_frame_seq = self
            .next_frame_seq
            .checked_add(1)
            .ok_or(SessionRuntimeError::FrameSequenceExhausted)?;
        if let Some(health) = self.path_health.get_mut(&path_id) {
            health.bytes_since_observation =
                health.bytes_since_observation.saturating_add(data_bytes);
        }
        Ok(())
    }

    fn retained_outbound_bytes(&self) -> usize {
        self.buffer_limit
            .saturating_sub(self.send_budget.available_permits())
    }

    fn current_snapshot(&self, closed: bool) -> SessionSnapshot {
        let path_quality = self
            .path_health
            .iter()
            .map(|(path_id, health)| {
                let loss_ppm = health
                    .retransmitted_controls
                    .saturating_mul(1_000_000)
                    .checked_div(health.sent_controls.max(1))
                    .unwrap_or(0)
                    .min(1_000_000) as u32;
                (
                    *path_id,
                    PathQualitySnapshot {
                        rtt_ms: health.rtt_ms,
                        jitter_ms: health.jitter_ms,
                        loss_ppm,
                        throughput_bps: health.throughput_bps,
                        reordering_events: health.reordering_events,
                        exclusion_reason: health.exclusion_reason,
                    },
                )
            })
            .collect();
        SessionSnapshot {
            session_id: self.session_id,
            path_id: self.path_id,
            ready_paths: self.multipath.ready_path_count(),
            ready_path_ids: self.multipath.ready_path_ids(),
            degraded_paths: self.multipath.degraded_path_count(),
            effective_capacity_bps: self.multipath.effective_capacity_bps(),
            egress_aggregate_capacity_bps: self.egress_aggregate_capacity_bps,
            recommended_path_count: self.recommended_path_count,
            path_quality,
            active_streams: self.streams.len(),
            pending_stream_opens: self.pending_ingress.len() + self.opening_tasks.len(),
            retained_outbound_bytes: self.retained_outbound_bytes(),
            bytes_sent: self.bytes_sent,
            bytes_received: self.bytes_received,
            closed,
        }
    }

    fn publish_snapshot(&self, closed: bool) {
        self.snapshots.send_replace(self.current_snapshot(closed));
    }

    async fn cleanup(&mut self) {
        for (_, pending) in self.pending_ingress.drain() {
            let _ = pending.reply.send(Err(OpenStreamError::SessionClosed));
        }
        for (_, pending) in self.pending_ingress_udp.drain() {
            let _ = pending.reply.send(Err(OpenUdpError::SessionClosed));
        }
        self.ingress_udp.clear();
        if let Some(runtime) = self.udp_runtime.as_mut() {
            runtime.close_all();
        }
        for (_, task) in self.opening_tasks.drain() {
            task.abort();
            let _ = task.await;
        }
        for (_, stream) in self.streams.drain() {
            let _ = stream.commands.try_send(StreamIoCommand::Reset);
            stream.task.abort();
            let _ = stream.task.await;
        }
        for (_, path) in self.extra_paths.drain() {
            path.writer_task.abort();
            path.reader_task.abort();
            let _ = path.writer_task.await;
            let _ = path.reader_task.await;
        }
        self.reader_task.abort();
        let _ = (&mut self.reader_task).await;
    }
}

impl<W> Drop for SessionActor<W> {
    fn drop(&mut self) {
        self.reader_task.abort();
        for task in self.opening_tasks.values() {
            task.abort();
        }
        for stream in self.streams.values() {
            stream.task.abort();
        }
        for path in self.extra_paths.values() {
            path.writer_task.abort();
            path.reader_task.abort();
        }
    }
}

async fn receive_command(
    commands: &mut Option<mpsc::Receiver<IngressCommand>>,
) -> Option<IngressCommand> {
    match commands {
        Some(commands) => commands.recv().await,
        None => pending().await,
    }
}

async fn send_path_command(
    commands: &mpsc::Sender<IngressCommand>,
    path_id: PathId,
    close: bool,
) -> Result<(), SessionRuntimeError> {
    let (reply, result) = oneshot::channel();
    commands
        .send(IngressCommand::PathControl {
            path_id,
            close,
            reply,
        })
        .await
        .map_err(|_| SessionRuntimeError::PathClosed)?;
    result.await.map_err(|_| SessionRuntimeError::PathClosed)?
}

async fn send_udp_close(
    commands: &mpsc::Sender<IngressCommand>,
    association_id: u64,
) -> Result<(), OpenUdpError> {
    let (reply, result) = oneshot::channel();
    commands
        .send(IngressCommand::CloseUdp {
            association_id,
            reply,
        })
        .await
        .map_err(|_| OpenUdpError::SessionClosed)?;
    result.await.map_err(|_| OpenUdpError::SessionClosed)?
}

fn target_flags(target: &TargetEndpoint) -> u64 {
    let mut flags = 0;
    if !target.hostname.is_empty() {
        flags |= 1;
    }
    if !target.resolved_addresses.is_empty() {
        flags |= 2;
    }
    flags
}

fn udp_association_id(message: &Message) -> u64 {
    match message {
        Message::UdpOpen(value) => value.association_id,
        Message::UdpOpenOk(value) => value.association_id,
        Message::UdpOpenErr(value) => value.association_id,
        Message::UdpDatagram(value) => value.association_id,
        Message::UdpClose(value) => value.association_id,
        _ => 0,
    }
}

fn runtime_buffer_limit(ready: &pathchord_core::PathReady) -> Result<usize, SessionRuntimeError> {
    usize::try_from(ready.max_session_buffering)
        .ok()
        .filter(|limit| *limit > 0 && *limit <= ProtocolLimits::HARD_MAX_SESSION_BUFFERING)
        .ok_or(SessionRuntimeError::InvalidRuntimeLimit)
}

struct RecordWriter<W> {
    io: W,
    noise: Arc<Mutex<NoiseTransport>>,
    limits: ProtocolLimits,
}

impl<W> RecordWriter<W>
where
    W: AsyncWrite + Unpin,
{
    async fn send(&mut self, frame: PathFrame) -> Result<(), SessionRuntimeError> {
        let encoded = {
            let mut noise = self
                .noise
                .lock()
                .map_err(|_| SessionRuntimeError::NoiseStatePoisoned)?;
            noise.seal_frame(&frame, self.limits)?.encode()
        };
        self.io.write_all(&encoded).await?;
        self.io.flush().await?;
        Ok(())
    }
}

struct RecordReader<R> {
    io: R,
    noise: Arc<Mutex<NoiseTransport>>,
    limits: ProtocolLimits,
}

impl<R> RecordReader<R>
where
    R: AsyncRead + Unpin,
{
    async fn receive(&mut self) -> Result<Option<PathFrame>, SessionRuntimeError> {
        let mut header = [0_u8; RECORD_ENVELOPE_HEADER_LEN];
        let first = self.io.read(&mut header[..1]).await?;
        if first == 0 {
            return Ok(None);
        }
        self.io.read_exact(&mut header[1..]).await?;
        let ciphertext_len = usize::from(u16::from_be_bytes([header[8], header[9]]));
        if !(TRANSPORT_TAG_LEN..=MAX_NOISE_MESSAGE_LEN).contains(&ciphertext_len) {
            return Err(SessionRuntimeError::InvalidCiphertextLength {
                actual: ciphertext_len,
                minimum: TRANSPORT_TAG_LEN,
                maximum: MAX_NOISE_MESSAGE_LEN,
            });
        }
        let mut encoded = Vec::with_capacity(RECORD_ENVELOPE_HEADER_LEN + ciphertext_len);
        encoded.extend_from_slice(&header);
        let mut ciphertext = vec![0_u8; ciphertext_len];
        self.io.read_exact(&mut ciphertext).await?;
        encoded.extend_from_slice(&ciphertext);
        let mut noise = self
            .noise
            .lock()
            .map_err(|_| SessionRuntimeError::NoiseStatePoisoned)?;
        Ok(Some(noise.open_encoded_frame(&encoded, self.limits)?))
    }
}

async fn record_reader_loop<R>(
    path_id: PathId,
    mut reader: RecordReader<R>,
    events: mpsc::Sender<ReaderEvent>,
) where
    R: AsyncRead + Send + Unpin + 'static,
{
    loop {
        let event = match reader.receive().await {
            Ok(Some(frame)) => ReaderEvent::Frame { path_id, frame },
            Ok(None) => ReaderEvent::Closed { path_id },
            Err(error) => ReaderEvent::Failed { path_id, error },
        };
        let terminal = !matches!(event, ReaderEvent::Frame { .. });
        if events.send(event).await.is_err() || terminal {
            return;
        }
    }
}

async fn path_writer_loop<W>(
    mut writer: RecordWriter<W>,
    mut commands: mpsc::Receiver<PathWriterCommand>,
    session_id: SessionId,
    path_id: PathId,
    limits: ProtocolLimits,
    mut next_frame_seq: u64,
) where
    W: AsyncWrite + Send + Unpin + 'static,
{
    while let Some(PathWriterCommand::Send { message, reply }) = commands.recv().await {
        let result = async {
            if next_frame_seq > MAX_VARINT {
                return Err(SessionRuntimeError::FrameSequenceExhausted);
            }
            let payload = message.encode(limits)?;
            let frame = PathFrame::new(
                message.frame_type(),
                FrameFlags::empty(),
                session_id,
                path_id,
                next_frame_seq,
                payload,
                limits,
            )?;
            writer.send(frame).await?;
            next_frame_seq = next_frame_seq
                .checked_add(1)
                .ok_or(SessionRuntimeError::FrameSequenceExhausted)?;
            Ok(())
        }
        .await;
        let failed = result.is_err();
        let _ = reply.send(result);
        if failed {
            return;
        }
    }
}

async fn run_stream_io(
    stream_id: StreamId,
    io: BoxedSessionStream,
    mut commands: mpsc::Receiver<StreamIoCommand>,
    events: mpsc::Sender<StreamEvent>,
    send_budget: Arc<Semaphore>,
    chunk_size: usize,
) {
    let (read, mut write) = split(io);
    let mut read_future = Box::pin(stream_read_loop(
        stream_id,
        read,
        events.clone(),
        send_budget,
        chunk_size,
    ));
    let mut local_done = false;
    let mut remote_done = false;
    loop {
        tokio::select! {
            () = &mut read_future, if !local_done => {
                local_done = true;
                if remote_done {
                    break;
                }
            }
            command = commands.recv() => {
                match command {
                    Some(StreamIoCommand::Data { bytes, permits }) => {
                        if let Err(error) = write.write_all(&bytes).await {
                            drop(permits);
                            let _ = events.send(StreamEvent::IoFailed {
                                stream_id,
                                reason: error.to_string(),
                            }).await;
                            break;
                        }
                        let length = bytes.len();
                        drop(permits);
                        if events.send(StreamEvent::Delivered {
                            stream_id,
                            bytes: length,
                        }).await.is_err() {
                            break;
                        }
                    }
                    Some(StreamIoCommand::Fin) => {
                        if let Err(error) = write.shutdown().await {
                            let _ = events.send(StreamEvent::IoFailed {
                                stream_id,
                                reason: error.to_string(),
                            }).await;
                            break;
                        }
                        remote_done = true;
                        if local_done {
                            break;
                        }
                    }
                    Some(StreamIoCommand::Reset) | None => break,
                }
            }
        }
    }
    let _ = events.send(StreamEvent::Finished { stream_id }).await;
}

async fn stream_read_loop(
    stream_id: StreamId,
    mut read: ReadHalf<BoxedSessionStream>,
    events: mpsc::Sender<StreamEvent>,
    send_budget: Arc<Semaphore>,
    chunk_size: usize,
) {
    loop {
        let mut data = vec![0_u8; chunk_size];
        let read_count = match read.read(&mut data).await {
            Ok(count) => count,
            Err(error) => {
                let _ = events
                    .send(StreamEvent::IoFailed {
                        stream_id,
                        reason: error.to_string(),
                    })
                    .await;
                return;
            }
        };
        if read_count == 0 {
            let _ = events.send(StreamEvent::LocalFin { stream_id }).await;
            return;
        }
        data.truncate(read_count);
        let Ok(used) = Arc::clone(&send_budget)
            .acquire_many_owned(read_count as u32)
            .await
        else {
            return;
        };
        if events
            .send(StreamEvent::Data {
                stream_id,
                data,
                permit: used,
            })
            .await
            .is_err()
        {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        AuthorizationState, EgressPathAdmissionConfig, IngressPathAdmissionConfig,
        PathAdmissionOutcome, PathAuthorization, accept_path, dial_path,
    };
    use pathchord_core::PathReady;
    use pathchord_noise::{StaticKeypair, generate_static_keypair};
    use std::net::IpAddr;
    use std::pin::Pin;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::task::{Context, Poll};
    use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream, copy};

    fn keys() -> (StaticKeypair, StaticKeypair) {
        (
            generate_static_keypair().expect("Ingress key"),
            generate_static_keypair().expect("Egress key"),
        )
    }

    fn ingress_config() -> IngressPathAdmissionConfig {
        IngressPathAdmissionConfig {
            egress_identity: b"PathChord/wire-v1/egress/runtime-egress".to_vec(),
            egress_id: b"runtime-egress".to_vec(),
            ingress_id: b"runtime-ingress".to_vec(),
            session_id: SessionId::new(0x1234),
            path_id: PathId::new(0x5678),
            offered_capabilities: 1,
            local_limits: ProtocolLimits::default(),
        }
    }

    fn egress_config() -> EgressPathAdmissionConfig {
        EgressPathAdmissionConfig {
            egress_identity: b"PathChord/wire-v1/egress/runtime-egress".to_vec(),
            egress_id: b"runtime-egress".to_vec(),
            required_capabilities: 1,
            supported_capabilities: 1,
            local_limits: ProtocolLimits::default(),
            ready_limits: PathReady {
                max_frame_payload: 4096,
                max_control_payload: 1024,
                max_session_buffering: 64 * 1024,
            },
        }
    }

    fn authorization(ingress: &StaticKeypair) -> PathAuthorization {
        PathAuthorization {
            ingress_id: b"runtime-ingress".to_vec(),
            public_key: *ingress.public(),
            state: AuthorizationState::Enabled,
            generation: 3,
        }
    }

    async fn admitted_pair() -> (
        IngressAdmittedPath<DuplexStream>,
        EgressAdmittedPath<DuplexStream>,
    ) {
        let (ingress_key, egress_key) = keys();
        let ingress_config = ingress_config();
        let egress_config = egress_config();
        let authorization = authorization(&ingress_key);
        let (ingress_io, egress_io) = duplex(512 * 1024);
        let (ingress, egress) = tokio::join!(
            dial_path(
                ingress_io,
                ingress_key.private(),
                egress_key.public(),
                &ingress_config,
            ),
            accept_path(
                egress_io,
                egress_key.private(),
                &egress_config,
                &authorization,
            ),
        );
        let PathAdmissionOutcome::Ready(ingress) = ingress.expect("Ingress admission") else {
            panic!("Ingress Path should be ready");
        };
        let PathAdmissionOutcome::Ready(egress) = egress.expect("Egress admission") else {
            panic!("Egress Path should be ready");
        };
        (ingress, egress)
    }

    async fn admitted_pair_for(
        ingress_key: &StaticKeypair,
        egress_key: &StaticKeypair,
        path_id: u128,
    ) -> (
        IngressAdmittedPath<DuplexStream>,
        EgressAdmittedPath<DuplexStream>,
    ) {
        let mut ingress_config = ingress_config();
        ingress_config.path_id = PathId::new(path_id);
        let egress_config = egress_config();
        let authorization = authorization(ingress_key);
        let (ingress_io, egress_io) = duplex(512 * 1024);
        let (ingress, egress) = tokio::join!(
            dial_path(
                ingress_io,
                ingress_key.private(),
                egress_key.public(),
                &ingress_config,
            ),
            accept_path(
                egress_io,
                egress_key.private(),
                &egress_config,
                &authorization,
            ),
        );
        let PathAdmissionOutcome::Ready(ingress) = ingress.expect("Ingress admission") else {
            panic!("Ingress Path should be ready");
        };
        let PathAdmissionOutcome::Ready(egress) = egress.expect("Egress admission") else {
            panic!("Egress Path should be ready");
        };
        (ingress, egress)
    }

    struct DropNextWrite<S> {
        inner: S,
        drop_next: Arc<AtomicBool>,
    }

    struct DropAllWrites<S> {
        inner: S,
        drop_all: Arc<AtomicBool>,
    }

    impl<S> AsyncRead for DropAllWrites<S>
    where
        S: AsyncRead + Unpin,
    {
        fn poll_read(
            mut self: Pin<&mut Self>,
            context: &mut Context<'_>,
            buffer: &mut tokio::io::ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.inner).poll_read(context, buffer)
        }
    }

    impl<S> AsyncWrite for DropAllWrites<S>
    where
        S: AsyncWrite + Unpin,
    {
        fn poll_write(
            mut self: Pin<&mut Self>,
            context: &mut Context<'_>,
            buffer: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            if self.drop_all.load(Ordering::Acquire) {
                return Poll::Ready(Ok(buffer.len()));
            }
            Pin::new(&mut self.inner).poll_write(context, buffer)
        }

        fn poll_flush(
            mut self: Pin<&mut Self>,
            context: &mut Context<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.inner).poll_flush(context)
        }

        fn poll_shutdown(
            mut self: Pin<&mut Self>,
            context: &mut Context<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.inner).poll_shutdown(context)
        }
    }

    impl<S> AsyncRead for DropNextWrite<S>
    where
        S: AsyncRead + Unpin,
    {
        fn poll_read(
            mut self: Pin<&mut Self>,
            context: &mut Context<'_>,
            buffer: &mut tokio::io::ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.inner).poll_read(context, buffer)
        }
    }

    impl<S> AsyncWrite for DropNextWrite<S>
    where
        S: AsyncWrite + Unpin,
    {
        fn poll_write(
            mut self: Pin<&mut Self>,
            context: &mut Context<'_>,
            buffer: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            if self.drop_next.swap(false, Ordering::AcqRel) {
                return Poll::Ready(Ok(buffer.len()));
            }
            Pin::new(&mut self.inner).poll_write(context, buffer)
        }

        fn poll_flush(
            mut self: Pin<&mut Self>,
            context: &mut Context<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.inner).poll_flush(context)
        }

        fn poll_shutdown(
            mut self: Pin<&mut Self>,
            context: &mut Context<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.inner).poll_shutdown(context)
        }
    }

    async fn admitted_pair_with_dropped_egress_write(
        drop_next: Arc<AtomicBool>,
    ) -> (
        IngressAdmittedPath<DuplexStream>,
        EgressAdmittedPath<DropNextWrite<DuplexStream>>,
    ) {
        let (ingress_key, egress_key) = keys();
        let ingress_config = ingress_config();
        let egress_config = egress_config();
        let authorization = authorization(&ingress_key);
        let (ingress_io, egress_io) = duplex(512 * 1024);
        let egress_io = DropNextWrite {
            inner: egress_io,
            drop_next,
        };
        let (ingress, egress) = tokio::join!(
            dial_path(
                ingress_io,
                ingress_key.private(),
                egress_key.public(),
                &ingress_config,
            ),
            accept_path(
                egress_io,
                egress_key.private(),
                &egress_config,
                &authorization,
            ),
        );
        let PathAdmissionOutcome::Ready(ingress) = ingress.expect("Ingress admission") else {
            panic!("Ingress Path should be ready");
        };
        let PathAdmissionOutcome::Ready(egress) = egress.expect("Egress admission") else {
            panic!("Egress Path should be ready");
        };
        (ingress, egress)
    }

    async fn admitted_pair_with_partition(
        drop_all: Arc<AtomicBool>,
    ) -> (
        IngressAdmittedPath<DuplexStream>,
        EgressAdmittedPath<DropAllWrites<DuplexStream>>,
    ) {
        let (ingress_key, egress_key) = keys();
        let ingress_config = ingress_config();
        let egress_config = egress_config();
        let authorization = authorization(&ingress_key);
        let (ingress_io, egress_io) = duplex(512 * 1024);
        let egress_io = DropAllWrites {
            inner: egress_io,
            drop_all,
        };
        let (ingress, egress) = tokio::join!(
            dial_path(
                ingress_io,
                ingress_key.private(),
                egress_key.public(),
                &ingress_config,
            ),
            accept_path(
                egress_io,
                egress_key.private(),
                &egress_config,
                &authorization,
            ),
        );
        let PathAdmissionOutcome::Ready(ingress) = ingress.expect("Ingress admission") else {
            panic!("Ingress Path should be ready");
        };
        let PathAdmissionOutcome::Ready(egress) = egress.expect("Egress admission") else {
            panic!("Egress Path should be ready");
        };
        (ingress, egress)
    }

    async fn admitted_pair_for_with_dropped_ingress_write(
        ingress_key: &StaticKeypair,
        egress_key: &StaticKeypair,
        path_id: u128,
        drop_next: Arc<AtomicBool>,
    ) -> (
        IngressAdmittedPath<DropNextWrite<DuplexStream>>,
        EgressAdmittedPath<DuplexStream>,
    ) {
        let mut ingress_config = ingress_config();
        ingress_config.path_id = PathId::new(path_id);
        let egress_config = egress_config();
        let authorization = authorization(ingress_key);
        let (ingress_io, egress_io) = duplex(512 * 1024);
        let ingress_io = DropNextWrite {
            inner: ingress_io,
            drop_next,
        };
        let (ingress, egress) = tokio::join!(
            dial_path(
                ingress_io,
                ingress_key.private(),
                egress_key.public(),
                &ingress_config,
            ),
            accept_path(
                egress_io,
                egress_key.private(),
                &egress_config,
                &authorization,
            ),
        );
        let PathAdmissionOutcome::Ready(ingress) = ingress.expect("Ingress admission") else {
            panic!("Ingress Path should be ready");
        };
        let PathAdmissionOutcome::Ready(egress) = egress.expect("Egress admission") else {
            panic!("Egress Path should be ready");
        };
        (ingress, egress)
    }

    fn target(name: &str) -> TargetEndpoint {
        TargetEndpoint {
            hostname: name.as_bytes().to_vec(),
            port: 443,
            resolved_addresses: Vec::<IpAddr>::new(),
        }
    }

    #[derive(Clone, Default)]
    struct EchoFactory {
        tasks: Arc<Mutex<Vec<JoinHandle<()>>>>,
    }

    impl EchoFactory {
        async fn join(&self) {
            let tasks = std::mem::take(&mut *self.tasks.lock().expect("echo task lock"));
            for task in tasks {
                task.await.expect("echo task");
            }
        }
    }

    #[async_trait]
    impl EgressStreamFactory for EchoFactory {
        async fn open(
            &self,
            _target: TargetEndpoint,
        ) -> Result<BoxedSessionStream, EgressStreamOpenError> {
            let (session, target) = duplex(128 * 1024);
            let task = tokio::spawn(async move {
                let (mut read, mut write) = split(target);
                copy(&mut read, &mut write).await.expect("echo copy");
                write.shutdown().await.expect("echo shutdown");
            });
            self.tasks.lock().expect("echo task lock").push(task);
            Ok(Box::new(session))
        }
    }

    struct RejectFactory;

    #[async_trait]
    impl EgressStreamFactory for RejectFactory {
        async fn open(
            &self,
            _target: TargetEndpoint,
        ) -> Result<BoxedSessionStream, EgressStreamOpenError> {
            Err(EgressStreamOpenError::new(
                ErrorClass::TargetFailure,
                b"target refused".to_vec(),
            ))
        }
    }

    #[tokio::test]
    async fn public_runtime_carries_echo_payload_and_half_close() {
        let (ingress_path, egress_path) = admitted_pair().await;
        let factory = EchoFactory::default();
        let egress_factory = factory.clone();
        let egress =
            tokio::spawn(async move { run_egress_session(egress_path, egress_factory).await });
        let ingress = IngressSessionHandle::start(ingress_path).expect("Ingress runtime");
        let mut stream = ingress
            .open_tcp(target("echo.test"))
            .await
            .expect("open Stream");

        let payload = vec![0x5a; 48 * 1024];
        stream.write_all(&payload).await.expect("write payload");
        stream.shutdown().await.expect("half close");
        let mut echoed = Vec::new();
        stream.read_to_end(&mut echoed).await.expect("read echo");
        assert_eq!(echoed, payload);

        let ingress_snapshot = ingress.shutdown().await.expect("Ingress shutdown");
        assert!(ingress_snapshot.closed);
        let egress_snapshot = egress.await.expect("Egress task").expect("Egress runtime");
        assert!(egress_snapshot.closed);
        assert_eq!(egress_snapshot.bytes_received, payload.len() as u64);
        factory.join().await;
    }

    #[tokio::test]
    async fn public_runtime_multiplexes_two_tcp_streams() {
        let (ingress_path, egress_path) = admitted_pair().await;
        let factory = EchoFactory::default();
        let egress_factory = factory.clone();
        let egress =
            tokio::spawn(async move { run_egress_session(egress_path, egress_factory).await });
        let ingress = IngressSessionHandle::start(ingress_path).expect("Ingress runtime");
        let (first, second) = tokio::join!(
            ingress.open_tcp(target("first.test")),
            ingress.open_tcp(target("second.test")),
        );
        let mut first = first.expect("first Stream");
        let mut second = second.expect("second Stream");
        let first_payload = b"first-stream-payload";
        let second_payload = b"second-stream-payload";
        let first_flow = async {
            first.write_all(first_payload).await.expect("first write");
            let mut echoed = vec![0_u8; first_payload.len()];
            first.read_exact(&mut echoed).await.expect("first read");
            assert_eq!(echoed, first_payload);
            first.shutdown().await.expect("first close");
            first.read_to_end(&mut Vec::new()).await.expect("first EOF");
        };
        let second_flow = async {
            second
                .write_all(second_payload)
                .await
                .expect("second write");
            let mut echoed = vec![0_u8; second_payload.len()];
            second.read_exact(&mut echoed).await.expect("second read");
            assert_eq!(echoed, second_payload);
            second.shutdown().await.expect("second close");
            second
                .read_to_end(&mut Vec::new())
                .await
                .expect("second EOF");
        };
        tokio::join!(first_flow, second_flow);

        ingress.shutdown().await.expect("Ingress shutdown");
        egress.await.expect("Egress task").expect("Egress runtime");
        factory.join().await;
    }

    #[tokio::test]
    async fn public_runtime_propagates_target_open_rejection() {
        let (ingress_path, egress_path) = admitted_pair().await;
        let egress =
            tokio::spawn(async move { run_egress_session(egress_path, RejectFactory).await });
        let ingress = IngressSessionHandle::start(ingress_path).expect("Ingress runtime");
        assert!(matches!(
            ingress.open_tcp(target("refused.test")).await,
            Err(OpenStreamError::Rejected {
                error: ErrorClass::TargetFailure,
                ..
            })
        ));
        ingress.shutdown().await.expect("Ingress shutdown");
        egress.await.expect("Egress task").expect("Egress runtime");
    }

    #[tokio::test]
    async fn dynamic_second_path_drains_and_fails_without_closing_tcp_stream() {
        let (ingress_key, egress_key) = keys();
        let (ingress_primary, egress_primary) =
            admitted_pair_for(&ingress_key, &egress_key, 1).await;
        let (ingress_secondary, egress_secondary) =
            admitted_pair_for(&ingress_key, &egress_key, 2).await;
        let factory = EchoFactory::default();
        let egress = EgressSessionHandle::start(egress_primary, factory.clone())
            .expect("Egress multipath runtime");
        let egress_controller = egress.controller();
        let ingress =
            IngressSessionHandle::start(ingress_primary).expect("Ingress multipath runtime");
        let fast_path = MultipathPathObservation {
            effective_capacity_bps: 1_000_000,
            weight_basis_points: 10_000,
            rtt_ms: 5,
            jitter_ms: 1,
            loss_basis_points: 0,
        };
        egress_controller
            .add_path(egress_secondary, fast_path.clone())
            .await
            .expect("add Egress Path");
        ingress
            .add_path(ingress_secondary, fast_path)
            .await
            .expect("add Ingress Path");
        assert_eq!(ingress.snapshot().ready_paths, 2);
        assert_eq!(egress_controller.snapshot().ready_paths, 2);

        let mut stream = ingress
            .open_tcp(target("multipath.test"))
            .await
            .expect("open multipath Stream");
        stream.write_all(b"before-drain").await.unwrap();
        let mut first = [0_u8; 12];
        stream.read_exact(&mut first).await.unwrap();
        assert_eq!(&first, b"before-drain");

        ingress.drain_path(PathId::new(2)).await.unwrap();
        stream.write_all(b"after-drain").await.unwrap();
        let mut second = [0_u8; 11];
        stream.read_exact(&mut second).await.unwrap();
        assert_eq!(&second, b"after-drain");
        ingress.close_path(PathId::new(2)).await.unwrap();
        assert_eq!(ingress.snapshot().ready_paths, 1);

        stream.write_all(b"after-failure").await.unwrap();
        let mut third = [0_u8; 13];
        stream.read_exact(&mut third).await.unwrap();
        assert_eq!(&third, b"after-failure");
        stream.shutdown().await.unwrap();
        stream.read_to_end(&mut Vec::new()).await.unwrap();
        ingress.shutdown().await.unwrap();
        egress.wait().await.unwrap();
        factory.join().await;
    }

    #[tokio::test]
    async fn bounded_rto_retransmits_after_a_lost_ack_without_duplicate_target_bytes() {
        let drop_next = Arc::new(AtomicBool::new(false));
        let (ingress_path, egress_path) =
            admitted_pair_with_dropped_egress_write(Arc::clone(&drop_next)).await;
        let factory = EchoFactory::default();
        let egress =
            EgressSessionHandle::start(egress_path, factory.clone()).expect("Egress runtime");
        let ingress = IngressSessionHandle::start(ingress_path).expect("Ingress runtime");
        let mut stream = ingress
            .open_tcp(target("rto.test"))
            .await
            .expect("open Stream");
        drop_next.store(true, Ordering::Release);
        stream.write_all(b"exactly-once").await.unwrap();
        let mut echoed = [0_u8; 12];
        stream.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"exactly-once");
        tokio::time::sleep(Duration::from_millis(350)).await;
        assert_eq!(ingress.snapshot().retained_outbound_bytes, 0);
        stream.shutdown().await.unwrap();
        stream.read_to_end(&mut Vec::new()).await.unwrap();
        ingress.shutdown().await.unwrap();
        egress.wait().await.unwrap();
        factory.join().await;
    }

    #[tokio::test]
    async fn failed_path_reframes_retained_tcp_data_on_another_noise_path() {
        let (ingress_key, egress_key) = keys();
        let (ingress_primary, egress_primary) =
            admitted_pair_for(&ingress_key, &egress_key, 11).await;
        let drop_next = Arc::new(AtomicBool::new(false));
        let (ingress_secondary, egress_secondary) = admitted_pair_for_with_dropped_ingress_write(
            &ingress_key,
            &egress_key,
            12,
            Arc::clone(&drop_next),
        )
        .await;
        let factory = EchoFactory::default();
        let egress = EgressSessionHandle::start(egress_primary, factory.clone()).unwrap();
        let egress_controller = egress.controller();
        let ingress = IngressSessionHandle::start(ingress_primary).unwrap();
        let preferred = MultipathPathObservation {
            effective_capacity_bps: 10_000_000,
            weight_basis_points: 10_000,
            rtt_ms: 5,
            jitter_ms: 1,
            loss_basis_points: 0,
        };
        egress_controller
            .add_path(egress_secondary, preferred.clone())
            .await
            .unwrap();
        ingress
            .add_path(ingress_secondary, preferred)
            .await
            .unwrap();
        let mut stream = ingress.open_tcp(target("cross-path.test")).await.unwrap();

        drop_next.store(true, Ordering::Release);
        stream.write_all(b"cross-path-retained").await.unwrap();
        for _ in 0..128 {
            if !drop_next.load(Ordering::Acquire) {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert!(!drop_next.load(Ordering::Acquire));
        ingress.close_path(PathId::new(12)).await.unwrap();
        let mut echoed = [0_u8; 19];
        stream.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"cross-path-retained");
        assert_eq!(ingress.snapshot().ready_paths, 1);

        stream.shutdown().await.unwrap();
        stream.read_to_end(&mut Vec::new()).await.unwrap();
        ingress.shutdown().await.unwrap();
        egress.wait().await.unwrap();
        factory.join().await;
    }

    #[tokio::test(start_paused = true)]
    async fn heartbeat_and_status_partition_degrades_then_recovers() {
        let drop_all = Arc::new(AtomicBool::new(false));
        let (ingress_path, egress_path) = admitted_pair_with_partition(Arc::clone(&drop_all)).await;
        let egress = EgressSessionHandle::start(egress_path, EchoFactory::default()).unwrap();
        let ingress = IngressSessionHandle::start(ingress_path).unwrap();
        tokio::time::advance(Duration::from_millis(2_100)).await;
        for _ in 0..20 {
            tokio::task::yield_now().await;
        }
        assert_eq!(ingress.snapshot().degraded_paths, 0);
        assert!(ingress.snapshot().path_quality[&PathId::new(0x5678)].rtt_ms > 0);

        drop_all.store(true, Ordering::Release);
        tokio::time::advance(Duration::from_millis(3_100)).await;
        tokio::task::yield_now().await;
        assert_eq!(ingress.snapshot().degraded_paths, 1);
        assert!(!ingress.snapshot().closed);

        drop_all.store(false, Ordering::Release);
        for _ in 0..10 {
            tokio::time::advance(Duration::from_millis(250)).await;
            for _ in 0..4 {
                tokio::task::yield_now().await;
            }
        }
        assert_eq!(ingress.snapshot().degraded_paths, 0);
        assert!(!ingress.snapshot().closed, "{:?}", ingress.snapshot());
        assert!(ingress.snapshot().path_quality[&PathId::new(0x5678)].loss_ppm > 0);
        ingress.shutdown().await.unwrap();
        egress.wait().await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn sustained_control_partition_fails_the_last_ready_path() {
        let drop_all = Arc::new(AtomicBool::new(false));
        let (ingress_path, egress_path) = admitted_pair_with_partition(Arc::clone(&drop_all)).await;
        let egress = EgressSessionHandle::start(egress_path, EchoFactory::default()).unwrap();
        let ingress = IngressSessionHandle::start(ingress_path).unwrap();
        tokio::time::advance(Duration::from_millis(2_100)).await;
        for _ in 0..20 {
            tokio::task::yield_now().await;
        }
        drop_all.store(true, Ordering::Release);
        tokio::time::advance(Duration::from_secs(7)).await;
        for _ in 0..20 {
            tokio::task::yield_now().await;
        }
        assert!(ingress.snapshot().closed);
        drop(ingress);
        let _ = egress.wait().await;
    }

    #[tokio::test]
    async fn egress_status_config_enforces_per_ingress_stream_limit() {
        let (ingress_path, egress_path) = admitted_pair().await;
        let factory = EchoFactory::default();
        let egress = EgressSessionHandle::start_with_status(
            egress_path,
            factory.clone(),
            EgressStatusConfig {
                capacity_bps: 10_000_000,
                recommended_path_count: 2,
                max_streams_per_ingress: 1,
                ..EgressStatusConfig::default()
            },
        )
        .unwrap();
        let ingress = IngressSessionHandle::start(ingress_path).unwrap();
        let mut first = ingress.open_tcp(target("first.test")).await.unwrap();
        assert!(matches!(
            ingress.open_tcp(target("second.test")).await,
            Err(OpenStreamError::Rejected {
                error: ErrorClass::EgressFailure,
                ..
            })
        ));
        first.shutdown().await.unwrap();
        first.read_to_end(&mut Vec::new()).await.unwrap();
        ingress.shutdown().await.unwrap();
        egress.wait().await.unwrap();
        factory.join().await;
    }

    #[tokio::test]
    async fn routed_stream_never_uses_a_higher_score_ineligible_path() {
        let (ingress_key, egress_key) = keys();
        let (ingress_primary, egress_primary) =
            admitted_pair_for(&ingress_key, &egress_key, 31).await;
        let blocked = Arc::new(AtomicBool::new(false));
        let (ingress_secondary, egress_secondary) = admitted_pair_for_with_dropped_ingress_write(
            &ingress_key,
            &egress_key,
            32,
            Arc::clone(&blocked),
        )
        .await;
        let factory = EchoFactory::default();
        let egress = EgressSessionHandle::start(egress_primary, factory.clone()).unwrap();
        let egress_controller = egress.controller();
        let ingress = IngressSessionHandle::start(ingress_primary).unwrap();
        let preferred = MultipathPathObservation {
            effective_capacity_bps: 100_000_000,
            weight_basis_points: 10_000,
            rtt_ms: 1,
            jitter_ms: 0,
            loss_basis_points: 0,
        };
        egress_controller
            .add_path(egress_secondary, preferred.clone())
            .await
            .unwrap();
        ingress
            .add_path(ingress_secondary, preferred)
            .await
            .unwrap();
        blocked.store(true, Ordering::Release);
        let mut stream = ingress
            .open_tcp_routed(
                target("isolated-rule.test"),
                BTreeMap::from([(PathId::new(31), 1)]),
            )
            .await
            .unwrap();
        stream.write_all(b"eligible-only").await.unwrap();
        let mut echoed = [0_u8; 13];
        stream.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"eligible-only");
        assert!(blocked.load(Ordering::Acquire));
        blocked.store(false, Ordering::Release);
        stream.shutdown().await.unwrap();
        stream.read_to_end(&mut Vec::new()).await.unwrap();
        ingress.shutdown().await.unwrap();
        egress.wait().await.unwrap();
        factory.join().await;
    }
}
