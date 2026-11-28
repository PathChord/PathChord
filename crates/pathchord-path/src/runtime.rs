//! Long-lived, reliable TCP Stream ownership for one admitted Path.

use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::future::pending;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use async_trait::async_trait;
use pathchord_core::{
    AckRange, AdmissionReason, CAPABILITY_TCP_STREAM, CAPABILITY_UDP_SESSION, CapacityState,
    ControlAck, ControlReceiver, ControlSender, EgressServiceState, ErrorClass, FrameCodecError,
    FrameFlags, FrameType, Heartbeat, MAX_VARINT, Message, MessageCodecError, PathClose, PathDrain,
    PathFrame, PathId, ProtocolLimits, ReliabilityError, RequestId, SessionClose, SessionControl,
    SessionControlCancel, SessionControlFlow, SessionId, StatusReport, StatusReportDisposition,
    StreamAck, StreamData, StreamFin, StreamId, StreamOpen, StreamOpenErr, StreamOpenOk,
    StreamReceiveBuffer, StreamRst, StreamState, StreamWindow, TargetEndpoint, TrafficClassConfig,
    UdpClose, UdpDatagram, UdpOpen, UdpOpenErr,
};
use pathchord_noise::{
    MAX_NOISE_MESSAGE_LEN, NoiseError, NoiseTransport, RECORD_ENVELOPE_HEADER_LEN,
    ReplayAwareFrame, TRANSPORT_TAG_LEN,
};
use thiserror::Error;
use tokio::io::{
    AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf, duplex, split,
};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc, oneshot, watch};
use tokio::task::JoinHandle;
use tokio::time::{Instant, MissedTickBehavior};

use crate::diagnostics::{
    DiagnosticDetail, DiagnosticHistory, DiagnosticIds, DiagnosticLevel, DiagnosticOutcome,
    DiagnosticReason, PathAttribution, PathTerminationReason,
};

use crate::{
    DemandKey, EgressAdmittedPath, IngressAdmittedPath, MultipathConfig, MultipathError,
    MultipathPathObservation, MultipathSession, NoiseRecordStream, PathEconomicStatus,
    ScheduleDirection, SessionUdpError, SessionUdpHandle, UdpAssociationRuntime, UdpTargetFactory,
    WirePriority,
};

const MAX_SESSION_STREAMS: usize = 256;
const MAX_DEMAND_KEYS: usize = crate::multipath::MAX_DEMAND_KEYS;
const COMMAND_QUEUE_CAPACITY: usize = 64;
const FRAME_QUEUE_CAPACITY: usize = 64;
const MAX_READER_EVENTS_PER_TURN: usize = 16;
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
const MAX_SESSION_CONTROL_MESSAGES: usize = 4096;
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(1);
// A stalled carrier must not hold the Session actor past heartbeat liveness
// deadlines for all other Paths. A partially written Noise record cannot be
// resumed safely, so a timeout is treated as a failure of that Path.
const PATH_WRITE_TIMEOUT: Duration = Duration::from_secs(1);
const CONTROL_RETRANSMISSION_TIMEOUT: Duration = Duration::from_millis(500);
const PATH_DEGRADED_AFTER: Duration = Duration::from_secs(3);
const PATH_FAILED_AFTER: Duration = Duration::from_secs(6);
const STATUS_REPORT_INTERVAL: Duration = Duration::from_secs(2);
const MAX_EGRESS_REQUEST_CACHE: usize = 256;

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

#[derive(Clone, Copy)]
enum InitialStatusError {
    SessionClosed,
    Timeout,
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

    /// Open a target while transferring an already-held global admission
    /// permit. Implementations that do not own a shared target semaphore may
    /// use the default behavior; the permit is dropped on entry.
    async fn open_with_permit(
        &self,
        target: TargetEndpoint,
        permit: Option<OwnedSemaphorePermit>,
    ) -> Result<BoxedSessionStream, EgressStreamOpenError> {
        let stream = self.open(target).await?;
        match permit {
            Some(permit) => Ok(Box::new(ReservedSessionStream {
                inner: stream,
                _permit: permit,
            })),
            None => Ok(stream),
        }
    }
}

struct ReservedSessionStream {
    inner: BoxedSessionStream,
    _permit: OwnedSemaphorePermit,
}

impl AsyncRead for ReservedSessionStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(self.inner.as_mut()).poll_read(cx, buffer)
    }
}

impl AsyncWrite for ReservedSessionStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(self.inner.as_mut()).poll_write(cx, data)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(self.inner.as_mut()).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(self.inner.as_mut()).poll_shutdown(cx)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EgressStatusConfig {
    pub capacity_bps: u64,
    pub max_inbound_target_connections: usize,
    pub quota_remaining: Option<u64>,
    pub traffic_multiplier_basis_points: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EgressStatusSample {
    pub connected: bool,
    pub service_state: EgressServiceState,
    pub admission_allowed: bool,
    pub admission_reason: AdmissionReason,
    pub load_basis_points: u16,
    pub connection_utilization_basis_points: u16,
    pub bandwidth_utilization_basis_points: u16,
    pub active_sessions: u64,
    pub active_streams: u64,
    pub active_target_connections: u64,
    pub configured_capacity_bps: u64,
    pub effective_capacity_bps: u64,
    pub current_wire_rate_bps: u64,
    pub replication_allowance_bps: u64,
    pub capacity_state: CapacityState,
    pub quota_remaining: Option<u64>,
    pub traffic_multiplier_basis_points: u32,
}

pub trait EgressStatusProvider: std::fmt::Debug + Send + Sync + 'static {
    fn sample(&self) -> EgressStatusSample;

    fn try_reserve_wire(&self, _priority: WirePriority, _bytes: u64) -> bool {
        true
    }
}

#[derive(Debug)]
struct StaticEgressStatusProvider(EgressStatusConfig);

impl EgressStatusProvider for StaticEgressStatusProvider {
    fn sample(&self) -> EgressStatusSample {
        EgressStatusSample {
            connected: true,
            service_state: EgressServiceState::Up,
            admission_allowed: true,
            admission_reason: AdmissionReason::None,
            load_basis_points: 0,
            connection_utilization_basis_points: 0,
            bandwidth_utilization_basis_points: 0,
            active_sessions: 1,
            active_streams: 0,
            active_target_connections: 0,
            configured_capacity_bps: self.0.capacity_bps,
            effective_capacity_bps: self.0.capacity_bps,
            current_wire_rate_bps: 0,
            replication_allowance_bps: self.0.capacity_bps,
            capacity_state: CapacityState::Provisional,
            quota_remaining: self.0.quota_remaining,
            traffic_multiplier_basis_points: self.0.traffic_multiplier_basis_points,
        }
    }
}

impl Default for EgressStatusConfig {
    fn default() -> Self {
        Self {
            capacity_bps: 1_000_000_000,
            max_inbound_target_connections: MAX_SESSION_STREAMS,
            quota_remaining: None,
            traffic_multiplier_basis_points: 10_000,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamSnapshot {
    pub stream_id: StreamId,
    pub state: StreamState,
    pub target: TargetEndpoint,
    pub traffic_class: Option<TrafficClassConfig>,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub bytes_acked: u64,
    pub retransmissions: u64,
    pub reorder_buffer_bytes: usize,
    pub receive_window: u64,
    pub opened_at_ms: u64,
    pub closed_at_ms: Option<u64>,
    pub close_reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionSnapshot {
    pub session_id: SessionId,
    pub path_id: PathId,
    pub ready_paths: usize,
    pub ready_path_ids: Vec<PathId>,
    pub path_states: BTreeMap<PathId, pathchord_core::PathState>,
    pub degraded_paths: usize,
    pub effective_capacity_bps: u64,
    pub egress_aggregate_capacity_bps: u64,
    pub target_path_count: u64,
    pub path_quality: BTreeMap<PathId, PathQualitySnapshot>,
    pub demand: BTreeMap<DemandKey, DemandSnapshot>,
    pub active_streams: usize,
    pub active_udp_associations: usize,
    pub pending_session_controls: usize,
    pub egress_status: Option<EgressStatusObservation>,
    pub streams: BTreeMap<StreamId, StreamSnapshot>,
    pub pending_stream_opens: usize,
    pub retained_outbound_bytes: usize,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub closed: bool,
    pub trust_failure: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DemandSnapshot {
    pub bytes_per_second: u64,
    pub ewma_bps: u64,
}

/// Latest authenticated Egress sample and its observed age at snapshot time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EgressStatusObservation {
    pub report: StatusReport,
    pub age_ms: u64,
    pub fresh: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathExclusionReason {
    HeartbeatStale,
    StatusStale,
    Draining,
    HardUnavailable,
    IncrementalCapacityBelowOverhead,
    CongestionWindowExhausted,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathQualitySnapshot {
    pub attribution: Option<PathAttribution>,
    pub rtt_ms: u64,
    pub jitter_ms: u64,
    pub loss_ppm: u32,
    pub throughput_bps: u64,
    pub effective_capacity_bps: u64,
    pub upstream_effective_capacity_bps: Option<u64>,
    pub downstream_effective_capacity_bps: Option<u64>,
    pub upstream_throughput_bps: u64,
    pub downstream_throughput_bps: u64,
    pub control_pending: usize,
    pub control_retransmissions: u64,
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
    #[error("Path write timed out after {elapsed_ms} ms")]
    PathWriteTimeout { elapsed_ms: u64 },
    #[error("Session Path closed")]
    PathClosed,
    #[error("Path {path_id} write failed: {source}")]
    PathWrite {
        path_id: PathId,
        source: Box<SessionRuntimeError>,
    },
    #[error(
        "Session Path closed with {bytes} unacknowledged bytes; timed retransmission is unavailable"
    )]
    UnacknowledgedData { bytes: usize },
    #[error("Session runtime limit is invalid")]
    InvalidRuntimeLimit,
    #[error("Session peer violated an authenticated Stream invariant")]
    SessionTrustFailure,
    #[error("Egress global wire budget is exhausted")]
    WireBudgetExhausted,
    #[error("Egress reported a hard down state")]
    EgressHardFailure,
    #[error("Session RequestID random source failed")]
    RequestIdRandom,
    #[error("Session task failed: {0}")]
    Task(String),
    #[error("Session multipath state failed: {0}")]
    Multipath(#[from] MultipathError),
    #[error("admitted Path belongs to another Session")]
    WrongSession,
    #[error("Session UDP runtime failed: {0}")]
    Udp(#[from] crate::UdpRuntimeError),
}

impl SessionRuntimeError {
    fn failed_path(&self) -> Option<PathId> {
        match self {
            Self::PathWrite { path_id, .. } => Some(*path_id),
            _ => None,
        }
    }

    fn write_termination_reason(&self) -> PathTerminationReason {
        match self {
            Self::PathWrite { source, .. } => source.write_termination_reason(),
            Self::PathWriteTimeout { .. } => PathTerminationReason::WriteTimeout,
            _ => PathTerminationReason::WriteError,
        }
    }

    fn write_elapsed_ms(&self) -> Option<u64> {
        match self {
            Self::PathWrite { source, .. } => source.write_elapsed_ms(),
            Self::PathWriteTimeout { elapsed_ms } => Some(*elapsed_ms),
            _ => None,
        }
    }

    fn is_flow_recoverable(&self) -> bool {
        matches!(
            self,
            Self::PathClosed
                | Self::Multipath(MultipathError::NoSchedulablePath)
                | Self::Multipath(MultipathError::UnknownPath(_))
                | Self::WireBudgetExhausted
        )
    }
}

#[derive(Clone)]
pub struct SessionDiagnostics {
    pub history: Arc<DiagnosticHistory>,
    pub egress_id: String,
    pub attribution: Option<PathAttribution>,
}

pub struct IngressSessionHandle {
    attached_paths: watch::Receiver<BTreeSet<PathId>>,
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
        Self::start_observed(path, None)
    }

    pub fn start_observed<S>(
        path: IngressAdmittedPath<S>,
        diagnostics: Option<SessionDiagnostics>,
    ) -> Result<Self, SessionRuntimeError>
    where
        S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
        let session_id = path.session_id();
        let path_id = path.path_id();
        let ready = path.limits().clone();
        let capabilities = path.negotiated_capabilities();
        let session_replication_budget_bytes = path.replication_budget_bytes_per_second();
        let records = path.into_transport();
        let buffer_limit = runtime_buffer_limit(&ready)?;
        let stream_capacity = buffer_limit.clamp(1, 64 * 1024);
        let (commands, command_rx) = mpsc::channel(COMMAND_QUEUE_CAPACITY);
        let initial = SessionSnapshot {
            session_id,
            path_id,
            ready_paths: 1,
            ready_path_ids: vec![path_id],
            path_states: BTreeMap::from([(path_id, pathchord_core::PathState::Active)]),
            degraded_paths: 0,
            effective_capacity_bps: 0,
            egress_aggregate_capacity_bps: 0,
            target_path_count: 1,
            path_quality: BTreeMap::new(),
            demand: BTreeMap::new(),
            active_streams: 0,
            active_udp_associations: 0,
            pending_session_controls: 0,
            egress_status: None,
            streams: BTreeMap::new(),
            pending_stream_opens: 0,
            retained_outbound_bytes: 0,
            bytes_sent: 0,
            bytes_received: 0,
            closed: false,
            trust_failure: false,
        };
        let (snapshot_tx, snapshots) = watch::channel(initial);
        let actor = SessionActor::new(
            records,
            SessionActorInit {
                diagnostics,
                role: ActorRole::Ingress,
                udp_factory: None,
                session_id,
                path_id,
                ready,
                commands: Some(command_rx),
                snapshots: snapshot_tx,
                egress_status: EgressStatusConfig::default(),
                status_provider: None,
                capabilities,
                session_replication_budget_bytes,
                target_open_slots: None,
            },
        )?;
        let attached_paths = actor.attached_paths.subscribe();
        let task = tokio::spawn(actor.run());
        Ok(Self {
            commands,
            snapshots,
            task: Some(task),
            attached_paths,
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
        if multipath_config.require_fresh_status_report {
            self.wait_for_initial_egress_status()
                .await
                .map_err(|error| match error {
                    InitialStatusError::SessionClosed => OpenStreamError::SessionClosed,
                    InitialStatusError::Timeout => OpenStreamError::ResourceLimit,
                })?;
        }
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
        if multipath_config.require_fresh_status_report {
            self.wait_for_initial_egress_status()
                .await
                .map_err(|error| match error {
                    InitialStatusError::SessionClosed => OpenUdpError::SessionClosed,
                    InitialStatusError::Timeout => OpenUdpError::ResourceLimit,
                })?;
        }
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

    async fn wait_for_initial_egress_status(&self) -> Result<(), InitialStatusError> {
        let mut snapshots = self.snapshots.clone();
        tokio::time::timeout(PATH_DEGRADED_AFTER, async {
            loop {
                let (closed, has_status) = {
                    let snapshot = snapshots.borrow_and_update();
                    (snapshot.closed, snapshot.egress_status.is_some())
                };
                if closed {
                    return Err(InitialStatusError::SessionClosed);
                }
                if has_status {
                    return Ok(());
                }
                snapshots
                    .changed()
                    .await
                    .map_err(|_| InitialStatusError::SessionClosed)?;
            }
        })
        .await
        .unwrap_or(Err(InitialStatusError::Timeout))
    }

    pub async fn add_path<S>(
        &self,
        path: IngressAdmittedPath<S>,
        observation: MultipathPathObservation,
    ) -> Result<(), SessionRuntimeError>
    where
        S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
        self.add_path_observed(path, observation, None).await
    }

    pub async fn add_path_observed<S>(
        &self,
        path: IngressAdmittedPath<S>,
        observation: MultipathPathObservation,
        attribution: Option<PathAttribution>,
    ) -> Result<(), SessionRuntimeError>
    where
        S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
        let mut path = ErasedAdmittedPath::from_ingress(path);
        path.attribution = attribution;
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

    pub async fn add_replacement_path<S>(
        &self,
        path: IngressAdmittedPath<S>,
        observation: MultipathPathObservation,
        previous_path_id: PathId,
    ) -> Result<(), SessionRuntimeError>
    where
        S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
        let result = self.add_path(path, observation).await;
        if result.is_ok() {
            let _ = previous_path_id;
        }
        result
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
        let _ = self
            .attached_paths
            .clone()
            .wait_for(|paths| !paths.contains(&path_id))
            .await;
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
    attached_paths: watch::Receiver<BTreeSet<PathId>>,
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
        self.add_path_observed(path, observation, None).await
    }

    pub async fn add_path_observed<S>(
        &self,
        path: EgressAdmittedPath<S>,
        observation: MultipathPathObservation,
        attribution: Option<PathAttribution>,
    ) -> Result<(), SessionRuntimeError>
    where
        S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
        let mut path = ErasedAdmittedPath::from_egress(path);
        path.attribution = attribution;
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
        let _ = self
            .attached_paths
            .clone()
            .wait_for(|paths| !paths.contains(&path_id))
            .await;
    }

    #[must_use]
    pub fn active_stream_count(&self) -> usize {
        self.snapshots.borrow().active_streams
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
        Self::start_inner(
            path,
            factory,
            None,
            EgressStatusConfig::default(),
            None,
            None,
            None,
        )
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
            None,
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
            || status.max_inbound_target_connections == 0
            || status.traffic_multiplier_basis_points == 0
        {
            return Err(SessionRuntimeError::InvalidRuntimeLimit);
        }
        Self::start_inner(path, factory, None, status, None, None, None)
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
            || status.max_inbound_target_connections == 0
            || status.traffic_multiplier_basis_points == 0
        {
            return Err(SessionRuntimeError::InvalidRuntimeLimit);
        }
        Self::start_inner(
            path,
            factory,
            Some(Arc::new(udp_factory)),
            status,
            None,
            None,
            None,
        )
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
            None,
            None,
        )
    }

    pub fn start_with_udp_and_status_provider_and_target_slots<S, F, U>(
        path: EgressAdmittedPath<S>,
        factory: F,
        udp_factory: U,
        status: EgressStatusConfig,
        provider: Arc<dyn EgressStatusProvider>,
        target_slots: Arc<Semaphore>,
    ) -> Result<Self, SessionRuntimeError>
    where
        S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
        F: EgressStreamFactory,
        U: UdpTargetFactory + 'static,
    {
        Self::start_observed(
            path,
            factory,
            udp_factory,
            status,
            provider,
            target_slots,
            None,
        )
    }

    pub fn start_observed<S, F, U>(
        path: EgressAdmittedPath<S>,
        factory: F,
        udp_factory: U,
        status: EgressStatusConfig,
        provider: Arc<dyn EgressStatusProvider>,
        target_slots: Arc<Semaphore>,
        diagnostics: Option<SessionDiagnostics>,
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
            Some(target_slots),
            diagnostics,
        )
    }

    fn start_inner<S, F>(
        path: EgressAdmittedPath<S>,
        factory: F,
        udp_factory: Option<Arc<dyn UdpTargetFactory>>,
        egress_status: EgressStatusConfig,
        status_provider: Option<Arc<dyn EgressStatusProvider>>,
        target_open_slots: Option<Arc<Semaphore>>,
        diagnostics: Option<SessionDiagnostics>,
    ) -> Result<Self, SessionRuntimeError>
    where
        S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
        F: EgressStreamFactory,
    {
        if egress_status.capacity_bps == 0
            || egress_status.max_inbound_target_connections == 0
            || egress_status.traffic_multiplier_basis_points == 0
        {
            return Err(SessionRuntimeError::InvalidRuntimeLimit);
        }
        let target_open_slots = target_open_slots.or_else(|| {
            Some(Arc::new(Semaphore::new(
                egress_status.max_inbound_target_connections,
            )))
        });
        let session_id = path.session_id();
        let path_id = path.path_id();
        let ready = path.limits().clone();
        let capabilities = path.negotiated_capabilities();
        let session_replication_budget_bytes = path.replication_budget_bytes_per_second();
        let records = path.into_transport();
        let initial = SessionSnapshot {
            session_id,
            path_id,
            ready_paths: 1,
            ready_path_ids: vec![path_id],
            path_states: BTreeMap::from([(path_id, pathchord_core::PathState::Active)]),
            degraded_paths: 0,
            effective_capacity_bps: 0,
            egress_aggregate_capacity_bps: 0,
            target_path_count: 1,
            path_quality: BTreeMap::new(),
            demand: BTreeMap::new(),
            active_streams: 0,
            active_udp_associations: 0,
            pending_session_controls: 0,
            egress_status: None,
            streams: BTreeMap::new(),
            pending_stream_opens: 0,
            retained_outbound_bytes: 0,
            bytes_sent: 0,
            bytes_received: 0,
            closed: false,
            trust_failure: false,
        };
        let (snapshot_tx, snapshots) = watch::channel(initial);
        let (commands, command_rx) = mpsc::channel(COMMAND_QUEUE_CAPACITY);
        let actor = SessionActor::new(
            records,
            SessionActorInit {
                diagnostics,
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
                capabilities,
                session_replication_budget_bytes,
                target_open_slots,
            },
        )?;
        let attached_paths = actor.attached_paths.subscribe();
        let task = tokio::spawn(actor.run());
        Ok(Self {
            controller: EgressSessionController {
                attached_paths,
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
    diagnostics: Option<SessionDiagnostics>,
    role: ActorRole,
    udp_factory: Option<Arc<dyn UdpTargetFactory>>,
    session_id: SessionId,
    path_id: PathId,
    ready: pathchord_core::PathReady,
    commands: Option<mpsc::Receiver<IngressCommand>>,
    snapshots: watch::Sender<SessionSnapshot>,
    egress_status: EgressStatusConfig,
    status_provider: Option<Arc<dyn EgressStatusProvider>>,
    capabilities: u64,
    session_replication_budget_bytes: u64,
    target_open_slots: Option<Arc<Semaphore>>,
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
    attribution: Option<PathAttribution>,
    capabilities: u64,
    replication_budget_bytes_per_second: u64,
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
        let capabilities = path.negotiated_capabilities();
        let replication_budget_bytes_per_second = path.replication_budget_bytes_per_second();
        let records = path.into_transport();
        let limits = records.limits();
        let (io, noise) = records.into_parts();
        Self {
            attribution: None,
            capabilities,
            replication_budget_bytes_per_second,
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
        let capabilities = path.negotiated_capabilities();
        let replication_budget_bytes_per_second = path.replication_budget_bytes_per_second();
        let records = path.into_transport();
        let limits = records.limits();
        let (io, noise) = records.into_parts();
        Self {
            attribution: None,
            capabilities,
            replication_budget_bytes_per_second,
            session_id,
            path_id,
            ready,
            records: NoiseRecordStream::new(Box::new(io), noise, limits),
        }
    }
}

struct PendingIngressOpen {
    traffic_class: Option<TrafficClassConfig>,
    demand_key: Option<DemandKey>,
    replication_budget: FlowReplicationBudget,
    io: BoxedSessionStream,
    eligible_paths: Option<BTreeMap<PathId, u32>>,
    reply: oneshot::Sender<Result<(), OpenStreamError>>,
}

struct PendingIngressUdp {
    traffic_class: Option<TrafficClassConfig>,
    demand_key: Option<DemandKey>,
    replication_budget: FlowReplicationBudget,
    datagrams: mpsc::Sender<Vec<u8>>,
    eligible_paths: Option<BTreeMap<PathId, u32>>,
    reply: oneshot::Sender<Result<u64, OpenUdpError>>,
}

struct IngressUdpAssociation {
    datagrams: mpsc::Sender<Vec<u8>>,
    eligible_paths: Option<BTreeMap<PathId, u32>>,
    demand_key: Option<DemandKey>,
    replication_budget: FlowReplicationBudget,
}

#[derive(Clone, Copy, Debug)]
struct FlowReplicationBudget {
    stream_bytes: u64,
    class_bytes: u64,
}

impl FlowReplicationBudget {
    fn unlimited(cap: u64) -> Self {
        Self {
            stream_bytes: cap,
            class_bytes: cap,
        }
    }

    fn from_config(config: &MultipathConfig, session_cap: u64) -> Self {
        let stream_bytes = config
            .default_stream_replication_budget_bytes
            .min(config.session_replication_budget_bytes)
            .min(session_cap);
        let class_bytes = config
            .traffic_class
            .as_ref()
            .map(|class| class.name.as_str())
            .or(Some("default"))
            .and_then(|class| config.class_replication_budget_bytes.get(class))
            .copied()
            .unwrap_or(stream_bytes)
            .min(stream_bytes);
        Self {
            stream_bytes,
            class_bytes,
        }
    }
}

#[derive(Clone)]
enum CachedOpenResult {
    Pending,
    Opened { metadata: Vec<u8> },
    Rejected { error: ErrorClass, reason: Vec<u8> },
}

struct CachedEgressOpen {
    traffic_class: Option<TrafficClassConfig>,
    request: StreamOpen,
    result: CachedOpenResult,
    eligible_paths: BTreeMap<PathId, u32>,
    unrestricted_paths: bool,
}

struct FactoryCompletion {
    stream_id: StreamId,
    request_id: RequestId,
    result: Result<BoxedSessionStream, EgressStreamOpenError>,
    elapsed_ms: u64,
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

enum RecordRead {
    Frame(PathFrame),
    ReplayDropped,
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
        operation: &'static str,
        kind: std::io::ErrorKind,
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
    traffic_class: Option<TrafficClassConfig>,
    demand_key: Option<DemandKey>,
    replication_budget: FlowReplicationBudget,
    fin_sent: bool,
    io_finished: bool,
    commands: mpsc::Sender<StreamIoCommand>,
    task: JoinHandle<()>,
    receive: StreamReceiveBuffer,
    inbound_permits: Vec<InboundPermit>,
    next_send_offset: u64,
    emitted: Vec<AckRange>,
    acknowledged: Vec<AckRange>,
    pending: VecDeque<OutboundChunk>,
    retained: BTreeMap<u64, RetainedChunk>,
    remote_receive_limit: u64,
    local_receive_limit: u64,
    local_fin: bool,
    remote_fin: bool,
    remote_fin_offset: Option<u64>,
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

#[derive(Clone, Debug, PartialEq, Eq)]
enum SessionControlEntry {
    Control(SessionControl),
    Cancel(SessionControlCancel),
}

impl SessionControlEntry {
    fn sequence(&self) -> u64 {
        match self {
            Self::Control(value) => value.sequence,
            Self::Cancel(value) => value.sequence,
        }
    }

    fn message(&self) -> Message {
        match self {
            Self::Control(value) => Message::SessionControl(value.clone()),
            Self::Cancel(value) => Message::SessionControlCancel(value.clone()),
        }
    }
}

struct PendingSessionControl {
    retry_round: usize,
    message: SessionControlEntry,
    eligible_paths: Option<BTreeMap<PathId, u32>>,
    last_sent_at: Instant,
}

struct PathHealth {
    attribution: Option<PathAttribution>,
    terminal_write: Option<(PathTerminationReason, Option<u64>)>,
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
    upstream_bytes_since_observation: u64,
    downstream_bytes_since_observation: u64,
    last_observation_at: Instant,
    throughput_bps: u64,
    upstream_throughput_bps: u64,
    downstream_throughput_bps: u64,
    reordering_events: u64,
    data_events: u64,
    effective_capacity_bps: u64,
    upstream_effective_capacity_bps: Option<u64>,
    downstream_effective_capacity_bps: Option<u64>,
    congestion_window_bytes: Option<u64>,
    incremental_capacity_bps: Option<u64>,
    scheduling_overhead_bps: Option<u64>,
    exclusion_reason: Option<PathExclusionReason>,
    relationship_weight_basis_points: u16,
    drain_deadline: Option<Instant>,
}

impl PathHealth {
    fn new(now: Instant) -> Result<Self, ReliabilityError> {
        Ok(Self {
            attribution: None,
            terminal_write: None,
            sender: ControlSender::new(MAX_PENDING_CONTROL_MESSAGES)?,
            receiver: ControlReceiver::new(MAX_PENDING_CONTROL_MESSAGES)?,
            last_heartbeat_received: now,
            last_heartbeat_sent: now,
            last_status_received: now,
            // Publish one authenticated status report on the first health
            // tick so production Ingress can require fresh admission state
            // without delaying the initial Session indefinitely.
            last_status_sent: now.checked_sub(STATUS_REPORT_INTERVAL).unwrap_or(now),
            rtt_ms: 1,
            jitter_ms: 0,
            sent_controls: 0,
            retransmitted_controls: 0,
            bytes_since_observation: 0,
            upstream_bytes_since_observation: 0,
            downstream_bytes_since_observation: 0,
            last_observation_at: now,
            throughput_bps: 0,
            upstream_throughput_bps: 0,
            downstream_throughput_bps: 0,
            reordering_events: 0,
            data_events: 0,
            effective_capacity_bps: 1,
            upstream_effective_capacity_bps: None,
            downstream_effective_capacity_bps: None,
            congestion_window_bytes: None,
            incremental_capacity_bps: None,
            scheduling_overhead_bps: None,
            exclusion_reason: None,
            relationship_weight_basis_points: 10_000,
            drain_deadline: None,
        })
    }
}

struct PendingUdpSend {
    datagram: UdpDatagram,
    reply: Option<oneshot::Sender<Result<(), OpenUdpError>>>,
    _permit: OwnedSemaphorePermit,
}

struct SessionActor<W> {
    attached_paths: watch::Sender<BTreeSet<PathId>>,
    diagnostics: Option<SessionDiagnostics>,
    session_control_sender: ControlSender<PendingSessionControl>,
    next_session_control: u64,
    queued_session_controls: BTreeMap<u64, (BTreeSet<PathId>, SessionControlEntry)>,
    active_control_eligible: Option<Option<BTreeMap<PathId, u32>>>,
    local_close_sequence: Option<u64>,
    remote_closing: bool,
    capabilities: u64,
    traffic_queue: crate::traffic_queue::TrafficQueue,
    stream_observations: BTreeMap<StreamId, StreamSnapshot>,
    closed_streams: VecDeque<StreamId>,
    udp_classes: HashMap<u64, TrafficClassConfig>,
    pending_udp: HashMap<u64, VecDeque<PendingUdpSend>>,
    closing_udp: HashMap<u64, Vec<oneshot::Sender<Result<(), OpenUdpError>>>>,
    role: ActorRole,
    writer: RecordWriter<W>,
    reader_task: Option<JoinHandle<()>>,
    frame_tx: mpsc::Sender<ReaderEvent>,
    frames: mpsc::Receiver<ReaderEvent>,
    extra_paths: HashMap<PathId, ExtraPath>,
    multipath: MultipathSession,
    path_health: HashMap<PathId, PathHealth>,
    retired_path_states: BTreeMap<PathId, pathchord_core::PathState>,
    retired_path_order: VecDeque<PathId>,
    next_status_report_seq: u64,
    status_provider: Arc<dyn EgressStatusProvider>,
    trust_failure: bool,
    target_path_count: u64,
    egress_aggregate_capacity_bps: u64,
    latest_egress_status: Option<(StatusReport, Instant)>,
    commands: Option<mpsc::Receiver<IngressCommand>>,
    stream_events: mpsc::Receiver<StreamEvent>,
    stream_event_tx: mpsc::Sender<StreamEvent>,
    factory_results: mpsc::Receiver<FactoryCompletion>,
    factory_result_tx: mpsc::Sender<FactoryCompletion>,
    opening_tasks: HashMap<StreamId, JoinHandle<()>>,
    target_open_slots: Option<Arc<Semaphore>>,
    streams: HashMap<StreamId, ActiveStream>,
    pending_ingress: HashMap<StreamId, PendingIngressOpen>,
    egress_requests: HashMap<RequestId, CachedEgressOpen>,
    egress_streams: HashMap<StreamId, RequestId>,
    pending_ingress_udp: HashMap<u64, PendingIngressUdp>,
    ingress_udp: HashMap<u64, IngressUdpAssociation>,
    egress_udp_paths: HashMap<u64, BTreeMap<PathId, u32>>,
    unrestricted_udp_paths: BTreeSet<u64>,
    retired_udp_associations: BTreeSet<u64>,
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
    send_budget: Arc<Semaphore>,
    inbound_budget: Arc<Semaphore>,
    remote_session_limit: u64,
    local_session_limit: u64,
    session_sent_total: u64,
    session_received_total: u64,
    bytes_sent: u64,
    bytes_received: u64,
    demand_bytes: BTreeMap<DemandKey, u64>,
    demand_last_bps: BTreeMap<DemandKey, u64>,
    demand_ewma_bps: BTreeMap<DemandKey, u64>,
    demand_window_started: Instant,
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
            diagnostics,
            role,
            udp_factory,
            session_id,
            path_id,
            ready,
            commands,
            snapshots,
            egress_status,
            status_provider,
            capabilities,
            session_replication_budget_bytes,
            target_open_slots,
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
            diagnostics: diagnostics
                .as_ref()
                .map(|context| Arc::clone(&context.history)),
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
        let outgoing_budget = session_replication_budget_bytes;
        let mut multipath = MultipathSession::new(
            session_id,
            MultipathConfig {
                session_replication_budget_bytes: outgoing_budget,
                default_stream_replication_budget_bytes: outgoing_budget,
                retransmission_replication_enabled: outgoing_budget != 0,
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
            diagnostics,
            session_control_sender: ControlSender::new(MAX_SESSION_CONTROL_MESSAGES)?,
            next_session_control: 0,
            queued_session_controls: BTreeMap::new(),
            active_control_eligible: None,
            local_close_sequence: None,
            remote_closing: false,
            capabilities,
            traffic_queue: Default::default(),
            stream_observations: BTreeMap::new(),
            closed_streams: VecDeque::new(),
            udp_classes: HashMap::new(),
            pending_udp: HashMap::new(),
            closing_udp: HashMap::new(),
            role,
            writer,
            reader_task: Some(reader_task),
            frame_tx,
            frames,
            attached_paths: watch::Sender::new(BTreeSet::from([path_id])),
            extra_paths: HashMap::new(),
            multipath,
            path_health,
            retired_path_states: BTreeMap::new(),
            retired_path_order: VecDeque::new(),
            next_status_report_seq: 0,
            status_provider,
            trust_failure: false,
            target_path_count: 1,
            egress_aggregate_capacity_bps: 0,
            latest_egress_status: None,
            commands,
            stream_events,
            stream_event_tx,
            factory_results,
            factory_result_tx,
            opening_tasks: HashMap::new(),
            target_open_slots,
            streams: HashMap::new(),
            pending_ingress: HashMap::new(),
            egress_requests: HashMap::new(),
            egress_streams: HashMap::new(),
            pending_ingress_udp: HashMap::new(),
            ingress_udp: HashMap::new(),
            egress_udp_paths: HashMap::new(),
            unrestricted_udp_paths: BTreeSet::new(),
            retired_udp_associations: BTreeSet::new(),
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
            send_budget: Arc::new(Semaphore::new(buffer_limit)),
            inbound_budget: Arc::new(Semaphore::new(buffer_limit)),
            remote_session_limit: buffer_limit as u64,
            local_session_limit: buffer_limit as u64,
            session_sent_total: 0,
            session_received_total: 0,
            bytes_sent: 0,
            bytes_received: 0,
            demand_bytes: BTreeMap::new(),
            demand_last_bps: BTreeMap::new(),
            demand_ewma_bps: BTreeMap::new(),
            demand_window_started: Instant::now(),
            snapshots,
        })
    }
}

impl<W> SessionActor<W>
where
    W: AsyncWrite + Send + Unpin + 'static,
{
    /// Validate one flow's immutable policy snapshot without mutating the
    /// Session-wide negotiated cap. A later flow must not inherit a stricter
    /// floor from an earlier low-budget flow.
    fn flow_replication_budget(
        &self,
        incoming: &MultipathConfig,
    ) -> Result<FlowReplicationBudget, MultipathError> {
        if incoming.max_paths == 0
            || (incoming.retransmission_replication_enabled
                && (incoming.session_replication_budget_bytes == 0
                    || incoming.default_stream_replication_budget_bytes == 0))
        {
            return Err(MultipathError::ZeroCapacity);
        }
        if incoming
            .class_replication_budget_bytes
            .values()
            .any(|budget| *budget > incoming.session_replication_budget_bytes)
        {
            return Err(MultipathError::InvalidReplicationBudget);
        }
        Ok(FlowReplicationBudget::from_config(
            incoming,
            self.multipath.session_replication_budget_bytes(),
        ))
    }

    async fn run(mut self) -> Result<SessionSnapshot, SessionRuntimeError> {
        self.publish_snapshot(false);
        let result = self.run_loop().await;
        if matches!(result, Err(SessionRuntimeError::SessionTrustFailure)) {
            self.trust_failure = true;
        }
        self.terminate_paths().await;
        if let Some(diagnostics) = &self.diagnostics {
            let reason = match &result {
                Ok(()) => None,
                Err(SessionRuntimeError::SessionTrustFailure) => Some(DiagnosticReason::Protocol),
                Err(SessionRuntimeError::PathClosed | SessionRuntimeError::EgressHardFailure) => {
                    Some(DiagnosticReason::Unavailable)
                }
                Err(SessionRuntimeError::PathWriteTimeout { .. }) => {
                    Some(DiagnosticReason::Timeout)
                }
                Err(_) => Some(DiagnosticReason::Unknown),
            };
            diagnostics.history.record(
                DiagnosticIds {
                    egress_id: Some(diagnostics.egress_id.clone()),
                    session_id: Some(self.session_id),
                    path_id: None,
                    stream_id: None,
                    transit_proxy_id: None,
                    attribution: None,
                    attempt_id: None,
                },
                DiagnosticDetail::SessionTermination {
                    outcome: if reason.is_some() {
                        DiagnosticOutcome::Failure
                    } else {
                        DiagnosticOutcome::Success
                    },
                    reason,
                },
            );
        }
        self.cleanup().await;
        self.publish_snapshot(true);
        result.map(|()| self.current_snapshot(true))
    }

    async fn run_loop(&mut self) -> Result<(), SessionRuntimeError> {
        let mut retransmission_tick = tokio::time::interval(MIN_RETRANSMISSION_TIMEOUT);
        retransmission_tick.set_missed_tick_behavior(MissedTickBehavior::Skip);
        retransmission_tick.tick().await;
        // Drain a bounded FIFO batch before snapshotting and revisiting health
        // timers, so queued acknowledgements can suppress needless retries.
        let mut reader_events = Vec::with_capacity(MAX_READER_EVENTS_PER_TURN);
        loop {
            tokio::select! {
                _ = tokio::task::yield_now(), if self.business_ready() => {},
                command = receive_command(&mut self.commands) => {
                    match command {
                        Some(command) => {
                            match self.handle_command(command).await {
                                Ok(true) => return Ok(()),
                                Ok(false) => {},
                                Err(error) => self.handle_runtime_error(error, None).await?,
                            }
                        }
                        None => self.commands = None,
                    }
                }
                count = self.frames.recv_many(&mut reader_events, MAX_READER_EVENTS_PER_TURN) => {
                    if count == 0 {
                        return Err(SessionRuntimeError::PathClosed);
                    }
                    for event in reader_events.drain(..) {
                        match event {
                            ReaderEvent::Frame { path_id, frame } => {
                                // A reader can have queued frames before its Path
                                // was failed by a different event.
                                if !self.path_health.contains_key(&path_id) {
                                    continue;
                                }
                                match self.handle_frame(path_id, frame).await {
                                    Ok(true) => return Ok(()),
                                    Ok(false) => {},
                                    Err(error) => self.handle_runtime_error(error, Some(path_id)).await?,
                                }
                            }
                            ReaderEvent::Closed { path_id } => {
                                if self.remote_closing { return Ok(()); }
                                if self.retire_path(path_id, false, PathTerminationReason::PeerEof, None).await? {
                                    let retained = self.retained_outbound_bytes();
                                    return if retained == 0 {
                                        Err(SessionRuntimeError::PathClosed)
                                    } else {
                                        Err(SessionRuntimeError::UnacknowledgedData { bytes: retained })
                                    };
                                }
                            }
                            ReaderEvent::Failed { path_id, error } => {
                                if self.remote_closing { return Ok(()); }
                                let reason = if matches!(&error, SessionRuntimeError::Io(_)) { PathTerminationReason::ReadError } else { PathTerminationReason::ProtocolError };
                                if self.retire_path(path_id, false, reason, None).await? {
                                    return Err(error);
                                }
                            }
                        }
                    }
                }
                event = self.stream_events.recv() => {
                    if let Some(event) = event
                        && let Err(error) = self.handle_stream_event(event).await
                    {
                        self.handle_runtime_error(error, None).await?;
                    }
                }
                completion = self.factory_results.recv() => {
                    if let Some(completion) = completion
                        && let Err(error) = self.handle_factory_completion(completion).await
                    {
                        self.handle_runtime_error(error, None).await?;
                    }
                }
                _ = retransmission_tick.tick() => {
                    if let Err(error) = self.retry_session_controls().await {
                        self.handle_runtime_error(error, None).await?;
                    }
                    if let Err(error) = self.handle_retransmission_timeouts().await {
                        self.handle_runtime_error(error, None).await?;
                    }
                    if let Err(error) = self.poll_udp_targets().await {
                        self.handle_runtime_error(error, None).await?;
                    }
                    if self.handle_path_health().await? {
                        return Err(SessionRuntimeError::PathClosed);
                    }
                    self.multipath.advance_status_age(
                        MIN_RETRANSMISSION_TIMEOUT.as_millis() as u64,
                    );
                }
            }
            for _ in 0..STREAM_EVENT_QUEUE_CAPACITY {
                let Ok(event) = self.stream_events.try_recv() else {
                    break;
                };
                if let Err(error) = self.handle_stream_event(event).await {
                    self.handle_runtime_error(error, None).await?;
                }
            }
            if let Err(error) = self.flush_business().await {
                self.handle_runtime_error(error, None).await?;
            }
            if let Err(error) = self.finish_pending_udp_closes().await {
                self.handle_runtime_error(error, None).await?;
            }
            self.retire_drained_udp();
            self.publish_snapshot(false);
        }
    }

    /// Attribute a failed write to the Path that actually failed. A business
    /// frame can be received on one Path while its ACK or response is sent on
    /// another; using the receiving Path here would incorrectly retire a
    /// healthy Path. Recoverable scheduling failures are kept at flow scope as
    /// long as another Path remains available.
    async fn handle_runtime_error(
        &mut self,
        error: SessionRuntimeError,
        received_path_id: Option<PathId>,
    ) -> Result<(), SessionRuntimeError> {
        if matches!(
            &error,
            SessionRuntimeError::SessionTrustFailure | SessionRuntimeError::EgressHardFailure
        ) {
            return Err(error);
        }
        let received_path_id = (!error.is_flow_recoverable())
            .then_some(received_path_id)
            .flatten();
        if let Some(path_id) = error.failed_path().or(received_path_id) {
            let closed = if error.failed_path().is_some() {
                self.retire_write_failure(path_id, &error).await?
            } else {
                self.retire_path(path_id, false, PathTerminationReason::ProtocolError, None)
                    .await?
            };
            if closed {
                return Err(error);
            }
            return Ok(());
        }
        if error.is_flow_recoverable() && self.multipath.ready_path_count() > 0 {
            self.cancel_unroutable_flows().await?;
            return Ok(());
        }
        Err(error)
    }

    async fn handle_command(
        &mut self,
        command: IngressCommand,
    ) -> Result<bool, SessionRuntimeError> {
        match command {
            IngressCommand::Shutdown => {
                if self.local_close_sequence.is_some() {
                    return Ok(false);
                }
                let sequence = self
                    .send_session_control(
                        Message::SessionClose(SessionClose {
                            error: ErrorClass::PathFailure,
                            reason: b"Ingress shutdown".to_vec(),
                        }),
                        None,
                    )
                    .await?;
                self.local_close_sequence = Some(sequence);
                Ok(false)
            }
            IngressCommand::OpenUdp {
                target,
                datagrams,
                eligible_paths: _requested_paths,
                multipath_config,
                reply,
            } => {
                if self.capabilities & CAPABILITY_UDP_SESSION == 0 {
                    let _ = reply.send(Err(OpenUdpError::Rejected {
                        error: ErrorClass::EgressFailure,
                        reason: b"UDP capability was not negotiated".to_vec(),
                    }));
                    return Ok(false);
                }
                let require_fresh_status = multipath_config
                    .as_ref()
                    .is_some_and(|config| config.require_fresh_status_report);
                let minimum = multipath_config
                    .as_ref()
                    .map_or(1, |config| config.minimum_usable_paths.max(1));
                if self
                    .multipath
                    .admissible_path_count(None, require_fresh_status)
                    < minimum
                {
                    let _ = reply.send(Err(OpenUdpError::ResourceLimit));
                    return Ok(false);
                }
                let traffic_class = multipath_config
                    .as_ref()
                    .and_then(|config| config.traffic_class.clone());
                let demand_key = multipath_config
                    .as_ref()
                    .and_then(|config| config.demand_key.clone());
                if traffic_class
                    .as_ref()
                    .is_some_and(|class| class.validate().is_err())
                {
                    let _ = reply.send(Err(OpenUdpError::Rejected {
                        error: ErrorClass::LocalPolicy,
                        reason: b"traffic class capability is unavailable or invalid".to_vec(),
                    }));
                    return Ok(false);
                }
                let replication_budget = match multipath_config
                    .as_ref()
                    .map(|config| self.flow_replication_budget(config))
                    .transpose()
                {
                    Ok(Some(budget)) => budget,
                    Ok(None) => FlowReplicationBudget {
                        stream_bytes: self.multipath.session_replication_budget_bytes(),
                        class_bytes: self.multipath.session_replication_budget_bytes(),
                    },
                    Err(error) => {
                        let _ = reply.send(Err(OpenUdpError::Rejected {
                            error: ErrorClass::LocalPolicy,
                            reason: error.to_string().into_bytes(),
                        }));
                        return Ok(false);
                    }
                };
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
                let request = UdpOpen {
                    association_id,
                    target_flags,
                    target,
                };
                let open = Message::UdpOpen(request);
                self.pending_ingress_udp.insert(
                    association_id,
                    PendingIngressUdp {
                        traffic_class,
                        demand_key,
                        replication_budget,
                        datagrams,
                        eligible_paths: None,
                        reply,
                    },
                );
                self.send_session_control(open, None).await?;
                Ok(false)
            }
            IngressCommand::SendUdp {
                association_id,
                payload,
                reply,
            } => {
                if !self.ingress_udp.contains_key(&association_id)
                    || self.closing_udp.contains_key(&association_id)
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
                self.queue_udp(
                    UdpDatagram {
                        association_id,
                        datagram_seq,
                        payload,
                    },
                    Some(reply),
                );
                Ok(false)
            }
            IngressCommand::CloseUdp {
                association_id,
                reply,
            } => {
                if self.ingress_udp.contains_key(&association_id) {
                    self.closing_udp
                        .entry(association_id)
                        .or_default()
                        .push(reply);
                } else {
                    let _ = reply.send(Ok(()));
                }
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
                        if error.failed_path().is_none() && !error.is_flow_recoverable() {
                            return Err(error);
                        }
                        if self.retire_write_failure(path_id, &error).await? {
                            return Err(error);
                        }
                        return Ok(false);
                    }
                    match self
                        .retire_path(
                            path_id,
                            false,
                            PathTerminationReason::AdministrativeClose,
                            None,
                        )
                        .await
                    {
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
                        if error.failed_path().is_none() && !error.is_flow_recoverable() {
                            return Err(error);
                        }
                        if self.retire_write_failure(path_id, &error).await? {
                            return Err(error);
                        }
                        return Ok(false);
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
                    health.effective_capacity_bps = observation.effective_capacity_bps;
                    health.upstream_effective_capacity_bps =
                        observation.upstream_effective_capacity_bps;
                    health.downstream_effective_capacity_bps =
                        observation.downstream_effective_capacity_bps;
                    health.congestion_window_bytes = observation.congestion_window_bytes;
                    health.incremental_capacity_bps = observation.incremental_capacity_bps;
                    health.scheduling_overhead_bps = observation.scheduling_overhead_bps;
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
                eligible_paths: _requested_paths,
                multipath_config,
                reply,
            } => {
                if self.capabilities & CAPABILITY_TCP_STREAM == 0 {
                    let _ = reply.send(Err(OpenStreamError::Rejected {
                        error: ErrorClass::EgressFailure,
                        reason: b"TCP capability was not negotiated".to_vec(),
                    }));
                    return Ok(false);
                }
                let require_fresh_status = multipath_config
                    .as_ref()
                    .is_some_and(|config| config.require_fresh_status_report);
                let minimum = multipath_config
                    .as_ref()
                    .map_or(1, |config| config.minimum_usable_paths.max(1));
                if self
                    .multipath
                    .admissible_path_count(None, require_fresh_status)
                    < minimum
                {
                    let _ = reply.send(Err(OpenStreamError::ResourceLimit));
                    return Ok(false);
                }
                let traffic_class = multipath_config
                    .as_ref()
                    .and_then(|config| config.traffic_class.clone());
                let demand_key = multipath_config
                    .as_ref()
                    .and_then(|config| config.demand_key.clone());
                if traffic_class
                    .as_ref()
                    .is_some_and(|class| class.validate().is_err())
                {
                    let _ = reply.send(Err(OpenStreamError::Rejected {
                        error: ErrorClass::LocalPolicy,
                        reason: b"traffic class capability is unavailable or invalid".to_vec(),
                    }));
                    return Ok(false);
                }
                let replication_budget = match multipath_config
                    .as_ref()
                    .map(|config| self.flow_replication_budget(config))
                    .transpose()
                {
                    Ok(Some(budget)) => budget,
                    Ok(None) => FlowReplicationBudget {
                        stream_bytes: self.multipath.session_replication_budget_bytes(),
                        class_bytes: self.multipath.session_replication_budget_bytes(),
                    },
                    Err(error) => {
                        let _ = reply.send(Err(OpenStreamError::Rejected {
                            error: ErrorClass::LocalPolicy,
                            reason: error.to_string().into_bytes(),
                        }));
                        return Ok(false);
                    }
                };
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
                let mut random = [0_u8; 16];
                getrandom::fill(&mut random).map_err(|_| SessionRuntimeError::RequestIdRandom)?;
                let request_id = RequestId::from_be_bytes(random);
                self.observe_open(stream_id, target.clone(), traffic_class.clone());
                let request = StreamOpen {
                    stream_id,
                    request_id,
                    target,
                };
                let open = Message::StreamOpen(request);
                self.pending_ingress.insert(
                    stream_id,
                    PendingIngressOpen {
                        traffic_class,
                        demand_key,
                        replication_budget,
                        io,
                        eligible_paths: None,
                        reply,
                    },
                );
                self.send_session_control(open, None).await?;
                Ok(false)
            }
        }
    }

    fn add_erased_path(
        &mut self,
        path: ErasedAdmittedPath,
        observation: MultipathPathObservation,
    ) -> Result<(), SessionRuntimeError> {
        if path.capabilities != self.capabilities {
            return Err(SessionRuntimeError::InvalidRuntimeLimit);
        }
        if path.replication_budget_bytes_per_second
            != self.multipath.session_replication_budget_bytes()
        {
            return Err(SessionRuntimeError::InvalidRuntimeLimit);
        }
        if path.session_id != self.session_id {
            return Err(SessionRuntimeError::WrongSession);
        }
        if path.records.limits() != self.limits
            || path.ready.max_frame_payload < (self.chunk_size + FRAME_OVERHEAD_RESERVE) as u64
            || path.ready.max_session_buffering < self.buffer_limit as u64
        {
            return Err(SessionRuntimeError::InvalidRuntimeLimit);
        }
        self.multipath.add_path(path.path_id, observation.clone())?;
        let path_id = path.path_id;
        let limits = path.records.limits();
        let (io, noise) = path.records.into_parts();
        let next_frame_seq = noise
            .next_send_nonce()
            .ok_or(SessionRuntimeError::FrameSequenceExhausted)?;
        let noise = Arc::new(Mutex::new(noise));
        let (read, write) = split(io);
        let writer = RecordWriter {
            diagnostics: self
                .diagnostics
                .as_ref()
                .map(|context| Arc::clone(&context.history)),
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
        let mut health = PathHealth::new(Instant::now())?;
        health.attribution = path.attribution;
        health.relationship_weight_basis_points = observation.weight_basis_points;
        health.effective_capacity_bps = observation.effective_capacity_bps;
        health.congestion_window_bytes = observation.congestion_window_bytes;
        health.incremental_capacity_bps = observation.incremental_capacity_bps;
        health.scheduling_overhead_bps = observation.scheduling_overhead_bps;
        self.path_health.insert(path_id, health);
        self.attached_paths.send_modify(|paths| {
            paths.insert(path_id);
        });
        for cached in self
            .egress_requests
            .values_mut()
            .filter(|cached| cached.unrestricted_paths)
        {
            cached.eligible_paths.entry(path_id).or_insert(100);
            if let Some(stream) = self.streams.get_mut(&cached.request.stream_id)
                && let Some(eligible) = stream.eligible_paths.as_mut()
            {
                eligible.entry(path_id).or_insert(100);
            }
        }
        for id in &self.unrestricted_udp_paths {
            self.egress_udp_paths
                .entry(*id)
                .or_default()
                .entry(path_id)
                .or_insert(100);
        }
        Ok(())
    }

    const fn outbound_direction(&self) -> ScheduleDirection {
        match &self.role {
            ActorRole::Ingress => ScheduleDirection::Upstream,
            ActorRole::Egress { .. } => ScheduleDirection::Downstream,
        }
    }

    fn record_path_termination(
        &self,
        path_id: PathId,
        health: &PathHealth,
        closed: bool,
        reason: PathTerminationReason,
        write_elapsed_ms: Option<u64>,
    ) {
        let Some(diagnostics) = &self.diagnostics else {
            return;
        };
        let attribution = if path_id == self.path_id {
            diagnostics.attribution.clone()
        } else {
            health.attribution.clone()
        };
        diagnostics.history.record(
            DiagnosticIds {
                egress_id: Some(diagnostics.egress_id.clone()),
                session_id: Some(self.session_id),
                path_id: Some(path_id),
                stream_id: None,
                transit_proxy_id: attribution
                    .as_ref()
                    .and_then(|node| node.transit_proxy_id.clone()),
                attribution,
                attempt_id: None,
            },
            DiagnosticDetail::PathTermination {
                state: if closed {
                    pathchord_core::PathState::Closed
                } else {
                    pathchord_core::PathState::Failed
                },
                reason,
                write_elapsed_ms,
                heartbeat_age_ms: Some(health.last_heartbeat_received.elapsed().as_millis() as u64),
            },
        );
    }

    async fn retire_write_failure(
        &mut self,
        path_id: PathId,
        error: &SessionRuntimeError,
    ) -> Result<bool, SessionRuntimeError> {
        self.retire_path(
            path_id,
            false,
            error.write_termination_reason(),
            error.write_elapsed_ms(),
        )
        .await
    }

    async fn handle_path_failure(&mut self, path_id: PathId) -> Result<bool, SessionRuntimeError> {
        self.retire_path(path_id, false, PathTerminationReason::Unknown, None)
            .await
    }

    async fn retire_path(
        &mut self,
        path_id: PathId,
        drained: bool,
        reason: PathTerminationReason,
        write_elapsed_ms: Option<u64>,
    ) -> Result<bool, SessionRuntimeError> {
        if !self.path_health.contains_key(&path_id) {
            return Ok(self.multipath.state() == pathchord_core::SessionState::Closed);
        }
        let health = self.path_health.remove(&path_id).expect("live Path");
        let (reason, write_elapsed_ms) =
            health.terminal_write.unwrap_or((reason, write_elapsed_ms));
        let outcome = if drained {
            self.multipath.mark_path_closed(path_id)?
        } else {
            self.multipath.mark_path_failed(path_id)?
        };
        self.record_path_termination(path_id, &health, drained, reason, write_elapsed_ms);
        if path_id == self.path_id {
            if let Some(task) = self.reader_task.take() {
                task.abort();
                let _ = task.await;
            }
            let _ =
                tokio::time::timeout(MIN_RETRANSMISSION_TIMEOUT, self.writer.io.shutdown()).await;
        }
        if let Some(path) = self.extra_paths.remove(&path_id) {
            path.writer_task.abort();
            path.reader_task.abort();
            let _ = path.writer_task.await;
            let _ = path.reader_task.await;
        }
        self.attached_paths.send_modify(|paths| {
            paths.remove(&path_id);
        });
        self.retired_path_states.insert(
            path_id,
            if drained {
                pathchord_core::PathState::Closed
            } else {
                pathchord_core::PathState::Failed
            },
        );
        self.retired_path_order.push_back(path_id);
        while self.retired_path_order.len() > 128 {
            if let Some(oldest) = self.retired_path_order.pop_front() {
                self.retired_path_states.remove(&oldest);
            }
        }
        if !outcome.session_closed {
            self.cancel_unroutable_flows().await?;
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
                if let Err(error) = self
                    .send_raw_message_on_priority(
                        plan.path_id,
                        Message::StreamData(plan.data.clone()),
                        WirePriority::Retransmission,
                    )
                    .await
                {
                    if !matches!(&error, SessionRuntimeError::WireBudgetExhausted) {
                        if let Some(failed_path_id) = error.failed_path()
                            && failed_path_id != path_id
                            && self.path_health.contains_key(&failed_path_id)
                        {
                            if Box::pin(self.retire_write_failure(failed_path_id, &error)).await? {
                                return Ok(true);
                            }
                            continue;
                        }
                        return Err(error);
                    }
                    if let Some(stream) = self.streams.get_mut(&stream_id)
                        && let Some(retained) = stream.retained.get_mut(&offset)
                    {
                        // This was a local budget refusal, not a wire
                        // attempt. Retry when capacity returns.
                        retained.last_sent_at = Instant::now();
                    }
                    continue;
                }
                self.record_emitted_range(stream_id, offset, plan.data.data.len())?;
                if let Some(stream) = self.streams.get_mut(&stream_id)
                    && let Some(retained) = stream.retained.get_mut(&offset)
                {
                    retained.last_path = plan.path_id;
                    retained.last_sent_at = Instant::now();
                    retained.attempts = plan.attempt;
                    if let Some(snapshot) = self.stream_observations.get_mut(&stream_id) {
                        snapshot.retransmissions = snapshot.retransmissions.saturating_add(1);
                    }
                }
                self.send_additional_replica(stream_id, offset, plan.path_id, eligible.as_ref())
                    .await?;
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
        self.forget_unreferenced_terminal_paths()?;
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
            let plan = self
                .multipath
                .retransmit_range(
                    stream_id,
                    offset,
                    excluded,
                    self.outbound_direction(),
                    eligible.as_ref(),
                )
                .or_else(|error| {
                    if error != MultipathError::NoSchedulablePath || excluded.is_none() {
                        return Err(error);
                    }
                    self.multipath.retransmit_range(
                        stream_id,
                        offset,
                        None,
                        self.outbound_direction(),
                        eligible.as_ref(),
                    )
                })?;
            if let Some(diagnostics) = &self.diagnostics {
                diagnostics.history.log(DiagnosticLevel::Trace, "stream_retransmission", || serde_json::json!({
                    "session_id":self.session_id.to_string(),"stream_id":stream_id.to_string(),
                    "previous_path_id":last_path.to_string(),"path_id":plan.path_id.to_string(),
                    "offset":offset,"attempt":plan.attempt,"bytes":plan.data.data.len(),
                }));
            }
            if let Err(error) = self
                .send_raw_message_on_priority(
                    plan.path_id,
                    Message::StreamData(plan.data.clone()),
                    WirePriority::Retransmission,
                )
                .await
            {
                if matches!(&error, SessionRuntimeError::WireBudgetExhausted) {
                    if let Some(stream) = self.streams.get_mut(&stream_id)
                        && let Some(retained) = stream.retained.get_mut(&offset)
                    {
                        retained.last_sent_at = now;
                    }
                    continue;
                }
                if let Some(failed_path_id) = error.failed_path() {
                    if self.retire_write_failure(failed_path_id, &error).await? {
                        return Err(error);
                    }
                    continue;
                }
                return Err(error);
            }
            self.record_emitted_range(stream_id, offset, plan.data.data.len())?;
            if let Some(stream) = self.streams.get_mut(&stream_id)
                && let Some(retained) = stream.retained.get_mut(&offset)
            {
                retained.last_path = plan.path_id;
                retained.last_sent_at = now;
                retained.attempts = plan.attempt;
                if let Some(snapshot) = self.stream_observations.get_mut(&stream_id) {
                    snapshot.retransmissions = snapshot.retransmissions.saturating_add(1);
                }
            }
            self.send_additional_replica(stream_id, offset, plan.path_id, eligible.as_ref())
                .await?;
        }
        self.forget_unreferenced_terminal_paths()?;
        Ok(())
    }

    /// Retain terminal Path metadata only while an unacknowledged range still
    /// needs its retransmission timeout. This keeps recovery bounded even if
    /// the range is later acknowledged or its Stream is reset.
    fn forget_unreferenced_terminal_paths(&mut self) -> Result<(), SessionRuntimeError> {
        let referenced: BTreeSet<_> = self
            .streams
            .values()
            .flat_map(|stream| stream.retained.values().map(|range| range.last_path))
            .collect();
        let terminal: Vec<_> = self
            .multipath
            .path_states()
            .into_iter()
            .filter_map(|(path_id, state)| {
                (matches!(
                    state,
                    pathchord_core::PathState::Failed | pathchord_core::PathState::Closed
                ) && !referenced.contains(&path_id))
                .then_some(path_id)
            })
            .collect();
        for path_id in terminal {
            self.multipath.forget_terminal_path(path_id)?;
        }
        Ok(())
    }

    async fn send_additional_replica(
        &mut self,
        stream_id: StreamId,
        offset: u64,
        primary_path: PathId,
        eligible: Option<&BTreeMap<PathId, u32>>,
    ) -> Result<(), SessionRuntimeError> {
        if !self.multipath.retransmission_replication_enabled() {
            return Ok(());
        }
        let direction = self.outbound_direction();
        let plan = match self.multipath.replicate_range(
            stream_id,
            offset,
            Some(primary_path),
            direction,
            eligible,
        ) {
            Ok(plan) => plan,
            Err(MultipathError::ReplicationBudgetExhausted | MultipathError::NoSchedulablePath) => {
                return Ok(());
            }
            Err(error) => return Err(error.into()),
        };
        // The ordinary retransmission was already sent. Failure of this optional
        // copy must not turn the Stream or Session into a failure.
        let _ = self
            .send_raw_message_on_priority(
                plan.path_id,
                Message::StreamData(plan.data),
                WirePriority::OptionalReplication,
            )
            .await;
        Ok(())
    }

    async fn handle_udp_message(
        &mut self,
        path_id: PathId,
        message: Message,
    ) -> Result<(), SessionRuntimeError> {
        if matches!(self.role, ActorRole::Egress { .. }) {
            if let Message::UdpOpen(open) = &message {
                if self.capabilities & CAPABILITY_UDP_SESSION == 0 {
                    self.udp_classes.remove(&open.association_id);
                    return self
                        .send_udp_message(
                            open.association_id,
                            Message::UdpOpenErr(UdpOpenErr {
                                association_id: open.association_id,
                                error: ErrorClass::EgressFailure,
                                reason: b"UDP capability was not negotiated".to_vec(),
                            }),
                        )
                        .await;
                }
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
                if let Message::UdpOpenErr(error) = &response {
                    self.udp_classes.remove(&error.association_id);
                }
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
                            demand_key: pending.demand_key,
                            replication_budget: pending.replication_budget,
                        },
                    );
                    if let Some(profile) = pending.traffic_class {
                        self.udp_classes.insert(response.association_id, profile);
                    }
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
                self.pending_udp.remove(&close.association_id);
                if let Some(waiters) = self.closing_udp.remove(&close.association_id) {
                    for waiter in waiters {
                        let _ = waiter.send(Ok(()));
                    }
                }
                self.udp_classes.remove(&close.association_id);
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
        if let Some(runtime) = self.udp_runtime.as_mut() {
            self.retired_udp_associations
                .extend(runtime.reap_draining());
        }
        Ok(())
    }

    fn retire_drained_udp(&mut self) {
        self.retired_udp_associations.retain(|id| {
            if self
                .pending_udp
                .get(id)
                .is_some_and(|queue| !queue.is_empty())
            {
                return true;
            }
            self.pending_udp.remove(id);
            self.egress_udp_paths.remove(id);
            self.unrestricted_udp_paths.remove(id);
            self.udp_classes.remove(id);
            self.udp_send_sequences.remove(id);
            false
        });
    }

    async fn finish_pending_udp_closes(&mut self) -> Result<(), SessionRuntimeError> {
        let ready: Vec<_> = self
            .closing_udp
            .keys()
            .copied()
            .filter(|id| self.pending_udp.get(id).is_none_or(VecDeque::is_empty))
            .collect();
        for id in ready {
            self.send_udp_message(
                id,
                Message::UdpClose(UdpClose {
                    association_id: id,
                    error: ErrorClass::PathFailure,
                    reason: b"UDP Association closed locally".to_vec(),
                }),
            )
            .await?;
            self.ingress_udp.remove(&id);
            self.pending_udp.remove(&id);
            self.udp_classes.remove(&id);
            self.udp_send_sequences.remove(&id);
            if let Some(waiters) = self.closing_udp.remove(&id) {
                for waiter in waiters {
                    let _ = waiter.send(Ok(()));
                }
            }
        }
        Ok(())
    }

    async fn handle_path_health(&mut self) -> Result<bool, SessionRuntimeError> {
        let now = Instant::now();
        self.rotate_demand(now);
        let ingress = matches!(self.role, ActorRole::Ingress);
        let egress = !ingress;
        let mut outgoing = Vec::new();
        let mut degraded = Vec::new();
        let mut active = Vec::new();
        let mut failed = Vec::new();
        let mut expired_drains = Vec::new();
        let mut status_paths = Vec::new();

        for (path_id, health) in &mut self.path_health {
            if health
                .drain_deadline
                .is_some_and(|deadline| now >= deadline)
            {
                expired_drains.push(*path_id);
                continue;
            }
            let heartbeat_age = now.duration_since(health.last_heartbeat_received);
            let status_age = now.duration_since(health.last_status_received);
            if heartbeat_age >= PATH_FAILED_AFTER {
                failed.push((*path_id, PathTerminationReason::HeartbeatTimeout, None));
                continue;
            }
            if heartbeat_age >= PATH_DEGRADED_AFTER
                || (ingress && status_age >= PATH_DEGRADED_AFTER)
            {
                degraded.push(*path_id);
            } else {
                active.push(*path_id);
            }

            // Retransmitting an outstanding probe already provides liveness
            // traffic. Avoid creating additional probes while its ACK is late.
            if now.duration_since(health.last_heartbeat_sent) >= HEARTBEAT_INTERVAL
                && health.sender.pending_len() < MAX_PENDING_CONTROL_MESSAGES
                && !health
                    .sender
                    .pending()
                    .any(|(_, probe)| probe.attempts < MAX_RETRANSMISSION_ATTEMPTS)
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
            if self.multipath.is_draining(path_id) {
                continue;
            }
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
            if self.multipath.is_draining(path_id) {
                continue;
            }
            self.multipath.activate_path(path_id)?;
            if self.multipath.path_is_schedulable(path_id)
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
            health.upstream_throughput_bps = health
                .upstream_bytes_since_observation
                .saturating_mul(8)
                .saturating_mul(1_000)
                / elapsed_ms;
            health.downstream_throughput_bps = health
                .downstream_bytes_since_observation
                .saturating_mul(8)
                .saturating_mul(1_000)
                / elapsed_ms;
            health.upstream_bytes_since_observation = 0;
            health.downstream_bytes_since_observation = 0;
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
                    effective_capacity_bps: health.effective_capacity_bps,
                    upstream_effective_capacity_bps: health
                        .upstream_effective_capacity_bps
                        .or_else(|| {
                            (health.upstream_throughput_bps > 0)
                                .then_some(health.upstream_throughput_bps)
                        }),
                    downstream_effective_capacity_bps: health
                        .downstream_effective_capacity_bps
                        .or_else(|| {
                            (health.downstream_throughput_bps > 0)
                                .then_some(health.downstream_throughput_bps)
                        }),
                    weight_basis_points: health.relationship_weight_basis_points,
                    rtt_ms: health.rtt_ms.max(1),
                    jitter_ms: health.jitter_ms,
                    loss_basis_points: (loss_ppm / 100).min(10_000) as u16,
                    reordering_basis_points: (health.data_events > 0).then(|| {
                        (health.reordering_events.saturating_mul(10_000) / health.data_events)
                            .min(10_000) as u16
                    }),
                    congestion_window_bytes: health.congestion_window_bytes,
                    incremental_capacity_bps: health.incremental_capacity_bps,
                    scheduling_overhead_bps: health.scheduling_overhead_bps,
                },
            )?;
        }
        if !status_paths.is_empty() {
            // Status describes the whole Egress at this instant, across all Paths.
            let sample = self.status_provider.sample();
            let adjusted_capacity = sample
                .effective_capacity_bps
                .saturating_mul(u64::from(sample.traffic_multiplier_basis_points))
                / 10_000;
            let quota_adjusted_capacity = if sample.quota_remaining == Some(0) {
                adjusted_capacity.saturating_mul(1_000) / 10_000
            } else {
                adjusted_capacity
            };
            for path_id in status_paths {
                let report_seqno = self.next_status_report_seq;
                self.next_status_report_seq = self
                    .next_status_report_seq
                    .checked_add(1)
                    .ok_or(SessionRuntimeError::FrameSequenceExhausted)?;
                outgoing.push((
                    path_id,
                    Message::StatusReport(StatusReport {
                        connected: sample.connected,
                        service_state: sample.service_state,
                        admission_allowed: sample.admission_allowed,
                        admission_reason: sample.admission_reason,
                        load_basis_points: sample.load_basis_points,
                        connection_utilization_basis_points: sample
                            .connection_utilization_basis_points,
                        bandwidth_utilization_basis_points: sample
                            .bandwidth_utilization_basis_points,
                        active_sessions: sample.active_sessions,
                        active_streams: sample.active_streams,
                        active_target_connections: sample.active_target_connections,
                        configured_capacity_bps: sample.configured_capacity_bps,
                        effective_capacity_bps: if matches!(
                            sample.capacity_state,
                            CapacityState::Unknown | CapacityState::Stale
                        ) {
                            0
                        } else {
                            quota_adjusted_capacity
                        },
                        current_wire_rate_bps: sample.current_wire_rate_bps,
                        replication_allowance_bps: sample.replication_allowance_bps,
                        capacity_state: sample.capacity_state,
                        report_seqno,
                        sample_age_ms: 0,
                        expires_after_ms: PATH_FAILED_AFTER.as_millis() as u64,
                    }),
                ));
            }
        }
        for (path_id, message) in outgoing {
            if let Err(error) = self.send_message_on(path_id, message).await {
                failed.push((
                    path_id,
                    error.write_termination_reason(),
                    error.write_elapsed_ms(),
                ));
            }
        }
        failed.sort_by_key(|(path_id, _, _)| *path_id);
        failed.dedup_by_key(|(path_id, _, _)| *path_id);
        for path_id in expired_drains {
            if self
                .retire_path(path_id, true, PathTerminationReason::Drained, None)
                .await?
            {
                return Ok(true);
            }
        }
        for (path_id, reason, write_elapsed_ms) in failed {
            if self
                .retire_path(path_id, false, reason, write_elapsed_ms)
                .await?
            {
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

    fn trace_frame(
        &self,
        path_id: PathId,
        direction: &'static str,
        message: &Message,
        size: usize,
        seq: Option<u64>,
        priority: Option<WirePriority>,
    ) {
        if let Some(diagnostics) = &self.diagnostics {
            diagnostics.history.log(DiagnosticLevel::Trace, "frame", || {
                let detail = match message {
                    Message::StreamData(v) => serde_json::json!({"stream_id":v.stream_id.to_string(),"offset":v.offset,"bytes":v.data.len(),"flags":v.flags}),
                    Message::StreamWindow(v) => serde_json::json!({"stream_id":v.stream_id.to_string(),"stream_limit":v.stream_limit,"session_limit":v.session_limit}),
                    Message::StreamAck(v) => serde_json::json!({"stream_id":v.stream_id.to_string(),"ranges":v.ranges.iter().map(|r| [r.start,r.end]).collect::<Vec<_>>()}),
                    Message::SessionControl(v) => {
                        let flow = session_control_flow(v, self.limits).ok().flatten();
                        let (stream_id, association_id) = match flow {
                            Some(SessionControlFlow::Stream(id)) => (Some(id.to_string()), None),
                            Some(SessionControlFlow::Udp(id)) => (None, Some(id)),
                            None => (None, None),
                        };
                        serde_json::json!({"sequence":v.sequence,"depends_on":v.depends_on,
                            "inner_frame_type":v.frame_type as u64,"stream_id":stream_id,"association_id":association_id})
                    }
                    Message::SessionControlAck(v) | Message::ControlAck(v) => serde_json::json!({"highest_contiguous":v.highest_contiguous,"ranges":v.ranges.iter().map(|r| [r.start,r.end]).collect::<Vec<_>>()}),
                    Message::StreamOpen(v) => serde_json::json!({"stream_id":v.stream_id.to_string(),"request_id":v.request_id.to_string(),"target_port":v.target.port}),
                    Message::StreamOpenOk(v) => serde_json::json!({"stream_id":v.stream_id.to_string()}),
                    Message::StreamOpenErr(v) => serde_json::json!({"stream_id":v.stream_id.to_string(),"error_class":v.error.code()}),
                    Message::StreamFin(v) => serde_json::json!({"stream_id":v.stream_id.to_string(),"flags":v.flags}),
                    Message::StreamRst(v) => serde_json::json!({"stream_id":v.stream_id.to_string(),"error_class":v.error.code()}),
                    Message::StatusReport(v) => serde_json::json!({"report_sequence":v.report_seqno,"age_ms":v.sample_age_ms,
                        "expires_after_ms":v.expires_after_ms,"admission_allowed":v.admission_allowed,
                        "admission_reason":format!("{:?}",v.admission_reason),"wire_bps":v.current_wire_rate_bps,
                        "capacity_bps":v.effective_capacity_bps,"active_streams":v.active_streams}),
                    Message::PathDrain(v) => serde_json::json!({"drain_reason":v.drain_reason,"deadline_ms":v.deadline_ms}),
                    Message::PathClose(v) => serde_json::json!({"error_class":v.error.code()}),
                    Message::SessionClose(v) => serde_json::json!({"error_class":v.error.code()}),
                    Message::UdpOpen(v) => serde_json::json!({"association_id":v.association_id,"target_port":v.target.port}),
                    Message::UdpOpenOk(v) => serde_json::json!({"association_id":v.association_id,"target_port":v.target_visible_port}),
                    Message::UdpOpenErr(v) => serde_json::json!({"association_id":v.association_id,"error_class":v.error.code()}),
                    Message::UdpClose(v) => serde_json::json!({"association_id":v.association_id,"error_class":v.error.code()}),
                    Message::Heartbeat(v) => serde_json::json!({"control_sequence":v.control_seq}),
                    Message::UdpDatagram(v) => serde_json::json!({"association_id":v.association_id,"datagram_sequence":v.datagram_seq,"bytes":v.payload.len()}),
                    _ => serde_json::Value::Null,
                };
                let attribution = if path_id == self.path_id { diagnostics.attribution.as_ref() } else { self.path_health.get(&path_id).and_then(|health| health.attribution.as_ref()) };
                serde_json::json!({"session_id":self.session_id.to_string(),"path_id":path_id.to_string(),
                    "egress_id":diagnostics.egress_id,"transit":attribution.map(PathAttribution::fields),
                    "direction":direction,"frame_type":message.frame_type() as u64,
                    "frame_sequence":seq,"priority":priority.map(|p| format!("{p:?}")),"payload_bytes":size,"detail":detail})
            });
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
        self.trace_frame(
            path_id,
            "receive",
            &message,
            frame.payload().len(),
            Some(frame.header().frame_seq()),
            None,
        );
        match message {
            Message::SessionControl(control) => self.handle_session_control(path_id, control).await,
            Message::SessionControlCancel(cancel) => {
                self.queue_session_control(path_id, SessionControlEntry::Cancel(cancel))
                    .await
            }
            Message::SessionControlAck(ack) => {
                if ack.highest_contiguous >= self.session_control_sender.next_sequence()
                    || ack
                        .ranges
                        .iter()
                        .any(|range| range.end >= self.session_control_sender.next_sequence())
                {
                    return Err(SessionRuntimeError::InvalidRuntimeLimit);
                }
                self.session_control_sender
                    .acknowledge(ack.highest_contiguous, &ack.ranges);
                Ok(self.local_close_sequence.is_some_and(|sequence| {
                    !self
                        .session_control_sender
                        .pending()
                        .any(|(pending, _)| pending == sequence)
                }))
            }
            other if other.frame_type().is_session_control() => {
                Err(SessionRuntimeError::UnexpectedFrame(other.frame_type()))
            }
            other => self.handle_message(path_id, other).await,
        }
    }

    async fn handle_session_control(
        &mut self,
        path_id: PathId,
        control: SessionControl,
    ) -> Result<bool, SessionRuntimeError> {
        let flow_open = matches!(
            control.frame_type,
            FrameType::StreamOpen | FrameType::UdpOpen
        );
        if !control.eligible_paths.is_empty() && !flow_open {
            return Err(SessionRuntimeError::InvalidRuntimeLimit);
        }
        self.queue_session_control(path_id, SessionControlEntry::Control(control))
            .await
    }

    async fn queue_session_control(
        &mut self,
        path_id: PathId,
        entry: SessionControlEntry,
    ) -> Result<bool, SessionRuntimeError> {
        let sequence = entry.sequence();
        if sequence < self.next_session_control {
            match entry {
                SessionControlEntry::Control(control) => {
                    let flow_open = matches!(
                        control.frame_type,
                        FrameType::StreamOpen | FrameType::UdpOpen
                    );
                    if matches!(self.role, ActorRole::Egress { .. })
                        && flow_open
                        && !control.eligible_paths.is_empty()
                    {
                        let inner =
                            Message::decode(control.frame_type, &control.payload, self.limits)?;
                        self.reject_retired_open(path_id, inner).await?;
                    } else {
                        self.note_duplicate_open_path(path_id, &control)?;
                    }
                }
                SessionControlEntry::Cancel(cancel) => self.cancel_flow_local(cancel.flow).await?,
            }
            self.ack_session_controls(path_id).await?;
            return Ok(false);
        }
        if self.remote_closing {
            return Err(SessionRuntimeError::UnexpectedFrame(
                FrameType::SessionControl,
            ));
        }
        if sequence.saturating_sub(self.next_session_control) >= MAX_SESSION_CONTROL_MESSAGES as u64
        {
            return Err(SessionRuntimeError::InvalidRuntimeLimit);
        }
        if let Some((paths, prior)) = self.queued_session_controls.get_mut(&sequence) {
            match (&*prior, &entry) {
                (SessionControlEntry::Control(a), SessionControlEntry::Control(b)) if a == b => {}
                (SessionControlEntry::Cancel(a), SessionControlEntry::Cancel(b)) if a == b => {}
                (SessionControlEntry::Control(a), SessionControlEntry::Cancel(b))
                    if session_control_flow(a, self.limits)? == Some(b.flow) =>
                {
                    *prior = entry
                }
                (SessionControlEntry::Cancel(a), SessionControlEntry::Control(b))
                    if session_control_flow(b, self.limits)? == Some(a.flow) => {}
                _ => return Err(SessionRuntimeError::InvalidRuntimeLimit),
            }
            paths.insert(path_id);
        } else {
            self.queued_session_controls
                .insert(sequence, (BTreeSet::from([path_id]), entry));
        }
        while let Some((paths, entry)) = self
            .queued_session_controls
            .remove(&self.next_session_control)
        {
            let path = *paths.first().expect("a received control has a Path");
            let close = match entry {
                SessionControlEntry::Cancel(cancel) => {
                    self.cancel_flow_local(cancel.flow).await?;
                    false
                }
                SessionControlEntry::Control(control) => {
                    let inner = Message::decode(control.frame_type, &control.payload, self.limits)?;
                    self.trace_frame(
                        path,
                        "apply_control",
                        &inner,
                        control.payload.len(),
                        None,
                        None,
                    );
                    let flow_open = matches!(
                        control.frame_type,
                        FrameType::StreamOpen | FrameType::UdpOpen
                    );
                    let close = if matches!(self.role, ActorRole::Egress { .. })
                        && flow_open
                        && !control.eligible_paths.is_empty()
                    {
                        self.reject_retired_open(path, inner).await?;
                        false
                    } else {
                        let result = self.handle_message(path, inner).await;
                        self.active_control_eligible = None;
                        let close = result?;
                        self.configure_open_paths(&control)?;
                        close
                    };
                    for duplicate_path in paths.into_iter().skip(1) {
                        self.note_duplicate_open_path(duplicate_path, &control)?;
                    }
                    close
                }
            };
            self.next_session_control = self
                .next_session_control
                .checked_add(1)
                .ok_or(SessionRuntimeError::FrameSequenceExhausted)?;
            if close {
                self.remote_closing = true;
                break;
            }
        }
        self.ack_session_controls(path_id).await?;
        Ok(false)
    }

    async fn reject_retired_open(
        &mut self,
        _received_path_id: PathId,
        message: Message,
    ) -> Result<(), SessionRuntimeError> {
        match message {
            Message::StreamOpen(request) => {
                self.send_open_error(
                    request.stream_id,
                    ErrorClass::LocalPolicy,
                    b"per-flow eligible Path lists are retired; use the Session Path pool".to_vec(),
                )
                .await
            }
            Message::UdpOpen(request) => {
                self.send_udp_message(
                    request.association_id,
                    Message::UdpOpenErr(UdpOpenErr {
                        association_id: request.association_id,
                        error: ErrorClass::LocalPolicy,
                        reason:
                            b"per-flow eligible Path lists are retired; use the Session Path pool"
                                .to_vec(),
                    }),
                )
                .await
            }
            _ => Err(SessionRuntimeError::InvalidRuntimeLimit),
        }
    }

    fn configure_open_paths(
        &mut self,
        control: &SessionControl,
    ) -> Result<(), SessionRuntimeError> {
        if !matches!(self.role, ActorRole::Egress { .. }) {
            return Ok(());
        }
        let message = Message::decode(control.frame_type, &control.payload, self.limits)?;
        let unrestricted = control.eligible_paths.is_empty();
        let paths = if unrestricted {
            self.multipath.ready_path_ids()
        } else {
            control.eligible_paths.clone()
        };
        match message {
            Message::StreamOpen(open) => {
                if let Some(cached) = self.egress_requests.get_mut(&open.request_id) {
                    cached.unrestricted_paths = unrestricted;
                }
            }
            Message::UdpOpen(open) => {
                if unrestricted {
                    self.unrestricted_udp_paths.insert(open.association_id);
                }
            }
            _ => return Ok(()),
        }
        for path in paths {
            self.note_duplicate_open_path(path, control)?;
        }
        Ok(())
    }

    fn note_duplicate_open_path(
        &mut self,
        path_id: PathId,
        control: &SessionControl,
    ) -> Result<(), SessionRuntimeError> {
        let message = Message::decode(control.frame_type, &control.payload, self.limits)?;
        let request = match &message {
            Message::StreamOpen(open) => Some((open, None)),
            _ => None,
        };
        if let Some((open, class)) = request
            && let Some(cached) = self.egress_requests.get_mut(&open.request_id)
            && cached.request == *open
            && cached.traffic_class.as_ref() == class
        {
            cached.eligible_paths.entry(path_id).or_insert(100);
            if let Some(stream) = self.streams.get_mut(&open.stream_id)
                && let Some(eligible) = stream.eligible_paths.as_mut()
            {
                eligible.entry(path_id).or_insert(100);
            }
        }
        let association_id = match message {
            Message::UdpOpen(open) => Some(open.association_id),
            _ => None,
        };
        if let Some(id) = association_id
            && let Some(paths) = self.egress_udp_paths.get_mut(&id)
        {
            paths.entry(path_id).or_insert(100);
        }
        Ok(())
    }

    async fn ack_session_controls(&mut self, path_id: PathId) -> Result<(), SessionRuntimeError> {
        if let Some(highest_contiguous) = self.next_session_control.checked_sub(1) {
            // A Path may fail after delivering the control record. A failed
            // ACK must not kill the Session: the sender will retry on an
            // eligible surviving Path and receive an ACK there.
            let _ = self
                .send_raw_message_on(
                    path_id,
                    Message::SessionControlAck(ControlAck {
                        highest_contiguous,
                        ranges: Vec::new(),
                    }),
                )
                .await;
        }
        Ok(())
    }

    async fn handle_message(
        &mut self,
        path_id: PathId,
        message: Message,
    ) -> Result<bool, SessionRuntimeError> {
        match message {
            Message::StreamOpen(request) => self.handle_egress_open(path_id, request, None).await?,
            Message::StreamOpenOk(response) => self.handle_ingress_open_ok(response).await?,
            Message::StreamOpenErr(response) => self.handle_ingress_open_err(response),
            Message::StreamData(data) => self.handle_stream_data(path_id, data).await?,
            Message::StreamAck(ack) => self.handle_stream_ack(ack).await?,
            Message::StreamWindow(window) => self.handle_stream_window(window).await?,
            Message::StreamFin(fin) => self.handle_stream_fin(fin, None).await?,
            Message::StreamRst(rst) => self.handle_stream_rst(rst).await,
            Message::PathDrain(drain) => {
                self.multipath.drain_path(path_id)?;
                if let Some(health) = self.path_health.get_mut(&path_id) {
                    health.exclusion_reason = Some(PathExclusionReason::Draining);
                    if drain.deadline_ms != 0 {
                        let deadline = Instant::now()
                            .checked_add(Duration::from_millis(drain.deadline_ms))
                            .ok_or(SessionRuntimeError::InvalidRuntimeLimit)?;
                        health.drain_deadline = Some(
                            health
                                .drain_deadline
                                .map_or(deadline, |current| current.min(deadline)),
                        );
                    }
                }
            }
            Message::PathClose(_) => return self.handle_path_failure(path_id).await,
            Message::SessionClose(_) => return Ok(true),
            Message::StatusReport(report) => {
                let capacity_bps = if report.effective_capacity_bps > 0 {
                    report.effective_capacity_bps
                } else {
                    report.configured_capacity_bps
                };
                let disposition = self
                    .multipath
                    .apply_status_report(path_id, report.clone())?;
                if disposition == StatusReportDisposition::Accepted
                    && (!report.connected || report.service_state == EgressServiceState::Down)
                {
                    return Err(SessionRuntimeError::EgressHardFailure);
                }
                if disposition == StatusReportDisposition::Accepted
                    && let Some(health) = self.path_health.get_mut(&path_id)
                {
                    health.last_status_received = Instant::now();
                    self.egress_aggregate_capacity_bps = capacity_bps;
                    if self
                        .latest_egress_status
                        .as_ref()
                        .is_none_or(|(previous, _)| report.report_seqno > previous.report_seqno)
                    {
                        self.latest_egress_status = Some((report, Instant::now()));
                    }
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
        traffic_class: Option<TrafficClassConfig>,
    ) -> Result<(), SessionRuntimeError> {
        let factory = match &self.role {
            ActorRole::Egress { factory } => Arc::clone(factory),
            ActorRole::Ingress => {
                return Err(SessionRuntimeError::UnexpectedFrame(FrameType::StreamOpen));
            }
        };
        if self.capabilities & CAPABILITY_TCP_STREAM == 0 {
            return self
                .send_open_error(
                    request.stream_id,
                    ErrorClass::EgressFailure,
                    b"TCP capability was not negotiated".to_vec(),
                )
                .await;
        }
        if let Some(cached) = self.egress_requests.get_mut(&request.request_id) {
            if cached.request != request || cached.traffic_class != traffic_class {
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
                    self.send_stream_message(
                        request.stream_id,
                        Message::StreamOpenOk(StreamOpenOk {
                            stream_id: request.stream_id,
                            result_metadata: metadata,
                        }),
                    )
                    .await?;
                    return Ok(());
                }
                CachedOpenResult::Rejected { error, reason } => {
                    return self.send_open_error(request.stream_id, error, reason).await;
                }
            }
        }
        if self.egress_streams.contains_key(&request.stream_id) {
            return self
                .send_open_error(
                    request.stream_id,
                    ErrorClass::EgressFailure,
                    b"StreamID or Session capacity is unavailable".to_vec(),
                )
                .await;
        }
        if !self.reserve_egress_request_slot() {
            return self
                .send_open_error(
                    request.stream_id,
                    ErrorClass::ResourceLimit,
                    b"Egress open request cache is full".to_vec(),
                )
                .await;
        }
        let target_permit = match &self.target_open_slots {
            Some(slots) => match Arc::clone(slots).try_acquire_owned() {
                Ok(permit) => Some(permit),
                Err(_) => {
                    return self
                        .send_open_error(
                            request.stream_id,
                            ErrorClass::ResourceLimit,
                            b"global inbound target-connection limit reached".to_vec(),
                        )
                        .await;
                }
            },
            None => None,
        };
        self.observe_open(
            request.stream_id,
            request.target.clone(),
            traffic_class.clone(),
        );
        self.egress_streams
            .insert(request.stream_id, request.request_id);
        self.egress_requests.insert(
            request.request_id,
            CachedEgressOpen {
                traffic_class,
                request: request.clone(),
                result: CachedOpenResult::Pending,
                eligible_paths: BTreeMap::from([(received_path_id, 100)]),
                unrestricted_paths: true,
            },
        );
        let result_tx = self.factory_result_tx.clone();
        let stream_id = request.stream_id;
        let request_id = request.request_id;
        let target = request.target;
        let task = tokio::spawn(async move {
            let started = Instant::now();
            let result = factory.open_with_permit(target, target_permit).await;
            let _ = result_tx
                .send(FactoryCompletion {
                    stream_id,
                    request_id,
                    elapsed_ms: started.elapsed().as_millis() as u64,
                    result,
                })
                .await;
        });
        self.opening_tasks.insert(stream_id, task);
        Ok(())
    }

    /// Keep idempotency state bounded without evicting an open operation whose
    /// result has not been published yet. Completed requests are no longer
    /// needed once their Stream closes and are safe eviction candidates.
    fn reserve_egress_request_slot(&mut self) -> bool {
        while self.egress_requests.len() >= MAX_EGRESS_REQUEST_CACHE {
            let Some(request_id) = self
                .egress_requests
                .iter()
                .find_map(|(request_id, cached)| {
                    (!matches!(cached.result, CachedOpenResult::Pending)).then_some(*request_id)
                })
            else {
                return false;
            };
            self.egress_requests.remove(&request_id);
            self.egress_streams
                .retain(|_, cached| *cached != request_id);
        }
        true
    }

    fn remove_egress_request_for_stream(&mut self, stream_id: StreamId) {
        if let Some(request_id) = self.egress_streams.remove(&stream_id) {
            self.egress_requests.remove(&request_id);
        }
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
        let eligible_paths = (!cached.unrestricted_paths).then(|| cached.eligible_paths.clone());
        let traffic_class = cached.traffic_class.clone();
        if let Some(diagnostics) = &self.diagnostics {
            diagnostics.history.log(if completion.result.is_ok() { DiagnosticLevel::Debug } else { DiagnosticLevel::Warn }, "target_connect", || serde_json::json!({
                "session_id":self.session_id.to_string(),"stream_id":completion.stream_id.to_string(),
                "request_id":completion.request_id.to_string(),"elapsed_ms":completion.elapsed_ms,
                "outcome":if completion.result.is_ok() {"success"} else {"error"},
                "error_class":completion.result.as_ref().err().map(|error| error.error.code()),
            }));
        }
        match completion.result {
            Ok(io) => {
                let replication_budget = FlowReplicationBudget {
                    stream_bytes: self.multipath.session_replication_budget_bytes(),
                    class_bytes: self.multipath.session_replication_budget_bytes(),
                };
                self.spawn_active_stream(
                    completion.stream_id,
                    io,
                    eligible_paths,
                    traffic_class,
                    replication_budget,
                )?;
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
                self.observe_closed(completion.stream_id, "target_rejected", StreamState::Reset);
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
        let demand_key = pending.demand_key.clone();
        let replication_budget = pending.replication_budget;
        self.spawn_active_stream(
            response.stream_id,
            pending.io,
            pending.eligible_paths,
            pending.traffic_class,
            replication_budget,
        )?;
        if let Some(stream) = self.streams.get_mut(&response.stream_id) {
            stream.demand_key = demand_key;
        }
        if let Err(error) = self.send_window(response.stream_id).await {
            let _ = pending.reply.send(Err(OpenStreamError::SessionClosed));
            return Err(error);
        }
        let _ = pending.reply.send(Ok(()));
        Ok(())
    }

    fn handle_ingress_open_err(&mut self, response: StreamOpenErr) {
        self.observe_closed(response.stream_id, "open_rejected", StreamState::Reset);
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
        traffic_class: Option<TrafficClassConfig>,
        replication_budget: FlowReplicationBudget,
    ) -> Result<(), SessionRuntimeError> {
        if let Some(snapshot) = self.stream_observations.get_mut(&stream_id) {
            snapshot.state = StreamState::Open;
        }
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
                traffic_class,
                demand_key: None,
                replication_budget,
                fin_sent: false,
                io_finished: false,
                commands,
                task,
                receive,
                inbound_permits: Vec::new(),
                next_send_offset: 0,
                emitted: Vec::new(),
                acknowledged: Vec::new(),
                pending: VecDeque::new(),
                retained: BTreeMap::new(),
                remote_receive_limit: self.buffer_limit as u64,
                local_receive_limit: self.buffer_limit as u64,
                local_fin: false,
                remote_fin: false,
                remote_fin_offset: None,
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
            } => {
                if let Some(diagnostics) = &self.diagnostics {
                    diagnostics
                        .history
                        .log(DiagnosticLevel::Trace, "stream_local_read", || {
                            serde_json::json!({
                                "session_id": self.session_id.to_string(),
                                "stream_id": stream_id.to_string(),
                                "bytes": data.len(),
                                "send_buffer_credit_bytes": self.send_budget.available_permits(),
                            })
                        });
                }
                self.queue_stream_data(stream_id, data, permit).await?;
            }
            StreamEvent::LocalFin { stream_id } => {
                if let Some(diagnostics) = &self.diagnostics {
                    diagnostics.history.log(DiagnosticLevel::Debug, "stream_local_eof", || serde_json::json!({
                        "session_id":self.session_id.to_string(),"stream_id":stream_id.to_string(),
                    }));
                }
                let should_send = self.streams.get_mut(&stream_id).is_some_and(|stream| {
                    if stream.local_fin {
                        false
                    } else {
                        stream.local_fin = true;
                        true
                    }
                });
                let _ = should_send;
            }
            StreamEvent::IoFailed {
                stream_id,
                operation,
                kind,
                reason,
            } => {
                if let Some(diagnostics) = &self.diagnostics {
                    diagnostics.history.log(DiagnosticLevel::Warn, "stream_local_io_error", || serde_json::json!({
                        "session_id":self.session_id.to_string(),"stream_id":stream_id.to_string(),
                        "operation":operation,"io_kind":format!("{kind:?}"),
                    }));
                }
                let error = match self.role {
                    ActorRole::Egress { .. } => ErrorClass::TargetFailure,
                    ActorRole::Ingress => ErrorClass::PathFailure,
                };
                self.reset_stream_with_error(stream_id, true, error, reason.into_bytes())
                    .await?;
            }
            StreamEvent::Delivered { stream_id, bytes } => {
                if let Some(diagnostics) = &self.diagnostics {
                    diagnostics.history.log(DiagnosticLevel::Trace, "stream_local_write", || serde_json::json!({
                        "session_id":self.session_id.to_string(),"stream_id":stream_id.to_string(),"bytes":bytes,
                    }));
                }
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
                if let Some(stream) = self.streams.get_mut(&stream_id) {
                    stream.io_finished = true;
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
        let demand_key = stream.demand_key.clone();
        let demand_bytes = data.len() as u64;
        stream.next_send_offset = offset
            .checked_add(data.len() as u64)
            .filter(|end| *end <= MAX_VARINT)
            .ok_or(SessionRuntimeError::FrameSequenceExhausted)?;
        stream.pending.push_back(OutboundChunk {
            offset,
            data,
            _permit: permit,
        });
        self.record_demand(demand_key, demand_bytes);
        Ok(())
    }

    async fn flush_stream(&mut self, stream_id: StreamId) -> Result<(), SessionRuntimeError> {
        let direction = self.outbound_direction();
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
                if let Some(diagnostics) = &self.diagnostics {
                    diagnostics.history.log(DiagnosticLevel::Trace, "stream_flow_control_wait", || serde_json::json!({
                        "session_id":self.session_id.to_string(),"stream_id":stream_id.to_string(),
                        "direction":match direction { ScheduleDirection::Upstream => "upstream", ScheduleDirection::Downstream => "downstream" },
                        "pending_chunks":stream.pending.len(),"next_chunk_bytes":front.data.len(),
                        "stream_end":end,"stream_limit":stream.remote_receive_limit,
                        "session_sent":self.session_sent_total,"session_limit":self.remote_session_limit,
                        "stream_blocked":end > stream.remote_receive_limit,
                        "session_blocked":self.session_sent_total + front.data.len() as u64 > self.remote_session_limit,
                    }));
                }
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
        let selection = match eligible.as_ref() {
            Some(eligible) => self
                .multipath
                .schedule_existing_eligible(direction, length, eligible),
            None => self.multipath.schedule_existing(direction, length),
        };
        if let Some(diagnostics) = &self.diagnostics {
            diagnostics.history.log(DiagnosticLevel::Trace, "path_selection", || serde_json::json!({
                "session_id":self.session_id.to_string(),"stream_id":stream_id.to_string(),
                "offset":chunk.offset,"bytes":length,"ready_paths":self.multipath.ready_path_count(),
                "eligible_paths":eligible.as_ref().map(BTreeMap::len),
                "path_id":selection.as_ref().ok().map(|selected| selected.path_id.to_string()),
                "score":selection.as_ref().ok().map(|selected| selected.score.to_string()),
            }));
        }
        let path_id = selection?.path_id;
        let traffic_class = self
            .streams
            .get(&stream_id)
            .and_then(|stream| stream.traffic_class.as_ref())
            .map_or("default", |class| class.name.as_str())
            .to_owned();
        let replication_budget = self.streams.get(&stream_id).map_or_else(
            || FlowReplicationBudget::unlimited(self.multipath.session_replication_budget_bytes()),
            |stream| stream.replication_budget,
        );
        self.multipath.retain_stream_data_with_budget(
            data.clone(),
            traffic_class,
            path_id,
            replication_budget.stream_bytes,
            replication_budget.class_bytes,
        )?;
        let send_result = self
            .send_message_on(path_id, Message::StreamData(data))
            .await;
        if matches!(&send_result, Err(SessionRuntimeError::WireBudgetExhausted)) {
            self.multipath.forget_retained(stream_id, chunk.offset);
            if let Some(stream) = self.streams.get_mut(&stream_id) {
                stream.pending.push_front(chunk);
            }
            return Ok(());
        }
        self.session_sent_total += length as u64;
        self.bytes_sent += length as u64;
        if let Some(snapshot) = self.stream_observations.get_mut(&stream_id) {
            snapshot.bytes_sent = snapshot.bytes_sent.saturating_add(length as u64);
        }
        if let Some(stream) = self.streams.get_mut(&stream_id) {
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
        if send_result.is_ok() {
            self.record_emitted_range(stream_id, chunk.offset, length)?;
        }
        if let Err(error) = send_result
            && self.retire_write_failure(path_id, &error).await?
        {
            return Err(error);
        }
        Ok(())
    }

    fn record_emitted_range(
        &mut self,
        stream_id: StreamId,
        offset: u64,
        length: usize,
    ) -> Result<(), SessionRuntimeError> {
        if length == 0 {
            return Ok(());
        }
        let end = offset
            .checked_add(length as u64 - 1)
            .ok_or(SessionRuntimeError::InvalidRuntimeLimit)?;
        let Some(stream) = self.streams.get_mut(&stream_id) else {
            return Ok(());
        };
        stream.emitted.push(AckRange { start: offset, end });
        stream.emitted.sort_by_key(|range| range.start);
        let mut merged: Vec<AckRange> = Vec::with_capacity(stream.emitted.len());
        for range in std::mem::take(&mut stream.emitted) {
            if let Some(last) = merged.last_mut()
                && range.start <= last.end.saturating_add(1)
            {
                last.end = last.end.max(range.end);
            } else {
                merged.push(range);
            }
        }
        if merged.len() > ProtocolLimits::HARD_MAX_ACK_RANGES {
            return Err(SessionRuntimeError::InvalidRuntimeLimit);
        }
        stream.emitted = merged;
        Ok(())
    }

    fn ack_range_is_emitted(emitted: &[AckRange], target: AckRange) -> bool {
        let mut cursor = target.start;
        for range in emitted {
            if range.end < cursor {
                continue;
            }
            if range.start > cursor {
                return false;
            }
            cursor = range.end.saturating_add(1);
            if cursor > target.end {
                return true;
            }
        }
        false
    }

    async fn retry_session_controls(&mut self) -> Result<(), SessionRuntimeError> {
        self.cancel_unroutable_flows().await?;
        let now = Instant::now();
        let mut retry = Vec::new();
        for (_, pending) in self.session_control_sender.pending_mut() {
            if now.duration_since(pending.last_sent_at) >= MIN_RETRANSMISSION_TIMEOUT {
                pending.last_sent_at = now;
                pending.retry_round = pending.retry_round.wrapping_add(1);
                retry.push((
                    pending.message.clone(),
                    pending.eligible_paths.clone(),
                    pending.retry_round,
                ));
            }
        }
        for (message, eligible, retry_round) in retry {
            if let Err(error) = self
                .send_control_copies(message.message(), eligible.as_ref(), retry_round)
                .await
                && !error.is_flow_recoverable()
            {
                return Err(error);
            }
        }
        Ok(())
    }

    /// Replace inaccessible controls with an opaque, sequenced cancellation.
    /// No target, credentials, or business bytes cross another flow's Path.
    fn cancel_pending_flow_controls(
        &mut self,
        flow: SessionControlFlow,
    ) -> Result<bool, SessionRuntimeError> {
        let mut replaced = false;
        for (sequence, pending) in self.session_control_sender.pending_mut() {
            match &pending.message {
                SessionControlEntry::Control(control)
                    if session_control_flow(control, self.limits)? == Some(flow) =>
                {
                    pending.message =
                        SessionControlEntry::Cancel(SessionControlCancel { sequence, flow });
                    pending.eligible_paths = None;
                    pending.last_sent_at = Instant::now()
                        .checked_sub(MIN_RETRANSMISSION_TIMEOUT)
                        .unwrap_or_else(Instant::now);
                    replaced = true;
                }
                SessionControlEntry::Cancel(cancel) if cancel.flow == flow => replaced = true,
                _ => {}
            }
        }
        Ok(replaced)
    }

    async fn cancel_flow_local(
        &mut self,
        flow: SessionControlFlow,
    ) -> Result<(), SessionRuntimeError> {
        self.cancel_pending_flow_controls(flow)?;
        match flow {
            SessionControlFlow::Stream(id) => {
                self.observe_closed(id, "path_failure", StreamState::Reset);
                if let Some(pending) = self.pending_ingress.remove(&id) {
                    let _ = pending.reply.send(Err(OpenStreamError::Rejected {
                        error: ErrorClass::PathFailure,
                        reason: b"no eligible Path remains".to_vec(),
                    }));
                }
                if let Some(task) = self.opening_tasks.remove(&id) {
                    task.abort();
                    let _ = task.await;
                }
                if let Some(request_id) = self.egress_streams.get(&id)
                    && let Some(cached) = self.egress_requests.get_mut(request_id)
                {
                    cached.result = CachedOpenResult::Rejected {
                        error: ErrorClass::PathFailure,
                        reason: b"no eligible Path remains".to_vec(),
                    };
                }
                if let Some(stream) = self.streams.remove(&id) {
                    let _ = stream.commands.try_send(StreamIoCommand::Reset);
                    stream.task.abort();
                    let _ = stream.task.await;
                }
                self.remove_egress_request_for_stream(id);
            }
            SessionControlFlow::Udp(id) => {
                if let Some(pending) = self.pending_ingress_udp.remove(&id) {
                    let _ = pending.reply.send(Err(OpenUdpError::Rejected {
                        error: ErrorClass::PathFailure,
                        reason: b"no eligible Path remains".to_vec(),
                    }));
                }
                if let Some(runtime) = self.udp_runtime.as_mut() {
                    runtime.close(id)?;
                }
                self.ingress_udp.remove(&id);
                self.egress_udp_paths.remove(&id);
                self.unrestricted_udp_paths.remove(&id);
                self.retired_udp_associations.remove(&id);
                self.pending_udp.remove(&id);
                self.udp_classes.remove(&id);
                self.udp_send_sequences.remove(&id);
                if let Some(waiters) = self.closing_udp.remove(&id) {
                    for waiter in waiters {
                        let _ = waiter.send(Err(OpenUdpError::SessionClosed));
                    }
                }
            }
        }
        Ok(())
    }

    async fn cancel_unroutable_flows(&mut self) -> Result<(), SessionRuntimeError> {
        let ready: BTreeSet<_> = self.multipath.existing_path_ids().into_iter().collect();
        if ready.is_empty() {
            return Ok(());
        }
        let unavailable =
            |paths: &BTreeMap<PathId, u32>| !paths.keys().any(|path| ready.contains(path));
        let mut flows = BTreeSet::new();
        for (_, pending) in self.session_control_sender.pending() {
            if pending.eligible_paths.as_ref().is_some_and(&unavailable)
                && let SessionControlEntry::Control(control) = &pending.message
                && let Some(flow) = session_control_flow(control, self.limits)?
            {
                flows.insert(flow);
            }
        }
        for (id, pending) in &self.pending_ingress {
            if pending.eligible_paths.as_ref().is_some_and(&unavailable) {
                flows.insert(SessionControlFlow::Stream(*id));
            }
        }
        for (id, stream) in &self.streams {
            if stream.eligible_paths.as_ref().is_some_and(&unavailable) {
                flows.insert(SessionControlFlow::Stream(*id));
            }
        }
        for (id, pending) in &self.pending_ingress_udp {
            if pending.eligible_paths.as_ref().is_some_and(&unavailable) {
                flows.insert(SessionControlFlow::Udp(*id));
            }
        }
        for (id, association) in &self.ingress_udp {
            if association
                .eligible_paths
                .as_ref()
                .is_some_and(&unavailable)
            {
                flows.insert(SessionControlFlow::Udp(*id));
            }
        }
        for (id, paths) in &self.egress_udp_paths {
            if !self.unrestricted_udp_paths.contains(id)
                && unavailable(paths)
                && self
                    .udp_runtime
                    .as_ref()
                    .is_some_and(|runtime| runtime.target(*id).is_some())
            {
                flows.insert(SessionControlFlow::Udp(*id));
            }
        }
        for flow in flows {
            let replaced = self.cancel_pending_flow_controls(flow)?;
            // A sender retains every Session control until its ACK, and an ACK
            // means the peer has applied it. Therefore a flow with no pending
            // opening control is already known remotely; creating a fresh
            // cancel sequence here would introduce a strict-sequence hole if
            // the old operation had only been observed through a stale view.
            // Clean the local flow and let its normal RST/close control (if
            // any) carry the peer-side cleanup.
            let _ = replaced;
            self.cancel_flow_local(flow).await?;
        }
        Ok(())
    }

    fn observe_open(
        &mut self,
        id: StreamId,
        target: TargetEndpoint,
        traffic_class: Option<TrafficClassConfig>,
    ) {
        self.stream_observations
            .entry(id)
            .or_insert(StreamSnapshot {
                stream_id: id,
                state: StreamState::Opening,
                target,
                traffic_class,
                bytes_sent: 0,
                bytes_received: 0,
                bytes_acked: 0,
                retransmissions: 0,
                reorder_buffer_bytes: 0,
                receive_window: self.buffer_limit as u64,
                opened_at_ms: wall_clock_ms(),
                closed_at_ms: None,
                close_reason: None,
            });
    }
    fn observe_closed(&mut self, id: StreamId, reason: &str, state: StreamState) {
        if let Some(snapshot) = self.stream_observations.get_mut(&id)
            && snapshot.closed_at_ms.is_none()
        {
            snapshot.state = state;
            snapshot.closed_at_ms = Some(wall_clock_ms());
            snapshot.close_reason = Some(reason.to_owned());
            self.closed_streams.push_back(id);
            if let Some(diagnostics) = &self.diagnostics {
                diagnostics.history.log(DiagnosticLevel::Debug, "stream_closed", || serde_json::json!({
                    "session_id":self.session_id.to_string(),"stream_id":id.to_string(),
                    "state":format!("{state:?}"),"reason":reason,
                    "bytes_sent":snapshot.bytes_sent,"bytes_received":snapshot.bytes_received,
                    "bytes_acked":snapshot.bytes_acked,"retransmissions":snapshot.retransmissions,
                }));
            }
        }
        while self.closed_streams.len() > 128 {
            if let Some(id) = self.closed_streams.pop_front() {
                self.stream_observations.remove(&id);
            }
        }
    }
    fn queue_udp(
        &mut self,
        datagram: UdpDatagram,
        reply: Option<oneshot::Sender<Result<(), OpenUdpError>>>,
    ) {
        let demand_key = self
            .ingress_udp
            .get(&datagram.association_id)
            .and_then(|association| association.demand_key.clone());
        let demand_bytes = datagram.payload.len() as u64;
        let permit = Arc::clone(&self.send_budget)
            .try_acquire_many_owned(datagram.payload.len().max(1) as u32);
        let queue = self.pending_udp.entry(datagram.association_id).or_default();
        if queue.len() >= STREAM_COMMAND_QUEUE_CAPACITY || permit.is_err() {
            if let Some(reply) = reply {
                let _ = reply.send(Err(OpenUdpError::ResourceLimit));
            }
            return;
        }
        queue.push_back(PendingUdpSend {
            datagram,
            reply,
            _permit: permit.unwrap(),
        });
        self.record_demand(demand_key, demand_bytes);
    }
    fn ready_business(
        &self,
    ) -> Vec<(
        crate::traffic_queue::FlowKey,
        Option<TrafficClassConfig>,
        usize,
    )> {
        let mut ready = Vec::new();
        for (id, stream) in &self.streams {
            if let Some(front) = stream.pending.front()
                && front.offset + front.data.len() as u64 <= stream.remote_receive_limit
                && self.session_sent_total + front.data.len() as u64 <= self.remote_session_limit
            {
                ready.push((
                    crate::traffic_queue::FlowKey::Tcp(id.get()),
                    stream.traffic_class.clone(),
                    front.data.len(),
                ));
            }
        }
        for (id, queue) in &self.pending_udp {
            if let Some(front) = queue.front() {
                ready.push((
                    crate::traffic_queue::FlowKey::Udp(*id),
                    self.udp_classes.get(id).cloned(),
                    front.datagram.payload.len(),
                ));
            }
        }
        ready
    }
    fn business_ready(&self) -> bool {
        !self.ready_business().is_empty()
    }
    async fn flush_business(&mut self) -> Result<(), SessionRuntimeError> {
        for _ in 0..8 {
            let ready = self.ready_business();
            let Some(flow) = self.traffic_queue.select(&ready, self.chunk_size) else {
                break;
            };
            match flow {
                crate::traffic_queue::FlowKey::Tcp(id) => {
                    self.flush_stream(
                        StreamId::new(id).map_err(|_| SessionRuntimeError::InvalidRuntimeLimit)?,
                    )
                    .await?
                }
                crate::traffic_queue::FlowKey::Udp(id) => {
                    if let Some(chunk) = self.pending_udp.get_mut(&id).and_then(VecDeque::pop_front)
                    {
                        let result = self
                            .send_udp_now(id, Message::UdpDatagram(chunk.datagram))
                            .await;
                        if let Some(reply) = chunk.reply {
                            let reply_result = match &result {
                                Ok(()) => Ok(()),
                                Err(SessionRuntimeError::WireBudgetExhausted) => {
                                    Err(OpenUdpError::ResourceLimit)
                                }
                                Err(_) => Err(OpenUdpError::SessionClosed),
                            };
                            let _ = reply.send(reply_result);
                        }
                        if let Err(error) = result
                            && !matches!(error, SessionRuntimeError::WireBudgetExhausted)
                        {
                            return Err(error);
                        }
                    }
                }
            }
        }
        let finished: Vec<_> = self
            .streams
            .iter()
            .filter_map(|(id, stream)| {
                (stream.local_fin
                    && !stream.fin_sent
                    && stream.pending.is_empty()
                    && stream.retained.is_empty()
                    && self
                        .stream_observations
                        .get(id)
                        .is_none_or(|snapshot| snapshot.bytes_acked >= snapshot.bytes_sent))
                .then_some(*id)
            })
            .collect();
        for id in finished {
            self.send_stream_message(
                id,
                Message::StreamFin(StreamFin {
                    stream_id: id,
                    flags: STREAM_FLAG_FIN,
                }),
            )
            .await?;
            if let Some(stream) = self.streams.get_mut(&id) {
                stream.fin_sent = true;
            }
        }
        let complete: Vec<_> = self
            .streams
            .iter()
            .filter_map(|(id, stream)| {
                (stream.io_finished
                    && stream.fin_sent
                    && stream.pending.is_empty()
                    && stream.retained.is_empty())
                .then_some(*id)
            })
            .collect();
        for id in complete {
            self.observe_closed(id, "finished", StreamState::Closed);
            if let Some(stream) = self.streams.remove(&id) {
                stream
                    .task
                    .await
                    .map_err(|error| SessionRuntimeError::Task(error.to_string()))?;
            }
            self.remove_egress_request_for_stream(id);
        }
        Ok(())
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
                self.handle_stream_fin(
                    StreamFin {
                        stream_id: data.stream_id,
                        flags: data.flags,
                    },
                    Some(data.offset),
                )
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
        let demand_key = stream.demand_key.clone();
        if let Some(health) = self.path_health.get_mut(&path_id) {
            health.data_events = health.data_events.saturating_add(1);
            if matches!(&self.role, ActorRole::Ingress) {
                health.downstream_bytes_since_observation = health
                    .downstream_bytes_since_observation
                    .saturating_add(data.data.len() as u64);
            } else {
                health.upstream_bytes_since_observation = health
                    .upstream_bytes_since_observation
                    .saturating_add(data.data.len() as u64);
            }
            if data.offset != stream.receive.next_offset() {
                health.reordering_events = health.reordering_events.saturating_add(1);
            }
        }
        let end = data
            .offset
            .checked_add(data.data.len() as u64)
            .ok_or(SessionRuntimeError::InvalidRuntimeLimit)?;
        if stream.remote_fin_offset.is_some_and(|offset| end > offset)
            || (stream.remote_fin && stream.remote_fin_offset.is_none())
        {
            self.reset_stream(
                data.stream_id,
                true,
                b"data exceeds the final Stream offset".to_vec(),
            )
            .await?;
            return Ok(());
        }
        let missing = match stream.receive.missing_ranges(data.offset, &data.data) {
            Ok(missing) => missing,
            Err(ReliabilityError::QueueFull { .. }) => {
                self.reset_stream(
                    data.stream_id,
                    true,
                    b"Stream receive buffer is full".to_vec(),
                )
                .await?;
                return Ok(());
            }
            Err(error) => return Err(error.into()),
        };
        let new_bytes: usize = missing
            .iter()
            .map(|(start, end)| (end - start) as usize)
            .sum();
        if end > stream.local_receive_limit
            || self.session_received_total.saturating_add(new_bytes as u64)
                > self.local_session_limit
        {
            self.reset_stream(
                data.stream_id,
                true,
                b"peer exceeded advertised receive window".to_vec(),
            )
            .await?;
            return Ok(());
        }
        let mut permit = if new_bytes == 0 {
            None
        } else {
            match Arc::clone(&self.inbound_budget).try_acquire_many_owned(new_bytes as u32) {
                Ok(permit) => Some(permit),
                Err(_) => {
                    self.reset_stream(
                        data.stream_id,
                        true,
                        b"Session receive buffer is full".to_vec(),
                    )
                    .await?;
                    return Ok(());
                }
            }
        };
        let result = stream.receive.insert(data.offset, &data.data)?;
        for (start, end) in missing {
            let part = permit
                .as_mut()
                .expect("non-empty ranges have a permit")
                .split((end - start) as usize)
                .expect("reserved exact unique byte count");
            stream
                .inbound_permits
                .push(InboundPermit { end, permit: part });
        }
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
        if let Some(snapshot) = self.stream_observations.get_mut(&data.stream_id) {
            snapshot.bytes_received = snapshot
                .bytes_received
                .saturating_add(delivered.len() as u64);
        }
        self.session_received_total += new_bytes as u64;
        self.bytes_received += new_bytes as u64;
        self.record_demand(demand_key, new_bytes as u64);
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
            self.handle_stream_fin(
                StreamFin {
                    stream_id: data.stream_id,
                    flags: data.flags,
                },
                Some(end),
            )
            .await?;
        } else {
            self.finish_pending_stream_fin(data.stream_id).await?;
        }
        Ok(())
    }

    async fn handle_stream_ack(&mut self, ack: StreamAck) -> Result<(), SessionRuntimeError> {
        let Some(stream) = self.streams.get(&ack.stream_id) else {
            if self
                .stream_observations
                .get(&ack.stream_id)
                .is_some_and(|snapshot| snapshot.closed_at_ms.is_some())
            {
                return Ok(());
            }
            return Err(SessionRuntimeError::SessionTrustFailure);
        };
        if ack
            .ranges
            .iter()
            .copied()
            .any(|range| !Self::ack_range_is_emitted(&stream.emitted, range))
        {
            return Err(SessionRuntimeError::SessionTrustFailure);
        }
        self.multipath.acknowledge(&ack);
        let Some(stream) = self.streams.get_mut(&ack.stream_id) else {
            return Ok(());
        };
        stream.acknowledged.extend(ack.ranges.iter().copied());
        stream.acknowledged.sort_by_key(|range| range.start);
        let mut merged: Vec<AckRange> = Vec::new();
        for range in std::mem::take(&mut stream.acknowledged) {
            if let Some(last) = merged.last_mut()
                && range.start <= last.end.saturating_add(1)
            {
                last.end = last.end.max(range.end);
            } else {
                merged.push(range);
            }
        }
        if merged.len() > ProtocolLimits::HARD_MAX_ACK_RANGES {
            return Err(SessionRuntimeError::InvalidRuntimeLimit);
        }
        let acked = merged.iter().map(|range| range.end - range.start + 1).sum();
        stream.acknowledged = merged;
        stream.retained.retain(|offset, chunk| {
            let end = *offset + chunk.data.len() as u64 - 1;
            !stream
                .acknowledged
                .iter()
                .any(|range| range.contains(*offset) && range.contains(end))
        });
        if let Some(snapshot) = self.stream_observations.get_mut(&ack.stream_id) {
            snapshot.bytes_acked = acked;
        }
        Ok(())
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
        Ok(())
    }

    async fn handle_stream_fin(
        &mut self,
        fin: StreamFin,
        fin_offset: Option<u64>,
    ) -> Result<(), SessionRuntimeError> {
        if fin.flags & STREAM_FLAG_FIN == 0 {
            return self
                .reset_stream(fin.stream_id, true, b"invalid FIN flags".to_vec())
                .await;
        }
        let invalid_offset = self.streams.get(&fin.stream_id).is_some_and(|stream| {
            fin_offset.is_some_and(|offset| {
                offset > stream.local_receive_limit
                    || offset < stream.receive.next_offset()
                    || stream
                        .remote_fin_offset
                        .is_some_and(|previous| previous != offset)
            })
        });
        if invalid_offset {
            return self
                .reset_stream(fin.stream_id, true, b"invalid final Stream offset".to_vec())
                .await;
        }
        let commands = {
            let Some(stream) = self.streams.get_mut(&fin.stream_id) else {
                return Ok(());
            };
            if let Some(offset) = fin_offset {
                stream.remote_fin_offset = Some(offset);
            }
            let ready = stream
                .remote_fin_offset
                .map_or(fin_offset.is_none(), |offset| {
                    stream.receive.next_offset() >= offset
                });
            if stream.remote_fin || !ready {
                None
            } else {
                stream.remote_fin = true;
                Some(stream.commands.clone())
            }
        };
        if let Some(commands) = commands
            && commands.try_send(StreamIoCommand::Fin).is_err()
        {
            self.reset_stream(
                fin.stream_id,
                true,
                b"Stream target writer is unavailable".to_vec(),
            )
            .await?;
        }
        Ok(())
    }

    async fn finish_pending_stream_fin(
        &mut self,
        stream_id: StreamId,
    ) -> Result<(), SessionRuntimeError> {
        let commands = {
            let Some(stream) = self.streams.get_mut(&stream_id) else {
                return Ok(());
            };
            let ready = !stream.remote_fin
                && stream
                    .remote_fin_offset
                    .is_some_and(|offset| stream.receive.next_offset() >= offset);
            if !ready {
                None
            } else {
                stream.remote_fin = true;
                Some(stream.commands.clone())
            }
        };
        if let Some(commands) = commands
            && commands.try_send(StreamIoCommand::Fin).is_err()
        {
            self.reset_stream(
                stream_id,
                true,
                b"Stream target writer is unavailable".to_vec(),
            )
            .await?;
        }
        Ok(())
    }

    async fn handle_stream_rst(&mut self, rst: StreamRst) {
        let _ = self
            .reset_stream_with_error(rst.stream_id, false, rst.error, rst.reason)
            .await;
    }

    async fn reset_stream(
        &mut self,
        stream_id: StreamId,
        notify_peer: bool,
        reason: Vec<u8>,
    ) -> Result<(), SessionRuntimeError> {
        self.reset_stream_with_error(stream_id, notify_peer, ErrorClass::PathFailure, reason)
            .await
    }

    async fn reset_stream_with_error(
        &mut self,
        stream_id: StreamId,
        notify_peer: bool,
        error: ErrorClass,
        mut reason: Vec<u8>,
    ) -> Result<(), SessionRuntimeError> {
        reason.truncate(self.limits.max_control_payload());
        let close_reason = if error == ErrorClass::TargetFailure {
            "target_failure"
        } else {
            "reset"
        };
        self.observe_closed(stream_id, close_reason, StreamState::Reset);
        if notify_peer {
            self.send_stream_message(
                stream_id,
                Message::StreamRst(StreamRst {
                    stream_id,
                    error,
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
        self.remove_egress_request_for_stream(stream_id);
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
        self.send_stream_message(
            stream_id,
            Message::StreamOpenErr(StreamOpenErr {
                stream_id,
                error,
                reason,
            }),
        )
        .await
    }

    async fn send_stream_message(
        &mut self,
        stream_id: StreamId,
        message: Message,
    ) -> Result<(), SessionRuntimeError> {
        let eligible = self.active_control_eligible.clone().unwrap_or_else(|| {
            match self.streams.get(&stream_id) {
                Some(stream) => stream.eligible_paths.clone(),
                None => self
                    .egress_requests
                    .values()
                    .find(|cached| {
                        cached.request.stream_id == stream_id && !cached.unrestricted_paths
                    })
                    .map(|cached| cached.eligible_paths.clone()),
            }
        });
        if message.frame_type().is_session_control() {
            self.send_session_control(message, eligible).await?;
            return Ok(());
        }
        if let Some(eligible) = eligible {
            let path_id = self
                .multipath
                .schedule_existing_eligible(self.outbound_direction(), 0, &eligible)?
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
        if let Message::UdpDatagram(datagram) = message {
            self.queue_udp(datagram, None);
            Ok(())
        } else {
            self.send_udp_now(association_id, message).await
        }
    }

    async fn send_udp_now(
        &mut self,
        association_id: u64,
        message: Message,
    ) -> Result<(), SessionRuntimeError> {
        // UDP Associations retain their own policy snapshot even though the
        // current v1 scheduler does not create optional datagram replicas.
        // Keeping the read here prevents a later Session-wide policy update
        // from silently changing that flow's accounting context.
        let _flow_replication_budget = self
            .ingress_udp
            .get(&association_id)
            .map(|association| association.replication_budget);
        let eligible = self.active_control_eligible.clone().unwrap_or_else(|| {
            if self.unrestricted_udp_paths.contains(&association_id) {
                return None;
            }
            self.ingress_udp
                .get(&association_id)
                .and_then(|association| association.eligible_paths.clone())
                .or_else(|| self.egress_udp_paths.get(&association_id).cloned())
        });
        if message.frame_type().is_session_control() {
            self.send_session_control(message, eligible).await?;
            return Ok(());
        }
        if let Some(eligible) = eligible {
            let bytes = match &message {
                Message::UdpDatagram(datagram) => datagram.payload.len(),
                _ => 0,
            };
            let path_id = self
                .multipath
                .schedule_existing_eligible(self.outbound_direction(), bytes, &eligible)?
                .path_id;
            self.send_message_on(path_id, message).await
        } else {
            self.send_message(message).await
        }
    }

    async fn send_message(&mut self, message: Message) -> Result<(), SessionRuntimeError> {
        if message.frame_type().is_session_control() {
            self.send_session_control(message, None).await?;
            return Ok(());
        }
        let bytes = match &message {
            Message::StreamData(data) => data.data.len(),
            Message::UdpDatagram(datagram) => datagram.payload.len(),
            _ => 0,
        };
        let direction = match &self.role {
            ActorRole::Ingress => ScheduleDirection::Upstream,
            ActorRole::Egress { .. } => ScheduleDirection::Downstream,
        };
        let path_id = self.multipath.schedule_existing(direction, bytes)?.path_id;
        self.send_message_on(path_id, message).await
    }

    async fn send_message_on(
        &mut self,
        path_id: PathId,
        message: Message,
    ) -> Result<(), SessionRuntimeError> {
        if message.frame_type().is_session_control() {
            self.send_session_control(message, Some(BTreeMap::from([(path_id, 1)])))
                .await?;
            return Ok(());
        }
        self.send_raw_message_on(path_id, message).await
    }

    async fn send_session_control(
        &mut self,
        message: Message,
        _eligible_paths: Option<BTreeMap<PathId, u32>>,
    ) -> Result<u64, SessionRuntimeError> {
        let sequence = self.session_control_sender.next_sequence();
        let control = SessionControl {
            sequence,
            depends_on: sequence.checked_sub(1),
            frame_type: message.frame_type(),
            // A Session owns one common Path pool. The registered field stays
            // in the envelope for profile compatibility, but new opens never
            // install a per-flow restriction.
            eligible_paths: Vec::new(),
            payload: message.encode(self.limits)?,
        };
        // Check the outer bound before consuming a sequence number.
        Message::SessionControl(control.clone()).encode(self.limits)?;
        let actual = self.session_control_sender.enqueue(PendingSessionControl {
            retry_round: 0,
            message: SessionControlEntry::Control(control.clone()),
            eligible_paths: None,
            last_sent_at: Instant::now(),
        })?;
        debug_assert_eq!(actual, sequence);
        if let Err(error) = self
            .send_control_copies(Message::SessionControl(control), None, 0)
            .await
        {
            if !matches!(
                error,
                SessionRuntimeError::PathClosed
                    | SessionRuntimeError::Multipath(MultipathError::NoSchedulablePath)
            ) {
                return Err(error);
            }
            self.cancel_unroutable_flows().await?;
        }
        Ok(sequence)
    }

    async fn send_control_copies(
        &mut self,
        message: Message,
        eligible: Option<&BTreeMap<PathId, u32>>,
        retry_round: usize,
    ) -> Result<(), SessionRuntimeError> {
        let mut paths: Vec<_> = self
            .multipath
            .existing_path_ids()
            .into_iter()
            .filter(|path| eligible.is_none_or(|eligible| eligible.contains_key(path)))
            .collect();
        if paths.is_empty() {
            return Err(MultipathError::NoSchedulablePath.into());
        }
        // A required retry may use another ready Path even when the Session
        // has no budget for optional copies in this transmission round.
        let start = retry_round % paths.len();
        paths.rotate_left(start);
        let copy_size = message.encode(self.limits)?.len().saturating_add(128) as u64;
        let mut sent = false;
        for path in paths {
            if sent && !self.multipath.charge_control_replication(copy_size) {
                break;
            }
            if self
                .send_raw_message_on_priority(path, message.clone(), WirePriority::RequiredControl)
                .await
                .is_ok()
            {
                sent = true;
            }
        }
        if sent {
            Ok(())
        } else {
            Err(SessionRuntimeError::PathClosed)
        }
    }

    async fn send_raw_message_on(
        &mut self,
        path_id: PathId,
        message: Message,
    ) -> Result<(), SessionRuntimeError> {
        self.send_raw_message_on_priority(path_id, message, WirePriority::Primary)
            .await
    }

    async fn send_raw_message_on_priority(
        &mut self,
        path_id: PathId,
        message: Message,
        priority: WirePriority,
    ) -> Result<(), SessionRuntimeError> {
        let data_bytes = match &message {
            Message::StreamData(data) => data.data.len() as u64,
            Message::UdpDatagram(datagram) => datagram.payload.len() as u64,
            _ => 0,
        };
        let payload = message.encode(self.limits)?;
        self.trace_frame(
            path_id,
            "send_attempt",
            &message,
            payload.len(),
            (path_id == self.path_id).then_some(self.next_frame_seq),
            Some(priority),
        );
        let sizing_frame = PathFrame::new(
            message.frame_type(),
            FrameFlags::empty(),
            self.session_id,
            path_id,
            if path_id == self.path_id {
                self.next_frame_seq
            } else {
                MAX_VARINT
            },
            payload,
            self.limits,
        )?;
        let wire_bytes = (sizing_frame.encode(self.limits)?.len()
            + RECORD_ENVELOPE_HEADER_LEN
            + TRANSPORT_TAG_LEN) as u64;
        if !self.status_provider.try_reserve_wire(priority, wire_bytes) {
            if let Some(diagnostics) = &self.diagnostics {
                diagnostics
                    .history
                    .log(DiagnosticLevel::Trace, "wire_budget_blocked", || {
                        serde_json::json!({
                            "session_id":self.session_id.to_string(),"path_id":path_id.to_string(),
                            "frame_type":message.frame_type() as u64,"wire_bytes":wire_bytes,
                            "priority":format!("{priority:?}"),
                        })
                    });
            }
            return Err(SessionRuntimeError::WireBudgetExhausted);
        }
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
                .map_err(|_| SessionRuntimeError::PathWrite {
                    path_id,
                    source: Box::new(SessionRuntimeError::PathClosed),
                })?;
            let result = result.await.unwrap_or(Err(SessionRuntimeError::PathClosed));
            if let Err(error) = result {
                if let Some(health) = self.path_health.get_mut(&path_id) {
                    health.terminal_write.get_or_insert((
                        error.write_termination_reason(),
                        error.write_elapsed_ms(),
                    ));
                }
                return Err(SessionRuntimeError::PathWrite {
                    path_id,
                    source: Box::new(error),
                });
            }
            if let Some(health) = self.path_health.get_mut(&path_id) {
                health.bytes_since_observation =
                    health.bytes_since_observation.saturating_add(data_bytes);
                if matches!(&self.role, ActorRole::Ingress) {
                    health.upstream_bytes_since_observation = health
                        .upstream_bytes_since_observation
                        .saturating_add(data_bytes);
                } else {
                    health.downstream_bytes_since_observation = health
                        .downstream_bytes_since_observation
                        .saturating_add(data_bytes);
                }
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
        self.writer
            .send(frame)
            .await
            .map_err(|error| SessionRuntimeError::PathWrite {
                path_id,
                source: Box::new(error),
            })?;
        self.next_frame_seq = self
            .next_frame_seq
            .checked_add(1)
            .ok_or(SessionRuntimeError::FrameSequenceExhausted)?;
        if let Some(health) = self.path_health.get_mut(&path_id) {
            health.bytes_since_observation =
                health.bytes_since_observation.saturating_add(data_bytes);
            if matches!(&self.role, ActorRole::Ingress) {
                health.upstream_bytes_since_observation = health
                    .upstream_bytes_since_observation
                    .saturating_add(data_bytes);
            } else {
                health.downstream_bytes_since_observation = health
                    .downstream_bytes_since_observation
                    .saturating_add(data_bytes);
            }
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
                        attribution: if *path_id == self.path_id {
                            self.diagnostics.as_ref().and_then(|context| context.attribution.clone())
                        } else {
                            health.attribution.clone()
                        },
                        rtt_ms: health.rtt_ms,
                        jitter_ms: health.jitter_ms,
                        loss_ppm,
                        throughput_bps: health.throughput_bps,
                        effective_capacity_bps: health.effective_capacity_bps,
                        upstream_effective_capacity_bps: health.upstream_effective_capacity_bps,
                        downstream_effective_capacity_bps: health.downstream_effective_capacity_bps,
                        upstream_throughput_bps: health.upstream_throughput_bps,
                        downstream_throughput_bps: health.downstream_throughput_bps,
                        control_pending: health.sender.pending_len(),
                        control_retransmissions: health.retransmitted_controls,
                        reordering_events: health.reordering_events,
                        exclusion_reason: health.exclusion_reason.or_else(|| self.multipath.quality_exclusion(*path_id).ok().flatten().map(|reason| match reason {
                            crate::PathQualityExclusionReason::IncrementalCapacityBelowOverhead => PathExclusionReason::IncrementalCapacityBelowOverhead,
                            crate::PathQualityExclusionReason::CongestionWindowExhausted => PathExclusionReason::CongestionWindowExhausted,
                        })),
                    },
                )
            })
            .collect();
        let mut path_states = self.retired_path_states.clone();
        path_states.extend(self.multipath.path_states());
        SessionSnapshot {
            session_id: self.session_id,
            path_id: self.path_id,
            ready_paths: self.multipath.ready_path_count(),
            ready_path_ids: self.multipath.ready_path_ids(),
            path_states,
            degraded_paths: self.multipath.degraded_path_count(),
            effective_capacity_bps: self.multipath.effective_capacity_bps(),
            egress_aggregate_capacity_bps: self.egress_aggregate_capacity_bps,
            target_path_count: self.target_path_count,
            path_quality,
            demand: self
                .demand_ewma_bps
                .keys()
                .map(|key| {
                    (
                        key.clone(),
                        DemandSnapshot {
                            bytes_per_second: self.demand_last_bps.get(key).copied().unwrap_or(0),
                            ewma_bps: self.demand_ewma_bps.get(key).copied().unwrap_or(0),
                        },
                    )
                })
                .collect(),
            streams: self
                .stream_observations
                .iter()
                .map(|(id, snapshot)| {
                    let mut snapshot = snapshot.clone();
                    if let Some(stream) = self.streams.get(id) {
                        snapshot.reorder_buffer_bytes = stream.receive.buffered_bytes();
                        snapshot.receive_window = stream
                            .remote_receive_limit
                            .saturating_sub(stream.next_send_offset);
                        snapshot.state = match (stream.local_fin, stream.remote_fin, &self.role) {
                            (true, true, _) => StreamState::Closed,
                            (true, false, ActorRole::Ingress)
                            | (false, true, ActorRole::Egress { .. }) => {
                                StreamState::IngressHalfClosed
                            }
                            (true, false, ActorRole::Egress { .. })
                            | (false, true, ActorRole::Ingress) => StreamState::EgressHalfClosed,
                            _ => StreamState::Open,
                        };
                    }
                    (*id, snapshot)
                })
                .collect(),
            active_streams: self.streams.len(),
            active_udp_associations: if matches!(self.role, ActorRole::Ingress) {
                self.ingress_udp.len()
            } else {
                self.udp_runtime
                    .as_ref()
                    .map_or(0, |runtime| runtime.snapshot().active_associations)
            },
            pending_session_controls: self.session_control_sender.pending_len(),
            egress_status: self
                .latest_egress_status
                .as_ref()
                .map(|(report, received)| {
                    let age_ms = report.sample_age_ms.saturating_add(
                        received.elapsed().as_millis().min(u128::from(u64::MAX)) as u64,
                    );
                    EgressStatusObservation {
                        report: report.clone(),
                        age_ms,
                        fresh: age_ms <= report.expires_after_ms,
                    }
                }),
            pending_stream_opens: self.pending_ingress.len() + self.opening_tasks.len(),
            retained_outbound_bytes: self.retained_outbound_bytes(),
            bytes_sent: self.bytes_sent,
            bytes_received: self.bytes_received,
            closed,
            trust_failure: self.trust_failure,
        }
    }

    fn publish_snapshot(&self, closed: bool) {
        self.snapshots.send_replace(self.current_snapshot(closed));
    }

    fn record_demand(&mut self, key: Option<DemandKey>, bytes: u64) {
        let Some(key) = key else {
            return;
        };
        if bytes == 0 {
            return;
        }
        if !self.demand_bytes.contains_key(&key) && self.demand_bytes.len() >= MAX_DEMAND_KEYS {
            return;
        }
        let entry = self.demand_bytes.entry(key).or_insert(0);
        *entry = entry.saturating_add(bytes);
    }

    fn rotate_demand(&mut self, now: Instant) {
        let elapsed_ms = now
            .duration_since(self.demand_window_started)
            .as_millis()
            .min(u128::from(u64::MAX)) as u64;
        if elapsed_ms < 1_000 {
            return;
        }
        let bytes = std::mem::take(&mut self.demand_bytes);
        for (key, value) in bytes {
            let bps = value.saturating_mul(8).saturating_mul(1_000) / elapsed_ms.max(1);
            if !self.demand_last_bps.contains_key(&key)
                && self.demand_last_bps.len() >= MAX_DEMAND_KEYS
                && let Some(oldest) = self.demand_last_bps.keys().next().cloned()
            {
                self.demand_last_bps.remove(&oldest);
                self.demand_ewma_bps.remove(&oldest);
            }
            self.demand_last_bps.insert(key.clone(), bps);
            let prior = self.demand_ewma_bps.get(&key).copied().unwrap_or(0);
            self.demand_ewma_bps
                .insert(key, prior.saturating_mul(3).saturating_add(bps) / 4);
        }
        while self.demand_ewma_bps.len() > MAX_DEMAND_KEYS {
            if let Some(oldest) = self.demand_ewma_bps.keys().next().cloned() {
                self.demand_ewma_bps.remove(&oldest);
                self.demand_last_bps.remove(&oldest);
            }
        }
        self.demand_window_started = now;
    }

    /// A terminal Session result closes every Path without attempting
    /// retransmission. Trust failures must not allow any Path to keep serving
    /// the retired Session while the Ingress constructs a fresh SessionID.
    async fn terminate_paths(&mut self) {
        for (_, path) in self.extra_paths.drain() {
            path.writer_task.abort();
            path.reader_task.abort();
            let _ = path.writer_task.await;
            let _ = path.reader_task.await;
        }
        if let Some(task) = self.reader_task.take() {
            task.abort();
            let _ = task.await;
        }
        for path_id in self
            .multipath
            .path_states()
            .keys()
            .copied()
            .collect::<Vec<_>>()
        {
            let _ = self.multipath.mark_path_closed(path_id);
        }
        self.attached_paths.send_modify(BTreeSet::clear);
        for (path_id, health) in std::mem::take(&mut self.path_health) {
            let (reason, elapsed) = health
                .terminal_write
                .unwrap_or((PathTerminationReason::SessionClosed, None));
            self.record_path_termination(path_id, &health, true, reason, elapsed);
        }
    }

    async fn cleanup(&mut self) {
        for id in self.stream_observations.keys().copied().collect::<Vec<_>>() {
            self.observe_closed(id, "session_closed", StreamState::Closed);
        }
        self.pending_udp.clear();
        for (_, waiters) in self.closing_udp.drain() {
            for waiter in waiters {
                let _ = waiter.send(Err(OpenUdpError::SessionClosed));
            }
        }
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
        if let Some(task) = self.reader_task.take() {
            task.abort();
            let _ = task.await;
        }
    }
}

impl<W> Drop for SessionActor<W> {
    fn drop(&mut self) {
        if let Some(task) = &self.reader_task {
            task.abort();
        }
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

fn wall_clock_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| {
            duration.as_millis().min(u128::from(u64::MAX)) as u64
        })
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

fn session_control_flow(
    control: &SessionControl,
    limits: ProtocolLimits,
) -> Result<Option<SessionControlFlow>, SessionRuntimeError> {
    let message = Message::decode(control.frame_type, &control.payload, limits)?;
    Ok(match message {
        Message::StreamOpen(value) => Some(SessionControlFlow::Stream(value.stream_id)),
        Message::StreamOpenOk(value) => Some(SessionControlFlow::Stream(value.stream_id)),
        Message::StreamOpenErr(value) => Some(SessionControlFlow::Stream(value.stream_id)),
        Message::StreamAck(value) => Some(SessionControlFlow::Stream(value.stream_id)),
        Message::StreamWindow(value) => Some(SessionControlFlow::Stream(value.stream_id)),
        Message::StreamFin(value) => Some(SessionControlFlow::Stream(value.stream_id)),
        Message::StreamRst(value) => Some(SessionControlFlow::Stream(value.stream_id)),
        Message::UdpOpen(value) => Some(SessionControlFlow::Udp(value.association_id)),
        Message::UdpOpenOk(value) => Some(SessionControlFlow::Udp(value.association_id)),
        Message::UdpOpenErr(value) => Some(SessionControlFlow::Udp(value.association_id)),
        Message::UdpClose(value) => Some(SessionControlFlow::Udp(value.association_id)),
        _ => None,
    })
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
    diagnostics: Option<Arc<DiagnosticHistory>>,
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
        let started = Instant::now();
        let result = tokio::time::timeout(PATH_WRITE_TIMEOUT, async {
            self.io.write_all(&encoded).await?;
            self.io.flush().await
        })
        .await;
        if let Some(history) = &self.diagnostics {
            history.log(DiagnosticLevel::Trace, "carrier_write", || {
                let header = frame.header();
                let (outcome, io_kind) = match &result {
                    Ok(Ok(())) => ("success", None),
                    Ok(Err(error)) => ("error", Some(format!("{:?}", error.kind()))),
                    Err(_) => ("timeout", None),
                };
                serde_json::json!({
                    "session_id":header.session_id().to_string(),"path_id":header.path_id().to_string(),
                    "frame_sequence":header.frame_seq(),"frame_type":header.frame_type() as u64,
                    "wire_bytes":encoded.len(),"elapsed_ms":started.elapsed().as_millis() as u64,
                    "deadline_ms":PATH_WRITE_TIMEOUT.as_millis() as u64,"outcome":outcome,"io_kind":io_kind,
                })
            });
        }
        result.map_err(|_| SessionRuntimeError::PathWriteTimeout {
            elapsed_ms: started.elapsed().as_millis() as u64,
        })??;
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
    async fn receive(&mut self) -> Result<Option<RecordRead>, SessionRuntimeError> {
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
        match noise.open_encoded_frame_replay_aware(&encoded, self.limits)? {
            ReplayAwareFrame::Accepted(frame) => Ok(Some(RecordRead::Frame(frame))),
            ReplayAwareFrame::Dropped => Ok(Some(RecordRead::ReplayDropped)),
        }
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
            Ok(Some(RecordRead::Frame(frame))) => ReaderEvent::Frame { path_id, frame },
            Ok(Some(RecordRead::ReplayDropped)) => continue,
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
                                operation: "write",
                                kind: error.kind(),
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
                                operation: "shutdown",
                                kind: error.kind(),
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
                        operation: "read",
                        kind: error.kind(),
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
#[path = "runtime_alignment_tests.rs"]
mod alignment_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CompleteFrameTransport;
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

    pub(super) fn keys() -> (StaticKeypair, StaticKeypair) {
        (
            generate_static_keypair().expect("Ingress key"),
            generate_static_keypair().expect("Egress key"),
        )
    }

    pub(super) fn ingress_config() -> IngressPathAdmissionConfig {
        IngressPathAdmissionConfig {
            egress_identity: b"PathChord/wire-v1/egress/runtime-egress".to_vec(),
            egress_id: b"runtime-egress".to_vec(),
            ingress_id: b"runtime-ingress".to_vec(),
            session_id: SessionId::new(0x1234),
            path_id: PathId::new(0x5678),
            offered_capabilities: CAPABILITY_TCP_STREAM | CAPABILITY_UDP_SESSION,
            required_capabilities: 1,
            replication_budget_bytes_per_second: 8 * 1024 * 1024,
            local_limits: ProtocolLimits::default(),
        }
    }

    pub(super) fn egress_config() -> EgressPathAdmissionConfig {
        EgressPathAdmissionConfig {
            egress_identity: b"PathChord/wire-v1/egress/runtime-egress".to_vec(),
            egress_id: b"runtime-egress".to_vec(),
            required_capabilities: 1,
            supported_capabilities: CAPABILITY_TCP_STREAM | CAPABILITY_UDP_SESSION,
            max_replication_budget_bytes_per_second: 8 * 1024 * 1024,
            local_limits: ProtocolLimits::default(),
            ready_limits: PathReady {
                max_frame_payload: 4096,
                max_control_payload: 1024,
                max_session_buffering: 64 * 1024,
            },
        }
    }

    pub(super) fn authorization(ingress: &StaticKeypair) -> PathAuthorization {
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
        admitted_pair_with_classes(false).await
    }

    #[tokio::test]
    async fn duplicate_authenticated_record_does_not_stop_the_path_reader() {
        let (ingress, egress) = admitted_pair().await;
        let session_id = ingress.session_id();
        let path_id = ingress.path_id();
        let (mut ingress_io, mut send_noise) = ingress.into_transport().into_parts();
        let (egress_io, receive_noise) = egress.into_transport().into_parts();
        let limits = ProtocolLimits::default();
        let (events_tx, mut events) = mpsc::channel(8);
        let reader_task = tokio::spawn(record_reader_loop(
            path_id,
            RecordReader {
                io: egress_io,
                noise: Arc::new(Mutex::new(receive_noise)),
                limits,
            },
            events_tx,
        ));

        let mut seal = |value: u64| {
            let nonce = send_noise.next_send_nonce().unwrap();
            let message = Message::Heartbeat(Heartbeat { control_seq: value });
            let frame = PathFrame::new(
                message.frame_type(),
                FrameFlags::empty(),
                session_id,
                path_id,
                nonce,
                message.encode(limits).unwrap(),
                limits,
            )
            .unwrap();
            send_noise.seal_frame(&frame, limits).unwrap().encode()
        };
        let first = seal(10);
        let second = seal(11);
        ingress_io.write_all(&first).await.unwrap();
        ingress_io.write_all(&first).await.unwrap();
        ingress_io.write_all(&second).await.unwrap();
        for expected in [10, 11] {
            let Some(ReaderEvent::Frame { frame, .. }) = events.recv().await else {
                panic!("duplicate unexpectedly stopped reader");
            };
            assert_eq!(
                Message::decode(frame.header().frame_type(), frame.payload(), limits).unwrap(),
                Message::Heartbeat(Heartbeat {
                    control_seq: expected
                })
            );
        }
        drop(ingress_io);
        assert!(matches!(
            events.recv().await,
            Some(ReaderEvent::Closed { .. })
        ));
        reader_task.await.unwrap();
    }

    #[tokio::test]
    async fn reordered_data_fin_waits_for_all_preceding_bytes() {
        let (path, _peer) = admitted_pair().await;
        let session_id = path.session_id();
        let path_id = path.path_id();
        let ready = path.limits().clone();
        let initial = SessionSnapshot {
            session_id,
            path_id,
            ready_paths: 1,
            ready_path_ids: vec![path_id],
            path_states: BTreeMap::from([(path_id, pathchord_core::PathState::Active)]),
            degraded_paths: 0,
            effective_capacity_bps: 0,
            egress_aggregate_capacity_bps: 0,
            target_path_count: 1,
            path_quality: BTreeMap::new(),
            demand: BTreeMap::new(),
            active_streams: 0,
            active_udp_associations: 0,
            pending_session_controls: 0,
            egress_status: None,
            streams: BTreeMap::new(),
            pending_stream_opens: 0,
            retained_outbound_bytes: 0,
            bytes_sent: 0,
            bytes_received: 0,
            closed: false,
            trust_failure: false,
        };
        let (snapshots, _) = watch::channel(initial);
        let mut actor = SessionActor::new(
            path.into_transport(),
            SessionActorInit {
                diagnostics: None,
                role: ActorRole::Ingress,
                udp_factory: None,
                session_id,
                path_id,
                ready,
                commands: None,
                snapshots,
                egress_status: Default::default(),
                status_provider: None,
                capabilities: 0,
                session_replication_budget_bytes: 8 * 1024 * 1024,
                target_open_slots: None,
            },
        )
        .unwrap();
        let stream_id = StreamId::new(1).unwrap();
        let (io, mut target) = duplex(1024);
        actor
            .spawn_active_stream(
                stream_id,
                Box::new(io),
                None,
                None,
                FlowReplicationBudget::unlimited(8 * 1024 * 1024),
            )
            .unwrap();
        actor
            .handle_stream_data(
                path_id,
                StreamData {
                    stream_id,
                    offset: 3,
                    flags: STREAM_FLAG_FIN,
                    data: b"def".to_vec(),
                },
            )
            .await
            .unwrap();
        let mut byte = [0_u8; 1];
        assert!(
            tokio::time::timeout(Duration::from_millis(20), target.read(&mut byte))
                .await
                .is_err()
        );
        actor
            .handle_stream_data(
                path_id,
                StreamData {
                    stream_id,
                    offset: 0,
                    flags: 0,
                    data: b"abc".to_vec(),
                },
            )
            .await
            .unwrap();
        let mut received = Vec::new();
        tokio::time::timeout(Duration::from_secs(1), target.read_to_end(&mut received))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(received, b"abcdef");
        actor.cleanup().await;
    }

    #[tokio::test]
    async fn future_stream_ack_does_not_release_retained_data() {
        let (path, _peer) = admitted_pair().await;
        let session_id = path.session_id();
        let path_id = path.path_id();
        let ready = path.limits().clone();
        let initial = SessionSnapshot {
            session_id,
            path_id,
            ready_paths: 1,
            ready_path_ids: vec![path_id],
            path_states: BTreeMap::from([(path_id, pathchord_core::PathState::Active)]),
            degraded_paths: 0,
            effective_capacity_bps: 0,
            egress_aggregate_capacity_bps: 0,
            target_path_count: 1,
            path_quality: BTreeMap::new(),
            demand: BTreeMap::new(),
            active_streams: 0,
            active_udp_associations: 0,
            pending_session_controls: 0,
            egress_status: None,
            streams: BTreeMap::new(),
            pending_stream_opens: 0,
            retained_outbound_bytes: 0,
            bytes_sent: 0,
            bytes_received: 0,
            closed: false,
            trust_failure: false,
        };
        let (snapshots, _) = watch::channel(initial);
        let mut actor = SessionActor::new(
            path.into_transport(),
            SessionActorInit {
                diagnostics: None,
                role: ActorRole::Ingress,
                udp_factory: None,
                session_id,
                path_id,
                ready,
                commands: None,
                snapshots,
                egress_status: Default::default(),
                status_provider: None,
                capabilities: 0,
                session_replication_budget_bytes: 8 * 1024 * 1024,
                target_open_slots: None,
            },
        )
        .unwrap();
        let stream_id = StreamId::new(1).unwrap();
        let (io, _peer) = duplex(1024);
        actor
            .spawn_active_stream(
                stream_id,
                Box::new(io),
                None,
                None,
                FlowReplicationBudget::unlimited(8 * 1024 * 1024),
            )
            .unwrap();
        let permit = actor.send_budget.clone().try_acquire_many_owned(5).unwrap();
        actor
            .queue_stream_data(stream_id, b"hello".to_vec(), permit)
            .await
            .unwrap();
        actor.flush_stream(stream_id).await.unwrap();
        assert_eq!(
            actor.streams[&stream_id].emitted,
            [AckRange { start: 0, end: 4 }]
        );
        assert_eq!(actor.streams[&stream_id].retained.len(), 1);
        assert!(matches!(
            actor
                .handle_stream_ack(StreamAck {
                    stream_id,
                    ranges: vec![AckRange { start: 0, end: 5 }],
                })
                .await,
            Err(SessionRuntimeError::SessionTrustFailure)
        ));
        assert_eq!(actor.streams[&stream_id].retained.len(), 1);
        actor
            .handle_stream_ack(StreamAck {
                stream_id,
                ranges: vec![AckRange { start: 0, end: 4 }],
            })
            .await
            .unwrap();
        assert!(actor.streams[&stream_id].retained.is_empty());
        actor.cleanup().await;
    }

    #[tokio::test]
    async fn future_stream_ack_closes_every_path_and_publishes_trust_failure() {
        let (ingress_path, egress_path) = admitted_pair().await;
        let session_id = ingress_path.session_id();
        let path_id = ingress_path.path_id();
        let ready = ingress_path.limits().clone();
        let (mut peer_io, mut peer_noise) = egress_path.into_transport().into_parts();
        let initial = SessionSnapshot {
            session_id,
            path_id,
            ready_paths: 1,
            ready_path_ids: vec![path_id],
            path_states: BTreeMap::from([(path_id, pathchord_core::PathState::Active)]),
            degraded_paths: 0,
            effective_capacity_bps: 0,
            egress_aggregate_capacity_bps: 0,
            target_path_count: 1,
            path_quality: BTreeMap::new(),
            demand: BTreeMap::new(),
            active_streams: 0,
            active_udp_associations: 0,
            pending_session_controls: 0,
            egress_status: None,
            streams: BTreeMap::new(),
            pending_stream_opens: 0,
            retained_outbound_bytes: 0,
            bytes_sent: 0,
            bytes_received: 0,
            closed: false,
            trust_failure: false,
        };
        let (snapshots, _snapshot_rx) = watch::channel(initial);
        let mut actor = SessionActor::new(
            ingress_path.into_transport(),
            SessionActorInit {
                diagnostics: None,
                role: ActorRole::Ingress,
                udp_factory: None,
                session_id,
                path_id,
                ready,
                commands: None,
                snapshots,
                egress_status: Default::default(),
                status_provider: None,
                capabilities: 0,
                session_replication_budget_bytes: 8 * 1024 * 1024,
                target_open_slots: None,
            },
        )
        .unwrap();
        let stream_id = StreamId::new(1).unwrap();
        let (io, _target) = duplex(1024);
        actor
            .spawn_active_stream(
                stream_id,
                Box::new(io),
                None,
                None,
                FlowReplicationBudget::unlimited(8 * 1024 * 1024),
            )
            .unwrap();
        let demand_key = DemandKey {
            rule_id: "rule-a".into(),
            policy_id: "policy-a".into(),
            traffic_class: Some("interactive".into()),
        };
        actor.streams.get_mut(&stream_id).unwrap().demand_key = Some(demand_key.clone());
        let permit = actor.send_budget.clone().try_acquire_many_owned(5).unwrap();
        actor
            .queue_stream_data(stream_id, b"hello".to_vec(), permit)
            .await
            .unwrap();
        actor.flush_stream(stream_id).await.unwrap();
        actor.demand_window_started = Instant::now() - Duration::from_secs(1);
        actor.rotate_demand(Instant::now());
        let demand_snapshot = actor.current_snapshot(false);
        let demand = demand_snapshot
            .demand
            .get(&demand_key)
            .expect("bounded demand key");
        assert!(demand.bytes_per_second > 0);
        assert!(demand.ewma_bps > 0);

        let task = tokio::spawn(actor.run());
        let inner = Message::StreamAck(StreamAck {
            stream_id,
            ranges: vec![AckRange { start: 0, end: 5 }],
        });
        let message = Message::SessionControl(SessionControl {
            sequence: 0,
            depends_on: None,
            frame_type: inner.frame_type(),
            eligible_paths: Vec::new(),
            payload: inner.encode(ProtocolLimits::default()).unwrap(),
        });
        let limits = ProtocolLimits::default();
        let frame = PathFrame::new(
            message.frame_type(),
            FrameFlags::empty(),
            session_id,
            path_id,
            peer_noise.next_send_nonce().unwrap(),
            message.encode(limits).unwrap(),
            limits,
        )
        .unwrap();
        peer_io
            .write_all(&peer_noise.seal_frame(&frame, limits).unwrap().encode())
            .await
            .unwrap();

        let snapshot = tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .expect("trust failure should terminate the Session")
            .expect("Session task should not panic")
            .expect_err("trust failure must be surfaced to the Session owner");
        assert!(
            matches!(snapshot, SessionRuntimeError::SessionTrustFailure),
            "unexpected terminal error: {snapshot:?}"
        );
        let snapshot = _snapshot_rx.borrow().clone();
        assert!(snapshot.closed);
        assert!(snapshot.trust_failure);
        assert_eq!(snapshot.ready_paths, 0);
        assert!(snapshot.ready_path_ids.is_empty());
        assert!(
            snapshot
                .path_states
                .values()
                .all(|state| *state == pathchord_core::PathState::Closed)
        );
    }

    #[tokio::test]
    async fn overlapping_retransmissions_ack_only_after_all_unique_bytes_are_buffered() {
        let (path, mut peer) = admitted_pair().await;
        let session_id = path.session_id();
        let path_id = path.path_id();
        let ready = path.limits().clone();
        let initial = SessionSnapshot {
            session_id,
            path_id,
            ready_paths: 1,
            ready_path_ids: vec![path_id],
            path_states: BTreeMap::from([(path_id, pathchord_core::PathState::Active)]),
            degraded_paths: 0,
            effective_capacity_bps: 0,
            egress_aggregate_capacity_bps: 0,
            target_path_count: 1,
            path_quality: BTreeMap::new(),
            demand: BTreeMap::new(),
            active_streams: 0,
            active_udp_associations: 0,
            pending_session_controls: 0,
            egress_status: None,
            streams: BTreeMap::new(),
            pending_stream_opens: 0,
            retained_outbound_bytes: 0,
            bytes_sent: 0,
            bytes_received: 0,
            closed: false,
            trust_failure: false,
        };
        let (snapshots, _) = watch::channel(initial);
        let mut actor = SessionActor::new(
            path.into_transport(),
            SessionActorInit {
                diagnostics: None,
                role: ActorRole::Ingress,
                udp_factory: None,
                session_id,
                path_id,
                ready,
                commands: None,
                snapshots,
                egress_status: Default::default(),
                status_provider: None,
                capabilities: 0,
                session_replication_budget_bytes: 8 * 1024 * 1024,
                target_open_slots: None,
            },
        )
        .unwrap();
        actor.inbound_budget = Arc::new(Semaphore::new(10));
        let id = StreamId::new(1).unwrap();
        let (io, mut target) = duplex(1024);
        actor
            .spawn_active_stream(
                id,
                Box::new(io),
                None,
                None,
                FlowReplicationBudget::unlimited(8 * 1024 * 1024),
            )
            .unwrap();
        for (offset, bytes, ack_end) in [
            (2, b"cd".as_slice(), 3),
            (6, b"gh".as_slice(), 7),
            (2, b"cd".as_slice(), 3),
            (0, b"abcdefghij".as_slice(), 9),
        ] {
            actor
                .handle_stream_data(
                    path_id,
                    StreamData {
                        stream_id: id,
                        offset,
                        flags: 0,
                        data: bytes.to_vec(),
                    },
                )
                .await
                .unwrap();
            let frame = peer.transport_mut().receive_frame().await.unwrap().unwrap();
            let Message::SessionControl(control) = Message::decode(
                frame.header().frame_type(),
                frame.payload(),
                ProtocolLimits::default(),
            )
            .unwrap() else {
                panic!("expected reliable Stream ACK");
            };
            let Message::StreamAck(ack) = Message::decode(
                control.frame_type,
                &control.payload,
                ProtocolLimits::default(),
            )
            .unwrap() else {
                panic!("expected Stream ACK");
            };
            assert_eq!(
                ack.ranges,
                [AckRange {
                    start: offset,
                    end: ack_end
                }]
            );
            if offset == 2 {
                assert!(actor.inbound_budget.available_permits() >= 6);
            }
        }
        assert_eq!(actor.session_received_total, 10);
        assert!(actor.streams.contains_key(&id));
        let mut bytes = [0_u8; 10];
        tokio::time::timeout(Duration::from_secs(1), target.read_exact(&mut bytes))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&bytes, b"abcdefghij");
        actor.cleanup().await;
    }

    #[tokio::test]
    async fn shared_session_keeps_independent_replication_policies() {
        for _reverse in [false, true] {
            let (path, _peer) = admitted_pair().await;
            let session_id = path.session_id();
            let path_id = path.path_id();
            let ready = path.limits().clone();
            let initial = SessionSnapshot {
                session_id,
                path_id,
                ready_paths: 1,
                ready_path_ids: vec![path_id],
                path_states: BTreeMap::from([(path_id, pathchord_core::PathState::Active)]),
                degraded_paths: 0,
                effective_capacity_bps: 0,
                egress_aggregate_capacity_bps: 0,
                target_path_count: 1,
                path_quality: BTreeMap::new(),
                demand: BTreeMap::new(),
                active_streams: 0,
                active_udp_associations: 0,
                pending_session_controls: 0,
                egress_status: None,
                streams: BTreeMap::new(),
                pending_stream_opens: 0,
                retained_outbound_bytes: 0,
                bytes_sent: 0,
                bytes_received: 0,
                closed: false,
                trust_failure: false,
            };
            let (snapshots, _) = watch::channel(initial);
            let mut actor = SessionActor::new(
                path.into_transport(),
                SessionActorInit {
                    diagnostics: None,
                    role: ActorRole::Ingress,
                    udp_factory: None,
                    session_id,
                    path_id,
                    ready,
                    commands: None,
                    snapshots,
                    egress_status: Default::default(),
                    status_provider: None,
                    capabilities: 0,
                    session_replication_budget_bytes: 8 * 1024 * 1024,
                    target_open_slots: None,
                },
            )
            .unwrap();
            let small = MultipathConfig {
                session_replication_budget_bytes: 1_000,
                default_stream_replication_budget_bytes: 500,
                class_replication_budget_bytes: BTreeMap::from([("a".to_owned(), 400)]),
                ..Default::default()
            };
            let large = MultipathConfig {
                session_replication_budget_bytes: 2_000,
                default_stream_replication_budget_bytes: 1_000,
                class_replication_budget_bytes: BTreeMap::from([
                    ("a".to_owned(), 800),
                    ("b".to_owned(), 1_700),
                ]),
                ..Default::default()
            };
            let small_budget = actor.flow_replication_budget(&small).unwrap();
            let large_budget = actor.flow_replication_budget(&large).unwrap();
            assert_eq!(small_budget.stream_bytes, 500);
            assert_eq!(small_budget.class_bytes, 500);
            assert_eq!(large_budget.stream_bytes, 1_000);
            assert_eq!(large_budget.class_bytes, 1_000);
            assert_eq!(
                actor.multipath.session_replication_budget_bytes(),
                8 * 1024 * 1024
            );
            actor.cleanup().await;
        }
    }
    async fn admitted_pair_with_classes(
        classes: bool,
    ) -> (
        IngressAdmittedPath<DuplexStream>,
        EgressAdmittedPath<DuplexStream>,
    ) {
        let (ingress_key, egress_key) = keys();
        let ingress_config = ingress_config();
        let egress_config = egress_config();
        let _ = classes;
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

    pub(super) async fn admitted_pair_for(
        ingress_key: &StaticKeypair,
        egress_key: &StaticKeypair,
        path_id: u128,
    ) -> (
        IngressAdmittedPath<DuplexStream>,
        EgressAdmittedPath<DuplexStream>,
    ) {
        let mut config = ingress_config();
        config.path_id = PathId::new(path_id);
        admit_duplex_pair(ingress_key, egress_key, config, duplex(512 * 1024)).await
    }

    async fn admit_duplex_pair(
        ingress_key: &StaticKeypair,
        egress_key: &StaticKeypair,
        ingress_config: IngressPathAdmissionConfig,
        (ingress_io, egress_io): (DuplexStream, DuplexStream),
    ) -> (
        IngressAdmittedPath<DuplexStream>,
        EgressAdmittedPath<DuplexStream>,
    ) {
        let egress_config = egress_config();
        let authorization = authorization(ingress_key);
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

    struct FailWrites<S> {
        inner: S,
        fail: Arc<AtomicBool>,
        stall: bool,
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

    impl<S> AsyncRead for FailWrites<S>
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

    impl<S> AsyncWrite for FailWrites<S>
    where
        S: AsyncWrite + Unpin,
    {
        fn poll_write(
            mut self: Pin<&mut Self>,
            context: &mut Context<'_>,
            buffer: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            if self.fail.load(Ordering::Acquire) {
                if self.stall {
                    return Poll::Pending;
                }
                return Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "test Path write failure",
                )));
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

    async fn admitted_pair_for_with_failing_egress_write(
        ingress_key: &StaticKeypair,
        egress_key: &StaticKeypair,
        path_id: u128,
        fail: Arc<AtomicBool>,
        stall: bool,
    ) -> (
        IngressAdmittedPath<DuplexStream>,
        EgressAdmittedPath<FailWrites<DuplexStream>>,
    ) {
        let mut ingress_config = ingress_config();
        ingress_config.path_id = PathId::new(path_id);
        let egress_config = egress_config();
        let authorization = authorization(ingress_key);
        let (ingress_io, egress_io) = duplex(512 * 1024);
        let egress_io = FailWrites {
            inner: egress_io,
            fail,
            stall,
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

    pub(super) fn target(name: &str) -> TargetEndpoint {
        TargetEndpoint {
            hostname: name.as_bytes().to_vec(),
            port: 443,
            resolved_addresses: Vec::<IpAddr>::new(),
        }
    }

    #[derive(Clone, Default)]
    pub(super) struct EchoFactory {
        tasks: Arc<Mutex<Vec<JoinHandle<()>>>>,
    }

    impl EchoFactory {
        pub(super) async fn join(&self) {
            let tasks = std::mem::take(&mut *self.tasks.lock().expect("echo task lock"));
            for task in tasks {
                task.await.expect("echo task");
            }
        }

        pub(super) fn opened_count(&self) -> usize {
            self.tasks.lock().expect("echo task lock").len()
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

    #[derive(Debug)]
    struct SwitchableStatus(AtomicBool);

    impl EgressStatusProvider for SwitchableStatus {
        fn sample(&self) -> EgressStatusSample {
            let mut sample = StaticEgressStatusProvider(EgressStatusConfig::default()).sample();
            if !self.0.load(Ordering::Acquire) {
                sample.service_state = EgressServiceState::Degraded;
                sample.admission_allowed = false;
                sample.admission_reason = AdmissionReason::ResourceLimit;
                sample.effective_capacity_bps = 0;
                sample.capacity_state = CapacityState::Stale;
            }
            sample
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

    #[tokio::test(start_paused = true)]
    async fn existing_stream_keeps_transferring_when_egress_denies_new_admission() {
        let (ingress_path, egress_path) = admitted_pair().await;
        let factory = EchoFactory::default();
        let status = Arc::new(SwitchableStatus(AtomicBool::new(true)));
        let egress = EgressSessionHandle::start_inner(
            egress_path,
            factory.clone(),
            Some(Arc::new(EchoUdpFactory)),
            EgressStatusConfig::default(),
            Some(status.clone()),
            None,
            None,
        )
        .unwrap();
        let ingress = IngressSessionHandle::start(ingress_path).unwrap();
        let mut stream = ingress.open_tcp(target("existing.test")).await.unwrap();
        stream.write_all(b"before").await.unwrap();
        let mut before = [0; 6];
        stream.read_exact(&mut before).await.unwrap();
        assert_eq!(&before, b"before");
        let mut udp = ingress.open_udp(target("existing-udp.test")).await.unwrap();
        udp.send(b"before-udp".to_vec()).await.unwrap();
        assert_eq!(udp.receive().await.unwrap(), b"before-udp");

        status.0.store(false, Ordering::Release);
        for _ in 0..20 {
            tokio::time::advance(Duration::from_millis(250)).await;
            for _ in 0..4 {
                tokio::task::yield_now().await;
            }
            if ingress
                .snapshot()
                .egress_status
                .is_some_and(|value| !value.report.admission_allowed)
            {
                break;
            }
        }
        assert!(
            ingress
                .snapshot()
                .egress_status
                .is_some_and(|value| !value.report.admission_allowed),
            "Ingress must observe the denial before testing the existing Stream"
        );
        assert!(!ingress.snapshot().closed);
        assert!(!factory.tasks.lock().unwrap()[0].is_finished());
        stream.write_all(b"after").await.unwrap();
        let mut after = [0; 5];
        tokio::time::timeout(Duration::from_secs(1), stream.read_exact(&mut after))
            .await
            .expect("existing Stream must continue")
            .expect("existing Stream must remain open");
        assert_eq!(&after, b"after");
        udp.send(b"after-udp".to_vec()).await.unwrap();
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), udp.receive())
                .await
                .expect("existing UDP Association must continue")
                .unwrap(),
            b"after-udp"
        );
        udp.close().await.unwrap();

        assert!(matches!(
            ingress.open_tcp(target("new-tcp.test")).await,
            Err(OpenStreamError::ResourceLimit)
        ));
        assert!(matches!(
            ingress.open_udp(target("new-udp.test")).await,
            Err(OpenUdpError::ResourceLimit)
        ));
        assert_eq!(factory.tasks.lock().unwrap().len(), 1);
        assert!(!ingress.snapshot().closed);

        status.0.store(true, Ordering::Release);
        for _ in 0..20 {
            tokio::time::advance(Duration::from_millis(250)).await;
            for _ in 0..4 {
                tokio::task::yield_now().await;
            }
            if ingress
                .snapshot()
                .egress_status
                .is_some_and(|value| value.report.admission_allowed)
            {
                break;
            }
        }
        assert!(
            ingress
                .snapshot()
                .egress_status
                .is_some_and(|value| value.report.admission_allowed)
        );
        let mut recovered = ingress.open_tcp(target("recovered.test")).await.unwrap();
        recovered.write_all(b"recovered").await.unwrap();
        let mut recovered_echo = [0; 9];
        recovered.read_exact(&mut recovered_echo).await.unwrap();
        assert_eq!(&recovered_echo, b"recovered");
        recovered.shutdown().await.unwrap();
        recovered.read_to_end(&mut Vec::new()).await.unwrap();

        stream.shutdown().await.unwrap();
        stream.read_to_end(&mut Vec::new()).await.unwrap();
        ingress.shutdown().await.unwrap();
        egress.wait().await.unwrap();
        factory.join().await;
    }

    #[tokio::test(start_paused = true)]
    async fn existing_stream_retransmits_lost_data_while_admission_is_denied() {
        let (ingress_key, egress_key) = keys();
        let drop_next = Arc::new(AtomicBool::new(false));
        let (ingress_path, egress_path) = admitted_pair_for_with_dropped_ingress_write(
            &ingress_key,
            &egress_key,
            0x5678,
            Arc::clone(&drop_next),
        )
        .await;
        let factory = EchoFactory::default();
        let status = Arc::new(SwitchableStatus(AtomicBool::new(true)));
        let egress = EgressSessionHandle::start_inner(
            egress_path,
            factory.clone(),
            None,
            EgressStatusConfig::default(),
            Some(status.clone()),
            None,
            None,
        )
        .unwrap();
        let ingress = IngressSessionHandle::start(ingress_path).unwrap();
        let mut stream = ingress.open_tcp(target("loss.test")).await.unwrap();
        status.0.store(false, Ordering::Release);
        for _ in 0..20 {
            tokio::time::advance(Duration::from_millis(250)).await;
            for _ in 0..4 {
                tokio::task::yield_now().await;
            }
            if ingress
                .snapshot()
                .egress_status
                .is_some_and(|value| !value.report.admission_allowed)
            {
                break;
            }
        }
        assert!(
            ingress
                .snapshot()
                .egress_status
                .is_some_and(|value| !value.report.admission_allowed)
        );
        for _ in 0..16 {
            tokio::task::yield_now().await;
        }
        drop_next.store(true, Ordering::Release);
        stream.write_all(b"lost-and-retried").await.unwrap();
        let mut reply = [0; 16];
        tokio::time::timeout(Duration::from_secs(2), stream.read_exact(&mut reply))
            .await
            .expect("lost data should be retransmitted")
            .unwrap();
        assert!(!drop_next.load(Ordering::Acquire));
        assert_eq!(&reply, b"lost-and-retried");
        for _ in 0..8 {
            tokio::task::yield_now().await;
        }
        assert!(
            ingress
                .snapshot()
                .streams
                .values()
                .any(|value| value.retransmissions > 0)
        );

        stream.shutdown().await.unwrap();
        stream.read_to_end(&mut Vec::new()).await.unwrap();
        ingress.shutdown().await.unwrap();
        egress.wait().await.unwrap();
        factory.join().await;
    }

    #[tokio::test(start_paused = true)]
    async fn strict_admission_waits_for_a_fresh_status_without_closing_the_session() {
        let (ingress_path, egress_path) = admitted_pair().await;
        let factory = EchoFactory::default();
        let ingress = IngressSessionHandle::start(ingress_path).unwrap();
        assert!(ingress.snapshot().egress_status.is_none());
        let policy = MultipathConfig {
            require_fresh_status_report: true,
            ..Default::default()
        };
        let paths = BTreeMap::from([(PathId::new(0x5678), 1)]);
        assert!(matches!(
            ingress
                .open_tcp_routed_with_config(target("strict.test"), paths.clone(), policy.clone())
                .await,
            Err(OpenStreamError::ResourceLimit)
        ));
        assert!(!ingress.snapshot().closed);
        assert!(ingress.snapshot().egress_status.is_none());
        let egress = EgressSessionHandle::start(egress_path, factory.clone()).unwrap();
        let mut stream = tokio::time::timeout(
            Duration::from_secs(2),
            ingress.open_tcp_routed_with_config(target("strict.test"), paths, policy),
        )
        .await
        .expect("the first status should unblock admission")
        .unwrap();
        stream.write_all(b"fresh").await.unwrap();
        let mut reply = [0; 5];
        stream.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply, b"fresh");
        stream.shutdown().await.unwrap();
        stream.read_to_end(&mut Vec::new()).await.unwrap();
        ingress.shutdown().await.unwrap();
        egress.wait().await.unwrap();
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
            ..Default::default()
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
        assert!(
            tokio::time::timeout(
                Duration::from_millis(20),
                ingress.wait_path_closed(PathId::new(2)),
            )
            .await
            .is_err(),
            "a draining Path still owns its carrier"
        );
        stream.write_all(b"after-drain").await.unwrap();
        let mut second = [0_u8; 11];
        stream.read_exact(&mut second).await.unwrap();
        assert_eq!(&second, b"after-drain");
        ingress.close_path(PathId::new(2)).await.unwrap();
        tokio::time::timeout(
            Duration::from_secs(1),
            egress_controller.wait_path_closed(PathId::new(2)),
        )
        .await
        .expect("the Egress Path owner observes carrier retirement");
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
    async fn rule_minimum_counts_only_eligible_paths_for_tcp_and_udp() {
        tokio::time::timeout(Duration::from_secs(5), async {
            let (ingress_key, egress_key) = keys();
            let (i1, e1) = admitted_pair_for(&ingress_key, &egress_key, 401).await;
            let (i2, e2) = admitted_pair_for(&ingress_key, &egress_key, 402).await;
            let factory = EchoFactory::default();
            let egress =
                EgressSessionHandle::start_with_udp(e1, factory.clone(), EchoUdpFactory).unwrap();
            let ingress = IngressSessionHandle::start(i1).unwrap();
            egress
                .controller()
                .add_path(e2, MultipathPathObservation::default())
                .await
                .unwrap();
            ingress
                .add_path(i2, MultipathPathObservation::default())
                .await
                .unwrap();
            let policy = MultipathConfig {
                minimum_usable_paths: 2,
                ..Default::default()
            };
            let only_one = BTreeMap::from([(PathId::new(401), 100)]);
            assert!(!ingress.snapshot().closed);
            let mut stream = ingress
                .open_tcp_routed_with_config(
                    target("minimum.test"),
                    only_one.clone(),
                    policy.clone(),
                )
                .await
                .unwrap();
            let mut udp = ingress
                .open_udp_routed_with_config(target("minimum-udp.test"), only_one, policy)
                .await
                .unwrap();
            ingress.close_path(PathId::new(401)).await.unwrap();
            stream.write_all(b"still-running").await.unwrap();
            let mut reply = [0; 13];
            stream.read_exact(&mut reply).await.unwrap();
            assert_eq!(&reply, b"still-running");
            udp.send(b"still-running".to_vec()).await.unwrap();
            assert_eq!(udp.receive().await.unwrap(), b"still-running");
            udp.close().await.unwrap();
            stream.shutdown().await.unwrap();
            stream.read_to_end(&mut Vec::new()).await.unwrap();
            ingress.shutdown().await.unwrap();
            egress.wait().await.unwrap();
            factory.join().await;
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn business_response_path_failure_keeps_the_other_path_alive() {
        for stall in [false, true] {
            tokio::time::timeout(Duration::from_secs(6), async {
                let (ingress_key, egress_key) = keys();
                let (ingress_primary, egress_primary) =
                    admitted_pair_for(&ingress_key, &egress_key, 302).await;
                let fail = Arc::new(AtomicBool::new(false));
                let (ingress_secondary, egress_secondary) =
                    admitted_pair_for_with_failing_egress_write(
                        &ingress_key,
                        &egress_key,
                        301,
                        Arc::clone(&fail),
                        stall,
                    )
                    .await;
                let factory = EchoFactory::default();
                let history = Arc::new(
                    DiagnosticHistory::new(crate::diagnostics::DiagnosticRole::Egress).unwrap(),
                );
                let egress = EgressSessionHandle::start_inner(
                    egress_primary,
                    factory.clone(),
                    None,
                    EgressStatusConfig::default(),
                    None,
                    None,
                    Some(SessionDiagnostics {
                        history: Arc::clone(&history),
                        egress_id: "egress-test".to_owned(),
                        attribution: None,
                    }),
                )
                .unwrap();
                let egress_controller = egress.controller();
                let ingress = IngressSessionHandle::start(ingress_primary).unwrap();
                egress_controller
                    .add_path(egress_secondary, MultipathPathObservation::default())
                    .await
                    .unwrap();
                ingress
                    .add_path(ingress_secondary, MultipathPathObservation::default())
                    .await
                    .unwrap();

                // Path 301 is first in the control-copy order. Its writer fails
                // after admission, so the Egress response must be retried over
                // Path 302 instead of closing the Session.
                fail.store(true, Ordering::Release);
                let mut stream = tokio::time::timeout(
                    Duration::from_secs(4),
                    ingress.open_tcp(target("response-failover.test")),
                )
                .await
                .expect("Stream open should fail over to the surviving Path")
                .expect("Stream should remain admissible");
                stream.write_all(b"surviving-path").await.unwrap();
                let mut echoed = [0_u8; 14];
                stream.read_exact(&mut echoed).await.unwrap();
                assert_eq!(&echoed, b"surviving-path");
                assert!(!ingress.snapshot().closed);
                assert_eq!(ingress.snapshot().ready_paths, 1);
                assert_eq!(egress_controller.snapshot().ready_paths, 1);

                let records = history.snapshot().records;
                assert_eq!(records.len(), 1);
                assert_eq!(records[0].ids.path_id, Some(PathId::new(301)));
                let expected_reason = if stall {
                    PathTerminationReason::WriteTimeout
                } else {
                    PathTerminationReason::WriteError
                };
                assert!(
                    matches!(
                        records[0].detail,
                        DiagnosticDetail::PathTermination { reason, write_elapsed_ms, .. }
                            if reason == expected_reason && write_elapsed_ms.is_some() == stall
                    ),
                    "{:?}",
                    records[0]
                );

                stream.shutdown().await.unwrap();
                stream.read_to_end(&mut Vec::new()).await.unwrap();
                ingress.shutdown().await.unwrap();
                egress.wait().await.unwrap();
                let records = history.snapshot().records;
                assert_eq!(records.len(), 3);
                assert_eq!(
                    records
                        .iter()
                        .filter(|record| record.ids.path_id == Some(PathId::new(301)))
                        .count(),
                    1
                );
                assert!(matches!(
                    records[2].detail,
                    DiagnosticDetail::SessionTermination { .. }
                ));
                factory.join().await;
            })
            .await
            .unwrap();
        }
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
            ..Default::default()
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
        assert!(ingress.snapshot().egress_status.is_none());
        tokio::time::advance(Duration::from_millis(2_100)).await;
        for _ in 0..20 {
            tokio::task::yield_now().await;
        }
        assert_eq!(ingress.snapshot().degraded_paths, 0);
        for _ in 0..20 {
            if ingress.snapshot().egress_status.is_some() {
                break;
            }
            tokio::time::advance(Duration::from_millis(100)).await;
            tokio::task::yield_now().await;
        }
        let sample = ingress
            .snapshot()
            .egress_status
            .expect("authenticated status report");
        assert!(sample.fresh);
        assert_eq!(
            sample.report.configured_capacity_bps,
            EgressStatusConfig::default().capacity_bps
        );
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
    async fn delayed_heartbeat_acks_do_not_multiply_probes() {
        let (path, mut peer) = admitted_pair().await;
        let ingress = IngressSessionHandle::start(path).unwrap();
        for expected in [0, 0, 0, 0, 1] {
            let frame = tokio::time::timeout(
                HEARTBEAT_INTERVAL + MIN_RETRANSMISSION_TIMEOUT,
                peer.transport_mut().receive_frame(),
            )
            .await
            .expect("a Path must continue to send liveness probes")
            .unwrap()
            .unwrap();
            let message = Message::decode(
                frame.header().frame_type(),
                frame.payload(),
                ProtocolLimits::default(),
            )
            .unwrap();
            assert_eq!(
                message,
                Message::Heartbeat(Heartbeat {
                    control_seq: expected
                })
            );
        }
        let limits = peer.transport_mut().limits();
        let ack = Message::ControlAck(ControlAck {
            highest_contiguous: 1,
            ranges: Vec::new(),
        });
        let frame = PathFrame::new(
            ack.frame_type(),
            FrameFlags::empty(),
            peer.session_id(),
            peer.path_id(),
            peer.transport_mut().transport.next_send_nonce().unwrap(),
            ack.encode(limits).unwrap(),
            limits,
        )
        .unwrap();
        peer.transport_mut().send_frame(frame).await.unwrap();
        tokio::time::timeout(MIN_RETRANSMISSION_TIMEOUT, async {
            while ingress.snapshot().path_quality[&peer.path_id()].control_pending > 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("late cumulative ACK must release both sequences");
        drop(peer);
        drop(ingress);
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
    async fn egress_status_config_does_not_enforce_per_ingress_stream_limit() {
        let (ingress_path, egress_path) = admitted_pair().await;
        let factory = EchoFactory::default();
        let egress = EgressSessionHandle::start_with_status(
            egress_path,
            factory.clone(),
            EgressStatusConfig {
                capacity_bps: 10_000_000,
                ..EgressStatusConfig::default()
            },
        )
        .unwrap();
        let ingress = IngressSessionHandle::start(ingress_path).unwrap();
        let mut first = ingress.open_tcp(target("first.test")).await.unwrap();
        let mut second = ingress.open_tcp(target("second.test")).await.unwrap();
        first.write_all(b"first").await.unwrap();
        second.write_all(b"second").await.unwrap();
        let mut first_echo = [0_u8; 5];
        let mut second_echo = [0_u8; 6];
        first.read_exact(&mut first_echo).await.unwrap();
        second.read_exact(&mut second_echo).await.unwrap();
        assert_eq!(&first_echo, b"first");
        assert_eq!(&second_echo, b"second");
        first.shutdown().await.unwrap();
        first.read_to_end(&mut Vec::new()).await.unwrap();
        second.shutdown().await.unwrap();
        second.read_to_end(&mut Vec::new()).await.unwrap();
        ingress.shutdown().await.unwrap();
        egress.wait().await.unwrap();
        factory.join().await;
    }

    #[tokio::test]
    async fn routed_stream_uses_the_common_session_pool() {
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
            ..Default::default()
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
        blocked.store(false, Ordering::Release);
        stream.shutdown().await.unwrap();
        stream.read_to_end(&mut Vec::new()).await.unwrap();
        ingress.shutdown().await.unwrap();
        egress.wait().await.unwrap();
        factory.join().await;
    }
    async fn class_pair_dropping_first_business_frame(
        drop_next: Arc<AtomicBool>,
    ) -> (
        IngressAdmittedPath<DropNextWrite<DuplexStream>>,
        EgressAdmittedPath<DuplexStream>,
    ) {
        let (ingress_key, egress_key) = keys();
        let ingress = ingress_config();
        let egress = egress_config();
        let authorization = authorization(&ingress_key);
        let (a, b) = duplex(512 * 1024);
        let (i, e) = tokio::join!(
            dial_path(
                DropNextWrite {
                    inner: a,
                    drop_next
                },
                ingress_key.private(),
                egress_key.public(),
                &ingress
            ),
            accept_path(b, egress_key.private(), &egress, &authorization)
        );
        let PathAdmissionOutcome::Ready(i) = i.unwrap() else {
            panic!("Ingress")
        };
        let PathAdmissionOutcome::Ready(e) = e.unwrap() else {
            panic!("Egress")
        };
        (i, e)
    }

    #[tokio::test]
    async fn class_open_retries_a_lost_request_and_preserves_single_target_open() {
        tokio::time::timeout(Duration::from_secs(5), async {
            let dropped = Arc::new(AtomicBool::new(false));
            let (i, e) = class_pair_dropping_first_business_frame(dropped.clone()).await;
            let factory = EchoFactory::default();
            let egress = EgressSessionHandle::start(e, factory.clone()).unwrap();
            let ingress = IngressSessionHandle::start(i).unwrap();
            dropped.store(true, Ordering::Release);
            let mut stream = ingress
                .open_tcp_routed_with_config(
                    target("retry-class.test"),
                    Default::default(),
                    MultipathConfig {
                        traffic_class: Some(class("priority", 10, 2)),
                        ..Default::default()
                    },
                )
                .await
                .unwrap();
            stream.write_all(b"retry").await.unwrap();
            stream.shutdown().await.unwrap();
            let mut bytes = Vec::new();
            stream.read_to_end(&mut bytes).await.unwrap();
            assert_eq!(bytes, b"retry");
            assert_eq!(factory.tasks.lock().unwrap().len(), 1);
            ingress.shutdown().await.unwrap();
            egress.wait().await.unwrap();
            factory.join().await;
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn ordinary_stream_open_retries_a_lost_control_without_redialing() {
        tokio::time::timeout(Duration::from_secs(5), async {
            let (ingress_key, egress_key) = keys();
            let drop_next = Arc::new(AtomicBool::new(false));
            let (i, e) = admitted_pair_for_with_dropped_ingress_write(
                &ingress_key,
                &egress_key,
                77,
                Arc::clone(&drop_next),
            )
            .await;
            let factory = EchoFactory::default();
            let egress = EgressSessionHandle::start(e, factory.clone()).unwrap();
            let ingress = IngressSessionHandle::start(i).unwrap();
            drop_next.store(true, Ordering::Release);
            let mut stream = ingress.open_tcp(target("retry.test")).await.unwrap();
            assert!(!drop_next.load(Ordering::Acquire));
            stream.write_all(b"once").await.unwrap();
            stream.shutdown().await.unwrap();
            let mut echoed = Vec::new();
            stream.read_to_end(&mut echoed).await.unwrap();
            assert_eq!(echoed, b"once");
            assert_eq!(factory.tasks.lock().unwrap().len(), 1);
            ingress.shutdown().await.unwrap();
            egress.wait().await.unwrap();
            factory.join().await;
        })
        .await
        .unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn unacknowledged_control_retries_on_another_ready_path_without_replication() {
        let (ik, ek) = keys();
        let config = |id| IngressPathAdmissionConfig {
            path_id: PathId::new(id),
            replication_budget_bytes_per_second: 0,
            ..ingress_config()
        };
        let (i, mut left) = duplex(512 * 1024);
        let (mut right, e) = duplex(512 * 1024);
        let mut relay =
            Box::pin(async move { tokio::io::copy_bidirectional(&mut left, &mut right).await });
        let (i1, e1) = tokio::select! {
            pair = admit_duplex_pair(&ik, &ek, config(1), (i, e)) => pair,
            result = &mut relay => panic!("first Path closed during admission: {result:?}"),
        };
        let (i2, e2) = admit_duplex_pair(&ik, &ek, config(2), duplex(512 * 1024)).await;
        let factory = EchoFactory::default();
        let egress = EgressSessionHandle::start(e1, factory.clone()).unwrap();
        let ingress = IngressSessionHandle::start(i1).unwrap();
        egress
            .controller()
            .add_path(e2, Default::default())
            .await
            .unwrap();
        ingress.add_path(i2, Default::default()).await.unwrap();

        // Keep both Paths attached but delay all records on the first until
        // the second has delivered the retried open. No record is discarded.
        let mut open = Box::pin(ingress.open_tcp(target("slow-control.test")));
        assert!(
            tokio::time::timeout(MIN_RETRANSMISSION_TIMEOUT / 2, &mut open)
                .await
                .is_err()
        );
        let mut stream = tokio::time::timeout(MIN_RETRANSMISSION_TIMEOUT * 5, open)
            .await
            .expect("the open should complete while both Paths are still ready")
            .unwrap();
        assert_eq!(ingress.snapshot().ready_paths, 2);
        let relay_task = tokio::spawn(relay);
        stream.write_all(b"once").await.unwrap();
        stream.shutdown().await.unwrap();
        let mut echoed = Vec::new();
        stream.read_to_end(&mut echoed).await.unwrap();
        assert_eq!(echoed, b"once");
        assert_eq!(factory.tasks.lock().unwrap().len(), 1);
        ingress.shutdown().await.unwrap();
        egress.wait().await.unwrap();
        factory.join().await;
        relay_task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn losing_one_path_does_not_cancel_other_flows_in_the_common_pool() {
        tokio::time::timeout(Duration::from_secs(5), async {
            let (ik, ek) = keys();
            let drop_next = Arc::new(AtomicBool::new(false));
            let (i1, e1) =
                admitted_pair_for_with_dropped_ingress_write(&ik, &ek, 201, drop_next.clone())
                    .await;
            let (i2, e2) = admitted_pair_for(&ik, &ek, 202).await;
            let factory = EchoFactory::default();
            let egress = EgressSessionHandle::start(e1, factory.clone()).unwrap();
            let ingress = IngressSessionHandle::start(i1).unwrap();
            egress
                .controller()
                .add_path(e2, MultipathPathObservation::default())
                .await
                .unwrap();
            ingress
                .add_path(i2, MultipathPathObservation::default())
                .await
                .unwrap();
            let mut healthy = ingress
                .open_tcp_routed(
                    target("healthy.test"),
                    BTreeMap::from([(PathId::new(202), 1)]),
                )
                .await
                .unwrap();
            tokio::time::sleep(Duration::from_millis(150)).await;
            let mut pooled = ingress
                .open_tcp_routed(
                    target("pooled-lost.test"),
                    BTreeMap::from([(PathId::new(201), 1)]),
                )
                .await
                .expect("common pool open");
            pooled.write_all(b"pooled").await.unwrap();
            let mut pooled_echo = [0_u8; 6];
            pooled.read_exact(&mut pooled_echo).await.unwrap();
            assert_eq!(&pooled_echo, b"pooled");
            healthy.write_all(b"still-live").await.unwrap();
            let mut echoed = [0_u8; 10];
            healthy.read_exact(&mut echoed).await.unwrap();
            assert_eq!(&echoed, b"still-live");
            let mut later = ingress
                .open_tcp_routed(
                    target("later.test"),
                    BTreeMap::from([(PathId::new(202), 1)]),
                )
                .await
                .unwrap();
            later.write_all(b"later").await.unwrap();
            let mut later_echo = [0_u8; 5];
            later.read_exact(&mut later_echo).await.unwrap();
            assert_eq!(&later_echo, b"later");
            assert_eq!(
                factory.tasks.lock().unwrap().len(),
                3,
                "all common-pool opens are admitted exactly once"
            );
            pooled.shutdown().await.unwrap();
            pooled.read_to_end(&mut Vec::new()).await.unwrap();
            healthy.shutdown().await.unwrap();
            later.shutdown().await.unwrap();
            healthy.read_to_end(&mut Vec::new()).await.unwrap();
            later.read_to_end(&mut Vec::new()).await.unwrap();
            ingress.shutdown().await.unwrap();
            egress.wait().await.unwrap();
            factory.join().await;
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn losing_one_path_keeps_an_open_flow_on_the_common_pool() {
        tokio::time::timeout(Duration::from_secs(5), async {
            let (ik, ek) = keys();
            let (i1, e1) = admitted_pair_for(&ik, &ek, 203).await;
            let (i2, e2) = admitted_pair_for(&ik, &ek, 204).await;
            let factory = EchoFactory::default();
            let egress = EgressSessionHandle::start(e1, factory.clone()).unwrap();
            let ingress = IngressSessionHandle::start(i1).unwrap();
            egress
                .controller()
                .add_path(e2, MultipathPathObservation::default())
                .await
                .unwrap();
            ingress
                .add_path(i2, MultipathPathObservation::default())
                .await
                .unwrap();
            let mut healthy = ingress
                .open_tcp_routed(
                    target("healthy.test"),
                    BTreeMap::from([(PathId::new(204), 1)]),
                )
                .await
                .unwrap();
            let mut lost = ingress
                .open_tcp_routed(target("lost.test"), BTreeMap::from([(PathId::new(203), 1)]))
                .await
                .unwrap();
            lost.write_all(b"survives").await.unwrap();
            let mut lost_echo = [0_u8; 8];
            lost.read_exact(&mut lost_echo).await.unwrap();
            assert_eq!(&lost_echo, b"survives");
            healthy.write_all(b"alive").await.unwrap();
            let mut echoed = [0_u8; 5];
            healthy.read_exact(&mut echoed).await.unwrap();
            assert_eq!(&echoed, b"alive");
            assert!(!factory.tasks.lock().unwrap()[1].is_finished());
            lost.shutdown().await.unwrap();
            lost.read_to_end(&mut Vec::new()).await.unwrap();
            healthy.shutdown().await.unwrap();
            healthy.read_to_end(&mut Vec::new()).await.unwrap();
            ingress.shutdown().await.unwrap();
            egress.wait().await.unwrap();
            factory.join().await;
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn zero_replication_budget_still_recovers_lost_tcp_data() {
        tokio::time::timeout(Duration::from_secs(5), async {
            let (ik, ek) = keys();
            let drop_next = Arc::new(AtomicBool::new(false));
            let (i, e) =
                admitted_pair_for_with_dropped_ingress_write(&ik, &ek, 78, Arc::clone(&drop_next))
                    .await;
            let factory = EchoFactory::default();
            let egress = EgressSessionHandle::start(e, factory.clone()).unwrap();
            let ingress = IngressSessionHandle::start(i).unwrap();
            let mut stream = ingress
                .open_tcp_routed_with_config(
                    target("no-replication.test"),
                    BTreeMap::from([(PathId::new(78), 1)]),
                    MultipathConfig {
                        session_replication_budget_bytes: 0,
                        default_stream_replication_budget_bytes: 0,
                        retransmission_replication_enabled: false,
                        ..Default::default()
                    },
                )
                .await
                .unwrap();
            tokio::time::sleep(Duration::from_millis(150)).await;
            drop_next.store(true, Ordering::Release);
            stream.write_all(b"recover").await.unwrap();
            let mut echoed = [0_u8; 7];
            stream.read_exact(&mut echoed).await.unwrap();
            assert!(!drop_next.load(Ordering::Acquire));
            assert_eq!(&echoed, b"recover");
            stream.shutdown().await.unwrap();
            stream.read_to_end(&mut Vec::new()).await.unwrap();
            ingress.shutdown().await.unwrap();
            egress.wait().await.unwrap();
            factory.join().await;
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn zero_replication_budget_preserves_eligible_failover() {
        tokio::time::timeout(Duration::from_secs(5), async {
            let (ik, ek) = keys();
            let drop_next = Arc::new(AtomicBool::new(false));
            let (i1, e1) =
                admitted_pair_for_with_dropped_ingress_write(&ik, &ek, 91, Arc::clone(&drop_next))
                    .await;
            let (i2, e2) = admitted_pair_for(&ik, &ek, 92).await;
            let factory = EchoFactory::default();
            let egress = EgressSessionHandle::start(e1, factory.clone()).unwrap();
            let ingress = IngressSessionHandle::start(i1).unwrap();
            egress
                .controller()
                .add_path(e2, MultipathPathObservation::default())
                .await
                .unwrap();
            ingress
                .add_path(i2, MultipathPathObservation::default())
                .await
                .unwrap();
            let mut stream = ingress
                .open_tcp_routed_with_config(
                    target("zero-budget-failover.test"),
                    BTreeMap::from([(PathId::new(91), 1), (PathId::new(92), 1)]),
                    MultipathConfig {
                        session_replication_budget_bytes: 0,
                        default_stream_replication_budget_bytes: 0,
                        retransmission_replication_enabled: false,
                        ..Default::default()
                    },
                )
                .await
                .unwrap();
            tokio::time::sleep(Duration::from_millis(150)).await;
            drop_next.store(true, Ordering::Release);
            stream.write_all(b"recovered").await.unwrap();
            for _ in 0..100 {
                if !drop_next.load(Ordering::Acquire) {
                    break;
                }
                tokio::task::yield_now().await;
            }
            assert!(!drop_next.load(Ordering::Acquire));
            ingress.close_path(PathId::new(91)).await.unwrap();
            let mut echoed = [0_u8; 9];
            stream.read_exact(&mut echoed).await.unwrap();
            assert_eq!(&echoed, b"recovered");
            stream.shutdown().await.unwrap();
            stream.read_to_end(&mut Vec::new()).await.unwrap();
            ingress.shutdown().await.unwrap();
            egress.wait().await.unwrap();
            factory.join().await;
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn allowed_replication_sends_an_extra_copy_on_another_eligible_path() {
        tokio::time::timeout(Duration::from_secs(5), async {
            let (ik, ek) = keys();
            let drop_a = Arc::new(AtomicBool::new(false));
            let drop_b = Arc::new(AtomicBool::new(false));
            let (i1, e1) =
                admitted_pair_for_with_dropped_ingress_write(&ik, &ek, 101, drop_a.clone()).await;
            let (i2, e2) =
                admitted_pair_for_with_dropped_ingress_write(&ik, &ek, 102, drop_b.clone()).await;
            let factory = EchoFactory::default();
            let egress = EgressSessionHandle::start(e1, factory.clone()).unwrap();
            let ingress = IngressSessionHandle::start(i1).unwrap();
            egress
                .controller()
                .add_path(e2, MultipathPathObservation::default())
                .await
                .unwrap();
            ingress
                .add_path(i2, MultipathPathObservation::default())
                .await
                .unwrap();
            let mut stream = ingress
                .open_tcp_routed_with_config(
                    target("extra-replica.test"),
                    BTreeMap::from([(PathId::new(101), 1), (PathId::new(102), 1)]),
                    MultipathConfig {
                        session_replication_budget_bytes: 10_000,
                        default_stream_replication_budget_bytes: 10_000,
                        retransmission_replication_enabled: true,
                        ..Default::default()
                    },
                )
                .await
                .unwrap();
            tokio::time::sleep(Duration::from_millis(150)).await;
            drop_a.store(true, Ordering::Release);
            drop_b.store(true, Ordering::Release);
            stream.write_all(b"two-paths").await.unwrap();
            let mut echoed = [0_u8; 9];
            stream.read_exact(&mut echoed).await.unwrap();
            assert_eq!(&echoed, b"two-paths");
            assert!(!drop_a.load(Ordering::Acquire) && !drop_b.load(Ordering::Acquire));
            assert_eq!(
                ingress
                    .snapshot()
                    .streams
                    .values()
                    .next()
                    .unwrap()
                    .retransmissions,
                1
            );
            stream.shutdown().await.unwrap();
            stream.read_to_end(&mut Vec::new()).await.unwrap();
            ingress.shutdown().await.unwrap();
            egress.wait().await.unwrap();
            factory.join().await;
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn session_close_retries_after_lost_control_or_ack() {
        for lose_ack in [false, true] {
            tokio::time::timeout(Duration::from_secs(3), async {
                let drop_next = Arc::new(AtomicBool::new(false));
                if lose_ack {
                    let (i, e) =
                        admitted_pair_with_dropped_egress_write(Arc::clone(&drop_next)).await;
                    let egress = EgressSessionHandle::start(e, EchoFactory::default()).unwrap();
                    let ingress = IngressSessionHandle::start(i).unwrap();
                    drop_next.store(true, Ordering::Release);
                    ingress.shutdown().await.unwrap();
                    assert!(!drop_next.load(Ordering::Acquire));
                    egress.wait().await.unwrap();
                } else {
                    let (ik, ek) = keys();
                    let (i, e) = admitted_pair_for_with_dropped_ingress_write(
                        &ik,
                        &ek,
                        79,
                        Arc::clone(&drop_next),
                    )
                    .await;
                    let egress = EgressSessionHandle::start(e, EchoFactory::default()).unwrap();
                    let ingress = IngressSessionHandle::start(i).unwrap();
                    drop_next.store(true, Ordering::Release);
                    ingress.shutdown().await.unwrap();
                    assert!(!drop_next.load(Ordering::Acquire));
                    egress.wait().await.unwrap();
                }
            })
            .await
            .unwrap();
        }
    }

    #[tokio::test]
    async fn reordered_session_controls_wait_for_predecessors_and_deduplicate() {
        tokio::time::timeout(Duration::from_secs(5), async {
            let (i, e) = admitted_pair().await;
            let session_id = i.session_id();
            let path_id = i.path_id();
            let (mut io, mut noise) = i.into_transport().into_parts();
            let factory = EchoFactory::default();
            let egress = EgressSessionHandle::start(e, factory.clone()).unwrap();
            async fn send(
                io: &mut DuplexStream,
                noise: &mut NoiseTransport,
                session_id: SessionId,
                path_id: PathId,
                sequence: u64,
                inner: Message,
            ) {
                let limits = ProtocolLimits::default();
                let control = Message::SessionControl(SessionControl {
                    sequence,
                    depends_on: sequence.checked_sub(1),
                    frame_type: inner.frame_type(),
                    eligible_paths: Vec::new(),
                    payload: inner.encode(limits).unwrap(),
                });
                let frame = PathFrame::new(
                    control.frame_type(),
                    FrameFlags::empty(),
                    session_id,
                    path_id,
                    noise.next_send_nonce().unwrap(),
                    control.encode(limits).unwrap(),
                    limits,
                )
                .unwrap();
                io.write_all(&noise.seal_frame(&frame, limits).unwrap().encode())
                    .await
                    .unwrap();
            }
            let open = |id| {
                Message::StreamOpen(StreamOpen {
                    stream_id: StreamId::new(id).unwrap(),
                    request_id: RequestId::new(id as u128),
                    target: target("ordered.test"),
                })
            };
            send(&mut io, &mut noise, session_id, path_id, 1, open(2)).await;
            tokio::time::sleep(Duration::from_millis(20)).await;
            assert!(factory.tasks.lock().unwrap().is_empty());
            send(&mut io, &mut noise, session_id, path_id, 0, open(1)).await;
            for _ in 0..100 {
                if egress.controller().snapshot().active_streams == 2 {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            assert_eq!(factory.tasks.lock().unwrap().len(), 2);
            send(&mut io, &mut noise, session_id, path_id, 0, open(1)).await;
            tokio::time::sleep(Duration::from_millis(20)).await;
            assert_eq!(factory.tasks.lock().unwrap().len(), 2);
            send(
                &mut io,
                &mut noise,
                session_id,
                path_id,
                2,
                Message::SessionClose(SessionClose {
                    error: ErrorClass::PathFailure,
                    reason: Vec::new(),
                }),
            )
            .await;
            // Wait for the peer to consume SessionClose before closing the
            // synthetic carrier. A fixed sleep races the actor on Windows and
            // can turn orderly Session shutdown into an unrelated PathClosed.
            let limits = ProtocolLimits::default();
            let mut peer = NoiseRecordStream::new(io, noise, limits);
            loop {
                let frame = crate::CompleteFrameTransport::receive_frame(&mut peer)
                    .await
                    .unwrap()
                    .expect("peer acknowledges SessionClose before carrier closure");
                if matches!(
                    Message::decode(frame.header().frame_type(), frame.payload(), limits).unwrap(),
                    Message::SessionControlAck(ack) if ack.highest_contiguous == 2
                ) {
                    break;
                }
            }
            drop(peer);
            egress.wait().await.unwrap();
            factory.join().await;
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn cancellation_before_original_control_prevents_late_open() {
        tokio::time::timeout(Duration::from_secs(5), async {
            let (i, e) = admitted_pair().await;
            let session_id = i.session_id();
            let path_id = i.path_id();
            let (mut io, mut noise) = i.into_transport().into_parts();
            let factory = EchoFactory::default();
            let egress = EgressSessionHandle::start(e, factory.clone()).unwrap();
            async fn send(
                io: &mut DuplexStream,
                noise: &mut NoiseTransport,
                session: SessionId,
                path: PathId,
                message: Message,
            ) {
                let limits = ProtocolLimits::default();
                let frame = PathFrame::new(
                    message.frame_type(),
                    FrameFlags::empty(),
                    session,
                    path,
                    noise.next_send_nonce().unwrap(),
                    message.encode(limits).unwrap(),
                    limits,
                )
                .unwrap();
                io.write_all(&noise.seal_frame(&frame, limits).unwrap().encode())
                    .await
                    .unwrap();
            }
            let open = |sequence: u64, id: u64| {
                let inner = Message::StreamOpen(StreamOpen {
                    stream_id: StreamId::new(id).unwrap(),
                    request_id: RequestId::new(u128::from(id)),
                    target: target("never-open-cancelled.test"),
                });
                Message::SessionControl(SessionControl {
                    sequence,
                    depends_on: sequence.checked_sub(1),
                    frame_type: inner.frame_type(),
                    eligible_paths: Vec::new(),
                    payload: inner.encode(ProtocolLimits::default()).unwrap(),
                })
            };
            let cancel = Message::SessionControlCancel(SessionControlCancel {
                sequence: 1,
                flow: SessionControlFlow::Stream(StreamId::new(2).unwrap()),
            });
            send(&mut io, &mut noise, session_id, path_id, cancel).await;
            send(&mut io, &mut noise, session_id, path_id, open(1, 2)).await;
            send(&mut io, &mut noise, session_id, path_id, open(0, 1)).await;
            for _ in 0..100 {
                if egress.controller().snapshot().active_streams == 1 {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            send(&mut io, &mut noise, session_id, path_id, open(1, 2)).await;
            send(&mut io, &mut noise, session_id, path_id, open(2, 3)).await;
            for _ in 0..100 {
                if egress.controller().snapshot().active_streams == 2 {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            assert_eq!(factory.tasks.lock().unwrap().len(), 2);
            let close = Message::SessionClose(SessionClose {
                error: ErrorClass::PathFailure,
                reason: Vec::new(),
            });
            send(
                &mut io,
                &mut noise,
                session_id,
                path_id,
                Message::SessionControl(SessionControl {
                    sequence: 3,
                    depends_on: Some(2),
                    frame_type: close.frame_type(),
                    eligible_paths: Vec::new(),
                    payload: close.encode(ProtocolLimits::default()).unwrap(),
                }),
            )
            .await;
            tokio::time::sleep(Duration::from_millis(20)).await;
            drop(io);
            egress.wait().await.unwrap();
            factory.join().await;
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn replicated_open_is_applied_once_and_survives_first_path_loss() {
        tokio::time::timeout(Duration::from_secs(5), async {
            let (ingress_key, egress_key) = keys();
            let (i1, e1) = admitted_pair_for(&ingress_key, &egress_key, 81).await;
            let (i2, e2) = admitted_pair_for(&ingress_key, &egress_key, 82).await;
            let factory = EchoFactory::default();
            let egress = EgressSessionHandle::start(e1, factory.clone()).unwrap();
            let ingress = IngressSessionHandle::start(i1).unwrap();
            egress
                .controller()
                .add_path(e2, MultipathPathObservation::default())
                .await
                .unwrap();
            ingress
                .add_path(i2, MultipathPathObservation::default())
                .await
                .unwrap();
            let mut stream = ingress
                .open_tcp_routed(
                    target("replicated.test"),
                    BTreeMap::from([(PathId::new(81), 1), (PathId::new(82), 1)]),
                )
                .await
                .unwrap();
            tokio::time::sleep(Duration::from_millis(30)).await;
            assert_eq!(factory.tasks.lock().unwrap().len(), 1);
            ingress.close_path(PathId::new(81)).await.unwrap();
            stream.write_all(b"survived").await.unwrap();
            stream.shutdown().await.unwrap();
            let mut echoed = Vec::new();
            stream.read_to_end(&mut echoed).await.unwrap();
            assert_eq!(echoed, b"survived");
            ingress.shutdown().await.unwrap();
            egress.wait().await.unwrap();
            factory.join().await;
        })
        .await
        .unwrap();
    }

    fn class(name: &str, priority: u8, share: u32) -> TrafficClassConfig {
        TrafficClassConfig {
            name: name.to_owned(),
            priority,
            share,
        }
    }

    #[test]
    fn ack_ranges_must_be_covered_by_emitted_intervals() {
        let emitted = [
            AckRange { start: 0, end: 4 },
            AckRange { start: 10, end: 14 },
        ];
        assert!(
            SessionActor::<WriteHalf<DuplexStream>>::ack_range_is_emitted(
                &emitted,
                AckRange { start: 1, end: 4 }
            )
        );
        assert!(
            SessionActor::<WriteHalf<DuplexStream>>::ack_range_is_emitted(
                &emitted,
                AckRange { start: 10, end: 14 }
            )
        );
        assert!(
            !SessionActor::<WriteHalf<DuplexStream>>::ack_range_is_emitted(
                &emitted,
                AckRange { start: 5, end: 10 }
            )
        );
        assert!(
            !SessionActor::<WriteHalf<DuplexStream>>::ack_range_is_emitted(
                &emitted,
                AckRange { start: 0, end: 15 }
            )
        );
    }

    #[tokio::test]
    async fn class_metadata_stays_on_ingress_while_egress_uses_uniform_wire_open() {
        tokio::time::timeout(Duration::from_secs(5), async {
            let (ingress_path, egress_path) = admitted_pair_with_classes(true).await;
            let factory = EchoFactory::default();
            let egress = EgressSessionHandle::start(egress_path, factory.clone()).unwrap();
            let ingress = IngressSessionHandle::start(ingress_path).unwrap();
            let profile = class("interactive", 200, 3);
            let mut stream = ingress
                .open_tcp_routed_with_config(
                    target("class.test"),
                    BTreeMap::new(),
                    MultipathConfig {
                        traffic_class: Some(profile.clone()),
                        ..Default::default()
                    },
                )
                .await
                .unwrap();
            let payload = vec![0x7a; 48 * 1024];
            stream.write_all(&payload).await.unwrap();
            stream.shutdown().await.unwrap();
            let mut echoed = Vec::new();
            stream.read_to_end(&mut echoed).await.unwrap();
            assert_eq!(echoed, payload);
            for _ in 0..30 {
                if ingress
                    .snapshot()
                    .streams
                    .values()
                    .any(|stream| stream.closed_at_ms.is_some())
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
            let observed = ingress.snapshot().streams.values().next().unwrap().clone();
            assert_eq!(observed.traffic_class, Some(profile.clone()));
            assert_eq!(observed.bytes_sent, payload.len() as u64);
            assert_eq!(observed.bytes_received, payload.len() as u64);
            assert_eq!(observed.target.hostname, b"class.test");
            assert!(observed.opened_at_ms > 0);
            assert_eq!(
                egress
                    .controller()
                    .snapshot()
                    .streams
                    .values()
                    .next()
                    .unwrap()
                    .traffic_class,
                None
            );
            ingress.shutdown().await.unwrap();
            egress.wait().await.unwrap();
            factory.join().await;
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn actual_pending_streams_are_arbitrated_by_class_share_not_flow_count() {
        tokio::time::timeout(Duration::from_secs(5), async {
            let (ingress_path, mut peer) = admitted_pair_with_classes(true).await;
            let id = ingress_path.session_id();
            let path = ingress_path.path_id();
            let ready = ingress_path.limits().clone();
            let initial = SessionSnapshot {
                session_id: id,
                path_id: path,
                ready_paths: 1,
                ready_path_ids: vec![path],
                path_states: BTreeMap::from([(path, pathchord_core::PathState::Active)]),
                degraded_paths: 0,
                effective_capacity_bps: 0,
                egress_aggregate_capacity_bps: 0,
                target_path_count: 1,
                path_quality: Default::default(),
                demand: Default::default(),
                active_streams: 0,
                active_udp_associations: 0,
                pending_session_controls: 0,
                egress_status: None,
                streams: Default::default(),
                pending_stream_opens: 0,
                retained_outbound_bytes: 0,
                bytes_sent: 0,
                bytes_received: 0,
                closed: false,
                trust_failure: false,
            };
            let (snapshots, _) = watch::channel(initial);
            let mut actor = SessionActor::new(
                ingress_path.into_transport(),
                SessionActorInit {
                    diagnostics: None,
                    role: ActorRole::Ingress,
                    udp_factory: None,
                    session_id: id,
                    path_id: path,
                    ready,
                    commands: None,
                    snapshots,
                    egress_status: Default::default(),
                    status_provider: None,
                    capabilities: 0,
                    session_replication_budget_bytes: 8 * 1024 * 1024,
                    target_open_slots: None,
                },
            )
            .unwrap();
            actor.chunk_size = 128;
            let mut peers = Vec::new();
            for index in 1..=4 {
                let stream_id = StreamId::new(index).unwrap();
                let (io, peer) = duplex(1024);
                peers.push(peer);
                let profile = if index == 1 {
                    class("high", 255, 3)
                } else {
                    class("low", 0, 1)
                };
                actor.observe_open(stream_id, target("queued.test"), Some(profile.clone()));
                actor
                    .spawn_active_stream(
                        stream_id,
                        Box::new(io),
                        None,
                        Some(profile),
                        FlowReplicationBudget::unlimited(8 * 1024 * 1024),
                    )
                    .unwrap();
                let count = if index == 1 { 192 } else { 64 };
                for _ in 0..count {
                    let permit = actor
                        .send_budget
                        .clone()
                        .try_acquire_many_owned(128)
                        .unwrap();
                    actor
                        .queue_stream_data(stream_id, vec![index as u8; 128], permit)
                        .await
                        .unwrap();
                }
            }
            let mut counts = [0; 4];
            for _ in 0..12 {
                actor.flush_business().await.unwrap();
                for _ in 0..8 {
                    let frame = peer.transport_mut().receive_frame().await.unwrap().unwrap();
                    let message = Message::decode(
                        frame.header().frame_type(),
                        frame.payload(),
                        ProtocolLimits::default(),
                    )
                    .unwrap();
                    let Message::StreamData(data) = message else {
                        panic!("business arbitration emits DATA");
                    };
                    counts[data.stream_id.get() as usize - 1] += 1;
                }
            }
            assert!((70..=74).contains(&counts[0]), "{counts:?}");
            for low in &counts[1..] {
                assert!((7..=9).contains(low), "{counts:?}");
            }
            actor
                .send_message(Message::Heartbeat(Heartbeat { control_seq: 0 }))
                .await
                .unwrap();
            let frame = peer.transport_mut().receive_frame().await.unwrap().unwrap();
            assert_eq!(frame.header().frame_type(), FrameType::Heartbeat);
            actor.cleanup().await;
            drop(peers);
        })
        .await
        .unwrap();
    }
    #[derive(Clone)]
    pub(super) struct EchoUdpFactory;
    struct EchoUdpSocket {
        pending: VecDeque<Vec<u8>>,
    }

    struct CountingUdpFactory(Arc<std::sync::atomic::AtomicUsize>);
    struct CountingUdpSocket(Arc<std::sync::atomic::AtomicUsize>);
    impl Drop for CountingUdpSocket {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }
    #[async_trait]
    impl crate::UdpTargetSocket for CountingUdpSocket {
        fn target_visible_port(&self) -> u16 {
            5353
        }
        async fn send_datagram(&mut self, _: &[u8]) -> Result<(), crate::UdpTargetError> {
            Ok(())
        }
        async fn receive_datagram(&mut self, _: usize) -> Result<Vec<u8>, crate::UdpTargetError> {
            pending().await
        }
    }
    #[async_trait]
    impl UdpTargetFactory for CountingUdpFactory {
        async fn open(
            &self,
            _: TargetEndpoint,
        ) -> Result<crate::BoxedUdpTargetSocket, crate::UdpTargetError> {
            Ok(Box::new(CountingUdpSocket(self.0.clone())))
        }
    }

    #[tokio::test]
    async fn udp_open_and_close_controls_recover_after_loss() {
        tokio::time::timeout(Duration::from_secs(5), async {
            let (ik, ek) = keys();
            let drop_next = Arc::new(AtomicBool::new(false));
            let closed = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let (i, e) =
                admitted_pair_for_with_dropped_ingress_write(&ik, &ek, 93, drop_next.clone()).await;
            let egress = EgressSessionHandle::start_with_udp(
                e,
                EchoFactory::default(),
                CountingUdpFactory(closed.clone()),
            )
            .unwrap();
            let ingress = IngressSessionHandle::start(i).unwrap();
            drop_next.store(true, Ordering::Release);
            let udp = ingress.open_udp(target("udp-retry.test")).await.unwrap();
            assert!(!drop_next.load(Ordering::Acquire));
            for _ in 0..100 {
                if ingress.snapshot().active_udp_associations == 1 {
                    break;
                }
                tokio::task::yield_now().await;
            }
            assert_eq!(ingress.snapshot().active_udp_associations, 1);
            tokio::time::sleep(Duration::from_millis(150)).await;
            drop_next.store(true, Ordering::Release);
            udp.close().await.unwrap();
            assert!(!drop_next.load(Ordering::Acquire));
            for _ in 0..50 {
                if closed.load(Ordering::SeqCst) == 1 {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            assert_eq!(closed.load(Ordering::SeqCst), 1);
            ingress.shutdown().await.unwrap();
            egress.wait().await.unwrap();
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn udp_open_result_retries_after_loss() {
        tokio::time::timeout(Duration::from_secs(5), async {
            let drop_next = Arc::new(AtomicBool::new(false));
            let (i, e) = admitted_pair_with_dropped_egress_write(drop_next.clone()).await;
            let egress =
                EgressSessionHandle::start_with_udp(e, EchoFactory::default(), EchoUdpFactory)
                    .unwrap();
            let ingress = IngressSessionHandle::start(i).unwrap();
            drop_next.store(true, Ordering::Release);
            let udp = ingress
                .open_udp(target("udp-response-retry.test"))
                .await
                .unwrap();
            assert!(!drop_next.load(Ordering::Acquire));
            udp.close().await.unwrap();
            ingress.shutdown().await.unwrap();
            egress.wait().await.unwrap();
        })
        .await
        .unwrap();
    }
    #[async_trait]
    impl crate::UdpTargetSocket for EchoUdpSocket {
        fn target_visible_port(&self) -> u16 {
            5353
        }
        async fn send_datagram(&mut self, payload: &[u8]) -> Result<(), crate::UdpTargetError> {
            self.pending.push_back(payload.to_vec());
            Ok(())
        }
        async fn receive_datagram(
            &mut self,
            _maximum: usize,
        ) -> Result<Vec<u8>, crate::UdpTargetError> {
            match self.pending.pop_front() {
                Some(payload) => Ok(payload),
                None => pending().await,
            }
        }
    }
    #[async_trait]
    impl UdpTargetFactory for EchoUdpFactory {
        async fn open(
            &self,
            _target: TargetEndpoint,
        ) -> Result<crate::BoxedUdpTargetSocket, crate::UdpTargetError> {
            Ok(Box::new(EchoUdpSocket {
                pending: VecDeque::new(),
            }))
        }
    }
    #[tokio::test]
    async fn negotiated_udp_classes_round_trip_without_using_tcp_stream_budget() {
        tokio::time::timeout(Duration::from_secs(5), async {
            let (i, e) = admitted_pair_with_classes(true).await;
            let factory = EchoFactory::default();
            let egress =
                EgressSessionHandle::start_with_udp(e, factory.clone(), EchoUdpFactory).unwrap();
            let ingress = IngressSessionHandle::start(i).unwrap();
            let mut udp = ingress
                .open_udp_routed_with_config(
                    target("udp-class.test"),
                    BTreeMap::new(),
                    MultipathConfig {
                        traffic_class: Some(class("dns", 220, 2)),
                        ..Default::default()
                    },
                )
                .await
                .unwrap();
            udp.send(b"first".to_vec()).await.unwrap();
            assert_eq!(udp.receive().await, Some(b"first".to_vec()));
            udp.send(b"second".to_vec()).await.unwrap();
            assert_eq!(udp.receive().await, Some(b"second".to_vec()));
            udp.close().await.unwrap();
            assert_eq!(ingress.snapshot().active_streams, 0);
            ingress.shutdown().await.unwrap();
            egress.wait().await.unwrap();
            factory.join().await;
        })
        .await
        .unwrap();
    }
}
