use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use async_trait::async_trait;
use pathchord_core::{ErrorClass, PathReady, ProtocolLimits, SessionId, TargetEndpoint};
use pathchord_noise::{StaticKeypair, WIRE_PROFILE_V1_PROLOGUE_PREFIX};
use pathchord_path::{
    AuthorizationState as PathAuthorizationState, BoxedSessionStream, BoxedUdpTargetSocket,
    EgressPathAdmissionConfig, EgressSessionController, EgressSessionHandle, EgressStatusConfig,
    EgressStatusProvider, EgressStatusSample, EgressStreamFactory, EgressStreamOpenError,
    MultipathPathObservation, PathAdmissionOutcome, PathAuthorization, PathAuthorizer,
    UdpTargetError, UdpTargetFactory, UdpTargetSocket, accept_path,
};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, TcpStream, UdpSocket, lookup_host};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc, oneshot};
use tokio::task::{AbortHandle, JoinSet};

use crate::{
    AuthorizationCleanup, AuthorizationDecision, AuthorizationState, AuthorizationStore,
    AuthorizationStoreError, BoxedTargetConnection, IngressId, TargetConnector, TargetRequest,
};

const DEFAULT_PATH_ADMISSION_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_PATH_ADMISSION_TIMEOUT: Duration = Duration::from_secs(60);

#[derive(Debug, Clone)]
pub struct EgressNodeConfig {
    pub bind: SocketAddr,
    pub egress_id: String,
    pub keypair: Arc<StaticKeypair>,
    pub authorizations: Arc<AuthorizationStore>,
    pub protocol_limits: ProtocolLimits,
    pub ready_limits: PathReady,
    pub required_capabilities: u64,
    pub supported_capabilities: u64,
    pub max_concurrent_paths: usize,
    pub capacity_bps: u64,
    pub recommended_path_count: u64,
    pub max_streams_per_ingress: usize,
    pub remote_dns_only: bool,
    pub quota_remaining: Option<u64>,
    pub traffic_multiplier_basis_points: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EgressNodeSnapshot {
    pub local_addr: SocketAddr,
    pub authorization_generation: u64,
    pub accepted_paths: u64,
    pub admitted_paths: u64,
    pub rejected_paths: u64,
    pub failed_paths: u64,
    pub duplicate_sessions: u64,
    pub completed_sessions: u64,
    pub active_paths: usize,
    pub active_sessions: usize,
    pub active_streams: usize,
    pub active_target_connections: u64,
    pub running: bool,
    pub quota_remaining: Option<u64>,
    pub traffic_multiplier_basis_points: u32,
}

#[derive(Debug, Error)]
pub enum EgressNodeError {
    #[error("Egress listener failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("Egress authorization store failed: {0}")]
    Authorization(#[from] AuthorizationStoreError),
    #[error("Egress node configuration is invalid: {0}")]
    InvalidConfig(&'static str),
    #[error("Egress node is already running")]
    AlreadyRunning,
    #[error("Egress runtime state lock is unavailable")]
    RuntimeStateLock,
    #[error("Egress Path task failed: {0}")]
    Task(String),
    #[error("Egress authorization cleanup is still pending")]
    CleanupPending,
    #[error("Egress authorization cleanup timed out")]
    CleanupTimeout,
}

pub struct EgressNode<C> {
    listener: TcpListener,
    local_addr: SocketAddr,
    config: EgressNodeConfig,
    admission: EgressPathAdmissionConfig,
    admission_timeout: Duration,
    connector: Arc<C>,
    runtime: Arc<Mutex<NodeRuntimeState>>,
    observations: Arc<NodeObservations>,
    running: AtomicBool,
    next_path_token: AtomicU64,
    session_status: EgressStatusConfig,
    status_provider: Arc<NodeStatusProvider>,
}

impl<C> std::fmt::Debug for EgressNode<C> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("EgressNode")
            .field("local_addr", &self.local_addr)
            .field("config", &self.config)
            .field("running", &self.running.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

impl<C> EgressNode<C>
where
    C: TargetConnector + 'static,
{
    pub async fn bind(config: EgressNodeConfig, connector: C) -> Result<Self, EgressNodeError> {
        validate_config(&config)?;
        let snapshot = config.authorizations.snapshot()?;
        if snapshot.egress_id().as_str() != config.egress_id
            || snapshot.egress_public_key() != config.keypair.public()
        {
            return Err(EgressNodeError::InvalidConfig(
                "authorization store identity does not match the node key",
            ));
        }
        let mut egress_identity = WIRE_PROFILE_V1_PROLOGUE_PREFIX.to_vec();
        egress_identity.extend_from_slice(config.egress_id.as_bytes());
        let admission = EgressPathAdmissionConfig {
            egress_identity,
            egress_id: config.egress_id.as_bytes().to_vec(),
            required_capabilities: config.required_capabilities,
            supported_capabilities: config.supported_capabilities,
            local_limits: config.protocol_limits,
            ready_limits: config.ready_limits.clone(),
        };
        let listener = TcpListener::bind(config.bind).await?;
        let local_addr = listener.local_addr()?;
        let session_status = EgressStatusConfig {
            capacity_bps: config.capacity_bps,
            recommended_path_count: config.recommended_path_count,
            max_streams_per_ingress: config.max_streams_per_ingress,
            quota_remaining: config.quota_remaining,
            traffic_multiplier_basis_points: config.traffic_multiplier_basis_points,
        };
        let runtime = Arc::new(Mutex::new(NodeRuntimeState::default()));
        let observations = Arc::new(NodeObservations::default());
        let status_provider = Arc::new(NodeStatusProvider {
            runtime: Arc::clone(&runtime),
            observations: Arc::clone(&observations),
            status: session_status,
        });
        Ok(Self {
            listener,
            local_addr,
            config,
            admission,
            admission_timeout: DEFAULT_PATH_ADMISSION_TIMEOUT,
            connector: Arc::new(connector),
            runtime,
            observations,
            running: AtomicBool::new(false),
            next_path_token: AtomicU64::new(1),
            session_status,
            status_provider,
        })
    }

    #[must_use]
    pub const fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Bounds the complete Noise, HELLO and ATTACH exchange before a Path
    /// can retain a live Session. Cancellation also releases its Path permit.
    pub fn with_admission_timeout(mut self, timeout: Duration) -> Result<Self, EgressNodeError> {
        if timeout.is_zero() || timeout > MAX_PATH_ADMISSION_TIMEOUT {
            return Err(EgressNodeError::InvalidConfig(
                "Path admission timeout must be positive and at most 60 seconds",
            ));
        }
        self.admission_timeout = timeout;
        Ok(self)
    }

    pub fn with_status_config(
        mut self,
        status: EgressStatusConfig,
    ) -> Result<Self, EgressNodeError> {
        if status.capacity_bps == 0
            || status.recommended_path_count == 0
            || status.max_streams_per_ingress == 0
        {
            return Err(EgressNodeError::InvalidConfig(
                "status capacity and per-Ingress limits must be non-zero",
            ));
        }
        self.session_status = status;
        Arc::get_mut(&mut self.status_provider)
            .expect("status provider is not shared before starting the node")
            .status = status;
        Ok(self)
    }

    pub fn snapshot(&self) -> Result<EgressNodeSnapshot, EgressNodeError> {
        let generation = self.config.authorizations.snapshot()?.generation();
        let runtime = self
            .runtime
            .lock()
            .map_err(|_| EgressNodeError::RuntimeStateLock)?;
        Ok(EgressNodeSnapshot {
            local_addr: self.local_addr,
            authorization_generation: generation,
            accepted_paths: self.observations.accepted.load(Ordering::Relaxed),
            admitted_paths: self.observations.admitted.load(Ordering::Relaxed),
            rejected_paths: self.observations.rejected.load(Ordering::Relaxed),
            failed_paths: self.observations.failed.load(Ordering::Relaxed),
            duplicate_sessions: self.observations.duplicates.load(Ordering::Relaxed),
            completed_sessions: self.observations.completed.load(Ordering::Relaxed),
            active_paths: runtime
                .sessions
                .values()
                .filter_map(|session| session.controller.as_ref())
                .map(|controller| controller.snapshot().ready_paths)
                .sum(),
            active_sessions: runtime
                .sessions
                .values()
                .filter_map(|session| session.controller.as_ref())
                .filter(|controller| !controller.snapshot().closed)
                .count(),
            active_streams: runtime
                .sessions
                .values()
                .filter_map(|session| session.controller.as_ref())
                .map(|controller| controller.snapshot().active_streams)
                .sum(),
            active_target_connections: self.observations.active_targets.load(Ordering::Relaxed),
            running: self.running.load(Ordering::Relaxed),
            quota_remaining: self.config.quota_remaining,
            traffic_multiplier_basis_points: self.config.traffic_multiplier_basis_points,
        })
    }

    /// Return live Path and Session counts by enrolled Ingress identity.
    pub fn authorization_activity(
        &self,
    ) -> Result<std::collections::BTreeMap<String, (usize, usize)>, EgressNodeError> {
        let runtime = self
            .runtime
            .lock()
            .map_err(|_| EgressNodeError::RuntimeStateLock)?;
        let mut activity = std::collections::BTreeMap::<String, (usize, usize)>::new();
        for ((ingress_id, _), session) in &runtime.sessions {
            if let Some(controller) = &session.controller {
                let snapshot = controller.snapshot();
                if !snapshot.closed {
                    let entry = activity.entry(ingress_id.clone()).or_default();
                    entry.0 += snapshot.ready_paths;
                    entry.1 += 1;
                }
            }
        }
        Ok(activity)
    }

    /// Snapshot live Session resources for the Egress management adapter.
    pub fn management_resources(
        &self,
    ) -> Result<(Vec<serde_json::Value>, Vec<serde_json::Value>), EgressNodeError> {
        let runtime = self
            .runtime
            .lock()
            .map_err(|_| EgressNodeError::RuntimeStateLock)?;
        let mut paths = Vec::new();
        let mut streams = Vec::new();
        for ((_, session_id), session) in &runtime.sessions {
            let Some(controller) = &session.controller else {
                continue;
            };
            let snapshot = controller.snapshot();
            for (path_id, quality) in snapshot.path_quality {
                paths.push(serde_json::json!({
                    "path_id": path_id.to_string(), "session_id": session_id.to_string(),
                    "egress_id": self.config.egress_id,
                    "state": snapshot.path_states.get(&path_id)
                        .map(|state| format!("{state:?}").to_ascii_lowercase()),
                    "rtt_ms": quality.rtt_ms, "jitter_ms": quality.jitter_ms,
                    "loss_ppm": quality.loss_ppm, "throughput_bps": quality.throughput_bps,
                    "reordering_events": quality.reordering_events,
                    "exclusion_reason": quality.exclusion_reason.map(|value| format!("{value:?}").to_ascii_lowercase()),
                }));
            }
            for stream in snapshot.streams.values() {
                streams.push(serde_json::json!({
                    "stream_id": stream.stream_id.to_string(), "session_id": session_id.to_string(),
                    "egress_id": self.config.egress_id, "state": format!("{:?}", stream.state).to_ascii_lowercase(),
                    "bytes_sent": stream.bytes_sent, "bytes_received": stream.bytes_received,
                    "bytes_acked": stream.bytes_acked, "retransmissions": stream.retransmissions,
                    "reorder_buffer_bytes": stream.reorder_buffer_bytes, "receive_window": stream.receive_window,
                    "opened_at_ms": stream.opened_at_ms, "closed_at_ms": stream.closed_at_ms,
                    "close_reason": stream.close_reason,
                    "traffic_class": stream.traffic_class.as_ref().map(|class| &class.name),
                }));
            }
        }
        Ok((paths, streams))
    }

    pub fn reconcile_authorizations(&self) -> Result<AuthorizationCleanup, EgressNodeError> {
        let CleanupBarrier {
            cleanup,
            tokens,
            targets,
        } = self.begin_authorization_cleanup()?;
        if tokens.is_empty()
            && targets
                .iter()
                .all(|targets| targets.load(Ordering::Relaxed) == 0)
        {
            return Ok(cleanup);
        }
        Err(EgressNodeError::CleanupPending)
    }

    pub async fn reconcile_authorizations_until(
        &self,
        deadline: Duration,
    ) -> Result<AuthorizationCleanup, EgressNodeError> {
        let CleanupBarrier {
            cleanup,
            tokens,
            targets,
        } = self.begin_authorization_cleanup()?;
        if tokens.is_empty() && targets.is_empty() {
            return Ok(cleanup);
        }
        let wait = async {
            loop {
                let paths_closed = self.runtime.lock().is_ok_and(|runtime| {
                    tokens
                        .iter()
                        .all(|token| !runtime.paths.contains_key(token))
                });
                let targets_closed = targets
                    .iter()
                    .all(|targets| targets.load(Ordering::Relaxed) == 0);
                if paths_closed && targets_closed {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        };
        tokio::time::timeout(deadline, wait)
            .await
            .map_err(|_| EgressNodeError::CleanupTimeout)?;
        Ok(cleanup)
    }

    fn begin_authorization_cleanup(&self) -> Result<CleanupBarrier, EgressNodeError> {
        let runtime = self
            .runtime
            .lock()
            .map_err(|_| EgressNodeError::RuntimeStateLock)?;
        // Claim registration takes the same lock before reading authorization.
        // A mutation has committed before this cleanup begins; holding the lock
        // across the snapshot fences both already-registered and pending Paths.
        let snapshot = self.config.authorizations.snapshot()?;
        let mut cleanup = AuthorizationCleanup::default();
        let mut cleaned_sessions = HashSet::new();
        let mut tokens = HashSet::new();
        let mut targets = Vec::new();
        for (token, control) in &runtime.paths {
            let Some(metadata) = &control.metadata else {
                // Its identity is not known yet. Abort and join the pending
                // handshake so it cannot claim an authorization observed
                // before this mutation committed.
                tokens.insert(*token);
                control.abort.abort();
                continue;
            };
            let decision = snapshot.authorize(
                &IngressId::new(metadata.ingress_id.clone()),
                &metadata.ingress_public_key,
            );
            if !matches!(decision, AuthorizationDecision::Authorized { .. }) {
                cleanup.paths += 1;
                if cleaned_sessions.insert((metadata.ingress_id.clone(), metadata.session_id)) {
                    cleanup.sessions += 1;
                    let target_count = metadata
                        .controller
                        .as_ref()
                        .map(|controller| controller.snapshot().active_streams as u64)
                        .unwrap_or_else(|| metadata.active_targets.load(Ordering::Relaxed));
                    cleanup.streams += target_count;
                    cleanup.target_connections += target_count;
                    targets.push(Arc::clone(&metadata.active_targets));
                }
                tokens.insert(*token);
                if metadata
                    .controller
                    .as_ref()
                    .is_none_or(|controller| controller.try_close_path(metadata.path_id).is_err())
                {
                    control.abort.abort();
                }
            }
        }
        Ok(CleanupBarrier {
            cleanup,
            tokens,
            targets,
        })
    }

    pub async fn run_until_shutdown<F>(
        &self,
        shutdown: F,
    ) -> Result<EgressNodeSnapshot, EgressNodeError>
    where
        F: Future<Output = ()> + Send,
    {
        if self
            .running
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Err(EgressNodeError::AlreadyRunning);
        }
        let _guard = RunGuard {
            running: &self.running,
            runtime: Arc::clone(&self.runtime),
        };
        let semaphore = Arc::new(Semaphore::new(self.config.max_concurrent_paths));
        let (events_tx, mut events) = mpsc::unbounded_channel();
        let mut tasks = JoinSet::new();
        let mut shutdown = Box::pin(shutdown);

        loop {
            tokio::select! {
                () = shutdown.as_mut() => break,
                accepted = self.listener.accept() => {
                    let (stream, _) = accepted?;
                    self.observations.accepted.fetch_add(1, Ordering::Relaxed);
                    let permit = match Arc::clone(&semaphore).try_acquire_owned() {
                        Ok(permit) => permit,
                        Err(_) => {
                            self.observations.rejected.fetch_add(1, Ordering::Relaxed);
                            drop(stream);
                            continue;
                        }
                    };
                    let token = self.next_path_token.fetch_add(1, Ordering::Relaxed);
                    let active_targets = Arc::new(AtomicU64::new(0));
                    let mut runtime = self.runtime.lock()
                        .map_err(|_| EgressNodeError::RuntimeStateLock)?;
                    // Construct the guard before spawning so cancellation
                    // before the task's first poll still publishes Finished.
                    let guard = PathTaskGuard {
                        token,
                        events: events_tx.clone(),
                        _permit: permit,
                    };
                    let task = tasks.spawn(run_path_task(
                        guard,
                        stream,
                        Arc::clone(&self.config.keypair),
                        self.admission.clone(),
                        self.admission_timeout,
                        Arc::clone(&self.config.authorizations),
                        Arc::clone(&self.connector),
                        Arc::clone(&self.observations),
                        Arc::clone(&active_targets),
                        self.session_status,
                        self.config.remote_dns_only,
                        Arc::clone(&self.status_provider),
                        events_tx.clone(),
                    ));
                    runtime.paths.insert(token, PathControl {
                            abort: task,
                            metadata: None,
                        });
                }
                event = events.recv() => {
                    if let Some(event) = event {
                        self.handle_event(event)?;
                    }
                }
                joined = tasks.join_next(), if !tasks.is_empty() => {
                    if let Some(Err(error)) = joined
                        && !error.is_cancelled()
                    {
                        self.observations.failed.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
        }

        {
            let runtime = self
                .runtime
                .lock()
                .map_err(|_| EgressNodeError::RuntimeStateLock)?;
            for control in runtime.paths.values() {
                control.abort.abort();
            }
        }
        tasks.abort_all();
        while let Some(result) = tasks.join_next().await {
            if let Err(error) = result
                && !error.is_cancelled()
            {
                self.observations.failed.fetch_add(1, Ordering::Relaxed);
            }
        }
        let mut runtime = self
            .runtime
            .lock()
            .map_err(|_| EgressNodeError::RuntimeStateLock)?;
        runtime.paths.clear();
        runtime.sessions.clear();
        drop(runtime);
        self.running.store(false, Ordering::Release);
        self.snapshot()
    }

    fn handle_event(&self, event: NodeEvent) -> Result<(), EgressNodeError> {
        match event {
            NodeEvent::Claim {
                token,
                ingress_id,
                ingress_public_key,
                session_id,
                path_id,
                active_targets,
                reply,
            } => {
                let mut runtime = self
                    .runtime
                    .lock()
                    .map_err(|_| EgressNodeError::RuntimeStateLock)?;
                let authorization = self.config.authorizations.snapshot()?;
                if !matches!(
                    authorization
                        .authorize(&IngressId::new(ingress_id.clone()), &ingress_public_key),
                    AuthorizationDecision::Authorized { .. }
                ) {
                    self.observations.rejected.fetch_add(1, Ordering::Relaxed);
                    let _ = reply.send(ClaimDecision::Reject);
                    return Ok(());
                }
                let key = (ingress_id.clone(), session_id);
                let existing = runtime
                    .sessions
                    .get(&key)
                    .and_then(|session| session.controller.clone());
                if runtime.sessions.contains_key(&key) && existing.is_none() {
                    self.observations.duplicates.fetch_add(1, Ordering::Relaxed);
                    self.observations.rejected.fetch_add(1, Ordering::Relaxed);
                    let _ = reply.send(ClaimDecision::Reject);
                    return Ok(());
                }
                let Some(control) = runtime.paths.get_mut(&token) else {
                    let _ = reply.send(ClaimDecision::Reject);
                    return Ok(());
                };
                control.metadata = Some(ActivePathMetadata {
                    ingress_id: ingress_id.clone(),
                    ingress_public_key,
                    session_id,
                    path_id,
                    active_targets,
                    controller: existing.clone(),
                });
                let decision = if let Some(controller) = existing {
                    ClaimDecision::Existing(controller)
                } else {
                    runtime.sessions.insert(
                        key,
                        SessionRegistration {
                            owner_token: token,
                            controller: None,
                        },
                    );
                    ClaimDecision::New
                };
                self.observations.admitted.fetch_add(1, Ordering::Relaxed);
                let _ = reply.send(decision);
            }
            NodeEvent::RegisterController {
                token,
                ingress_id,
                session_id,
                controller,
            } => {
                let mut runtime = self
                    .runtime
                    .lock()
                    .map_err(|_| EgressNodeError::RuntimeStateLock)?;
                if let Some(session) = runtime.sessions.get_mut(&(ingress_id, session_id))
                    && session.owner_token == token
                {
                    session.controller = Some(controller.clone());
                }
                if let Some(control) = runtime.paths.get_mut(&token)
                    && let Some(metadata) = control.metadata.as_mut()
                {
                    metadata.controller = Some(controller);
                }
            }
            NodeEvent::Rejected => {
                self.observations.rejected.fetch_add(1, Ordering::Relaxed);
            }
            NodeEvent::Failed => {
                self.observations.failed.fetch_add(1, Ordering::Relaxed);
            }
            NodeEvent::Completed => {
                self.observations.completed.fetch_add(1, Ordering::Relaxed);
            }
            NodeEvent::Finished { token } => {
                let mut runtime = self
                    .runtime
                    .lock()
                    .map_err(|_| EgressNodeError::RuntimeStateLock)?;
                if let Some(control) = runtime.paths.remove(&token)
                    && let Some(metadata) = control.metadata
                {
                    let key = (metadata.ingress_id, metadata.session_id);
                    if runtime
                        .sessions
                        .get(&key)
                        .is_some_and(|session| session.owner_token == token)
                    {
                        runtime.sessions.remove(&key);
                    }
                }
            }
        }
        Ok(())
    }
}

fn validate_config(config: &EgressNodeConfig) -> Result<(), EgressNodeError> {
    if config.egress_id.is_empty() {
        return Err(EgressNodeError::InvalidConfig("EgressID is empty"));
    }
    if config.max_concurrent_paths == 0 {
        return Err(EgressNodeError::InvalidConfig(
            "max_concurrent_paths must be greater than zero",
        ));
    }
    if config.capacity_bps == 0
        || config.recommended_path_count == 0
        || config.max_streams_per_ingress == 0
        || config.traffic_multiplier_basis_points == 0
    {
        return Err(EgressNodeError::InvalidConfig(
            "status capacity, limits, and traffic multiplier must be non-zero",
        ));
    }
    if config.required_capabilities & config.supported_capabilities != config.required_capabilities
    {
        return Err(EgressNodeError::InvalidConfig(
            "required capabilities are not supported",
        ));
    }
    if config.ready_limits.max_frame_payload == 0
        || config.ready_limits.max_control_payload == 0
        || config.ready_limits.max_session_buffering == 0
        || config.ready_limits.max_frame_payload > config.protocol_limits.max_frame_payload() as u64
        || config.ready_limits.max_control_payload
            > config.protocol_limits.max_control_payload() as u64
        || config.ready_limits.max_session_buffering
            > config.protocol_limits.max_session_buffering() as u64
        || config.ready_limits.max_control_payload > config.ready_limits.max_frame_payload
    {
        return Err(EgressNodeError::InvalidConfig(
            "PATH_READY limits exceed local limits",
        ));
    }
    Ok(())
}

#[derive(Default)]
struct NodeRuntimeState {
    paths: HashMap<u64, PathControl>,
    sessions: HashMap<(String, SessionId), SessionRegistration>,
}

struct CleanupBarrier {
    cleanup: AuthorizationCleanup,
    tokens: HashSet<u64>,
    targets: Vec<Arc<AtomicU64>>,
}

struct SessionRegistration {
    owner_token: u64,
    controller: Option<EgressSessionController>,
}

struct PathControl {
    abort: AbortHandle,
    metadata: Option<ActivePathMetadata>,
}

struct ActivePathMetadata {
    ingress_id: String,
    ingress_public_key: [u8; 32],
    session_id: SessionId,
    path_id: pathchord_core::PathId,
    active_targets: Arc<AtomicU64>,
    controller: Option<EgressSessionController>,
}

#[derive(Default)]
struct NodeObservations {
    accepted: AtomicU64,
    admitted: AtomicU64,
    rejected: AtomicU64,
    failed: AtomicU64,
    duplicates: AtomicU64,
    completed: AtomicU64,
    active_targets: Arc<AtomicU64>,
}

struct NodeStatusProvider {
    runtime: Arc<Mutex<NodeRuntimeState>>,
    observations: Arc<NodeObservations>,
    status: EgressStatusConfig,
}

impl std::fmt::Debug for NodeStatusProvider {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NodeStatusProvider")
            .field("status", &self.status)
            .finish_non_exhaustive()
    }
}

impl EgressStatusProvider for NodeStatusProvider {
    fn sample(&self) -> EgressStatusSample {
        let (active_sessions, active_streams) = self.runtime.lock().map_or((0, 0), |runtime| {
            let mut streams = 0_u64;
            for session in runtime.sessions.values() {
                if let Some(controller) = &session.controller {
                    streams = streams.saturating_add(controller.snapshot().active_streams as u64);
                }
            }
            (runtime.sessions.len() as u64, streams)
        });
        let active_targets = self.observations.active_targets.load(Ordering::Relaxed);
        let maximum_connections = active_sessions
            .max(1)
            .saturating_mul(self.status.max_streams_per_ingress as u64);
        let utilization = active_targets
            .saturating_mul(10_000)
            .checked_div(maximum_connections)
            .unwrap_or(0)
            .min(10_000) as u16;
        EgressStatusSample {
            connected: true,
            service_state: pathchord_core::EgressServiceState::Up,
            load_basis_points: utilization,
            connection_utilization_basis_points: utilization,
            bandwidth_utilization_basis_points: 0,
            active_sessions,
            active_streams,
            active_target_connections: active_targets,
            capacity_bps: self.status.capacity_bps,
            recommended_path_count: self.status.recommended_path_count,
            quota_remaining: self.status.quota_remaining,
            traffic_multiplier_basis_points: self.status.traffic_multiplier_basis_points,
        }
    }
}

enum NodeEvent {
    Claim {
        token: u64,
        ingress_id: String,
        ingress_public_key: [u8; 32],
        session_id: SessionId,
        path_id: pathchord_core::PathId,
        active_targets: Arc<AtomicU64>,
        reply: oneshot::Sender<ClaimDecision>,
    },
    RegisterController {
        token: u64,
        ingress_id: String,
        session_id: SessionId,
        controller: EgressSessionController,
    },
    Rejected,
    Failed,
    Completed,
    Finished {
        token: u64,
    },
}

enum ClaimDecision {
    New,
    Existing(EgressSessionController),
    Reject,
}

struct PathTaskGuard {
    token: u64,
    events: mpsc::UnboundedSender<NodeEvent>,
    _permit: OwnedSemaphorePermit,
}

impl Drop for PathTaskGuard {
    fn drop(&mut self) {
        let _ = self.events.send(NodeEvent::Finished { token: self.token });
    }
}

struct RunGuard<'a> {
    running: &'a AtomicBool,
    runtime: Arc<Mutex<NodeRuntimeState>>,
}

impl Drop for RunGuard<'_> {
    fn drop(&mut self) {
        self.running.store(false, Ordering::Release);
        if let Ok(mut runtime) = self.runtime.lock() {
            for control in runtime.paths.values() {
                control.abort.abort();
            }
            runtime.paths.clear();
            runtime.sessions.clear();
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_path_task<C>(
    guard: PathTaskGuard,
    stream: TcpStream,
    keypair: Arc<StaticKeypair>,
    admission: EgressPathAdmissionConfig,
    admission_timeout: Duration,
    authorizations: Arc<AuthorizationStore>,
    connector: Arc<C>,
    observations: Arc<NodeObservations>,
    active_targets: Arc<AtomicU64>,
    session_status: EgressStatusConfig,
    remote_dns_only: bool,
    status_provider: Arc<NodeStatusProvider>,
    events: mpsc::UnboundedSender<NodeEvent>,
) where
    C: TargetConnector + 'static,
{
    let token = guard.token;
    let _guard = guard;
    let authorizer = StorePathAuthorizer {
        store: Arc::clone(&authorizations),
    };
    let path = match tokio::time::timeout(
        admission_timeout,
        accept_path(stream, keypair.private(), &admission, &authorizer),
    )
    .await
    {
        Ok(Ok(PathAdmissionOutcome::Ready(path))) => path,
        Ok(Ok(PathAdmissionOutcome::Rejected { .. })) => {
            let _ = events.send(NodeEvent::Rejected);
            return;
        }
        Ok(Err(_)) | Err(_) => {
            let _ = events.send(NodeEvent::Failed);
            return;
        }
    };
    let Ok(ingress_id) = std::str::from_utf8(path.ingress_id()).map(str::to_owned) else {
        let _ = events.send(NodeEvent::Failed);
        return;
    };
    let ingress_public_key = *path.authenticated_remote_key();
    let session_id = path.session_id();
    let path_id = path.path_id();
    let (claim, claimed) = oneshot::channel();
    if events
        .send(NodeEvent::Claim {
            token,
            ingress_id: ingress_id.clone(),
            ingress_public_key,
            session_id,
            path_id,
            active_targets: Arc::clone(&active_targets),
            reply: claim,
        })
        .is_err()
    {
        return;
    }
    let factory = ConnectorStreamFactory {
        connector,
        session_targets: active_targets,
        global_targets: Arc::clone(&observations.active_targets),
        remote_dns_only,
    };
    match claimed.await.unwrap_or(ClaimDecision::Reject) {
        ClaimDecision::New => {
            let handle = match EgressSessionHandle::start_with_udp_and_status_provider(
                path,
                factory,
                TokioUdpTargetFactory { remote_dns_only },
                session_status,
                status_provider,
            ) {
                Ok(handle) => handle,
                Err(_) => {
                    let _ = events.send(NodeEvent::Failed);
                    return;
                }
            };
            let controller = handle.controller();
            if events
                .send(NodeEvent::RegisterController {
                    token,
                    ingress_id,
                    session_id,
                    controller,
                })
                .is_err()
            {
                return;
            }
            match handle.wait().await {
                Ok(_) => {
                    let _ = events.send(NodeEvent::Completed);
                }
                Err(_) => {
                    let _ = events.send(NodeEvent::Failed);
                }
            }
        }
        ClaimDecision::Existing(controller) => {
            if controller
                .add_path(path, MultipathPathObservation::default())
                .await
                .is_err()
            {
                let _ = events.send(NodeEvent::Failed);
                return;
            }
            controller.wait_path_closed(path_id).await;
        }
        ClaimDecision::Reject => {}
    }
}

struct StorePathAuthorizer {
    store: Arc<AuthorizationStore>,
}

impl PathAuthorizer for StorePathAuthorizer {
    fn authorization_for(&self, authenticated_key: &[u8; 32]) -> Option<PathAuthorization> {
        let snapshot = self.store.snapshot().ok()?;
        let mut records = snapshot
            .records()
            .filter(|record| &record.ingress_public_key == authenticated_key);
        let record = records.next()?;
        if records.next().is_some() {
            return None;
        }
        Some(PathAuthorization {
            ingress_id: record.ingress_id.as_str().as_bytes().to_vec(),
            public_key: record.ingress_public_key,
            state: match record.state {
                AuthorizationState::Enabled => PathAuthorizationState::Enabled,
                AuthorizationState::Disabled => PathAuthorizationState::Disabled,
                AuthorizationState::Revoked => PathAuthorizationState::Revoked,
            },
            generation: snapshot.generation(),
        })
    }
}

struct ConnectorStreamFactory<C> {
    connector: Arc<C>,
    session_targets: Arc<AtomicU64>,
    global_targets: Arc<AtomicU64>,
    remote_dns_only: bool,
}

#[async_trait]
impl<C> EgressStreamFactory for ConnectorStreamFactory<C>
where
    C: TargetConnector + 'static,
{
    async fn open(
        &self,
        target: TargetEndpoint,
    ) -> Result<BoxedSessionStream, EgressStreamOpenError> {
        let original_hostname = if target.hostname.is_empty() {
            None
        } else {
            Some(String::from_utf8(target.hostname).map_err(|_| {
                EgressStreamOpenError::new(
                    ErrorClass::TargetFailure,
                    b"target hostname is not UTF-8".to_vec(),
                )
            })?)
        };
        let resolved_ip_candidates = if self.remote_dns_only && original_hostname.is_some() {
            Vec::new()
        } else {
            target.resolved_addresses
        };
        let request = TargetRequest {
            original_hostname,
            resolved_ip_candidates,
            port: target.port,
        };
        let connection = self.connector.connect(request).await.map_err(|error| {
            EgressStreamOpenError::new(ErrorClass::TargetFailure, error.to_string().into_bytes())
        })?;
        self.session_targets.fetch_add(1, Ordering::Relaxed);
        self.global_targets.fetch_add(1, Ordering::Relaxed);
        Ok(Box::new(TrackedTargetStream {
            inner: connection,
            session_targets: Arc::clone(&self.session_targets),
            global_targets: Arc::clone(&self.global_targets),
        }))
    }
}

struct TrackedTargetStream {
    inner: BoxedTargetConnection,
    session_targets: Arc<AtomicU64>,
    global_targets: Arc<AtomicU64>,
}

impl AsyncRead for TrackedTargetStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(self.inner.as_mut()).poll_read(context, buffer)
    }
}

impl AsyncWrite for TrackedTargetStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        Pin::new(self.inner.as_mut()).poll_write(context, buffer)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(self.inner.as_mut()).poll_flush(context)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(self.inner.as_mut()).poll_shutdown(context)
    }
}

impl Drop for TrackedTargetStream {
    fn drop(&mut self) {
        self.session_targets.fetch_sub(1, Ordering::Relaxed);
        self.global_targets.fetch_sub(1, Ordering::Relaxed);
    }
}

#[derive(Clone, Copy, Debug)]
struct TokioUdpTargetFactory {
    remote_dns_only: bool,
}

#[async_trait]
impl UdpTargetFactory for TokioUdpTargetFactory {
    async fn open(&self, target: TargetEndpoint) -> Result<BoxedUdpTargetSocket, UdpTargetError> {
        let mut tried = HashSet::new();
        if !self.remote_dns_only || target.hostname.is_empty() {
            for ip in &target.resolved_addresses {
                let address = SocketAddr::new(*ip, target.port);
                if tried.insert(address)
                    && let Some(socket) = connect_udp_target(address).await
                {
                    return Ok(Box::new(socket));
                }
            }
        }
        if !target.hostname.is_empty() {
            let hostname = std::str::from_utf8(&target.hostname).map_err(|_| {
                UdpTargetError::new(
                    ErrorClass::TargetFailure,
                    b"UDP target hostname is not UTF-8".to_vec(),
                )
            })?;
            let addresses = lookup_host((hostname, target.port)).await.map_err(|_| {
                UdpTargetError::new(
                    ErrorClass::TargetFailure,
                    b"UDP target resolution failed".to_vec(),
                )
            })?;
            for address in addresses {
                if tried.insert(address)
                    && let Some(socket) = connect_udp_target(address).await
                {
                    return Ok(Box::new(socket));
                }
            }
        }
        Err(UdpTargetError::new(
            ErrorClass::TargetFailure,
            b"no usable UDP target address".to_vec(),
        ))
    }
}

async fn connect_udp_target(address: SocketAddr) -> Option<TokioUdpTargetSocket> {
    let bind = match address {
        SocketAddr::V4(_) => "0.0.0.0:0",
        SocketAddr::V6(_) => "[::]:0",
    };
    let socket = UdpSocket::bind(bind).await.ok()?;
    socket.connect(address).await.ok()?;
    let visible_port = socket.local_addr().ok()?.port();
    Some(TokioUdpTargetSocket {
        socket,
        visible_port,
    })
}

struct TokioUdpTargetSocket {
    socket: UdpSocket,
    visible_port: u16,
}

#[async_trait]
impl UdpTargetSocket for TokioUdpTargetSocket {
    fn target_visible_port(&self) -> u16 {
        self.visible_port
    }

    async fn send_datagram(&mut self, payload: &[u8]) -> Result<(), UdpTargetError> {
        self.socket.send(payload).await.map_err(|_| {
            UdpTargetError::new(
                ErrorClass::TargetFailure,
                b"UDP target send failed".to_vec(),
            )
        })?;
        Ok(())
    }

    async fn receive_datagram(&mut self, maximum: usize) -> Result<Vec<u8>, UdpTargetError> {
        let mut payload = vec![0_u8; maximum];
        let received = self.socket.recv(&mut payload).await.map_err(|_| {
            UdpTargetError::new(
                ErrorClass::TargetFailure,
                b"UDP target receive failed".to_vec(),
            )
        })?;
        payload.truncate(received);
        Ok(payload)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        AuthorizationMutation, AuthorizationMutationRequest, EgressId, TargetConnectError,
    };
    use pathchord_noise::generate_static_keypair;
    use pathchord_path::{
        IngressPathAdmissionConfig, IngressSessionHandle, OpenStreamError, PathAdmissionOutcome,
        dial_path,
    };
    use std::collections::BTreeMap;
    use std::path::PathBuf;
    use std::sync::atomic::AtomicUsize;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, copy, duplex, split};

    static NEXT_DB: AtomicUsize = AtomicUsize::new(0);

    fn database_path() -> PathBuf {
        std::env::temp_dir().join(format!(
            "pathchord-egress-node-{}-{}.sqlite",
            std::process::id(),
            NEXT_DB.fetch_add(1, Ordering::Relaxed)
        ))
    }

    fn enroll(store: &AuthorizationStore, ingress: &StaticKeypair) {
        store
            .mutate(AuthorizationMutationRequest {
                actor_id: "test-admin".to_owned(),
                request_id: "enroll-1".to_owned(),
                expected_generation: 0,
                ingress_id: IngressId::new("runtime-ingress"),
                mutation: AuthorizationMutation::Enroll {
                    public_key: *ingress.public(),
                    administrator_labels: BTreeMap::new(),
                },
            })
            .expect("enroll Ingress");
    }

    fn node_config(
        keypair: Arc<StaticKeypair>,
        store: Arc<AuthorizationStore>,
    ) -> EgressNodeConfig {
        EgressNodeConfig {
            bind: "127.0.0.1:0".parse().expect("bind address"),
            egress_id: "runtime-egress".to_owned(),
            keypair,
            authorizations: store,
            protocol_limits: ProtocolLimits::default(),
            ready_limits: PathReady {
                max_frame_payload: 4096,
                max_control_payload: 1024,
                max_session_buffering: 64 * 1024,
            },
            required_capabilities: 1,
            supported_capabilities: pathchord_core::CAPABILITY_TCP_STREAM
                | pathchord_core::CAPABILITY_UDP_SESSION,
            max_concurrent_paths: 8,
            capacity_bps: 1_000_000_000,
            recommended_path_count: 1,
            max_streams_per_ingress: 256,
            remote_dns_only: false,
            quota_remaining: None,
            traffic_multiplier_basis_points: 10_000,
        }
    }

    fn ingress_config(session: u128, path: u128) -> IngressPathAdmissionConfig {
        IngressPathAdmissionConfig {
            egress_identity: b"PathChord/wire-v1/egress/runtime-egress".to_vec(),
            egress_id: b"runtime-egress".to_vec(),
            ingress_id: b"runtime-ingress".to_vec(),
            session_id: SessionId::new(session),
            path_id: pathchord_core::PathId::new(path),
            offered_capabilities: pathchord_core::CAPABILITY_TCP_STREAM
                | pathchord_core::CAPABILITY_UDP_SESSION,
            required_capabilities: 1,
            local_limits: ProtocolLimits::default(),
        }
    }

    async fn run_node<C>(
        node: Arc<EgressNode<C>>,
        shutdown: oneshot::Receiver<()>,
    ) -> Result<EgressNodeSnapshot, EgressNodeError>
    where
        C: TargetConnector + 'static,
    {
        node.run_until_shutdown(async move {
            let _ = shutdown.await;
        })
        .await
    }

    async fn dial_ingress<C>(
        node: &EgressNode<C>,
        ingress: &StaticKeypair,
        egress: &StaticKeypair,
        session: u128,
        path: u128,
    ) -> pathchord_path::PathAdmissionOutcome<pathchord_path::IngressAdmittedPath<TcpStream>>
    where
        C: TargetConnector + 'static,
    {
        let stream = TcpStream::connect(node.local_addr())
            .await
            .expect("connect Egress");
        dial_path(
            stream,
            ingress.private(),
            egress.public(),
            &ingress_config(session, path),
        )
        .await
        .expect("Ingress admission result")
    }

    #[derive(Clone, Default)]
    struct EchoConnector {
        tasks: Arc<Mutex<Vec<tokio::task::JoinHandle<()>>>>,
    }

    impl EchoConnector {
        async fn join(&self) {
            let tasks = std::mem::take(&mut *self.tasks.lock().expect("echo task lock"));
            for task in tasks {
                task.await.expect("echo task");
            }
        }
    }

    #[async_trait]
    impl TargetConnector for EchoConnector {
        async fn connect(
            &self,
            _request: TargetRequest,
        ) -> Result<BoxedTargetConnection, TargetConnectError> {
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

    struct RejectConnector;

    #[derive(Clone, Default)]
    struct RecordingConnector(Arc<Mutex<Vec<TargetRequest>>>);

    #[async_trait]
    impl TargetConnector for RecordingConnector {
        async fn connect(
            &self,
            request: TargetRequest,
        ) -> Result<BoxedTargetConnection, TargetConnectError> {
            self.0.lock().unwrap().push(request);
            Ok(Box::new(duplex(1024).0))
        }
    }

    #[tokio::test]
    async fn remote_dns_policy_does_not_trust_ingress_candidates_for_hostname() {
        let connector = Arc::new(RecordingConnector::default());
        let factory = ConnectorStreamFactory {
            connector: Arc::clone(&connector),
            session_targets: Arc::new(AtomicU64::new(0)),
            global_targets: Arc::new(AtomicU64::new(0)),
            remote_dns_only: true,
        };
        let stream = factory
            .open(TargetEndpoint {
                hostname: b"example.test".to_vec(),
                port: 443,
                resolved_addresses: vec!["192.0.2.1".parse().unwrap()],
            })
            .await
            .unwrap();
        drop(stream);
        let requests = connector.0.lock().unwrap();
        assert_eq!(
            requests[0].original_hostname.as_deref(),
            Some("example.test")
        );
        assert!(requests[0].resolved_ip_candidates.is_empty());
    }

    #[tokio::test]
    async fn status_config_updates_the_provider_used_by_sessions() {
        let egress_key = Arc::new(generate_static_keypair().unwrap());
        let store = Arc::new(
            AuthorizationStore::open(
                ":memory:",
                EgressId::new("runtime-egress"),
                *egress_key.public(),
            )
            .unwrap(),
        );
        let status = EgressStatusConfig {
            capacity_bps: 42_000,
            recommended_path_count: 3,
            ..EgressStatusConfig::default()
        };
        let node = EgressNode::bind(node_config(egress_key, store), EchoConnector::default())
            .await
            .unwrap()
            .with_status_config(status)
            .unwrap();
        let sample = node.status_provider.sample();
        assert_eq!(sample.capacity_bps, 42_000);
        assert_eq!(sample.recommended_path_count, 3);
    }

    #[tokio::test]
    async fn udp_remote_dns_policy_uses_egress_resolver() {
        let address = lookup_host(("localhost", 53))
            .await
            .unwrap()
            .next()
            .unwrap();
        let bind = SocketAddr::new(address.ip(), 0);
        let target = UdpSocket::bind(bind).await.unwrap();
        let target_address = target.local_addr().unwrap();
        let factory = TokioUdpTargetFactory {
            remote_dns_only: true,
        };
        let mut socket = factory
            .open(TargetEndpoint {
                hostname: b"localhost".to_vec(),
                port: target_address.port(),
                resolved_addresses: vec!["192.0.2.1".parse().unwrap()],
            })
            .await
            .unwrap();
        socket.send_datagram(b"dns-policy").await.unwrap();
        let mut data = [0; 16];
        let (length, _) = tokio::time::timeout(Duration::from_secs(2), target.recv_from(&mut data))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&data[..length], b"dns-policy");
    }

    #[tokio::test]
    async fn udp_target_tries_later_candidates_when_first_cannot_connect() {
        let target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let target_address = target.local_addr().unwrap();
        let factory = TokioUdpTargetFactory {
            remote_dns_only: false,
        };
        let mut socket = factory
            .open(TargetEndpoint {
                hostname: Vec::new(),
                port: target_address.port(),
                resolved_addresses: vec!["fe80::1".parse().unwrap(), target_address.ip()],
            })
            .await
            .unwrap();
        socket.send_datagram(b"candidate").await.unwrap();
        let mut data = [0; 16];
        let (length, _) = tokio::time::timeout(Duration::from_secs(2), target.recv_from(&mut data))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&data[..length], b"candidate");
    }

    #[tokio::test]
    async fn stale_handshake_cannot_claim_reenrolled_identity() {
        let old_key = generate_static_keypair().unwrap();
        let new_key = generate_static_keypair().unwrap();
        let egress_key = Arc::new(generate_static_keypair().unwrap());
        let store = Arc::new(
            AuthorizationStore::open(
                ":memory:",
                EgressId::new("runtime-egress"),
                *egress_key.public(),
            )
            .unwrap(),
        );
        enroll(&store, &old_key);
        let node = EgressNode::bind(
            node_config(egress_key, Arc::clone(&store)),
            EchoConnector::default(),
        )
        .await
        .unwrap();
        let task = tokio::spawn(std::future::pending::<()>());
        node.runtime.lock().unwrap().paths.insert(
            99,
            PathControl {
                abort: task.abort_handle(),
                metadata: None,
            },
        );
        for (generation, operation, request_id) in [
            (1, AuthorizationMutation::Disable, "disable"),
            (2, AuthorizationMutation::Delete, "delete"),
            (
                3,
                AuthorizationMutation::Enroll {
                    public_key: *new_key.public(),
                    administrator_labels: Default::default(),
                },
                "reenroll",
            ),
        ] {
            store
                .mutate(AuthorizationMutationRequest {
                    actor_id: "admin".into(),
                    request_id: request_id.into(),
                    expected_generation: generation,
                    ingress_id: IngressId::new("runtime-ingress"),
                    mutation: operation,
                })
                .unwrap();
        }
        let (reply, decision) = oneshot::channel();
        node.handle_event(NodeEvent::Claim {
            token: 99,
            ingress_id: "runtime-ingress".into(),
            ingress_public_key: *old_key.public(),
            session_id: SessionId::new(1),
            path_id: pathchord_core::PathId::new(1),
            active_targets: Arc::new(AtomicU64::new(0)),
            reply,
        })
        .unwrap();
        assert!(matches!(decision.await.unwrap(), ClaimDecision::Reject));
        assert!(node.runtime.lock().unwrap().sessions.is_empty());
        let barrier = node.begin_authorization_cleanup().unwrap();
        assert!(barrier.tokens.contains(&99));
        assert!(task.await.unwrap_err().is_cancelled());
    }

    #[tokio::test]
    async fn revocation_waits_for_pending_handshake_to_be_cancelled() {
        let ingress_key = generate_static_keypair().unwrap();
        let egress_key = Arc::new(generate_static_keypair().unwrap());
        let store = Arc::new(
            AuthorizationStore::open(
                ":memory:",
                EgressId::new("runtime-egress"),
                *egress_key.public(),
            )
            .unwrap(),
        );
        enroll(&store, &ingress_key);
        let node = Arc::new(
            EgressNode::bind(
                node_config(egress_key, Arc::clone(&store)),
                EchoConnector::default(),
            )
            .await
            .unwrap(),
        );
        let (shutdown, shutdown_rx) = oneshot::channel();
        let runner = tokio::spawn(run_node(Arc::clone(&node), shutdown_rx));
        let mut pending = TcpStream::connect(node.local_addr()).await.unwrap();
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if node.observations.accepted.load(Ordering::Relaxed) != 0 {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        store
            .mutate(AuthorizationMutationRequest {
                actor_id: "admin".into(),
                request_id: "disable-pending".into(),
                expected_generation: 1,
                ingress_id: IngressId::new("runtime-ingress"),
                mutation: AuthorizationMutation::Disable,
            })
            .unwrap();
        node.reconcile_authorizations_until(Duration::from_secs(2))
            .await
            .unwrap();
        let mut byte = [0];
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(2), pending.read(&mut byte))
                .await
                .unwrap()
                .unwrap(),
            0
        );
        shutdown.send(()).unwrap();
        runner.await.unwrap().unwrap();
    }

    #[async_trait]
    impl TargetConnector for RejectConnector {
        async fn connect(
            &self,
            _request: TargetRequest,
        ) -> Result<BoxedTargetConnection, TargetConnectError> {
            Err(TargetConnectError::Connection("target refused".to_owned()))
        }
    }

    #[tokio::test]
    async fn incomplete_admission_releases_the_only_path_permit() {
        let ingress_key = generate_static_keypair().unwrap();
        let egress_key = Arc::new(generate_static_keypair().unwrap());
        let store = Arc::new(
            AuthorizationStore::open(
                ":memory:",
                EgressId::new("runtime-egress"),
                *egress_key.public(),
            )
            .unwrap(),
        );
        enroll(&store, &ingress_key);
        let mut config = node_config(Arc::clone(&egress_key), store);
        config.max_concurrent_paths = 1;
        let node = Arc::new(
            EgressNode::bind(config, EchoConnector::default())
                .await
                .unwrap()
                .with_admission_timeout(Duration::from_millis(150))
                .unwrap(),
        );
        let (shutdown, shutdown_rx) = oneshot::channel();
        let runner = tokio::spawn(run_node(Arc::clone(&node), shutdown_rx));

        for stage in 0..5 {
            let mut peer = TcpStream::connect(node.local_addr()).await.unwrap();
            match stage {
                0 => {}                                          // No prefix.
                1 => peer.write_all(&[0]).await.unwrap(),        // Incomplete prefix.
                2 => peer.write_all(&[0, 96, 1]).await.unwrap(), // Incomplete Noise body.
                _ => {
                    let config = ingress_config(10 + stage, 20 + stage);
                    let mut handshake = pathchord_noise::InitiatorHandshake::new(
                        ingress_key.private(),
                        egress_key.public(),
                        &config.egress_identity,
                    )
                    .unwrap();
                    let request = handshake.write_message(&[]).unwrap();
                    peer.write_all(&(request.len() as u16).to_be_bytes())
                        .await
                        .unwrap();
                    peer.write_all(&request).await.unwrap();
                    let mut prefix = [0_u8; 2];
                    peer.read_exact(&mut prefix).await.unwrap();
                    let mut response = vec![0; u16::from_be_bytes(prefix) as usize];
                    peer.read_exact(&mut response).await.unwrap();
                    handshake.read_message(&response).unwrap();
                    if stage == 4 {
                        let mut noise = handshake.into_transport().unwrap();
                        let message =
                            pathchord_core::Message::PathHello(pathchord_core::PathHello {
                                version: pathchord_core::WIRE_PROFILE_V1_VERSION,
                                capabilities: 1,
                                path_id: config.path_id,
                                transport_metadata: Vec::new(),
                            });
                        let frame = pathchord_core::PathFrame::new(
                            message.frame_type(),
                            pathchord_core::FrameFlags::empty(),
                            config.session_id,
                            config.path_id,
                            0,
                            message.encode(config.local_limits).unwrap(),
                            config.local_limits,
                        )
                        .unwrap();
                        peer.write_all(
                            &noise
                                .seal_frame(&frame, config.local_limits)
                                .unwrap()
                                .encode(),
                        )
                        .await
                        .unwrap();
                    }
                }
            }
            tokio::time::timeout(Duration::from_secs(2), async {
                loop {
                    if node.snapshot().unwrap().failed_paths > stage as u64
                        && node.runtime.lock().unwrap().paths.is_empty()
                    {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }
            })
            .await
            .expect("admission must expire and release the permit");
            assert_eq!(peer.read(&mut [0_u8; 1]).await.unwrap(), 0);
        }
        let PathAdmissionOutcome::Ready(path) =
            dial_ingress(&node, &ingress_key, &egress_key, 100, 101).await
        else {
            panic!("valid admission should recover")
        };
        let ingress = IngressSessionHandle::start(path).unwrap();
        ingress.shutdown().await.unwrap();
        shutdown.send(()).unwrap();
        let result = runner.await.unwrap().unwrap();
        assert_eq!(result.failed_paths, 5);
        assert_eq!(result.admitted_paths, 1);
    }

    #[tokio::test]
    async fn loopback_node_admits_and_proxies_a_real_path() {
        let ingress_key = generate_static_keypair().expect("Ingress key");
        let egress_key = Arc::new(generate_static_keypair().expect("Egress key"));
        let database = database_path();
        let store = Arc::new(
            AuthorizationStore::open(
                &database,
                EgressId::new("runtime-egress"),
                *egress_key.public(),
            )
            .expect("authorization store"),
        );
        enroll(&store, &ingress_key);
        let connector = EchoConnector::default();
        let node = Arc::new(
            EgressNode::bind(
                node_config(Arc::clone(&egress_key), Arc::clone(&store)),
                connector.clone(),
            )
            .await
            .expect("bind Egress node"),
        );
        let (shutdown, shutdown_rx) = oneshot::channel();
        let runner = tokio::spawn(run_node(Arc::clone(&node), shutdown_rx));

        let PathAdmissionOutcome::Ready(path) =
            dial_ingress(&node, &ingress_key, &egress_key, 1, 1).await
        else {
            panic!("Path should be admitted");
        };
        let ingress = IngressSessionHandle::start(path).expect("Ingress Session");
        let mut stream = ingress
            .open_tcp(TargetEndpoint {
                hostname: b"echo.test".to_vec(),
                port: 443,
                resolved_addresses: Vec::new(),
            })
            .await
            .expect("open target Stream");
        let payload = vec![0x7c; 32 * 1024];
        stream.write_all(&payload).await.expect("write target");
        stream.shutdown().await.expect("half close target");
        let mut echoed = Vec::new();
        stream.read_to_end(&mut echoed).await.expect("read target");
        assert_eq!(echoed, payload);
        ingress.shutdown().await.expect("Ingress shutdown");

        shutdown.send(()).expect("node shutdown");
        let snapshot = runner.await.expect("node task").expect("node runtime");
        assert_eq!(snapshot.admitted_paths, 1);
        assert_eq!(snapshot.active_sessions, 0);
        assert_eq!(snapshot.active_target_connections, 0);
        connector.join().await;
        drop(node);
        drop(store);
        std::fs::remove_file(database).expect("remove authorization database");
    }

    #[tokio::test]
    async fn loopback_node_proxies_udp_datagrams_bidirectionally() {
        let ingress_key = generate_static_keypair().expect("Ingress key");
        let egress_key = Arc::new(generate_static_keypair().expect("Egress key"));
        let database = database_path();
        let store = Arc::new(
            AuthorizationStore::open(
                &database,
                EgressId::new("runtime-egress"),
                *egress_key.public(),
            )
            .expect("authorization store"),
        );
        enroll(&store, &ingress_key);
        let connector = EchoConnector::default();
        let node = Arc::new(
            EgressNode::bind(
                node_config(Arc::clone(&egress_key), Arc::clone(&store)),
                connector.clone(),
            )
            .await
            .expect("bind Egress node"),
        );
        let udp_echo = UdpSocket::bind("127.0.0.1:0").await.expect("UDP echo bind");
        let udp_address = udp_echo.local_addr().expect("UDP echo address");
        let echo_task = tokio::spawn(async move {
            let mut payload = [0_u8; 2048];
            let (received, peer) = udp_echo
                .recv_from(&mut payload)
                .await
                .expect("UDP echo receive");
            udp_echo
                .send_to(&payload[..received], peer)
                .await
                .expect("UDP echo send");
        });
        let (shutdown, shutdown_rx) = oneshot::channel();
        let runner = tokio::spawn(run_node(Arc::clone(&node), shutdown_rx));
        let PathAdmissionOutcome::Ready(path) =
            dial_ingress(&node, &ingress_key, &egress_key, 20, 20).await
        else {
            panic!("Path should be admitted");
        };
        let ingress = IngressSessionHandle::start(path).expect("Ingress Session");
        let mut association = ingress
            .open_udp(TargetEndpoint {
                hostname: Vec::new(),
                port: udp_address.port(),
                resolved_addresses: vec![udp_address.ip()],
            })
            .await
            .expect("open UDP Association");
        association.send(b"one-datagram".to_vec()).await.unwrap();
        assert_eq!(association.receive().await, Some(b"one-datagram".to_vec()));
        association.close().await.unwrap();
        echo_task.await.expect("UDP echo task");
        ingress.shutdown().await.expect("Ingress shutdown");
        shutdown.send(()).expect("node shutdown");
        runner.await.expect("node task").expect("node runtime");
        drop(node);
        drop(store);
        std::fs::remove_file(database).expect("remove authorization database");
    }

    #[tokio::test]
    async fn loopback_node_rejects_an_unenrolled_ingress() {
        let ingress_key = generate_static_keypair().expect("Ingress key");
        let egress_key = Arc::new(generate_static_keypair().expect("Egress key"));
        let database = database_path();
        let store = Arc::new(
            AuthorizationStore::open(
                &database,
                EgressId::new("runtime-egress"),
                *egress_key.public(),
            )
            .expect("authorization store"),
        );
        let node = Arc::new(
            EgressNode::bind(
                node_config(Arc::clone(&egress_key), Arc::clone(&store)),
                EchoConnector::default(),
            )
            .await
            .expect("bind Egress node"),
        );
        let (shutdown, shutdown_rx) = oneshot::channel();
        let runner = tokio::spawn(run_node(Arc::clone(&node), shutdown_rx));
        assert!(matches!(
            dial_ingress(&node, &ingress_key, &egress_key, 2, 2).await,
            PathAdmissionOutcome::Rejected {
                error: ErrorClass::EgressFailure,
                ..
            }
        ));
        shutdown.send(()).expect("node shutdown");
        let snapshot = runner.await.expect("node task").expect("node runtime");
        assert_eq!(snapshot.admitted_paths, 0);
        assert!(snapshot.rejected_paths >= 1);
        drop(node);
        drop(store);
        std::fs::remove_file(database).expect("remove authorization database");
    }

    #[tokio::test]
    async fn target_open_failure_is_returned_without_stopping_the_node() {
        let ingress_key = generate_static_keypair().expect("Ingress key");
        let egress_key = Arc::new(generate_static_keypair().expect("Egress key"));
        let database = database_path();
        let store = Arc::new(
            AuthorizationStore::open(
                &database,
                EgressId::new("runtime-egress"),
                *egress_key.public(),
            )
            .expect("authorization store"),
        );
        enroll(&store, &ingress_key);
        let node = Arc::new(
            EgressNode::bind(
                node_config(Arc::clone(&egress_key), Arc::clone(&store)),
                RejectConnector,
            )
            .await
            .expect("bind Egress node"),
        );
        let (shutdown, shutdown_rx) = oneshot::channel();
        let runner = tokio::spawn(run_node(Arc::clone(&node), shutdown_rx));
        let PathAdmissionOutcome::Ready(path) =
            dial_ingress(&node, &ingress_key, &egress_key, 3, 3).await
        else {
            panic!("Path should be admitted");
        };
        let ingress = IngressSessionHandle::start(path).expect("Ingress Session");
        assert!(matches!(
            ingress
                .open_tcp(TargetEndpoint {
                    hostname: b"refused.test".to_vec(),
                    port: 443,
                    resolved_addresses: Vec::new(),
                })
                .await,
            Err(OpenStreamError::Rejected {
                error: ErrorClass::TargetFailure,
                ..
            })
        ));
        ingress.shutdown().await.expect("Ingress shutdown");
        shutdown.send(()).expect("node shutdown");
        runner.await.expect("node task").expect("node runtime");
        drop(node);
        drop(store);
        std::fs::remove_file(database).expect("remove authorization database");
    }

    #[tokio::test]
    async fn node_shutdown_aborts_and_joins_active_sessions() {
        let ingress_key = generate_static_keypair().expect("Ingress key");
        let egress_key = Arc::new(generate_static_keypair().expect("Egress key"));
        let database = database_path();
        let store = Arc::new(
            AuthorizationStore::open(
                &database,
                EgressId::new("runtime-egress"),
                *egress_key.public(),
            )
            .expect("authorization store"),
        );
        enroll(&store, &ingress_key);
        let node = Arc::new(
            EgressNode::bind(
                node_config(Arc::clone(&egress_key), Arc::clone(&store)),
                EchoConnector::default(),
            )
            .await
            .expect("bind Egress node"),
        );
        let (shutdown, shutdown_rx) = oneshot::channel();
        let runner = tokio::spawn(run_node(Arc::clone(&node), shutdown_rx));
        let PathAdmissionOutcome::Ready(path) =
            dial_ingress(&node, &ingress_key, &egress_key, 4, 4).await
        else {
            panic!("Path should be admitted");
        };
        let ingress = IngressSessionHandle::start(path).expect("Ingress Session");
        shutdown.send(()).expect("node shutdown");
        let snapshot = runner.await.expect("node task").expect("node runtime");
        assert_eq!(snapshot.active_paths, 0);
        assert_eq!(snapshot.active_sessions, 0);
        drop(ingress);
        drop(node);
        drop(store);
        std::fs::remove_file(database).expect("remove authorization database");
    }

    #[tokio::test]
    async fn reconcile_disables_existing_and_new_sessions() {
        let ingress_key = generate_static_keypair().expect("Ingress key");
        let egress_key = Arc::new(generate_static_keypair().expect("Egress key"));
        let database = database_path();
        let store = Arc::new(
            AuthorizationStore::open(
                &database,
                EgressId::new("runtime-egress"),
                *egress_key.public(),
            )
            .expect("authorization store"),
        );
        enroll(&store, &ingress_key);
        let connector = EchoConnector::default();
        let node = Arc::new(
            EgressNode::bind(
                node_config(Arc::clone(&egress_key), Arc::clone(&store)),
                connector.clone(),
            )
            .await
            .expect("bind Egress node"),
        );
        let (shutdown, shutdown_rx) = oneshot::channel();
        let runner = tokio::spawn(run_node(Arc::clone(&node), shutdown_rx));
        let PathAdmissionOutcome::Ready(path) =
            dial_ingress(&node, &ingress_key, &egress_key, 5, 5).await
        else {
            panic!("Path should be admitted");
        };
        let ingress = IngressSessionHandle::start(path).expect("Ingress Session");
        let mut stream = ingress
            .open_tcp(TargetEndpoint {
                hostname: b"cleanup.test".to_vec(),
                port: 443,
                resolved_addresses: Vec::new(),
            })
            .await
            .expect("open cleanup target");
        stream.write_all(b"live").await.unwrap();
        let mut echoed = [0_u8; 4];
        stream.read_exact(&mut echoed).await.unwrap();
        let PathAdmissionOutcome::Ready(second_path) =
            dial_ingress(&node, &ingress_key, &egress_key, 5, 55).await
        else {
            panic!("second Path should be admitted");
        };
        ingress
            .add_path(second_path, MultipathPathObservation::default())
            .await
            .expect("add second cleanup Path");
        store
            .mutate(AuthorizationMutationRequest {
                actor_id: "test-admin".to_owned(),
                request_id: "disable-1".to_owned(),
                expected_generation: 1,
                ingress_id: IngressId::new("runtime-ingress"),
                mutation: AuthorizationMutation::Disable,
            })
            .expect("disable Ingress");
        let cleanup = node
            .reconcile_authorizations_until(Duration::from_secs(2))
            .await
            .expect("reconcile authorization");
        assert_eq!(cleanup.paths, 2);
        assert_eq!(cleanup.sessions, 1);
        assert_eq!(cleanup.streams, 1);
        assert_eq!(cleanup.target_connections, 1);
        assert!(matches!(
            dial_ingress(&node, &ingress_key, &egress_key, 6, 6).await,
            PathAdmissionOutcome::Rejected { .. }
        ));
        drop(stream);
        drop(ingress);
        shutdown.send(()).expect("node shutdown");
        runner.await.expect("node task").expect("node runtime");
        connector.join().await;
        drop(node);
        drop(store);
        std::fs::remove_file(database).expect("remove authorization database");
    }

    #[tokio::test]
    async fn node_attaches_a_second_path_to_the_existing_session() {
        let ingress_key = generate_static_keypair().expect("Ingress key");
        let egress_key = Arc::new(generate_static_keypair().expect("Egress key"));
        let database = database_path();
        let store = Arc::new(
            AuthorizationStore::open(
                &database,
                EgressId::new("runtime-egress"),
                *egress_key.public(),
            )
            .expect("authorization store"),
        );
        enroll(&store, &ingress_key);
        let connector = EchoConnector::default();
        let node = Arc::new(
            EgressNode::bind(
                node_config(Arc::clone(&egress_key), Arc::clone(&store)),
                connector.clone(),
            )
            .await
            .expect("bind Egress node"),
        );
        let (shutdown, shutdown_rx) = oneshot::channel();
        let runner = tokio::spawn(run_node(Arc::clone(&node), shutdown_rx));

        let PathAdmissionOutcome::Ready(first_path) =
            dial_ingress(&node, &ingress_key, &egress_key, 7, 7).await
        else {
            panic!("first Path should be admitted");
        };
        let first = IngressSessionHandle::start(first_path).expect("first Session");
        let mut probe = first
            .open_tcp(TargetEndpoint {
                hostname: b"probe.test".to_vec(),
                port: 443,
                resolved_addresses: Vec::new(),
            })
            .await
            .expect("first Path probe");
        probe.write_all(b"ready").await.unwrap();
        let mut echoed = [0_u8; 5];
        probe.read_exact(&mut echoed).await.unwrap();
        drop(probe);

        let PathAdmissionOutcome::Ready(second_path) =
            dial_ingress(&node, &ingress_key, &egress_key, 7, 8).await
        else {
            panic!("second Path should complete admission");
        };
        first
            .add_path(second_path, MultipathPathObservation::default())
            .await
            .expect("attach second Ingress Path");
        assert_eq!(first.snapshot().ready_paths, 2);
        let mut stream = first
            .open_tcp(TargetEndpoint {
                hostname: b"multipath.test".to_vec(),
                port: 443,
                resolved_addresses: Vec::new(),
            })
            .await
            .expect("multipath target");
        stream.write_all(b"multipath").await.unwrap();
        let mut echoed = [0_u8; 9];
        stream.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"multipath");
        let status = node.status_provider.sample();
        assert_eq!(status.active_sessions, 1);
        assert_eq!(status.active_streams, 1);
        assert_eq!(status.capacity_bps, 1_000_000_000);
        first
            .close_path(pathchord_core::PathId::new(8))
            .await
            .unwrap();
        stream.write_all(b"after-path-loss").await.unwrap();
        let mut after_loss = [0_u8; 15];
        stream.read_exact(&mut after_loss).await.unwrap();
        assert_eq!(&after_loss, b"after-path-loss");
        assert_eq!(first.snapshot().ready_paths, 1);
        stream.shutdown().await.unwrap();
        first.shutdown().await.expect("first Session shutdown");
        shutdown.send(()).expect("node shutdown");
        let snapshot = runner.await.expect("node task").expect("node runtime");
        assert_eq!(snapshot.duplicate_sessions, 0);
        assert_eq!(snapshot.admitted_paths, 2);
        connector.join().await;
        drop(node);
        drop(store);
        std::fs::remove_file(database).expect("remove authorization database");
    }
}
