//! Ingress-owned policy, Transit, Session, and logical TCP Stream runtime.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use pathchord_core::{PathId, ProtocolLimits, SessionId, TargetEndpoint as WireTargetEndpoint};
use pathchord_noise::{STATIC_KEY_LEN, StaticKeypair, WIRE_PROFILE_V1_PROLOGUE_PREFIX};
use pathchord_path::{
    AutoscaleDecision, AutoscaleInput, IngressPathAdmissionConfig, IngressSessionHandle,
    MultipathConfig, MultipathPathObservation, OpenStreamError, OpenUdpError, PathAdmissionError,
    PathAdmissionOutcome, PathAutoscaler, PathAutoscalerConfig, PathEconomicStatus,
    PathQualitySnapshot, SessionRuntimeError, SessionSnapshot, SessionUdpHandle, dial_path,
};
use pathchord_policy::{
    CompiledPolicy, EgressConfig, EgressId, EgressRouteCandidate, EgressRuntimeStatus, Evaluation,
    FlowProtocol, PolicyContext, ProxyRoutePlan, RoutePlan, RuntimeCatalog, RuntimeNodeState,
    Selector, TrafficPolicy, TrafficPolicyId, TransitProxyConfig, TransitProxyId,
    TransitProxyRuntimeStatus, ValidatedPolicySnapshot,
};
use pathchord_transit::{
    AdapterRegistry, ConnectRequest, DirectTransitAdapter, Endpoint as TransitEndpoint,
    TransitAdapter, TransitCredentialProvider, TransitError, ValidatedTransitAdapter,
};
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{Mutex, RwLock};
use tokio::task::JoinSet;
use tokio::time::{Instant, timeout};

use crate::{
    BoxedLocalConnection, BoxedUdpFlowHandle, ConnectionContext, DnsAdapterError, DnsRouteAdapter,
    DnsRouteRequest, DnsRouteSelection, FlowBridgeError, MAX_DNS_MESSAGE_BYTES, TcpFlowOpener,
};

pub const DEFAULT_PATH_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_ORDINARY_PROXY_ATTEMPTS: usize = 8;
const MAX_EGRESS_DIAL_ATTEMPTS: usize = 4;
const BACKGROUND_PATH_CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
const TCP_CAPABILITY: u64 = 1;
const UDP_CAPABILITY: u64 = 1 << 1;
const STATIC_PATH_DRAIN_TIMEOUT: Duration = Duration::from_secs(5);
const TRUST_FAILURE_WINDOW: Duration = Duration::from_secs(60);
const TRUST_FAILURE_COOLDOWN: Duration = Duration::from_secs(300);
const TRUST_FAILURE_THRESHOLD: usize = 3;
const AUTOSCALE_DECISION_INTERVAL: Duration = Duration::from_secs(5);
/// Keep one independently dialed Path ready to take over a transiently
/// failing business Path. The target is bounded by the Session's max-path
/// limit and is applied only while Egress admission is healthy.
const PATH_RESERVE_COUNT: usize = 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StaticReloadOutcome {
    pub generation: u64,
    pub added: Vec<TransitProxyId>,
    pub changed: Vec<TransitProxyId>,
    pub removed: Vec<TransitProxyId>,
}

pub struct PreparedStaticReload {
    base_generation: u64,
    compiled: CompiledPolicy,
    configs: BTreeMap<TransitProxyId, TransitProxyConfig>,
    adapters: BTreeMap<TransitProxyId, Arc<dyn TransitAdapter>>,
    outcome: StaticReloadOutcome,
}

impl std::fmt::Debug for PreparedStaticReload {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PreparedStaticReload")
            .field("base_generation", &self.base_generation)
            .field("outcome", &self.outcome)
            .finish_non_exhaustive()
    }
}

#[derive(Debug)]
pub struct IngressDataPlaneConfig {
    pub ingress_id: String,
    pub identity: StaticKeypair,
    pub policy: ValidatedPolicySnapshot,
    pub path_connect_timeout: Duration,
}

impl IngressDataPlaneConfig {
    pub fn new(
        ingress_id: impl Into<String>,
        identity: StaticKeypair,
        policy: ValidatedPolicySnapshot,
    ) -> Self {
        Self {
            ingress_id: ingress_id.into(),
            identity,
            policy,
            path_connect_timeout: DEFAULT_PATH_CONNECT_TIMEOUT,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DataPlaneSnapshot {
    pub configured_egresses: usize,
    pub sessions: usize,
    pub ready_paths: usize,
    pub streams: usize,
    pub retained_outbound_bytes: usize,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub path_quality: BTreeMap<PathId, PathQualitySnapshot>,
    pub egress_aggregate_capacity_bps: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataPlaneSessionSnapshot {
    pub egress_id: String,
    pub session: SessionSnapshot,
    pub path_transit: BTreeMap<PathId, String>,
    pub minimum_usable_paths: usize,
    pub eligible_transit_count: usize,
    pub traffic_policy_id: Option<String>,
    pub replication_cap_bps: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DynamicTransitRegistration {
    Registered,
    SourceBlocked,
    StaticConflict,
    StaleAdmission,
}

#[derive(Debug, Error)]
pub enum DataPlaneError {
    #[error("Ingress identity is invalid")]
    InvalidIngressIdentity,
    #[error("configured Egress public key is invalid")]
    InvalidEgressKey,
    #[error("policy compilation failed: {0}")]
    PolicyCompile(#[from] pathchord_policy::CompileError),
    #[error("compiled policy does not match its validated configuration generation")]
    PolicyGenerationMismatch,
    #[error("local policy rejected the flow")]
    PolicyRejected,
    #[error("no usable route is available")]
    NoUsableRoute,
    #[error("Transit adapter is unavailable: {0}")]
    TransitUnavailable(String),
    #[error("Transit connection failed: {0}")]
    Transit(#[from] TransitError),
    #[error("Path admission failed: {0}")]
    Admission(#[from] PathAdmissionError),
    #[error("Egress rejected Path admission")]
    AdmissionRejected,
    #[error("Session failed: {0}")]
    Session(#[from] SessionRuntimeError),
    #[error("Stream open failed: {0}")]
    Stream(#[from] OpenStreamError),
    #[error("UDP Association open failed: {0}")]
    Udp(#[from] OpenUdpError),
    #[error("Ingress data plane is shutting down")]
    ShuttingDown,
    #[error("secure identifier generation failed")]
    IdentifierGeneration,
    #[error("static Transit reload generation conflicts with the active snapshot")]
    StaticReloadConflict,
    #[error("changing Egress topology requires restarting the data plane")]
    StaticReloadRequiresRestart,
    #[error("static Transit identity conflicts with a subscription node")]
    StaticDynamicConflict,
    #[error("node probe configuration is invalid")]
    InvalidProbeConfig,
    #[error("control-plane reload transaction was rejected")]
    ControlCommitRejected,
}

struct SessionSlot {
    egress: EgressConfig,
    session: Mutex<Option<Arc<IngressSessionHandle>>>,
    dial_gate: Mutex<()>,
    transit_paths: Mutex<BTreeMap<TransitProxyId, BTreeSet<PathId>>>,
    draining_paths: Mutex<BTreeMap<PathId, (TransitProxyId, Instant)>>,
    autoscaler: Mutex<PathAutoscaler>,
    eligible_transits: Mutex<BTreeMap<TransitProxyId, u32>>,
    target_path_count: Mutex<usize>,
    replication_budget_bytes: Mutex<Option<u64>>,
    session_policy: Mutex<Option<MultipathConfig>>,
    warmup_cursor: std::sync::atomic::AtomicUsize,
    trust_failures: Mutex<TrustFailureState>,
    maintenance_sample: Mutex<(Instant, u64)>,
    last_autoscale_decision: Mutex<Instant>,
    maintenance_epoch: Instant,
}

impl SessionSlot {
    fn new(egress: EgressConfig) -> Self {
        let min_paths = (egress.status_requirements.min_usable_paths as usize).max(1);
        let now = Instant::now();
        Self {
            egress,
            session: Mutex::new(None),
            dial_gate: Mutex::new(()),
            transit_paths: Mutex::new(BTreeMap::new()),
            draining_paths: Mutex::new(BTreeMap::new()),
            autoscaler: Mutex::new(
                PathAutoscaler::new(PathAutoscalerConfig {
                    min_paths,
                    max_paths: 8_usize.max(min_paths),
                    ..PathAutoscalerConfig::default()
                })
                .expect("static autoscaler configuration"),
            ),
            eligible_transits: Mutex::new(BTreeMap::new()),
            target_path_count: Mutex::new(reserved_path_target(min_paths, 8_usize.max(min_paths))),
            replication_budget_bytes: Mutex::new(None),
            session_policy: Mutex::new(None),
            warmup_cursor: std::sync::atomic::AtomicUsize::new(0),
            trust_failures: Mutex::new(TrustFailureState::default()),
            maintenance_sample: Mutex::new((now, 0)),
            last_autoscale_decision: Mutex::new(
                now.checked_sub(AUTOSCALE_DECISION_INTERVAL).unwrap_or(now),
            ),
            maintenance_epoch: now,
        }
    }
}

#[derive(Debug, Default)]
struct TrustFailureState {
    failures: VecDeque<Instant>,
    retry_after: Option<Instant>,
    blocked_until: Option<Instant>,
    last_session: Option<SessionId>,
}

impl TrustFailureState {
    fn record_for(&mut self, session_id: SessionId, now: Instant) {
        if self.last_session == Some(session_id) {
            return;
        }
        self.last_session = Some(session_id);
        while self
            .failures
            .front()
            .is_some_and(|failure| now.duration_since(*failure) > TRUST_FAILURE_WINDOW)
        {
            self.failures.pop_front();
        }
        self.failures.push_back(now);
        if self.failures.len() >= TRUST_FAILURE_THRESHOLD {
            self.blocked_until = Some(now + TRUST_FAILURE_COOLDOWN);
            self.retry_after = self.blocked_until;
            return;
        }
        let exponent = (self.failures.len().saturating_sub(1) as u32).min(5);
        self.retry_after = Some(now + Duration::from_secs(1_u64 << exponent));
    }

    fn can_attempt(&mut self, now: Instant) -> bool {
        if self.blocked_until.is_some_and(|until| now >= until) {
            self.blocked_until = None;
            self.failures.clear();
        }
        self.retry_after
            .is_none_or(|retry_after| now >= retry_after)
    }

    fn reset(&mut self) {
        self.failures.clear();
        self.retry_after = None;
        self.blocked_until = None;
        self.last_session = None;
    }
}

pub struct IngressDataPlane {
    ingress_id: String,
    identity: Arc<StaticKeypair>,
    compiled: RwLock<CompiledPolicy>,
    generation: std::sync::atomic::AtomicU64,
    egresses: BTreeMap<EgressId, EgressConfig>,
    transit_configs: RwLock<BTreeMap<TransitProxyId, TransitProxyConfig>>,
    configuration_gate: RwLock<()>,
    traffic_policies: RwLock<BTreeMap<TrafficPolicyId, TrafficPolicy>>,
    dynamic_transit_configs: RwLock<BTreeMap<TransitProxyId, TransitProxyConfig>>,
    dynamic_admissions: RwLock<BTreeMap<TransitProxyId, ValidatedTransitAdapter>>,
    blocked_subscriptions: RwLock<BTreeSet<String>>,
    transit_adapters: RwLock<BTreeMap<TransitProxyId, Arc<dyn TransitAdapter>>>,
    runtime: RwLock<RuntimeCatalog>,
    sessions: BTreeMap<EgressId, Arc<SessionSlot>>,
    path_connect_timeout: Duration,
    shutting_down: std::sync::atomic::AtomicBool,
    retired_paths: Mutex<JoinSet<()>>,
    probes: Mutex<crate::node_probe::ProbeStore>,
    probe_running: Mutex<()>,
}

impl std::fmt::Debug for IngressDataPlane {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("IngressDataPlane")
            .field("ingress_id", &self.ingress_id)
            .field(
                "generation",
                &self.generation.load(std::sync::atomic::Ordering::Relaxed),
            )
            .field("egress_count", &self.egresses.len())
            .field(
                "transit_count",
                &self
                    .transit_configs
                    .try_read()
                    .map(|configs| configs.len())
                    .ok(),
            )
            .finish_non_exhaustive()
    }
}

impl IngressDataPlane {
    pub fn new(config: IngressDataPlaneConfig) -> Result<Self, DataPlaneError> {
        let compiled = CompiledPolicy::compile(&config.policy)?;
        Self::new_with_compiled(config, compiled)
    }

    /// Construct the runtime with the exact policy already validated and
    /// compiled by the configuration loader, including external data.
    pub fn new_with_compiled(
        config: IngressDataPlaneConfig,
        compiled: CompiledPolicy,
    ) -> Result<Self, DataPlaneError> {
        if !valid_identifier(config.ingress_id.as_bytes()) {
            return Err(DataPlaneError::InvalidIngressIdentity);
        }
        if !compiled.matches_snapshot(&config.policy) {
            return Err(DataPlaneError::PolicyGenerationMismatch);
        }
        let generation = config.policy.generation();
        let policy = config.policy.config();
        let egresses: BTreeMap<_, _> = policy
            .egresses
            .iter()
            .cloned()
            .map(|egress| (egress.id.clone(), egress))
            .collect();
        let transit_configs: BTreeMap<_, _> = policy
            .transit_proxies
            .iter()
            .cloned()
            .map(|transit| (transit.id.clone(), transit))
            .collect();
        let traffic_policies: BTreeMap<_, _> = policy
            .traffic_policies
            .iter()
            .cloned()
            .map(|policy| (policy.id.clone(), policy))
            .collect();
        let sessions = egresses
            .iter()
            .map(|(id, egress)| (id.clone(), Arc::new(SessionSlot::new(egress.clone()))))
            .collect();
        let mut runtime = RuntimeCatalog::default();
        let mut transit_adapters: BTreeMap<TransitProxyId, Arc<dyn TransitAdapter>> =
            BTreeMap::new();
        for (id, transit) in &transit_configs {
            if transit.protocol == "direct" {
                transit_adapters.insert(
                    id.clone(),
                    Arc::new(DirectTransitAdapter::new(
                        id.as_str(),
                        config.path_connect_timeout,
                    )),
                );
                runtime.set_transit_proxy(
                    id.clone(),
                    TransitProxyRuntimeStatus {
                        state: RuntimeNodeState::Ready,
                        capabilities: if transit.options.udp == Some(false) {
                            BTreeSet::from([FlowProtocol::Tcp])
                        } else {
                            BTreeSet::from([FlowProtocol::Tcp, FlowProtocol::Udp])
                        },
                        selection_score: 1,
                        quota_remaining: None,
                        traffic_multiplier_basis_points: None,
                        ..TransitProxyRuntimeStatus::default()
                    },
                );
            }
        }
        for id in egresses.keys() {
            runtime.set_egress(id.clone(), EgressRuntimeStatus::default());
        }
        Ok(Self {
            ingress_id: config.ingress_id,
            identity: Arc::new(config.identity),
            compiled: RwLock::new(compiled),
            generation: std::sync::atomic::AtomicU64::new(generation.get()),
            egresses,
            transit_configs: RwLock::new(transit_configs),
            configuration_gate: RwLock::new(()),
            traffic_policies: RwLock::new(traffic_policies),
            dynamic_transit_configs: RwLock::new(BTreeMap::new()),
            dynamic_admissions: RwLock::new(BTreeMap::new()),
            blocked_subscriptions: RwLock::new(BTreeSet::new()),
            transit_adapters: RwLock::new(transit_adapters),
            runtime: RwLock::new(runtime),
            sessions,
            path_connect_timeout: config.path_connect_timeout,
            shutting_down: std::sync::atomic::AtomicBool::new(false),
            retired_paths: Mutex::new(JoinSet::new()),
            probes: Mutex::new(crate::node_probe::ProbeStore::default()),
            probe_running: Mutex::new(()),
        })
    }

    pub async fn register_transit_adapter(
        &self,
        id: TransitProxyId,
        adapter: Arc<dyn TransitAdapter>,
        mut status: TransitProxyRuntimeStatus,
    ) -> Result<(), DataPlaneError> {
        let _configuration = self.configuration_gate.write().await;
        let config = self.transit_configs.read().await.get(&id).cloned();
        let Some(config) = config else {
            return Err(DataPlaneError::TransitUnavailable(id.as_str().to_owned()));
        };
        if !adapter.supports_udp() || config.options.udp == Some(false) {
            status.capabilities.remove(&FlowProtocol::Udp);
        }
        if !adapter.supports_tcp() {
            status.capabilities.remove(&FlowProtocol::Tcp);
        }
        self.probes.lock().await.forget(&id);
        self.transit_adapters
            .write()
            .await
            .insert(id.clone(), adapter);
        self.runtime.write().await.set_transit_proxy(id, status);
        Ok(())
    }

    pub async fn replace_compiled_policy(&self, compiled: CompiledPolicy) {
        let _configuration = self.configuration_gate.write().await;
        let generation = compiled.generation().get();
        let traffic_policies = compiled.traffic_policies();
        // Keep runtime admission budgets aligned with the atomically published
        // policy generation used for subsequent Streams and UDP Associations.
        // Existing Sessions retain their current actor state until the next
        // routed open applies the selected policy configuration.
        *self.traffic_policies.write().await = traffic_policies;
        *self.compiled.write().await = compiled;
        self.generation
            .store(generation, std::sync::atomic::Ordering::Release);
    }

    /// Builds and validates every changed adapter before publishing any part
    /// of the next static policy generation. New admissions hold the same
    /// gate while selecting both policy and adapter, so they cannot mix them.
    pub async fn prepare_static_snapshot<P>(
        &self,
        snapshot: &ValidatedPolicySnapshot,
        registry: &AdapterRegistry<P>,
    ) -> Result<PreparedStaticReload, DataPlaneError>
    where
        P: TransitCredentialProvider + 'static,
    {
        let compiled = snapshot.compile()?;
        self.prepare_static_snapshot_with_compiled(snapshot, compiled, registry)
            .await
    }

    pub async fn prepare_static_snapshot_with_compiled<P>(
        &self,
        snapshot: &ValidatedPolicySnapshot,
        compiled: CompiledPolicy,
        registry: &AdapterRegistry<P>,
    ) -> Result<PreparedStaticReload, DataPlaneError>
    where
        P: TransitCredentialProvider + 'static,
    {
        if self
            .shutting_down
            .load(std::sync::atomic::Ordering::Acquire)
        {
            return Err(DataPlaneError::ShuttingDown);
        }
        if !compiled.matches_snapshot(snapshot) {
            return Err(DataPlaneError::PolicyGenerationMismatch);
        }
        let desired: BTreeMap<_, _> = snapshot
            .config()
            .transit_proxies
            .iter()
            .cloned()
            .map(|config| (config.id.clone(), config))
            .collect();
        let egresses: BTreeMap<_, _> = snapshot
            .config()
            .egresses
            .iter()
            .cloned()
            .map(|config| (config.id.clone(), config))
            .collect();
        if egresses != self.egresses {
            return Err(DataPlaneError::StaticReloadRequiresRestart);
        }
        let current_policies = self.traffic_policies.read().await.clone();
        let next_policies = compiled.traffic_policies();
        if egresses.values().any(|egress| {
            egress
                .traffic_policy
                .as_ref()
                .is_some_and(|id| current_policies.get(id) != next_policies.get(id))
        }) {
            return Err(DataPlaneError::StaticReloadRequiresRestart);
        }
        let (generation, previous, previous_adapters) = {
            let _configuration = self.configuration_gate.read().await;
            (
                self.generation.load(std::sync::atomic::Ordering::Acquire),
                self.transit_configs.read().await.clone(),
                self.transit_adapters.read().await.clone(),
            )
        };
        if snapshot.generation().get() <= generation {
            return Err(DataPlaneError::StaticReloadConflict);
        }
        let mut outcome = StaticReloadOutcome {
            generation: snapshot.generation().get(),
            added: Vec::new(),
            changed: Vec::new(),
            removed: previous
                .keys()
                .filter(|id| !desired.contains_key(*id))
                .cloned()
                .collect(),
        };
        let mut prepared = BTreeMap::new();
        for (id, config) in &desired {
            let adapter = if previous.get(id) == Some(config) && previous_adapters.contains_key(id)
            {
                Arc::clone(&previous_adapters[id])
            } else {
                let adapter = registry.build(config).await?;
                timeout(self.path_connect_timeout, adapter.prepare())
                    .await
                    .map_err(|_| {
                        TransitError::Connection("Transit adapter preparation timed out".to_owned())
                    })??;
                if previous.contains_key(id) {
                    outcome.changed.push(id.clone());
                } else {
                    outcome.added.push(id.clone());
                }
                adapter
            };
            prepared.insert(id.clone(), adapter);
        }
        Ok(PreparedStaticReload {
            base_generation: generation,
            compiled,
            configs: desired,
            adapters: prepared,
            outcome,
        })
    }

    pub async fn apply_static_snapshot<P>(
        &self,
        snapshot: &ValidatedPolicySnapshot,
        registry: &AdapterRegistry<P>,
    ) -> Result<StaticReloadOutcome, DataPlaneError>
    where
        P: TransitCredentialProvider + 'static,
    {
        let prepared = self.prepare_static_snapshot(snapshot, registry).await?;
        self.commit_static_snapshot(prepared, || Ok(())).await
    }

    /// Acquires every runtime publication guard before calling the synchronous
    /// durable hook. No await separates a successful hook from publication.
    pub async fn commit_static_snapshot<F>(
        &self,
        prepared: PreparedStaticReload,
        before_commit: F,
    ) -> Result<StaticReloadOutcome, DataPlaneError>
    where
        F: FnOnce() -> Result<(), DataPlaneError> + Send,
    {
        self.commit_static_snapshot_inner(prepared, || before_commit().map(|()| None))
            .await
    }

    /// Commits declarative subscription visibility in the same publication
    /// barrier as the static graph and its durable control transaction.
    pub async fn commit_static_snapshot_with_subscription_visibility<F>(
        &self,
        prepared: PreparedStaticReload,
        before_commit: F,
    ) -> Result<StaticReloadOutcome, DataPlaneError>
    where
        F: FnOnce() -> Result<BTreeMap<String, (bool, bool)>, DataPlaneError> + Send,
    {
        self.commit_static_snapshot_inner(prepared, || before_commit().map(Some))
            .await
    }

    async fn commit_static_snapshot_inner<F>(
        &self,
        prepared: PreparedStaticReload,
        before_commit: F,
    ) -> Result<StaticReloadOutcome, DataPlaneError>
    where
        F: FnOnce() -> Result<Option<BTreeMap<String, (bool, bool)>>, DataPlaneError> + Send,
    {
        let _configuration = self.configuration_gate.write().await;
        if self
            .shutting_down
            .load(std::sync::atomic::Ordering::Acquire)
        {
            return Err(DataPlaneError::ShuttingDown);
        }
        if self.generation.load(std::sync::atomic::Ordering::Acquire) != prepared.base_generation {
            return Err(DataPlaneError::StaticReloadConflict);
        }
        let dynamic = self.dynamic_transit_configs.read().await;
        if prepared.configs.keys().any(|id| dynamic.contains_key(id)) {
            return Err(DataPlaneError::StaticDynamicConflict);
        }
        let mut configs = self.transit_configs.write().await;
        let mut adapters = self.transit_adapters.write().await;
        let mut runtime = self.runtime.write().await;
        let mut policies = self.traffic_policies.write().await;
        let mut compiled = self.compiled.write().await;
        let mut probes = self.probes.lock().await;
        let mut retirement = self.retired_paths.lock().await;
        let mut next_adapters = adapters.clone();
        let mut next_runtime = runtime.clone();
        let mut blocked_subscriptions = self.blocked_subscriptions.write().await;
        for id in configs.keys() {
            if !prepared.configs.contains_key(id) {
                next_adapters.remove(id);
                next_runtime.remove_dynamic_transit_proxy(id);
            }
        }
        for (id, adapter) in &prepared.adapters {
            let mut status = next_runtime.transit_proxy(id).cloned().unwrap_or_default();
            status.state = if prepared.configs[id]
                .source
                .as_ref()
                .is_some_and(|source| blocked_subscriptions.contains(&source.subscription))
            {
                RuntimeNodeState::Draining
            } else {
                RuntimeNodeState::Ready
            };
            status.capabilities = adapter_capabilities(adapter.as_ref(), &prepared.configs[id]);
            status.selection_score = status.selection_score.max(1);
            next_runtime.set_transit_proxy(id.clone(), status);
            next_adapters.insert(id.clone(), Arc::clone(adapter));
        }
        let next_policies = prepared.compiled.traffic_policies();
        let retired: BTreeSet<_> = prepared
            .outcome
            .changed
            .iter()
            .chain(prepared.outcome.removed.iter())
            .cloned()
            .collect();
        let mut guarded_paths = Vec::new();
        if !retired.is_empty() {
            for slot in self.sessions.values() {
                let session = slot.session.lock().await.clone();
                guarded_paths.push((
                    session,
                    slot.transit_paths.lock().await,
                    slot.draining_paths.lock().await,
                    slot.eligible_transits.lock().await,
                ));
            }
        }
        if let Some(visibility) = before_commit()? {
            // An absent source is deleted. Mark it unavailable before the
            // new graph is published; a concurrent old worker cannot revive it.
            for (id, (enabled, changed)) in &visibility {
                if !*enabled || *changed {
                    blocked_subscriptions.insert(id.clone());
                }
            }
            for config in prepared.configs.values().chain(dynamic.values()) {
                let Some(source) = config
                    .source
                    .as_ref()
                    .filter(|source| source.source_type != "static")
                else {
                    continue;
                };
                let enabled = visibility
                    .get(&source.subscription)
                    .is_some_and(|(enabled, _)| *enabled)
                    && !blocked_subscriptions.contains(&source.subscription);
                if !enabled {
                    blocked_subscriptions.insert(source.subscription.clone());
                    probes.cancel(&config.id);
                }
                if let Some(mut status) = next_runtime.transit_proxy(&config.id).cloned() {
                    if !enabled {
                        status.state = RuntimeNodeState::Draining;
                    } else if prepared.adapters.contains_key(&config.id) {
                        status.state = RuntimeNodeState::Ready;
                    }
                    next_runtime.set_transit_proxy(config.id.clone(), status);
                }
            }
        }
        *configs = prepared.configs;
        *adapters = next_adapters;
        *runtime = next_runtime;
        *policies = next_policies;
        *compiled = prepared.compiled;
        self.generation.store(
            prepared.outcome.generation,
            std::sync::atomic::Ordering::Release,
        );
        for id in &retired {
            probes.forget(id);
        }
        while retirement.try_join_next().is_some() {}
        for (session, mut paths, mut draining, mut eligible) in guarded_paths {
            for id in &retired {
                let path_ids = paths.remove(id).unwrap_or_default();
                eligible.remove(id);
                for path_id in path_ids {
                    draining.remove(&path_id);
                    if let Some(session) = session.as_ref() {
                        let session = Arc::clone(session);
                        retirement.spawn(async move {
                            let _ =
                                timeout(Duration::from_secs(1), session.drain_path(path_id)).await;
                            tokio::time::sleep(STATIC_PATH_DRAIN_TIMEOUT).await;
                            let _ =
                                timeout(Duration::from_secs(1), session.close_path(path_id)).await;
                        });
                    }
                }
            }
        }
        Ok(prepared.outcome)
    }

    pub fn policy_generation(&self) -> u64 {
        self.generation.load(std::sync::atomic::Ordering::Acquire)
    }

    pub async fn configure_node_probe(
        &self,
        config: Option<crate::TransitProbeConfig>,
    ) -> Result<(), DataPlaneError> {
        if config.as_ref().is_some_and(|config| !config.valid()) {
            return Err(DataPlaneError::InvalidProbeConfig);
        }
        self.probes.lock().await.configure(config);
        Ok(())
    }

    pub async fn probe_transits(&self) {
        let Ok(_running) = self.probe_running.try_lock() else {
            return;
        };
        let (config, candidates) = {
            let _configuration = self.configuration_gate.read().await;
            let mut probes = self.probes.lock().await;
            let Some(config) = probes.config.clone() else {
                return;
            };
            let adapters: Vec<_> = self
                .transit_adapters
                .read()
                .await
                .iter()
                .map(|(id, adapter)| (id.clone(), Arc::clone(adapter)))
                .collect();
            let runtime = self.runtime.read().await;
            let adapters: Vec<_> = adapters
                .into_iter()
                .filter(|(id, _)| {
                    runtime.transit_proxy(id).is_some_and(|status| {
                        matches!(
                            status.state,
                            RuntimeNodeState::Ready | RuntimeNodeState::Degraded
                        )
                    })
                })
                .collect();
            drop(runtime);
            if adapters.is_empty() {
                return;
            }
            let start = probes.cursor % adapters.len();
            let admissions = self.dynamic_admissions.read().await;
            let candidates: Vec<_> = adapters
                .iter()
                .cycle()
                .skip(start)
                .take(config.max_nodes_per_batch.min(adapters.len()))
                .map(|(id, adapter)| crate::node_probe::ProbeCandidate {
                    id: id.clone(),
                    adapter: Arc::clone(adapter),
                    admission: admissions.get(id).map(|admission| admission.revocation()),
                    cancelled: probes.arm(id),
                })
                .collect();
            probes.cursor = (start + candidates.len()) % adapters.len();
            (config, candidates)
        };
        let expected: BTreeMap<_, _> = candidates
            .iter()
            .map(|candidate| {
                (
                    candidate.id.clone(),
                    (Arc::clone(&candidate.adapter), candidate.admission.clone()),
                )
            })
            .collect();
        let results = crate::node_probe::probe_batch(config.clone(), candidates).await;
        let _configuration = self.configuration_gate.read().await;
        let current = self.transit_adapters.read().await;
        let runtime = self.runtime.read().await;
        let mut probes = self.probes.lock().await;
        probes.finish_batch();
        if probes.config.as_ref() != Some(&config) {
            return;
        }
        for (id, outcome) in results {
            if current.get(&id).zip(expected.get(&id)).is_some_and(
                |(current, (expected, admission))| {
                    Arc::ptr_eq(current, expected)
                        && admission.as_ref().is_none_or(|token| token.is_valid())
                },
            ) && runtime.transit_proxy(&id).is_some_and(|status| {
                matches!(
                    status.state,
                    RuntimeNodeState::Ready | RuntimeNodeState::Degraded
                )
            }) {
                probes.record(id, outcome, config.window_size);
            }
        }
    }

    pub async fn transit_observations(
        &self,
    ) -> BTreeMap<TransitProxyId, crate::TransitProbeObservation> {
        let _configuration = self.configuration_gate.read().await;
        let runtime = self.runtime.read().await;
        let static_configs = self.transit_configs.read().await;
        let dynamic_configs = self.dynamic_transit_configs.read().await;
        let adapters = self.transit_adapters.read().await;
        let nodes = static_configs
            .keys()
            .chain(dynamic_configs.keys())
            .map(|id| {
                (
                    id.clone(),
                    adapters.contains_key(id)
                        && runtime.transit_proxy(id).is_some_and(|status| {
                            matches!(
                                status.state,
                                RuntimeNodeState::Ready | RuntimeNodeState::Degraded
                            )
                        }),
                )
            })
            .collect::<Vec<_>>();
        self.probes.lock().await.observations(nodes)
    }

    #[cfg(test)]
    pub(crate) async fn register_dynamic_transit_adapter(
        &self,
        config: TransitProxyConfig,
        adapter: Arc<dyn TransitAdapter>,
        status: TransitProxyRuntimeStatus,
    ) -> DynamicTransitRegistration {
        self.register_dynamic_transit_inner(config, adapter, status, None)
            .await
    }

    pub async fn register_verified_dynamic_transit_adapter(
        &self,
        config: TransitProxyConfig,
        admission: ValidatedTransitAdapter,
        status: TransitProxyRuntimeStatus,
    ) -> DynamicTransitRegistration {
        if !admission.matches_config(&config) {
            return DynamicTransitRegistration::StaleAdmission;
        }
        let adapter = admission.adapter();
        self.register_dynamic_transit_inner(config, adapter, status, Some(admission))
            .await
    }

    async fn register_dynamic_transit_inner(
        &self,
        config: TransitProxyConfig,
        adapter: Arc<dyn TransitAdapter>,
        mut status: TransitProxyRuntimeStatus,
        admission: Option<ValidatedTransitAdapter>,
    ) -> DynamicTransitRegistration {
        let _configuration = self.configuration_gate.write().await;
        if self.transit_configs.read().await.contains_key(&config.id) {
            return DynamicTransitRegistration::StaticConflict;
        }
        if admission
            .as_ref()
            .is_some_and(|value| !value.matches_config(&config))
        {
            return DynamicTransitRegistration::StaleAdmission;
        }
        if !adapter.supports_udp() || config.options.udp == Some(false) {
            status.capabilities.remove(&FlowProtocol::Udp);
        }
        if !adapter.supports_tcp() {
            status.capabilities.remove(&FlowProtocol::Tcp);
        }
        let previous = self
            .dynamic_admissions
            .read()
            .await
            .get(&config.id)
            .cloned();
        let identity_changed = previous.as_ref().is_some_and(|old| {
            admission
                .as_ref()
                .is_none_or(|next| !old.same_connection(next))
        });
        let mut path_draining = false;
        for slot in self.sessions.values() {
            if slot
                .draining_paths
                .lock()
                .await
                .values()
                .any(|(id, _)| id == &config.id)
            {
                path_draining = true;
                break;
            }
        }
        if identity_changed || path_draining {
            self.retire_replaced_transit_paths_inner(std::slice::from_ref(&config.id))
                .await;
        }
        let blocked = self.subscription_is_blocked(&config).await;
        if blocked {
            status.state = RuntimeNodeState::Draining;
            if let Some(admission) = &admission {
                admission.revocation().revoke();
            }
        }
        let id = config.id.clone();
        self.probes.lock().await.forget(&id);
        let mut configs = self.dynamic_transit_configs.write().await;
        let mut adapters = self.transit_adapters.write().await;
        let mut admissions = self.dynamic_admissions.write().await;
        let mut runtime = self.runtime.write().await;
        if let Some(previous) = admissions.remove(&id)
            && admission
                .as_ref()
                .is_none_or(|next| !previous.revocation().same(&next.revocation()))
        {
            previous.revocation().revoke();
        }
        if let Some(admission) = admission {
            admissions.insert(id.clone(), admission);
        }
        configs.insert(id.clone(), config.clone());
        adapters.insert(id, adapter);
        runtime.set_dynamic_transit_proxy(config, status);
        if blocked {
            DynamicTransitRegistration::SourceBlocked
        } else {
            DynamicTransitRegistration::Registered
        }
    }

    pub async fn publish_dynamic_transit_status(
        &self,
        config: TransitProxyConfig,
        mut status: TransitProxyRuntimeStatus,
    ) {
        let _configuration = self.configuration_gate.write().await;
        if self.transit_configs.read().await.contains_key(&config.id) {
            return;
        }
        // Status-only publication never admits a node; readiness requires a
        // validated adapter registration with its bound admission token.
        if matches!(
            status.state,
            RuntimeNodeState::Ready | RuntimeNodeState::Degraded
        ) {
            status.state = RuntimeNodeState::Down;
            status.capabilities.clear();
        }
        if self.subscription_is_blocked(&config).await {
            status.state = RuntimeNodeState::Draining;
        }
        if status.state != RuntimeNodeState::Ready
            && self
                .dynamic_admissions
                .read()
                .await
                .contains_key(&config.id)
        {
            self.retire_replaced_transit_paths_inner(std::slice::from_ref(&config.id))
                .await;
        }
        if status.state != RuntimeNodeState::Ready {
            self.probes.lock().await.cancel(&config.id);
        }
        let mut configs = self.dynamic_transit_configs.write().await;
        let admissions = self.dynamic_admissions.read().await;
        let mut runtime = self.runtime.write().await;
        if status.state != RuntimeNodeState::Ready
            && let Some(admission) = admissions.get(&config.id)
        {
            admission.revocation().revoke();
        }
        configs.insert(config.id.clone(), config.clone());
        runtime.set_dynamic_transit_proxy(config, status);
    }

    async fn subscription_is_blocked(&self, config: &TransitProxyConfig) -> bool {
        let blocked = self.blocked_subscriptions.read().await;
        config
            .source
            .as_ref()
            .is_some_and(|source| blocked.contains(&source.subscription))
    }

    /// Runs a durable control mutation while new flow selection and dynamic
    /// publication are fenced. All async locks are acquired before `commit`,
    /// so cancellation cannot interrupt a successful commit before its new
    /// visibility takes effect. The returned visibility must reflect current
    /// durable state, including on idempotent replays.
    pub(crate) async fn subscription_transaction<T>(
        &self,
        subscription: &str,
        commit: impl FnOnce() -> (T, Option<bool>) + Send,
    ) -> T {
        let _configuration = self.configuration_gate.write().await;
        let static_configs = self.transit_configs.read().await;
        let dynamic_configs = self.dynamic_transit_configs.read().await;
        let mut blocked = self.blocked_subscriptions.write().await;
        let admissions = self.dynamic_admissions.read().await;
        let mut runtime = self.runtime.write().await;
        let mut probes = self.probes.lock().await;
        let (result, enabled) = commit();
        if let Some(enabled) = enabled
            && !enabled
        {
            blocked.insert(subscription.to_owned());
            for config in static_configs.values().chain(dynamic_configs.values()) {
                if config
                    .source
                    .as_ref()
                    .is_some_and(|source| source.subscription == subscription)
                    && let Some(mut status) = runtime.transit_proxy(&config.id).cloned()
                {
                    if let Some(admission) = admissions.get(&config.id) {
                        admission.revocation().revoke();
                    }
                    probes.cancel(&config.id);
                    status.state = RuntimeNodeState::Draining;
                    runtime.set_transit_proxy(config.id.clone(), status);
                }
            }
        }
        result
    }

    /// Releases a previously blocked source only after a worker has verified
    /// and refreshed its current full specification while holding the control
    /// dispatcher lock. Existing draining nodes are republished by the worker.
    pub async fn allow_subscription_after_refresh(&self, subscription: &str) {
        let _configuration = self.configuration_gate.write().await;
        self.blocked_subscriptions
            .write()
            .await
            .remove(subscription);
        let static_configs = self.transit_configs.read().await;
        let adapters = self.transit_adapters.read().await;
        let mut runtime = self.runtime.write().await;
        for config in static_configs.values() {
            if config
                .source
                .as_ref()
                .is_some_and(|source| source.subscription == subscription)
                && adapters.contains_key(&config.id)
                && let Some(mut status) = runtime.transit_proxy(&config.id).cloned()
                && status.state == RuntimeNodeState::Draining
            {
                status.state = RuntimeNodeState::Ready;
                runtime.set_transit_proxy(config.id.clone(), status);
            }
        }
    }

    /// Initializes visibility from durable control state before any listener
    /// accepts business flows. Runtime control mutations use the transaction
    /// above, not this startup convenience method.
    pub async fn initialize_subscription_visibility(&self, subscription: &str, enabled: bool) {
        self.subscription_transaction(subscription, || ((), Some(enabled)))
            .await;
    }

    pub async fn apply_transit_admin_metadata(
        &self,
        id: &TransitProxyId,
        labels: BTreeMap<String, String>,
        tags: BTreeSet<String>,
    ) -> bool {
        let _configuration = self.configuration_gate.read().await;
        let mut runtime = self.runtime.write().await;
        let Some(mut status) = runtime.transit_proxy(id).cloned() else {
            return false;
        };
        status.labels = labels;
        status.tags = tags;
        runtime.set_transit_proxy(id.clone(), status);
        true
    }

    pub async fn drain_transit(&self, id: &TransitProxyId) {
        let _configuration = self.configuration_gate.read().await;
        if !self
            .runtime
            .read()
            .await
            .transit_proxy(id)
            .is_some_and(|status| status.state == RuntimeNodeState::Draining)
        {
            return;
        }
        for slot in self.sessions.values() {
            let session = slot.session.lock().await.clone();
            let path_ids = slot
                .transit_paths
                .lock()
                .await
                .get(id)
                .cloned()
                .unwrap_or_default();
            if let Some(session) = session {
                for path_id in path_ids {
                    if session.drain_path(path_id).await.is_ok() {
                        slot.draining_paths
                            .lock()
                            .await
                            .insert(path_id, (id.clone(), Instant::now()));
                    }
                }
            }
        }
    }

    /// Remove old Paths from future route eligibility before replacing the
    /// adapter behind an existing dynamic node identity.
    pub async fn retire_replaced_transit_paths(&self, ids: &[TransitProxyId]) {
        let _configuration = self.configuration_gate.write().await;
        self.retire_replaced_transit_paths_inner(ids).await;
    }

    async fn retire_replaced_transit_paths_inner(&self, ids: &[TransitProxyId]) {
        let mut retirement = self.retired_paths.lock().await;
        while retirement.try_join_next().is_some() {}
        for slot in self.sessions.values() {
            let mut session_guard = slot.session.lock().await;
            let session = session_guard.clone();
            let mut paths = slot.transit_paths.lock().await;
            let mut draining = slot.draining_paths.lock().await;
            let mut eligible = slot.eligible_transits.lock().await;
            let mut removed_paths = BTreeSet::new();
            for id in ids {
                let path_ids = paths.remove(id).unwrap_or_default();
                eligible.remove(id);
                for path_id in path_ids {
                    draining.remove(&path_id);
                    removed_paths.insert(path_id);
                }
            }
            if let Some(session) = session {
                let ready = session.snapshot().ready_path_ids;
                if !removed_paths.is_empty() && ready.iter().all(|id| removed_paths.contains(id)) {
                    // The last drained Path cannot return its Session to
                    // Active; preserve the old actor for admitted flows and
                    // let the next open establish a fresh Session.
                    session_guard.take();
                    paths.clear();
                    draining.clear();
                    *slot.target_path_count.lock().await =
                        (slot.egress.status_requirements.min_usable_paths as usize).max(1);
                    slot.autoscaler.lock().await.reset();
                }
                for path_id in removed_paths {
                    let session = Arc::clone(&session);
                    retirement.spawn(async move {
                        // The Path was removed from new-route eligibility
                        // above; existing admitted Streams may still use it
                        // until the grace period expires.
                        tokio::time::sleep(STATIC_PATH_DRAIN_TIMEOUT).await;
                        let _ = timeout(Duration::from_secs(1), session.drain_path(path_id)).await;
                        let _ = timeout(Duration::from_secs(1), session.close_path(path_id)).await;
                    });
                }
            }
        }
    }

    pub async fn transit_in_use(&self, id: &TransitProxyId) -> bool {
        for slot in self.sessions.values() {
            if slot.transit_paths.lock().await.contains_key(id)
                || slot
                    .draining_paths
                    .lock()
                    .await
                    .values()
                    .any(|(transit_id, _)| transit_id == id)
            {
                return true;
            }
        }
        false
    }

    pub async fn remove_dynamic_transit(&self, id: &TransitProxyId) {
        let _configuration = self.configuration_gate.write().await;
        let mut configs = self.dynamic_transit_configs.write().await;
        if !configs.contains_key(id) {
            return;
        }
        let mut adapters = self.transit_adapters.write().await;
        let mut admissions = self.dynamic_admissions.write().await;
        let mut runtime = self.runtime.write().await;
        let mut probes = self.probes.lock().await;
        configs.remove(id);
        adapters.remove(id);
        if let Some(admission) = admissions.remove(id) {
            admission.revocation().revoke();
        }
        runtime.remove_dynamic_transit_proxy(id);
        probes.forget(id);
    }

    pub fn dns_route_adapter(self: &Arc<Self>) -> Arc<dyn DnsRouteAdapter> {
        Arc::new(DataPlaneDnsAdapter {
            data_plane: Arc::clone(self),
        })
    }

    /// Establishes the configured Egress Path pool without synthesizing a
    /// business flow. Every Egress owns one common Transit binding and one
    /// minimum; route matches only decide which already-owned Session is used.
    pub async fn warmup(&self) {
        let _configuration = self.configuration_gate.read().await;
        let sessions: Vec<_> = self
            .sessions
            .iter()
            .map(|(id, slot)| (id.clone(), Arc::clone(slot)))
            .collect();
        for (egress_id, slot) in sessions {
            let candidates = self.eligible_transits_for_egress(&slot.egress).await;
            {
                let mut eligible = slot.eligible_transits.lock().await;
                eligible.clear();
                eligible.extend(candidates.iter().cloned());
            }
            let session = slot.session.lock().await.clone();
            let max_paths = slot.autoscaler.lock().await.config().max_paths;
            let target = reserved_path_target(
                (slot.egress.status_requirements.min_usable_paths as usize).max(1),
                max_paths,
            );
            if !candidates.is_empty()
                && session.as_ref().is_none_or(|current| {
                    current.snapshot().closed || current.snapshot().ready_paths < target
                })
            {
                let index = slot
                    .warmup_cursor
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
                    % candidates.len();
                let transit = &candidates[index].0;
                if session
                    .as_ref()
                    .is_none_or(|current| current.snapshot().closed)
                {
                    let _ = self
                        .ensure_session_path(
                            &egress_id,
                            transit,
                            false,
                            BACKGROUND_PATH_CONNECT_TIMEOUT.min(self.path_connect_timeout),
                        )
                        .await;
                } else {
                    let _ = self.add_session_path(&egress_id, transit).await;
                }
            }
        }
        // Existing Sessions still receive their low-frequency aggregate demand
        // sample and autoscaling decision after the unconditional bootstrap.
        for (egress_id, slot) in &self.sessions {
            let session = slot.session.lock().await.clone();
            if session
                .as_ref()
                .is_none_or(|current| current.snapshot().closed)
            {
                continue;
            }
            let snapshot = session.as_ref().map(|session| session.snapshot());
            let total_bytes = snapshot.as_ref().map_or(0, |snapshot| {
                snapshot.bytes_sent.saturating_add(snapshot.bytes_received)
            });
            let now = Instant::now();
            let mut sample = slot.maintenance_sample.lock().await;
            let elapsed_ms = now
                .duration_since(sample.0)
                .as_millis()
                .max(1)
                .min(u128::from(u64::MAX)) as u64;
            let demand_bps = if elapsed_ms >= 1_000 {
                let demand_bps = total_bytes
                    .saturating_sub(sample.1)
                    .saturating_mul(8)
                    .saturating_mul(1_000)
                    / elapsed_ms;
                *sample = (now, total_bytes);
                demand_bps
            } else {
                0
            };
            drop(sample);
            let directional = snapshot.as_ref().and_then(|snapshot| {
                (!snapshot.path_quality.is_empty()).then(|| {
                    snapshot.path_quality.values().fold(
                        (0_u64, 0_u64, 0_u64, 0_u64),
                        |(up_demand, down_demand, up_capacity, down_capacity), path| {
                            (
                                up_demand.saturating_add(path.upstream_throughput_bps),
                                down_demand.saturating_add(path.downstream_throughput_bps),
                                up_capacity.saturating_add(
                                    path.upstream_effective_capacity_bps
                                        .unwrap_or(path.effective_capacity_bps),
                                ),
                                down_capacity.saturating_add(
                                    path.downstream_effective_capacity_bps
                                        .unwrap_or(path.effective_capacity_bps),
                                ),
                            )
                        },
                    )
                })
            });
            let input = AutoscaleInput {
                demand_bps,
                effective_capacity_bps: snapshot.as_ref().map_or(0, |snapshot| {
                    snapshot
                        .egress_status
                        .as_ref()
                        .map(|status| {
                            if status.report.effective_capacity_bps > 0 {
                                status.report.effective_capacity_bps
                            } else {
                                status.report.configured_capacity_bps
                            }
                        })
                        .unwrap_or(snapshot.egress_aggregate_capacity_bps)
                }),
                upstream_demand_bps: directional.map(|values| values.0),
                downstream_demand_bps: directional.map(|values| values.1),
                upstream_capacity_bps: directional.map(|values| values.2),
                downstream_capacity_bps: directional.map(|values| values.3),
                ready_paths: snapshot.as_ref().map_or(0, |snapshot| snapshot.ready_paths),
                degraded_paths: snapshot
                    .as_ref()
                    .map_or(0, |snapshot| snapshot.degraded_paths),
                target_path_count: None,
                hard_available: snapshot.as_ref().is_none_or(|snapshot| {
                    snapshot.egress_status.as_ref().is_none_or(|status| {
                        !status.fresh
                            || (status.report.connected
                                && !matches!(
                                    status.report.service_state,
                                    pathchord_core::EgressServiceState::Down
                                ))
                    })
                }),
                admission_allowed: snapshot.as_ref().is_none_or(|snapshot| {
                    snapshot
                        .egress_status
                        .as_ref()
                        .is_none_or(|status| status.fresh && status.report.admission_allowed)
                }),
                quota_remaining: None,
                traffic_multiplier_basis_points: 10_000,
                incremental_capacity_bps: None,
                scheduling_overhead_bps: 0,
            };
            let now_ms = now
                .duration_since(slot.maintenance_epoch)
                .as_millis()
                .min(u128::from(u64::MAX)) as u64;
            let _ = self
                .maintain_egress_paths_inner(egress_id, input, now_ms)
                .await;
        }
    }

    pub async fn maintain_egress_paths(
        &self,
        egress_id: &EgressId,
        input: AutoscaleInput,
        now_ms: u64,
    ) -> Result<AutoscaleDecision, DataPlaneError> {
        let _configuration = self.configuration_gate.read().await;
        self.maintain_egress_paths_inner(egress_id, input, now_ms)
            .await
    }

    async fn maintain_egress_paths_inner(
        &self,
        egress_id: &EgressId,
        mut input: AutoscaleInput,
        now_ms: u64,
    ) -> Result<AutoscaleDecision, DataPlaneError> {
        let slot = self
            .sessions
            .get(egress_id)
            .ok_or(DataPlaneError::NoUsableRoute)?;
        let session = slot.session.lock().await.clone();
        if let Some(session) = &session {
            let due: Vec<_> = slot
                .draining_paths
                .lock()
                .await
                .iter()
                .filter(|(_, (_, started))| started.elapsed() >= Duration::from_secs(5))
                .map(|(path_id, (transit_id, _))| (*path_id, transit_id.clone()))
                .collect();
            for (path_id, transit_id) in due {
                let _ = session.close_path(path_id).await;
                slot.draining_paths.lock().await.remove(&path_id);
                let mut transit_paths = slot.transit_paths.lock().await;
                if let Some(paths) = transit_paths.get_mut(&transit_id) {
                    paths.remove(&path_id);
                    if paths.is_empty() {
                        transit_paths.remove(&transit_id);
                    }
                }
            }
            // A transport failure removes the Path from the Session actor
            // immediately, while the Ingress ownership index is intentionally
            // updated asynchronously. Reconcile that index before publishing
            // economics or planning a replacement; otherwise a stale Path ID
            // makes maintenance return PathClosed and skips the replacement.
            let known_paths: BTreeSet<_> = session
                .snapshot()
                .path_states
                .iter()
                .filter_map(|(path_id, state)| {
                    matches!(
                        state,
                        pathchord_core::PathState::Active
                            | pathchord_core::PathState::Degraded
                            | pathchord_core::PathState::Draining
                    )
                    .then_some(*path_id)
                })
                .collect();
            slot.draining_paths
                .lock()
                .await
                .retain(|path_id, _| known_paths.contains(path_id));
            let mut transit_paths = slot.transit_paths.lock().await;
            transit_paths.retain(|_, path_ids| {
                path_ids.retain(|path_id| known_paths.contains(path_id));
                !path_ids.is_empty()
            });
            drop(transit_paths);
            let snapshot = session.snapshot();
            input.ready_paths = snapshot.ready_paths;
            let max_paths = slot.autoscaler.lock().await.config().max_paths;
            let minimum = (slot.egress.status_requirements.min_usable_paths as usize).max(1);
            let target = (*slot.target_path_count.lock().await)
                .max(reserved_path_target(minimum, max_paths));
            *slot.target_path_count.lock().await = target;
            input.target_path_count = Some(target);
            let paths = slot.transit_paths.lock().await.clone();
            let runtime = self.runtime.read().await;
            let economics: BTreeMap<_, _> = paths
                .keys()
                .filter_map(|id| {
                    runtime
                        .transit_proxy(id)
                        .cloned()
                        .map(|status| (id.clone(), status))
                })
                .collect();
            drop(runtime);
            for (transit_id, path_ids) in &paths {
                let observed = economics.get(transit_id);
                let quota_remaining = match (
                    input.quota_remaining,
                    observed.and_then(|status| status.quota_remaining),
                ) {
                    (Some(egress), Some(provider)) => Some(egress.min(provider)),
                    (egress, provider) => egress.or(provider),
                };
                let multiplier = observed
                    .and_then(|status| status.traffic_multiplier_basis_points)
                    .unwrap_or(10_000);
                let traffic_multiplier_basis_points =
                    (u64::from(input.traffic_multiplier_basis_points)
                        .saturating_mul(u64::from(multiplier))
                        / 10_000)
                        .clamp(1, u64::from(u32::MAX)) as u32;
                for path_id in path_ids {
                    if let Err(error) = session
                        .update_path_economic_status(
                            *path_id,
                            PathEconomicStatus {
                                hard_available: input.hard_available,
                                quota_remaining,
                                traffic_multiplier_basis_points,
                            },
                        )
                        .await
                    {
                        if matches!(
                            &error,
                            SessionRuntimeError::PathClosed
                                | SessionRuntimeError::Multipath(
                                    pathchord_path::MultipathError::UnknownPath(_)
                                )
                        ) {
                            continue;
                        }
                        return Err(error.into());
                    }
                }
            }
        }
        // A failed Path is a transport event, not a capacity sample. Replace
        // the deficit on the next maintenance tick without waiting for the
        // autoscaler's hysteresis window; this keeps an admitted Stream on a
        // surviving Path while a fresh connection is established.
        let current = slot.transit_paths.lock().await.clone();
        let max_paths = slot.autoscaler.lock().await.config().max_paths;
        let target = input.target_path_count.unwrap_or_else(|| {
            reserved_path_target(
                (slot.egress.status_requirements.min_usable_paths as usize).max(1),
                max_paths,
            )
        });
        if session.is_some()
            && input.hard_available
            && input.admission_allowed
            && input.ready_paths < max_paths
            && input.ready_paths < target
        {
            let deficit = target.saturating_sub(input.ready_paths);
            let eligible = slot.eligible_transits.lock().await.clone();
            let available: BTreeMap<_, _> = self
                .transit_adapters
                .read()
                .await
                .keys()
                .filter(|id| eligible.contains_key(*id))
                .map(|id| (id.clone(), eligible[id]))
                .collect();
            let start = slot
                .warmup_cursor
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let attempts = 1;
            let mut added = 0_usize;
            for transit_id in plan_transit_candidates(&available, &current, attempts, start) {
                if self.add_session_path(egress_id, &transit_id).await.is_ok() {
                    added = added.saturating_add(1);
                    if added >= deficit {
                        break;
                    }
                }
            }
            if added > 0 {
                self.mark_egress(
                    egress_id,
                    RuntimeNodeState::Ready,
                    session.as_ref().map_or(added as u32, |current| {
                        current.snapshot().ready_paths as u32
                    }),
                )
                .await;
                return Ok(AutoscaleDecision::Add { count: added });
            }
        }
        {
            let mut last = slot.last_autoscale_decision.lock().await;
            if last.elapsed() < AUTOSCALE_DECISION_INTERVAL {
                return Ok(AutoscaleDecision::Hold);
            }
            *last = Instant::now();
        }
        let decision = slot.autoscaler.lock().await.evaluate(input, now_ms);
        match decision {
            AutoscaleDecision::Add { count } => {
                let eligible = slot.eligible_transits.lock().await.clone();
                let available: BTreeMap<_, _> = self
                    .transit_adapters
                    .read()
                    .await
                    .keys()
                    .filter(|id| eligible.contains_key(*id))
                    .map(|id| (id.clone(), eligible[id]))
                    .collect();
                let current = slot.transit_paths.lock().await.clone();
                let start = slot
                    .warmup_cursor
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let attempts = count.min(1);
                let mut added = 0;
                for transit_id in plan_transit_candidates(&available, &current, attempts, start) {
                    if self.add_session_path(egress_id, &transit_id).await.is_ok() {
                        added += 1;
                        if added >= count {
                            break;
                        }
                    }
                }
            }
            AutoscaleDecision::Drain { count } => {
                if let Some(session) = session {
                    let transit_paths = slot.transit_paths.lock().await.clone();
                    let draining_paths = slot.draining_paths.lock().await.clone();
                    let ready_paths: BTreeSet<_> =
                        session.snapshot().ready_path_ids.into_iter().collect();
                    let minimum =
                        (slot.egress.status_requirements.min_usable_paths as usize).max(1);
                    let mut selected = 0_usize;
                    let candidates: Vec<_> = transit_paths
                        .iter()
                        .flat_map(|(transit_id, path_ids)| {
                            path_ids
                                .iter()
                                .rev()
                                .map(move |path_id| (*path_id, transit_id.clone()))
                        })
                        .rev()
                        .filter(|(path_id, _)| {
                            if draining_paths.contains_key(path_id) {
                                return false;
                            }
                            let usable = ready_paths
                                .iter()
                                .filter(|candidate| !draining_paths.contains_key(candidate))
                                .count();
                            if usable.saturating_sub(selected + 1) < minimum {
                                return false;
                            }
                            selected += 1;
                            true
                        })
                        .take(count)
                        .collect();
                    for (path_id, transit_id) in candidates {
                        session.drain_path(path_id).await?;
                        slot.draining_paths
                            .lock()
                            .await
                            .insert(path_id, (transit_id, Instant::now()));
                    }
                }
            }
            AutoscaleDecision::Hold => {}
        }
        Ok(decision)
    }

    async fn multipath_config_for(&self, policy_id: &TrafficPolicyId) -> MultipathConfig {
        let default = MultipathConfig::default();
        let policies = self.traffic_policies.read().await;
        let Some(policy) = policies.get(policy_id) else {
            return default;
        };
        // One fixed window lasts one second. Round down so a sub-byte budget
        // cannot accidentally permit more bits than the configured limit.
        let bits_to_bytes = |bits_per_second: u64| bits_per_second / 8;
        let configured_budget = bits_to_bytes(policy.session_replication_budget_bps);
        let replication_enabled = configured_budget > 0
            && matches!(
                policy.retransmission_replication,
                pathchord_policy::RetransmissionReplication::Allowed
            );
        let session_budget = if replication_enabled {
            configured_budget
        } else {
            0
        };
        MultipathConfig {
            traffic_class: None,
            session_replication_budget_bytes: session_budget,
            default_stream_replication_budget_bytes: session_budget,
            class_replication_budget_bytes: BTreeMap::new(),
            retransmission_replication_enabled: replication_enabled,
            require_fresh_status_report: true,
            ..default
        }
    }

    async fn session_replication_budget_bytes(&self, slot: &SessionSlot) -> u64 {
        if let Some(budget) = *slot.replication_budget_bytes.lock().await {
            return budget;
        }
        if let Some(config) = slot.session_policy.lock().await.clone() {
            let budget = config.session_replication_budget_bytes;
            *slot.replication_budget_bytes.lock().await = Some(budget);
            return budget;
        }
        let configured = match slot.egress.traffic_policy.as_ref() {
            Some(id) => self.traffic_policies.read().await.get(id).cloned(),
            None => None,
        };
        let budget = configured.map_or(
            pathchord_path::DEFAULT_SESSION_REPLICATION_BUDGET_BYTES_PER_SECOND,
            |policy| {
                if matches!(
                    policy.retransmission_replication,
                    pathchord_policy::RetransmissionReplication::Allowed
                ) {
                    policy.session_replication_budget_bps / 8
                } else {
                    0
                }
            },
        );
        *slot.replication_budget_bytes.lock().await = Some(budget);
        budget
    }

    async fn session_multipath_config(&self, slot: &SessionSlot) -> MultipathConfig {
        if let Some(config) = slot.session_policy.lock().await.clone() {
            return config;
        }
        let mut config = match slot.egress.traffic_policy.as_ref() {
            Some(policy_id) => self.multipath_config_for(policy_id).await,
            None => MultipathConfig::default(),
        };
        config.minimum_usable_paths =
            (slot.egress.status_requirements.min_usable_paths as usize).max(1);
        config.demand_key = None;
        *slot.session_policy.lock().await = Some(config.clone());
        config
    }

    async fn eligible_transits_for_egress(
        &self,
        egress: &EgressConfig,
    ) -> Vec<(TransitProxyId, u32)> {
        let runtime = self.runtime.read().await;
        let static_configs = self.transit_configs.read().await;
        let dynamic_configs = self.dynamic_transit_configs.read().await;
        let adapters = self.transit_adapters.read().await;
        static_configs
            .iter()
            .chain(dynamic_configs.iter())
            .filter_map(|(id, config)| {
                if id.namespace() != egress.id.namespace() {
                    return None;
                }
                let status = runtime.transit_proxy(id)?;
                if !matches!(
                    status.state,
                    RuntimeNodeState::Ready | RuntimeNodeState::Degraded
                ) {
                    return None;
                }
                let adapter = adapters.get(id)?;
                if !adapter_capabilities(adapter.as_ref(), config).contains(&FlowProtocol::Tcp)
                    || !selector_matches_transit(&egress.transit.require, config, status)
                    || egress
                        .transit
                        .reject_tags
                        .iter()
                        .any(|tag| config.tags.contains(tag) || status.tags.contains(tag))
                {
                    return None;
                }
                Some((id.clone(), config.weight))
            })
            .collect()
    }

    async fn existing_candidate_paths(
        &self,
        slot: &SessionSlot,
        candidate: &EgressRouteCandidate,
    ) -> Option<(Arc<IngressSessionHandle>, BTreeMap<PathId, u32>)> {
        let session = slot.session.lock().await.clone()?;
        let snapshot = session.snapshot();
        if snapshot.closed {
            return None;
        }
        let paths = slot.transit_paths.lock().await;
        let mut eligible = BTreeMap::new();
        for transit in &candidate.transit_proxies {
            if let Some(path_ids) = paths.get(&transit.id) {
                for path_id in path_ids {
                    if snapshot.ready_path_ids.contains(path_id) {
                        eligible.insert(*path_id, transit.relationship_weight);
                    }
                }
            }
        }
        (!eligible.is_empty()).then_some((session, eligible))
    }

    async fn candidate_paths(
        &self,
        slot: &SessionSlot,
        candidate: &EgressRouteCandidate,
    ) -> Result<(Arc<IngressSessionHandle>, BTreeMap<PathId, u32>), DataPlaneError> {
        // Do not dial every provider node on the business request's critical
        // path. Existing eligible Paths can carry the request immediately;
        // background maintenance owns reserve and capacity adjustments.
        if let Some(paths) = self.existing_candidate_paths(slot, candidate).await {
            return Ok(paths);
        }
        let count = candidate
            .transit_proxies
            .len()
            .min(MAX_EGRESS_DIAL_ATTEMPTS);
        let deadline = Instant::now() + self.path_connect_timeout;
        let mut last_error = DataPlaneError::NoUsableRoute;
        for (index, transit) in candidate.transit_proxies.iter().take(count).enumerate() {
            let budget =
                deadline.saturating_duration_since(Instant::now()) / (count - index) as u32;
            if budget.is_zero() {
                break;
            }
            match timeout(
                budget,
                self.ensure_session(&candidate.egress_id, &transit.id),
            )
            .await
            {
                Ok(Ok(_)) => {
                    if let Some(paths) = self.existing_candidate_paths(slot, candidate).await {
                        return Ok(paths);
                    }
                }
                Ok(Err(error)) => last_error = error,
                Err(_) => {
                    last_error =
                        TransitError::Connection("Egress Path connection timed out".into()).into();
                }
            }
        }
        Err(last_error)
    }

    pub async fn open_tcp(
        &self,
        context: &ConnectionContext,
    ) -> Result<BoxedLocalConnection, DataPlaneError> {
        let _configuration = self.configuration_gate.read().await;
        if self
            .shutting_down
            .load(std::sync::atomic::Ordering::Acquire)
        {
            return Err(DataPlaneError::ShuttingDown);
        }
        self.refresh_runtime().await;
        let policy_context = context.policy_context();
        let evaluation = {
            let runtime = self.runtime.read().await;
            self.compiled
                .read()
                .await
                .evaluate(&policy_context, &runtime)
        };
        match evaluation {
            Evaluation::Direct { .. } => self.connect_direct(&policy_context).await,
            Evaluation::Reject { .. } => Err(DataPlaneError::PolicyRejected),
            Evaluation::Route(RoutePlan::Proxy(route)) => {
                self.connect_proxy(&route, &policy_context).await
            }
            Evaluation::Route(RoutePlan::Egress(route)) => {
                let mut last_error = None;
                let mut route_error = None;
                for candidate in &route.candidates {
                    let Some(slot) = self.sessions.get(&candidate.egress_id) else {
                        continue;
                    };
                    {
                        let mut eligible = slot.eligible_transits.lock().await;
                        for transit in &candidate.transit_proxies {
                            eligible.insert(transit.id.clone(), transit.relationship_weight);
                        }
                    }
                    let (session, eligible) = match self.candidate_paths(slot, candidate).await {
                        Ok(paths) => paths,
                        Err(error) => {
                            route_error = Some(error);
                            continue;
                        }
                    };
                    let multipath_config = self.session_multipath_config(slot).await;
                    match session
                        .open_tcp_routed_with_config(
                            wire_target(&policy_context)?,
                            eligible,
                            multipath_config,
                        )
                        .await
                    {
                        Ok(stream) => return Ok(Box::new(stream) as BoxedLocalConnection),
                        Err(error) if retryable_pre_admission_stream_error(&error) => {
                            last_error = Some(error);
                        }
                        Err(error) => return Err(error.into()),
                    }
                }
                match last_error {
                    Some(error) => Err(DataPlaneError::Stream(error)),
                    None => Err(route_error.unwrap_or(DataPlaneError::NoUsableRoute)),
                }
            }
        }
    }

    pub async fn open_udp(
        &self,
        context: &ConnectionContext,
    ) -> Result<BoxedUdpFlowHandle, DataPlaneError> {
        let _configuration = self.configuration_gate.read().await;
        if self
            .shutting_down
            .load(std::sync::atomic::Ordering::Acquire)
        {
            return Err(DataPlaneError::ShuttingDown);
        }
        self.refresh_runtime().await;
        let mut policy_context = context.policy_context();
        policy_context.protocol = FlowProtocol::Udp;
        let evaluation = {
            let runtime = self.runtime.read().await;
            self.compiled
                .read()
                .await
                .evaluate(&policy_context, &runtime)
        };
        let route = match evaluation {
            Evaluation::Reject { .. } => return Err(DataPlaneError::PolicyRejected),
            Evaluation::Direct { .. } => {
                let adapter =
                    DirectTransitAdapter::new("builtin-direct", self.path_connect_timeout);
                let datagram = adapter
                    .connect_udp(ConnectRequest {
                        destination: transit_target(&policy_context)?,
                    })
                    .await?;
                return Ok(Box::new(crate::udp_flow::TransitUdpFlowHandle::new(
                    datagram,
                )));
            }
            Evaluation::Route(RoutePlan::Proxy(route)) => {
                return self.connect_proxy_udp(&route, &policy_context).await;
            }
            Evaluation::Route(RoutePlan::Egress(route)) => route,
        };
        let mut last_error = None;
        let mut route_error = None;
        for candidate in &route.candidates {
            let Some(slot) = self.sessions.get(&candidate.egress_id) else {
                continue;
            };
            {
                let mut eligible = slot.eligible_transits.lock().await;
                for transit in &candidate.transit_proxies {
                    eligible.insert(transit.id.clone(), transit.relationship_weight);
                }
            }
            let (session, eligible) = match self.candidate_paths(slot, candidate).await {
                Ok(paths) => paths,
                Err(error) => {
                    route_error = Some(error);
                    continue;
                }
            };
            let multipath_config = self.session_multipath_config(slot).await;
            match session
                .open_udp_routed_with_config(
                    wire_target(&policy_context)?,
                    eligible,
                    multipath_config,
                )
                .await
            {
                Ok(handle) => return Ok(Box::new(handle)),
                Err(error) if retryable_pre_admission_udp_error(&error) => {
                    last_error = Some(error);
                }
                Err(error) => return Err(error.into()),
            }
        }
        match last_error {
            Some(error) => Err(DataPlaneError::Udp(error)),
            None => Err(route_error.unwrap_or(DataPlaneError::NoUsableRoute)),
        }
    }

    pub async fn snapshot(&self) -> DataPlaneSnapshot {
        let mut snapshot = DataPlaneSnapshot {
            configured_egresses: self.sessions.len(),
            ..DataPlaneSnapshot::default()
        };
        for slot in self.sessions.values() {
            let session = slot.session.lock().await.clone();
            let Some(session) = session else {
                continue;
            };
            let current = session.snapshot();
            if !current.closed {
                snapshot.sessions += 1;
                snapshot.ready_paths += current.ready_paths;
            }
            snapshot.streams += current.active_streams;
            snapshot.retained_outbound_bytes += current.retained_outbound_bytes;
            snapshot.bytes_sent = snapshot.bytes_sent.saturating_add(current.bytes_sent);
            snapshot.bytes_received = snapshot
                .bytes_received
                .saturating_add(current.bytes_received);
            snapshot.egress_aggregate_capacity_bps = snapshot
                .egress_aggregate_capacity_bps
                .max(current.egress_aggregate_capacity_bps);
            snapshot.path_quality.extend(current.path_quality);
        }
        snapshot
    }

    pub async fn session_snapshots(&self) -> Vec<DataPlaneSessionSnapshot> {
        let mut snapshots = Vec::new();
        for (egress_id, slot) in &self.sessions {
            if let Some(session) = slot.session.lock().await.clone() {
                snapshots.push(DataPlaneSessionSnapshot {
                    egress_id: egress_id.as_str().to_owned(),
                    session: session.snapshot(),
                    minimum_usable_paths: (slot.egress.status_requirements.min_usable_paths
                        as usize)
                        .max(1),
                    eligible_transit_count: slot.eligible_transits.lock().await.len(),
                    traffic_policy_id: slot
                        .egress
                        .traffic_policy
                        .as_ref()
                        .map(|id| id.as_str().to_owned()),
                    replication_cap_bps: (*slot.replication_budget_bytes.lock().await)
                        .map(|bytes| bytes.saturating_mul(8)),
                    path_transit: slot
                        .transit_paths
                        .lock()
                        .await
                        .iter()
                        .flat_map(|(transit, paths)| {
                            paths
                                .iter()
                                .map(move |path| (*path, transit.as_str().to_owned()))
                        })
                        .collect(),
                });
            }
        }
        snapshots
    }

    pub async fn shutdown(&self) -> Result<DataPlaneSnapshot, DataPlaneError> {
        self.shutting_down
            .store(true, std::sync::atomic::Ordering::Release);
        let mut retired = self.retired_paths.lock().await;
        retired.abort_all();
        while retired.join_next().await.is_some() {}
        drop(retired);
        for slot in self.sessions.values() {
            let session = slot.session.lock().await.take();
            if let Some(session) = session {
                shutdown_session(session).await?;
            }
        }
        Ok(self.snapshot().await)
    }

    async fn connect_direct(
        &self,
        context: &PolicyContext,
    ) -> Result<BoxedLocalConnection, DataPlaneError> {
        let adapter = DirectTransitAdapter::new("builtin-direct", self.path_connect_timeout);
        let stream = adapter
            .connect(ConnectRequest {
                destination: transit_target(context)?,
            })
            .await?;
        Ok(Box::new(stream) as BoxedLocalConnection)
    }

    async fn connect_proxy(
        &self,
        route: &ProxyRoutePlan,
        context: &PolicyContext,
    ) -> Result<BoxedLocalConnection, DataPlaneError> {
        // `open_tcp` holds the configuration gate, so this ordered set and
        // its adapters belong to the same publication as the policy decision.
        // Only errors before connect returns are eligible for another attempt.
        let destination = transit_target(context)?;
        let candidates: Vec<_> = {
            let adapters = self.transit_adapters.read().await;
            route
                .candidates
                .iter()
                .take(MAX_ORDINARY_PROXY_ATTEMPTS)
                .map(|id| (id, adapters.get(id).cloned()))
                .collect()
        };
        let mut last_error = DataPlaneError::NoUsableRoute;
        let deadline = Instant::now() + self.path_connect_timeout;
        let total_candidates = candidates.len();
        for (index, (id, adapter)) in candidates.into_iter().enumerate() {
            let Some(adapter) = adapter else {
                last_error = DataPlaneError::TransitUnavailable(id.as_str().to_owned());
                continue;
            };
            let remaining = deadline.saturating_duration_since(Instant::now());
            let budget = remaining / (total_candidates - index) as u32;
            if budget.is_zero() {
                return Err(TransitError::Connection("connection timed out".into()).into());
            }
            match timeout(
                budget,
                adapter.connect(ConnectRequest {
                    destination: destination.clone(),
                }),
            )
            .await
            {
                Ok(Ok(stream)) => return Ok(Box::new(stream) as BoxedLocalConnection),
                Ok(Err(error)) => last_error = error.into(),
                Err(_) => {
                    last_error = TransitError::Connection("connection timed out".into()).into();
                }
            }
        }
        Err(last_error)
    }

    async fn connect_proxy_udp(
        &self,
        route: &ProxyRoutePlan,
        context: &PolicyContext,
    ) -> Result<BoxedUdpFlowHandle, DataPlaneError> {
        // Do not retry a datagram after an association has been returned: its
        // payload may already have reached the previous target.
        let destination = transit_target(context)?;
        let candidates: Vec<_> = {
            let configs = self.transit_configs.read().await;
            let dynamic = self.dynamic_transit_configs.read().await;
            let adapters = self.transit_adapters.read().await;
            route
                .candidates
                .iter()
                .take(MAX_ORDINARY_PROXY_ATTEMPTS)
                .map(|id| {
                    let disabled = configs
                        .get(id)
                        .or_else(|| dynamic.get(id))
                        .is_some_and(|config| config.options.udp == Some(false));
                    (id, disabled, adapters.get(id).cloned())
                })
                .collect()
        };
        let mut last_error = DataPlaneError::NoUsableRoute;
        let deadline = Instant::now() + self.path_connect_timeout;
        let total_candidates = candidates.len();
        for (index, (id, disabled, adapter)) in candidates.into_iter().enumerate() {
            if disabled {
                last_error = DataPlaneError::NoUsableRoute;
                continue;
            }
            let Some(adapter) = adapter else {
                last_error = DataPlaneError::TransitUnavailable(id.as_str().to_owned());
                continue;
            };
            if !adapter.supports_udp() {
                last_error = DataPlaneError::NoUsableRoute;
                continue;
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            let budget = remaining / (total_candidates - index) as u32;
            if budget.is_zero() {
                return Err(TransitError::Connection("connection timed out".into()).into());
            }
            match timeout(
                budget,
                adapter.connect_udp(ConnectRequest {
                    destination: destination.clone(),
                }),
            )
            .await
            {
                Ok(Ok(datagram)) => {
                    return Ok(Box::new(crate::udp_flow::TransitUdpFlowHandle::new(
                        datagram,
                    )));
                }
                Ok(Err(error)) => last_error = error.into(),
                Err(_) => {
                    last_error = TransitError::Connection("connection timed out".into()).into();
                }
            }
        }
        Err(last_error)
    }

    async fn ensure_session(
        &self,
        egress_id: &EgressId,
        transit_id: &TransitProxyId,
    ) -> Result<Arc<IngressSessionHandle>, DataPlaneError> {
        self.ensure_session_path(egress_id, transit_id, false, self.path_connect_timeout)
            .await
            .map(|(session, _)| session)
    }

    async fn ensure_session_path(
        &self,
        egress_id: &EgressId,
        transit_id: &TransitProxyId,
        force_new: bool,
        dial_timeout: Duration,
    ) -> Result<(Arc<IngressSessionHandle>, PathId), DataPlaneError> {
        if egress_id.namespace() != transit_id.namespace() {
            return Err(DataPlaneError::NoUsableRoute);
        }
        let slot = self
            .sessions
            .get(egress_id)
            .ok_or(DataPlaneError::NoUsableRoute)?;
        if !self
            .eligible_transits_for_egress(&slot.egress)
            .await
            .iter()
            .any(|(id, _)| id == transit_id)
        {
            return Err(DataPlaneError::TransitUnavailable(
                transit_id.as_str().to_owned(),
            ));
        }
        if !self
            .runtime
            .read()
            .await
            .transit_proxy(transit_id)
            .is_some_and(|status| {
                matches!(
                    status.state,
                    RuntimeNodeState::Ready | RuntimeNodeState::Degraded
                )
            })
        {
            return Err(DataPlaneError::TransitUnavailable(
                transit_id.as_str().to_owned(),
            ));
        }
        // Serialize attachment without holding the Session or Path-index
        // locks across a network dial. Observability and flows with an
        // existing eligible Path must remain responsive while a node stalls.
        let _dial = slot.dial_gate.lock().await;
        let existing = slot.session.lock().await.clone();
        if let Some(session) = existing.as_ref()
            && let snapshot = session.snapshot()
            && snapshot.closed
            && snapshot.trust_failure
        {
            slot.trust_failures
                .lock()
                .await
                .record_for(snapshot.session_id, Instant::now());
        }
        if !slot.trust_failures.lock().await.can_attempt(Instant::now()) {
            return Err(DataPlaneError::NoUsableRoute);
        }
        if let Some(session) = existing.as_ref()
            && !session.snapshot().closed
        {
            let session_snapshot = session.snapshot();
            let draining = slot.draining_paths.lock().await;
            let mut transit_paths = slot.transit_paths.lock().await;
            transit_paths.retain(|_, path_ids| {
                path_ids.retain(|path_id| {
                    session_snapshot.ready_path_ids.contains(path_id)
                        || draining.contains_key(path_id)
                });
                !path_ids.is_empty()
            });
            let ready_path = transit_paths.get(transit_id).and_then(|path_ids| {
                path_ids
                    .iter()
                    .find(|path_id| session_snapshot.ready_path_ids.contains(path_id))
                    .copied()
            });
            drop(transit_paths);
            drop(draining);
            if !force_new && let Some(path_id) = ready_path {
                return Ok((Arc::clone(session), path_id));
            }
            let path_id = PathId::new(random_u128()?);
            let path = self
                .dial_session_path(
                    slot,
                    transit_id,
                    session_snapshot.session_id,
                    path_id,
                    dial_timeout,
                )
                .await?;
            let weight = slot
                .eligible_transits
                .lock()
                .await
                .get(transit_id)
                .copied()
                .unwrap_or(10_000)
                .clamp(1, 10_000) as u16;
            session
                .add_path(
                    path,
                    MultipathPathObservation {
                        weight_basis_points: weight,
                        ..MultipathPathObservation::default()
                    },
                )
                .await?;
            slot.transit_paths
                .lock()
                .await
                .entry(transit_id.clone())
                .or_default()
                .insert(path_id);
            self.mark_egress(
                egress_id,
                RuntimeNodeState::Ready,
                session.snapshot().ready_paths as u32,
            )
            .await;
            return Ok((Arc::clone(session), path_id));
        }
        slot.session.lock().await.take();
        slot.transit_paths.lock().await.clear();
        slot.draining_paths.lock().await.clear();
        *slot.target_path_count.lock().await = reserved_path_target(
            (slot.egress.status_requirements.min_usable_paths as usize).max(1),
            slot.autoscaler.lock().await.config().max_paths,
        );
        *slot.replication_budget_bytes.lock().await = None;
        *slot.session_policy.lock().await = None;
        let _ = self.session_multipath_config(slot).await;
        slot.autoscaler.lock().await.reset();
        let now = Instant::now();
        *slot.maintenance_sample.lock().await = (now, 0);
        *slot.last_autoscale_decision.lock().await =
            now.checked_sub(AUTOSCALE_DECISION_INTERVAL).unwrap_or(now);
        let session_id = SessionId::new(random_u128()?);
        let path_id = PathId::new(random_u128()?);
        let path = self
            .dial_session_path(slot, transit_id, session_id, path_id, dial_timeout)
            .await?;
        let session = Arc::new(IngressSessionHandle::start(path)?);
        let weight = slot
            .eligible_transits
            .lock()
            .await
            .get(transit_id)
            .copied()
            .unwrap_or(10_000)
            .clamp(1, 10_000) as u16;
        session
            .update_path_observation(
                path_id,
                MultipathPathObservation {
                    weight_basis_points: weight,
                    ..MultipathPathObservation::default()
                },
            )
            .await?;
        let mut transit_paths = slot.transit_paths.lock().await;
        transit_paths.clear();
        transit_paths.insert(transit_id.clone(), BTreeSet::from([path_id]));
        drop(transit_paths);
        *slot.session.lock().await = Some(Arc::clone(&session));
        self.mark_egress(egress_id, RuntimeNodeState::Ready, 1)
            .await;
        Ok((session, path_id))
    }

    async fn add_session_path(
        &self,
        egress_id: &EgressId,
        transit_id: &TransitProxyId,
    ) -> Result<PathId, DataPlaneError> {
        self.ensure_session_path(
            egress_id,
            transit_id,
            true,
            BACKGROUND_PATH_CONNECT_TIMEOUT.min(self.path_connect_timeout),
        )
        .await
        .map(|(_, path_id)| path_id)
    }

    async fn dial_session_path(
        &self,
        slot: &SessionSlot,
        transit_id: &TransitProxyId,
        session_id: SessionId,
        path_id: PathId,
        dial_timeout: Duration,
    ) -> Result<
        pathchord_path::IngressAdmittedPath<pathchord_transit::BoxedTransitConnection>,
        DataPlaneError,
    > {
        let adapter = self
            .transit_adapters
            .read()
            .await
            .get(transit_id)
            .cloned()
            .ok_or_else(|| DataPlaneError::TransitUnavailable(transit_id.as_str().to_owned()))?;
        let deadline = Instant::now() + dial_timeout;
        let io = timeout(
            dial_timeout,
            adapter.connect(ConnectRequest {
                destination: TransitEndpoint {
                    host: slot.egress.endpoint.host.clone(),
                    port: slot.egress.endpoint.port,
                },
            }),
        )
        .await
        .map_err(|_| TransitError::Connection("Egress Path connection timed out".into()))??;
        let responder_key = decode_key(&slot.egress.public_key)?;
        let replication_budget_bytes_per_second = self.session_replication_budget_bytes(slot).await;
        let mut prologue = WIRE_PROFILE_V1_PROLOGUE_PREFIX.to_vec();
        prologue.extend_from_slice(slot.egress.id.resource_name().as_bytes());
        let admission = IngressPathAdmissionConfig {
            egress_identity: prologue,
            egress_id: slot.egress.id.resource_name().as_bytes().to_vec(),
            ingress_id: self.ingress_id.as_bytes().to_vec(),
            session_id,
            path_id,
            offered_capabilities: TCP_CAPABILITY | UDP_CAPABILITY,
            required_capabilities: if slot.egress.capabilities.tcp {
                TCP_CAPABILITY
            } else {
                0
            } | if slot.egress.capabilities.udp {
                UDP_CAPABILITY
            } else {
                0
            },
            replication_budget_bytes_per_second,
            local_limits: ProtocolLimits::default(),
        };
        let outcome = timeout(
            deadline.saturating_duration_since(Instant::now()),
            dial_path(io, self.identity.private(), &responder_key, &admission),
        )
        .await
        .map_err(|_| TransitError::Connection("Egress Path admission timed out".into()))??;
        match outcome {
            PathAdmissionOutcome::Ready(path) => Ok(path),
            PathAdmissionOutcome::Rejected { .. } => Err(DataPlaneError::AdmissionRejected),
        }
    }

    async fn refresh_runtime(&self) {
        for (egress_id, slot) in &self.sessions {
            let session = slot.session.lock().await.clone();
            if let Some(session) = &session {
                let snapshot = session.snapshot();
                if !snapshot.closed
                    && snapshot
                        .egress_status
                        .as_ref()
                        .is_some_and(|status| status.fresh)
                {
                    slot.trust_failures.lock().await.reset();
                }
            }
            let ready_paths = session
                .as_ref()
                .map_or(0, |session| session.snapshot().ready_paths as u32);
            let ready = ready_paths > 0;
            self.mark_egress(
                egress_id,
                if ready {
                    RuntimeNodeState::Ready
                } else {
                    RuntimeNodeState::Down
                },
                ready_paths,
            )
            .await;
        }
    }

    async fn mark_egress(&self, id: &EgressId, state: RuntimeNodeState, usable_paths: u32) {
        let labels = self
            .egresses
            .get(id)
            .map(|egress| egress.labels.clone())
            .unwrap_or_default();
        self.runtime.write().await.set_egress(
            id.clone(),
            EgressRuntimeStatus {
                state,
                usable_paths,
                labels,
                tags: BTreeSet::new(),
            },
        );
    }
}

#[async_trait::async_trait]
impl TcpFlowOpener for IngressDataPlane {
    async fn connect(
        &self,
        context: ConnectionContext,
    ) -> Result<BoxedLocalConnection, FlowBridgeError> {
        self.open_tcp(&context).await.map_err(flow_error)
    }
}

#[async_trait::async_trait]
impl TcpFlowOpener for Arc<IngressDataPlane> {
    async fn connect(
        &self,
        context: ConnectionContext,
    ) -> Result<BoxedLocalConnection, FlowBridgeError> {
        self.open_tcp(&context).await.map_err(flow_error)
    }
}

struct DataPlaneDnsAdapter {
    data_plane: Arc<IngressDataPlane>,
}

impl std::fmt::Debug for DataPlaneDnsAdapter {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("DataPlaneDnsAdapter(..)")
    }
}

#[async_trait::async_trait]
impl DnsRouteAdapter for DataPlaneDnsAdapter {
    async fn exchange(&self, request: DnsRouteRequest) -> Result<Vec<u8>, DnsAdapterError> {
        let _configuration = self.data_plane.configuration_gate.read().await;
        match request.selection {
            DnsRouteSelection::Egress {
                namespace,
                egress_selector,
                servers,
            } => {
                let egress_id = self
                    .select_egress(&namespace, &egress_selector)
                    .await
                    .ok_or(DnsAdapterError::Unavailable)?;
                let slot = self
                    .data_plane
                    .sessions
                    .get(&egress_id)
                    .ok_or(DnsAdapterError::Unavailable)?;
                let candidates = self
                    .data_plane
                    .eligible_transits_for_egress(&slot.egress)
                    .await;
                let Some((transit_id, weight)) = candidates.first().cloned() else {
                    return Err(DnsAdapterError::Unavailable);
                };
                {
                    let mut eligible = slot.eligible_transits.lock().await;
                    eligible.clear();
                    eligible.extend(candidates);
                    eligible.insert(transit_id.clone(), weight);
                }
                let session = self
                    .data_plane
                    .ensure_session(&egress_id, &transit_id)
                    .await
                    .map_err(|_| DnsAdapterError::Unavailable)?;
                let target = dns_target(servers.first().ok_or(DnsAdapterError::Unavailable)?);
                session
                    .exchange_datagram(target, request.wire_query, MAX_DNS_MESSAGE_BYTES)
                    .await
                    .map_err(|error| match error {
                        pathchord_path::SessionUdpError::ResponseTooLarge => {
                            DnsAdapterError::ResponseTooLarge
                        }
                        pathchord_path::SessionUdpError::Unavailable
                        | pathchord_path::SessionUdpError::Exchange => DnsAdapterError::Unavailable,
                    })
            }
            DnsRouteSelection::Transit {
                namespace,
                proxy_selector,
                servers,
            } => {
                let proxy_id = self
                    .select_transit(&namespace, &proxy_selector)
                    .await
                    .ok_or(DnsAdapterError::Unavailable)?;
                let adapter = self
                    .data_plane
                    .transit_adapters
                    .read()
                    .await
                    .get(&proxy_id)
                    .cloned()
                    .ok_or(DnsAdapterError::Unavailable)?;
                let server = servers.first().ok_or(DnsAdapterError::Unavailable)?;
                let mut stream = adapter
                    .connect(ConnectRequest {
                        destination: TransitEndpoint {
                            host: server.host.clone(),
                            port: server.port,
                        },
                    })
                    .await
                    .map_err(|_| DnsAdapterError::Unavailable)?;
                let length = u16::try_from(request.wire_query.len())
                    .map_err(|_| DnsAdapterError::ResponseTooLarge)?;
                stream
                    .write_all(&length.to_be_bytes())
                    .await
                    .map_err(|_| DnsAdapterError::Unavailable)?;
                stream
                    .write_all(&request.wire_query)
                    .await
                    .map_err(|_| DnsAdapterError::Unavailable)?;
                stream
                    .flush()
                    .await
                    .map_err(|_| DnsAdapterError::Unavailable)?;
                let response_len = stream
                    .read_u16()
                    .await
                    .map_err(|_| DnsAdapterError::Unavailable)?
                    as usize;
                if response_len > MAX_DNS_MESSAGE_BYTES {
                    return Err(DnsAdapterError::ResponseTooLarge);
                }
                let mut response = vec![0_u8; response_len];
                stream
                    .read_exact(&mut response)
                    .await
                    .map_err(|_| DnsAdapterError::Protocol)?;
                Ok(response)
            }
            DnsRouteSelection::Local => Err(DnsAdapterError::Unavailable),
        }
    }
}

impl DataPlaneDnsAdapter {
    async fn select_egress(&self, namespace: &str, selector: &Selector) -> Option<EgressId> {
        let runtime = self.data_plane.runtime.read().await;
        self.data_plane
            .egresses
            .iter()
            .find(|(id, config)| {
                id.namespace() == namespace
                    && runtime.egress(id).is_some_and(|status| {
                        matches!(
                            status.state,
                            RuntimeNodeState::Ready | RuntimeNodeState::Degraded
                        ) && status.usable_paths > 0
                            && selector_matches_egress(selector, config, status)
                    })
            })
            .map(|(id, _)| id.clone())
    }

    async fn select_transit(&self, namespace: &str, selector: &Selector) -> Option<TransitProxyId> {
        let runtime = self.data_plane.runtime.read().await;
        let dynamic = self.data_plane.dynamic_transit_configs.read().await;
        let static_configs = self.data_plane.transit_configs.read().await;
        static_configs
            .iter()
            .chain(dynamic.iter())
            .find(|(id, config)| {
                id.namespace() == namespace
                    && runtime.transit_proxy(id).is_some_and(|status| {
                        matches!(
                            status.state,
                            RuntimeNodeState::Ready | RuntimeNodeState::Degraded
                        ) && selector_matches_transit(selector, config, status)
                    })
            })
            .map(|(id, _)| id.clone())
    }
}

fn adapter_capabilities(
    adapter: &dyn TransitAdapter,
    config: &TransitProxyConfig,
) -> BTreeSet<FlowProtocol> {
    let mut capabilities = BTreeSet::new();
    if adapter.supports_tcp() {
        capabilities.insert(FlowProtocol::Tcp);
    }
    if adapter.supports_udp() && config.options.udp != Some(false) {
        capabilities.insert(FlowProtocol::Udp);
    }
    capabilities
}

fn selector_matches_egress(
    selector: &Selector,
    config: &EgressConfig,
    status: &EgressRuntimeStatus,
) -> bool {
    selector.labels.iter().all(|(key, expected)| {
        status.labels.get(key).or_else(|| config.labels.get(key)) == Some(expected)
    }) && selector.tags.is_subset(&status.tags)
        && selector
            .capabilities
            .iter()
            .all(|capability| match capability {
                FlowProtocol::Tcp => config.capabilities.tcp,
                FlowProtocol::Udp => config.capabilities.udp,
            })
}

fn selector_matches_transit(
    selector: &Selector,
    config: &TransitProxyConfig,
    status: &TransitProxyRuntimeStatus,
) -> bool {
    selector.labels.iter().all(|(key, expected)| {
        status.labels.get(key).or_else(|| config.labels.get(key)) == Some(expected)
    }) && selector
        .tags
        .iter()
        .all(|tag| config.tags.contains(tag) || status.tags.contains(tag))
        && selector.capabilities.is_subset(&status.capabilities)
}

fn dns_target(endpoint: &pathchord_policy::Endpoint) -> WireTargetEndpoint {
    match endpoint.host.parse() {
        Ok(address) => WireTargetEndpoint {
            hostname: Vec::new(),
            port: endpoint.port,
            resolved_addresses: vec![address],
        },
        Err(_) => WireTargetEndpoint {
            hostname: endpoint.host.as_bytes().to_vec(),
            port: endpoint.port,
            resolved_addresses: Vec::new(),
        },
    }
}

fn retryable_pre_admission_stream_error(error: &OpenStreamError) -> bool {
    match error {
        OpenStreamError::ResourceLimit | OpenStreamError::SessionClosed => true,
        OpenStreamError::Rejected { error, .. } => matches!(
            error,
            pathchord_core::ErrorClass::PathFailure
                | pathchord_core::ErrorClass::EgressFailure
                | pathchord_core::ErrorClass::ResourceLimit
        ),
    }
}

fn reserved_path_target(required: usize, max_paths: usize) -> usize {
    required
        .max(1)
        .saturating_add(PATH_RESERVE_COUNT)
        .min(max_paths.max(1))
}

fn plan_transit_candidates(
    eligible: &BTreeMap<TransitProxyId, u32>,
    current: &BTreeMap<TransitProxyId, BTreeSet<PathId>>,
    count: usize,
    start: usize,
) -> Vec<TransitProxyId> {
    let mut ordered: Vec<_> = eligible.keys().cloned().collect();
    ordered.sort_by_key(|id| current.get(id).map_or(0, BTreeSet::len));
    if ordered.is_empty() {
        return Vec::new();
    }
    let offset = start % ordered.len();
    (0..count)
        .map(|index| ordered[(offset + index) % ordered.len()].clone())
        .collect()
}

fn retryable_pre_admission_udp_error(error: &OpenUdpError) -> bool {
    match error {
        OpenUdpError::ResourceLimit | OpenUdpError::SessionClosed => true,
        OpenUdpError::Rejected { error, .. } => matches!(
            error,
            pathchord_core::ErrorClass::PathFailure
                | pathchord_core::ErrorClass::EgressFailure
                | pathchord_core::ErrorClass::ResourceLimit
        ),
    }
}

fn flow_error(error: DataPlaneError) -> FlowBridgeError {
    match error {
        DataPlaneError::PolicyRejected => FlowBridgeError::PolicyRejected,
        DataPlaneError::NoUsableRoute | DataPlaneError::TransitUnavailable(_) => {
            FlowBridgeError::NoUsableRoute
        }
        DataPlaneError::AdmissionRejected => FlowBridgeError::EgressRejected {
            error: pathchord_core::ErrorClass::EgressFailure,
            reason: b"Path admission rejected".to_vec(),
        },
        DataPlaneError::Stream(OpenStreamError::Rejected { error, reason }) => {
            if error == pathchord_core::ErrorClass::ResourceLimit {
                FlowBridgeError::ResourceLimit
            } else {
                FlowBridgeError::EgressRejected { error, reason }
            }
        }
        DataPlaneError::Udp(OpenUdpError::Rejected { error, reason }) => {
            if error == pathchord_core::ErrorClass::ResourceLimit {
                FlowBridgeError::ResourceLimit
            } else {
                FlowBridgeError::EgressRejected { error, reason }
            }
        }
        DataPlaneError::Stream(OpenStreamError::ResourceLimit) => FlowBridgeError::ResourceLimit,
        DataPlaneError::Udp(OpenUdpError::ResourceLimit) => FlowBridgeError::ResourceLimit,
        DataPlaneError::ShuttingDown => FlowBridgeError::ShuttingDown,
        DataPlaneError::Transit(source) => FlowBridgeError::Dial(source.to_string()),
        DataPlaneError::InvalidIngressIdentity
        | DataPlaneError::InvalidEgressKey
        | DataPlaneError::PolicyCompile(_)
        | DataPlaneError::PolicyGenerationMismatch
        | DataPlaneError::Admission(_)
        | DataPlaneError::Session(_)
        | DataPlaneError::Stream(OpenStreamError::SessionClosed)
        | DataPlaneError::Udp(_)
        | DataPlaneError::StaticReloadConflict
        | DataPlaneError::StaticReloadRequiresRestart
        | DataPlaneError::StaticDynamicConflict
        | DataPlaneError::InvalidProbeConfig
        | DataPlaneError::ControlCommitRejected
        | DataPlaneError::IdentifierGeneration => FlowBridgeError::SessionUnavailable,
    }
}

#[cfg(test)]
#[path = "data_plane_reload_tests.rs"]
mod reload_tests;

#[cfg(test)]
#[path = "data_plane_subscription_tests.rs"]
mod subscription_tests;

async fn shutdown_session(session: Arc<IngressSessionHandle>) -> Result<(), DataPlaneError> {
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut session = session;
    loop {
        match Arc::try_unwrap(session) {
            Ok(owner) => {
                owner.shutdown().await?;
                return Ok(());
            }
            Err(shared) if Instant::now() < deadline => {
                session = shared;
                tokio::task::yield_now().await;
            }
            Err(_) => return Err(DataPlaneError::ShuttingDown),
        }
    }
}

fn decode_key(value: &str) -> Result<[u8; STATIC_KEY_LEN], DataPlaneError> {
    let decoded = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| DataPlaneError::InvalidEgressKey)?;
    decoded
        .try_into()
        .map_err(|_| DataPlaneError::InvalidEgressKey)
}

fn random_u128() -> Result<u128, DataPlaneError> {
    let mut bytes = [0_u8; 16];
    getrandom::fill(&mut bytes).map_err(|_| DataPlaneError::IdentifierGeneration)?;
    Ok(u128::from_be_bytes(bytes))
}

fn wire_target(context: &PolicyContext) -> Result<WireTargetEndpoint, DataPlaneError> {
    let (hostname, resolved_addresses) = match &context.target.host {
        pathchord_policy::TargetHost::Hostname(host) => (host.as_bytes().to_vec(), Vec::new()),
        pathchord_policy::TargetHost::Ip(address) => (Vec::new(), vec![*address]),
    };
    if context.target.port == 0 || (hostname.is_empty() && resolved_addresses.is_empty()) {
        return Err(DataPlaneError::NoUsableRoute);
    }
    Ok(WireTargetEndpoint {
        hostname,
        port: context.target.port,
        resolved_addresses,
    })
}

fn transit_target(context: &PolicyContext) -> Result<TransitEndpoint, DataPlaneError> {
    let host = match &context.target.host {
        pathchord_policy::TargetHost::Hostname(host) => host.clone(),
        pathchord_policy::TargetHost::Ip(address) => address.to_string(),
    };
    if host.is_empty() || context.target.port == 0 {
        return Err(DataPlaneError::NoUsableRoute);
    }
    Ok(TransitEndpoint {
        host,
        port: context.target.port,
    })
}

fn valid_identifier(value: &[u8]) -> bool {
    value.len() <= ProtocolLimits::HARD_MAX_TARGET_NAME
        && value.first().is_some_and(u8::is_ascii_alphanumeric)
        && value
            .iter()
            .skip(1)
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(*byte, b'.' | b'_' | b'-'))
}

#[cfg(test)]
mod tests {
    use super::*;
    use pathchord_policy::{
        FallbackAction, FlowMatch, Generation, PolicyConfig, ProxyRule, ProxySelection,
        RetransmissionReplication, RuleId, Scheduler, Selector, TrafficPolicy, TrafficPolicyId,
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    fn data_plane(fallback: FallbackAction) -> IngressDataPlane {
        let identity = pathchord_noise::generate_static_keypair().expect("identity");
        let policy = ValidatedPolicySnapshot::new(
            Generation::new(1),
            PolicyConfig {
                fallback: Some(fallback),
                ..PolicyConfig::default()
            },
        )
        .expect("policy");
        IngressDataPlane::new(IngressDataPlaneConfig::new("ingress-a", identity, policy))
            .expect("data plane")
    }

    fn context(address: std::net::SocketAddr) -> ConnectionContext {
        ConnectionContext {
            flow_tags: BTreeSet::new(),
            listener_id: crate::ListenerId::new("local-http"),
            source: "127.0.0.1:2345".parse().expect("source"),
            authentication_identity: None,
            process: None,
            protocol: FlowProtocol::Tcp,
            target: crate::TargetAddress {
                host: crate::TargetHost::Ip(address.ip()),
                port: address.port(),
            },
        }
    }

    #[tokio::test]
    async fn one_transit_relationship_tracks_independent_path_instances() {
        let slot = SessionSlot::new(EgressConfig {
            id: EgressId::new("edge"),
            endpoint: pathchord_policy::Endpoint {
                host: "127.0.0.1".into(),
                port: 7443,
            },
            public_key: "key".into(),
            labels: BTreeMap::new(),
            capabilities: pathchord_policy::Capabilities {
                tcp: true,
                udp: true,
            },
            status_requirements: Default::default(),
            transit: pathchord_policy::EgressTransitBinding::default(),
            traffic_policy: None,
        });
        let relationship = TransitProxyId::new("transit");
        let first = PathId::new(1);
        let second = PathId::new(2);
        {
            let mut paths = slot.transit_paths.lock().await;
            paths
                .entry(relationship.clone())
                .or_default()
                .extend([first, second]);
        }
        let mut paths = slot.transit_paths.lock().await;
        assert_eq!(paths[&relationship], BTreeSet::from([first, second]));
        paths
            .get_mut(&relationship)
            .expect("relationship")
            .remove(&first);
        assert_eq!(paths[&relationship], BTreeSet::from([second]));
    }

    #[test]
    fn reserved_path_target_keeps_one_spare_without_exceeding_session_limit() {
        assert_eq!(reserved_path_target(1, 4), 2);
        assert_eq!(reserved_path_target(3, 4), 4);
        assert_eq!(reserved_path_target(4, 4), 4);
        assert_eq!(reserved_path_target(0, 0), 1);
    }

    #[test]
    fn replacement_candidates_prefer_a_different_transit_and_rotate_after_failure() {
        let a = TransitProxyId::new("a");
        let b = TransitProxyId::new("b");
        let c = TransitProxyId::new("c");
        let eligible = BTreeMap::from([(a.clone(), 100), (b.clone(), 100), (c.clone(), 100)]);
        let current = BTreeMap::from([(a.clone(), BTreeSet::from([PathId::new(1)]))]);
        let first = plan_transit_candidates(&eligible, &current, 1, 0);
        let next = plan_transit_candidates(&eligible, &current, 1, 1);
        assert_eq!(first, vec![b]);
        assert_eq!(next, vec![c]);
    }

    #[test]
    fn pre_admission_failover_does_not_retry_after_target_admission() {
        assert!(retryable_pre_admission_stream_error(
            &OpenStreamError::ResourceLimit
        ));
        assert!(retryable_pre_admission_stream_error(
            &OpenStreamError::Rejected {
                error: pathchord_core::ErrorClass::PathFailure,
                reason: Vec::new(),
            }
        ));
        assert!(retryable_pre_admission_stream_error(
            &OpenStreamError::Rejected {
                error: pathchord_core::ErrorClass::ResourceLimit,
                reason: Vec::new(),
            }
        ));
        assert!(!retryable_pre_admission_stream_error(
            &OpenStreamError::Rejected {
                error: pathchord_core::ErrorClass::TargetFailure,
                reason: Vec::new(),
            }
        ));
        assert!(retryable_pre_admission_udp_error(
            &OpenUdpError::ResourceLimit
        ));
        assert!(!retryable_pre_admission_udp_error(
            &OpenUdpError::Rejected {
                error: pathchord_core::ErrorClass::TargetFailure,
                reason: Vec::new(),
            }
        ));
    }

    #[tokio::test]
    async fn dns_selectors_and_session_bootstrap_stay_in_the_owners_namespace() {
        let identity = pathchord_noise::generate_static_keypair().unwrap();
        let mut config = PolicyConfig {
            fallback: Some(FallbackAction::Reject),
            ..Default::default()
        };
        for namespace in ["alpha", "beta"] {
            config.egresses.push(EgressConfig {
                id: EgressId::in_namespace(namespace, "edge"),
                endpoint: pathchord_policy::Endpoint {
                    host: "127.0.0.1".into(),
                    port: 9,
                },
                public_key: base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .encode(identity.public()),
                labels: BTreeMap::from([("region".into(), "jp".into())]),
                capabilities: pathchord_policy::Capabilities {
                    tcp: true,
                    udp: true,
                },
                status_requirements: Default::default(),
                transit: pathchord_policy::EgressTransitBinding::default(),
                traffic_policy: None,
            });
            config.transit_proxies.push(TransitProxyConfig {
                id: TransitProxyId::in_namespace(namespace, "node"),
                source: None,
                protocol: "direct".into(),
                endpoint: pathchord_policy::Endpoint {
                    host: String::new(),
                    port: 1,
                },
                credentials_ref: None,
                labels: BTreeMap::from([("region".into(), "jp".into())]),
                tags: BTreeSet::new(),
                weight: 100,
                options: Default::default(),
            });
        }
        let policy = ValidatedPolicySnapshot::new(Generation::new(1), config).unwrap();
        let plane = Arc::new(
            IngressDataPlane::new(IngressDataPlaneConfig::new("ingress", identity, policy))
                .unwrap(),
        );
        for namespace in ["alpha", "beta"] {
            plane
                .mark_egress(
                    &EgressId::in_namespace(namespace, "edge"),
                    RuntimeNodeState::Ready,
                    1,
                )
                .await;
        }
        let adapter = DataPlaneDnsAdapter {
            data_plane: Arc::clone(&plane),
        };
        let selector = Selector {
            labels: BTreeMap::from([("region".into(), "jp".into())]),
            ..Default::default()
        };
        assert_eq!(
            adapter.select_egress("beta", &selector).await,
            Some(EgressId::in_namespace("beta", "edge"))
        );
        assert_eq!(
            adapter.select_transit("beta", &selector).await,
            Some(TransitProxyId::in_namespace("beta", "node"))
        );
        assert!(matches!(
            plane
                .ensure_session(
                    &EgressId::in_namespace("alpha", "edge"),
                    &TransitProxyId::in_namespace("beta", "node")
                )
                .await,
            Err(DataPlaneError::NoUsableRoute)
        ));
        plane.runtime.write().await.set_transit_proxy(
            TransitProxyId::in_namespace("alpha", "node"),
            TransitProxyRuntimeStatus::default(),
        );
        plane
            .mark_egress(
                &EgressId::in_namespace("alpha", "edge"),
                RuntimeNodeState::Down,
                0,
            )
            .await;
        assert_eq!(adapter.select_transit("alpha", &selector).await, None);
        assert_eq!(adapter.select_egress("alpha", &selector).await, None);
        let alpha_slot = plane
            .sessions
            .get(&EgressId::in_namespace("alpha", "edge"))
            .expect("alpha session slot");
        assert!(
            plane
                .eligible_transits_for_egress(&alpha_slot.egress)
                .await
                .is_empty()
        );
        let beta_slot = plane
            .sessions
            .get(&EgressId::in_namespace("beta", "edge"))
            .expect("beta session slot");
        assert_eq!(
            plane
                .eligible_transits_for_egress(&beta_slot.egress)
                .await
                .first()
                .map(|(id, _)| id.clone()),
            Some(TransitProxyId::in_namespace("beta", "node"))
        );
    }

    #[tokio::test]
    async fn explicit_direct_fallback_connects_without_a_session() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("target");
        let address = listener.local_addr().expect("target address");
        let target = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept");
            let mut value = [0_u8; 4];
            stream.read_exact(&mut value).await.expect("read");
            stream.write_all(&value).await.expect("write");
        });
        let plane = data_plane(FallbackAction::Direct);
        let mut stream = plane.open_tcp(&context(address)).await.expect("open");
        stream.write_all(b"ping").await.expect("send");
        let mut echoed = [0_u8; 4];
        stream.read_exact(&mut echoed).await.expect("echo");
        assert_eq!(&echoed, b"ping");
        target.await.expect("target task");
        assert_eq!(plane.snapshot().await.sessions, 0);
    }

    #[tokio::test]
    async fn explicit_direct_fallback_forwards_udp_without_a_session() {
        let target = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = target.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let mut bytes = [0; 128];
            for expected in [b"one".as_slice(), b"two-two".as_slice()] {
                let (length, peer) = target.recv_from(&mut bytes).await.unwrap();
                assert_eq!(&bytes[..length], expected);
                target.send_to(&bytes[..length], peer).await.unwrap();
            }
        });
        let plane = data_plane(FallbackAction::Direct);
        let mut handle = plane.open_udp(&context(address)).await.unwrap();
        for payload in [b"one".to_vec(), b"two-two".to_vec()] {
            handle.send(payload.clone()).await.unwrap();
            assert_eq!(
                timeout(Duration::from_secs(2), handle.receive())
                    .await
                    .unwrap(),
                Some(payload)
            );
        }
        handle.close().await.unwrap();
        task.await.unwrap();
        assert_eq!(plane.snapshot().await.sessions, 0);
    }

    #[tokio::test]
    async fn udp_reject_fallback_never_contacts_the_target() {
        let target = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let plane = data_plane(FallbackAction::Reject);
        assert!(matches!(
            plane.open_udp(&context(target.local_addr().unwrap())).await,
            Err(DataPlaneError::PolicyRejected)
        ));
        let mut packet = [0; 16];
        assert!(
            timeout(Duration::from_millis(20), target.recv_from(&mut packet))
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn explicitly_disabled_udp_is_not_admitted_as_an_ordinary_proxy_route() {
        let id = TransitProxyId::new("tcp-only-direct");
        let policy = ValidatedPolicySnapshot::new(
            Generation::new(1),
            PolicyConfig {
                transit_proxies: vec![TransitProxyConfig {
                    id,
                    source: None,
                    protocol: "direct".into(),
                    endpoint: pathchord_policy::Endpoint {
                        host: String::new(),
                        port: 1,
                    },
                    credentials_ref: None,
                    labels: Default::default(),
                    tags: Default::default(),
                    weight: 100,
                    options: pathchord_policy::TransitOptions {
                        udp: Some(false),
                        ..Default::default()
                    },
                }],
                proxy_rules: vec![ProxyRule {
                    id: RuleId::new("selected-proxy"),
                    matches: FlowMatch::default(),
                    require: Selector::default(),
                    select: ProxySelection::Any,
                }],
                fallback: Some(FallbackAction::Reject),
                ..Default::default()
            },
        )
        .unwrap();
        let plane = IngressDataPlane::new(IngressDataPlaneConfig::new(
            "ingress-a",
            pathchord_noise::generate_static_keypair().unwrap(),
            policy,
        ))
        .unwrap();
        assert!(matches!(
            plane
                .open_udp(&context("127.0.0.1:9".parse().unwrap()))
                .await,
            Err(DataPlaneError::PolicyRejected)
        ));
    }

    #[tokio::test]
    async fn ordinary_proxy_rules_open_native_udp_on_the_selected_adapter() {
        #[derive(Debug)]
        struct CountingAdapter {
            sends: Arc<std::sync::atomic::AtomicU64>,
        }
        #[derive(Debug)]
        struct CountingDatagram {
            sends: Arc<std::sync::atomic::AtomicU64>,
            reply: Option<Vec<u8>>,
        }
        #[async_trait::async_trait]
        impl pathchord_transit::TransitDatagram for CountingDatagram {
            async fn send(&mut self, payload: &[u8]) -> Result<(), TransitError> {
                self.sends.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                self.reply = Some(payload.to_vec());
                Ok(())
            }
            async fn receive(&mut self) -> Result<Vec<u8>, TransitError> {
                Ok(self.reply.take().unwrap())
            }
        }
        #[async_trait::async_trait]
        impl TransitAdapter for CountingAdapter {
            fn metadata(&self) -> &pathchord_transit::TransitMetadata {
                panic!("metadata is not needed for routing")
            }
            fn supports_udp(&self) -> bool {
                true
            }
            async fn connect(
                &self,
                _: ConnectRequest,
            ) -> Result<pathchord_transit::BoxedTransitConnection, TransitError> {
                panic!("UDP must not use the TCP adapter")
            }
            async fn connect_udp(
                &self,
                request: ConnectRequest,
            ) -> Result<pathchord_transit::BoxedTransitDatagram, TransitError> {
                assert_eq!(request.destination.host, "unresolved.example.test");
                Ok(Box::new(CountingDatagram {
                    sends: Arc::clone(&self.sends),
                    reply: None,
                }))
            }
        }
        let id = TransitProxyId::new("native-udp");
        let config = TransitProxyConfig {
            id: id.clone(),
            source: None,
            protocol: "socks5".into(),
            endpoint: pathchord_policy::Endpoint {
                host: "127.0.0.1".into(),
                port: 1080,
            },
            credentials_ref: None,
            options: Default::default(),
            labels: Default::default(),
            tags: Default::default(),
            weight: 100,
        };
        let policy = ValidatedPolicySnapshot::new(
            Generation::new(1),
            PolicyConfig {
                transit_proxies: vec![config],
                proxy_rules: vec![ProxyRule {
                    id: RuleId::new("udp-proxy"),
                    matches: FlowMatch::default(),
                    require: Selector::default(),
                    select: ProxySelection::Any,
                }],
                fallback: Some(FallbackAction::Reject),
                ..PolicyConfig::default()
            },
        )
        .unwrap();
        let plane = IngressDataPlane::new(IngressDataPlaneConfig::new(
            "ingress-a",
            pathchord_noise::generate_static_keypair().unwrap(),
            policy,
        ))
        .unwrap();
        let sends = Arc::new(std::sync::atomic::AtomicU64::new(0));
        plane
            .register_transit_adapter(
                id,
                Arc::new(CountingAdapter {
                    sends: Arc::clone(&sends),
                }),
                TransitProxyRuntimeStatus {
                    state: RuntimeNodeState::Ready,
                    capabilities: BTreeSet::from([FlowProtocol::Tcp, FlowProtocol::Udp]),
                    selection_score: 1,
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        let mut ctx = context("127.0.0.1:53".parse().unwrap());
        ctx.target.host = crate::TargetHost::Hostname("unresolved.example.test".into());
        let mut handle = plane.open_udp(&ctx).await.unwrap();
        handle.send(b"native-udp".to_vec()).await.unwrap();
        assert_eq!(handle.receive().await, Some(b"native-udp".to_vec()));
        assert_eq!(sends.load(std::sync::atomic::Ordering::SeqCst), 1);
        handle.close().await.unwrap();
    }

    #[tokio::test]
    async fn disabled_replication_requests_zero_even_with_a_positive_policy_budget() {
        let identity = pathchord_noise::generate_static_keypair().expect("identity");
        let policy = ValidatedPolicySnapshot::new(
            Generation::new(1),
            PolicyConfig {
                traffic_policies: vec![TrafficPolicy {
                    id: TrafficPolicyId::in_namespace("tenant-a", "latency"),
                    scheduler: Scheduler::EffectiveCapacityWeighted,
                    session_replication_budget_bps: 16_000,
                    class_replication_budget_bps: None,
                    retransmission_replication: RetransmissionReplication::Disabled,
                    classes: BTreeMap::new(),
                }],
                fallback: Some(FallbackAction::Reject),
                ..PolicyConfig::default()
            },
        )
        .expect("policy");
        let plane =
            IngressDataPlane::new(IngressDataPlaneConfig::new("ingress-a", identity, policy))
                .expect("data plane");
        let config = plane
            .multipath_config_for(&TrafficPolicyId::in_namespace("tenant-a", "latency"))
            .await;
        assert_eq!(config.session_replication_budget_bytes, 0);
        assert_eq!(config.default_stream_replication_budget_bytes, 0);
        assert!(config.class_replication_budget_bytes.is_empty());
        assert!(!config.retransmission_replication_enabled);
    }

    #[tokio::test]
    async fn zero_replication_budget_remains_zero_even_when_replication_is_allowed() {
        let identity = pathchord_noise::generate_static_keypair().expect("identity");
        let policy = ValidatedPolicySnapshot::new(
            Generation::new(1),
            PolicyConfig {
                traffic_policies: vec![TrafficPolicy {
                    id: TrafficPolicyId::new("none"),
                    scheduler: Scheduler::EffectiveCapacityWeighted,
                    session_replication_budget_bps: 0,
                    class_replication_budget_bps: None,
                    retransmission_replication: RetransmissionReplication::Allowed,
                    classes: BTreeMap::new(),
                }],
                fallback: Some(FallbackAction::Reject),
                ..PolicyConfig::default()
            },
        )
        .expect("policy");
        let plane =
            IngressDataPlane::new(IngressDataPlaneConfig::new("ingress-a", identity, policy))
                .expect("data plane");
        let config = plane
            .multipath_config_for(&TrafficPolicyId::new("none"))
            .await;
        assert_eq!(config.session_replication_budget_bytes, 0);
        assert_eq!(config.default_stream_replication_budget_bytes, 0);
        assert!(!config.retransmission_replication_enabled);
    }

    #[tokio::test]
    async fn replication_budget_rounds_down_and_zero_class_is_never_bypassed() {
        let identity = pathchord_noise::generate_static_keypair().expect("identity");
        let policy = ValidatedPolicySnapshot::new(
            Generation::new(1),
            PolicyConfig {
                traffic_policies: vec![
                    TrafficPolicy {
                        id: TrafficPolicyId::new("low-rate"),
                        scheduler: Scheduler::EffectiveCapacityWeighted,
                        session_replication_budget_bps: 7,
                        class_replication_budget_bps: None,
                        retransmission_replication: RetransmissionReplication::Allowed,
                        classes: BTreeMap::new(),
                    },
                    TrafficPolicy {
                        id: TrafficPolicyId::new("restricted"),
                        scheduler: Scheduler::EffectiveCapacityWeighted,
                        session_replication_budget_bps: 80,
                        class_replication_budget_bps: None,
                        retransmission_replication: RetransmissionReplication::Allowed,
                        classes: BTreeMap::new(),
                    },
                ],
                fallback: Some(FallbackAction::Reject),
                ..PolicyConfig::default()
            },
        )
        .unwrap();
        let plane =
            IngressDataPlane::new(IngressDataPlaneConfig::new("test", identity, policy)).unwrap();
        let low = plane
            .multipath_config_for(&TrafficPolicyId::new("low-rate"))
            .await;
        assert_eq!(low.session_replication_budget_bytes, 0);
        assert!(!low.retransmission_replication_enabled);

        let config = plane
            .multipath_config_for(&TrafficPolicyId::new("restricted"))
            .await;
        assert_eq!(config.session_replication_budget_bytes, 10);
        let mut session =
            pathchord_path::MultipathSession::new(pathchord_core::SessionId::new(1), config)
                .unwrap();
        for path_id in [
            pathchord_core::PathId::new(1),
            pathchord_core::PathId::new(2),
        ] {
            session
                .add_path(path_id, MultipathPathObservation::default())
                .unwrap();
        }
        let stream_id = pathchord_core::StreamId::new(1).unwrap();
        session
            .retain_stream_data(
                pathchord_core::StreamData {
                    stream_id,
                    offset: 0,
                    flags: 0,
                    data: vec![1],
                },
                "default",
                pathchord_core::PathId::new(1),
            )
            .unwrap();
        assert!(matches!(
            session.replicate_range(
                stream_id,
                0,
                Some(pathchord_core::PathId::new(1)),
                pathchord_path::ScheduleDirection::Upstream,
                None
            ),
            Err(pathchord_path::MultipathError::ReplicationBudgetExhausted)
        ));
    }

    #[tokio::test]
    async fn reject_fallback_never_dials_the_target() {
        let plane = data_plane(FallbackAction::Reject);
        let address = "127.0.0.1:9".parse().expect("address");
        assert!(matches!(
            plane.open_tcp(&context(address)).await,
            Err(DataPlaneError::PolicyRejected)
        ));
    }

    #[tokio::test]
    async fn flow_tags_reach_the_compiled_data_plane_policy() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let target = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut value = [0_u8; 4];
            stream.read_exact(&mut value).await.unwrap();
            stream.write_all(&value).await.unwrap();
        });
        let identity = pathchord_noise::generate_static_keypair().unwrap();
        let policy = ValidatedPolicySnapshot::new(
            Generation::new(1),
            PolicyConfig {
                proxy_rules: vec![ProxyRule {
                    id: RuleId::new("tagged-direct"),
                    matches: FlowMatch {
                        flow_tags: BTreeSet::from(["allow-direct".to_owned()]),
                        ..FlowMatch::default()
                    },
                    require: Selector::default(),
                    select: ProxySelection::Direct,
                }],
                fallback: Some(FallbackAction::Reject),
                ..PolicyConfig::default()
            },
        )
        .unwrap();
        let plane =
            IngressDataPlane::new(IngressDataPlaneConfig::new("ingress-a", identity, policy))
                .unwrap();
        let mut untagged = context(address);
        assert!(matches!(
            plane.open_tcp(&untagged).await,
            Err(DataPlaneError::PolicyRejected)
        ));
        untagged.flow_tags.insert("allow-direct".to_owned());
        let mut stream = plane.open_tcp(&untagged).await.unwrap();
        stream.write_all(b"tags").await.unwrap();
        let mut echoed = [0_u8; 4];
        stream.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"tags");
        target.await.unwrap();
    }

    #[test]
    fn trust_failures_back_off_and_open_a_circuit() {
        let start = Instant::now();
        let mut state = TrustFailureState::default();
        let first = SessionId::new(1);
        let second = SessionId::new(2);
        let third = SessionId::new(3);
        state.record_for(first, start);
        assert!(!state.can_attempt(start));
        assert!(state.can_attempt(start + Duration::from_secs(1)));
        state.record_for(second, start + Duration::from_secs(1));
        state.record_for(third, start + Duration::from_secs(3));
        assert!(!state.can_attempt(start + Duration::from_secs(4)));
        assert!(state.can_attempt(start + TRUST_FAILURE_COOLDOWN + Duration::from_secs(4)));
    }
}
