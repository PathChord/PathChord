//! Ingress-owned policy, Transit, Session, and logical TCP Stream runtime.

use std::collections::{BTreeMap, BTreeSet};
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
    CompiledPolicy, EgressConfig, EgressId, EgressRuntimeStatus, Evaluation, FlowProtocol,
    PolicyContext, ProxyRoutePlan, RoutePlan, RuntimeCatalog, RuntimeNodeState, Selector,
    TrafficPolicy, TrafficPolicyId, TransitProxyConfig, TransitProxyId, TransitProxyRuntimeStatus,
    ValidatedPolicySnapshot,
};
use pathchord_transit::{
    ConnectRequest, DirectTransitAdapter, Endpoint as TransitEndpoint, TransitAdapter, TransitError,
};
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{Mutex, RwLock};
use tokio::time::{Instant, timeout};

use crate::{
    BoxedLocalConnection, BoxedUdpFlowHandle, ConnectionContext, DnsAdapterError, DnsRouteAdapter,
    DnsRouteRequest, DnsRouteSelection, FlowBridgeError, MAX_DNS_MESSAGE_BYTES, TcpFlowOpener,
};

pub const DEFAULT_PATH_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const TCP_CAPABILITY: u64 = 1;
const UDP_CAPABILITY: u64 = 1 << 1;

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
}

#[derive(Debug, Error)]
pub enum DataPlaneError {
    #[error("Ingress identity is invalid")]
    InvalidIngressIdentity,
    #[error("configured Egress public key is invalid")]
    InvalidEgressKey,
    #[error("policy compilation failed: {0}")]
    PolicyCompile(#[from] pathchord_policy::CompileError),
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
}

struct SessionSlot {
    egress: EgressConfig,
    session: Mutex<Option<Arc<IngressSessionHandle>>>,
    transit_paths: Mutex<BTreeMap<TransitProxyId, PathId>>,
    draining_paths: Mutex<BTreeMap<TransitProxyId, (PathId, Instant)>>,
    autoscaler: Mutex<PathAutoscaler>,
    eligible_transits: Mutex<BTreeMap<TransitProxyId, u32>>,
    maintenance_sample: Mutex<(Instant, u64)>,
    maintenance_epoch: Instant,
}

impl SessionSlot {
    fn new(egress: EgressConfig) -> Self {
        let min_paths = (egress.status_requirements.min_usable_paths as usize).max(1);
        Self {
            egress,
            session: Mutex::new(None),
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
            maintenance_sample: Mutex::new((Instant::now(), 0)),
            maintenance_epoch: Instant::now(),
        }
    }
}

pub struct IngressDataPlane {
    ingress_id: String,
    identity: Arc<StaticKeypair>,
    compiled: RwLock<CompiledPolicy>,
    generation: std::sync::atomic::AtomicU64,
    egresses: BTreeMap<EgressId, EgressConfig>,
    transit_configs: BTreeMap<TransitProxyId, TransitProxyConfig>,
    traffic_policies: RwLock<BTreeMap<TrafficPolicyId, TrafficPolicy>>,
    dynamic_transit_configs: RwLock<BTreeMap<TransitProxyId, TransitProxyConfig>>,
    transit_adapters: RwLock<BTreeMap<TransitProxyId, Arc<dyn TransitAdapter>>>,
    runtime: RwLock<RuntimeCatalog>,
    sessions: BTreeMap<EgressId, Arc<SessionSlot>>,
    path_connect_timeout: Duration,
    shutting_down: std::sync::atomic::AtomicBool,
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
            .field("transit_count", &self.transit_configs.len())
            .finish_non_exhaustive()
    }
}

impl IngressDataPlane {
    pub fn new(config: IngressDataPlaneConfig) -> Result<Self, DataPlaneError> {
        if !valid_identifier(config.ingress_id.as_bytes()) {
            return Err(DataPlaneError::InvalidIngressIdentity);
        }
        let compiled = CompiledPolicy::compile(&config.policy)?;
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
            transit_configs,
            traffic_policies: RwLock::new(traffic_policies),
            dynamic_transit_configs: RwLock::new(BTreeMap::new()),
            transit_adapters: RwLock::new(transit_adapters),
            runtime: RwLock::new(runtime),
            sessions,
            path_connect_timeout: config.path_connect_timeout,
            shutting_down: std::sync::atomic::AtomicBool::new(false),
        })
    }

    pub async fn register_transit_adapter(
        &self,
        id: TransitProxyId,
        adapter: Arc<dyn TransitAdapter>,
        mut status: TransitProxyRuntimeStatus,
    ) -> Result<(), DataPlaneError> {
        if !self.transit_configs.contains_key(&id) {
            return Err(DataPlaneError::TransitUnavailable(id.as_str().to_owned()));
        }
        if !adapter.supports_udp() || self.transit_configs[&id].options.udp == Some(false) {
            status.capabilities.remove(&FlowProtocol::Udp);
        }
        if !adapter.supports_tcp() {
            status.capabilities.remove(&FlowProtocol::Tcp);
        }
        self.transit_adapters
            .write()
            .await
            .insert(id.clone(), adapter);
        self.runtime.write().await.set_transit_proxy(id, status);
        Ok(())
    }

    pub async fn replace_compiled_policy(&self, compiled: CompiledPolicy) {
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

    pub async fn register_dynamic_transit_adapter(
        &self,
        config: TransitProxyConfig,
        adapter: Arc<dyn TransitAdapter>,
        mut status: TransitProxyRuntimeStatus,
    ) {
        if !adapter.supports_udp() || config.options.udp == Some(false) {
            status.capabilities.remove(&FlowProtocol::Udp);
        }
        if !adapter.supports_tcp() {
            status.capabilities.remove(&FlowProtocol::Tcp);
        }
        let id = config.id.clone();
        self.dynamic_transit_configs
            .write()
            .await
            .insert(id.clone(), config.clone());
        self.transit_adapters.write().await.insert(id, adapter);
        self.runtime
            .write()
            .await
            .set_dynamic_transit_proxy(config, status);
    }

    pub async fn publish_dynamic_transit_status(
        &self,
        config: TransitProxyConfig,
        status: TransitProxyRuntimeStatus,
    ) {
        self.dynamic_transit_configs
            .write()
            .await
            .insert(config.id.clone(), config.clone());
        self.runtime
            .write()
            .await
            .set_dynamic_transit_proxy(config, status);
    }

    pub async fn apply_transit_admin_metadata(
        &self,
        id: &TransitProxyId,
        labels: BTreeMap<String, String>,
        tags: BTreeSet<String>,
    ) -> bool {
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
        for slot in self.sessions.values() {
            let path_id = slot.transit_paths.lock().await.get(id).copied();
            let session = slot.session.lock().await.clone();
            if let (Some(path_id), Some(session)) = (path_id, session)
                && session.drain_path(path_id).await.is_ok()
            {
                slot.draining_paths
                    .lock()
                    .await
                    .insert(id.clone(), (path_id, Instant::now()));
            }
        }
    }

    pub async fn transit_in_use(&self, id: &TransitProxyId) -> bool {
        for slot in self.sessions.values() {
            if slot.transit_paths.lock().await.contains_key(id)
                || slot.draining_paths.lock().await.contains_key(id)
            {
                return true;
            }
        }
        false
    }

    pub async fn remove_dynamic_transit(&self, id: &TransitProxyId) {
        self.transit_adapters.write().await.remove(id);
        self.dynamic_transit_configs.write().await.remove(id);
        self.runtime.write().await.remove_dynamic_transit_proxy(id);
    }

    pub fn dns_route_adapter(self: &Arc<Self>) -> Arc<dyn DnsRouteAdapter> {
        Arc::new(DataPlaneDnsAdapter {
            data_plane: Arc::clone(self),
        })
    }

    /// Establishes the Phase-1 single Path for every configured Egress that has
    /// at least one available Transit adapter. Failed relationships remain down.
    pub async fn warmup(&self) {
        for egress_id in self.egresses.keys() {
            let Some(slot) = self.sessions.get(egress_id) else {
                continue;
            };
            let mut session = slot.session.lock().await.clone();
            if session.is_none() {
                let minimum = (slot.egress.status_requirements.min_usable_paths as usize).max(1);
                let candidates: Vec<_> = self
                    .transit_adapters
                    .read()
                    .await
                    .keys()
                    .take(minimum)
                    .cloned()
                    .collect();
                for transit_id in candidates {
                    slot.eligible_transits
                        .lock()
                        .await
                        .entry(transit_id.clone())
                        .or_insert(100);
                    let _ = self.ensure_session(egress_id, &transit_id).await;
                }
                session = slot.session.lock().await.clone();
            }
            if session.is_none() {
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
            let demand_bps = total_bytes
                .saturating_sub(sample.1)
                .saturating_mul(8)
                .saturating_mul(1_000)
                / elapsed_ms;
            *sample = (now, total_bytes);
            drop(sample);
            let input = AutoscaleInput {
                demand_bps,
                effective_capacity_bps: snapshot
                    .as_ref()
                    .map_or(0, |snapshot| snapshot.egress_aggregate_capacity_bps),
                ready_paths: snapshot.as_ref().map_or(0, |snapshot| snapshot.ready_paths),
                degraded_paths: snapshot
                    .as_ref()
                    .map_or(0, |snapshot| snapshot.degraded_paths),
                recommended_path_count: snapshot
                    .as_ref()
                    .map(|snapshot| snapshot.recommended_path_count as usize),
                hard_available: true,
                quota_remaining: None,
                traffic_multiplier_basis_points: 10_000,
            };
            let now_ms = now
                .duration_since(slot.maintenance_epoch)
                .as_millis()
                .min(u128::from(u64::MAX)) as u64;
            let _ = self.maintain_egress_paths(egress_id, input, now_ms).await;
        }
    }

    pub async fn maintain_egress_paths(
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
                .map(|(transit_id, (path_id, _))| (transit_id.clone(), *path_id))
                .collect();
            for (transit_id, path_id) in due {
                let _ = session.close_path(path_id).await;
                slot.draining_paths.lock().await.remove(&transit_id);
                slot.transit_paths.lock().await.remove(&transit_id);
            }
            let snapshot = session.snapshot();
            input.ready_paths = snapshot.ready_paths;
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
            for (transit_id, path_id) in &paths {
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
                session
                    .update_path_economic_status(
                        *path_id,
                        PathEconomicStatus {
                            hard_available: input.hard_available,
                            quota_remaining,
                            traffic_multiplier_basis_points,
                        },
                    )
                    .await?;
            }
        }
        let decision = slot.autoscaler.lock().await.evaluate(input, now_ms);
        match decision {
            AutoscaleDecision::Add { count } => {
                let active = slot.transit_paths.lock().await.clone();
                let draining = slot.draining_paths.lock().await.clone();
                let eligible = slot.eligible_transits.lock().await.clone();
                let candidates: Vec<_> = self
                    .transit_adapters
                    .read()
                    .await
                    .keys()
                    .filter(|id| {
                        eligible.contains_key(*id)
                            && !active.contains_key(*id)
                            && !draining.contains_key(*id)
                    })
                    .take(count)
                    .cloned()
                    .collect();
                for transit_id in candidates {
                    let _ = self.ensure_session(egress_id, &transit_id).await;
                }
            }
            AutoscaleDecision::Drain { count } => {
                if let Some(session) = session {
                    let candidates: Vec<_> = slot
                        .transit_paths
                        .lock()
                        .await
                        .iter()
                        .rev()
                        .take(count)
                        .map(|(transit_id, path_id)| (transit_id.clone(), *path_id))
                        .collect();
                    for (transit_id, path_id) in candidates {
                        session.drain_path(path_id).await?;
                        slot.draining_paths
                            .lock()
                            .await
                            .insert(transit_id, (path_id, Instant::now()));
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
        let bits_to_bytes = |bits_per_second: u64, fallback: u64| {
            if bits_per_second == 0 {
                fallback
            } else {
                bits_per_second.saturating_div(8).max(1)
            }
        };
        let session_budget = bits_to_bytes(
            policy.session_replication_budget_bps,
            default.session_replication_budget_bytes,
        );
        let class_budget = policy
            .class_replication_budget_bps
            .map_or(session_budget, |budget| {
                bits_to_bytes(budget, session_budget)
            });
        let class_replication_budget_bytes = policy
            .classes
            .keys()
            .map(|class| (class.clone(), class_budget))
            .collect();
        MultipathConfig {
            session_replication_budget_bytes: session_budget,
            default_stream_replication_budget_bytes: session_budget,
            class_replication_budget_bytes,
            retransmission_replication_enabled: matches!(
                policy.retransmission_replication,
                pathchord_policy::RetransmissionReplication::Allowed
            ),
            ..default
        }
    }

    pub async fn open_tcp(
        &self,
        context: &ConnectionContext,
    ) -> Result<BoxedLocalConnection, DataPlaneError> {
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
                let candidate = route
                    .candidates
                    .first()
                    .ok_or(DataPlaneError::NoUsableRoute)?;
                let mut session = None;
                {
                    let slot = self
                        .sessions
                        .get(&candidate.egress_id)
                        .ok_or(DataPlaneError::NoUsableRoute)?;
                    let mut eligible = slot.eligible_transits.lock().await;
                    for transit in &candidate.transit_proxies {
                        eligible.insert(transit.id.clone(), transit.relationship_weight);
                    }
                }
                for transit in &candidate.transit_proxies {
                    if let Ok(ready) = self.ensure_session(&candidate.egress_id, &transit.id).await
                    {
                        session = Some(ready);
                    }
                }
                let session = session.ok_or(DataPlaneError::NoUsableRoute)?;
                let slot = self
                    .sessions
                    .get(&candidate.egress_id)
                    .ok_or(DataPlaneError::NoUsableRoute)?;
                let paths = slot.transit_paths.lock().await;
                let eligible: BTreeMap<_, _> = candidate
                    .transit_proxies
                    .iter()
                    .filter_map(|transit| {
                        paths
                            .get(&transit.id)
                            .map(|path_id| (*path_id, transit.relationship_weight))
                    })
                    .collect();
                drop(paths);
                if eligible.is_empty() {
                    return Err(DataPlaneError::NoUsableRoute);
                }
                let maximum_weight = eligible.values().copied().max().unwrap_or(1).max(1);
                for (path_id, weight) in &eligible {
                    session
                        .update_path_observation(
                            *path_id,
                            MultipathPathObservation {
                                weight_basis_points: (u64::from(*weight).saturating_mul(10_000)
                                    / u64::from(maximum_weight))
                                .max(1) as u16,
                                ..MultipathPathObservation::default()
                            },
                        )
                        .await?;
                }
                let stream = session
                    .open_tcp_routed_with_config(
                        wire_target(&policy_context)?,
                        eligible,
                        self.multipath_config_for(&candidate.traffic_policy_id)
                            .await,
                    )
                    .await?;
                Ok(Box::new(stream) as BoxedLocalConnection)
            }
        }
    }

    pub async fn open_udp(
        &self,
        context: &ConnectionContext,
    ) -> Result<BoxedUdpFlowHandle, DataPlaneError> {
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
                let disabled = self
                    .transit_configs
                    .get(&route.transit_proxy_id)
                    .is_some_and(|config| config.options.udp == Some(false))
                    || self
                        .dynamic_transit_configs
                        .read()
                        .await
                        .get(&route.transit_proxy_id)
                        .is_some_and(|config| config.options.udp == Some(false));
                if disabled {
                    return Err(DataPlaneError::NoUsableRoute);
                }
                let adapter = self
                    .transit_adapters
                    .read()
                    .await
                    .get(&route.transit_proxy_id)
                    .cloned()
                    .ok_or_else(|| {
                        DataPlaneError::TransitUnavailable(
                            route.transit_proxy_id.as_str().to_owned(),
                        )
                    })?;
                if !adapter.supports_udp() {
                    return Err(DataPlaneError::NoUsableRoute);
                }
                let datagram = adapter
                    .connect_udp(ConnectRequest {
                        destination: transit_target(&policy_context)?,
                    })
                    .await?;
                return Ok(Box::new(crate::udp_flow::TransitUdpFlowHandle::new(
                    datagram,
                )));
            }
            Evaluation::Route(RoutePlan::Egress(route)) => route,
        };
        let candidate = route
            .candidates
            .first()
            .ok_or(DataPlaneError::NoUsableRoute)?;
        let slot = self
            .sessions
            .get(&candidate.egress_id)
            .ok_or(DataPlaneError::NoUsableRoute)?;
        {
            let mut eligible = slot.eligible_transits.lock().await;
            for transit in &candidate.transit_proxies {
                eligible.insert(transit.id.clone(), transit.relationship_weight);
            }
        }
        let mut session = None;
        for transit in &candidate.transit_proxies {
            if let Ok(ready) = self.ensure_session(&candidate.egress_id, &transit.id).await {
                session = Some(ready);
            }
        }
        let session = session.ok_or(DataPlaneError::NoUsableRoute)?;
        let paths = slot.transit_paths.lock().await;
        let eligible: BTreeMap<_, _> = candidate
            .transit_proxies
            .iter()
            .filter_map(|transit| {
                paths
                    .get(&transit.id)
                    .map(|path_id| (*path_id, transit.relationship_weight))
            })
            .collect();
        drop(paths);
        if eligible.is_empty() {
            return Err(DataPlaneError::NoUsableRoute);
        }
        let maximum_weight = eligible.values().copied().max().unwrap_or(1).max(1);
        for (path_id, weight) in &eligible {
            session
                .update_path_observation(
                    *path_id,
                    MultipathPathObservation {
                        weight_basis_points: (u64::from(*weight).saturating_mul(10_000)
                            / u64::from(maximum_weight))
                        .max(1) as u16,
                        ..MultipathPathObservation::default()
                    },
                )
                .await?;
        }
        Ok(Box::new(
            session
                .open_udp_routed_with_config(
                    wire_target(&policy_context)?,
                    eligible,
                    self.multipath_config_for(&candidate.traffic_policy_id)
                        .await,
                )
                .await?,
        ))
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
                });
            }
        }
        snapshots
    }

    pub async fn shutdown(&self) -> Result<DataPlaneSnapshot, DataPlaneError> {
        self.shutting_down
            .store(true, std::sync::atomic::Ordering::Release);
        for slot in self.sessions.values() {
            let session = slot.session.lock().await.take();
            if let Some(session) = session {
                shutdown_session(session).await?;
            }
        }
        Ok(self.snapshot().await)
    }

    async fn first_available_transit(&self) -> Option<TransitProxyId> {
        self.transit_adapters.read().await.keys().next().cloned()
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
        let adapter = self
            .transit_adapters
            .read()
            .await
            .get(&route.transit_proxy_id)
            .cloned()
            .ok_or_else(|| {
                DataPlaneError::TransitUnavailable(route.transit_proxy_id.as_str().to_owned())
            })?;
        let stream = adapter
            .connect(ConnectRequest {
                destination: transit_target(context)?,
            })
            .await?;
        Ok(Box::new(stream) as BoxedLocalConnection)
    }

    async fn ensure_session(
        &self,
        egress_id: &EgressId,
        transit_id: &TransitProxyId,
    ) -> Result<Arc<IngressSessionHandle>, DataPlaneError> {
        let slot = self
            .sessions
            .get(egress_id)
            .ok_or(DataPlaneError::NoUsableRoute)?;
        let mut guard = slot.session.lock().await;
        if let Some(session) = guard.as_ref()
            && !session.snapshot().closed
        {
            let session_snapshot = session.snapshot();
            let draining = slot.draining_paths.lock().await;
            let mut transit_paths = slot.transit_paths.lock().await;
            transit_paths.retain(|transit_id, path_id| {
                session_snapshot.ready_path_ids.contains(path_id)
                    || draining.contains_key(transit_id)
            });
            if !transit_paths.contains_key(transit_id) {
                let session_id = session_snapshot.session_id;
                let path_id = PathId::new(random_u128()?);
                let path = self
                    .dial_session_path(slot, transit_id, session_id, path_id)
                    .await?;
                session
                    .add_path(path, MultipathPathObservation::default())
                    .await?;
                transit_paths.insert(transit_id.clone(), path_id);
                let ready_paths = session.snapshot().ready_paths as u32;
                self.mark_egress(egress_id, RuntimeNodeState::Ready, ready_paths)
                    .await;
            }
            drop(transit_paths);
            return Ok(Arc::clone(session));
        }
        guard.take();
        let session_id = SessionId::new(random_u128()?);
        let path_id = PathId::new(random_u128()?);
        let path = self
            .dial_session_path(slot, transit_id, session_id, path_id)
            .await?;
        let session = Arc::new(IngressSessionHandle::start(path)?);
        let mut transit_paths = slot.transit_paths.lock().await;
        transit_paths.clear();
        transit_paths.insert(transit_id.clone(), path_id);
        drop(transit_paths);
        *guard = Some(Arc::clone(&session));
        drop(guard);
        self.mark_egress(egress_id, RuntimeNodeState::Ready, 1)
            .await;
        Ok(session)
    }

    async fn dial_session_path(
        &self,
        slot: &SessionSlot,
        transit_id: &TransitProxyId,
        session_id: SessionId,
        path_id: PathId,
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
        let io = timeout(
            self.path_connect_timeout,
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
        let mut prologue = WIRE_PROFILE_V1_PROLOGUE_PREFIX.to_vec();
        prologue.extend_from_slice(slot.egress.id.as_str().as_bytes());
        let outcome = dial_path(
            io,
            self.identity.private(),
            &responder_key,
            &IngressPathAdmissionConfig {
                egress_identity: prologue,
                egress_id: slot.egress.id.as_str().as_bytes().to_vec(),
                ingress_id: self.ingress_id.as_bytes().to_vec(),
                session_id,
                path_id,
                offered_capabilities: TCP_CAPABILITY | UDP_CAPABILITY,
                local_limits: ProtocolLimits::default(),
            },
        )
        .await?;
        match outcome {
            PathAdmissionOutcome::Ready(path) => Ok(path),
            PathAdmissionOutcome::Rejected { .. } => Err(DataPlaneError::AdmissionRejected),
        }
    }

    async fn refresh_runtime(&self) {
        for (egress_id, slot) in &self.sessions {
            let session = slot.session.lock().await.clone();
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
        match request.selection {
            DnsRouteSelection::Egress {
                egress_selector,
                servers,
            } => {
                let egress_id = self
                    .select_egress(&egress_selector)
                    .await
                    .ok_or(DnsAdapterError::Unavailable)?;
                let transit_id = self
                    .data_plane
                    .first_available_transit()
                    .await
                    .ok_or(DnsAdapterError::Unavailable)?;
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
                proxy_selector,
                servers,
            } => {
                let proxy_id = self
                    .select_transit(&proxy_selector)
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
    async fn select_egress(&self, selector: &Selector) -> Option<EgressId> {
        let runtime = self.data_plane.runtime.read().await;
        self.data_plane
            .egresses
            .iter()
            .find(|(id, config)| {
                runtime.egress(id).is_some_and(|status| {
                    matches!(
                        status.state,
                        RuntimeNodeState::Ready | RuntimeNodeState::Degraded
                    ) && status.usable_paths > 0
                        && selector_matches_egress(selector, config, status)
                })
            })
            .map(|(id, _)| id.clone())
    }

    async fn select_transit(&self, selector: &Selector) -> Option<TransitProxyId> {
        let runtime = self.data_plane.runtime.read().await;
        let dynamic = self.data_plane.dynamic_transit_configs.read().await;
        self.data_plane
            .transit_configs
            .iter()
            .chain(dynamic.iter())
            .find(|(id, config)| {
                runtime.transit_proxy(id).is_some_and(|status| {
                    matches!(
                        status.state,
                        RuntimeNodeState::Ready | RuntimeNodeState::Degraded
                    ) && selector_matches_transit(selector, config, status)
                })
            })
            .map(|(id, _)| id.clone())
    }
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
            FlowBridgeError::EgressRejected { error, reason }
        }
        DataPlaneError::Udp(OpenUdpError::Rejected { error, reason }) => {
            FlowBridgeError::EgressRejected { error, reason }
        }
        DataPlaneError::Stream(OpenStreamError::ResourceLimit) => FlowBridgeError::ResourceLimit,
        DataPlaneError::Udp(OpenUdpError::ResourceLimit) => FlowBridgeError::ResourceLimit,
        DataPlaneError::ShuttingDown => FlowBridgeError::ShuttingDown,
        DataPlaneError::Transit(source) => FlowBridgeError::Dial(source.to_string()),
        DataPlaneError::InvalidIngressIdentity
        | DataPlaneError::InvalidEgressKey
        | DataPlaneError::PolicyCompile(_)
        | DataPlaneError::Admission(_)
        | DataPlaneError::Session(_)
        | DataPlaneError::Stream(OpenStreamError::SessionClosed)
        | DataPlaneError::Udp(_)
        | DataPlaneError::IdentifierGeneration => FlowBridgeError::SessionUnavailable,
    }
}

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
        RetransmissionReplication, RuleId, Scheduler, Selector, TrafficClass, TrafficPolicy,
        TrafficPolicyId,
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
    async fn traffic_policy_maps_replication_budgets_into_session_config() {
        let identity = pathchord_noise::generate_static_keypair().expect("identity");
        let policy = ValidatedPolicySnapshot::new(
            Generation::new(1),
            PolicyConfig {
                traffic_policies: vec![TrafficPolicy {
                    id: TrafficPolicyId::new("latency"),
                    scheduler: Scheduler::EffectiveCapacityWeighted,
                    session_replication_budget_bps: 16_000,
                    class_replication_budget_bps: Some(8_000),
                    retransmission_replication: RetransmissionReplication::Disabled,
                    classes: BTreeMap::from([(
                        "interactive".into(),
                        TrafficClass {
                            priority: 10,
                            share: 100,
                        },
                    )]),
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
            .multipath_config_for(&TrafficPolicyId::new("latency"))
            .await;
        assert_eq!(config.session_replication_budget_bytes, 2_000);
        assert_eq!(config.default_stream_replication_budget_bytes, 2_000);
        assert_eq!(config.class_replication_budget_bytes["interactive"], 1_000);
        assert!(!config.retransmission_replication_enabled);
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
}
