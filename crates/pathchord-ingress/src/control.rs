//! Typed Ingress control/query service.
//!
//! This module is deliberately transport-neutral. The local JSON protocol and
//! a future REST/SSE or GraphQL adapter should call this service instead of
//! editing configuration, caches, or runtime state directly.

use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::fmt;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::store::{AuditRecord, IngressControlStore, StoreCommit};
use crate::{
    FakePlatformProxyAdapter, ListenerDescriptor, ListenerKind, PlatformProxyAdapter,
    PlatformProxyKind, PlatformProxyRequest,
    control_views::{SystemProxyPlatformEffect, SystemProxyRestorationState},
};
use pathchord_core::{PathId, PathState, RequestId, SessionId, SessionState, StreamId};
use pathchord_policy::{
    ListenerId, SubscriptionCache as PolicySubscriptionCache,
    SubscriptionConfig as PolicySubscriptionConfig,
    SubscriptionRefresh as PolicySubscriptionRefresh, SubscriptionSource, SubscriptionSourceType,
};
use thiserror::Error;

pub const MAX_NODE_COUNT: usize = 4096;
pub const MAX_SUBSCRIPTION_COUNT: usize = 256;
pub const MAX_EVENT_COUNT: usize = 2048;
pub const MAX_REQUEST_CACHE_COUNT: usize = 4096;
pub const MAX_REFRESH_QUEUE_COUNT: usize = 256;
pub const MAX_CONNECTION_OBSERVATIONS: usize = 16_384;
pub const DEFAULT_OBSERVATION_STALE_AFTER_MS: u64 = 30_000;
pub const REQUEST_CACHE_TTL_MS: u64 = 24 * 60 * 60 * 1000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SystemProxyPlatform {
    Linux,
    Windows,
    FreeBsd,
}

impl SystemProxyPlatform {
    #[must_use]
    pub const fn current() -> Self {
        if cfg!(target_os = "windows") {
            Self::Windows
        } else if cfg!(target_os = "freebsd") {
            Self::FreeBsd
        } else {
            Self::Linux
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SystemProxyState {
    Disabled,
    Applying,
    Applied,
    Restoring,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SystemProxyStatus {
    pub state: SystemProxyState,
    pub enabled: bool,
    pub listener_id: Option<ListenerId>,
    pub platform_effect: SystemProxyPlatformEffect,
    pub environment_applied: bool,
    pub operating_system_applied: bool,
    pub restoration_state: SystemProxyRestorationState,
    pub error: Option<String>,
}

impl Default for SystemProxyStatus {
    fn default() -> Self {
        Self {
            state: SystemProxyState::Disabled,
            enabled: false,
            listener_id: None,
            platform_effect: SystemProxyPlatformEffect::Disabled,
            environment_applied: false,
            operating_system_applied: false,
            restoration_state: SystemProxyRestorationState::NotRequired,
            error: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SystemProxyMutation {
    pub generation: u64,
    pub event_id: u64,
    pub replayed: bool,
    pub status: SystemProxyStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NodeId(String);

impl NodeId {
    pub fn new(value: impl Into<String>) -> Result<Self, ControlError> {
        let value = value.into();
        if value.is_empty() || value.len() > 255 {
            return Err(ControlError::InvalidIdentifier { kind: "node" });
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for NodeId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SubscriptionId(String);

impl SubscriptionId {
    pub fn new(value: impl Into<String>) -> Result<Self, ControlError> {
        let value = value.into();
        if value.is_empty() || value.len() > 255 {
            return Err(ControlError::InvalidIdentifier {
                kind: "subscription",
            });
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for SubscriptionId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NodeAdminPatch {
    pub set_labels: BTreeMap<String, String>,
    pub remove_labels: BTreeSet<String>,
    pub add_tags: BTreeSet<String>,
    pub remove_tags: BTreeSet<String>,
}

impl NodeAdminPatch {
    fn validate(&self) -> Result<(), ControlError> {
        for key in self.set_labels.keys().chain(self.remove_labels.iter()) {
            if !key.starts_with("admin.") || key.len() == "admin.".len() {
                return Err(ControlError::InvalidNamespace { key: key.clone() });
            }
        }
        if self.set_labels.values().any(|value| value.len() > 256) {
            return Err(ControlError::FieldTooLarge { field: "label" });
        }
        if self
            .add_tags
            .iter()
            .chain(self.remove_tags.iter())
            .any(|tag| tag.is_empty() || tag.len() > 128)
        {
            return Err(ControlError::FieldTooLarge { field: "tag" });
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NodeAdminState {
    pub labels: BTreeMap<String, String>,
    pub tags: BTreeSet<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubscriptionRefreshSpec {
    pub interval_seconds: u64,
    pub timeout_seconds: u64,
    pub max_attempts: u32,
    pub backoff_seconds: u64,
}

/// Public control-plane alias matching the policy model's terminology.
pub type SubscriptionRefresh = SubscriptionRefreshSpec;

impl Default for SubscriptionRefreshSpec {
    fn default() -> Self {
        Self {
            interval_seconds: 3_600,
            timeout_seconds: 30,
            max_attempts: 3,
            backoff_seconds: 5,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubscriptionCacheSpec {
    pub path: String,
    pub max_age_seconds: u64,
}

/// Public control-plane alias matching the policy model's terminology.
pub type SubscriptionCache = SubscriptionCacheSpec;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubscriptionSpec {
    pub id: SubscriptionId,
    pub source_type: String,
    pub display_name: String,
    pub enabled: bool,
    pub url: String,
    pub credentials_ref: Option<String>,
    pub refresh: SubscriptionRefreshSpec,
    pub cache: Option<SubscriptionCacheSpec>,
}

impl SubscriptionSpec {
    pub(crate) fn validate(&self) -> Result<(), ControlError> {
        if !matches!(self.source_type.as_str(), "static" | "clash" | "sip008") {
            return Err(ControlError::InvalidSubscription {
                field: "source.type",
            });
        }
        if self.display_name.is_empty() || self.display_name.len() > 256 {
            return Err(ControlError::FieldTooLarge {
                field: "subscription display name",
            });
        }
        if self.url.is_empty() || self.url.len() > 4_096 || self.url.chars().any(char::is_control) {
            return Err(ControlError::InvalidSubscription {
                field: "source.url",
            });
        }
        let parsed = url::Url::parse(&self.url).map_err(|_| ControlError::InvalidSubscription {
            field: "source.url",
        })?;
        if !matches!(parsed.scheme(), "http" | "https")
            || !parsed.username().is_empty()
            || parsed.password().is_some()
        {
            return Err(ControlError::InvalidSubscription {
                field: "source.url",
            });
        }
        if self.credentials_ref.as_ref().is_some_and(|reference| {
            reference.is_empty() || reference.len() > 256 || reference.chars().any(char::is_control)
        }) {
            return Err(ControlError::InvalidSubscription {
                field: "source.credentials_ref",
            });
        }
        if !(60..=604_800).contains(&self.refresh.interval_seconds)
            || !(1..=300).contains(&self.refresh.timeout_seconds)
            || !(1..=10).contains(&self.refresh.max_attempts)
            || !(1..=3_600).contains(&self.refresh.backoff_seconds)
        {
            return Err(ControlError::InvalidSubscription { field: "refresh" });
        }
        if self.cache.as_ref().is_some_and(|cache| {
            cache.path.is_empty()
                || cache.path.len() > 4_096
                || cache.path.chars().any(char::is_control)
                || !(60..=2_592_000).contains(&cache.max_age_seconds)
        }) {
            return Err(ControlError::InvalidSubscription { field: "cache" });
        }
        Ok(())
    }

    pub fn runtime_config(&self) -> Result<PolicySubscriptionConfig, ControlError> {
        self.validate()?;
        let source_type = match self.source_type.as_str() {
            "static" => SubscriptionSourceType::Static,
            "clash" => SubscriptionSourceType::Clash,
            "sip008" => SubscriptionSourceType::Sip008,
            _ => {
                return Err(ControlError::InvalidSubscription {
                    field: "source.type",
                });
            }
        };
        Ok(PolicySubscriptionConfig {
            id: pathchord_policy::SubscriptionId::new(self.id.as_str()),
            enabled: self.enabled,
            source: SubscriptionSource {
                source_type,
                url: self.url.clone(),
                credentials_ref: self.credentials_ref.clone(),
            },
            refresh: PolicySubscriptionRefresh {
                interval_seconds: self.refresh.interval_seconds,
                timeout_seconds: self.refresh.timeout_seconds,
                max_attempts: self.refresh.max_attempts,
                backoff_seconds: self.refresh.backoff_seconds,
            },
            cache: self.cache.as_ref().map(|cache| PolicySubscriptionCache {
                path: cache.path.clone(),
                max_age_seconds: cache.max_age_seconds,
            }),
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubscriptionRefreshState {
    Idle,
    Queued,
    Healthy,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubscriptionState {
    pub spec: SubscriptionSpec,
    pub revision: u64,
    pub refresh_state: SubscriptionRefreshState,
    pub last_error: Option<String>,
    pub cache_metadata: BTreeMap<String, String>,
    pub last_refresh_at_ms: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IngressControlSnapshot {
    pub generation: u64,
    pub nodes: BTreeMap<NodeId, NodeAdminState>,
    pub subscriptions: BTreeMap<SubscriptionId, SubscriptionState>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RuntimeCounts {
    pub sessions: u64,
    pub ready_paths: u64,
    pub streams: u64,
    pub target_connections: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeHealthState {
    Unknown,
    Up,
    Degraded,
    Down,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NodeObservation {
    pub state: NodeHealthState,
    pub rtt_ms: Option<u32>,
    pub jitter_ms: Option<u32>,
    /// Loss in parts per million, avoiding floating-point ambiguity in the
    /// transport-neutral snapshot.
    pub loss_ppm: Option<u32>,
    pub throughput_bps: Option<u64>,
    pub effective_capacity_bps: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    Opening,
    Open,
    HalfClosed,
    Closed,
    Reset,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionObservation {
    pub connection_id: String,
    pub session_id: Option<SessionId>,
    pub stream_id: Option<StreamId>,
    pub state: ConnectionState,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    /// Already-redacted display value; raw target credentials and payloads are
    /// intentionally not representable here.
    pub target_display: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionObservation {
    pub session_id: SessionId,
    pub egress_id: String,
    pub state: SessionState,
    pub ready_paths: usize,
    pub active_streams: usize,
    pub retained_outbound_bytes: usize,
    pub bytes_sent: u64,
    pub bytes_received: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathObservation {
    pub path_id: PathId,
    pub session_id: SessionId,
    pub state: PathState,
    pub rtt_ms: u64,
    pub jitter_ms: u64,
    pub loss_ppm: u32,
    pub throughput_bps: u64,
    pub reordering_events: u64,
    pub exclusion_reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservationSnapshot {
    pub generation: u64,
    pub captured_at_ms: u64,
    pub node_count: usize,
    pub subscription_count: usize,
    pub queued_refreshes: usize,
    pub runtime: RuntimeCounts,
    pub runtime_state: RuntimeSnapshotState,
    pub active_listener_count: usize,
    pub nodes: BTreeMap<NodeId, NodeObservation>,
    pub sessions: BTreeMap<SessionId, SessionObservation>,
    pub paths: BTreeMap<PathId, PathObservation>,
    pub connections: BTreeMap<String, ConnectionObservation>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeSnapshotState {
    Fresh,
    Stale,
    Unavailable,
}

#[derive(Debug, Default)]
struct SharedObservationState {
    generation: u64,
    runtime: RuntimeCounts,
    last_updated_ms: Option<u64>,
    active_listeners: BTreeSet<ListenerId>,
    nodes: BTreeMap<NodeId, NodeObservation>,
    sessions: BTreeMap<SessionId, SessionObservation>,
    paths: BTreeMap<PathId, PathObservation>,
    connections: BTreeMap<String, ConnectionObservation>,
    connection_listeners: BTreeMap<String, ListenerId>,
}

/// Cloneable, capability-limited writer for live runtime observations.
#[derive(Debug, Clone)]
pub struct IngressObservationHandle {
    state: Arc<Mutex<SharedObservationState>>,
}

impl IngressObservationHandle {
    pub fn set_runtime_counts(&self, counts: RuntimeCounts) -> Result<(), ControlError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| ControlError::ObservationUnavailable)?;
        state.runtime = counts;
        touch_observations(&mut state);
        Ok(())
    }

    pub fn replace_session_observations(
        &self,
        sessions: impl IntoIterator<Item = SessionObservation>,
        paths: impl IntoIterator<Item = PathObservation>,
    ) -> Result<(), ControlError> {
        let sessions: BTreeMap<_, _> = sessions
            .into_iter()
            .map(|session| (session.session_id, session))
            .collect();
        let paths: BTreeMap<_, _> = paths.into_iter().map(|path| (path.path_id, path)).collect();
        if sessions.len() > MAX_CONNECTION_OBSERVATIONS || paths.len() > MAX_CONNECTION_OBSERVATIONS
        {
            return Err(ControlError::ResourceLimit {
                resource: "Session or Path observations",
            });
        }
        let mut state = self
            .state
            .lock()
            .map_err(|_| ControlError::ObservationUnavailable)?;
        state.runtime.sessions = sessions.len() as u64;
        state.runtime.ready_paths = paths
            .values()
            .filter(|path| matches!(path.state, PathState::Active | PathState::Degraded))
            .count() as u64;
        state.runtime.streams = sessions
            .values()
            .map(|session| session.active_streams as u64)
            .sum();
        state.sessions = sessions;
        state.paths = paths;
        state.last_updated_ms = Some(now_ms());
        state.generation = state.generation.saturating_add(1);
        Ok(())
    }

    pub fn set_connection_observation(
        &self,
        observation: ConnectionObservation,
    ) -> Result<(), ControlError> {
        if observation.connection_id.is_empty() {
            return Err(ControlError::InvalidIdentifier { kind: "connection" });
        }
        let mut state = self
            .state
            .lock()
            .map_err(|_| ControlError::ObservationUnavailable)?;
        if !state.connections.contains_key(&observation.connection_id)
            && state.connections.len() >= MAX_CONNECTION_OBSERVATIONS
        {
            return Err(ControlError::ResourceLimit {
                resource: "connection observations",
            });
        }
        state
            .connections
            .insert(observation.connection_id.clone(), observation);
        touch_observations(&mut state);
        refresh_target_connection_count(&mut state);
        Ok(())
    }

    pub fn remove_connection_observation(
        &self,
        connection_id: &str,
    ) -> Result<Option<ConnectionObservation>, ControlError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| ControlError::ObservationUnavailable)?;
        let removed = state.connections.remove(connection_id);
        if removed.is_some() {
            state.connection_listeners.remove(connection_id);
            touch_observations(&mut state);
            refresh_target_connection_count(&mut state);
        }
        Ok(removed)
    }

    /// Applies one redacted ListenerRuntime event to the shared snapshot.
    pub fn apply_listener_event(
        &self,
        event: crate::runtime::ListenerRuntimeEvent,
    ) -> Result<(), ControlError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| ControlError::ObservationUnavailable)?;
        let changed = match event {
            crate::runtime::ListenerRuntimeEvent::ListenerStarted { listener_id, .. } => {
                state.active_listeners.insert(listener_id)
            }
            crate::runtime::ListenerRuntimeEvent::ListenerStopped { listener_id }
            | crate::runtime::ListenerRuntimeEvent::ListenerFailed { listener_id, .. } => {
                let removed = state.active_listeners.remove(&listener_id);
                let affected: Vec<_> = state
                    .connection_listeners
                    .iter()
                    .filter(|(_, owner)| **owner == listener_id)
                    .map(|(id, _)| id.clone())
                    .collect();
                let had_affected = !affected.is_empty();
                for connection_id in affected {
                    if let Some(connection) = state.connections.get_mut(&connection_id)
                        && matches!(
                            connection.state,
                            ConnectionState::Opening
                                | ConnectionState::Open
                                | ConnectionState::HalfClosed
                        )
                    {
                        connection.state = ConnectionState::Reset;
                    }
                    state.connection_listeners.remove(&connection_id);
                }
                removed || had_affected
            }
            crate::runtime::ListenerRuntimeEvent::ConnectionAccepted {
                listener_id,
                connection_id,
                target_display,
            } => {
                if !state.connections.contains_key(&connection_id)
                    && state.connections.len() >= MAX_CONNECTION_OBSERVATIONS
                {
                    return Err(ControlError::ResourceLimit {
                        resource: "connection observations",
                    });
                }
                state
                    .connection_listeners
                    .insert(connection_id.clone(), listener_id);
                state.connections.insert(
                    connection_id.clone(),
                    ConnectionObservation {
                        connection_id,
                        session_id: None,
                        stream_id: None,
                        state: ConnectionState::Open,
                        bytes_sent: 0,
                        bytes_received: 0,
                        target_display: Some(target_display),
                    },
                );
                true
            }
            crate::runtime::ListenerRuntimeEvent::ConnectionCompleted {
                connection_id,
                stats,
                ..
            } => {
                let changed = if let Some(connection) = state.connections.get_mut(&connection_id) {
                    connection.state = ConnectionState::Closed;
                    connection.bytes_sent = stats.local_to_target_bytes;
                    connection.bytes_received = stats.target_to_local_bytes;
                    true
                } else {
                    false
                };
                state.connection_listeners.remove(&connection_id);
                changed
            }
            crate::runtime::ListenerRuntimeEvent::ConnectionFailed {
                connection_id: Some(connection_id),
                ..
            } => {
                let changed = if let Some(connection) = state.connections.get_mut(&connection_id) {
                    connection.state = ConnectionState::Reset;
                    true
                } else {
                    false
                };
                state.connection_listeners.remove(&connection_id);
                changed
            }
            crate::runtime::ListenerRuntimeEvent::ProtocolRejected { .. }
            | crate::runtime::ListenerRuntimeEvent::PolicyRejected { .. }
            | crate::runtime::ListenerRuntimeEvent::ConnectionFailed {
                connection_id: None,
                ..
            } => false,
        };
        if changed {
            touch_observations(&mut state);
            refresh_target_connection_count(&mut state);
        } else {
            state.last_updated_ms = Some(now_ms());
        }
        Ok(())
    }
}

fn refresh_target_connection_count(state: &mut SharedObservationState) {
    state.runtime.target_connections = state
        .connections
        .values()
        .filter(|connection| {
            matches!(
                connection.state,
                ConnectionState::Opening | ConnectionState::Open | ConnectionState::HalfClosed
            )
        })
        .count() as u64;
}

fn touch_observations(state: &mut SharedObservationState) {
    state.generation = state.generation.saturating_add(1);
    state.last_updated_ms = Some(now_ms());
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControlEventKind {
    NodeChanged,
    SubscriptionChanged,
    SubscriptionRefreshRequested,
    ObservationChanged,
    SystemProxyChanged,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControlEvent {
    pub id: u64,
    pub generation: u64,
    pub kind: ControlEventKind,
    pub resource_id: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MutationReceipt {
    pub generation: u64,
    pub event_id: u64,
    pub replayed: bool,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ControlError {
    #[error("{kind} identifier must not be empty")]
    InvalidIdentifier { kind: &'static str },
    #[error("label key {key} is outside the admin namespace")]
    InvalidNamespace { key: String },
    #[error("{field} exceeds its bounded length")]
    FieldTooLarge { field: &'static str },
    #[error("resource limit reached for {resource}")]
    ResourceLimit { resource: &'static str },
    #[error("node {0} was not found")]
    NodeNotFound(NodeId),
    #[error("subscription {0} was not found")]
    SubscriptionNotFound(SubscriptionId),
    #[error("subscription {0} already exists")]
    SubscriptionExists(SubscriptionId),
    #[error("subscription field {field} is invalid")]
    InvalidSubscription { field: &'static str },
    #[error("generation conflict: expected {expected}, current {current}")]
    GenerationConflict { expected: u64, current: u64 },
    #[error("request {request_id} was reused with a different command")]
    IdempotencyConflict { request_id: RequestId },
    #[error("refresh for subscription {0} is already queued")]
    RefreshAlreadyQueued(SubscriptionId),
    #[error("actor identity must not be empty")]
    EmptyActor,
    #[error("operation {operation} is unsupported on {platform:?}")]
    UnsupportedOperation {
        operation: &'static str,
        platform: SystemProxyPlatform,
    },
    #[error("listener {0:?} was not found")]
    ListenerNotFound(ListenerId),
    #[error("listener {listener_id:?} has incompatible kind {kind:?} for system proxy")]
    InvalidSystemProxyListener {
        listener_id: ListenerId,
        kind: ListenerKind,
    },
    #[error("runtime observation state is unavailable")]
    ObservationUnavailable,
    #[error("platform system-proxy operation failed: {message}")]
    PlatformProxy { message: String },
    #[error("durable Ingress control state is unavailable")]
    PersistenceUnavailable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CachedCommand {
    pub(crate) fingerprint: String,
    pub(crate) receipt: MutationReceipt,
    pub(crate) created_at_ms: u64,
}

/// Transport-neutral control service with an optional durable SQLite adapter.
#[derive(Debug)]
pub struct IngressControlService {
    snapshot: IngressControlSnapshot,
    observations: Arc<Mutex<SharedObservationState>>,
    events: VecDeque<ControlEvent>,
    refresh_queue: VecDeque<SubscriptionId>,
    request_cache: HashMap<(String, RequestId), CachedCommand>,
    next_event_id: u64,
    listeners: BTreeMap<ListenerId, ListenerDescriptor>,
    system_proxy: SystemProxyStatus,
    platform_proxy: Arc<dyn PlatformProxyAdapter>,
    store: Option<Arc<IngressControlStore>>,
}

#[derive(Clone)]
struct DurableCheckpoint {
    snapshot: IngressControlSnapshot,
    events: VecDeque<ControlEvent>,
    refresh_queue: VecDeque<SubscriptionId>,
    request_cache: HashMap<(String, RequestId), CachedCommand>,
    next_event_id: u64,
}

impl Default for IngressControlService {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for IngressControlService {
    fn drop(&mut self) {
        if self.system_proxy.enabled {
            let _ = self.platform_proxy.restore();
        }
    }
}

impl IngressControlService {
    #[must_use]
    pub fn new() -> Self {
        Self::with_platform_proxy(Arc::new(FakePlatformProxyAdapter::new()))
    }

    #[must_use]
    pub fn with_platform_proxy(platform_proxy: Arc<dyn PlatformProxyAdapter>) -> Self {
        let system_proxy = match platform_proxy.recover() {
            Ok(effect) => SystemProxyStatus {
                restoration_state: if effect.restored {
                    SystemProxyRestorationState::Restored
                } else {
                    SystemProxyRestorationState::NotRequired
                },
                ..SystemProxyStatus::default()
            },
            Err(error) => SystemProxyStatus {
                state: SystemProxyState::Failed,
                platform_effect: SystemProxyPlatformEffect::Failed,
                restoration_state: SystemProxyRestorationState::Failed,
                error: Some(error.to_string()),
                ..SystemProxyStatus::default()
            },
        };
        Self {
            snapshot: IngressControlSnapshot {
                generation: 0,
                nodes: BTreeMap::new(),
                subscriptions: BTreeMap::new(),
            },
            observations: Arc::new(Mutex::new(SharedObservationState::default())),
            events: VecDeque::new(),
            refresh_queue: VecDeque::new(),
            request_cache: HashMap::new(),
            next_event_id: 0,
            listeners: BTreeMap::new(),
            system_proxy,
            platform_proxy,
            store: None,
        }
    }

    pub fn open(store: Arc<IngressControlStore>) -> Result<Self, ControlError> {
        Self::open_with_platform_proxy(store, Arc::new(FakePlatformProxyAdapter::new()))
    }

    pub fn open_with_platform_proxy(
        store: Arc<IngressControlStore>,
        platform_proxy: Arc<dyn PlatformProxyAdapter>,
    ) -> Result<Self, ControlError> {
        let durable = store
            .load()
            .map_err(|_| ControlError::PersistenceUnavailable)?;
        let mut service = Self::with_platform_proxy(platform_proxy);
        service.snapshot = durable.snapshot;
        service.events = durable.events;
        service.refresh_queue = durable.refresh_queue;
        service.request_cache = durable.request_cache;
        service.next_event_id = durable.next_event_id;
        service.store = Some(store);
        Ok(service)
    }

    /// Registers or replaces a Listener descriptor in the control-plane
    /// inventory. Runtime adapters call this when their declarative snapshot is
    /// published; the descriptor contains no platform secret or socket state.
    pub fn register_listener(&mut self, descriptor: ListenerDescriptor) {
        self.listeners.insert(descriptor.id.clone(), descriptor);
    }

    pub fn reconcile_declarative_resources(
        &mut self,
        generation: u64,
        nodes: impl IntoIterator<Item = NodeId>,
        subscriptions: impl IntoIterator<Item = SubscriptionSpec>,
    ) -> Result<(), ControlError> {
        let checkpoint = self.durable_checkpoint();
        for node in nodes {
            if !self.snapshot.nodes.contains_key(&node)
                && self.snapshot.nodes.len() >= MAX_NODE_COUNT
            {
                self.restore_checkpoint(checkpoint);
                return Err(ControlError::ResourceLimit { resource: "nodes" });
            }
            self.snapshot.nodes.entry(node).or_default();
        }
        for spec in subscriptions {
            spec.validate()?;
            if !self.snapshot.subscriptions.contains_key(&spec.id)
                && self.snapshot.subscriptions.len() >= MAX_SUBSCRIPTION_COUNT
            {
                self.restore_checkpoint(checkpoint);
                return Err(ControlError::ResourceLimit {
                    resource: "subscriptions",
                });
            }
            match self.snapshot.subscriptions.get_mut(&spec.id) {
                Some(existing) if existing.spec != spec => {
                    let was_enabled = existing.spec.enabled;
                    existing.spec = spec;
                    existing.refresh_state = SubscriptionRefreshState::Idle;
                    existing.last_error = None;
                    if was_enabled && !existing.spec.enabled {
                        self.refresh_queue
                            .retain(|queued| queued != &existing.spec.id);
                    }
                }
                Some(_) => {}
                None => {
                    self.snapshot.subscriptions.insert(
                        spec.id.clone(),
                        SubscriptionState {
                            spec,
                            revision: 0,
                            refresh_state: SubscriptionRefreshState::Idle,
                            last_error: None,
                            cache_metadata: BTreeMap::new(),
                            last_refresh_at_ms: None,
                        },
                    );
                }
            }
        }
        self.snapshot.generation = self.snapshot.generation.max(generation);
        if let Err(error) = self.persist(None) {
            self.restore_checkpoint(checkpoint);
            return Err(error);
        }
        Ok(())
    }

    pub fn record_authentication_failure(&self, source: &str) -> Result<(), ControlError> {
        if source.is_empty() || source.len() > 256 {
            return Err(ControlError::FieldTooLarge {
                field: "authentication source",
            });
        }
        self.persist(Some(AuditRecord::new(
            "unauthenticated",
            None,
            "authentication.failure",
            source.to_owned(),
            self.snapshot.generation,
        )))
    }

    #[must_use]
    pub fn listeners(&self) -> BTreeMap<ListenerId, ListenerDescriptor> {
        self.listeners.clone()
    }

    #[must_use]
    pub fn system_proxy_status(&self) -> SystemProxyStatus {
        self.system_proxy.clone()
    }

    /// Enables Windows system-proxy integration for an HTTP/SOCKS Listener.
    pub fn enable_system_proxy(
        &mut self,
        actor: &str,
        request_id: RequestId,
        platform: SystemProxyPlatform,
        listener_id: ListenerId,
    ) -> Result<SystemProxyMutation, ControlError> {
        self.check_actor(actor)?;
        if platform != SystemProxyPlatform::Windows {
            return Err(ControlError::UnsupportedOperation {
                operation: "system_proxy.enable",
                platform,
            });
        }
        let descriptor = self
            .listeners
            .get(&listener_id)
            .ok_or_else(|| ControlError::ListenerNotFound(listener_id.clone()))?;
        let proxy_kind = match descriptor.kind {
            ListenerKind::Http | ListenerKind::Mixed => PlatformProxyKind::Http,
            ListenerKind::Socks5 => PlatformProxyKind::Socks5,
            kind => {
                return Err(ControlError::InvalidSystemProxyListener { listener_id, kind });
            }
        };
        let request = PlatformProxyRequest {
            listener_id: listener_id.clone(),
            kind: proxy_kind,
            endpoint: descriptor
                .bind
                .ok_or_else(|| ControlError::InvalidSystemProxyListener {
                    listener_id: listener_id.clone(),
                    kind: descriptor.kind,
                })?,
        };
        let fingerprint = format!("system-proxy-enable:{listener_id:?}:{platform:?}");
        if self.cached(actor, request_id, &fingerprint)?.is_some()
            || (self.system_proxy.enabled
                && self.system_proxy.listener_id.as_ref() == Some(&listener_id))
        {
            return Ok(self.system_proxy_mutation(true));
        }
        self.ensure_cache_capacity(actor, request_id)?;
        self.system_proxy = SystemProxyStatus {
            state: SystemProxyState::Applying,
            enabled: false,
            listener_id: Some(listener_id.clone()),
            platform_effect: SystemProxyPlatformEffect::Disabled,
            environment_applied: false,
            operating_system_applied: false,
            restoration_state: SystemProxyRestorationState::Pending,
            error: None,
        };
        let effect = match self.platform_proxy.apply(&request) {
            Ok(effect) => effect,
            Err(error) => {
                self.system_proxy = SystemProxyStatus {
                    state: SystemProxyState::Failed,
                    enabled: false,
                    listener_id: Some(listener_id.clone()),
                    platform_effect: SystemProxyPlatformEffect::Failed,
                    environment_applied: false,
                    operating_system_applied: false,
                    restoration_state: SystemProxyRestorationState::Failed,
                    error: Some(error.to_string()),
                };
                self.increment_observation_generation()?;
                self.emit(
                    ControlEventKind::SystemProxyChanged,
                    listener_id.as_str().to_owned(),
                );
                return Err(ControlError::PlatformProxy {
                    message: error.to_string(),
                });
            }
        };
        self.system_proxy = SystemProxyStatus {
            state: SystemProxyState::Applied,
            enabled: true,
            listener_id: Some(listener_id.clone()),
            platform_effect: SystemProxyPlatformEffect::Applied,
            environment_applied: effect.environment_applied,
            operating_system_applied: effect.operating_system_applied,
            restoration_state: SystemProxyRestorationState::Pending,
            error: None,
        };
        self.increment_observation_generation()?;
        let receipt = self.emit(
            ControlEventKind::SystemProxyChanged,
            listener_id.as_str().to_owned(),
        );
        self.cache(actor, request_id, fingerprint, receipt)?;
        Ok(SystemProxyMutation {
            generation: receipt.generation,
            event_id: receipt.event_id,
            replayed: false,
            status: self.system_proxy.clone(),
        })
    }

    pub fn disable_system_proxy(
        &mut self,
        actor: &str,
        request_id: RequestId,
        platform: SystemProxyPlatform,
    ) -> Result<SystemProxyMutation, ControlError> {
        self.check_actor(actor)?;
        if platform != SystemProxyPlatform::Windows {
            return Err(ControlError::UnsupportedOperation {
                operation: "system_proxy.disable",
                platform,
            });
        }
        let fingerprint = format!("system-proxy-disable:{platform:?}");
        if self.cached(actor, request_id, &fingerprint)?.is_some()
            || self.system_proxy.state == SystemProxyState::Disabled
        {
            return Ok(self.system_proxy_mutation(true));
        }
        self.ensure_cache_capacity(actor, request_id)?;
        let listener_id = self.system_proxy.listener_id.clone();
        self.system_proxy.state = SystemProxyState::Restoring;
        let effect = match self.platform_proxy.restore() {
            Ok(effect) => effect,
            Err(error) => {
                self.system_proxy.state = SystemProxyState::Failed;
                self.system_proxy.platform_effect = SystemProxyPlatformEffect::Failed;
                self.system_proxy.restoration_state = SystemProxyRestorationState::Failed;
                self.system_proxy.error = Some(error.to_string());
                self.increment_observation_generation()?;
                self.emit(
                    ControlEventKind::SystemProxyChanged,
                    listener_id
                        .as_ref()
                        .map_or_else(|| "system-proxy".to_owned(), |id| id.as_str().to_owned()),
                );
                return Err(ControlError::PlatformProxy {
                    message: error.to_string(),
                });
            }
        };
        self.system_proxy = SystemProxyStatus {
            state: SystemProxyState::Disabled,
            enabled: false,
            listener_id: None,
            platform_effect: SystemProxyPlatformEffect::Disabled,
            environment_applied: effect.environment_applied,
            operating_system_applied: effect.operating_system_applied,
            restoration_state: if effect.restored {
                SystemProxyRestorationState::Restored
            } else {
                SystemProxyRestorationState::NotRequired
            },
            error: None,
        };
        self.increment_observation_generation()?;
        let receipt = self.emit(
            ControlEventKind::SystemProxyChanged,
            listener_id.map_or_else(|| "system-proxy".to_owned(), |id| id.as_str().to_owned()),
        );
        self.cache(actor, request_id, fingerprint, receipt)?;
        Ok(SystemProxyMutation {
            generation: receipt.generation,
            event_id: receipt.event_id,
            replayed: false,
            status: self.system_proxy.clone(),
        })
    }

    fn system_proxy_mutation(&self, replayed: bool) -> SystemProxyMutation {
        SystemProxyMutation {
            generation: self.snapshot.generation,
            event_id: self.next_event_id,
            replayed,
            status: self.system_proxy.clone(),
        }
    }

    #[must_use]
    pub fn snapshot(&self) -> IngressControlSnapshot {
        self.snapshot.clone()
    }

    #[must_use]
    pub fn observation_handle(&self) -> IngressObservationHandle {
        IngressObservationHandle {
            state: Arc::clone(&self.observations),
        }
    }

    #[must_use]
    pub fn observation_snapshot(&self) -> ObservationSnapshot {
        let observations = self
            .observations
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let captured_at_ms = now_ms();
        let runtime_state = match observations.last_updated_ms {
            None => RuntimeSnapshotState::Unavailable,
            Some(updated)
                if captured_at_ms.saturating_sub(updated) > DEFAULT_OBSERVATION_STALE_AFTER_MS =>
            {
                RuntimeSnapshotState::Stale
            }
            Some(_) => RuntimeSnapshotState::Fresh,
        };
        ObservationSnapshot {
            generation: observations.generation,
            captured_at_ms,
            node_count: self.snapshot.nodes.len(),
            subscription_count: self.snapshot.subscriptions.len(),
            queued_refreshes: self.refresh_queue.len(),
            runtime: observations.runtime,
            runtime_state,
            active_listener_count: observations.active_listeners.len(),
            nodes: observations.nodes.clone(),
            sessions: observations.sessions.clone(),
            paths: observations.paths.clone(),
            connections: observations.connections.clone(),
        }
    }

    pub fn set_node_observation(
        &mut self,
        node_id: NodeId,
        observation: NodeObservation,
    ) -> Result<MutationReceipt, ControlError> {
        if !self.snapshot.nodes.contains_key(&node_id) {
            return Err(ControlError::NodeNotFound(node_id));
        }
        let mut observations = self
            .observations
            .lock()
            .map_err(|_| ControlError::ObservationUnavailable)?;
        observations.nodes.insert(node_id.clone(), observation);
        touch_observations(&mut observations);
        drop(observations);
        Ok(self.emit(ControlEventKind::ObservationChanged, node_id.0))
    }

    pub fn set_connection_observation(
        &mut self,
        observation: ConnectionObservation,
    ) -> Result<MutationReceipt, ControlError> {
        if observation.connection_id.is_empty() {
            return Err(ControlError::InvalidIdentifier { kind: "connection" });
        }
        let mut observations = self
            .observations
            .lock()
            .map_err(|_| ControlError::ObservationUnavailable)?;
        if !observations
            .connections
            .contains_key(&observation.connection_id)
            && observations.connections.len() >= MAX_CONNECTION_OBSERVATIONS
        {
            return Err(ControlError::ResourceLimit {
                resource: "connection observations",
            });
        }
        let id = observation.connection_id.clone();
        observations.connections.insert(id.clone(), observation);
        touch_observations(&mut observations);
        refresh_target_connection_count(&mut observations);
        drop(observations);
        Ok(self.emit(ControlEventKind::ObservationChanged, id))
    }

    pub fn remove_connection_observation(
        &mut self,
        connection_id: &str,
    ) -> Option<ConnectionObservation> {
        let mut observations = self
            .observations
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let removed = observations.connections.remove(connection_id);
        if removed.is_some() {
            observations.connection_listeners.remove(connection_id);
            touch_observations(&mut observations);
            refresh_target_connection_count(&mut observations);
            drop(observations);
            self.emit(
                ControlEventKind::ObservationChanged,
                connection_id.to_owned(),
            );
        } else {
            drop(observations);
        }
        removed
    }

    pub fn set_runtime_counts(&mut self, counts: RuntimeCounts) -> MutationReceipt {
        let mut observations = self
            .observations
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        observations.runtime = counts;
        touch_observations(&mut observations);
        drop(observations);
        self.emit(ControlEventKind::ObservationChanged, "runtime".to_owned())
    }

    pub fn events_since(&self, last_event_id: Option<u64>) -> Vec<ControlEvent> {
        self.events
            .iter()
            .filter(|event| last_event_id.is_none_or(|id| event.id > id))
            .cloned()
            .collect()
    }

    pub fn patch_node(
        &mut self,
        actor: &str,
        request_id: RequestId,
        node_id: NodeId,
        expected_generation: u64,
        patch: NodeAdminPatch,
    ) -> Result<MutationReceipt, ControlError> {
        patch.validate()?;
        let fingerprint = format!("patch-node:{node_id:?}:{patch:?}:{expected_generation}");
        if let Some(receipt) = self.cached(actor, request_id, &fingerprint)? {
            return Ok(receipt);
        }
        self.check_actor(actor)?;
        self.ensure_cache_capacity(actor, request_id)?;
        self.check_generation(expected_generation)?;
        let checkpoint = self.durable_checkpoint();
        let resource_id = node_id.0.clone();
        let node = self
            .snapshot
            .nodes
            .get_mut(&node_id)
            .ok_or_else(|| ControlError::NodeNotFound(node_id.clone()))?;
        for (key, value) in patch.set_labels {
            node.labels.insert(key, value);
        }
        for key in patch.remove_labels {
            node.labels.remove(&key);
        }
        node.tags.extend(patch.add_tags);
        for tag in patch.remove_tags {
            node.tags.remove(&tag);
        }
        if node.labels.len() > 256 || node.tags.len() > 256 {
            self.restore_checkpoint(checkpoint);
            return Err(ControlError::ResourceLimit {
                resource: "node metadata",
            });
        }
        self.snapshot.generation += 1;
        let receipt = self.emit(ControlEventKind::NodeChanged, node_id.0.clone());
        self.cache(actor, request_id, fingerprint.clone(), receipt)?;
        self.persist_or_restore(
            checkpoint,
            AuditRecord::new(
                actor,
                Some(request_id),
                "node.patch",
                resource_id,
                receipt.generation,
            ),
        )?;
        Ok(receipt)
    }

    pub fn add_node(&mut self, node_id: NodeId) -> Result<(), ControlError> {
        if self.snapshot.nodes.len() >= MAX_NODE_COUNT {
            return Err(ControlError::ResourceLimit { resource: "nodes" });
        }
        if self.snapshot.nodes.contains_key(&node_id) {
            return Ok(());
        }
        let checkpoint = self.durable_checkpoint();
        let resource_id = node_id.0.clone();
        self.snapshot
            .nodes
            .insert(node_id, NodeAdminState::default());
        if let Err(error) = self.persist(Some(AuditRecord::new(
            "runtime",
            None,
            "node.add",
            resource_id,
            self.snapshot.generation,
        ))) {
            self.restore_checkpoint(checkpoint);
            return Err(error);
        }
        Ok(())
    }

    pub fn remove_node(&mut self, node_id: &NodeId) -> Result<(), ControlError> {
        if !self.snapshot.nodes.contains_key(node_id) {
            return Ok(());
        }
        let checkpoint = self.durable_checkpoint();
        self.snapshot.nodes.remove(node_id);
        self.snapshot.generation = self.snapshot.generation.saturating_add(1);
        if let Ok(mut observations) = self.observations.lock() {
            observations.nodes.remove(node_id);
            touch_observations(&mut observations);
        }
        if let Err(error) = self.persist(Some(AuditRecord::new(
            "runtime",
            None,
            "node.remove",
            node_id.0.clone(),
            self.snapshot.generation,
        ))) {
            self.restore_checkpoint(checkpoint);
            return Err(error);
        }
        Ok(())
    }

    pub fn add_subscription(
        &mut self,
        actor: &str,
        request_id: RequestId,
        expected_generation: u64,
        spec: SubscriptionSpec,
    ) -> Result<MutationReceipt, ControlError> {
        spec.validate()?;
        let fingerprint = format!("add-subscription:{spec:?}:{expected_generation}");
        if let Some(receipt) = self.cached(actor, request_id, &fingerprint)? {
            return Ok(receipt);
        }
        self.check_actor(actor)?;
        self.ensure_cache_capacity(actor, request_id)?;
        self.check_generation(expected_generation)?;
        if self.snapshot.subscriptions.contains_key(&spec.id) {
            return Err(ControlError::SubscriptionExists(spec.id));
        }
        if self.snapshot.subscriptions.len() >= MAX_SUBSCRIPTION_COUNT {
            return Err(ControlError::ResourceLimit {
                resource: "subscriptions",
            });
        }
        let checkpoint = self.durable_checkpoint();
        let id = spec.id.clone();
        self.snapshot.subscriptions.insert(
            id.clone(),
            SubscriptionState {
                spec,
                revision: 0,
                refresh_state: SubscriptionRefreshState::Idle,
                last_error: None,
                cache_metadata: BTreeMap::new(),
                last_refresh_at_ms: None,
            },
        );
        self.snapshot.generation += 1;
        let receipt = self.emit(ControlEventKind::SubscriptionChanged, id.0.clone());
        self.cache(actor, request_id, fingerprint.clone(), receipt)?;
        self.persist_or_restore(
            checkpoint,
            AuditRecord::new(
                actor,
                Some(request_id),
                "subscription.create",
                id.0,
                receipt.generation,
            ),
        )?;
        Ok(receipt)
    }

    pub fn delete_subscription(
        &mut self,
        actor: &str,
        request_id: RequestId,
        expected_generation: u64,
        id: &SubscriptionId,
    ) -> Result<MutationReceipt, ControlError> {
        let fingerprint = format!("delete-subscription:{id:?}:{expected_generation}");
        if let Some(receipt) = self.cached(actor, request_id, &fingerprint)? {
            return Ok(receipt);
        }
        self.check_actor(actor)?;
        self.ensure_cache_capacity(actor, request_id)?;
        self.check_generation(expected_generation)?;
        let checkpoint = self.durable_checkpoint();
        self.snapshot
            .subscriptions
            .remove(id)
            .ok_or_else(|| ControlError::SubscriptionNotFound(id.clone()))?;
        self.refresh_queue.retain(|queued| queued != id);
        self.snapshot.generation += 1;
        let receipt = self.emit(ControlEventKind::SubscriptionChanged, id.0.clone());
        self.cache(actor, request_id, fingerprint.clone(), receipt)?;
        self.persist_or_restore(
            checkpoint,
            AuditRecord::new(
                actor,
                Some(request_id),
                "subscription.delete",
                id.0.clone(),
                receipt.generation,
            ),
        )?;
        Ok(receipt)
    }

    pub fn set_subscription_enabled(
        &mut self,
        actor: &str,
        request_id: RequestId,
        expected_generation: u64,
        id: &SubscriptionId,
        enabled: bool,
    ) -> Result<MutationReceipt, ControlError> {
        let fingerprint =
            format!("set-subscription-enabled:{id:?}:{enabled}:{expected_generation}");
        if let Some(receipt) = self.cached(actor, request_id, &fingerprint)? {
            return Ok(receipt);
        }
        self.check_actor(actor)?;
        self.ensure_cache_capacity(actor, request_id)?;
        self.check_generation(expected_generation)?;
        let checkpoint = self.durable_checkpoint();
        let subscription = self
            .snapshot
            .subscriptions
            .get_mut(id)
            .ok_or_else(|| ControlError::SubscriptionNotFound(id.clone()))?;
        subscription.spec.enabled = enabled;
        if !enabled {
            self.refresh_queue.retain(|queued| queued != id);
            subscription.refresh_state = SubscriptionRefreshState::Idle;
        }
        self.snapshot.generation += 1;
        let receipt = self.emit(ControlEventKind::SubscriptionChanged, id.0.clone());
        self.cache(actor, request_id, fingerprint, receipt)?;
        self.persist_or_restore(
            checkpoint,
            AuditRecord::new(
                actor,
                Some(request_id),
                if enabled {
                    "subscription.enable"
                } else {
                    "subscription.disable"
                },
                id.0.clone(),
                receipt.generation,
            ),
        )?;
        Ok(receipt)
    }

    pub fn request_subscription_refresh(
        &mut self,
        actor: &str,
        request_id: RequestId,
        id: &SubscriptionId,
    ) -> Result<MutationReceipt, ControlError> {
        let fingerprint = format!("refresh-subscription:{id:?}");
        if let Some(receipt) = self.cached(actor, request_id, &fingerprint)? {
            return Ok(receipt);
        }
        self.check_actor(actor)?;
        self.ensure_cache_capacity(actor, request_id)?;
        let checkpoint = self.durable_checkpoint();
        let subscription = self
            .snapshot
            .subscriptions
            .get_mut(id)
            .ok_or_else(|| ControlError::SubscriptionNotFound(id.clone()))?;
        if self.refresh_queue.iter().any(|queued| queued == id) {
            return Err(ControlError::RefreshAlreadyQueued(id.clone()));
        }
        if self.refresh_queue.len() >= MAX_REFRESH_QUEUE_COUNT {
            return Err(ControlError::ResourceLimit {
                resource: "refresh queue",
            });
        }
        subscription.refresh_state = SubscriptionRefreshState::Queued;
        self.refresh_queue.push_back(id.clone());
        let receipt = self.emit(ControlEventKind::SubscriptionRefreshRequested, id.0.clone());
        self.cache(actor, request_id, fingerprint.clone(), receipt)?;
        self.persist_or_restore(
            checkpoint,
            AuditRecord::new(
                actor,
                Some(request_id),
                "subscription.refresh",
                id.0.clone(),
                receipt.generation,
            ),
        )?;
        Ok(receipt)
    }

    #[must_use]
    pub fn next_queued_subscription_refresh(&self) -> Option<SubscriptionId> {
        self.refresh_queue.front().cloned()
    }

    /// Completes one queued refresh. A failed refresh leaves the existing
    /// subscription revision and imported node snapshot untouched.
    pub fn complete_subscription_refresh(
        &mut self,
        id: &SubscriptionId,
        success: bool,
        error: Option<String>,
    ) -> Result<MutationReceipt, ControlError> {
        let checkpoint = self.durable_checkpoint();
        let subscription = self
            .snapshot
            .subscriptions
            .get_mut(id)
            .ok_or_else(|| ControlError::SubscriptionNotFound(id.clone()))?;
        self.refresh_queue.retain(|queued| queued != id);
        if success {
            subscription.revision += 1;
            subscription.refresh_state = SubscriptionRefreshState::Healthy;
            subscription.last_error = None;
        } else {
            subscription.refresh_state = SubscriptionRefreshState::Failed;
            subscription.last_error = error.map(|value| value.chars().take(256).collect());
        }
        subscription.last_refresh_at_ms = Some(now_ms());
        self.snapshot.generation += 1;
        let receipt = self.emit(ControlEventKind::SubscriptionChanged, id.0.clone());
        self.persist_or_restore(
            checkpoint,
            AuditRecord::new(
                "subscription-worker",
                None,
                "subscription.refresh.complete",
                id.0.clone(),
                receipt.generation,
            ),
        )?;
        Ok(receipt)
    }

    pub fn set_subscription_cache_metadata(
        &mut self,
        id: &SubscriptionId,
        metadata: BTreeMap<String, String>,
    ) -> Result<MutationReceipt, ControlError> {
        if metadata.len() > 32
            || metadata
                .iter()
                .any(|(key, value)| key.is_empty() || key.len() > 64 || value.len() > 1024)
        {
            return Err(ControlError::FieldTooLarge {
                field: "cache_metadata",
            });
        }
        let checkpoint = self.durable_checkpoint();
        let subscription = self
            .snapshot
            .subscriptions
            .get_mut(id)
            .ok_or_else(|| ControlError::SubscriptionNotFound(id.clone()))?;
        subscription.cache_metadata = metadata;
        self.snapshot.generation += 1;
        let receipt = self.emit(ControlEventKind::SubscriptionChanged, id.0.clone());
        self.persist_or_restore(
            checkpoint,
            AuditRecord::new(
                "subscription-worker",
                None,
                "subscription.cache_metadata",
                id.0.clone(),
                receipt.generation,
            ),
        )?;
        Ok(receipt)
    }

    fn durable_checkpoint(&self) -> DurableCheckpoint {
        DurableCheckpoint {
            snapshot: self.snapshot.clone(),
            events: self.events.clone(),
            refresh_queue: self.refresh_queue.clone(),
            request_cache: self.request_cache.clone(),
            next_event_id: self.next_event_id,
        }
    }

    fn restore_checkpoint(&mut self, checkpoint: DurableCheckpoint) {
        self.snapshot = checkpoint.snapshot;
        self.events = checkpoint.events;
        self.refresh_queue = checkpoint.refresh_queue;
        self.request_cache = checkpoint.request_cache;
        self.next_event_id = checkpoint.next_event_id;
    }

    fn persist(&self, audit: Option<AuditRecord>) -> Result<(), ControlError> {
        let Some(store) = &self.store else {
            return Ok(());
        };
        store
            .commit(StoreCommit {
                snapshot: &self.snapshot,
                events: &self.events,
                refresh_queue: &self.refresh_queue,
                request_cache: &self.request_cache,
                next_event_id: self.next_event_id,
                audit,
            })
            .map_err(|_| ControlError::PersistenceUnavailable)
    }

    fn persist_or_restore(
        &mut self,
        checkpoint: DurableCheckpoint,
        audit: AuditRecord,
    ) -> Result<(), ControlError> {
        if let Err(error) = self.persist(Some(audit)) {
            self.restore_checkpoint(checkpoint);
            return Err(error);
        }
        Ok(())
    }

    fn check_actor(&self, actor: &str) -> Result<(), ControlError> {
        if actor.is_empty() || actor.len() > 128 {
            Err(ControlError::EmptyActor)
        } else {
            Ok(())
        }
    }

    fn check_generation(&self, expected: u64) -> Result<(), ControlError> {
        if expected == self.snapshot.generation {
            Ok(())
        } else {
            Err(ControlError::GenerationConflict {
                expected,
                current: self.snapshot.generation,
            })
        }
    }

    fn cached(
        &self,
        actor: &str,
        request_id: RequestId,
        fingerprint: &str,
    ) -> Result<Option<MutationReceipt>, ControlError> {
        let Some(cached) = self.request_cache.get(&(actor.to_owned(), request_id)) else {
            return Ok(None);
        };
        if now_ms().saturating_sub(cached.created_at_ms) > REQUEST_CACHE_TTL_MS {
            return Ok(None);
        }
        if cached.fingerprint == fingerprint {
            Ok(Some(MutationReceipt {
                replayed: true,
                ..cached.receipt
            }))
        } else {
            Err(ControlError::IdempotencyConflict { request_id })
        }
    }

    fn cache(
        &mut self,
        actor: &str,
        request_id: RequestId,
        fingerprint: String,
        receipt: MutationReceipt,
    ) -> Result<(), ControlError> {
        let cutoff = now_ms().saturating_sub(REQUEST_CACHE_TTL_MS);
        self.request_cache
            .retain(|_, cached| cached.created_at_ms >= cutoff);
        self.request_cache.insert(
            (actor.to_owned(), request_id),
            CachedCommand {
                fingerprint,
                receipt,
                created_at_ms: now_ms(),
            },
        );
        Ok(())
    }

    fn ensure_cache_capacity(
        &self,
        actor: &str,
        request_id: RequestId,
    ) -> Result<(), ControlError> {
        let cutoff = now_ms().saturating_sub(REQUEST_CACHE_TTL_MS);
        let live_count = self
            .request_cache
            .values()
            .filter(|cached| cached.created_at_ms >= cutoff)
            .count();
        if live_count >= MAX_REQUEST_CACHE_COUNT
            && !self
                .request_cache
                .contains_key(&(actor.to_owned(), request_id))
        {
            return Err(ControlError::ResourceLimit {
                resource: "request cache",
            });
        }
        Ok(())
    }

    fn increment_observation_generation(&self) -> Result<(), ControlError> {
        let mut observations = self
            .observations
            .lock()
            .map_err(|_| ControlError::ObservationUnavailable)?;
        observations.generation = observations.generation.saturating_add(1);
        Ok(())
    }

    fn emit(&mut self, kind: ControlEventKind, resource_id: String) -> MutationReceipt {
        self.next_event_id += 1;
        let event = ControlEvent {
            id: self.next_event_id,
            generation: self.snapshot.generation,
            kind,
            resource_id,
        };
        self.events.push_back(event.clone());
        while self.events.len() > MAX_EVENT_COUNT {
            self.events.pop_front();
        }
        MutationReceipt {
            generation: event.generation,
            event_id: event.id,
            replayed: false,
        }
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| {
            duration.as_millis().min(u128::from(u64::MAX)) as u64
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn service_with_node() -> (IngressControlService, NodeId) {
        let mut service = IngressControlService::new();
        let node = NodeId::new("node-1").unwrap();
        service.add_node(node.clone()).unwrap();
        (service, node)
    }

    #[test]
    fn patches_admin_metadata_with_generation_and_idempotency() {
        let (mut service, node) = service_with_node();
        let patch = NodeAdminPatch {
            set_labels: BTreeMap::from([(String::from("admin.region"), String::from("jp"))]),
            add_tags: BTreeSet::from([String::from("gaming")]),
            ..NodeAdminPatch::default()
        };
        let first = service
            .patch_node(
                "operator",
                RequestId::new(1),
                node.clone(),
                0,
                patch.clone(),
            )
            .unwrap();
        let replay = service
            .patch_node("operator", RequestId::new(1), node.clone(), 0, patch)
            .unwrap();
        assert!(!first.replayed);
        assert!(replay.replayed);
        assert_eq!(service.snapshot().generation, 1);
        assert_eq!(
            service.snapshot().nodes[&node].tags,
            BTreeSet::from([String::from("gaming")])
        );
    }

    #[test]
    fn rejects_generation_conflicts_and_non_admin_namespaces() {
        let (mut service, node) = service_with_node();
        let patch = NodeAdminPatch {
            set_labels: BTreeMap::from([(String::from("observed.rtt_ms"), String::from("3"))]),
            ..NodeAdminPatch::default()
        };
        assert!(matches!(
            service.patch_node("operator", RequestId::new(1), node.clone(), 0, patch),
            Err(ControlError::InvalidNamespace { .. })
        ));
        let good = NodeAdminPatch {
            set_labels: BTreeMap::from([(String::from("admin.region"), String::from("jp"))]),
            ..NodeAdminPatch::default()
        };
        service
            .patch_node("operator", RequestId::new(2), node, 0, good)
            .unwrap();
        assert!(matches!(
            service.patch_node(
                "operator",
                RequestId::new(3),
                NodeId::new("node-1").unwrap(),
                0,
                NodeAdminPatch::default()
            ),
            Err(ControlError::GenerationConflict { .. })
        ));
    }

    #[test]
    fn subscription_refresh_failure_retains_revision_and_snapshot() {
        let mut service = IngressControlService::new();
        let id = SubscriptionId::new("source-a").unwrap();
        service
            .add_subscription(
                "operator",
                RequestId::new(1),
                0,
                SubscriptionSpec {
                    id: id.clone(),
                    source_type: "clash".into(),
                    display_name: "Provider A".into(),
                    enabled: true,
                    url: "https://provider.example/subscription".into(),
                    credentials_ref: Some("provider-a-token".into()),
                    refresh: SubscriptionRefreshSpec::default(),
                    cache: Some(SubscriptionCacheSpec {
                        path: "provider-a.snapshot".into(),
                        max_age_seconds: 86_400,
                    }),
                },
            )
            .unwrap();
        service
            .request_subscription_refresh("operator", RequestId::new(2), &id)
            .unwrap();
        service
            .complete_subscription_refresh(&id, false, Some("timeout".into()))
            .unwrap();
        let state = &service.snapshot().subscriptions[&id];
        assert_eq!(state.revision, 0);
        assert_eq!(state.refresh_state, SubscriptionRefreshState::Failed);
        assert_eq!(state.last_error.as_deref(), Some("timeout"));
    }

    #[test]
    fn subscription_runtime_contract_preserves_opaque_reference_and_rejects_bad_bounds() {
        let spec = SubscriptionSpec {
            id: SubscriptionId::new("provider-a").unwrap(),
            source_type: "clash".into(),
            display_name: "Provider A".into(),
            enabled: true,
            url: "https://provider.example/subscription".into(),
            credentials_ref: Some("provider-a-token".into()),
            refresh: SubscriptionRefreshSpec {
                interval_seconds: 900,
                timeout_seconds: 15,
                max_attempts: 4,
                backoff_seconds: 7,
            },
            cache: Some(SubscriptionCacheSpec {
                path: "provider-a.snapshot".into(),
                max_age_seconds: 86_400,
            }),
        };
        let runtime = spec.runtime_config().expect("runtime subscription");
        assert_eq!(runtime.source.url, spec.url);
        assert_eq!(runtime.source.credentials_ref, spec.credentials_ref);
        assert_eq!(runtime.refresh.interval_seconds, 900);
        assert_eq!(runtime.cache.expect("cache").path, "provider-a.snapshot");

        let mut invalid = spec;
        invalid.refresh.interval_seconds = 59;
        assert!(matches!(
            invalid.runtime_config(),
            Err(ControlError::InvalidSubscription { field: "refresh" })
        ));
    }

    #[test]
    fn observations_and_events_are_structured_and_bounded() {
        let mut service = IngressControlService::new();
        let node = NodeId::new("node-1").unwrap();
        service.add_node(node.clone()).unwrap();
        service
            .set_node_observation(
                node,
                NodeObservation {
                    state: NodeHealthState::Up,
                    rtt_ms: Some(12),
                    jitter_ms: Some(2),
                    loss_ppm: Some(100),
                    throughput_bps: Some(1_000_000),
                    effective_capacity_bps: Some(2_000_000),
                },
            )
            .unwrap();
        service
            .set_connection_observation(ConnectionObservation {
                connection_id: "connection-1".into(),
                session_id: Some(SessionId::new(1)),
                stream_id: Some(StreamId::try_from(1).unwrap()),
                state: ConnectionState::Open,
                bytes_sent: 10,
                bytes_received: 20,
                target_display: Some("example.test:443".into()),
            })
            .unwrap();
        service.set_runtime_counts(RuntimeCounts {
            sessions: 2,
            ready_paths: 3,
            streams: 4,
            target_connections: 5,
        });
        let snapshot = service.observation_snapshot();
        assert_eq!(service.snapshot().generation, 0);
        assert_eq!(snapshot.generation, 3);
        assert_eq!(snapshot.runtime.streams, 4);
        assert_eq!(snapshot.nodes.len(), 1);
        assert_eq!(snapshot.connections.len(), 1);
        assert_eq!(service.events_since(None).len(), 3);
        assert_eq!(service.events_since(Some(1)).len(), 2);
    }

    #[test]
    fn path_quality_observations_are_retained_in_the_control_snapshot() {
        let service = IngressControlService::new();
        let handle = service.observation_handle();
        let session_id = SessionId::new(41);
        let path_id = PathId::new(42);
        handle
            .replace_session_observations(
                [SessionObservation {
                    session_id,
                    egress_id: "egress-a".into(),
                    state: SessionState::Active,
                    ready_paths: 1,
                    active_streams: 2,
                    retained_outbound_bytes: 3,
                    bytes_sent: 4,
                    bytes_received: 5,
                }],
                [PathObservation {
                    path_id,
                    session_id,
                    state: PathState::Degraded,
                    rtt_ms: 12,
                    jitter_ms: 3,
                    loss_ppm: 4_000,
                    throughput_bps: 5_000_000,
                    reordering_events: 6,
                    exclusion_reason: Some("status_stale".into()),
                }],
            )
            .unwrap();
        let snapshot = service.observation_snapshot();
        let path = snapshot.paths.get(&path_id).expect("path observation");
        assert_eq!(path.rtt_ms, 12);
        assert_eq!(path.jitter_ms, 3);
        assert_eq!(path.loss_ppm, 4_000);
        assert_eq!(path.throughput_bps, 5_000_000);
        assert_eq!(path.reordering_events, 6);
        assert_eq!(path.exclusion_reason.as_deref(), Some("status_stale"));
    }

    #[test]
    fn cloned_observation_handle_tracks_listener_connections() {
        let service = IngressControlService::new();
        let handle = service.observation_handle();
        let listener_id = pathchord_policy::ListenerId::new("local-http");
        handle
            .apply_listener_event(crate::runtime::ListenerRuntimeEvent::ListenerStarted {
                listener_id: listener_id.clone(),
                bind: Some("127.0.0.1:8080".parse().unwrap()),
                interface: None,
                address: None,
                mtu: None,
            })
            .unwrap();
        handle
            .apply_listener_event(crate::runtime::ListenerRuntimeEvent::ConnectionAccepted {
                listener_id: listener_id.clone(),
                connection_id: "local-http-1".to_owned(),
                target_display: "example.test:443".to_owned(),
            })
            .unwrap();

        let active = service.observation_snapshot();
        assert_eq!(active.runtime_state, RuntimeSnapshotState::Fresh);
        assert_eq!(active.active_listener_count, 1);
        assert_eq!(active.runtime.target_connections, 1);
        assert_eq!(
            active.connections["local-http-1"].state,
            ConnectionState::Open
        );

        handle
            .apply_listener_event(crate::runtime::ListenerRuntimeEvent::ConnectionCompleted {
                listener_id: listener_id.clone(),
                connection_id: "local-http-1".to_owned(),
                stats: crate::FlowBridgeStats {
                    local_to_target_bytes: 10,
                    target_to_local_bytes: 20,
                },
            })
            .unwrap();
        handle
            .apply_listener_event(crate::runtime::ListenerRuntimeEvent::ListenerStopped {
                listener_id,
            })
            .unwrap();
        let stopped = service.observation_snapshot();
        assert_eq!(stopped.active_listener_count, 0);
        assert_eq!(stopped.runtime.target_connections, 0);
        assert_eq!(
            stopped.connections["local-http-1"].state,
            ConnectionState::Closed
        );
        assert_eq!(stopped.connections["local-http-1"].bytes_sent, 10);
        assert_eq!(stopped.connections["local-http-1"].bytes_received, 20);

        handle.state.lock().unwrap().last_updated_ms =
            Some(now_ms().saturating_sub(DEFAULT_OBSERVATION_STALE_AFTER_MS.saturating_add(1)));
        assert_eq!(
            service.observation_snapshot().runtime_state,
            RuntimeSnapshotState::Stale
        );
    }

    fn listener(id: &str, kind: crate::ListenerKind) -> crate::ListenerDescriptor {
        crate::ListenerDescriptor {
            id: pathchord_policy::ListenerId::new(id),
            kind,
            bind: Some("127.0.0.1:8080".parse().expect("listener address")),
            interface: None,
            address: None,
            mtu: None,
            flow_tags: std::collections::BTreeSet::new(),
            process_metadata: crate::ProcessMetadataRequest::default(),
            allowed_sources: Vec::new(),
            authentication_required: false,
        }
    }

    #[test]
    fn windows_system_proxy_requires_http_or_socks_listener_and_is_idempotent() {
        let mut service = IngressControlService::new();
        service.register_listener(listener("local-http", crate::ListenerKind::Http));
        service.register_listener(listener("tun", crate::ListenerKind::Tun));

        let first = service
            .enable_system_proxy(
                "operator",
                RequestId::new(1),
                SystemProxyPlatform::Windows,
                pathchord_policy::ListenerId::new("local-http"),
            )
            .expect("enable system proxy");
        assert_eq!(first.status.state, SystemProxyState::Applied);
        assert!(first.status.enabled);
        assert!(first.status.environment_applied);
        assert!(first.status.operating_system_applied);

        let replay = service
            .enable_system_proxy(
                "operator",
                RequestId::new(1),
                SystemProxyPlatform::Windows,
                pathchord_policy::ListenerId::new("local-http"),
            )
            .expect("idempotent enable");
        assert!(replay.replayed);
        assert_eq!(replay.status, first.status);

        assert!(matches!(
            service.enable_system_proxy(
                "operator",
                RequestId::new(2),
                SystemProxyPlatform::Windows,
                pathchord_policy::ListenerId::new("tun"),
            ),
            Err(ControlError::InvalidSystemProxyListener { .. })
        ));
        assert!(matches!(
            service.enable_system_proxy(
                "operator",
                RequestId::new(3),
                SystemProxyPlatform::Linux,
                pathchord_policy::ListenerId::new("local-http"),
            ),
            Err(ControlError::UnsupportedOperation { .. })
        ));
    }

    #[test]
    fn disabling_windows_system_proxy_restores_saved_state_and_emits_event() {
        let mut service = IngressControlService::new();
        service.register_listener(listener("local-socks", crate::ListenerKind::Socks5));
        service
            .enable_system_proxy(
                "operator",
                RequestId::new(10),
                SystemProxyPlatform::Windows,
                pathchord_policy::ListenerId::new("local-socks"),
            )
            .expect("enable");

        let disabled = service
            .disable_system_proxy("operator", RequestId::new(11), SystemProxyPlatform::Windows)
            .expect("disable");
        assert_eq!(disabled.status.state, SystemProxyState::Disabled);
        assert!(!disabled.status.enabled);
        assert_eq!(
            disabled.status.restoration_state,
            SystemProxyRestorationState::Restored
        );
        assert!(
            service
                .events_since(None)
                .iter()
                .any(|event| event.kind == ControlEventKind::SystemProxyChanged)
        );

        let replay = service
            .disable_system_proxy("operator", RequestId::new(11), SystemProxyPlatform::Windows)
            .expect("idempotent disable");
        assert!(replay.replayed);
    }

    #[test]
    fn mixed_system_proxy_selection_uses_the_shared_http_endpoint() {
        let adapter = Arc::new(FakePlatformProxyAdapter::new());
        let mut service = IngressControlService::with_platform_proxy(adapter.clone());
        let mixed = listener("shared-proxy", crate::ListenerKind::Mixed);
        let endpoint = mixed.bind.unwrap();
        service.register_listener(mixed);
        let result = service
            .enable_system_proxy(
                "operator",
                RequestId::new(12),
                SystemProxyPlatform::Windows,
                pathchord_policy::ListenerId::new("shared-proxy"),
            )
            .expect("enable mixed system proxy");
        assert!(result.status.enabled);
        assert_eq!(
            result.status.listener_id,
            Some(pathchord_policy::ListenerId::new("shared-proxy"))
        );
        let applied = adapter.applied().expect("applied proxy settings");
        assert_eq!(applied.kind, PlatformProxyKind::Http);
        assert_eq!(applied.endpoint, endpoint);
    }

    #[test]
    fn platform_proxy_failure_is_typed_and_visible_in_status() {
        let adapter = Arc::new(FakePlatformProxyAdapter::new());
        let mut service = IngressControlService::with_platform_proxy(adapter.clone());
        service.register_listener(listener("local-http", crate::ListenerKind::Http));
        adapter.fail_next("registry denied");

        assert!(matches!(
            service.enable_system_proxy(
                "operator",
                RequestId::new(20),
                SystemProxyPlatform::Windows,
                pathchord_policy::ListenerId::new("local-http"),
            ),
            Err(ControlError::PlatformProxy { .. })
        ));
        let status = service.system_proxy_status();
        assert_eq!(status.state, SystemProxyState::Failed);
        assert_eq!(status.platform_effect, SystemProxyPlatformEffect::Failed);
        assert!(
            status
                .error
                .as_deref()
                .is_some_and(|value| value.contains("registry denied"))
        );
    }
}
