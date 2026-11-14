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
use serde_json::{Value, json};
use thiserror::Error;

pub const MAX_NODE_COUNT: usize = 4096;
pub const MAX_SUBSCRIPTION_COUNT: usize = 256;
pub const MAX_EVENT_COUNT: usize = 2048;
pub const MAX_REQUEST_CACHE_COUNT: usize = 4096;
pub const MAX_REFRESH_QUEUE_COUNT: usize = 256;
pub const MAX_CONNECTION_OBSERVATIONS: usize = 16_384;
/// Terminal connections are optional history; live connections have priority.
pub const MAX_CONNECTION_HISTORY: usize = 1024;
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum SystemProxyState {
    Disabled,
    Applying,
    Applied,
    Restoring,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
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
        if SubscriptionSourceType::from_name(&self.source_type).is_none() {
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
        let source_type = SubscriptionSourceType::from_name(&self.source_type).ok_or(
            ControlError::InvalidSubscription {
                field: "source.type",
            },
        )?;
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeObservation {
    pub state: NodeHealthState,
    pub rtt_ms: Option<u32>,
    pub jitter_ms: Option<u32>,
    /// Loss in parts per million, avoiding floating-point ambiguity in the
    /// transport-neutral snapshot.
    pub loss_ppm: Option<u32>,
    pub throughput_bps: Option<u64>,
    pub effective_capacity_bps: Option<u64>,
    pub diagnostic: Option<pathchord_transit::NodeDiagnostic>,
    pub usage: Option<pathchord_transit::SubscriptionUsage>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NodeMetadata {
    pub namespace: Option<String>,
    pub protocol: Option<String>,
    pub endpoint: Option<String>,
    pub source_subscription: Option<String>,
    pub labels: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubscriptionRuntimeObservation {
    pub next_refresh_at_ms: Option<u64>,
    pub imported_node_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EgressRuntimeObservation {
    pub report: Option<pathchord_core::StatusReport>,
    pub age_ms: u64,
    pub fresh: bool,
    pub active_udp_associations: usize,
    pub pending_session_controls: usize,
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
pub struct StreamObservation {
    pub session_id: SessionId,
    pub stream_id: StreamId,
    pub state: pathchord_core::StreamState,
    /// Hostname and port only; credentials and payloads are never represented.
    pub target_display: String,
    pub traffic_class: Option<String>,
    pub traffic_class_priority: Option<u8>,
    pub traffic_class_share: Option<u32>,
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
pub struct PathObservation {
    pub path_id: PathId,
    pub session_id: SessionId,
    pub state: PathState,
    pub rtt_ms: Option<u64>,
    pub jitter_ms: Option<u64>,
    pub loss_ppm: Option<u32>,
    pub throughput_bps: Option<u64>,
    pub reordering_events: Option<u64>,
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
    pub resource_limits: BTreeSet<&'static str>,
    pub active_listener_count: usize,
    pub listener_states: BTreeMap<ListenerId, ListenerObservation>,
    pub connection_listeners: BTreeMap<String, ListenerId>,
    pub node_metadata: BTreeMap<NodeId, NodeMetadata>,
    pub subscription_runtime: BTreeMap<SubscriptionId, SubscriptionRuntimeObservation>,
    pub egress_runtime: BTreeMap<String, EgressRuntimeObservation>,
    pub nodes: BTreeMap<NodeId, NodeObservation>,
    pub sessions: BTreeMap<SessionId, SessionObservation>,
    pub streams: BTreeMap<(SessionId, StreamId), StreamObservation>,
    pub paths: BTreeMap<PathId, PathObservation>,
    pub connections: BTreeMap<String, ConnectionObservation>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListenerObservation {
    pub state: &'static str,
    pub reason: Option<&'static str>,
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
    listener_states: BTreeMap<ListenerId, ListenerObservation>,
    nodes: BTreeMap<NodeId, NodeObservation>,
    sessions: BTreeMap<SessionId, SessionObservation>,
    streams: BTreeMap<(SessionId, StreamId), StreamObservation>,
    paths: BTreeMap<PathId, PathObservation>,
    connections: BTreeMap<String, ConnectionObservation>,
    closed_connection_ids: VecDeque<String>,
    resource_limits: BTreeSet<&'static str>,
    connection_listeners: BTreeMap<String, ListenerId>,
    node_metadata: BTreeMap<NodeId, NodeMetadata>,
    subscription_runtime: BTreeMap<SubscriptionId, SubscriptionRuntimeObservation>,
    egress_runtime: BTreeMap<String, EgressRuntimeObservation>,
    pending_events: VecDeque<PendingObservationEvent>,
    pending_overflow: bool,
}

#[derive(Debug)]
struct PendingObservationEvent {
    kind: ControlEventKind,
    resource_id: String,
    generation: u64,
    emitted_at_ms: u64,
    payload: Value,
}

/// Cloneable, capability-limited writer for live runtime observations.
#[derive(Debug, Clone)]
pub struct IngressObservationHandle {
    state: Arc<Mutex<SharedObservationState>>,
}

impl IngressObservationHandle {
    pub fn set_egress_runtime(
        &self,
        egress_id: String,
        report: Option<pathchord_core::StatusReport>,
        age_ms: u64,
        fresh: bool,
        active_udp_associations: usize,
        pending_session_controls: usize,
    ) -> Result<(), ControlError> {
        if egress_id.is_empty() || egress_id.len() > 128 || egress_id.chars().any(char::is_control)
        {
            return Err(ControlError::InvalidIdentifier { kind: "egress" });
        }
        let mut state = self
            .state
            .lock()
            .map_err(|_| ControlError::ObservationUnavailable)?;
        if !state.egress_runtime.contains_key(&egress_id)
            && state.egress_runtime.len() >= MAX_NODE_COUNT
        {
            return Err(ControlError::ResourceLimit {
                resource: "egress observations",
            });
        }
        let next = EgressRuntimeObservation {
            report,
            age_ms,
            fresh,
            active_udp_associations,
            pending_session_controls,
        };
        if state.egress_runtime.get(&egress_id) != Some(&next) {
            state.egress_runtime.insert(egress_id, next);
            touch_observations(&mut state);
        }
        Ok(())
    }
    pub fn set_node_metadata(
        &self,
        node_id: NodeId,
        namespace: Option<String>,
        protocol: Option<String>,
        endpoint: Option<String>,
        source_subscription: Option<String>,
        labels: BTreeMap<String, String>,
    ) -> Result<(), ControlError> {
        if [&namespace, &protocol, &endpoint, &source_subscription]
            .into_iter()
            .flatten()
            .any(|value| value.len() > 256 || value.chars().any(char::is_control))
            || labels.len() > 256
            || labels.iter().any(|(key, value)| {
                key.is_empty()
                    || key.len() > 64
                    || value.len() > 256
                    || key.chars().any(char::is_control)
                    || value.chars().any(char::is_control)
            })
        {
            return Err(ControlError::FieldTooLarge {
                field: "node metadata",
            });
        }
        let mut state = self
            .state
            .lock()
            .map_err(|_| ControlError::ObservationUnavailable)?;
        if !state.node_metadata.contains_key(&node_id)
            && state.node_metadata.len() >= MAX_NODE_COUNT
        {
            return Err(ControlError::ResourceLimit {
                resource: "node metadata",
            });
        }
        let next = NodeMetadata {
            namespace,
            protocol,
            endpoint,
            source_subscription,
            labels,
        };
        if state.node_metadata.get(&node_id) != Some(&next) {
            state.node_metadata.insert(node_id, next);
            touch_observations(&mut state);
        }
        Ok(())
    }

    pub fn set_subscription_runtime(
        &self,
        id: SubscriptionId,
        next_refresh_at_ms: Option<u64>,
        imported_node_count: usize,
    ) -> Result<(), ControlError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| ControlError::ObservationUnavailable)?;
        if !state.subscription_runtime.contains_key(&id)
            && state.subscription_runtime.len() >= MAX_SUBSCRIPTION_COUNT
        {
            return Err(ControlError::ResourceLimit {
                resource: "subscription observations",
            });
        }
        let next = SubscriptionRuntimeObservation {
            next_refresh_at_ms,
            imported_node_count,
        };
        if state.subscription_runtime.get(&id) != Some(&next) {
            state.subscription_runtime.insert(id, next);
            touch_observations(&mut state);
        }
        Ok(())
    }

    pub fn remove_node_metadata(&self, id: &NodeId) -> Result<(), ControlError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| ControlError::ObservationUnavailable)?;
        if state.node_metadata.remove(id).is_some() {
            touch_observations(&mut state);
        }
        Ok(())
    }

    pub fn remove_subscription_runtime(&self, id: &SubscriptionId) -> Result<(), ControlError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| ControlError::ObservationUnavailable)?;
        if state.subscription_runtime.remove(id).is_some() {
            touch_observations(&mut state);
        }
        Ok(())
    }

    pub fn set_runtime_counts(&self, counts: RuntimeCounts) -> Result<(), ControlError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| ControlError::ObservationUnavailable)?;
        // Listener events own the live target-connection count. The data-plane
        // refresh supplies only Session/Path/Stream totals and must not replace
        // that independently observed value with a stream count.
        state.runtime.sessions = counts.sessions;
        state.runtime.ready_paths = counts.ready_paths;
        state.runtime.streams = counts.streams;
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
        let mut changes = Vec::new();
        for (id, session) in &sessions {
            if state.sessions.get(id) != Some(session) {
                changes.push((ControlEventKind::SessionChanged, id.to_string(), json!({"session_id": id.to_string(), "egress_id": session.egress_id, "state": format!("{:?}", session.state).to_ascii_lowercase(), "ready_path_count": session.ready_paths, "active_streams": session.active_streams})));
            }
        }
        for id in state
            .sessions
            .keys()
            .filter(|id| !sessions.contains_key(*id))
        {
            changes.push((
                ControlEventKind::SessionChanged,
                id.to_string(),
                json!({"session_id": id.to_string(), "state": "removed"}),
            ));
        }
        for (id, path) in &paths {
            if state.paths.get(id) != Some(path) {
                changes.push((ControlEventKind::PathChanged, id.to_string(), json!({"path_id": id.to_string(), "session_id": path.session_id.to_string(), "state": format!("{:?}", path.state).to_ascii_lowercase(), "rtt_ms": path.rtt_ms, "jitter_ms": path.jitter_ms, "loss_ppm": path.loss_ppm, "throughput_bps": path.throughput_bps, "exclusion_reason": path.exclusion_reason})));
            }
        }
        for id in state.paths.keys().filter(|id| !paths.contains_key(*id)) {
            changes.push((
                ControlEventKind::PathChanged,
                id.to_string(),
                json!({"path_id": id.to_string(), "state": "removed"}),
            ));
        }
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
        for (kind, id, payload) in changes {
            queue_observation_event(&mut state, kind, id, payload);
        }
        Ok(())
    }

    pub fn replace_stream_observations(
        &self,
        streams: impl IntoIterator<Item = StreamObservation>,
    ) -> Result<(), ControlError> {
        let streams: BTreeMap<_, _> = streams
            .into_iter()
            .map(|stream| ((stream.session_id, stream.stream_id), stream))
            .collect();
        if streams.len() > MAX_CONNECTION_OBSERVATIONS {
            return Err(ControlError::ResourceLimit {
                resource: "stream observations",
            });
        }
        let mut state = self
            .state
            .lock()
            .map_err(|_| ControlError::ObservationUnavailable)?;
        let mut changes = Vec::new();
        for (key, stream) in &streams {
            if state.streams.get(key) != Some(stream) {
                changes.push((format!("{}:{}", stream.session_id, stream.stream_id), json!({"session_id": stream.session_id.to_string(), "stream_id": stream.stream_id.to_string(), "state": format!("{:?}", stream.state).to_ascii_lowercase(), "bytes_sent": stream.bytes_sent, "bytes_received": stream.bytes_received, "bytes_acked": stream.bytes_acked, "traffic_class_name": stream.traffic_class, "traffic_class_priority": stream.traffic_class_priority, "traffic_class_share": stream.traffic_class_share, "close_reason": stream.close_reason})));
            }
        }
        for (session_id, stream_id) in state
            .streams
            .keys()
            .filter(|key| !streams.contains_key(*key))
        {
            changes.push((format!("{session_id}:{stream_id}"), json!({"session_id": session_id.to_string(), "stream_id": stream_id.to_string(), "state": "removed"})));
        }
        state.streams = streams;
        touch_observations(&mut state);
        for (id, payload) in changes {
            queue_observation_event(&mut state, ControlEventKind::StreamChanged, id, payload);
        }
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
        upsert_connection_observation(&mut state, observation)?;
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
            state.closed_connection_ids.retain(|id| id != connection_id);
            state.resource_limits.remove("connection_observations");
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
        let event_connection_id = match &event {
            crate::runtime::ListenerRuntimeEvent::ConnectionAccepted { connection_id, .. }
            | crate::runtime::ListenerRuntimeEvent::ConnectionCompleted { connection_id, .. }
            | crate::runtime::ListenerRuntimeEvent::ConnectionFailed {
                connection_id: Some(connection_id),
                ..
            } => Some(connection_id.clone()),
            _ => None,
        };
        let changed = match event {
            crate::runtime::ListenerRuntimeEvent::ListenerStarted { listener_id, .. } => {
                state.active_listeners.insert(listener_id.clone());
                state.listener_states.insert(
                    listener_id,
                    ListenerObservation {
                        state: "available",
                        reason: None,
                    },
                );
                true
            }
            event @ (crate::runtime::ListenerRuntimeEvent::ListenerStopped { .. }
            | crate::runtime::ListenerRuntimeEvent::ListenerFailed { .. }) => {
                let (listener_id, status) = match event {
                    crate::runtime::ListenerRuntimeEvent::ListenerStopped { listener_id } => (
                        listener_id,
                        ListenerObservation {
                            state: "stopped",
                            reason: Some("listener_stopped"),
                        },
                    ),
                    crate::runtime::ListenerRuntimeEvent::ListenerFailed {
                        listener_id, ..
                    } => (
                        listener_id,
                        ListenerObservation {
                            state: "degraded",
                            reason: Some("listener_failed"),
                        },
                    ),
                    _ => unreachable!(),
                };
                let removed = state.active_listeners.remove(&listener_id);
                let previous = state
                    .listener_states
                    .insert(listener_id.clone(), status.clone());
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
                        retain_terminal_connection(&mut state, &connection_id);
                    }
                }
                removed || had_affected || previous.as_ref() != Some(&status)
            }
            crate::runtime::ListenerRuntimeEvent::ConnectionAccepted {
                listener_id,
                connection_id,
                target_display,
            } => {
                upsert_connection_observation(
                    &mut state,
                    ConnectionObservation {
                        connection_id: connection_id.clone(),
                        session_id: None,
                        stream_id: None,
                        state: ConnectionState::Open,
                        bytes_sent: 0,
                        bytes_received: 0,
                        target_display: Some(target_display),
                    },
                )?;
                state
                    .connection_listeners
                    .insert(connection_id.clone(), listener_id);
                true
            }
            crate::runtime::ListenerRuntimeEvent::ConnectionCompleted {
                connection_id,
                stats,
                ..
            } => {
                if let Some(connection) = state.connections.get_mut(&connection_id) {
                    connection.state = ConnectionState::Closed;
                    connection.bytes_sent = stats.local_to_target_bytes;
                    connection.bytes_received = stats.target_to_local_bytes;
                    retain_terminal_connection(&mut state, &connection_id);
                    true
                } else {
                    false
                }
            }
            crate::runtime::ListenerRuntimeEvent::ConnectionFailed {
                connection_id: Some(connection_id),
                ..
            } => {
                if let Some(connection) = state.connections.get_mut(&connection_id) {
                    connection.state = ConnectionState::Reset;
                    retain_terminal_connection(&mut state, &connection_id);
                    true
                } else {
                    false
                }
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
            if let Some(id) = event_connection_id
                && let Some(connection) = state.connections.get(&id)
            {
                let payload = json!({"connection_id": id, "state": format!("{:?}", connection.state).to_ascii_lowercase(), "bytes_sent": connection.bytes_sent, "bytes_received": connection.bytes_received});
                queue_observation_event(
                    &mut state,
                    ControlEventKind::ConnectionChanged,
                    id,
                    payload,
                );
            }
        } else {
            state.last_updated_ms = Some(now_ms());
        }
        Ok(())
    }
}

fn connection_is_live(connection: &ConnectionObservation) -> bool {
    matches!(
        connection.state,
        ConnectionState::Opening | ConnectionState::Open | ConnectionState::HalfClosed
    )
}

fn record_observation_limit(state: &mut SharedObservationState, resource: &'static str) {
    if state.resource_limits.insert(resource) {
        touch_observations(state);
        queue_observation_event(
            state,
            ControlEventKind::ObservationChanged,
            "runtime".to_owned(),
            json!({"state": "degraded", "reason": "resource_limit", "resource": resource}),
        );
    }
}

fn evict_terminal_connection(state: &mut SharedObservationState) -> bool {
    let Some(id) = state.closed_connection_ids.pop_front() else {
        return false;
    };
    state.connections.remove(&id);
    state.connection_listeners.remove(&id);
    record_observation_limit(state, "connection_history");
    queue_observation_event(
        state,
        ControlEventKind::ConnectionChanged,
        id.clone(),
        json!({"connection_id": id, "state": "removed", "reason": "history_limit"}),
    );
    true
}

fn retain_terminal_connection(state: &mut SharedObservationState, id: &str) {
    if !state.closed_connection_ids.iter().any(|old| old == id) {
        state.closed_connection_ids.push_back(id.to_owned());
    }
    while state.closed_connection_ids.len() > MAX_CONNECTION_HISTORY {
        evict_terminal_connection(state);
    }
}

fn upsert_connection_observation(
    state: &mut SharedObservationState,
    observation: ConnectionObservation,
) -> Result<(), ControlError> {
    if !state.connections.contains_key(&observation.connection_id) {
        while state.connections.len() >= MAX_CONNECTION_OBSERVATIONS {
            if !evict_terminal_connection(state) {
                record_observation_limit(state, "connection_observations");
                return Err(ControlError::ResourceLimit {
                    resource: "connection observations",
                });
            }
        }
    }
    state.resource_limits.remove("connection_observations");
    let id = observation.connection_id.clone();
    if connection_is_live(&observation) {
        state.closed_connection_ids.retain(|closed| closed != &id);
    }
    let terminal = !connection_is_live(&observation);
    state.connections.insert(id.clone(), observation);
    if terminal {
        retain_terminal_connection(state, &id);
    }
    Ok(())
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

fn queue_observation_event(
    state: &mut SharedObservationState,
    kind: ControlEventKind,
    resource_id: String,
    payload: Value,
) {
    if state.pending_events.len() == MAX_EVENT_COUNT {
        state.pending_events.pop_front();
        state.pending_overflow = true;
    }
    state.pending_events.push_back(PendingObservationEvent {
        kind,
        resource_id,
        generation: state.generation,
        emitted_at_ms: now_ms(),
        payload,
    });
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControlEventKind {
    NodeChanged,
    SubscriptionChanged,
    SubscriptionRefreshRequested,
    ObservationChanged,
    SystemProxyChanged,
    AuditNotice,
    PathChanged,
    SessionChanged,
    StreamChanged,
    ConnectionChanged,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControlEvent {
    pub id: u64,
    pub generation: u64,
    pub kind: ControlEventKind,
    pub resource_id: String,
    /// Old persisted events may predate event timestamps and payloads.
    pub emitted_at_ms: Option<u64>,
    pub payload: Value,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MutationReceipt {
    pub generation: u64,
    pub event_id: u64,
    pub replayed: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GenerationPrecondition {
    Expected(u64),
    Force,
}

impl std::fmt::Display for GenerationPrecondition {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Expected(value) => write!(formatter, "expected:{value}"),
            Self::Force => formatter.write_str("force"),
        }
    }
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
    #[error("subscription revision conflict: expected {expected}, current {current}")]
    RevisionConflict { expected: u64, current: u64 },
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

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct CachedCommand {
    pub(crate) fingerprint: String,
    pub(crate) receipt: MutationReceipt,
    pub(crate) created_at_ms: u64,
    pub(crate) system_proxy_status: Option<SystemProxyStatus>,
    pub(crate) response_fingerprint: Option<String>,
    pub(crate) response: Option<pathchord_core::management::ResponseEnvelope>,
}

impl CachedCommand {
    /// An idempotency record expires only after both the minimum retention
    /// period and the generation that produced it have passed.
    pub(crate) fn is_live(&self, current_generation: u64, now: u64) -> bool {
        self.receipt.generation >= current_generation
            || now.saturating_sub(self.created_at_ms) <= REQUEST_CACHE_TTL_MS
    }
}

/// Transport-neutral control service with an optional durable SQLite adapter.
#[derive(Debug)]
pub struct IngressControlService {
    snapshot: IngressControlSnapshot,
    declarative_subscriptions: BTreeMap<SubscriptionId, DeclarativeSubscriptionBaseline>,
    declarative_initialized: bool,
    observations: Arc<Mutex<SharedObservationState>>,
    events: VecDeque<ControlEvent>,
    refresh_queue: VecDeque<SubscriptionId>,
    request_cache: HashMap<(String, RequestId), CachedCommand>,
    next_event_id: u64,
    last_observation_gap: Option<u64>,
    listeners: BTreeMap<ListenerId, ListenerDescriptor>,
    system_proxy: SystemProxyStatus,
    platform_proxy: Arc<dyn PlatformProxyAdapter>,
    store: Option<Arc<IngressControlStore>>,
    reload_handle: Option<crate::ConfigReloadHandle>,
    audit_degraded: bool,
}

#[derive(Clone)]
struct DurableCheckpoint {
    snapshot: IngressControlSnapshot,
    declarative_subscriptions: BTreeMap<SubscriptionId, DeclarativeSubscriptionBaseline>,
    declarative_initialized: bool,
    events: VecDeque<ControlEvent>,
    refresh_queue: VecDeque<SubscriptionId>,
    request_cache: HashMap<(String, RequestId), CachedCommand>,
    next_event_id: u64,
    last_observation_gap: Option<u64>,
}

/// Tracks the last declaration without storing a second copy of its source URL.
#[derive(Debug, Clone)]
pub(crate) struct DeclarativeSubscriptionBaseline {
    pub(crate) fingerprint: String,
    pub(crate) deleted: bool,
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
    pub(crate) fn replay_management_response(
        &self,
        request: &pathchord_core::management::RequestEnvelope,
        request_id: RequestId,
        fingerprint: &str,
    ) -> Result<Option<pathchord_core::management::ResponseEnvelope>, ControlError> {
        let Some(cached) = self
            .request_cache
            .get(&(request.actor.id.clone(), request_id))
        else {
            return Ok(None);
        };
        if !cached.is_live(self.snapshot.generation, now_ms()) {
            return Ok(None);
        }
        match (&cached.response_fingerprint, &cached.response) {
            (Some(stored), Some(response)) if stored == fingerprint => Ok(Some(response.clone())),
            (Some(_), Some(_)) => Err(ControlError::IdempotencyConflict { request_id }),
            _ => Ok(None),
        }
    }

    pub(crate) fn remember_management_response(
        &mut self,
        actor: &str,
        request_id: RequestId,
        fingerprint: String,
        response: &pathchord_core::management::ResponseEnvelope,
    ) {
        if let Some(cached) = self.request_cache.get_mut(&(actor.to_owned(), request_id)) {
            cached.response_fingerprint = Some(fingerprint);
            cached.response = Some(response.clone());
        }
    }

    /// Persist a deterministic failure together with the request identity. A
    /// store failure restores the in-memory cache so the operation can retry.
    pub(crate) fn remember_management_failure(
        &mut self,
        actor: &str,
        request_id: RequestId,
        fingerprint: String,
        response: &pathchord_core::management::ResponseEnvelope,
    ) -> Result<(), ControlError> {
        if self
            .request_cache
            .get(&(actor.to_owned(), request_id))
            .is_some_and(|entry| entry.is_live(self.snapshot.generation, now_ms()))
        {
            return Err(ControlError::IdempotencyConflict { request_id });
        }
        self.ensure_cache_capacity(actor, request_id)?;
        let checkpoint = self.durable_checkpoint();
        let generation = self.snapshot.generation;
        let now = now_ms();
        self.request_cache
            .retain(|_, entry| entry.is_live(generation, now));
        self.request_cache.insert(
            (actor.to_owned(), request_id),
            CachedCommand {
                fingerprint: fingerprint.clone(),
                receipt: MutationReceipt {
                    generation,
                    event_id: self.next_event_id,
                    replayed: false,
                },
                created_at_ms: now,
                system_proxy_status: None,
                response_fingerprint: Some(fingerprint),
                response: Some(response.clone()),
            },
        );
        if let Err(error) = self.persist(None) {
            self.restore_checkpoint(checkpoint);
            return Err(error);
        }
        Ok(())
    }
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
            declarative_subscriptions: BTreeMap::new(),
            declarative_initialized: false,
            observations: Arc::new(Mutex::new(SharedObservationState::default())),
            events: VecDeque::new(),
            refresh_queue: VecDeque::new(),
            request_cache: HashMap::new(),
            next_event_id: 0,
            last_observation_gap: None,
            listeners: BTreeMap::new(),
            system_proxy,
            platform_proxy,
            store: None,
            reload_handle: None,
            audit_degraded: false,
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
        service.declarative_subscriptions = durable.declarative_subscriptions;
        service.declarative_initialized = durable.declarative_initialized;
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

    pub fn set_reload_handle(&mut self, handle: crate::ConfigReloadHandle) {
        self.reload_handle = Some(handle);
    }

    #[must_use]
    pub fn reload_status(&self) -> Option<crate::ReloadStatus> {
        self.reload_handle
            .as_ref()
            .map(crate::ConfigReloadHandle::status)
    }

    pub fn reconcile_declarative_resources(
        &mut self,
        generation: u64,
        nodes: impl IntoIterator<Item = NodeId>,
        subscriptions: impl IntoIterator<Item = SubscriptionSpec>,
    ) -> Result<(), ControlError> {
        // Validate the whole candidate before modifying any runtime or durable state.
        let mut declared = BTreeMap::new();
        for spec in subscriptions {
            spec.validate()?;
            let id = spec.id.clone();
            if declared.insert(id.clone(), spec).is_some() {
                return Err(ControlError::SubscriptionExists(id));
            }
        }
        if declared.len() > MAX_SUBSCRIPTION_COUNT {
            return Err(ControlError::ResourceLimit {
                resource: "subscriptions",
            });
        }
        let checkpoint = self.durable_checkpoint();
        let mut changed = false;
        for node in nodes {
            if !self.snapshot.nodes.contains_key(&node)
                && self.snapshot.nodes.len() >= MAX_NODE_COUNT
            {
                self.restore_checkpoint(checkpoint);
                return Err(ControlError::ResourceLimit { resource: "nodes" });
            }
            if let std::collections::btree_map::Entry::Vacant(entry) =
                self.snapshot.nodes.entry(node)
            {
                entry.insert(NodeAdminState::default());
                changed = true;
            }
        }
        // Remove only resources known to have originated in the declaration.
        let removed: Vec<_> = self
            .declarative_subscriptions
            .keys()
            .filter(|id| !declared.contains_key(*id))
            .cloned()
            .collect();
        for id in removed {
            self.declarative_subscriptions.remove(&id);
            changed |= self.snapshot.subscriptions.remove(&id).is_some();
            self.refresh_queue.retain(|queued| queued != &id);
        }

        for (id, spec) in declared {
            let fingerprint = subscription_declaration_fingerprint(&spec);
            let previous = self.declarative_subscriptions.get(&id);
            let unchanged = previous.is_some_and(|baseline| baseline.fingerprint == fingerprint);
            let deleted = unchanged && previous.is_some_and(|baseline| baseline.deleted);
            // An existing DB predating baselines may contain an administrator's
            // override. Adopt that state on migration, then track future changes.
            let adopt_existing = !self.declarative_initialized
                && previous.is_none()
                && self.snapshot.subscriptions.contains_key(&id);
            self.declarative_subscriptions.insert(
                id.clone(),
                DeclarativeSubscriptionBaseline {
                    fingerprint,
                    deleted,
                },
            );
            if deleted || unchanged || adopt_existing {
                continue;
            }
            if !self.snapshot.subscriptions.contains_key(&id)
                && self.snapshot.subscriptions.len() >= MAX_SUBSCRIPTION_COUNT
            {
                self.restore_checkpoint(checkpoint);
                return Err(ControlError::ResourceLimit {
                    resource: "subscriptions",
                });
            }
            match self.snapshot.subscriptions.get_mut(&id) {
                Some(existing) if existing.spec != spec => {
                    let was_enabled = existing.spec.enabled;
                    let source_changed = existing.spec.source_type != spec.source_type
                        || existing.spec.url != spec.url
                        || existing.spec.credentials_ref != spec.credentials_ref;
                    existing.spec = spec;
                    existing.refresh_state = SubscriptionRefreshState::Idle;
                    existing.last_error = None;
                    if source_changed {
                        existing.cache_metadata.clear();
                        existing.last_refresh_at_ms = None;
                    }
                    if was_enabled && !existing.spec.enabled {
                        self.refresh_queue
                            .retain(|queued| queued != &existing.spec.id);
                    }
                    changed = true;
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
                    changed = true;
                }
            }
        }
        self.snapshot.generation = self
            .snapshot
            .generation
            .saturating_add(u64::from(changed))
            .max(generation);
        self.declarative_initialized = true;
        if let Err(error) = self.persist(None) {
            self.restore_checkpoint(checkpoint);
            return Err(error);
        }
        Ok(())
    }

    pub fn record_authentication_failure(&mut self, source: &str) -> Result<(), ControlError> {
        if source.is_empty() || source.len() > 256 {
            return Err(ControlError::FieldTooLarge {
                field: "authentication source",
            });
        }
        let checkpoint = self.durable_checkpoint();
        let receipt = self.emit(ControlEventKind::AuditNotice, source.to_owned());
        if let Err(error) = self.persist(Some(AuditRecord::authentication_failure(
            source,
            self.snapshot.generation,
            receipt.event_id,
        ))) {
            self.restore_checkpoint(checkpoint);
            return Err(error);
        }
        Ok(())
    }

    pub(crate) fn record_management_outcome(
        &mut self,
        request: &pathchord_core::management::RequestEnvelope,
        response: &pathchord_core::management::ResponseEnvelope,
        source: pathchord_core::management::ManagementSource,
    ) {
        let resource_id = ["node_id", "listener_id", "id"]
            .iter()
            .find_map(|field| request.body.get(field).and_then(Value::as_str))
            .filter(|value| {
                value.len() <= 128
                    && value
                        .chars()
                        .all(|ch| ch.is_ascii_alphanumeric() || "._-".contains(ch))
            })
            .unwrap_or("unknown")
            .to_owned();
        let checkpoint = self.durable_checkpoint();
        let receipt = self.emit(ControlEventKind::AuditNotice, resource_id.clone());
        let reason = response
            .error
            .as_ref()
            .and_then(|error| serde_json::to_value(error.code).ok());
        let expected = request.expected_generation.as_ref().map(|value| json!({
            "scope": if matches!(value.scope.as_str(), "configuration" | "observation" | "authorization") { value.scope.as_str() } else { "invalid" },
            "value": value.value,
        }));
        if let Some(event) = self.events.back_mut() {
            event.payload = json!({
                "actor_id": request.actor.id.chars().filter(|ch| !ch.is_control()).take(128).collect::<String>(),
                "source": source.as_str(),
                "operation": request.operation,
                "request_id": request.request_id.chars().filter(|ch| !ch.is_control()).take(128).collect::<String>(),
                "target_resource": resource_id,
                "expected_generation": expected,
                "applied_generation": response.result.as_ref().and_then(|value| value.get("applied_generation")),
                "result": if response.ok { "success" } else { "failed" },
                "reason": reason,
            });
        }
        let audit = AuditRecord::management(
            request,
            response,
            resource_id,
            self.snapshot.generation,
            receipt.event_id,
            source,
        );
        if self.persist(Some(audit)).is_err() {
            self.restore_checkpoint(checkpoint);
            self.audit_degraded = true;
        }
    }

    #[must_use]
    pub const fn audit_degraded(&self) -> bool {
        self.audit_degraded
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
        self.enable_system_proxy_precondition(
            actor,
            request_id,
            platform,
            listener_id,
            GenerationPrecondition::Force,
        )
    }

    pub(crate) fn enable_system_proxy_precondition(
        &mut self,
        actor: &str,
        request_id: RequestId,
        platform: SystemProxyPlatform,
        listener_id: ListenerId,
        expected_generation: GenerationPrecondition,
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
        let fingerprint =
            format!("system-proxy-enable:{listener_id:?}:{platform:?}:{expected_generation}");
        if let Some(receipt) = self.cached(actor, request_id, &fingerprint)? {
            return Ok(self.replayed_system_proxy_mutation(actor, request_id, receipt));
        }
        self.ensure_cache_capacity(actor, request_id)?;
        self.check_generation(expected_generation)?;
        if self.system_proxy.enabled && self.system_proxy.listener_id.as_ref() == Some(&listener_id)
        {
            let mutation = self.system_proxy_mutation(true);
            self.cache(
                actor,
                request_id,
                fingerprint,
                MutationReceipt {
                    generation: mutation.generation,
                    event_id: mutation.event_id,
                    replayed: false,
                },
            )?;
            self.persist(None)?;
            return Ok(mutation);
        }
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
        self.disable_system_proxy_precondition(
            actor,
            request_id,
            platform,
            GenerationPrecondition::Force,
        )
    }

    pub(crate) fn disable_system_proxy_precondition(
        &mut self,
        actor: &str,
        request_id: RequestId,
        platform: SystemProxyPlatform,
        expected_generation: GenerationPrecondition,
    ) -> Result<SystemProxyMutation, ControlError> {
        self.check_actor(actor)?;
        if platform != SystemProxyPlatform::Windows {
            return Err(ControlError::UnsupportedOperation {
                operation: "system_proxy.disable",
                platform,
            });
        }
        let fingerprint = format!("system-proxy-disable:{platform:?}:{expected_generation}");
        if let Some(receipt) = self.cached(actor, request_id, &fingerprint)? {
            return Ok(self.replayed_system_proxy_mutation(actor, request_id, receipt));
        }
        self.ensure_cache_capacity(actor, request_id)?;
        self.check_generation(expected_generation)?;
        if self.system_proxy.state == SystemProxyState::Disabled {
            let mutation = self.system_proxy_mutation(true);
            self.cache(
                actor,
                request_id,
                fingerprint,
                MutationReceipt {
                    generation: mutation.generation,
                    event_id: mutation.event_id,
                    replayed: false,
                },
            )?;
            self.persist(None)?;
            return Ok(mutation);
        }
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

    fn replayed_system_proxy_mutation(
        &self,
        actor: &str,
        request_id: RequestId,
        receipt: MutationReceipt,
    ) -> SystemProxyMutation {
        let status = self
            .request_cache
            .get(&(actor.to_owned(), request_id))
            .and_then(|entry| entry.system_proxy_status.clone())
            .unwrap_or_else(|| self.system_proxy.clone());
        SystemProxyMutation {
            generation: receipt.generation,
            event_id: receipt.event_id,
            replayed: true,
            status,
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
            resource_limits: observations.resource_limits.clone(),
            active_listener_count: observations.active_listeners.len(),
            listener_states: observations.listener_states.clone(),
            connection_listeners: observations.connection_listeners.clone(),
            node_metadata: observations.node_metadata.clone(),
            subscription_runtime: observations.subscription_runtime.clone(),
            egress_runtime: observations.egress_runtime.clone(),
            nodes: observations.nodes.clone(),
            sessions: observations.sessions.clone(),
            streams: observations.streams.clone(),
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
        let id = observation.connection_id.clone();
        upsert_connection_observation(&mut observations, observation)?;
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
            observations
                .closed_connection_ids
                .retain(|id| id != connection_id);
            observations
                .resource_limits
                .remove("connection_observations");
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
        observations.runtime.sessions = counts.sessions;
        observations.runtime.ready_paths = counts.ready_paths;
        observations.runtime.streams = counts.streams;
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

    #[must_use]
    pub fn event_replay_gap(&self, last_event_id: Option<u64>) -> bool {
        last_event_id.is_some_and(|id| {
            id > self.next_event_id
                || self.last_observation_gap.is_some_and(|gap| id < gap)
                || self
                    .events
                    .front()
                    .map_or(id < self.next_event_id, |first| {
                        id.saturating_add(1) < first.id
                    })
                || self
                    .events
                    .iter()
                    .zip(self.events.iter().skip(1))
                    .any(|(before, after)| before.id.saturating_add(1) < after.id && id < after.id)
        })
    }

    #[must_use]
    pub const fn latest_event_id(&self) -> u64 {
        self.next_event_id
    }

    pub(crate) fn flush_observation_events(&mut self) -> Result<(), ControlError> {
        let (pending, overflow) = {
            let mut observations = self
                .observations
                .lock()
                .map_err(|_| ControlError::ObservationUnavailable)?;
            (
                std::mem::take(&mut observations.pending_events),
                std::mem::take(&mut observations.pending_overflow),
            )
        };
        if pending.is_empty() && !overflow {
            return Ok(());
        }
        let checkpoint = self.durable_checkpoint();
        if overflow {
            self.next_event_id = self.next_event_id.saturating_add(1);
            self.last_observation_gap = Some(self.next_event_id);
        }
        for event in &pending {
            self.next_event_id = self.next_event_id.saturating_add(1);
            self.events.push_back(ControlEvent {
                id: self.next_event_id,
                generation: event.generation,
                kind: event.kind,
                resource_id: event.resource_id.clone(),
                emitted_at_ms: Some(event.emitted_at_ms),
                payload: event.payload.clone(),
            });
            if self.events.len() > MAX_EVENT_COUNT {
                self.events.pop_front();
            }
        }
        if let Err(error) = self.persist(None) {
            self.restore_checkpoint(checkpoint);
            let mut observations = self
                .observations
                .lock()
                .map_err(|_| ControlError::ObservationUnavailable)?;
            for event in pending.into_iter().rev() {
                observations.pending_events.push_front(event);
            }
            while observations.pending_events.len() > MAX_EVENT_COUNT {
                observations.pending_events.pop_front();
                observations.pending_overflow = true;
            }
            observations.pending_overflow |= overflow;
            return Err(error);
        }
        Ok(())
    }

    pub fn patch_node(
        &mut self,
        actor: &str,
        request_id: RequestId,
        node_id: NodeId,
        expected_generation: u64,
        patch: NodeAdminPatch,
    ) -> Result<MutationReceipt, ControlError> {
        self.patch_node_precondition(
            actor,
            request_id,
            node_id,
            GenerationPrecondition::Expected(expected_generation),
            patch,
        )
    }

    pub(crate) fn patch_node_precondition(
        &mut self,
        actor: &str,
        request_id: RequestId,
        node_id: NodeId,
        expected_generation: GenerationPrecondition,
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
        self.add_subscription_precondition(
            actor,
            request_id,
            GenerationPrecondition::Expected(expected_generation),
            spec,
        )
    }

    pub(crate) fn add_subscription_precondition(
        &mut self,
        actor: &str,
        request_id: RequestId,
        expected_generation: GenerationPrecondition,
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
        if let Some(baseline) = self.declarative_subscriptions.get_mut(&id) {
            baseline.deleted = false;
        }
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
        self.delete_subscription_precondition(
            actor,
            request_id,
            GenerationPrecondition::Expected(expected_generation),
            id,
        )
    }

    pub(crate) fn delete_subscription_precondition(
        &mut self,
        actor: &str,
        request_id: RequestId,
        expected_generation: GenerationPrecondition,
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
        if let Some(baseline) = self.declarative_subscriptions.get_mut(id) {
            baseline.deleted = true;
        }
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
        self.set_subscription_enabled_precondition(
            actor,
            request_id,
            GenerationPrecondition::Expected(expected_generation),
            id,
            enabled,
        )
    }

    pub(crate) fn set_subscription_enabled_precondition(
        &mut self,
        actor: &str,
        request_id: RequestId,
        expected_generation: GenerationPrecondition,
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
        let expected_generation = self.snapshot.generation;
        self.request_subscription_refresh_with_generation(
            actor,
            request_id,
            expected_generation,
            id,
        )
    }

    pub fn request_subscription_refresh_with_generation(
        &mut self,
        actor: &str,
        request_id: RequestId,
        expected_generation: u64,
        id: &SubscriptionId,
    ) -> Result<MutationReceipt, ControlError> {
        let revision = self
            .snapshot
            .subscriptions
            .get(id)
            .ok_or_else(|| ControlError::SubscriptionNotFound(id.clone()))?
            .revision;
        self.request_subscription_refresh_checked(
            actor,
            request_id,
            expected_generation,
            id,
            revision,
        )
    }

    pub fn request_subscription_refresh_checked(
        &mut self,
        actor: &str,
        request_id: RequestId,
        expected_generation: u64,
        id: &SubscriptionId,
        expected_revision: u64,
    ) -> Result<MutationReceipt, ControlError> {
        self.request_subscription_refresh_precondition(
            actor,
            request_id,
            GenerationPrecondition::Expected(expected_generation),
            id,
            expected_revision,
        )
    }

    pub(crate) fn request_subscription_refresh_precondition(
        &mut self,
        actor: &str,
        request_id: RequestId,
        expected_generation: GenerationPrecondition,
        id: &SubscriptionId,
        expected_revision: u64,
    ) -> Result<MutationReceipt, ControlError> {
        let fingerprint =
            format!("refresh-subscription:{id:?}:{expected_generation}:{expected_revision}");
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
        if subscription.revision != expected_revision {
            return Err(ControlError::RevisionConflict {
                expected: expected_revision,
                current: subscription.revision,
            });
        }
        if !subscription.spec.enabled || subscription.spec.source_type == "static" {
            return Err(ControlError::InvalidSubscription {
                field: "enabled/source.type",
            });
        }
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
            declarative_subscriptions: self.declarative_subscriptions.clone(),
            declarative_initialized: self.declarative_initialized,
            events: self.events.clone(),
            refresh_queue: self.refresh_queue.clone(),
            request_cache: self.request_cache.clone(),
            next_event_id: self.next_event_id,
            last_observation_gap: self.last_observation_gap,
        }
    }

    fn restore_checkpoint(&mut self, checkpoint: DurableCheckpoint) {
        self.snapshot = checkpoint.snapshot;
        self.declarative_subscriptions = checkpoint.declarative_subscriptions;
        self.declarative_initialized = checkpoint.declarative_initialized;
        self.events = checkpoint.events;
        self.refresh_queue = checkpoint.refresh_queue;
        self.request_cache = checkpoint.request_cache;
        self.next_event_id = checkpoint.next_event_id;
        self.last_observation_gap = checkpoint.last_observation_gap;
    }

    fn persist(&self, audit: Option<AuditRecord>) -> Result<(), ControlError> {
        let Some(store) = &self.store else {
            return Ok(());
        };
        store
            .commit(StoreCommit {
                snapshot: &self.snapshot,
                declarative_subscriptions: &self.declarative_subscriptions,
                declarative_initialized: self.declarative_initialized,
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

    fn check_generation(&self, expected: GenerationPrecondition) -> Result<(), ControlError> {
        if matches!(expected, GenerationPrecondition::Force)
            || expected == GenerationPrecondition::Expected(self.snapshot.generation)
        {
            Ok(())
        } else {
            Err(ControlError::GenerationConflict {
                expected: match expected {
                    GenerationPrecondition::Expected(value) => value,
                    GenerationPrecondition::Force => unreachable!(),
                },
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
        if !cached.is_live(self.snapshot.generation, now_ms()) {
            return Ok(None);
        }
        let legacy = fingerprint.replace(":expected:", ":");
        if cached.fingerprint == fingerprint_digest(fingerprint)
            || (legacy != fingerprint && cached.fingerprint == fingerprint_digest(&legacy))
        {
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
        let now = now_ms();
        let generation = self.snapshot.generation;
        self.request_cache
            .retain(|_, cached| cached.is_live(generation, now));
        let system_proxy_status = fingerprint
            .starts_with("system-proxy-")
            .then(|| self.system_proxy.clone());
        self.request_cache.insert(
            (actor.to_owned(), request_id),
            CachedCommand {
                fingerprint: fingerprint_digest(&fingerprint),
                receipt,
                created_at_ms: now_ms(),
                system_proxy_status,
                response_fingerprint: None,
                response: None,
            },
        );
        Ok(())
    }

    fn ensure_cache_capacity(
        &self,
        actor: &str,
        request_id: RequestId,
    ) -> Result<(), ControlError> {
        let now = now_ms();
        let live_count = self
            .request_cache
            .values()
            .filter(|cached| cached.is_live(self.snapshot.generation, now))
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
        let observation = self.observation_snapshot();
        let generation = match kind {
            ControlEventKind::ObservationChanged
            | ControlEventKind::AuditNotice
            | ControlEventKind::PathChanged
            | ControlEventKind::SessionChanged
            | ControlEventKind::StreamChanged
            | ControlEventKind::ConnectionChanged => observation.generation,
            _ => self.snapshot.generation,
        };
        let payload = match kind {
            ControlEventKind::NodeChanged => self
                .snapshot
                .nodes
                .iter()
                .find(|(id, _)| id.as_str() == resource_id)
                .map_or_else(
                    || json!({"id": resource_id, "state": "deleted"}),
                    |(id, node)| json!({"id": id.as_str(), "admin": {"labels": node.labels, "tags": node.tags}}),
                ),
            ControlEventKind::SubscriptionChanged | ControlEventKind::SubscriptionRefreshRequested => self
                .snapshot
                .subscriptions
                .iter()
                .find(|(id, _)| id.as_str() == resource_id)
                .map_or_else(
                    || json!({"id": resource_id, "state": "deleted"}),
                    |(id, subscription)| json!({
                        "id": id.as_str(),
                        "enabled": subscription.spec.enabled,
                        "revision": subscription.revision,
                        "state": if !subscription.spec.enabled {"disabled"} else {
                            match subscription.refresh_state {
                                SubscriptionRefreshState::Idle | SubscriptionRefreshState::Healthy => "enabled",
                                SubscriptionRefreshState::Queued => "refreshing",
                                SubscriptionRefreshState::Failed => "failed",
                            }
                        },
                        "last_error": subscription.last_error,
                    }),
                ),
            ControlEventKind::ObservationChanged => json!({
                "sessions": observation.runtime.sessions,
                "ready_paths": observation.runtime.ready_paths,
                "streams": observation.runtime.streams,
                "target_connections": observation.runtime.target_connections,
                "freshness": format!("{:?}", observation.runtime_state).to_ascii_lowercase(),
            }),
            ControlEventKind::SystemProxyChanged => json!({
                "enabled": self.system_proxy.enabled,
                "listener_id": self.system_proxy.listener_id.as_ref().map(ListenerId::as_str),
                "platform_effect": format!("{:?}", self.system_proxy.platform_effect).to_ascii_lowercase(),
                "restoration_state": format!("{:?}", self.system_proxy.restoration_state).to_ascii_lowercase(),
            }),
            ControlEventKind::AuditNotice => json!({
                "source": resource_id,
                "operation": "authentication.failure",
                "result": "denied",
            }),
            ControlEventKind::PathChanged | ControlEventKind::SessionChanged | ControlEventKind::StreamChanged | ControlEventKind::ConnectionChanged => Value::Null,
        };
        let event = ControlEvent {
            id: self.next_event_id,
            generation,
            kind,
            resource_id,
            emitted_at_ms: Some(now_ms()),
            payload,
        };
        self.events.push_back(event.clone());
        while self.events.len() > MAX_EVENT_COUNT {
            self.events.pop_front();
        }
        MutationReceipt {
            generation: self.snapshot.generation,
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

pub(crate) fn fingerprint_digest(fingerprint: &str) -> String {
    use std::fmt::Write as _;
    let digest = orion::hazardous::hash::sha2::sha256::Sha256::digest(fingerprint.as_bytes())
        .expect("bounded management fingerprint");
    let mut result = String::from("sha256:");
    for byte in digest.as_ref() {
        write!(result, "{byte:02x}").expect("writing to a String cannot fail");
    }
    result
}

fn subscription_declaration_fingerprint(spec: &SubscriptionSpec) -> String {
    // A fixed JSON array is unambiguous and stable across map ordering and
    // debug-format changes; only its digest is written to the database.
    let value = json!([
        "subscription-declaration-v1",
        spec.id.as_str(),
        spec.source_type,
        spec.display_name,
        spec.enabled,
        spec.url,
        spec.credentials_ref,
        spec.refresh.interval_seconds,
        spec.refresh.timeout_seconds,
        spec.refresh.max_attempts,
        spec.refresh.backoff_seconds,
        spec.cache
            .as_ref()
            .map(|cache| (&cache.path, cache.max_age_seconds)),
    ]);
    fingerprint_digest(&value.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_cache_requires_both_elapsed_time_and_superseded_generation_to_expire() {
        let cached = CachedCommand {
            fingerprint: "request".into(),
            receipt: MutationReceipt {
                generation: 5,
                event_id: 1,
                replayed: false,
            },
            created_at_ms: 1,
            system_proxy_status: None,
            response_fingerprint: None,
            response: None,
        };
        assert!(cached.is_live(5, REQUEST_CACHE_TTL_MS + 2));
        assert!(cached.is_live(6, REQUEST_CACHE_TTL_MS));
        assert!(!cached.is_live(6, REQUEST_CACHE_TTL_MS + 2));
    }

    #[test]
    fn repeated_runtime_publication_does_not_advance_observation_generation() {
        let service = IngressControlService::new();
        let handle = service.observation_handle();
        let id = NodeId::new("node-a").unwrap();
        handle
            .set_node_metadata(
                id.clone(),
                None,
                Some("socks5".into()),
                None,
                None,
                BTreeMap::new(),
            )
            .unwrap();
        let generation = service.observation_snapshot().generation;
        handle
            .set_node_metadata(id, None, Some("socks5".into()), None, None, BTreeMap::new())
            .unwrap();
        assert_eq!(service.observation_snapshot().generation, generation);
    }

    #[test]
    fn manual_refresh_rejects_disabled_and_static_sources() {
        for (enabled, source_type) in [(false, "clash"), (true, "static")] {
            let mut service = IngressControlService::new();
            let id = SubscriptionId::new(format!("{source_type}-{enabled}")).unwrap();
            service
                .add_subscription(
                    "operator",
                    RequestId::new(1),
                    0,
                    SubscriptionSpec {
                        id: id.clone(),
                        source_type: source_type.into(),
                        display_name: "Provider".into(),
                        enabled,
                        url: "https://example.invalid/subscription".into(),
                        credentials_ref: None,
                        refresh: SubscriptionRefreshSpec::default(),
                        cache: None,
                    },
                )
                .unwrap();
            assert!(matches!(
                service.request_subscription_refresh_with_generation(
                    "operator",
                    RequestId::new(2),
                    1,
                    &id
                ),
                Err(ControlError::InvalidSubscription { .. })
            ));
            assert!(service.next_queued_subscription_refresh().is_none());
            assert_eq!(service.snapshot().subscriptions[&id].revision, 0);
        }
    }

    #[test]
    fn refresh_checks_revision_and_replays_before_current_revision_changes() {
        let mut service = IngressControlService::new();
        let id = SubscriptionId::new("provider").unwrap();
        service
            .add_subscription(
                "operator",
                RequestId::new(1),
                0,
                SubscriptionSpec {
                    id: id.clone(),
                    source_type: "clash".into(),
                    display_name: "Provider".into(),
                    enabled: true,
                    url: "https://example.invalid/subscription".into(),
                    credentials_ref: None,
                    refresh: SubscriptionRefreshSpec::default(),
                    cache: None,
                },
            )
            .unwrap();
        assert!(matches!(
            service.request_subscription_refresh_checked("operator", RequestId::new(2), 1, &id, 1),
            Err(ControlError::RevisionConflict {
                expected: 1,
                current: 0
            })
        ));
        let first = service
            .request_subscription_refresh_checked("operator", RequestId::new(3), 1, &id, 0)
            .unwrap();
        service
            .complete_subscription_refresh(&id, true, None)
            .unwrap();
        let replay = service
            .request_subscription_refresh_checked("operator", RequestId::new(3), 1, &id, 0)
            .unwrap();
        assert!(replay.replayed);
        assert_eq!(replay.generation, first.generation);
        assert_eq!(service.snapshot().subscriptions[&id].revision, 1);
    }

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
                    diagnostic: None,
                    usage: None,
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
        assert_eq!(snapshot.runtime.target_connections, 1);
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
                    rtt_ms: Some(12),
                    jitter_ms: Some(3),
                    loss_ppm: Some(4_000),
                    throughput_bps: Some(5_000_000),
                    reordering_events: Some(6),
                    exclusion_reason: Some("status_stale".into()),
                }],
            )
            .unwrap();
        let snapshot = service.observation_snapshot();
        let path = snapshot.paths.get(&path_id).expect("path observation");
        assert_eq!(path.rtt_ms, Some(12));
        assert_eq!(path.jitter_ms, Some(3));
        assert_eq!(path.loss_ppm, Some(4_000));
        assert_eq!(path.throughput_bps, Some(5_000_000));
        assert_eq!(path.reordering_events, Some(6));
        assert_eq!(path.exclusion_reason.as_deref(), Some("status_stale"));
    }

    #[test]
    fn connection_churn_keeps_live_state_and_bounds_terminal_history() {
        let service = IngressControlService::new();
        let handle = service.observation_handle();
        let listener_id = ListenerId::new("history-test");
        handle
            .apply_listener_event(crate::ListenerRuntimeEvent::ConnectionAccepted {
                listener_id: listener_id.clone(),
                connection_id: "still-live".into(),
                target_display: "live.example:443".into(),
            })
            .unwrap();
        for index in 0..=MAX_CONNECTION_OBSERVATIONS {
            let id = format!("finished-{index}");
            handle
                .apply_listener_event(crate::ListenerRuntimeEvent::ConnectionAccepted {
                    listener_id: listener_id.clone(),
                    connection_id: id.clone(),
                    target_display: "target.example:443".into(),
                })
                .unwrap();
            handle
                .apply_listener_event(crate::ListenerRuntimeEvent::ConnectionCompleted {
                    listener_id: listener_id.clone(),
                    connection_id: id,
                    stats: crate::FlowBridgeStats {
                        local_to_target_bytes: 11,
                        target_to_local_bytes: 22,
                    },
                })
                .unwrap();
        }
        let snapshot = service.observation_snapshot();
        assert_eq!(snapshot.connections.len(), MAX_CONNECTION_HISTORY + 1);
        assert_eq!(
            snapshot.connection_listeners.len(),
            snapshot.connections.len()
        );
        assert_eq!(snapshot.runtime.target_connections, 1);
        assert_eq!(
            snapshot.connections["still-live"].state,
            ConnectionState::Open
        );
        assert!(!snapshot.connections.contains_key("finished-0"));
        assert_eq!(
            snapshot.connections[&format!("finished-{MAX_CONNECTION_OBSERVATIONS}")].bytes_received,
            22
        );
        assert!(snapshot.resource_limits.contains("connection_history"));
        let state = handle.state.lock().unwrap();
        assert_eq!(state.closed_connection_ids.len(), MAX_CONNECTION_HISTORY);
        assert!(state.pending_events.len() <= MAX_EVENT_COUNT);
    }

    #[test]
    fn connection_limit_preserves_live_records_and_recovers_after_close() {
        let service = IngressControlService::new();
        let handle = service.observation_handle();
        let observation = |id: String, state| ConnectionObservation {
            connection_id: id,
            session_id: None,
            stream_id: None,
            state,
            bytes_sent: 0,
            bytes_received: 0,
            target_display: None,
        };
        {
            let mut state = handle.state.lock().unwrap();
            for index in 0..MAX_CONNECTION_OBSERVATIONS {
                let id = format!("live-{index}");
                state
                    .connections
                    .insert(id.clone(), observation(id, ConnectionState::Open));
            }
            refresh_target_connection_count(&mut state);
        }
        assert!(matches!(
            handle
                .set_connection_observation(observation("next-live".into(), ConnectionState::Open)),
            Err(ControlError::ResourceLimit { .. })
        ));
        let full = service.observation_snapshot();
        assert_eq!(full.connections.len(), MAX_CONNECTION_OBSERVATIONS);
        assert!(full.connections.values().all(connection_is_live));
        assert!(full.resource_limits.contains("connection_observations"));
        handle
            .set_connection_observation(observation("live-0".into(), ConnectionState::Closed))
            .unwrap();
        handle
            .set_connection_observation(observation("next-live".into(), ConnectionState::Open))
            .unwrap();
        let recovered = service.observation_snapshot();
        assert_eq!(recovered.connections.len(), MAX_CONNECTION_OBSERVATIONS);
        assert_eq!(
            recovered.runtime.target_connections,
            MAX_CONNECTION_OBSERVATIONS as u64
        );
        assert!(!recovered.connections.contains_key("live-0"));
        assert!(recovered.connections.contains_key("live-1"));
        assert!(recovered.connections.contains_key("next-live"));
        assert!(
            !recovered
                .resource_limits
                .contains("connection_observations")
        );
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
