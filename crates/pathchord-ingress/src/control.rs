//! Typed Ingress control/query service.
//!
//! This module is deliberately transport-neutral. The local JSON protocol and
//! a future REST/SSE or GraphQL adapter should call this service instead of
//! editing configuration, caches, or runtime state directly.

use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

use pathchord_core::{RequestId, SessionId, StreamId};
use thiserror::Error;

pub const MAX_NODE_COUNT: usize = 4096;
pub const MAX_SUBSCRIPTION_COUNT: usize = 256;
pub const MAX_EVENT_COUNT: usize = 2048;
pub const MAX_REQUEST_CACHE_COUNT: usize = 4096;
pub const MAX_REFRESH_QUEUE_COUNT: usize = 256;
pub const MAX_CONNECTION_OBSERVATIONS: usize = 16_384;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NodeId(String);

impl NodeId {
    pub fn new(value: impl Into<String>) -> Result<Self, ControlError> {
        let value = value.into();
        if value.is_empty() {
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
        if value.is_empty() {
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
pub struct SubscriptionSpec {
    pub id: SubscriptionId,
    pub source_type: String,
    pub display_name: String,
    pub enabled: bool,
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
    pub session_id: SessionId,
    pub stream_id: Option<StreamId>,
    pub state: ConnectionState,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    /// Already-redacted display value; raw target credentials and payloads are
    /// intentionally not representable here.
    pub target_display: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservationSnapshot {
    pub generation: u64,
    pub captured_at_ms: u64,
    pub node_count: usize,
    pub subscription_count: usize,
    pub queued_refreshes: usize,
    pub runtime: RuntimeCounts,
    pub nodes: BTreeMap<NodeId, NodeObservation>,
    pub connections: BTreeMap<String, ConnectionObservation>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControlEventKind {
    NodeChanged,
    SubscriptionChanged,
    SubscriptionRefreshRequested,
    ObservationChanged,
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
    #[error("generation conflict: expected {expected}, current {current}")]
    GenerationConflict { expected: u64, current: u64 },
    #[error("request {request_id} was reused with a different command")]
    IdempotencyConflict { request_id: RequestId },
    #[error("refresh for subscription {0} is already queued")]
    RefreshAlreadyQueued(SubscriptionId),
    #[error("actor identity must not be empty")]
    EmptyActor,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CachedCommand {
    fingerprint: String,
    receipt: MutationReceipt,
}

/// In-memory Phase-1 control service. Persistence and network refresh workers
/// are intentionally injected later; this type defines their stable boundary.
#[derive(Debug)]
pub struct IngressControlService {
    snapshot: IngressControlSnapshot,
    observation_generation: u64,
    runtime: RuntimeCounts,
    node_observations: BTreeMap<NodeId, NodeObservation>,
    connection_observations: BTreeMap<String, ConnectionObservation>,
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

impl IngressControlService {
    #[must_use]
    pub fn new() -> Self {
        Self {
            snapshot: IngressControlSnapshot {
                generation: 0,
                nodes: BTreeMap::new(),
                subscriptions: BTreeMap::new(),
            },
            observation_generation: 0,
            runtime: RuntimeCounts::default(),
            node_observations: BTreeMap::new(),
            connection_observations: BTreeMap::new(),
            events: VecDeque::new(),
            refresh_queue: VecDeque::new(),
            request_cache: HashMap::new(),
            next_event_id: 0,
        }
    }

    #[must_use]
    pub fn snapshot(&self) -> IngressControlSnapshot {
        self.snapshot.clone()
    }

    #[must_use]
    pub fn observation_snapshot(&self) -> ObservationSnapshot {
        ObservationSnapshot {
            generation: self.observation_generation,
            captured_at_ms: now_ms(),
            node_count: self.snapshot.nodes.len(),
            subscription_count: self.snapshot.subscriptions.len(),
            queued_refreshes: self.refresh_queue.len(),
            runtime: self.runtime,
            nodes: self.node_observations.clone(),
            connections: self.connection_observations.clone(),
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
        self.node_observations.insert(node_id.clone(), observation);
        self.observation_generation = self.observation_generation.saturating_add(1);
        Ok(self.emit(ControlEventKind::ObservationChanged, node_id.0))
    }

    pub fn set_connection_observation(
        &mut self,
        observation: ConnectionObservation,
    ) -> Result<MutationReceipt, ControlError> {
        if observation.connection_id.is_empty() {
            return Err(ControlError::InvalidIdentifier { kind: "connection" });
        }
        if !self
            .connection_observations
            .contains_key(&observation.connection_id)
            && self.connection_observations.len() >= MAX_CONNECTION_OBSERVATIONS
        {
            return Err(ControlError::ResourceLimit {
                resource: "connection observations",
            });
        }
        let id = observation.connection_id.clone();
        self.connection_observations.insert(id.clone(), observation);
        self.observation_generation = self.observation_generation.saturating_add(1);
        Ok(self.emit(ControlEventKind::ObservationChanged, id))
    }

    pub fn remove_connection_observation(
        &mut self,
        connection_id: &str,
    ) -> Option<ConnectionObservation> {
        let removed = self.connection_observations.remove(connection_id);
        if removed.is_some() {
            self.observation_generation = self.observation_generation.saturating_add(1);
            self.emit(
                ControlEventKind::ObservationChanged,
                connection_id.to_owned(),
            );
        }
        removed
    }

    pub fn set_runtime_counts(&mut self, counts: RuntimeCounts) -> MutationReceipt {
        self.runtime = counts;
        self.observation_generation = self.observation_generation.saturating_add(1);
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
        self.snapshot.generation += 1;
        let receipt = self.emit(ControlEventKind::NodeChanged, node_id.0.clone());
        self.cache(actor, request_id, fingerprint, receipt)?;
        Ok(receipt)
    }

    pub fn add_node(&mut self, node_id: NodeId) -> Result<(), ControlError> {
        if self.snapshot.nodes.len() >= MAX_NODE_COUNT {
            return Err(ControlError::ResourceLimit { resource: "nodes" });
        }
        self.snapshot.nodes.entry(node_id).or_default();
        Ok(())
    }

    pub fn add_subscription(
        &mut self,
        actor: &str,
        request_id: RequestId,
        expected_generation: u64,
        spec: SubscriptionSpec,
    ) -> Result<MutationReceipt, ControlError> {
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
        let id = spec.id.clone();
        self.snapshot.subscriptions.insert(
            id.clone(),
            SubscriptionState {
                spec,
                revision: 0,
                refresh_state: SubscriptionRefreshState::Idle,
                last_error: None,
            },
        );
        self.snapshot.generation += 1;
        let receipt = self.emit(ControlEventKind::SubscriptionChanged, id.0);
        self.cache(actor, request_id, fingerprint, receipt)?;
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
        self.snapshot
            .subscriptions
            .remove(id)
            .ok_or_else(|| ControlError::SubscriptionNotFound(id.clone()))?;
        self.refresh_queue.retain(|queued| queued != id);
        self.snapshot.generation += 1;
        let receipt = self.emit(ControlEventKind::SubscriptionChanged, id.0.clone());
        self.cache(actor, request_id, fingerprint, receipt)?;
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
        self.cache(actor, request_id, fingerprint, receipt)?;
        Ok(receipt)
    }

    /// Completes one queued refresh. A failed refresh leaves the existing
    /// subscription revision and imported node snapshot untouched.
    pub fn complete_subscription_refresh(
        &mut self,
        id: &SubscriptionId,
        success: bool,
        error: Option<String>,
    ) -> Result<MutationReceipt, ControlError> {
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
        self.snapshot.generation += 1;
        Ok(self.emit(ControlEventKind::SubscriptionChanged, id.0.clone()))
    }

    fn check_actor(&self, actor: &str) -> Result<(), ControlError> {
        if actor.is_empty() {
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
        self.request_cache.insert(
            (actor.to_owned(), request_id),
            CachedCommand {
                fingerprint,
                receipt,
            },
        );
        Ok(())
    }

    fn ensure_cache_capacity(
        &self,
        actor: &str,
        request_id: RequestId,
    ) -> Result<(), ControlError> {
        if self.request_cache.len() >= MAX_REQUEST_CACHE_COUNT
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
                session_id: SessionId::new(1),
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
}
