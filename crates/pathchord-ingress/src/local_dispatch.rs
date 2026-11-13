//! Typed operation dispatch for the local control-plane envelope.
//!
//! This layer deliberately owns request validation and response shaping while
//! leaving sockets, named pipes, and platform side effects to adapters.

use std::collections::{BTreeMap, BTreeSet};
use std::hash::{Hash, Hasher};
use std::sync::Arc;

use pathchord_core::management::ManagementDispatcher;
use serde_json::{Value, json};

use crate::{
    ErrorBody, ErrorCode, GenerationExpectation, IngressControlService, LOCAL_API_VERSION,
    ListenerDescriptor, NodeAdminPatch, PlatformProxyAdapter, RequestEnvelope, ResponseEnvelope,
    SubscriptionCacheSpec, SubscriptionRefreshSpec, SubscriptionSpec, SystemProxyPlatform,
};
use pathchord_core::RequestId;
use pathchord_policy::ListenerId;

/// Synchronous, transport-neutral dispatcher for local management operations.
#[derive(Debug)]
pub struct LocalControlDispatcher {
    service: IngressControlService,
    platform: SystemProxyPlatform,
}

impl LocalControlDispatcher {
    #[must_use]
    pub fn new(platform: SystemProxyPlatform) -> Self {
        Self {
            service: IngressControlService::with_platform_proxy(default_platform_adapter(platform)),
            platform,
        }
    }

    #[must_use]
    pub fn with_platform_proxy(
        platform: SystemProxyPlatform,
        adapter: Arc<dyn PlatformProxyAdapter>,
    ) -> Self {
        Self {
            service: IngressControlService::with_platform_proxy(adapter),
            platform,
        }
    }

    #[must_use]
    pub fn with_service(platform: SystemProxyPlatform, service: IngressControlService) -> Self {
        Self { service, platform }
    }

    pub fn service_mut(&mut self) -> &mut IngressControlService {
        &mut self.service
    }

    #[must_use]
    pub fn service(&self) -> &IngressControlService {
        &self.service
    }

    /// Dispatches one validated request and always returns a typed response.
    #[must_use]
    pub fn dispatch(&mut self, request: RequestEnvelope) -> ResponseEnvelope {
        let request_id = request.request_id.clone();
        let observed = self.observed_generation();
        if request.api_version != LOCAL_API_VERSION {
            return self.failure(
                request_id,
                observed,
                ErrorCode::UnsupportedOperation,
                "unsupported API version",
                Some(json!({"api_version": request.api_version})),
            );
        }
        if request.actor.id.is_empty() {
            return self.failure(
                request_id,
                observed,
                ErrorCode::AuthenticationRequired,
                "actor identity is required",
                None,
            );
        }

        match request.operation.as_str() {
            "status.get" => self.dispatch_status(request),
            "nodes.list" => self.dispatch_nodes_list(request),
            "nodes.get" => self.dispatch_node_get(request),
            "nodes.patch_labels" => self.dispatch_node_patch(request, false),
            "nodes.patch_tags" => self.dispatch_node_patch(request, true),
            "sessions.list" => self.dispatch_sessions_list(request),
            "sessions.get" => self.dispatch_session_get(request),
            "connections.list" => self.dispatch_connections_list(request),
            "listeners.list" => self.dispatch_listeners(request),
            "subscriptions.list" => self.dispatch_subscriptions_list(request),
            "subscriptions.create" => self.dispatch_subscription_create(request),
            "subscriptions.delete" => self.dispatch_subscription_delete(request),
            "subscriptions.enable" => self.dispatch_subscription_enabled(request, true),
            "subscriptions.disable" => self.dispatch_subscription_enabled(request, false),
            "subscriptions.refresh" => self.dispatch_subscription_refresh(request),
            "metrics.snapshot" => self.dispatch_metrics_snapshot(request),
            "metrics.paths" => self.dispatch_path_metrics(request),
            "metrics.streams" => self.dispatch_stream_metrics(request),
            "events.subscribe" => self.dispatch_events(request),
            "system_proxy.get" => self.dispatch_system_proxy_get(request),
            "system_proxy.enable" => self.dispatch_system_proxy_enable(request),
            "system_proxy.disable" => self.dispatch_system_proxy_disable(request),
            operation => self.failure(
                request_id,
                observed,
                ErrorCode::UnsupportedOperation,
                "operation is not supported",
                Some(json!({"operation": operation})),
            ),
        }
    }

    fn dispatch_status(&self, request: RequestEnvelope) -> ResponseEnvelope {
        if let Err(response) = self.require_capability(&request, "status:read") {
            return *response;
        }
        let snapshot = self.service.observation_snapshot();
        let runtime_state = match snapshot.runtime_state {
            crate::control::RuntimeSnapshotState::Fresh => "fresh",
            crate::control::RuntimeSnapshotState::Stale => "stale",
            crate::control::RuntimeSnapshotState::Unavailable => "unavailable",
        };
        let data_path_summary = match snapshot.runtime_state {
            crate::control::RuntimeSnapshotState::Unavailable => "down",
            crate::control::RuntimeSnapshotState::Stale => "degraded",
            crate::control::RuntimeSnapshotState::Fresh
                if snapshot.runtime.sessions > 0 && snapshot.runtime.ready_paths == 0 =>
            {
                "degraded"
            }
            crate::control::RuntimeSnapshotState::Fresh
                if snapshot.runtime.sessions > 0 && snapshot.runtime.ready_paths > 0 =>
            {
                "connected"
            }
            crate::control::RuntimeSnapshotState::Fresh => "down",
        };
        self.success(
            request.request_id,
            json!({
                "ingress": {"state": "running"},
                "control_plane": {"state": "running"},
                "runtime_snapshot": {"state": runtime_state, "generation": snapshot.generation},
                "data_path_summary": data_path_summary,
                "configuration_generation": self.service.snapshot().generation,
                "observation_generation": snapshot.generation,
                "sessions": snapshot.runtime.sessions,
                "ready_paths": snapshot.runtime.ready_paths,
                "streams": snapshot.runtime.streams,
                "target_connections": snapshot.runtime.target_connections,
                "system_proxy": self.system_proxy_value(),
            }),
        )
    }

    fn dispatch_listeners(&self, request: RequestEnvelope) -> ResponseEnvelope {
        if let Err(response) = self.require_capability(&request, "listeners:read") {
            return *response;
        }
        let generation = self.service.snapshot().generation;
        let query = match ListenerListQuery::parse(&request.body) {
            Ok(query) => query,
            Err(message) => {
                return self.failure(
                    request.request_id,
                    self.observed_generation(),
                    ErrorCode::ValidationFailed,
                    &message,
                    None,
                );
            }
        };
        let mut descriptors: Vec<_> = self.service.listeners().into_values().collect();
        descriptors.retain(|descriptor| query.matches(descriptor));
        descriptors.sort_by(|left, right| query.compare(left, right));
        let end = query
            .offset
            .saturating_add(query.page_size)
            .min(descriptors.len());
        let page = if query.offset < descriptors.len() {
            &descriptors[query.offset..end]
        } else {
            &[]
        };
        let items: Vec<_> = page
            .iter()
            .map(|descriptor| listener_value(descriptor, generation))
            .collect();
        let next_page_token = if end < descriptors.len() {
            Some(end.to_string())
        } else {
            None
        };
        self.success(
            request.request_id,
            json!({"items": items, "next_page_token": next_page_token}),
        )
    }

    fn dispatch_nodes_list(&self, request: RequestEnvelope) -> ResponseEnvelope {
        if let Err(response) = self.require_capability(&request, "nodes:read") {
            return *response;
        }
        let snapshot = self.service.snapshot();
        let items: Vec<_> = snapshot
            .nodes
            .iter()
            .map(|(id, state)| {
                json!({
                    "id": id.as_str(),
                    "admin": {"labels": state.labels, "tags": state.tags},
                    "generation": snapshot.generation,
                })
            })
            .collect();
        self.success(
            request.request_id,
            json!({"items": items, "next_page_token": Value::Null}),
        )
    }

    fn dispatch_node_get(&self, request: RequestEnvelope) -> ResponseEnvelope {
        if let Err(response) = self.require_capability(&request, "nodes:read") {
            return *response;
        }
        let Some(node_id) = request.body.get("node_id").and_then(Value::as_str) else {
            return self.failure(
                request.request_id,
                self.observed_generation(),
                ErrorCode::ValidationFailed,
                "node_id is required",
                None,
            );
        };
        let snapshot = self.service.snapshot();
        let Some((id, state)) = snapshot.nodes.iter().find(|(id, _)| id.as_str() == node_id) else {
            return self.failure(
                request.request_id,
                self.observed_generation(),
                ErrorCode::NotFound,
                "node was not found",
                None,
            );
        };
        self.success(
            request.request_id,
            json!({
                "id": id.as_str(),
                "admin": {"labels": state.labels, "tags": state.tags},
                "generation": snapshot.generation,
            }),
        )
    }

    fn dispatch_node_patch(
        &mut self,
        request: RequestEnvelope,
        tags_only: bool,
    ) -> ResponseEnvelope {
        if let Err(response) = self.require_capability(&request, "nodes:write") {
            return *response;
        }
        let expected = match self.required_configuration_generation(&request) {
            Ok(value) => value,
            Err(response) => return *response,
        };
        let node_id = match request.body.get("node_id").and_then(Value::as_str) {
            Some(value) => match crate::NodeId::new(value) {
                Ok(id) => id,
                Err(error) => return self.control_error(request.request_id, error),
            },
            None => {
                return self.failure(
                    request.request_id,
                    self.observed_generation(),
                    ErrorCode::ValidationFailed,
                    "node_id is required",
                    None,
                );
            }
        };
        let patch = if tags_only {
            NodeAdminPatch {
                add_tags: parse_string_set(request.body.get("add")),
                remove_tags: parse_string_set(request.body.get("remove")),
                ..NodeAdminPatch::default()
            }
        } else {
            NodeAdminPatch {
                set_labels: parse_string_map(request.body.get("set")),
                remove_labels: parse_string_set(request.body.get("remove")),
                ..NodeAdminPatch::default()
            }
        };
        let internal_request_id = match request_id(&request.request_id) {
            Ok(value) => value,
            Err(message) => {
                return self.failure(
                    request.request_id,
                    self.observed_generation(),
                    ErrorCode::ValidationFailed,
                    &message,
                    None,
                );
            }
        };
        match self.service.patch_node(
            &request.actor.id,
            internal_request_id,
            node_id.clone(),
            expected,
            patch,
        ) {
            Ok(receipt) => self.success(
                request.request_id,
                json!({
                    "applied_generation": {"scope": "configuration", "value": receipt.generation},
                    "resource": {"node_id": node_id.as_str()},
                    "cleanup": zero_cleanup(),
                }),
            ),
            Err(error) => self.control_error(request.request_id, error),
        }
    }

    fn dispatch_subscription_create(&mut self, request: RequestEnvelope) -> ResponseEnvelope {
        if let Err(response) = self.require_capability(&request, "subscriptions:write") {
            return *response;
        }
        let expected = match self.required_configuration_generation(&request) {
            Ok(value) => value,
            Err(response) => return *response,
        };
        let spec = match parse_subscription_spec(&request.body) {
            Ok(spec) => spec,
            Err(message) => {
                return self.failure(
                    request.request_id,
                    self.observed_generation(),
                    ErrorCode::ValidationFailed,
                    &message,
                    None,
                );
            }
        };
        let internal_request_id = match request_id(&request.request_id) {
            Ok(value) => value,
            Err(message) => {
                return self.failure(
                    request.request_id,
                    self.observed_generation(),
                    ErrorCode::ValidationFailed,
                    &message,
                    None,
                );
            }
        };
        match self.service.add_subscription(
            &request.actor.id,
            internal_request_id,
            expected,
            spec.clone(),
        ) {
            Ok(receipt) => self.success(
                request.request_id,
                json!({
                    "applied_generation": {"scope": "configuration", "value": receipt.generation},
                    "resource": {"id": spec.id.as_str(), "state": "configured"},
                    "cleanup": zero_cleanup(),
                }),
            ),
            Err(error) => self.control_error(request.request_id, error),
        }
    }

    fn dispatch_subscription_delete(&mut self, request: RequestEnvelope) -> ResponseEnvelope {
        if let Err(response) = self.require_capability(&request, "subscriptions:write") {
            return *response;
        }
        let expected = match self.required_configuration_generation(&request) {
            Ok(value) => value,
            Err(response) => return *response,
        };
        let id = match subscription_id_from_body(&request.body) {
            Ok(id) => id,
            Err(message) => {
                return self.failure(
                    request.request_id,
                    self.observed_generation(),
                    ErrorCode::ValidationFailed,
                    &message,
                    None,
                );
            }
        };
        let internal_request_id = match request_id(&request.request_id) {
            Ok(value) => value,
            Err(message) => {
                return self.failure(
                    request.request_id,
                    self.observed_generation(),
                    ErrorCode::ValidationFailed,
                    &message,
                    None,
                );
            }
        };
        match self.service.delete_subscription(
            &request.actor.id,
            internal_request_id,
            expected,
            &id,
        ) {
            Ok(receipt) => self.success(
                request.request_id,
                json!({
                    "applied_generation": {"scope": "configuration", "value": receipt.generation},
                    "resource": {"id": id.as_str(), "state": "deleted"},
                    "cleanup": zero_cleanup(),
                }),
            ),
            Err(error) => self.control_error(request.request_id, error),
        }
    }

    fn dispatch_subscription_enabled(
        &mut self,
        request: RequestEnvelope,
        enabled: bool,
    ) -> ResponseEnvelope {
        if let Err(response) = self.require_capability(&request, "subscriptions:write") {
            return *response;
        }
        let expected = match self.required_configuration_generation(&request) {
            Ok(value) => value,
            Err(response) => return *response,
        };
        let id = match subscription_id_from_body(&request.body) {
            Ok(id) => id,
            Err(message) => {
                return self.failure(
                    request.request_id,
                    self.observed_generation(),
                    ErrorCode::ValidationFailed,
                    &message,
                    None,
                );
            }
        };
        let internal_request_id = match request_id(&request.request_id) {
            Ok(value) => value,
            Err(message) => {
                return self.failure(
                    request.request_id,
                    self.observed_generation(),
                    ErrorCode::ValidationFailed,
                    &message,
                    None,
                );
            }
        };
        match self.service.set_subscription_enabled(
            &request.actor.id,
            internal_request_id,
            expected,
            &id,
            enabled,
        ) {
            Ok(receipt) => self.success(
                request.request_id,
                json!({
                    "applied_generation": {"scope": "configuration", "value": receipt.generation},
                    "resource": {"id": id.as_str(), "state": if enabled {"enabled"} else {"disabled"}},
                    "cleanup": zero_cleanup(),
                }),
            ),
            Err(error) => self.control_error(request.request_id, error),
        }
    }

    fn dispatch_subscription_refresh(&mut self, request: RequestEnvelope) -> ResponseEnvelope {
        if let Err(response) = self.require_capability(&request, "subscriptions:write") {
            return *response;
        }
        let id = match subscription_id_from_body(&request.body) {
            Ok(id) => id,
            Err(message) => {
                return self.failure(
                    request.request_id,
                    self.observed_generation(),
                    ErrorCode::ValidationFailed,
                    &message,
                    None,
                );
            }
        };
        let internal_request_id = match request_id(&request.request_id) {
            Ok(value) => value,
            Err(message) => {
                return self.failure(
                    request.request_id,
                    self.observed_generation(),
                    ErrorCode::ValidationFailed,
                    &message,
                    None,
                );
            }
        };
        match self
            .service
            .request_subscription_refresh(&request.actor.id, internal_request_id, &id)
        {
            Ok(receipt) => self.success(
                request.request_id,
                json!({
                    "applied_generation": {"scope": "configuration", "value": receipt.generation},
                    "resource": {"id": id.as_str(), "state": "refresh_queued"},
                    "cleanup": zero_cleanup(),
                }),
            ),
            Err(error) => self.control_error(request.request_id, error),
        }
    }

    fn dispatch_subscriptions_list(&self, request: RequestEnvelope) -> ResponseEnvelope {
        if let Err(response) = self.require_capability(&request, "status:read") {
            return *response;
        }
        let snapshot = self.service.snapshot();
        let items: Vec<_> = snapshot
            .subscriptions
            .values()
            .map(|subscription| {
                json!({
                    "id": subscription.spec.id.as_str(),
                    "display_name": subscription.spec.display_name,
                    "source_type": subscription.spec.source_type,
                    "source": {
                        "type": subscription.spec.source_type,
                        "url": subscription.spec.url,
                        "credentials_ref": subscription.spec.credentials_ref,
                    },
                    "refresh": {
                        "interval_seconds": subscription.spec.refresh.interval_seconds,
                        "timeout_seconds": subscription.spec.refresh.timeout_seconds,
                        "max_attempts": subscription.spec.refresh.max_attempts,
                        "backoff_seconds": subscription.spec.refresh.backoff_seconds,
                    },
                    "cache": subscription.spec.cache.as_ref().map(|cache| json!({
                        "path": cache.path,
                        "max_age_seconds": cache.max_age_seconds,
                    })),
                    "enabled": subscription.spec.enabled,
                    "revision": subscription.revision,
                    "state": format!("{:?}", subscription.refresh_state).to_ascii_lowercase(),
                    "last_refresh_at": subscription.last_refresh_at_ms,
                    "next_refresh_at": Value::Null,
                    "imported_node_count": 0,
                    "last_error": subscription.last_error,
                })
            })
            .collect();
        self.success(
            request.request_id,
            json!({"items": items, "next_page_token": Value::Null}),
        )
    }

    fn dispatch_sessions_list(&self, request: RequestEnvelope) -> ResponseEnvelope {
        if let Err(response) = self.require_capability(&request, "status:read") {
            return *response;
        }
        let snapshot = self.service.observation_snapshot();
        let items: Vec<_> = snapshot.sessions.values().map(session_value).collect();
        self.success(
            request.request_id,
            json!({"items": items, "next_page_token": Value::Null}),
        )
    }

    fn dispatch_session_get(&self, request: RequestEnvelope) -> ResponseEnvelope {
        if let Err(response) = self.require_capability(&request, "status:read") {
            return *response;
        }
        let Some(session_id) = request.body.get("session_id").and_then(Value::as_str) else {
            return self.failure(
                request.request_id,
                self.observed_generation(),
                ErrorCode::ValidationFailed,
                "session_id is required",
                None,
            );
        };
        let snapshot = self.service.observation_snapshot();
        let Some(session) = snapshot
            .sessions
            .values()
            .find(|session| session.session_id.to_string() == session_id)
        else {
            return self.failure(
                request.request_id,
                self.observed_generation(),
                ErrorCode::NotFound,
                "Session was not found",
                None,
            );
        };
        self.success(request.request_id, session_value(session))
    }

    fn dispatch_connections_list(&self, request: RequestEnvelope) -> ResponseEnvelope {
        if let Err(response) = self.require_capability(&request, "metrics:read") {
            return *response;
        }
        let reveal_targets = request
            .actor
            .capabilities
            .iter()
            .any(|capability| capability == "targets:read");
        let snapshot = self.service.observation_snapshot();
        let items: Vec<_> = snapshot
            .connections
            .values()
            .map(|connection| {
                json!({
                    "connection_id": connection.connection_id,
                    "session_id": connection.session_id.map(|id| id.to_string()),
                    "stream_id": connection.stream_id.map(|id| id.get()),
                    "state": format!("{:?}", connection.state).to_ascii_lowercase(),
                    "bytes_sent": connection.bytes_sent,
                    "bytes_received": connection.bytes_received,
                    "target": if reveal_targets { connection.target_display.clone() } else { None },
                    "target_redacted": !reveal_targets && connection.target_display.is_some(),
                })
            })
            .collect();
        self.success(
            request.request_id,
            json!({"items": items, "next_page_token": Value::Null}),
        )
    }

    fn dispatch_metrics_snapshot(&self, request: RequestEnvelope) -> ResponseEnvelope {
        if let Err(response) = self.require_capability(&request, "metrics:read") {
            return *response;
        }
        let snapshot = self.service.observation_snapshot();
        self.success(
            request.request_id,
            json!({
                "captured_at_ms": snapshot.captured_at_ms,
                "generation": snapshot.generation,
                "runtime": {
                    "sessions": snapshot.runtime.sessions,
                    "ready_paths": snapshot.runtime.ready_paths,
                    "streams": snapshot.runtime.streams,
                    "target_connections": snapshot.runtime.target_connections,
                },
                "nodes": snapshot.nodes.len(),
                "connections": snapshot.connections.len(),
            }),
        )
    }

    fn dispatch_path_metrics(&self, request: RequestEnvelope) -> ResponseEnvelope {
        if let Err(response) = self.require_capability(&request, "metrics:read") {
            return *response;
        }
        let snapshot = self.service.observation_snapshot();
        let items: Vec<_> = snapshot
            .paths
            .values()
            .map(|path| {
                json!({
                    "path_id": path.path_id.to_string(),
                    "session_id": path.session_id.to_string(),
                    "state": format!("{:?}", path.state).to_ascii_lowercase(),
                    "rtt_ms": path.rtt_ms,
                    "jitter_ms": path.jitter_ms,
                    "loss_ppm": path.loss_ppm,
                    "throughput_bps": path.throughput_bps,
                    "reordering_events": path.reordering_events,
                    "exclusion_reason": path.exclusion_reason,
                })
            })
            .collect();
        self.success(request.request_id, json!({"items": items}))
    }

    fn dispatch_stream_metrics(&self, request: RequestEnvelope) -> ResponseEnvelope {
        if let Err(response) = self.require_capability(&request, "metrics:read") {
            return *response;
        }
        let snapshot = self.service.observation_snapshot();
        let items: Vec<_> = snapshot
            .sessions
            .values()
            .map(|session| {
                json!({
                    "session_id": session.session_id.to_string(),
                    "egress_id": session.egress_id,
                    "state": format!("{:?}", session.state).to_ascii_lowercase(),
                    "ready_paths": session.ready_paths,
                    "active_streams": session.active_streams,
                    "retained_outbound_bytes": session.retained_outbound_bytes,
                    "bytes_sent": session.bytes_sent,
                    "bytes_received": session.bytes_received,
                })
            })
            .collect();
        self.success(request.request_id, json!({"items": items}))
    }

    fn dispatch_events(&self, request: RequestEnvelope) -> ResponseEnvelope {
        if let Err(response) = self.require_capability(&request, "metrics:read") {
            return *response;
        }
        let last_event_id = request.body.get("last_event_id").and_then(Value::as_u64);
        let events: Vec<_> = self
            .service
            .events_since(last_event_id)
            .into_iter()
            .map(|event| {
                json!({
                    "id": event.id,
                    "generation": event.generation,
                    "type": format!("{:?}", event.kind).to_ascii_lowercase(),
                    "resource_id": event.resource_id,
                })
            })
            .collect();
        self.success(request.request_id, json!({"items": events}))
    }

    fn dispatch_system_proxy_get(&self, request: RequestEnvelope) -> ResponseEnvelope {
        if let Err(response) = self.require_capability(&request, "status:read") {
            return *response;
        }
        self.success(request.request_id, self.system_proxy_value())
    }

    fn dispatch_system_proxy_enable(&mut self, request: RequestEnvelope) -> ResponseEnvelope {
        if let Err(response) = self.require_capability(&request, "system_proxy:write") {
            return *response;
        }
        if let Some(response) = self.check_expected_generation(&request, "configuration") {
            return response;
        }
        let listener_id = match request.body.get("listener_id").and_then(Value::as_str) {
            Some(value) if !value.is_empty() => ListenerId::new(value),
            _ => {
                return self.failure(
                    request.request_id,
                    self.observed_generation(),
                    ErrorCode::ValidationFailed,
                    "listener_id is required",
                    None,
                );
            }
        };
        let internal_request_id = match request_id(&request.request_id) {
            Ok(value) => value,
            Err(message) => {
                return self.failure(
                    request.request_id,
                    self.observed_generation(),
                    ErrorCode::ValidationFailed,
                    &message,
                    None,
                );
            }
        };
        match self.service.enable_system_proxy(
            &request.actor.id,
            internal_request_id,
            self.platform,
            listener_id,
        ) {
            Ok(mutation) => self.success(
                request.request_id,
                json!({
                    "applied_generation": {"scope": "configuration", "value": mutation.generation},
                    "resource": self.system_proxy_value(),
                    "cleanup": zero_cleanup(),
                }),
            ),
            Err(error) => self.control_error(request.request_id, error),
        }
    }

    fn dispatch_system_proxy_disable(&mut self, request: RequestEnvelope) -> ResponseEnvelope {
        if let Err(response) = self.require_capability(&request, "system_proxy:write") {
            return *response;
        }
        if let Some(response) = self.check_expected_generation(&request, "configuration") {
            return response;
        }
        let internal_request_id = match request_id(&request.request_id) {
            Ok(value) => value,
            Err(message) => {
                return self.failure(
                    request.request_id,
                    self.observed_generation(),
                    ErrorCode::ValidationFailed,
                    &message,
                    None,
                );
            }
        };
        match self.service.disable_system_proxy(
            &request.actor.id,
            internal_request_id,
            self.platform,
        ) {
            Ok(mutation) => self.success(
                request.request_id,
                json!({
                    "applied_generation": {"scope": "configuration", "value": mutation.generation},
                    "resource": self.system_proxy_value(),
                    "cleanup": zero_cleanup(),
                }),
            ),
            Err(error) => self.control_error(request.request_id, error),
        }
    }

    fn require_capability(
        &self,
        request: &RequestEnvelope,
        capability: &str,
    ) -> Result<(), Box<ResponseEnvelope>> {
        if request
            .actor
            .capabilities
            .iter()
            .any(|value| value == capability)
        {
            Ok(())
        } else {
            Err(Box::new(self.failure(
                request.request_id.clone(),
                self.observed_generation(),
                ErrorCode::CapabilityDenied,
                "actor lacks the required capability",
                Some(json!({"capability": capability})),
            )))
        }
    }

    fn control_error(&self, request_id: String, error: crate::ControlError) -> ResponseEnvelope {
        let (code, message) = match error {
            crate::ControlError::UnsupportedOperation { .. } => {
                (ErrorCode::UnsupportedOperation, "operation is unsupported")
            }
            crate::ControlError::ListenerNotFound(_) => {
                (ErrorCode::NotFound, "listener was not found")
            }
            crate::ControlError::NodeNotFound(_) | crate::ControlError::SubscriptionNotFound(_) => {
                (ErrorCode::NotFound, "resource was not found")
            }
            crate::ControlError::SubscriptionExists(_) => {
                (ErrorCode::ValidationFailed, "subscription already exists")
            }
            crate::ControlError::InvalidSystemProxyListener { .. } => (
                ErrorCode::ValidationFailed,
                "listener cannot back system proxy",
            ),
            crate::ControlError::EmptyActor => (
                ErrorCode::AuthenticationRequired,
                "actor identity is required",
            ),
            crate::ControlError::GenerationConflict { .. } => {
                (ErrorCode::GenerationConflict, "generation conflict")
            }
            crate::ControlError::IdempotencyConflict { .. } => {
                (ErrorCode::IdempotencyConflict, "idempotency conflict")
            }
            crate::ControlError::PlatformProxy { .. } => (
                ErrorCode::PersistenceUnavailable,
                "platform system-proxy operation failed",
            ),
            _ => (ErrorCode::ValidationFailed, "control operation failed"),
        };
        self.failure(request_id, self.observed_generation(), code, message, None)
    }

    fn observed_generation(&self) -> GenerationExpectation {
        GenerationExpectation {
            scope: "observation".to_owned(),
            value: self.service.observation_snapshot().generation,
        }
    }

    fn check_expected_generation(
        &self,
        request: &RequestEnvelope,
        scope: &str,
    ) -> Option<ResponseEnvelope> {
        let expected = request.expected_generation.as_ref()?;
        let current = match scope {
            "configuration" => self.service.snapshot().generation,
            "observation" => self.service.observation_snapshot().generation,
            _ => {
                return Some(self.failure(
                    request.request_id.clone(),
                    self.observed_generation(),
                    ErrorCode::ValidationFailed,
                    "unsupported generation scope",
                    None,
                ));
            }
        };
        if expected.scope != scope || expected.value != current {
            Some(self.failure(
                request.request_id.clone(),
                self.observed_generation(),
                ErrorCode::GenerationConflict,
                "generation mismatch",
                Some(json!({
                    "expected": {"scope": expected.scope, "value": expected.value},
                    "current": {"scope": scope, "value": current},
                })),
            ))
        } else {
            None
        }
    }

    fn required_configuration_generation(
        &self,
        request: &RequestEnvelope,
    ) -> Result<u64, Box<ResponseEnvelope>> {
        match request.expected_generation.as_ref() {
            Some(expected) if expected.scope == "configuration" => Ok(expected.value),
            Some(_) => Err(Box::new(self.failure(
                request.request_id.clone(),
                self.observed_generation(),
                ErrorCode::ValidationFailed,
                "configuration generation precondition is required",
                None,
            ))),
            None => Err(Box::new(self.failure(
                request.request_id.clone(),
                self.observed_generation(),
                ErrorCode::ValidationFailed,
                "expected_generation is required for this mutation",
                None,
            ))),
        }
    }

    fn system_proxy_value(&self) -> Value {
        // Linux exposes ordinary listener inventory but has no system-proxy
        // activation state. Keep this response distinct from Windows'
        // disabled state so clients cannot mistake unsupported for restored.
        if self.platform == SystemProxyPlatform::Linux {
            return json!({
                "enabled": false,
                "listener_id": Value::Null,
                "platform_effect": "unsupported",
                "environment_applied": false,
                "operating_system_applied": false,
                "restoration_state": "not_required",
                "error": Value::Null,
            });
        }
        let status = self.service.system_proxy_status();
        json!({
            "enabled": status.enabled,
            "listener_id": status.listener_id.map(|value| value.as_str().to_owned()),
            "platform_effect": format!("{:?}", status.platform_effect).to_ascii_lowercase(),
            "environment_applied": status.environment_applied,
            "operating_system_applied": status.operating_system_applied,
            "restoration_state": format!("{:?}", status.restoration_state).to_ascii_lowercase(),
            "error": status.error,
        })
    }

    fn success(&self, request_id: String, result: Value) -> ResponseEnvelope {
        ResponseEnvelope::success(request_id, self.observed_generation(), result)
    }

    fn failure(
        &self,
        request_id: String,
        observed_generation: GenerationExpectation,
        code: ErrorCode,
        message: &str,
        details: Option<Value>,
    ) -> ResponseEnvelope {
        ResponseEnvelope::failure(
            request_id,
            observed_generation,
            ErrorBody {
                code,
                message: message.to_owned(),
                details,
            },
        )
    }
}

fn default_platform_adapter(platform: SystemProxyPlatform) -> Arc<dyn PlatformProxyAdapter> {
    match platform {
        SystemProxyPlatform::Linux => Arc::new(crate::UnsupportedPlatformProxyAdapter),
        SystemProxyPlatform::Windows => default_windows_platform_adapter(),
    }
}

#[cfg(all(windows, not(test)))]
fn default_windows_platform_adapter() -> Arc<dyn PlatformProxyAdapter> {
    Arc::new(crate::WindowsSystemProxyAdapter::default())
}

#[cfg(any(not(windows), test))]
fn default_windows_platform_adapter() -> Arc<dyn PlatformProxyAdapter> {
    Arc::new(crate::FakePlatformProxyAdapter::new())
}

impl Default for LocalControlDispatcher {
    fn default() -> Self {
        Self::new(crate::SystemProxyPlatform::Linux)
    }
}

#[async_trait::async_trait]
impl ManagementDispatcher for LocalControlDispatcher {
    async fn dispatch(&mut self, request: RequestEnvelope) -> ResponseEnvelope {
        LocalControlDispatcher::dispatch(self, request)
    }

    async fn record_authentication_failure(&mut self, source: &str) {
        let _ = self.service.record_authentication_failure(source);
    }
}

fn session_value(session: &crate::SessionObservation) -> Value {
    json!({
        "session_id": session.session_id.to_string(),
        "egress_id": session.egress_id,
        "state": format!("{:?}", session.state).to_ascii_lowercase(),
        "ready_paths": session.ready_paths,
        "active_streams": session.active_streams,
        "retained_outbound_bytes": session.retained_outbound_bytes,
        "bytes_sent": session.bytes_sent,
        "bytes_received": session.bytes_received,
    })
}

fn listener_value(descriptor: &ListenerDescriptor, generation: u64) -> Value {
    json!({
        "id": descriptor.id.as_str(),
        "kind": format!("{:?}", descriptor.kind).to_ascii_lowercase(),
        "platform": std::env::consts::OS,
        "bind": descriptor.bind.map(|value| value.to_string()),
        "interface": descriptor.interface,
        "address": descriptor.address,
        "mtu": descriptor.mtu,
        "flow_tags": descriptor.flow_tags,
        "process_metadata": descriptor.process_metadata,
        "allowed_sources": descriptor.allowed_sources,
        "authentication": if descriptor.authentication_required {"required"} else {"disabled"},
        "state": "available",
        "generation": generation,
        "status": {"reason": Value::Null},
    })
}

#[derive(Debug, Default)]
struct ListenerListQuery {
    page_size: usize,
    offset: usize,
    kind: Option<String>,
    platform: Option<String>,
    state: Option<String>,
    sort: String,
    descending: bool,
}

impl ListenerListQuery {
    fn parse(body: &Value) -> Result<Self, String> {
        let object = body
            .as_object()
            .ok_or_else(|| "listeners.list body must be an object".to_owned())?;
        for key in object.keys() {
            if !matches!(
                key.as_str(),
                "page_size" | "page_token" | "filter" | "sort" | "direction"
            ) {
                return Err(format!("unknown listeners.list query field: {key}"));
            }
        }
        let page_size = match object.get("page_size") {
            None => 100,
            Some(value) => value
                .as_u64()
                .and_then(|value| usize::try_from(value).ok())
                .filter(|value| (1..=1000).contains(value))
                .ok_or_else(|| "page_size must be an integer in 1..=1000".to_owned())?,
        };
        let offset = match object.get("page_token") {
            None | Some(Value::Null) => 0,
            Some(Value::String(value)) => value
                .parse::<usize>()
                .map_err(|_| "page_token is invalid".to_owned())?,
            Some(_) => return Err("page_token must be an opaque string".to_owned()),
        };
        let mut query = Self {
            page_size,
            offset,
            sort: "id".to_owned(),
            ..Self::default()
        };
        if let Some(filter) = object.get("filter") {
            let filter = filter
                .as_object()
                .ok_or_else(|| "filter must be an object".to_owned())?;
            for key in filter.keys() {
                if !matches!(key.as_str(), "kind" | "platform" | "state") {
                    return Err(format!("unknown listener filter field: {key}"));
                }
            }
            query.kind = filter
                .get("kind")
                .and_then(Value::as_str)
                .map(str::to_owned);
            query.platform = filter
                .get("platform")
                .and_then(Value::as_str)
                .map(str::to_owned);
            query.state = filter
                .get("state")
                .and_then(Value::as_str)
                .map(str::to_owned);
            if filter.values().any(|value| !value.is_string()) {
                return Err("listener filter values must be strings".to_owned());
            }
        }
        if let Some(sort) = object.get("sort") {
            query.sort = sort
                .as_str()
                .ok_or_else(|| "sort must be a string".to_owned())?
                .to_owned();
        }
        if !matches!(
            query.sort.as_str(),
            "id" | "kind" | "platform" | "state" | "bind"
        ) {
            return Err("sort must be id, kind, platform, state, or bind".to_owned());
        }
        if let Some(direction) = object.get("direction") {
            query.descending = match direction
                .as_str()
                .ok_or_else(|| "direction must be asc or desc".to_owned())?
            {
                "asc" => false,
                "desc" => true,
                _ => return Err("direction must be asc or desc".to_owned()),
            };
        }
        Ok(query)
    }

    fn matches(&self, descriptor: &ListenerDescriptor) -> bool {
        let kind = format!("{:?}", descriptor.kind).to_ascii_lowercase();
        let platform = std::env::consts::OS;
        let state = "available";
        self.kind.as_deref().is_none_or(|value| value == kind)
            && self
                .platform
                .as_deref()
                .is_none_or(|value| value == platform)
            && self.state.as_deref().is_none_or(|value| value == state)
    }

    fn compare(&self, left: &ListenerDescriptor, right: &ListenerDescriptor) -> std::cmp::Ordering {
        let left_value = listener_sort_key(left, &self.sort);
        let right_value = listener_sort_key(right, &self.sort);
        let ordering = left_value
            .cmp(&right_value)
            .then_with(|| left.id.cmp(&right.id));
        if self.descending {
            ordering.reverse()
        } else {
            ordering
        }
    }
}

fn listener_sort_key(descriptor: &ListenerDescriptor, sort: &str) -> String {
    match sort {
        "kind" => format!("{:?}", descriptor.kind).to_ascii_lowercase(),
        "platform" => std::env::consts::OS.to_owned(),
        "state" => "available".to_owned(),
        "bind" => descriptor
            .bind
            .map(|value| value.to_string())
            .unwrap_or_default(),
        _ => descriptor.id.as_str().to_owned(),
    }
}

fn parse_string_set(value: Option<&Value>) -> BTreeSet<String> {
    value
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect()
}

fn parse_string_map(value: Option<&Value>) -> BTreeMap<String, String> {
    value
        .and_then(Value::as_object)
        .map(|object| {
            object
                .iter()
                .filter_map(|(key, value)| {
                    value.as_str().map(|value| (key.clone(), value.to_owned()))
                })
                .collect()
        })
        .unwrap_or_default()
}

fn parse_subscription_spec(body: &Value) -> Result<SubscriptionSpec, String> {
    let object = body
        .as_object()
        .ok_or_else(|| "subscriptions.create body must be an object".to_owned())?;
    for key in object.keys() {
        if !matches!(
            key.as_str(),
            "id" | "display_name"
                | "enabled"
                | "source"
                | "refresh"
                | "cache"
                | "source_type"
                | "url"
                | "credentials_ref"
        ) {
            return Err(format!("unknown subscriptions.create field: {key}"));
        }
    }

    let id_value = object
        .get("id")
        .and_then(Value::as_str)
        .ok_or_else(|| "id is required".to_owned())?;
    let id = crate::SubscriptionId::new(id_value).map_err(|error| error.to_string())?;
    let display_name = match object.get("display_name") {
        None => id.as_str().to_owned(),
        Some(Value::String(value)) => value.clone(),
        Some(_) => return Err("display_name must be a string".to_owned()),
    };
    let enabled = match object.get("enabled") {
        None => true,
        Some(Value::Bool(value)) => *value,
        Some(_) => return Err("enabled must be a boolean".to_owned()),
    };

    let source = match object.get("source") {
        None => None,
        Some(Value::Object(source)) => {
            for key in source.keys() {
                if !matches!(key.as_str(), "type" | "url" | "credentials_ref") {
                    return Err(format!("unknown source field: {key}"));
                }
            }
            Some(source)
        }
        Some(_) => return Err("source must be an object".to_owned()),
    };
    let source_type = source
        .and_then(|source| source.get("type"))
        .or_else(|| object.get("source_type"))
        .map(|value| {
            value
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| "source.type must be a string".to_owned())
        })
        .transpose()?
        .unwrap_or_else(|| "static".to_owned());
    let url = source
        .and_then(|source| source.get("url"))
        .or_else(|| object.get("url"))
        .and_then(Value::as_str)
        .ok_or_else(|| "source.url is required".to_owned())?
        .to_owned();
    let credentials_ref = optional_string(
        source
            .and_then(|source| source.get("credentials_ref"))
            .or_else(|| object.get("credentials_ref")),
        "source.credentials_ref",
    )?;

    let refresh = match object.get("refresh") {
        None => SubscriptionRefreshSpec::default(),
        Some(Value::Object(refresh)) => {
            for key in refresh.keys() {
                if !matches!(
                    key.as_str(),
                    "interval_seconds" | "timeout_seconds" | "max_attempts" | "backoff_seconds"
                ) {
                    return Err(format!("unknown refresh field: {key}"));
                }
            }
            let defaults = SubscriptionRefreshSpec::default();
            SubscriptionRefreshSpec {
                interval_seconds: optional_u64(
                    refresh.get("interval_seconds"),
                    defaults.interval_seconds,
                    "refresh.interval_seconds",
                )?,
                timeout_seconds: optional_u64(
                    refresh.get("timeout_seconds"),
                    defaults.timeout_seconds,
                    "refresh.timeout_seconds",
                )?,
                max_attempts: u32::try_from(optional_u64(
                    refresh.get("max_attempts"),
                    u64::from(defaults.max_attempts),
                    "refresh.max_attempts",
                )?)
                .map_err(|_| "refresh.max_attempts is outside the integer range".to_owned())?,
                backoff_seconds: optional_u64(
                    refresh.get("backoff_seconds"),
                    defaults.backoff_seconds,
                    "refresh.backoff_seconds",
                )?,
            }
        }
        Some(_) => return Err("refresh must be an object".to_owned()),
    };
    let cache = match object.get("cache") {
        None | Some(Value::Null) => None,
        Some(Value::Object(cache)) => {
            for key in cache.keys() {
                if !matches!(key.as_str(), "path" | "max_age_seconds") {
                    return Err(format!("unknown cache field: {key}"));
                }
            }
            let path = cache
                .get("path")
                .and_then(Value::as_str)
                .ok_or_else(|| "cache.path is required".to_owned())?
                .to_owned();
            Some(SubscriptionCacheSpec {
                path,
                max_age_seconds: optional_u64(
                    cache.get("max_age_seconds"),
                    86_400,
                    "cache.max_age_seconds",
                )?,
            })
        }
        Some(_) => return Err("cache must be an object or null".to_owned()),
    };

    Ok(SubscriptionSpec {
        id,
        source_type,
        display_name,
        enabled,
        url,
        credentials_ref,
        refresh,
        cache,
    })
}

fn optional_string(value: Option<&Value>, field: &str) -> Result<Option<String>, String> {
    match value {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) => Ok(Some(value.clone())),
        Some(_) => Err(format!("{field} must be a string or null")),
    }
}

fn optional_u64(value: Option<&Value>, default: u64, field: &str) -> Result<u64, String> {
    match value {
        None => Ok(default),
        Some(value) => value
            .as_u64()
            .ok_or_else(|| format!("{field} must be a non-negative integer")),
    }
}

fn subscription_id_from_body(body: &Value) -> Result<crate::SubscriptionId, String> {
    let value = body
        .get("id")
        .and_then(Value::as_str)
        .ok_or_else(|| "id is required".to_owned())?;
    crate::SubscriptionId::new(value).map_err(|error| error.to_string())
}

fn zero_cleanup() -> Value {
    json!({"paths": 0, "sessions": 0, "streams": 0, "target_connections": 0})
}

fn request_id(value: &str) -> Result<RequestId, String> {
    if value.is_empty() {
        return Err("request_id is required".to_owned());
    }
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    value.hash(&mut hasher);
    Ok(RequestId::new(u128::from(hasher.finish())))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Actor, ListenerKind};
    use std::net::SocketAddr;

    fn request(operation: &str, capabilities: &[&str], body: Value) -> RequestEnvelope {
        RequestEnvelope {
            api_version: LOCAL_API_VERSION.to_owned(),
            operation: operation.to_owned(),
            request_id: format!("request-{operation}"),
            actor: Actor {
                id: "operator".to_owned(),
                capabilities: capabilities
                    .iter()
                    .map(|value| (*value).to_owned())
                    .collect(),
            },
            expected_generation: None,
            body,
        }
    }

    fn dispatcher(platform: SystemProxyPlatform) -> LocalControlDispatcher {
        let mut dispatcher = LocalControlDispatcher::new(platform);
        dispatcher
            .service_mut()
            .register_listener(ListenerDescriptor {
                id: ListenerId::new("local-http"),
                kind: ListenerKind::Http,
                bind: Some("127.0.0.1:8080".parse::<SocketAddr>().unwrap()),
                interface: None,
                address: None,
                mtu: None,
                flow_tags: std::collections::BTreeSet::new(),
                process_metadata: crate::ProcessMetadataRequest::default(),
                allowed_sources: Vec::new(),
                authentication_required: false,
            });
        dispatcher
            .service_mut()
            .register_listener(ListenerDescriptor {
                id: ListenerId::new("lan-tun"),
                kind: ListenerKind::Tun,
                bind: Some("0.0.0.0:15000".parse::<SocketAddr>().unwrap()),
                interface: None,
                address: None,
                mtu: None,
                flow_tags: std::collections::BTreeSet::new(),
                process_metadata: crate::ProcessMetadataRequest::default(),
                allowed_sources: Vec::new(),
                authentication_required: false,
            });
        dispatcher
    }

    #[test]
    fn status_and_listener_inventory_are_typed() {
        let mut dispatcher = dispatcher(SystemProxyPlatform::Windows);
        let status = dispatcher.dispatch(request("status.get", &["status:read"], json!({})));
        assert!(status.ok);
        assert_eq!(status.result.unwrap()["control_plane"]["state"], "running");
        let status = dispatcher.dispatch(request("status.get", &["status:read"], json!({})));
        let result = status.result.unwrap();
        assert_eq!(result["data_path_summary"], "down");
        assert_eq!(result["runtime_snapshot"]["state"], "unavailable");
        let listeners =
            dispatcher.dispatch(request("listeners.list", &["listeners:read"], json!({})));
        assert!(listeners.ok);
        assert_eq!(
            listeners.result.unwrap()["items"].as_array().unwrap().len(),
            2
        );
    }

    #[test]
    fn metrics_expose_path_quality_and_session_stream_fields() {
        let mut dispatcher = dispatcher(SystemProxyPlatform::Linux);
        let observations = dispatcher.service().observation_handle();
        let session_id = pathchord_core::SessionId::new(51);
        let path_id = pathchord_core::PathId::new(52);
        observations
            .replace_session_observations(
                [crate::SessionObservation {
                    session_id,
                    egress_id: "egress-a".into(),
                    state: pathchord_core::SessionState::Active,
                    ready_paths: 1,
                    active_streams: 2,
                    retained_outbound_bytes: 3,
                    bytes_sent: 4,
                    bytes_received: 5,
                }],
                [crate::PathObservation {
                    path_id,
                    session_id,
                    state: pathchord_core::PathState::Active,
                    rtt_ms: 12,
                    jitter_ms: 3,
                    loss_ppm: 4_000,
                    throughput_bps: 5_000_000,
                    reordering_events: 6,
                    exclusion_reason: None,
                }],
            )
            .unwrap();
        let paths = dispatcher.dispatch(request("metrics.paths", &["metrics:read"], json!({})));
        let path = &paths.result.expect("path metrics")["items"][0];
        assert_eq!(path["rtt_ms"], 12);
        assert_eq!(path["loss_ppm"], 4_000);
        assert_eq!(path["reordering_events"], 6);
        assert!(path["exclusion_reason"].is_null());

        let streams = dispatcher.dispatch(request("metrics.streams", &["metrics:read"], json!({})));
        let stream = &streams.result.expect("stream metrics")["items"][0];
        assert_eq!(stream["egress_id"], "egress-a");
        assert_eq!(stream["ready_paths"], 1);
        assert_eq!(stream["active_streams"], 2);
    }

    #[test]
    fn listener_observation_does_not_claim_data_path_connectivity() {
        let mut dispatcher = dispatcher(SystemProxyPlatform::Linux);
        let observations = dispatcher.service().observation_handle();
        observations
            .apply_listener_event(crate::ListenerRuntimeEvent::ListenerStarted {
                listener_id: ListenerId::new("local-http"),
                bind: Some("127.0.0.1:8080".parse().unwrap()),
                interface: None,
                address: None,
                mtu: None,
            })
            .unwrap();

        let status = dispatcher.dispatch(request("status.get", &["status:read"], json!({})));
        let result = status.result.unwrap();
        assert_eq!(result["runtime_snapshot"]["state"], "fresh");
        assert_eq!(result["data_path_summary"], "down");
    }

    #[test]
    fn listeners_list_validates_query_and_paginates_deterministically() {
        let mut dispatcher = dispatcher(SystemProxyPlatform::Linux);
        let first = dispatcher.dispatch(request(
            "listeners.list",
            &["listeners:read"],
            json!({"page_size": 1, "sort": "id"}),
        ));
        assert!(first.ok);
        let result = first.result.expect("first page");
        assert_eq!(result["items"].as_array().expect("items").len(), 1);
        let token = result["next_page_token"].as_str().expect("next token");

        let second = dispatcher.dispatch(request(
            "listeners.list",
            &["listeners:read"],
            json!({"page_size": 1, "page_token": token}),
        ));
        assert!(second.ok);
        assert_eq!(
            second.result.expect("second page")["items"]
                .as_array()
                .unwrap()
                .len(),
            1
        );

        let invalid = dispatcher.dispatch(request(
            "listeners.list",
            &["listeners:read"],
            json!({"page_size": 0}),
        ));
        assert!(!invalid.ok);
        assert_eq!(
            invalid.error.expect("validation error").code,
            ErrorCode::ValidationFailed
        );
    }

    #[test]
    fn node_and_subscription_mutations_use_generation_preconditions() {
        let mut dispatcher = dispatcher(SystemProxyPlatform::Linux);
        dispatcher
            .service_mut()
            .add_node(crate::NodeId::new("node-1").expect("node"))
            .expect("add node");
        let patch = request(
            "nodes.patch_labels",
            &["nodes:write"],
            json!({"node_id": "node-1", "set": {"admin.region": "jp"}, "remove": []}),
        );
        let mut patch = patch;
        patch.expected_generation = Some(GenerationExpectation {
            scope: "configuration".to_owned(),
            value: 0,
        });
        assert!(dispatcher.dispatch(patch).ok);

        let mut create = request(
            "subscriptions.create",
            &["subscriptions:write"],
            json!({
                "id": "source-a",
                "display_name": "A",
                "enabled": true,
                "source": {
                    "type": "clash",
                    "url": "https://provider.example/subscription",
                    "credentials_ref": "provider-a-token"
                },
                "refresh": {
                    "interval_seconds": 900,
                    "timeout_seconds": 15,
                    "max_attempts": 4,
                    "backoff_seconds": 7
                },
                "cache": {
                    "path": "provider-a.snapshot",
                    "max_age_seconds": 86400
                }
            }),
        );
        create.expected_generation = Some(GenerationExpectation {
            scope: "configuration".to_owned(),
            value: 1,
        });
        assert!(dispatcher.dispatch(create).ok);
        let subscriptions =
            dispatcher.dispatch(request("subscriptions.list", &["status:read"], json!({})));
        let result = subscriptions.result.unwrap();
        let items = result["items"].as_array().unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(
            items[0]["source"]["url"],
            "https://provider.example/subscription"
        );
        assert_eq!(items[0]["source"]["credentials_ref"], "provider-a-token");
        assert_eq!(items[0]["refresh"]["interval_seconds"], 900);
        assert_eq!(items[0]["cache"]["path"], "provider-a.snapshot");
    }

    #[test]
    fn windows_system_proxy_enable_disable_and_linux_rejection() {
        let mut windows = dispatcher(SystemProxyPlatform::Windows);
        let enabled = windows.dispatch(request(
            "system_proxy.enable",
            &["system_proxy:write"],
            json!({"listener_id": "local-http"}),
        ));
        assert!(enabled.ok);
        assert_eq!(enabled.result.unwrap()["resource"]["enabled"], true);
        let disabled = windows.dispatch(request(
            "system_proxy.disable",
            &["system_proxy:write"],
            json!({}),
        ));
        assert!(disabled.ok);
        assert_eq!(disabled.result.unwrap()["resource"]["enabled"], false);

        let mut linux = dispatcher(SystemProxyPlatform::Linux);
        let response = linux.dispatch(request(
            "system_proxy.enable",
            &["system_proxy:write"],
            json!({"listener_id": "local-http"}),
        ));
        assert!(!response.ok);
        assert_eq!(
            response.error.unwrap().code,
            ErrorCode::UnsupportedOperation
        );

        let status = linux.dispatch(request("system_proxy.get", &["status:read"], json!({})));
        assert!(status.ok);
        let resource = status.result.expect("Linux system proxy status");
        assert_eq!(resource["enabled"], false);
        assert_eq!(resource["platform_effect"], "unsupported");
        assert_eq!(resource["restoration_state"], "not_required");
    }

    #[test]
    fn system_proxy_mutation_checks_expected_generation_when_supplied() {
        let mut dispatcher = dispatcher(SystemProxyPlatform::Windows);
        let mut request = request(
            "system_proxy.enable",
            &["system_proxy:write"],
            json!({"listener_id": "local-http"}),
        );
        request.expected_generation = Some(GenerationExpectation {
            scope: "configuration".to_owned(),
            value: 99,
        });
        let response = dispatcher.dispatch(request);
        assert!(!response.ok);
        assert_eq!(
            response.error.expect("generation error").code,
            ErrorCode::GenerationConflict
        );
    }

    #[test]
    fn missing_capability_and_unknown_operation_are_typed_errors() {
        let mut dispatcher = dispatcher(SystemProxyPlatform::Windows);
        let denied = dispatcher.dispatch(request("status.get", &[], json!({})));
        assert_eq!(denied.error.unwrap().code, ErrorCode::CapabilityDenied);
        let unknown =
            dispatcher.dispatch(request("unknown.operation", &["status:read"], json!({})));
        assert_eq!(unknown.error.unwrap().code, ErrorCode::UnsupportedOperation);
    }
}
