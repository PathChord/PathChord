//! Typed operation dispatch for the local control-plane envelope.
//!
//! This layer deliberately owns request validation and response shaping while
//! leaving sockets, named pipes, and platform side effects to adapters.

use std::collections::{BTreeMap, BTreeSet};
use std::hash::{Hash, Hasher};
use std::sync::Arc;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use pathchord_core::management::{ManagementDispatcher, ManagementSource};
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
    subscription_data_plane: Option<Arc<crate::IngressDataPlane>>,
}

impl LocalControlDispatcher {
    #[must_use]
    pub fn new(platform: SystemProxyPlatform) -> Self {
        Self {
            service: IngressControlService::with_platform_proxy(default_platform_adapter(platform)),
            platform,
            subscription_data_plane: None,
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
            subscription_data_plane: None,
        }
    }

    #[must_use]
    pub fn with_service(platform: SystemProxyPlatform, service: IngressControlService) -> Self {
        Self {
            service,
            platform,
            subscription_data_plane: None,
        }
    }

    pub fn set_subscription_data_plane(&mut self, data_plane: Arc<crate::IngressDataPlane>) {
        self.subscription_data_plane = Some(data_plane);
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
        if self.subscription_data_plane.is_some()
            && is_subscription_visibility_mutation(&request.operation)
        {
            return self.failure(
                request.request_id,
                self.observed_generation(),
                ErrorCode::PersistenceUnavailable,
                "subscription mutations require the asynchronous runtime dispatcher",
                None,
            );
        }
        self.dispatch_with_source(request, ManagementSource::Local)
    }

    async fn dispatch_guarded(
        &mut self,
        request: RequestEnvelope,
        source: ManagementSource,
    ) -> ResponseEnvelope {
        let Some(data_plane) = self.subscription_data_plane.clone() else {
            return self.dispatch_with_source(request, source);
        };
        if !is_subscription_visibility_mutation(&request.operation) {
            return self.dispatch_with_source(request, source);
        }
        let Ok(id) = subscription_id_from_body(&request.body) else {
            return self.dispatch_with_source(request, source);
        };
        data_plane
            .subscription_transaction(id.as_str(), || {
                let response = self.dispatch_with_source(request, source);
                // On replay, use the current state rather than the old
                // response: a stale enable/disable cannot reverse a later one.
                let visible = response.ok.then(|| {
                    self.service
                        .snapshot()
                        .subscriptions
                        .get(&id)
                        .is_some_and(|subscription| subscription.spec.enabled)
                });
                (response, visible)
            })
            .await
    }

    fn dispatch_with_source(
        &mut self,
        request: RequestEnvelope,
        source: ManagementSource,
    ) -> ResponseEnvelope {
        if self.service.flush_observation_events().is_err() {
            return self.failure(
                request.request_id,
                self.observed_generation(),
                ErrorCode::PersistenceUnavailable,
                "runtime event publication failed",
                None,
            );
        }
        let audit_request = request.clone();
        let mutation = matches!(
            audit_request.operation.as_str(),
            "nodes.patch_labels"
                | "nodes.patch_tags"
                | "subscriptions.create"
                | "subscriptions.delete"
                | "subscriptions.enable"
                | "subscriptions.disable"
                | "subscriptions.refresh"
                | "system_proxy.enable"
                | "system_proxy.disable"
        );
        let eligible = mutation && eligible_for_idempotency(&audit_request);
        let fingerprint = eligible.then(|| management_request_fingerprint(&audit_request));
        let internal_request_id = eligible
            .then(|| request_id(&audit_request.request_id))
            .transpose();
        let (mut response, replayed) = if let (Some(fingerprint), Ok(Some(internal_request_id))) =
            (&fingerprint, &internal_request_id)
        {
            match self.service.replay_management_response(
                &audit_request,
                *internal_request_id,
                fingerprint,
            ) {
                Ok(Some(response)) => (response, true),
                Ok(None) => (self.dispatch_inner(request), false),
                Err(error) => (
                    self.control_error(audit_request.request_id.clone(), error),
                    false,
                ),
            }
        } else {
            (self.dispatch_inner(request), false)
        };
        if mutation {
            if let (Some(fingerprint), Ok(Some(internal_request_id))) =
                (fingerprint, internal_request_id)
            {
                if response.ok {
                    self.service.remember_management_response(
                        &audit_request.actor.id,
                        internal_request_id,
                        fingerprint,
                        &response,
                    );
                } else if !replayed && cacheable_failure(&response) {
                    sanitize_cached_failure(&mut response);
                    if let Err(error) = self.service.remember_management_failure(
                        &audit_request.actor.id,
                        internal_request_id,
                        fingerprint,
                        &response,
                    ) {
                        response = self.control_error(audit_request.request_id.clone(), error);
                    }
                }
            }
            self.service
                .record_management_outcome(&audit_request, &response, source);
        }
        response
    }

    fn dispatch_inner(&mut self, request: RequestEnvelope) -> ResponseEnvelope {
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
                "control_plane": {"state": if self.service.audit_degraded() {"degraded"} else {"running"}},
                "runtime_snapshot": {"state": runtime_state, "generation": snapshot.generation},
                "observations": {
                    "state": if snapshot.resource_limits.is_empty() {"running"} else {"degraded"},
                    "resource_limits": snapshot.resource_limits,
                },
                "data_path_summary": data_path_summary,
                "configuration_generation": self.service.snapshot().generation,
                "observation_generation": snapshot.generation,
                "configuration_reload": self.service.reload_status().map(|status| json!({
                    "state": format!("{:?}", status.state).to_ascii_lowercase(),
                    "active_generation": status.active_generation,
                    "observed_at": rfc3339_utc(status.observed_at_ms),
                    "reason": status.reason,
                    "diagnostic": status.diagnostic,
                })),
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
        let query = match ListQuery::parse(
            &request.body,
            "listeners",
            &["kind", "platform", "state"],
            &[
                "id",
                "kind",
                "platform",
                "bind",
                "authentication",
                "state",
                "generation",
            ],
        ) {
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
        let observations = self.service.observation_snapshot();
        let items: Vec<_> = self
            .service
            .listeners()
            .into_values()
            .map(|descriptor| {
                listener_value(
                    &descriptor,
                    generation,
                    observations.listener_states.get(&descriptor.id),
                )
            })
            .collect();
        let (items, next_page_token) = query.page(items);
        self.success(
            request.request_id,
            json!({"items": items, "next_page_token": next_page_token}),
        )
    }

    fn dispatch_nodes_list(&self, request: RequestEnvelope) -> ResponseEnvelope {
        if let Err(response) = self.require_capability(&request, "nodes:read") {
            return *response;
        }
        let query = match ListQuery::parse(
            &request.body,
            "nodes",
            &["id", "state", "namespace", "source.subscription"],
            &[
                "id",
                "state",
                "namespace",
                "protocol",
                "endpoint",
                "generation",
            ],
        ) {
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
        let snapshot = self.service.snapshot();
        let observations = self.service.observation_snapshot();
        let items: Vec<_> = snapshot
            .nodes
            .iter()
            .map(|(id, state)| {
                node_value(
                    id,
                    state,
                    observations.nodes.get(id),
                    observations.node_metadata.get(id),
                    snapshot.generation,
                )
            })
            .collect();
        let (items, next_page_token) = query.page(items);
        self.success(
            request.request_id,
            json!({"items": items, "next_page_token": next_page_token}),
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
        let observations = self.service.observation_snapshot();
        self.success(
            request.request_id,
            node_value(
                id,
                state,
                observations.nodes.get(id),
                observations.node_metadata.get(id),
                snapshot.generation,
            ),
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
        let Some(object) = request.body.as_object() else {
            return self.failure(
                request.request_id,
                self.observed_generation(),
                ErrorCode::ValidationFailed,
                "node patch body must be an object",
                None,
            );
        };
        let allowed = if tags_only {
            ["node_id", "add", "remove"].as_slice()
        } else {
            ["node_id", "set", "remove"].as_slice()
        };
        if let Some(key) = object.keys().find(|key| !allowed.contains(&key.as_str())) {
            return self.failure(
                request.request_id,
                self.observed_generation(),
                ErrorCode::ValidationFailed,
                &format!("unknown node patch field: {key}"),
                None,
            );
        }
        let patch = if tags_only {
            let add_tags = match parse_string_set(request.body.get("add"), "add") {
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
            let remove_tags = match parse_string_set(request.body.get("remove"), "remove") {
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
            NodeAdminPatch {
                add_tags,
                remove_tags,
                ..NodeAdminPatch::default()
            }
        } else {
            let set_labels = match parse_string_map(request.body.get("set"), "set") {
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
            let remove_labels = match parse_string_set(request.body.get("remove"), "remove") {
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
            NodeAdminPatch {
                set_labels,
                remove_labels,
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
        match self.service.patch_node_precondition(
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
        match self.service.add_subscription_precondition(
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
        match self.service.delete_subscription_precondition(
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
        match self.service.set_subscription_enabled_precondition(
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
        if request.body.as_object().is_none_or(|body| {
            body.keys()
                .any(|key| !matches!(key.as_str(), "id" | "revision"))
        }) {
            return self.failure(
                request.request_id,
                self.observed_generation(),
                ErrorCode::ValidationFailed,
                "refresh accepts only id and revision",
                None,
            );
        }
        let Some(revision) = request.body.get("revision").and_then(Value::as_u64) else {
            return self.failure(
                request.request_id,
                self.observed_generation(),
                ErrorCode::ValidationFailed,
                "revision is required and must be an unsigned integer",
                None,
            );
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
        match self.service.request_subscription_refresh_precondition(
            &request.actor.id,
            internal_request_id,
            expected,
            &id,
            revision,
        ) {
            Ok(receipt) => self.success(
                request.request_id,
                json!({
                    "applied_generation": {"scope": "configuration", "value": receipt.generation},
                    "resource": {"id": id.as_str(), "state": "refreshing", "revision": revision},
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
        let query = match ListQuery::parse(
            &request.body,
            "subscriptions",
            &["id", "state", "source_type", "enabled"],
            &[
                "id",
                "state",
                "source_type",
                "enabled",
                "revision",
                "last_refresh_at",
                "next_refresh_at",
                "imported_node_count",
            ],
        ) {
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
        let snapshot = self.service.snapshot();
        let observations = self.service.observation_snapshot();
        let items: Vec<_> = snapshot
            .subscriptions
            .values()
            .map(|subscription| {
                json!({
                    "id": subscription.spec.id.as_str(),
                    "name": pathchord_policy::ResourceIdentity::from_id(subscription.spec.id.as_str()).name,
                    "namespace": pathchord_policy::ResourceIdentity::from_id(subscription.spec.id.as_str()).namespace,
                    "display_name": subscription.spec.display_name,
                    "source_type": subscription.spec.source_type,
                    "source": {
                        "type": subscription.spec.source_type,
                        "url": Value::Null,
                        "url_redaction_reason": "sensitive_source",
                        "origin": subscription_origin(&subscription.spec.url),
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
                    "state": subscription_state_name(subscription),
                    "last_refresh_at": subscription.last_refresh_at_ms,
                    "next_refresh_at": observations.subscription_runtime.get(&subscription.spec.id).and_then(|value| value.next_refresh_at_ms),
                    "imported_node_count": observations.subscription_runtime.get(&subscription.spec.id).map(|value| value.imported_node_count),
                    "last_error": subscription.last_error,
                })
            })
            .collect();
        let (items, next_page_token) = query.page(items);
        self.success(
            request.request_id,
            json!({"items": items, "next_page_token": next_page_token}),
        )
    }

    fn dispatch_sessions_list(&self, request: RequestEnvelope) -> ResponseEnvelope {
        if let Err(response) = self.require_capability(&request, "status:read") {
            return *response;
        }
        let query = match ListQuery::parse(
            &request.body,
            "sessions",
            &["session_id", "egress_id", "state", "admission_generation"],
            &[
                "session_id",
                "egress_id",
                "state",
                "ready_path_count",
                "admission_generation",
                "created_at",
                "last_change_at",
                "close_reason",
                "active_udp_associations",
                "pending_session_controls",
            ],
        ) {
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
        let snapshot = self.service.observation_snapshot();
        let items: Vec<_> = snapshot
            .sessions
            .values()
            .map(|session| {
                session_value(
                    session,
                    snapshot.egress_runtime.get(&session.egress_id),
                    snapshot.generation,
                )
            })
            .collect();
        let (items, next_page_token) = query.page(items);
        self.success(
            request.request_id,
            json!({"items": items, "next_page_token": next_page_token}),
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
        self.success(
            request.request_id,
            session_value(
                session,
                snapshot.egress_runtime.get(&session.egress_id),
                snapshot.generation,
            ),
        )
    }

    fn dispatch_connections_list(&self, request: RequestEnvelope) -> ResponseEnvelope {
        if let Err(response) = self.require_capability(&request, "metrics:read") {
            return *response;
        }
        let query = match ListQuery::parse(
            &request.body,
            "connections",
            &[
                "connection_id",
                "listener_id",
                "protocol",
                "session_id",
                "state",
            ],
            &[
                "connection_id",
                "session_id",
                "listener_id",
                "protocol",
                "stream_id",
                "target_kind",
                "state",
                "bytes_sent",
                "bytes_received",
                "close_reason",
            ],
        ) {
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
                    "listener_id": snapshot.connection_listeners.get(&connection.connection_id).map(ListenerId::as_str),
                    "protocol": snapshot.connection_listeners.get(&connection.connection_id).map(|_| "tcp"),
                    "target_kind": Value::Null,
                    "close_reason": Value::Null,
                    "generation": snapshot.generation,
                    "state": format!("{:?}", connection.state).to_ascii_lowercase(),
                    "bytes_sent": connection.bytes_sent,
                    "bytes_received": connection.bytes_received,
                    "target": if reveal_targets { connection.target_display.clone() } else { None },
                    "target_redacted": !reveal_targets && connection.target_display.is_some(),
                    "target_redaction_reason": if !reveal_targets && connection.target_display.is_some() {
                        Some("capability_required")
                    } else {
                        None
                    },
                })
            })
            .collect();
        let (items, next_page_token) = query.page(items);
        self.success(
            request.request_id,
            json!({"items": items, "next_page_token": next_page_token}),
        )
    }

    fn dispatch_metrics_snapshot(&self, request: RequestEnvelope) -> ResponseEnvelope {
        if let Err(response) = self.require_capability(&request, "metrics:read") {
            return *response;
        }
        let snapshot = self.service.observation_snapshot();
        let mut node_health = BTreeMap::from([
            ("unknown", 0_u64),
            ("up", 0_u64),
            ("degraded", 0_u64),
            ("down", 0_u64),
        ]);
        for observation in snapshot.nodes.values() {
            let key = match observation.state {
                crate::NodeHealthState::Unknown => "unknown",
                crate::NodeHealthState::Up => "up",
                crate::NodeHealthState::Degraded => "degraded",
                crate::NodeHealthState::Down => "down",
            };
            *node_health
                .get_mut(key)
                .expect("all node states are initialized") += 1;
        }
        let path_rtt_ms_sum = sum_observed(snapshot.paths.values().map(|path| path.rtt_ms));
        let path_jitter_ms_sum = sum_observed(snapshot.paths.values().map(|path| path.jitter_ms));
        let path_loss_ppm_sum = sum_observed(
            snapshot
                .paths
                .values()
                .map(|path| path.loss_ppm.map(u64::from)),
        );
        let path_throughput_bps_sum =
            sum_observed(snapshot.paths.values().map(|path| path.throughput_bps));
        let path_capacity_bps_sum = sum_observed(
            snapshot
                .paths
                .values()
                .map(|path| path.available_capacity_bps),
        );
        let path_reordering_events =
            sum_observed(snapshot.paths.values().map(|path| path.reordering_events));
        let stream_bytes_sent: u64 = snapshot
            .streams
            .values()
            .map(|stream| stream.bytes_sent)
            .sum();
        let stream_bytes_received: u64 = snapshot
            .streams
            .values()
            .map(|stream| stream.bytes_received)
            .sum();
        let stream_bytes_acked: u64 = snapshot
            .streams
            .values()
            .map(|stream| stream.bytes_acked)
            .sum();
        let stream_retransmissions: u64 = snapshot
            .streams
            .values()
            .map(|stream| stream.retransmissions)
            .sum();
        let control = self.service.snapshot();
        let measured = snapshot.runtime_state != crate::control::RuntimeSnapshotState::Unavailable;
        let session_count = |wanted| {
            snapshot
                .sessions
                .values()
                .filter(|value| value.state == wanted)
                .count()
        };
        let path_count = |wanted| {
            snapshot
                .paths
                .values()
                .filter(|value| value.state == wanted)
                .count()
        };
        let stream_count = |wanted| {
            snapshot
                .streams
                .values()
                .filter(|value| value.state == wanted)
                .count()
        };
        let subscriptions_healthy = control
            .subscriptions
            .values()
            .filter(|value| {
                value.spec.enabled
                    && value.refresh_state == crate::SubscriptionRefreshState::Healthy
            })
            .count();
        let egress_state_count = |wanted| {
            snapshot
                .egress_runtime
                .values()
                .filter(|entry| {
                    entry.fresh
                        && entry
                            .report
                            .as_ref()
                            .is_some_and(|report| report.service_state == wanted)
                })
                .count()
        };
        let egress_reports: Vec<_> = snapshot.egress_runtime.iter().filter_map(|(id, entry)| entry.report.as_ref().map(|report| json!({
            "egress_id": id,
            "state": if entry.fresh {format!("{:?}", report.service_state).to_ascii_lowercase()} else {"stale".to_owned()},
            "freshness": if entry.fresh {"fresh"} else {"stale"},
            "load_ratio": f64::from(report.load_basis_points) / 10_000.0,
            "connection_utilization_ratio": f64::from(report.connection_utilization_basis_points) / 10_000.0,
            "bandwidth_utilization_ratio": f64::from(report.bandwidth_utilization_basis_points) / 10_000.0,
            "active_sessions": report.active_sessions,
            "active_streams": report.active_streams,
            "active_target_connections": report.active_target_connections,
            "configured_capacity_bps": report.configured_capacity_bps,
            "effective_capacity_bps": report.effective_capacity_bps,
            "current_wire_rate_bps": report.current_wire_rate_bps,
            "replication_allowance_bps": report.replication_allowance_bps,
            "capacity_state": format!("{:?}", report.capacity_state).to_ascii_lowercase(),
            "admission_allowed": report.admission_allowed,
            "admission_reason": format!("{:?}", report.admission_reason).to_ascii_lowercase(),
            "status_report_age_ms": entry.age_ms,
        }))).collect();
        let (
            egress_configured_capacity_bps,
            egress_effective_capacity_bps,
            egress_current_wire_rate_bps,
            egress_replication_allowance_bps,
            egress_admission_denied,
            egress_stale_reports,
        ) = snapshot.egress_runtime.values().fold(
            (0_u64, 0_u64, 0_u64, 0_u64, 0_u64, 0_u64),
            |totals, entry| {
                let Some(report) = entry.report.as_ref() else {
                    return (
                        totals.0,
                        totals.1,
                        totals.2,
                        totals.3,
                        totals.4,
                        totals.5 + 1,
                    );
                };
                (
                    totals.0.saturating_add(report.configured_capacity_bps),
                    totals.1.saturating_add(report.effective_capacity_bps),
                    totals.2.saturating_add(report.current_wire_rate_bps),
                    totals.3.saturating_add(report.replication_allowance_bps),
                    totals
                        .4
                        .saturating_add(u64::from(!report.admission_allowed)),
                    totals.5.saturating_add(u64::from(!entry.fresh)),
                )
            },
        );
        let udp_associations: usize = snapshot
            .egress_runtime
            .values()
            .map(|entry| entry.active_udp_associations)
            .sum();
        ResponseEnvelope::success(
            request.request_id,
            GenerationExpectation {
                scope: "observation".to_owned(),
                value: snapshot.generation,
            },
            json!({
                "captured_at_ms": snapshot.captured_at_ms,
                "captured_at": rfc3339_utc(snapshot.captured_at_ms),
                "generation": snapshot.generation,
                "snapshot_generation": snapshot.generation,
                "freshness": format!("{:?}", snapshot.runtime_state).to_ascii_lowercase(),
                "observations": {
                    "state": if snapshot.resource_limits.is_empty() {"running"} else {"degraded"},
                    "resource_limits": snapshot.resource_limits,
                },
                "ingress": {"state": "running"},
                "system_proxy": self.system_proxy_value(),
                "egress": {
                    "configured": measured.then_some(snapshot.egress_runtime.len()),
                    "up": measured.then(|| egress_state_count(pathchord_core::EgressServiceState::Up)),
                    "degraded": measured.then(|| egress_state_count(pathchord_core::EgressServiceState::Degraded)),
                    "draining": measured.then(|| egress_state_count(pathchord_core::EgressServiceState::Draining)),
                    "down": measured.then(|| egress_state_count(pathchord_core::EgressServiceState::Down)),
                    "configured_capacity_bps": measured.then_some(egress_configured_capacity_bps),
                    "effective_capacity_bps": measured.then_some(egress_effective_capacity_bps),
                    "current_wire_rate_bps": measured.then_some(egress_current_wire_rate_bps),
                    "replication_allowance_bps": measured.then_some(egress_replication_allowance_bps),
                    "admission_denied": measured.then_some(egress_admission_denied),
                    "stale_reports": measured.then_some(egress_stale_reports),
                },
                "egress_reports": measured.then_some(egress_reports),
                "runtime": {
                    "sessions": measured.then_some(snapshot.runtime.sessions),
                    "ready_paths": measured.then_some(snapshot.runtime.ready_paths),
                    "streams": measured.then_some(snapshot.runtime.streams),
                    "target_connections": measured.then_some(snapshot.runtime.target_connections),
                },
                "nodes": snapshot.nodes.len(),
                "node_health": node_health,
                "observed_paths": snapshot.paths.len(),
                "path_quality": {
                    "rtt_ms_sum": path_rtt_ms_sum,
                    "jitter_ms_sum": path_jitter_ms_sum,
                    "loss_ppm_sum": path_loss_ppm_sum,
                    "throughput_bps_sum": path_throughput_bps_sum,
                    "capacity_bps_sum": path_capacity_bps_sum,
                    "reordering_events": path_reordering_events,
                },
                "streams_observed": snapshot.streams.len(),
                "stream_totals": {
                    "bytes_sent": stream_bytes_sent,
                    "bytes_received": stream_bytes_received,
                    "bytes_acked": stream_bytes_acked,
                    "retransmissions": stream_retransmissions,
                },
                "observed_connections": snapshot.connections.len(),
                "connections": {"targets": measured.then_some(snapshot.runtime.target_connections)},
                "sessions": {
                    "configured": measured.then_some(snapshot.egress_runtime.len()),
                    "active": measured.then_some(snapshot.runtime.sessions),
                    "degraded": measured.then(|| session_count(pathchord_core::SessionState::Degraded)),
                    "draining": measured.then(|| session_count(pathchord_core::SessionState::Draining)),
                },
                "paths": {
                    "ready": measured.then_some(snapshot.runtime.ready_paths),
                    "draining": measured.then(|| path_count(pathchord_core::PathState::Draining)),
                    "failed": measured.then(|| path_count(pathchord_core::PathState::Failed)),
                },
                "streams": {
                    "open": measured.then(|| stream_count(pathchord_core::StreamState::Open)),
                    "half_closed": measured.then(|| stream_count(pathchord_core::StreamState::IngressHalfClosed) + stream_count(pathchord_core::StreamState::EgressHalfClosed)),
                    "reset": measured.then(|| stream_count(pathchord_core::StreamState::Reset)),
                },
                "udp": {"associations": measured.then_some(udp_associations)},
                "policy": {"generation": control.generation},
                "subscriptions": {
                    "configured": control.subscriptions.len(),
                    "healthy": subscriptions_healthy,
                },
            }),
        )
    }

    fn dispatch_path_metrics(&self, request: RequestEnvelope) -> ResponseEnvelope {
        if let Err(response) = self.require_capability(&request, "metrics:read") {
            return *response;
        }
        let query = match ListQuery::parse(
            &request.body,
            "metrics.paths",
            &[
                "path_id",
                "session_id",
                "egress_id",
                "transit_proxy_id",
                "state",
            ],
            &[
                "path_id",
                "session_id",
                "egress_id",
                "transit_proxy_id",
                "state",
                "ready_since_ms",
                "last_change_at_ms",
                "rtt_ms",
                "jitter_ms",
                "loss_ppm",
                "throughput_bps",
                "upstream_throughput_bps",
                "downstream_throughput_bps",
                "available_capacity_bps",
                "reordering_events",
                "control_pending",
                "control_retransmissions",
            ],
        ) {
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
        let snapshot = self.service.observation_snapshot();
        let items: Vec<_> = snapshot
            .paths
            .values()
            .map(|path| {
                json!({
                    "path_id": path.path_id.to_string(),
                    "session_id": path.session_id.to_string(),
                    "egress_id": path.egress_id.as_ref().or_else(|| snapshot.sessions.get(&path.session_id).map(|session| &session.egress_id)),
                    "transit_proxy_id": path.transit_proxy_id,
                    "generation": snapshot.generation,
                    "state": format!("{:?}", path.state).to_ascii_lowercase(),
                    "ready_since_ms": path.ready_since_ms,
                    "ready_since": path.ready_since_ms.map(rfc3339_utc),
                    "last_change_at_ms": path.last_change_at_ms,
                    "last_change_at": path.last_change_at_ms.map(rfc3339_utc),
                    "rtt_ms": path.rtt_ms,
                    "jitter_ms": path.jitter_ms,
                    "loss_ppm": path.loss_ppm,
                    "throughput_bps": path.throughput_bps,
                    "upstream_throughput_bps": path.upstream_throughput_bps,
                    "downstream_throughput_bps": path.downstream_throughput_bps,
                    "available_capacity_bps": path.available_capacity_bps,
                    "reordering_events": path.reordering_events,
                    "control_pending": path.control_pending,
                    "control_retransmissions": path.control_retransmissions,
                    "exclusion_reason": path.exclusion_reason,
                })
            })
            .collect();
        let (items, next_page_token) = query.page(items);
        self.success(
            request.request_id,
            json!({"items": items, "next_page_token": next_page_token}),
        )
    }

    fn dispatch_stream_metrics(&self, request: RequestEnvelope) -> ResponseEnvelope {
        if let Err(response) = self.require_capability(&request, "metrics:read") {
            return *response;
        }
        let query = match ListQuery::parse(
            &request.body,
            "metrics.streams",
            &[
                "stream_id",
                "session_id",
                "egress_id",
                "state",
                "traffic_class",
            ],
            &[
                "stream_id",
                "session_id",
                "egress_id",
                "state",
                "bytes_sent",
                "bytes_received",
                "bytes_acked",
                "retransmissions",
                "opened_at_ms",
                "closed_at_ms",
            ],
        ) {
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
        let reveal_targets = request
            .actor
            .capabilities
            .iter()
            .any(|capability| capability == "targets:read");
        let snapshot = self.service.observation_snapshot();
        let items: Vec<_> = {
            snapshot
                .streams
                .values()
                .map(|stream| {
                    json!({
                        "session_id": stream.session_id.to_string(),
                        "stream_id": stream.stream_id.to_string(),
                        "egress_id": snapshot.sessions.get(&stream.session_id).map(|session| &session.egress_id),
                        "generation": snapshot.generation,
                        "state": format!("{:?}", stream.state).to_ascii_lowercase(),
                        "target": if reveal_targets {
                            Some(stream.target_display.clone())
                        } else {
                            None
                        },
                        "target_redacted": !reveal_targets,
                        "traffic_class": stream.traffic_class,
                        "traffic_class_name": stream.traffic_class,
                        "traffic_class_priority": stream.traffic_class_priority,
                        "traffic_class_share": stream.traffic_class_share,
                        "bytes_sent": stream.bytes_sent,
                        "bytes_received": stream.bytes_received,
                        "bytes_acked": stream.bytes_acked,
                        "retransmissions": stream.retransmissions,
                        "reorder_buffer_bytes": stream.reorder_buffer_bytes,
                        "receive_window": stream.receive_window,
                        "opened_at_ms": stream.opened_at_ms,
                        "closed_at_ms": stream.closed_at_ms,
                        "close_reason": stream.close_reason,
                    })
                })
                .collect()
        };
        let (items, next_page_token) = query.page(items);
        self.success(
            request.request_id,
            json!({"items": items, "next_page_token": next_page_token}),
        )
    }

    fn dispatch_events(&self, request: RequestEnvelope) -> ResponseEnvelope {
        if let Err(response) = self.require_capability(&request, "metrics:read") {
            return *response;
        }
        let Some(object) = request.body.as_object() else {
            return self.failure(
                request.request_id,
                self.observed_generation(),
                ErrorCode::ValidationFailed,
                "events.subscribe body must be an object",
                None,
            );
        };
        if object.keys().any(|key| key != "last_event_id") {
            return self.failure(
                request.request_id,
                self.observed_generation(),
                ErrorCode::ValidationFailed,
                "unknown events.subscribe field",
                None,
            );
        }
        let last_event_id = match object.get("last_event_id") {
            None | Some(Value::Null) => None,
            Some(value) => match value.as_u64() {
                Some(value) => Some(value),
                None => {
                    return self.failure(
                        request.request_id,
                        self.observed_generation(),
                        ErrorCode::ValidationFailed,
                        "last_event_id must be an unsigned integer",
                        None,
                    );
                }
            },
        };
        let reset_required = self.service.event_replay_gap(last_event_id);
        let latest_event_id = self.service.latest_event_id();
        let events: Vec<_> = self
            .service
            .events_since(last_event_id)
            .into_iter()
            .map(|event| {
                json!({
                    "id": event.id,
                    "generation": {"scope": event_generation_scope(event.kind), "value": event.generation},
                    "type": event_type(event.kind),
                    "emitted_at": event.emitted_at_ms.and_then(rfc3339_utc),
                    "resource_type": event_type(event.kind).split('.').next().unwrap_or("runtime"),
                    "resource_id": event.resource_id,
                    "payload": event.payload,
                })
            })
            .collect();
        self.success(request.request_id, json!({"items": events, "reset_required": reset_required, "latest_event_id": latest_event_id}))
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
        let expected = match self.required_configuration_generation(&request) {
            Ok(value) => value,
            Err(response) => return *response,
        };
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
        match self.service.enable_system_proxy_precondition(
            &request.actor.id,
            internal_request_id,
            self.platform,
            listener_id,
            expected,
        ) {
            Ok(mutation) => self.success(
                request.request_id,
                json!({
                    "applied_generation": {"scope": "configuration", "value": mutation.generation},
                    "resource": system_proxy_status_value(&mutation.status),
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
        let expected = match self.required_configuration_generation(&request) {
            Ok(value) => value,
            Err(response) => return *response,
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
        match self.service.disable_system_proxy_precondition(
            &request.actor.id,
            internal_request_id,
            self.platform,
            expected,
        ) {
            Ok(mutation) => self.success(
                request.request_id,
                json!({
                    "applied_generation": {"scope": "configuration", "value": mutation.generation},
                    "resource": system_proxy_status_value(&mutation.status),
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
        match &error {
            crate::ControlError::GenerationConflict { expected, current } => return self.failure(request_id, self.observed_generation(), ErrorCode::GenerationConflict, "generation mismatch", Some(json!({"expected": {"scope": "configuration", "value": expected}, "current": {"scope": "configuration", "value": current}}))),
            crate::ControlError::RevisionConflict { expected, current } => return self.failure(request_id, self.observed_generation(), ErrorCode::GenerationConflict, "subscription revision mismatch", Some(json!({"expected_revision": expected, "current_revision": current}))),
            crate::ControlError::RefreshAlreadyQueued(_) => return self.failure(request_id, self.observed_generation(), ErrorCode::ValidationFailed, "subscription refresh is already queued", Some(json!({"retryable": true}))),
            _ => {}
        }
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
            crate::ControlError::InvalidSubscription {
                field: "enabled/source.type",
            } => (
                ErrorCode::ValidationFailed,
                "subscription is disabled or its source cannot be refreshed",
            ),
            crate::ControlError::InvalidSystemProxyListener { .. } => (
                ErrorCode::ValidationFailed,
                "listener cannot back system proxy",
            ),
            crate::ControlError::EmptyActor => (
                ErrorCode::AuthenticationRequired,
                "actor identity is required",
            ),
            crate::ControlError::GenerationConflict { .. }
            | crate::ControlError::RevisionConflict { .. } => {
                (ErrorCode::GenerationConflict, "generation conflict")
            }
            crate::ControlError::IdempotencyConflict { .. } => {
                (ErrorCode::IdempotencyConflict, "idempotency conflict")
            }
            crate::ControlError::PlatformProxy { .. } => (
                ErrorCode::PersistenceUnavailable,
                "platform system-proxy operation failed",
            ),
            crate::ControlError::ObservationUnavailable
            | crate::ControlError::PersistenceUnavailable => (
                ErrorCode::PersistenceUnavailable,
                "control service is unavailable",
            ),
            crate::ControlError::ResourceLimit { .. } => (
                ErrorCode::ResourceLimit,
                "control service resource limit reached",
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

    fn required_configuration_generation(
        &self,
        request: &RequestEnvelope,
    ) -> Result<crate::control::GenerationPrecondition, Box<ResponseEnvelope>> {
        match request.expected_generation.as_ref() {
            Some(expected) if expected.scope == "configuration" => Ok(
                crate::control::GenerationPrecondition::Expected(expected.value),
            ),
            Some(_) => Err(Box::new(self.failure(
                request.request_id.clone(),
                self.observed_generation(),
                ErrorCode::ValidationFailed,
                "configuration generation precondition is required",
                None,
            ))),
            None if request
                .actor
                .capabilities
                .iter()
                .any(|value| value == "force") =>
            {
                Ok(crate::control::GenerationPrecondition::Force)
            }
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
        // Unix platforms expose ordinary listener inventory but have no system-proxy
        // activation state. Keep this response distinct from Windows'
        // disabled state so clients cannot mistake unsupported for restored.
        if self.platform != SystemProxyPlatform::Windows {
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
        system_proxy_status_value(&self.service.system_proxy_status())
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

fn system_proxy_status_value(status: &crate::SystemProxyStatus) -> Value {
    json!({
        "enabled": status.enabled,
        "listener_id": status.listener_id.as_ref().map(|value| value.as_str()),
        "platform_effect": format!("{:?}", status.platform_effect).to_ascii_lowercase(),
        "environment_applied": status.environment_applied,
        "operating_system_applied": status.operating_system_applied,
        "restoration_state": format!("{:?}", status.restoration_state).to_ascii_lowercase(),
        "error": status.error,
    })
}

fn node_value(
    id: &crate::NodeId,
    state: &crate::NodeAdminState,
    observed: Option<&crate::NodeObservation>,
    metadata: Option<&crate::control::NodeMetadata>,
    generation: u64,
) -> Value {
    let mut labels = metadata.map_or_else(BTreeMap::new, |value| value.labels.clone());
    labels.extend(state.labels.clone());
    let health = observed.map_or("unknown", |value| match value.state {
        crate::NodeHealthState::Unknown => "unknown",
        crate::NodeHealthState::Up => "up",
        crate::NodeHealthState::Degraded => "degraded",
        crate::NodeHealthState::Down => "down",
    });
    let identity = pathchord_policy::ResourceIdentity::from_id(id.as_str());
    json!({
        "id": id.as_str(),
        "name": identity.name,
        "namespace": metadata.and_then(|value| value.namespace.as_deref()).unwrap_or(identity.namespace),
        "protocol": metadata.and_then(|value| value.protocol.as_deref()),
        "endpoint": metadata.and_then(|value| value.endpoint.as_deref()),
        "node": {"id": id.as_str(), "protocol": metadata.and_then(|value| value.protocol.as_deref()), "endpoint": metadata.and_then(|value| value.endpoint.as_deref())},
        "source": {"subscription": metadata.and_then(|value| value.source_subscription.as_deref()), "imported_at": Value::Null},
        "labels": labels,
        "admin": {"labels": state.labels, "tags": state.tags},
        "state": health,
        "observed": node_observation_value(observed),
        "generation": generation,
    })
}

fn node_observation_value(observation: Option<&crate::NodeObservation>) -> Value {
    let Some(observation) = observation else {
        return json!({"state": "unknown", "diagnostic": Value::Null});
    };
    json!({
        "state": format!("{:?}", observation.state).to_ascii_lowercase(),
        "rtt_ms": observation.rtt_ms,
        "jitter_ms": observation.jitter_ms,
        "loss_ppm": observation.loss_ppm,
        "throughput_bps": observation.throughput_bps,
        "effective_capacity_bps": observation.effective_capacity_bps,
        "diagnostic": observation.diagnostic,
        "quota": observation.usage.as_ref().map(|usage| json!({
            "upload_bytes": usage.upload_bytes, "download_bytes": usage.download_bytes,
            "total_bytes": usage.total_bytes, "remaining_bytes": usage.remaining_bytes(),
            "remaining_ratio": usage.remaining_ratio(), "expires_at": usage.expires_at,
        })),
        "billing": observation.usage.as_ref().and_then(|usage| usage.traffic_multiplier_basis_points).map(|basis_points| json!({"traffic_multiplier_basis_points": basis_points})),
    })
}

fn subscription_state_name(subscription: &crate::SubscriptionState) -> &'static str {
    if !subscription.spec.enabled {
        return "disabled";
    }
    match subscription.refresh_state {
        crate::SubscriptionRefreshState::Queued => "refreshing",
        crate::SubscriptionRefreshState::Failed => "failed",
        crate::SubscriptionRefreshState::Idle | crate::SubscriptionRefreshState::Healthy => {
            "enabled"
        }
    }
}

fn subscription_origin(value: &str) -> Option<String> {
    Some(url::Url::parse(value).ok()?.origin().ascii_serialization())
}

fn default_platform_adapter(platform: SystemProxyPlatform) -> Arc<dyn PlatformProxyAdapter> {
    match platform {
        SystemProxyPlatform::Linux | SystemProxyPlatform::FreeBsd => {
            Arc::new(crate::UnsupportedPlatformProxyAdapter)
        }
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
        Self::new(SystemProxyPlatform::current())
    }
}

#[async_trait::async_trait]
impl ManagementDispatcher for LocalControlDispatcher {
    async fn dispatch(&mut self, request: RequestEnvelope) -> ResponseEnvelope {
        self.dispatch_guarded(request, ManagementSource::Local)
            .await
    }

    async fn dispatch_from(
        &mut self,
        request: RequestEnvelope,
        source: ManagementSource,
    ) -> ResponseEnvelope {
        self.dispatch_guarded(request, source).await
    }

    async fn record_authentication_failure(&mut self, source: &str) {
        let _ = self.service.record_authentication_failure(source);
    }
}

fn is_subscription_visibility_mutation(operation: &str) -> bool {
    matches!(
        operation,
        "subscriptions.create"
            | "subscriptions.enable"
            | "subscriptions.disable"
            | "subscriptions.delete"
    )
}

fn session_value(
    session: &crate::SessionObservation,
    runtime: Option<&crate::control::EgressRuntimeObservation>,
    generation: u64,
) -> Value {
    json!({
        "session_id": session.session_id.to_string(),
        "egress_id": session.egress_id,
        "state": format!("{:?}", session.state).to_ascii_lowercase(),
        "admission_generation": session.admission_generation,
        "created_at_ms": session.created_at_ms,
        "created_at": session.created_at_ms.map(rfc3339_utc),
        "last_change_at_ms": session.last_change_at_ms,
        "last_change_at": session.last_change_at_ms.map(rfc3339_utc),
        "close_reason": session.close_reason,
        "ready_paths": session.ready_paths,
        "ready_path_count": session.ready_paths,
        "active_streams": session.active_streams,
        "active_udp_associations": session.active_udp_associations,
        "pending_session_controls": session.pending_session_controls,
        "control_pending": runtime
            .map(|value| value.pending_session_controls)
            .or(Some(session.pending_session_controls)),
        "generation": generation,
        "retained_outbound_bytes": session.retained_outbound_bytes,
        "bytes_sent": session.bytes_sent,
        "bytes_received": session.bytes_received,
    })
}

fn listener_value(
    descriptor: &ListenerDescriptor,
    generation: u64,
    observation: Option<&crate::control::ListenerObservation>,
) -> Value {
    json!({
        "id": descriptor.id.as_str(),
        "name": descriptor.id.resource_name(),
        "namespace": descriptor.id.namespace(),
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
        "state": observation.map_or("unknown", |value| value.state),
        "generation": generation,
        "status": {"reason": observation.and_then(|value| value.reason)},
    })
}

fn parse_string_set(value: Option<&Value>, field: &str) -> Result<BTreeSet<String>, String> {
    let Some(value) = value else {
        return Ok(BTreeSet::new());
    };
    let array = value
        .as_array()
        .ok_or_else(|| format!("{field} must be an array of strings"))?;
    array
        .iter()
        .map(|value| {
            value
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| format!("{field} must be an array of strings"))
        })
        .collect()
}

fn parse_string_map(
    value: Option<&Value>,
    field: &str,
) -> Result<BTreeMap<String, String>, String> {
    let Some(value) = value else {
        return Ok(BTreeMap::new());
    };
    let object = value
        .as_object()
        .ok_or_else(|| format!("{field} must be an object of string values"))?;
    object
        .iter()
        .map(|(key, value)| {
            value
                .as_str()
                .map(|value| (key.clone(), value.to_owned()))
                .ok_or_else(|| format!("{field} must be an object of string values"))
        })
        .collect()
}

#[derive(Debug, Clone)]
struct ListQuery {
    resource: String,
    page_size: usize,
    offset: usize,
    filters: BTreeMap<String, Value>,
    sort: String,
    descending: bool,
}

impl ListQuery {
    fn parse(
        body: &Value,
        resource: &str,
        allowed_filters: &[&str],
        allowed_sorts: &[&str],
    ) -> Result<Self, String> {
        let object = body
            .as_object()
            .ok_or_else(|| format!("{resource}.list body must be an object"))?;
        for key in object.keys() {
            if !matches!(
                key.as_str(),
                "page_size" | "page_token" | "filter" | "sort" | "direction"
            ) {
                return Err(format!("unknown {resource}.list query field: {key}"));
            }
        }
        let page_size = object.get("page_size").map_or(Ok(100), |value| {
            value
                .as_u64()
                .and_then(|value| usize::try_from(value).ok())
                .filter(|value| (1..=1000).contains(value))
                .ok_or_else(|| "page_size must be an integer in 1..=1000".to_owned())
        })?;
        let filters = match object.get("filter") {
            None | Some(Value::Null) => BTreeMap::new(),
            Some(Value::Object(value)) => {
                for key in value.keys() {
                    if !allowed_filters.contains(&key.as_str())
                        && !(resource == "nodes"
                            && key
                                .strip_prefix("label.")
                                .is_some_and(|label| !label.is_empty() && label.len() <= 64))
                    {
                        return Err(format!("unknown {resource} filter field: {key}"));
                    }
                }
                for (key, value) in value {
                    let valid = match key.as_str() {
                        "enabled" => value.is_boolean(),
                        "admission_generation" => value.as_u64().is_some(),
                        _ => value.as_str().is_some_and(|value| value.len() <= 256),
                    };
                    if !valid {
                        return Err(format!("invalid {resource} filter value for {key}"));
                    }
                }
                value.clone().into_iter().collect()
            }
            Some(_) => return Err("filter must be an object".to_owned()),
        };
        let sort = object.get("sort").map_or_else(
            || Ok((*allowed_sorts.first().unwrap_or(&"id")).to_owned()),
            |value| {
                value
                    .as_str()
                    .map(str::to_owned)
                    .ok_or_else(|| "sort must be a string".to_owned())
            },
        )?;
        if !allowed_sorts.contains(&sort.as_str()) {
            return Err(format!("sort must be one of: {}", allowed_sorts.join(", ")));
        }
        let descending = match object.get("direction") {
            None => false,
            Some(value) => match value
                .as_str()
                .ok_or_else(|| "direction must be asc or desc".to_owned())?
            {
                "asc" => false,
                "desc" => true,
                _ => return Err("direction must be asc or desc".to_owned()),
            },
        };
        let mut query = Self {
            resource: resource.to_owned(),
            page_size,
            offset: 0,
            filters,
            sort,
            descending,
        };
        query.offset = match object.get("page_token") {
            None | Some(Value::Null) => 0,
            Some(Value::String(value)) if value.len() <= 512 => {
                let bytes = URL_SAFE_NO_PAD
                    .decode(value)
                    .map_err(|_| "page_token is invalid".to_owned())?;
                let token =
                    std::str::from_utf8(&bytes).map_err(|_| "page_token is invalid".to_owned())?;
                let expected_prefix = format!("v1:{}:{:016x}:", query.resource, query.signature());
                token
                    .strip_prefix(&expected_prefix)
                    .and_then(|value| value.parse::<usize>().ok())
                    .filter(|offset| *offset > 0)
                    .ok_or_else(|| "page_token is invalid for this query".to_owned())?
            }
            Some(_) => return Err("page_token must be an opaque string".to_owned()),
        };
        Ok(query)
    }

    fn signature(&self) -> u64 {
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        self.resource.hash(&mut hasher);
        self.sort.hash(&mut hasher);
        self.descending.hash(&mut hasher);
        for (key, value) in &self.filters {
            key.hash(&mut hasher);
            value.to_string().hash(&mut hasher);
        }
        hasher.finish()
    }

    fn page(&self, mut items: Vec<Value>) -> (Vec<Value>, Option<String>) {
        items.retain(|item| {
            self.filters.iter().all(|(key, expected)| {
                query_value(item, key).is_some_and(|actual| actual == expected)
            })
        });
        items.sort_by(|left, right| {
            let ordering = compare_values(
                query_value(left, &self.sort),
                query_value(right, &self.sort),
            );
            let ordering = if self.descending {
                ordering.reverse()
            } else {
                ordering
            };
            ordering.then_with(|| resource_id(left).cmp(&resource_id(right)))
        });
        let end = self.offset.saturating_add(self.page_size).min(items.len());
        let page = if self.offset < items.len() {
            items[self.offset..end].to_vec()
        } else {
            Vec::new()
        };
        let next = (end < items.len()).then(|| {
            URL_SAFE_NO_PAD.encode(format!(
                "v1:{}:{:016x}:{end}",
                self.resource,
                self.signature()
            ))
        });
        (page, next)
    }
}

fn query_value<'a>(item: &'a Value, field: &str) -> Option<&'a Value> {
    if let Some(label) = field.strip_prefix("label.") {
        return item.get("labels")?.get(label);
    }
    if field == "source.subscription" {
        return item.get("source")?.get("subscription");
    }
    item.get(field)
}

fn sum_observed(values: impl Iterator<Item = Option<u64>>) -> Option<u64> {
    let mut result = None;
    for value in values {
        let value = value?;
        result = Some(result.unwrap_or(0_u64).saturating_add(value));
    }
    result
}

fn compare_values(left: Option<&Value>, right: Option<&Value>) -> std::cmp::Ordering {
    use std::cmp::Ordering;
    match (left, right) {
        (Some(Value::Number(left)), Some(Value::Number(right))) => {
            match (left.as_u64(), right.as_u64(), left.as_i64(), right.as_i64()) {
                (Some(a), Some(b), _, _) => a.cmp(&b),
                (_, _, Some(a), Some(b)) => a.cmp(&b),
                _ => left
                    .as_f64()
                    .partial_cmp(&right.as_f64())
                    .unwrap_or(Ordering::Equal),
            }
        }
        (Some(Value::String(left)), Some(Value::String(right))) => left.cmp(right),
        (Some(Value::Bool(left)), Some(Value::Bool(right))) => left.cmp(right),
        (None | Some(Value::Null), None | Some(Value::Null)) => Ordering::Equal,
        (None | Some(Value::Null), _) => Ordering::Less,
        (_, None | Some(Value::Null)) => Ordering::Greater,
        _ => Ordering::Equal,
    }
}

fn resource_id(item: &Value) -> String {
    ["id", "connection_id", "path_id", "session_id", "stream_id"]
        .iter()
        .filter_map(|key| item.get(key).and_then(Value::as_str))
        .collect::<Vec<_>>()
        .join("\0")
}

fn event_type(kind: crate::ControlEventKind) -> &'static str {
    match kind {
        crate::ControlEventKind::NodeChanged => "node.changed",
        crate::ControlEventKind::SubscriptionChanged
        | crate::ControlEventKind::SubscriptionRefreshRequested => "subscription.changed",
        crate::ControlEventKind::ObservationChanged => "metrics.snapshot",
        crate::ControlEventKind::SystemProxyChanged => "system_proxy.changed",
        crate::ControlEventKind::AuditNotice => "audit.notice",
        crate::ControlEventKind::PathChanged => "path.changed",
        crate::ControlEventKind::SessionChanged => "session.changed",
        crate::ControlEventKind::StreamChanged => "stream.changed",
        crate::ControlEventKind::ConnectionChanged => "connection.changed",
    }
}

fn event_generation_scope(kind: crate::ControlEventKind) -> &'static str {
    match kind {
        crate::ControlEventKind::ObservationChanged
        | crate::ControlEventKind::AuditNotice
        | crate::ControlEventKind::PathChanged
        | crate::ControlEventKind::SessionChanged
        | crate::ControlEventKind::StreamChanged
        | crate::ControlEventKind::ConnectionChanged => "observation",
        _ => "configuration",
    }
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

fn management_request_fingerprint(request: &RequestEnvelope) -> String {
    let capabilities: BTreeSet<_> = request.actor.capabilities.iter().collect();
    let canonical = json!({"api_version": request.api_version, "operation": request.operation,
        "expected_generation": request.expected_generation, "body": request.body, "capabilities": capabilities});
    crate::control::fingerprint_digest(&canonical.to_string())
}

fn eligible_for_idempotency(request: &RequestEnvelope) -> bool {
    let capability = match request.operation.as_str() {
        "nodes.patch_labels" | "nodes.patch_tags" => "nodes:write",
        "subscriptions.create"
        | "subscriptions.delete"
        | "subscriptions.enable"
        | "subscriptions.disable"
        | "subscriptions.refresh" => "subscriptions:write",
        "system_proxy.enable" | "system_proxy.disable" => "system_proxy:write",
        _ => return false,
    };
    request.api_version == LOCAL_API_VERSION
        && !request.actor.id.is_empty()
        && request.actor.id.len() <= 128
        && !request.actor.id.chars().any(char::is_control)
        && !request.request_id.is_empty()
        && request.request_id.len() <= 128
        && !request.request_id.chars().any(char::is_control)
        && request
            .actor
            .capabilities
            .iter()
            .any(|value| value == capability)
}

fn cacheable_failure(response: &ResponseEnvelope) -> bool {
    response.error.as_ref().is_some_and(|error| {
        matches!(
            error.code,
            ErrorCode::ValidationFailed
                | ErrorCode::NotFound
                | ErrorCode::GenerationConflict
                | ErrorCode::UnsupportedOperation
        ) && !error.details.as_ref().is_some_and(|details| {
            details.get("retryable").and_then(Value::as_bool) == Some(true)
                || details.get("pending_apply").and_then(Value::as_bool) == Some(true)
        })
    })
}

fn sanitize_cached_failure(response: &mut ResponseEnvelope) {
    let Some(error) = response.error.as_mut() else {
        return;
    };
    error.message = match error.code {
        ErrorCode::ValidationFailed
            if error.message == "subscription is disabled or its source cannot be refreshed" =>
        {
            error.message.clone()
        }
        ErrorCode::ValidationFailed => "validation failed".to_owned(),
        ErrorCode::NotFound => "resource was not found".to_owned(),
        ErrorCode::GenerationConflict => error.message.clone(),
        ErrorCode::UnsupportedOperation => "operation is unsupported".to_owned(),
        _ => return,
    };
    if error.code != ErrorCode::GenerationConflict {
        error.details = None;
    }
}

fn rfc3339_utc(milliseconds: u64) -> Option<String> {
    // Convert days since 1970-01-01 to the proleptic Gregorian calendar.
    let seconds = milliseconds / 1_000;
    let days = i64::try_from(seconds / 86_400).ok()?.checked_add(719_468)?;
    let era = days / 146_097;
    let day_of_era = days - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_part = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_part + 2) / 5 + 1;
    let month = month_part + if month_part < 10 { 3 } else { -9 };
    let year = year + i64::from(month <= 2);
    if year > 9_999 {
        return None;
    }
    let day_seconds = seconds % 86_400;
    Some(format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{:03}Z",
        day_seconds / 3_600,
        day_seconds / 60 % 60,
        day_seconds % 60,
        milliseconds % 1_000
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Actor, ListenerKind};
    use std::net::SocketAddr;

    #[test]
    fn node_queries_keep_independent_billing_without_usage_measurements() {
        let mut dispatcher = LocalControlDispatcher::new(SystemProxyPlatform::Linux);
        let node = crate::NodeId::new("billing-only").unwrap();
        dispatcher.service_mut().add_node(node.clone()).unwrap();
        dispatcher
            .service_mut()
            .set_node_observation(
                node,
                crate::NodeObservation {
                    state: crate::NodeHealthState::Unknown,
                    rtt_ms: None,
                    jitter_ms: None,
                    loss_ppm: None,
                    throughput_bps: None,
                    effective_capacity_bps: None,
                    diagnostic: None,
                    usage: Some(pathchord_transit::SubscriptionUsage {
                        upload_bytes: None,
                        download_bytes: None,
                        total_bytes: None,
                        expires_at: None,
                        traffic_multiplier_basis_points: Some(25000),
                    }),
                },
            )
            .unwrap();
        let response = dispatcher.dispatch(request(
            "nodes.get",
            &["nodes:read"],
            json!({"node_id": "billing-only"}),
        ));
        assert!(response.ok);
        let node = response.result.unwrap();
        assert!(node["observed"]["quota"]["upload_bytes"].is_null());
        assert!(node["observed"]["quota"]["download_bytes"].is_null());
        assert!(node["observed"]["quota"]["remaining_bytes"].is_null());
        assert_eq!(
            node["observed"]["billing"]["traffic_multiplier_basis_points"],
            25000
        );
    }

    #[test]
    fn connection_history_limit_is_queryable_as_typed_degradation() {
        let mut dispatcher = LocalControlDispatcher::new(SystemProxyPlatform::Linux);
        let handle = dispatcher.service().observation_handle();
        for index in 0..=crate::control::MAX_CONNECTION_HISTORY {
            handle
                .set_connection_observation(crate::ConnectionObservation {
                    connection_id: format!("closed-{index}"),
                    session_id: None,
                    stream_id: None,
                    state: crate::ConnectionState::Closed,
                    bytes_sent: 0,
                    bytes_received: 0,
                    target_display: None,
                })
                .unwrap();
        }
        for operation in ["status.get", "metrics.snapshot"] {
            let response = dispatcher.dispatch(request(
                operation,
                &["status:read", "metrics:read"],
                json!({}),
            ));
            assert!(response.ok);
            let result = response.result.unwrap();
            assert_eq!(result["observations"]["state"], "degraded");
            assert_eq!(
                result["observations"]["resource_limits"],
                json!(["connection_history"])
            );
        }
    }

    #[test]
    fn node_queries_expose_a_sanitized_unavailability_reason() {
        let mut dispatcher = LocalControlDispatcher::new(SystemProxyPlatform::Linux);
        let node = crate::NodeId::new("imported-node").unwrap();
        dispatcher.service_mut().add_node(node.clone()).unwrap();
        dispatcher
            .service_mut()
            .set_node_observation(
                node,
                crate::NodeObservation {
                    state: crate::NodeHealthState::Down,
                    rtt_ms: None,
                    jitter_ms: None,
                    loss_ppm: None,
                    throughput_bps: None,
                    effective_capacity_bps: None,
                    diagnostic: Some(pathchord_transit::NodeDiagnostic {
                        code: pathchord_transit::NodeUnavailableReason::UnsupportedParameters,
                        fields: vec!["reality-opts".to_owned()],
                        message: "node has unsupported connection parameters".to_owned(),
                    }),
                    usage: Some(pathchord_transit::SubscriptionUsage {
                        upload_bytes: Some(100),
                        download_bytes: Some(150),
                        total_bytes: Some(1000),
                        expires_at: Some(1900000000),
                        traffic_multiplier_basis_points: Some(25000),
                    }),
                },
            )
            .unwrap();
        for (operation, body) in [
            ("nodes.list", json!({})),
            ("nodes.get", json!({"node_id":"imported-node"})),
        ] {
            let result = dispatcher.dispatch(request(operation, &["nodes:read"], body));
            assert!(result.ok);
            let value = result.result.unwrap();
            let node = if operation == "nodes.list" {
                &value["items"][0]
            } else {
                &value
            };
            assert_eq!(node["observed"]["state"], "down");
            assert_eq!(node["observed"]["diagnostic"]["fields"][0], "reality-opts");
            assert_eq!(node["observed"]["quota"]["remaining_bytes"], 750);
            assert_eq!(node["observed"]["quota"]["expires_at"], 1900000000_u64);
            assert_eq!(
                node["observed"]["billing"]["traffic_multiplier_basis_points"],
                25000
            );
            assert_eq!(node["admin"]["labels"], json!({}));
        }
    }

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
            expected_generation: matches!(
                operation,
                "system_proxy.enable" | "system_proxy.disable"
            )
            .then(|| GenerationExpectation {
                scope: "configuration".into(),
                value: 0,
            }),
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
                    admission_generation: None,
                    created_at_ms: None,
                    last_change_at_ms: None,
                    close_reason: None,
                    ready_paths: 1,
                    active_streams: 2,
                    active_udp_associations: 0,
                    pending_session_controls: 0,
                    retained_outbound_bytes: 3,
                    bytes_sent: 4,
                    bytes_received: 5,
                }],
                [crate::PathObservation {
                    path_id,
                    session_id,
                    egress_id: Some("egress-a".into()),
                    transit_proxy_id: Some("transit-a".into()),
                    state: pathchord_core::PathState::Active,
                    ready_since_ms: None,
                    last_change_at_ms: None,
                    rtt_ms: Some(12),
                    jitter_ms: Some(3),
                    loss_ppm: Some(4_000),
                    throughput_bps: Some(5_000_000),
                    upstream_throughput_bps: Some(4_000_000),
                    downstream_throughput_bps: Some(6_000_000),
                    available_capacity_bps: Some(7_000_000),
                    reordering_events: Some(6),
                    control_pending: Some(1),
                    control_retransmissions: Some(2),
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
        assert!(
            streams.result.expect("stream metrics")["items"]
                .as_array()
                .unwrap()
                .is_empty()
        );

        observations
            .replace_stream_observations([crate::StreamObservation {
                session_id,
                stream_id: pathchord_core::StreamId::new(53).expect("stream id"),
                state: pathchord_core::StreamState::Open,
                target_display: "private.example:443".into(),
                traffic_class: Some("interactive".into()),
                traffic_class_priority: Some(10),
                traffic_class_share: Some(2),
                bytes_sent: 10,
                bytes_received: 11,
                bytes_acked: 9,
                retransmissions: 1,
                reorder_buffer_bytes: 2,
                receive_window: 3,
                opened_at_ms: 4,
                closed_at_ms: None,
                close_reason: None,
            }])
            .unwrap();
        let redacted =
            dispatcher.dispatch(request("metrics.streams", &["metrics:read"], json!({})));
        let redacted = &redacted.result.expect("redacted stream metrics")["items"][0];
        assert!(redacted["target"].is_null());
        assert_eq!(redacted["target_redacted"], true);
        assert_eq!(redacted["traffic_class"], "interactive");
        let revealed = dispatcher.dispatch(request(
            "metrics.streams",
            &["metrics:read", "targets:read"],
            json!({}),
        ));
        assert_eq!(
            revealed.result.expect("revealed stream metrics")["items"][0]["target"],
            "private.example:443"
        );
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
    fn listeners_list_preserves_and_filters_the_mixed_kind() {
        let mut dispatcher = dispatcher(SystemProxyPlatform::Linux);
        let mut mixed = dispatcher
            .service()
            .listeners()
            .get(&ListenerId::new("local-http"))
            .cloned()
            .unwrap();
        mixed.id = ListenerId::new("shared-proxy");
        mixed.kind = ListenerKind::Mixed;
        mixed.authentication_required = true;
        mixed.flow_tags.insert("interactive".to_owned());
        dispatcher.service_mut().register_listener(mixed);
        let response = dispatcher.dispatch(request(
            "listeners.list",
            &["listeners:read"],
            json!({"filter": {"kind": "mixed"}, "sort": "kind"}),
        ));
        assert!(response.ok);
        let result = response.result.expect("mixed listener inventory");
        let items = result["items"].as_array().unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0]["id"], "shared-proxy");
        assert_eq!(items[0]["kind"], "mixed");
        assert_eq!(items[0]["authentication"], "required");
        assert_eq!(items[0]["flow_tags"], json!(["interactive"]));
    }

    #[test]
    fn resource_views_preserve_names_and_namespace_independently_of_internal_ids() {
        let id = pathchord_policy::TransitProxyId::in_namespace("tenant-a", "shared");
        let id = crate::NodeId::new(id.as_str()).unwrap();
        let node = node_value(&id, &crate::NodeAdminState::default(), None, None, 1);
        assert_eq!(node["id"], id.as_str());
        assert_eq!(node["name"], "shared");
        assert_eq!(node["namespace"], "tenant-a");
        let mut dispatcher = dispatcher(SystemProxyPlatform::Linux);
        let mut listener = dispatcher
            .service()
            .listeners()
            .get(&ListenerId::new("local-http"))
            .unwrap()
            .clone();
        listener.id = ListenerId::in_namespace("tenant-b", "shared");
        dispatcher.service_mut().register_listener(listener);
        let result = dispatcher
            .dispatch(request("listeners.list", &["listeners:read"], json!({})))
            .result
            .unwrap();
        let listener = result["items"]
            .as_array()
            .unwrap()
            .iter()
            .find(|item| item["name"] == "shared")
            .unwrap();
        assert_eq!(listener["namespace"], "tenant-b");
    }

    #[test]
    fn resource_lists_validate_queries_and_paginate_nodes() {
        let mut dispatcher = dispatcher(SystemProxyPlatform::Linux);
        dispatcher
            .service_mut()
            .add_node(crate::NodeId::new("node-a").expect("node"))
            .unwrap();
        dispatcher
            .service_mut()
            .add_node(crate::NodeId::new("node-b").expect("node"))
            .unwrap();
        let first = dispatcher.dispatch(request(
            "nodes.list",
            &["nodes:read"],
            json!({"page_size": 1, "sort": "id"}),
        ));
        assert!(first.ok);
        let result = first.result.expect("node page");
        assert_eq!(result["items"].as_array().unwrap().len(), 1);
        assert!(result["next_page_token"].is_string());

        let invalid = dispatcher.dispatch(request(
            "nodes.list",
            &["nodes:read"],
            json!({"filter": {"unknown": "value"}}),
        ));
        assert_eq!(
            invalid.error.expect("validation error").code,
            ErrorCode::ValidationFailed
        );
    }

    #[test]
    fn list_queries_sort_numbers_and_bind_tokens_to_filters() {
        let query = ListQuery::parse(
            &json!({"page_size": 1, "sort": "revision"}),
            "subscriptions",
            &["enabled"],
            &["id", "revision"],
        )
        .unwrap();
        let values = vec![
            json!({"id": "a", "revision": 10, "enabled": true}),
            json!({"id": "b", "revision": 2, "enabled": true}),
        ];
        let (first, token) = query.page(values.clone());
        assert_eq!(first[0]["id"], "b");
        let token = token.unwrap();
        let next = ListQuery::parse(
            &json!({"page_size": 1, "sort": "revision", "page_token": token}),
            "subscriptions",
            &["enabled"],
            &["id", "revision"],
        )
        .unwrap();
        assert_eq!(next.page(values).0[0]["id"], "a");
        assert!(
            ListQuery::parse(
                &json!({"page_token": token, "filter": {"enabled": false}, "sort": "revision"}),
                "subscriptions",
                &["enabled"],
                &["id", "revision"]
            )
            .is_err()
        );
        assert!(
            ListQuery::parse(
                &json!({"filter": {"enabled": "true"}}),
                "subscriptions",
                &["enabled"],
                &["id"]
            )
            .is_err()
        );
    }

    #[test]
    fn node_filters_use_published_metadata_and_admin_labels() {
        let mut dispatcher = dispatcher(SystemProxyPlatform::Linux);
        let id = crate::NodeId::new("node-a").unwrap();
        dispatcher.service_mut().add_node(id.clone()).unwrap();
        let handle = dispatcher.service().observation_handle();
        handle
            .set_node_metadata(
                id,
                Some("default".into()),
                Some("socks5".into()),
                Some("proxy.test:1080".into()),
                Some("provider-a".into()),
                BTreeMap::from([("region".into(), "jp".into())]),
            )
            .unwrap();
        let query = dispatcher.dispatch(request("nodes.list", &["nodes:read"], json!({"filter": {"namespace": "default", "source.subscription": "provider-a", "label.region": "jp"}})));
        let items = query.result.unwrap()["items"].as_array().unwrap().clone();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0]["node"]["protocol"], "socks5");
        assert_eq!(items[0]["source"]["subscription"], "provider-a");
    }

    #[test]
    fn listener_inventory_tracks_observed_lifecycle() {
        let mut dispatcher = dispatcher(SystemProxyPlatform::Linux);
        let handle = dispatcher.service().observation_handle();
        let id = ListenerId::new("local-http");
        let state = |dispatcher: &mut LocalControlDispatcher| {
            dispatcher
                .dispatch(request(
                    "listeners.list",
                    &["listeners:read"],
                    json!({"filter": {"kind": "http"}}),
                ))
                .result
                .unwrap()["items"][0]["state"]
                .clone()
        };
        assert_eq!(state(&mut dispatcher), "unknown");
        handle
            .apply_listener_event(crate::ListenerRuntimeEvent::ListenerStarted {
                listener_id: id.clone(),
                bind: None,
                interface: None,
                address: None,
                mtu: None,
            })
            .unwrap();
        assert_eq!(state(&mut dispatcher), "available");
        handle
            .apply_listener_event(crate::ListenerRuntimeEvent::ListenerFailed {
                listener_id: id,
                error: "untrusted error".into(),
            })
            .unwrap();
        let result = dispatcher
            .dispatch(request(
                "listeners.list",
                &["listeners:read"],
                json!({"filter": {"state": "degraded"}}),
            ))
            .result
            .unwrap();
        assert_eq!(result["items"][0]["status"]["reason"], "listener_failed");
    }

    #[test]
    fn utc_timestamps_are_rfc3339_and_keep_milliseconds() {
        assert_eq!(rfc3339_utc(0).as_deref(), Some("1970-01-01T00:00:00.000Z"));
        assert_eq!(
            rfc3339_utc(1_709_251_200_123).as_deref(),
            Some("2024-03-01T00:00:00.123Z")
        );
        assert_eq!(rfc3339_utc(u64::MAX), None);
    }

    #[test]
    fn snapshot_exposes_published_egress_reports_without_fabricating_missing_values() {
        let mut dispatcher = dispatcher(SystemProxyPlatform::Linux);
        let handle = dispatcher.service().observation_handle();
        let report = pathchord_core::StatusReport {
            connected: true,
            service_state: pathchord_core::EgressServiceState::Up,
            admission_allowed: true,
            admission_reason: pathchord_core::AdmissionReason::None,
            load_basis_points: 2500,
            connection_utilization_basis_points: 1000,
            bandwidth_utilization_basis_points: 5000,
            active_sessions: 1,
            active_streams: 2,
            active_target_connections: 3,
            configured_capacity_bps: 1234,
            effective_capacity_bps: 1234,
            current_wire_rate_bps: 100,
            replication_allowance_bps: 1234,
            capacity_state: pathchord_core::CapacityState::Measured,
            report_seqno: 1,
            sample_age_ms: 5,
            expires_after_ms: 1000,
        };
        handle
            .set_egress_runtime("egress-a".into(), Some(report), 25, true, 4, 3)
            .unwrap();
        let response =
            dispatcher.dispatch(request("metrics.snapshot", &["metrics:read"], json!({})));
        let result = response.result.unwrap();
        assert_eq!(result["egress"]["configured"], 1);
        assert_eq!(result["egress_reports"][0]["load_ratio"], 0.25);
        assert_eq!(result["egress_reports"][0]["status_report_age_ms"], 25);
        assert_eq!(result["udp"]["associations"], 4);
        assert!(result["captured_at"].as_str().unwrap().ends_with('Z'));
    }

    #[test]
    fn observation_events_capture_real_scope_payload_and_creation_time() {
        let mut dispatcher = dispatcher(SystemProxyPlatform::Linux);
        let handle = dispatcher.service().observation_handle();
        let session_id = pathchord_core::SessionId::new(51);
        handle
            .replace_session_observations(
                [crate::SessionObservation {
                    session_id,
                    egress_id: "egress-a".into(),
                    state: pathchord_core::SessionState::Active,
                    admission_generation: None,
                    created_at_ms: None,
                    last_change_at_ms: None,
                    close_reason: None,
                    ready_paths: 1,
                    active_streams: 0,
                    active_udp_associations: 0,
                    pending_session_controls: 0,
                    retained_outbound_bytes: 0,
                    bytes_sent: 0,
                    bytes_received: 0,
                }],
                [],
            )
            .unwrap();
        let first = dispatcher.dispatch(request("events.subscribe", &["metrics:read"], json!({})));
        let event = first.result.unwrap()["items"]
            .as_array()
            .unwrap()
            .iter()
            .find(|event| event["type"] == "session.changed")
            .unwrap()
            .clone();
        assert_eq!(event["generation"]["scope"], "observation");
        assert_eq!(event["payload"]["egress_id"], "egress-a");
        let second = dispatcher.dispatch(request("events.subscribe", &["metrics:read"], json!({})));
        let replay = second.result.unwrap()["items"]
            .as_array()
            .unwrap()
            .iter()
            .find(|item| item["id"] == event["id"])
            .unwrap()
            .clone();
        assert_eq!(event["emitted_at"], replay["emitted_at"]);
    }

    #[test]
    fn node_patch_rejects_unknown_fields_and_wrong_value_types() {
        let mut dispatcher = dispatcher(SystemProxyPlatform::Linux);
        dispatcher
            .service_mut()
            .add_node(crate::NodeId::new("node-a").expect("node"))
            .unwrap();
        let mut unknown = request(
            "nodes.patch_labels",
            &["nodes:write"],
            json!({"node_id": "node-a", "set": {}, "remove": [], "extra": true}),
        );
        unknown.expected_generation = Some(GenerationExpectation {
            scope: "configuration".to_owned(),
            value: 0,
        });
        assert_eq!(
            dispatcher
                .dispatch(unknown)
                .error
                .expect("validation error")
                .code,
            ErrorCode::ValidationFailed
        );

        let mut wrong_type = request(
            "nodes.patch_tags",
            &["nodes:write"],
            json!({"node_id": "node-a", "add": "preferred", "remove": []}),
        );
        wrong_type.expected_generation = Some(GenerationExpectation {
            scope: "configuration".to_owned(),
            value: 0,
        });
        assert_eq!(
            dispatcher
                .dispatch(wrong_type)
                .error
                .expect("validation error")
                .code,
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
        assert!(items[0]["source"]["url"].is_null());
        assert_eq!(
            items[0]["source"]["url_redaction_reason"],
            "sensitive_source"
        );
        assert_eq!(items[0]["source"]["origin"], "https://provider.example");
        assert_eq!(items[0]["source"]["credentials_ref"], "provider-a-token");
        assert_eq!(items[0]["refresh"]["interval_seconds"], 900);
        assert_eq!(items[0]["cache"]["path"], "provider-a.snapshot");
    }

    #[test]
    fn subscription_list_redacts_url_path_query_and_fragment() {
        let mut dispatcher = dispatcher(SystemProxyPlatform::Linux);
        let spec = crate::SubscriptionSpec {
            id: crate::SubscriptionId::new("private-provider").unwrap(),
            source_type: "clash".into(),
            display_name: "Provider".into(),
            enabled: true,
            url: "https://provider.example/token-in-path?token=secret-query#secret-fragment".into(),
            credentials_ref: None,
            refresh: crate::SubscriptionRefreshSpec::default(),
            cache: None,
        };
        dispatcher
            .service_mut()
            .add_subscription("operator", RequestId::new(1), 0, spec)
            .unwrap();
        let result = dispatcher
            .dispatch(request("subscriptions.list", &["status:read"], json!({})))
            .result
            .unwrap();
        assert!(result["items"][0]["source"]["url"].is_null());
        assert_eq!(
            result["items"][0]["source"]["origin"],
            "https://provider.example"
        );
        assert_eq!(
            result["items"][0]["source"]["url_redaction_reason"],
            "sensitive_source"
        );
        let serialized = result.to_string();
        assert!(!serialized.contains("token-in-path"));
        assert!(!serialized.contains("secret-query"));
        assert!(!serialized.contains("secret-fragment"));
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
    fn freebsd_system_proxy_operations_are_unsupported() {
        let mut dispatcher = dispatcher(SystemProxyPlatform::FreeBsd);
        let generation = dispatcher.service().snapshot().generation;
        for (operation, params) in [
            ("system_proxy.enable", json!({"listener_id": "local-http"})),
            ("system_proxy.disable", json!({})),
        ] {
            let response = dispatcher.dispatch(request(operation, &["system_proxy:write"], params));
            assert!(!response.ok);
            let error = response.error.expect("unsupported system-proxy operation");
            assert_eq!(error.code, ErrorCode::UnsupportedOperation);
            assert_eq!(dispatcher.service().snapshot().generation, generation);
        }
        let response =
            dispatcher.dispatch(request("system_proxy.get", &["status:read"], json!({})));
        assert!(response.ok);
        let resource = response.result.expect("FreeBSD system-proxy status");
        assert_eq!(resource["enabled"], false);
        assert_eq!(resource["listener_id"], Value::Null);
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
    fn force_replay_is_stable_and_system_proxy_replays_before_generation_check() {
        let mut dispatcher = dispatcher(SystemProxyPlatform::Windows);
        dispatcher
            .service_mut()
            .add_node(crate::NodeId::new("node-a").unwrap())
            .unwrap();
        let mut force = request(
            "nodes.patch_tags",
            &["nodes:write", "force"],
            json!({"node_id": "node-a", "add": ["first"]}),
        );
        force.request_id = "force-1".into();
        let first_force = dispatcher.dispatch(force.clone());
        assert!(first_force.ok);
        dispatcher
            .service()
            .observation_handle()
            .set_egress_runtime("observation-change".into(), None, 0, false, 0, 0)
            .unwrap();
        assert_eq!(dispatcher.dispatch(force), first_force);

        let mut enable = request(
            "system_proxy.enable",
            &["system_proxy:write"],
            json!({"listener_id": "local-http"}),
        );
        enable.expected_generation.as_mut().unwrap().value = 1;
        enable.request_id = "enable-1".into();
        assert_eq!(
            dispatcher.dispatch(enable.clone()).result.unwrap()["resource"]["enabled"],
            true
        );
        let mut disable = request("system_proxy.disable", &["system_proxy:write"], json!({}));
        disable.expected_generation.as_mut().unwrap().value = 1;
        disable.request_id = "disable-1".into();
        assert!(dispatcher.dispatch(disable).ok);
        let mut change = request(
            "nodes.patch_tags",
            &["nodes:write"],
            json!({"node_id": "node-a", "add": ["second"]}),
        );
        change.expected_generation = Some(GenerationExpectation {
            scope: "configuration".into(),
            value: 1,
        });
        change.request_id = "change-1".into();
        assert!(dispatcher.dispatch(change).ok);
        let replay = dispatcher.dispatch(enable);
        assert!(replay.ok);
        assert_eq!(replay.result.unwrap()["resource"]["enabled"], true);
        assert!(!dispatcher.service().system_proxy_status().enabled);
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
