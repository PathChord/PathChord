//! Typed operation dispatch for the local control-plane envelope.
//!
//! This layer deliberately owns request validation and response shaping while
//! leaving sockets, named pipes, and platform side effects to adapters.

use std::hash::{Hash, Hasher};

use serde_json::{Value, json};

use crate::{
    ErrorBody, ErrorCode, GenerationExpectation, IngressControlService, LOCAL_API_VERSION,
    ListenerDescriptor, RequestEnvelope, ResponseEnvelope, SystemProxyPlatform,
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
            service: IngressControlService::new(),
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
            "sessions.list" => self.dispatch_empty_list(request, "sessions", "status:read"),
            "connections.list" => self.dispatch_connections_list(request),
            "listeners.list" => self.dispatch_listeners(request),
            "subscriptions.list" => self.dispatch_subscriptions_list(request),
            "metrics.snapshot" => self.dispatch_metrics_snapshot(request),
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
        self.success(
            request.request_id,
            json!({
                "ingress": {"state": "running"},
                "control_plane": {"state": "running"},
                "runtime_snapshot": {"state": "unavailable", "generation": snapshot.generation},
                "data_path_summary": "down",
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
                    "source_type": subscription.spec.source_type,
                    "enabled": subscription.spec.enabled,
                    "revision": subscription.revision,
                    "state": format!("{:?}", subscription.refresh_state).to_ascii_lowercase(),
                    "last_error": subscription.last_error,
                })
            })
            .collect();
        self.success(
            request.request_id,
            json!({"items": items, "next_page_token": Value::Null}),
        )
    }

    fn dispatch_connections_list(&self, request: RequestEnvelope) -> ResponseEnvelope {
        if let Err(response) = self.require_capability(&request, "metrics:read") {
            return *response;
        }
        let snapshot = self.service.observation_snapshot();
        let items: Vec<_> = snapshot
            .connections
            .values()
            .map(|connection| {
                json!({
                    "connection_id": connection.connection_id,
                    "session_id": connection.session_id.to_string(),
                    "stream_id": connection.stream_id.map(|id| id.get()),
                    "state": format!("{:?}", connection.state).to_ascii_lowercase(),
                    "bytes_sent": connection.bytes_sent,
                    "bytes_received": connection.bytes_received,
                    "target": connection.target_display,
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

    fn dispatch_empty_list(
        &self,
        request: RequestEnvelope,
        _resource: &str,
        capability: &str,
    ) -> ResponseEnvelope {
        if let Err(response) = self.require_capability(&request, capability) {
            return *response;
        }
        self.success(
            request.request_id,
            json!({"items": [], "next_page_token": Value::Null}),
        )
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

impl Default for LocalControlDispatcher {
    fn default() -> Self {
        Self::new(crate::SystemProxyPlatform::Linux)
    }
}

fn listener_value(descriptor: &ListenerDescriptor, generation: u64) -> Value {
    json!({
        "id": descriptor.id.as_str(),
        "kind": format!("{:?}", descriptor.kind).to_ascii_lowercase(),
        "platform": std::env::consts::OS,
        "bind": descriptor.bind.to_string(),
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
        "bind" => descriptor.bind.to_string(),
        _ => descriptor.id.as_str().to_owned(),
    }
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
                bind: "127.0.0.1:8080".parse::<SocketAddr>().unwrap(),
                allowed_sources: Vec::new(),
                authentication_required: false,
            });
        dispatcher
            .service_mut()
            .register_listener(ListenerDescriptor {
                id: ListenerId::new("lan-tun"),
                kind: ListenerKind::Tun,
                bind: "0.0.0.0:15000".parse::<SocketAddr>().unwrap(),
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
