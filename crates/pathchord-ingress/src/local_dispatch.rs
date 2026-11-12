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
            "listeners.list" => self.dispatch_listeners(request),
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
                "runtime_snapshot": {"state": "fresh", "generation": snapshot.generation},
                "data_path_summary": "connected",
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
        let mut items = Vec::new();
        for descriptor in self.service.listeners().values() {
            items.push(listener_value(descriptor, generation));
        }
        self.success(
            request.request_id,
            json!({"items": items, "next_page_token": Value::Null}),
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

    fn system_proxy_value(&self) -> Value {
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

fn listener_value(descriptor: &ListenerDescriptor, generation: u64) -> Value {
    json!({
        "id": descriptor.id.as_str(),
        "kind": format!("{:?}", descriptor.kind).to_ascii_lowercase(),
        "platform": std::env::consts::OS,
        "bind": descriptor.bind.to_string(),
        "authentication": if descriptor.authentication_required {"required"} else {"disabled"},
        "state": "available",
        "generation": generation,
        "status": {"reason": Value::Null},
    })
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
                authentication_required: false,
            });
        dispatcher
            .service_mut()
            .register_listener(ListenerDescriptor {
                id: ListenerId::new("lan-tun"),
                kind: ListenerKind::Tun,
                bind: "0.0.0.0:15000".parse::<SocketAddr>().unwrap(),
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
        let listeners =
            dispatcher.dispatch(request("listeners.list", &["listeners:read"], json!({})));
        assert!(listeners.ok);
        assert_eq!(
            listeners.result.unwrap()["items"].as_array().unwrap().len(),
            2
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
