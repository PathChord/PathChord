//! Egress-owned local authorization control dispatcher.

use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use pathchord_core::management::{
    ErrorBody, ErrorCode, GenerationExpectation, LOCAL_API_VERSION, ManagementDispatcher,
    RequestEnvelope, ResponseEnvelope,
};
use serde_json::{Value, json};

use crate::{
    AuthorizationCleanup, AuthorizationMutation, AuthorizationMutationRequest,
    AuthorizationMutationResult, AuthorizationRecord, AuthorizationState, AuthorizationStore,
    AuthorizationStoreError, IngressId,
};

const AUTHORIZATION_SCOPE: &str = "authorization";

type CleanupFuture = Pin<Box<dyn Future<Output = Result<AuthorizationCleanup, String>> + Send>>;
type CleanupHook = dyn Fn(IngressId) -> CleanupFuture + Send + Sync;
type StatusFuture = Pin<Box<dyn Future<Output = Result<Value, String>> + Send>>;
type StatusHook = dyn Fn() -> StatusFuture + Send + Sync;

#[derive(Clone)]
pub struct AuthorizationControlDispatcher {
    store: Arc<AuthorizationStore>,
    cleanup_hook: Arc<CleanupHook>,
    status_hook: Arc<StatusHook>,
}

impl std::fmt::Debug for AuthorizationControlDispatcher {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AuthorizationControlDispatcher")
            .field("store", &self.store)
            .finish_non_exhaustive()
    }
}

impl AuthorizationControlDispatcher {
    #[must_use]
    pub fn new(store: Arc<AuthorizationStore>) -> Self {
        Self {
            store,
            cleanup_hook: Arc::new(|_| Box::pin(async { Ok(AuthorizationCleanup::default()) })),
            status_hook: Arc::new(|| Box::pin(async { Ok(Value::Object(Default::default())) })),
        }
    }

    #[must_use]
    pub fn with_cleanup_hook<F, Fut>(mut self, hook: F) -> Self
    where
        F: Fn(IngressId) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<AuthorizationCleanup, String>> + Send + 'static,
    {
        self.cleanup_hook = Arc::new(move |id| Box::pin(hook(id)));
        self
    }

    #[must_use]
    pub fn with_status_hook<F, Fut>(mut self, hook: F) -> Self
    where
        F: Fn() -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<Value, String>> + Send + 'static,
    {
        self.status_hook = Arc::new(move || Box::pin(hook()));
        self
    }

    #[must_use]
    pub fn store(&self) -> &Arc<AuthorizationStore> {
        &self.store
    }

    pub async fn dispatch(&self, request: RequestEnvelope) -> ResponseEnvelope {
        let observed = self.observed_generation();
        if request.api_version != LOCAL_API_VERSION {
            return failure(
                request.request_id,
                observed,
                ErrorCode::UnsupportedOperation,
                "unsupported local API version",
                None,
            );
        }
        if request.actor.id.is_empty() {
            return failure(
                request.request_id,
                observed,
                ErrorCode::AuthenticationRequired,
                "actor identity is required",
                None,
            );
        }

        match request.operation.as_str() {
            "status.get" => self.status(request).await,
            "authorizations.list" => self.list(request),
            "authorizations.get" => self.get(request),
            "authorizations.enroll" => self.mutate(request, MutationKind::Enroll).await,
            "authorizations.enable" => self.mutate(request, MutationKind::Enable).await,
            "authorizations.disable" => self.mutate(request, MutationKind::Disable).await,
            "authorizations.revoke" => self.mutate(request, MutationKind::Revoke).await,
            "authorizations.delete" => self.mutate(request, MutationKind::Delete).await,
            operation => failure(
                request.request_id,
                observed,
                ErrorCode::UnsupportedOperation,
                "operation is not supported by the Egress control plane",
                Some(json!({"operation": operation})),
            ),
        }
    }

    async fn status(&self, request: RequestEnvelope) -> ResponseEnvelope {
        if let Some(response) =
            require_capability(&request, "status:read", self.observed_generation())
        {
            return response;
        }
        let snapshot = match self.store.snapshot() {
            Ok(snapshot) => snapshot,
            Err(error) => return self.store_failure(request.request_id, error),
        };
        let runtime = match (self.status_hook)().await {
            Ok(runtime) => runtime,
            Err(_) => {
                return failure(
                    request.request_id,
                    generation(snapshot.generation()),
                    ErrorCode::PersistenceUnavailable,
                    "Egress runtime status is unavailable",
                    None,
                );
            }
        };
        ResponseEnvelope::success(
            request.request_id,
            generation(snapshot.generation()),
            json!({
                "egress_id": snapshot.egress_id().as_str(),
                "authorization_generation": snapshot.generation(),
                "runtime": runtime,
            }),
        )
    }

    fn list(&self, request: RequestEnvelope) -> ResponseEnvelope {
        if let Some(response) =
            require_capability(&request, "status:read", self.observed_generation())
        {
            return response;
        }
        let snapshot = match self.store.snapshot() {
            Ok(snapshot) => snapshot,
            Err(error) => return self.store_failure(request.request_id, error),
        };
        let mut records: Vec<_> = snapshot.records().collect();
        records.sort_by(|left, right| left.ingress_id.as_str().cmp(right.ingress_id.as_str()));
        let items: Vec<_> = records
            .into_iter()
            .map(|record| record_value(snapshot.egress_id().as_str(), record))
            .collect();
        ResponseEnvelope::success(
            request.request_id,
            generation(snapshot.generation()),
            json!({"items": items, "next_page_token": Value::Null}),
        )
    }

    fn get(&self, request: RequestEnvelope) -> ResponseEnvelope {
        if let Some(response) =
            require_capability(&request, "status:read", self.observed_generation())
        {
            return response;
        }
        let ingress_id = match body_string(&request.body, "ingress_id") {
            Ok(value) => value,
            Err(message) => {
                return failure(
                    request.request_id,
                    self.observed_generation(),
                    ErrorCode::ValidationFailed,
                    message,
                    Some(json!({"field": "ingress_id"})),
                );
            }
        };
        let snapshot = match self.store.snapshot() {
            Ok(snapshot) => snapshot,
            Err(error) => return self.store_failure(request.request_id, error),
        };
        let Some(record) = snapshot
            .records()
            .find(|record| record.ingress_id.as_str() == ingress_id)
        else {
            return failure(
                request.request_id,
                generation(snapshot.generation()),
                ErrorCode::NotFound,
                "authorization record was not found",
                None,
            );
        };
        ResponseEnvelope::success(
            request.request_id,
            generation(snapshot.generation()),
            record_value(snapshot.egress_id().as_str(), record),
        )
    }

    async fn mutate(&self, request: RequestEnvelope, kind: MutationKind) -> ResponseEnvelope {
        if let Some(response) =
            require_capability(&request, "authorization:write", self.observed_generation())
        {
            return response;
        }
        let expected_generation = match request.expected_generation.as_ref() {
            Some(expected) if expected.scope == AUTHORIZATION_SCOPE => expected.value,
            Some(_) => {
                return failure(
                    request.request_id,
                    self.observed_generation(),
                    ErrorCode::ValidationFailed,
                    "authorization generation precondition is required",
                    Some(json!({"scope": AUTHORIZATION_SCOPE})),
                );
            }
            None => {
                return failure(
                    request.request_id,
                    self.observed_generation(),
                    ErrorCode::ValidationFailed,
                    "expected_generation is required for this mutation",
                    Some(json!({"scope": AUTHORIZATION_SCOPE})),
                );
            }
        };
        let ingress_id = match body_string(&request.body, "ingress_id") {
            Ok(value) => IngressId::new(value),
            Err(message) => {
                return failure(
                    request.request_id,
                    self.observed_generation(),
                    ErrorCode::ValidationFailed,
                    message,
                    Some(json!({"field": "ingress_id"})),
                );
            }
        };
        let mutation = match self.mutation(&request, kind) {
            Ok(mutation) => mutation,
            Err(response) => return *response,
        };
        let actor_id = request.actor.id.clone();
        let mut result = match self.store.mutate(AuthorizationMutationRequest {
            actor_id: request.actor.id,
            request_id: request.request_id.clone(),
            expected_generation,
            ingress_id: ingress_id.clone(),
            mutation,
        }) {
            Ok(result) => result,
            Err(error) => return self.store_failure(request.request_id, error),
        };
        if matches!(
            kind,
            MutationKind::Disable | MutationKind::Revoke | MutationKind::Delete
        ) && !result.cleanup_complete
        {
            let cleanup = match (self.cleanup_hook)(ingress_id.clone()).await {
                Ok(cleanup) => cleanup,
                Err(_) => {
                    return failure(
                        request.request_id,
                        generation(result.applied_generation),
                        ErrorCode::PersistenceUnavailable,
                        "authorization generation is pending live-resource cleanup",
                        Some(json!({"pending_apply": true})),
                    );
                }
            };
            if let Err(error) = self
                .store
                .record_cleanup(&actor_id, &request.request_id, cleanup)
            {
                return self.store_failure(request.request_id, error);
            }
            result.cleanup = cleanup;
            result.cleanup_complete = true;
        }
        self.mutation_success(request.request_id, &ingress_id, result)
    }

    fn mutation(
        &self,
        request: &RequestEnvelope,
        kind: MutationKind,
    ) -> Result<AuthorizationMutation, Box<ResponseEnvelope>> {
        let simple = match kind {
            MutationKind::Enable => Some(AuthorizationMutation::Enable),
            MutationKind::Disable => Some(AuthorizationMutation::Disable),
            MutationKind::Revoke => Some(AuthorizationMutation::Revoke),
            MutationKind::Delete => Some(AuthorizationMutation::Delete),
            MutationKind::Enroll => None,
        };
        if let Some(mutation) = simple {
            return Ok(mutation);
        }

        let snapshot = self
            .store
            .snapshot()
            .map_err(|error| Box::new(self.store_failure(request.request_id.clone(), error)))?;
        let egress_id = body_string(&request.body, "egress_id").map_err(|message| {
            Box::new(failure(
                request.request_id.clone(),
                generation(snapshot.generation()),
                ErrorCode::ValidationFailed,
                message,
                Some(json!({"field": "egress_id"})),
            ))
        })?;
        if egress_id != snapshot.egress_id().as_str() {
            return Err(Box::new(failure(
                request.request_id.clone(),
                generation(snapshot.generation()),
                ErrorCode::ValidationFailed,
                "enrollment names a different Egress",
                Some(json!({"field": "egress_id"})),
            )));
        }
        let encoded_key = body_string(&request.body, "public_key").map_err(|message| {
            Box::new(failure(
                request.request_id.clone(),
                generation(snapshot.generation()),
                ErrorCode::ValidationFailed,
                message,
                Some(json!({"field": "public_key"})),
            ))
        })?;
        let public_key = decode_public_key(encoded_key).map_err(|message| {
            Box::new(failure(
                request.request_id.clone(),
                generation(snapshot.generation()),
                ErrorCode::ValidationFailed,
                message,
                Some(json!({"field": "public_key"})),
            ))
        })?;
        let administrator_labels = labels(&request.body).map_err(|message| {
            Box::new(failure(
                request.request_id.clone(),
                generation(snapshot.generation()),
                ErrorCode::ValidationFailed,
                message,
                Some(json!({"field": "administrator_labels"})),
            ))
        })?;
        Ok(AuthorizationMutation::Enroll {
            public_key,
            administrator_labels,
        })
    }

    fn mutation_success(
        &self,
        request_id: String,
        ingress_id: &IngressId,
        result: AuthorizationMutationResult,
    ) -> ResponseEnvelope {
        let state = result.state.map(state_name);
        ResponseEnvelope::success(
            request_id,
            generation(result.applied_generation),
            json!({
                "applied_generation": generation(result.applied_generation),
                "resource": {"id": ingress_id.as_str(), "state": state},
                "replayed": result.replayed,
                "cleanup": {
                    "paths": result.cleanup.paths,
                    "sessions": result.cleanup.sessions,
                    "streams": result.cleanup.streams,
                    "target_connections": result.cleanup.target_connections,
                },
            }),
        )
    }

    fn store_failure(
        &self,
        request_id: String,
        error: AuthorizationStoreError,
    ) -> ResponseEnvelope {
        let observed = self.observed_generation();
        let (code, message, details) = match error {
            AuthorizationStoreError::GenerationConflict { expected, current } => (
                ErrorCode::GenerationConflict,
                "authorization generation conflict",
                Some(json!({"expected": expected, "current": current})),
            ),
            AuthorizationStoreError::AlreadyExists => (
                ErrorCode::ValidationFailed,
                "authorization record already exists",
                None,
            ),
            AuthorizationStoreError::NotFound => (
                ErrorCode::NotFound,
                "authorization record was not found",
                None,
            ),
            AuthorizationStoreError::RevokedIsTerminal => (
                ErrorCode::ValidationFailed,
                "revoked authorization state is terminal",
                None,
            ),
            AuthorizationStoreError::IdempotencyConflict => (
                ErrorCode::IdempotencyConflict,
                "request ID was reused with different input",
                None,
            ),
            AuthorizationStoreError::InvalidField { field } => (
                ErrorCode::ValidationFailed,
                "authorization request is invalid",
                Some(json!({"field": field})),
            ),
            AuthorizationStoreError::Sql(_)
            | AuthorizationStoreError::IdentityMismatch
            | AuthorizationStoreError::Snapshot(_)
            | AuthorizationStoreError::Json(_)
            | AuthorizationStoreError::Lock
            | AuthorizationStoreError::Clock => (
                ErrorCode::PersistenceUnavailable,
                "authorization store is unavailable",
                None,
            ),
        };
        failure(request_id, observed, code, message, details)
    }

    fn observed_generation(&self) -> GenerationExpectation {
        generation(
            self.store
                .snapshot()
                .map(|snapshot| snapshot.generation())
                .unwrap_or(0),
        )
    }
}

#[async_trait::async_trait]
impl ManagementDispatcher for AuthorizationControlDispatcher {
    async fn dispatch(&mut self, request: RequestEnvelope) -> ResponseEnvelope {
        AuthorizationControlDispatcher::dispatch(self, request).await
    }

    async fn record_authentication_failure(&mut self, source: &str) {
        let _ = self.store.record_authentication_failure(source);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MutationKind {
    Enroll,
    Enable,
    Disable,
    Revoke,
    Delete,
}

fn require_capability(
    request: &RequestEnvelope,
    capability: &str,
    observed: GenerationExpectation,
) -> Option<ResponseEnvelope> {
    if request
        .actor
        .capabilities
        .iter()
        .any(|candidate| candidate == capability)
    {
        None
    } else {
        Some(failure(
            request.request_id.clone(),
            observed,
            ErrorCode::CapabilityDenied,
            "actor lacks the required capability",
            Some(json!({"capability": capability})),
        ))
    }
}

fn body_string<'a>(body: &'a Value, field: &'static str) -> Result<&'a str, &'static str> {
    body.get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or("required string field is missing or empty")
}

fn labels(body: &Value) -> Result<BTreeMap<String, String>, &'static str> {
    let Some(value) = body.get("administrator_labels") else {
        return Ok(BTreeMap::new());
    };
    let Some(object) = value.as_object() else {
        return Err("administrator_labels must be an object of string values");
    };
    object
        .iter()
        .map(|(key, value)| {
            value
                .as_str()
                .map(|value| (key.clone(), value.to_owned()))
                .ok_or("administrator_labels must be an object of string values")
        })
        .collect()
}

fn decode_public_key(value: &str) -> Result<[u8; 32], &'static str> {
    if value.contains('=') {
        return Err("public_key must be unpadded base64url");
    }
    URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| "public_key must be unpadded base64url")?
        .try_into()
        .map_err(|_| "public_key must decode to exactly 32 bytes")
}

fn record_value(egress_id: &str, record: &AuthorizationRecord) -> Value {
    json!({
        "ingress_id": record.ingress_id.as_str(),
        "egress_id": egress_id,
        "public_key": URL_SAFE_NO_PAD.encode(record.ingress_public_key),
        "state": state_name(record.state),
        "administrator_labels": record.administrator_labels,
        "generation": record.record_generation,
    })
}

const fn state_name(state: AuthorizationState) -> &'static str {
    match state {
        AuthorizationState::Enabled => "enabled",
        AuthorizationState::Disabled => "disabled",
        AuthorizationState::Revoked => "revoked",
    }
}

fn generation(value: u64) -> GenerationExpectation {
    GenerationExpectation {
        scope: AUTHORIZATION_SCOPE.to_owned(),
        value,
    }
}

fn failure(
    request_id: String,
    observed: GenerationExpectation,
    code: ErrorCode,
    message: &'static str,
    details: Option<Value>,
) -> ResponseEnvelope {
    ResponseEnvelope::failure(
        request_id,
        observed,
        ErrorBody {
            code,
            message: message.to_owned(),
            details,
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use pathchord_core::management::Actor;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn dispatcher() -> AuthorizationControlDispatcher {
        AuthorizationControlDispatcher::new(Arc::new(
            AuthorizationStore::open(":memory:", crate::EgressId::new("egress-a"), [9; 32])
                .expect("store"),
        ))
    }

    fn request(
        operation: &str,
        request_id: &str,
        expected_generation: Option<u64>,
        body: Value,
    ) -> RequestEnvelope {
        RequestEnvelope {
            api_version: LOCAL_API_VERSION.to_owned(),
            operation: operation.to_owned(),
            request_id: request_id.to_owned(),
            actor: Actor {
                id: "local-admin".to_owned(),
                capabilities: vec!["status:read".to_owned(), "authorization:write".to_owned()],
            },
            expected_generation: expected_generation.map(generation),
            body,
        }
    }

    #[tokio::test]
    async fn enrollment_mutations_are_typed_and_idempotent() {
        let dispatcher = dispatcher();
        let enroll = request(
            "authorizations.enroll",
            "req-enroll",
            Some(0),
            json!({
                "ingress_id": "ingress-a",
                "egress_id": "egress-a",
                "public_key": URL_SAFE_NO_PAD.encode([7; 32]),
                "administrator_labels": {"admin.region": "jp"},
            }),
        );
        let first = dispatcher.dispatch(enroll.clone()).await;
        assert!(first.ok);
        assert_eq!(first.observed_generation.value, 1);
        let result = first.result.expect("result");
        assert_eq!(result["resource"]["state"], "enabled");
        assert_eq!(result["cleanup"]["paths"], 0);

        let replay = dispatcher.dispatch(enroll).await;
        assert!(replay.ok);
        assert_eq!(replay.result.expect("result")["replayed"], true);

        let list = dispatcher
            .dispatch(request("authorizations.list", "req-list", None, json!({})))
            .await;
        let items = list.result.expect("list")["items"]
            .as_array()
            .expect("items")
            .clone();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0]["ingress_id"], "ingress-a");
        assert_eq!(items[0]["administrator_labels"]["admin.region"], "jp");
    }

    #[tokio::test]
    async fn cleanup_is_applied_once_and_replayed_with_the_mutation() {
        let calls = Arc::new(AtomicUsize::new(0));
        let hook_calls = Arc::clone(&calls);
        let dispatcher = dispatcher().with_cleanup_hook(move |_| {
            let hook_calls = Arc::clone(&hook_calls);
            async move {
                hook_calls.fetch_add(1, Ordering::Relaxed);
                Ok(AuthorizationCleanup {
                    paths: 1,
                    sessions: 1,
                    streams: 2,
                    target_connections: 2,
                })
            }
        });
        let enroll = request(
            "authorizations.enroll",
            "req-enroll-cleanup",
            Some(0),
            json!({
                "ingress_id": "ingress-a",
                "egress_id": "egress-a",
                "public_key": URL_SAFE_NO_PAD.encode([7; 32]),
            }),
        );
        assert!(dispatcher.dispatch(enroll).await.ok);
        let disable = request(
            "authorizations.disable",
            "req-disable-cleanup",
            Some(1),
            json!({"ingress_id": "ingress-a"}),
        );
        let first = dispatcher.dispatch(disable.clone()).await;
        assert!(first.ok);
        assert_eq!(first.result.as_ref().unwrap()["cleanup"]["paths"], 1);
        let replay = dispatcher.dispatch(disable).await;
        assert!(replay.ok);
        assert_eq!(replay.result.as_ref().unwrap()["cleanup"]["streams"], 2);
        assert_eq!(calls.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn generation_and_terminal_state_errors_are_typed() {
        let dispatcher = dispatcher();
        let enroll = request(
            "authorizations.enroll",
            "req-enroll",
            Some(0),
            json!({
                "ingress_id": "ingress-a",
                "egress_id": "egress-a",
                "public_key": URL_SAFE_NO_PAD.encode([7; 32]),
            }),
        );
        assert!(dispatcher.dispatch(enroll).await.ok);

        let stale = dispatcher
            .dispatch(request(
                "authorizations.disable",
                "req-stale",
                Some(0),
                json!({"ingress_id": "ingress-a"}),
            ))
            .await;
        assert_eq!(
            stale.error.expect("error").code,
            ErrorCode::GenerationConflict
        );

        assert!(
            dispatcher
                .dispatch(request(
                    "authorizations.revoke",
                    "req-revoke",
                    Some(1),
                    json!({"ingress_id": "ingress-a"}),
                ))
                .await
                .ok
        );
        let enable = dispatcher
            .dispatch(request(
                "authorizations.enable",
                "req-enable",
                Some(2),
                json!({"ingress_id": "ingress-a"}),
            ))
            .await;
        assert_eq!(
            enable.error.expect("error").code,
            ErrorCode::ValidationFailed
        );
    }
}
