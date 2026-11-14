//! Egress-owned local authorization control dispatcher.

use std::collections::{BTreeMap, VecDeque};
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use pathchord_core::management::{
    ErrorBody, ErrorCode, GenerationExpectation, LOCAL_API_VERSION, ManagementDispatcher,
    ManagementSource, RequestEnvelope, ResponseEnvelope,
};
use serde_json::{Value, json};

use crate::{
    AuthorizationCleanup, AuthorizationMutation, AuthorizationMutationRequest,
    AuthorizationMutationResult, AuthorizationRecord, AuthorizationState, AuthorizationStore,
    AuthorizationStoreError, IngressId,
};

const AUTHORIZATION_SCOPE: &str = "authorization";
const MAX_AUTHORIZATION_EVENTS: usize = 2048;

#[derive(Default)]
struct AuthorizationEvents {
    next_id: u64,
    events: VecDeque<Value>,
}

type CleanupFuture = Pin<Box<dyn Future<Output = Result<AuthorizationCleanup, String>> + Send>>;
type CleanupHook = dyn Fn(IngressId) -> CleanupFuture + Send + Sync;
type StatusFuture = Pin<Box<dyn Future<Output = Result<Value, String>> + Send>>;
type StatusHook = dyn Fn() -> StatusFuture + Send + Sync;
type ResourcesHook = dyn Fn() -> StatusFuture + Send + Sync;

#[derive(Clone)]
pub struct AuthorizationControlDispatcher {
    store: Arc<AuthorizationStore>,
    cleanup_hook: Arc<CleanupHook>,
    status_hook: Arc<StatusHook>,
    resources_hook: Arc<ResourcesHook>,
    events: Arc<Mutex<AuthorizationEvents>>,
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
            resources_hook: Arc::new(|| {
                Box::pin(async { Err("resource observations unavailable".into()) })
            }),
            events: Arc::new(Mutex::new(AuthorizationEvents::default())),
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
    pub fn with_resources_hook<F, Fut>(mut self, hook: F) -> Self
    where
        F: Fn() -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<Value, String>> + Send + 'static,
    {
        self.resources_hook = Arc::new(move || Box::pin(hook()));
        self
    }

    #[must_use]
    pub fn store(&self) -> &Arc<AuthorizationStore> {
        &self.store
    }

    pub async fn dispatch(&self, request: RequestEnvelope) -> ResponseEnvelope {
        self.dispatch_with_source(request, ManagementSource::Local)
            .await
    }

    async fn dispatch_with_source(
        &self,
        request: RequestEnvelope,
        source: ManagementSource,
    ) -> ResponseEnvelope {
        let audit = request.clone();
        // Serialize the complete check/apply/failure-cache transaction for all
        // dispatcher clones that share this store, including asynchronous cleanup.
        let _mutation_guard = if is_authorization_mutation(&audit.operation) {
            Some(self.store.lock_mutations().await)
        } else {
            None
        };
        let fingerprint =
            eligible_failure_cache(&audit).then(|| authorization_request_fingerprint(&audit));
        let (mut response, replayed) = if let Some(fingerprint) = &fingerprint {
            match self
                .store
                .replay_failed_request(&audit.actor.id, &audit.request_id, fingerprint)
            {
                Ok(Some(response)) => (response, true),
                Ok(None) => (self.dispatch_inner(request, source).await, false),
                Err(error) => (self.store_failure(audit.request_id.clone(), error), false),
            }
        } else {
            (self.dispatch_inner(request, source).await, false)
        };
        if !replayed && fingerprint.is_some() && cacheable_authorization_failure(&response) {
            sanitize_authorization_failure(&mut response);
        }
        if !response.ok && is_authorization_mutation(&audit.operation) {
            let reason = response
                .error
                .as_ref()
                .map_or("UNKNOWN", |error| match error.code {
                    ErrorCode::MalformedRequest => "MALFORMED_REQUEST",
                    ErrorCode::AuthenticationRequired => "AUTHENTICATION_REQUIRED",
                    ErrorCode::CapabilityDenied => "CAPABILITY_DENIED",
                    ErrorCode::ValidationFailed => "VALIDATION_FAILED",
                    ErrorCode::NotFound => "NOT_FOUND",
                    ErrorCode::GenerationConflict => "GENERATION_CONFLICT",
                    ErrorCode::IdempotencyConflict => "IDEMPOTENCY_CONFLICT",
                    ErrorCode::ResourceLimit => "RESOURCE_LIMIT",
                    ErrorCode::PersistenceUnavailable => "PERSISTENCE_UNAVAILABLE",
                    ErrorCode::UnsupportedOperation => "UNSUPPORTED_OPERATION",
                });
            let actor = safe_audit_identifier(&audit.actor.id);
            let request_id = safe_audit_identifier(&audit.request_id);
            let ingress = audit
                .body
                .get("ingress_id")
                .and_then(Value::as_str)
                .map_or("invalid", safe_audit_identifier);
            let audit_result = if response
                .error
                .as_ref()
                .and_then(|error| error.details.as_ref())
                .and_then(|details| details.get("pending_apply"))
                .and_then(Value::as_bool)
                == Some(true)
            {
                "pending_cleanup"
            } else {
                "denied"
            };
            if self
                .store
                .record_mutation_failure(crate::authorization_store::AuthorizationFailureAudit {
                    actor,
                    operation: &audit.operation,
                    request_id,
                    ingress_id: ingress,
                    expected_generation: audit
                        .expected_generation
                        .as_ref()
                        .filter(|value| value.scope == AUTHORIZATION_SCOPE)
                        .map(|value| value.value),
                    result: audit_result,
                    reason,
                    source: source.as_str(),
                })
                .is_err()
            {
                return failure(
                    audit.request_id,
                    self.observed_generation(),
                    ErrorCode::PersistenceUnavailable,
                    "authorization audit is unavailable",
                    None,
                );
            }
            self.emit_event(
                "audit.notice",
                ingress,
                self.observed_generation().value,
                json!({"operation": audit.operation, "result": audit_result, "reason": reason}),
            );
            if !replayed
                && cacheable_authorization_failure(&response)
                && let Some(fingerprint) = &fingerprint
            {
                response = match self.store.remember_failed_request(
                    &audit.actor.id,
                    &audit.request_id,
                    fingerprint,
                    &response,
                ) {
                    Ok(response) => response,
                    Err(error) => self.store_failure(audit.request_id.clone(), error),
                };
            }
        }
        response
    }

    async fn dispatch_inner(
        &self,
        request: RequestEnvelope,
        source: ManagementSource,
    ) -> ResponseEnvelope {
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
            "metrics.snapshot" => self.metrics_snapshot(request).await,
            "metrics.paths" => {
                self.metric_resources(request, "path_metrics", "path_id")
                    .await
            }
            "metrics.streams" => {
                self.metric_resources(request, "stream_metrics", "stream_id")
                    .await
            }
            "events.subscribe" => self.events(request),
            "authorizations.list" => self.list(request).await,
            "authorizations.get" => self.get(request).await,
            "authorizations.enroll" => self.mutate(request, MutationKind::Enroll, source).await,
            "authorizations.enable" => self.mutate(request, MutationKind::Enable, source).await,
            "authorizations.disable" => self.mutate(request, MutationKind::Disable, source).await,
            "authorizations.revoke" => self.mutate(request, MutationKind::Revoke, source).await,
            "authorizations.delete" => self.mutate(request, MutationKind::Delete, source).await,
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

    async fn metrics_snapshot(&self, request: RequestEnvelope) -> ResponseEnvelope {
        if let Some(response) =
            require_capability(&request, "metrics:read", self.observed_generation())
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
                "captured_at_ms": now_ms(),
                "snapshot_generation": snapshot.generation(),
                "freshness": if runtime.get("running").and_then(Value::as_bool).is_some() {"fresh"} else {"unavailable"},
                "generation": snapshot.generation(),
                "runtime": {
                    "sessions": runtime.get("active_sessions"),
                    "ready_paths": runtime.get("active_paths"),
                    "streams": runtime.get("active_streams"),
                    "target_connections": runtime.get("active_target_connections")
                },
                "authorizations": snapshot.records().count()
            }),
        )
    }

    async fn metric_resources(
        &self,
        request: RequestEnvelope,
        resource: &str,
        id_field: &str,
    ) -> ResponseEnvelope {
        if let Some(response) =
            require_capability(&request, "metrics:read", self.observed_generation())
        {
            return response;
        }
        let query = match MetricListQuery::parse(&request.body, id_field) {
            Ok(query) => query,
            Err(message) => {
                return failure(
                    request.request_id,
                    self.observed_generation(),
                    ErrorCode::ValidationFailed,
                    message,
                    None,
                );
            }
        };
        let runtime = match (self.resources_hook)().await {
            Ok(runtime) => runtime,
            Err(_) => {
                return failure(
                    request.request_id,
                    self.observed_generation(),
                    ErrorCode::PersistenceUnavailable,
                    "Egress runtime status is unavailable",
                    None,
                );
            }
        };
        let Some(mut items) = runtime.get(resource).and_then(Value::as_array).cloned() else {
            return failure(
                request.request_id,
                self.observed_generation(),
                ErrorCode::PersistenceUnavailable,
                "Egress resource observations are unavailable",
                None,
            );
        };
        items.retain(|item| {
            query
                .filters
                .iter()
                .all(|(key, value)| item.get(key) == Some(value))
        });
        items.sort_by(|left, right| {
            let key = |item: &Value, field: &str| {
                item.get(field)
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned()
            };
            key(left, &query.sort)
                .cmp(&key(right, &query.sort))
                .then_with(|| key(left, id_field).cmp(&key(right, id_field)))
        });
        if query.descending {
            items.reverse();
        }
        let end = query
            .offset
            .saturating_add(query.page_size)
            .min(items.len());
        let next = (end < items.len()).then(|| end.to_string());
        let page = items.get(query.offset..end).unwrap_or_default().to_vec();
        ResponseEnvelope::success(
            request.request_id,
            self.observed_generation(),
            json!({"items": page, "next_page_token": next}),
        )
    }

    fn events(&self, request: RequestEnvelope) -> ResponseEnvelope {
        if let Some(response) =
            require_capability(&request, "metrics:read", self.observed_generation())
        {
            return response;
        }
        let cursor = match request.body.get("last_event_id") {
            None | Some(Value::Null) => None,
            Some(value) => match value.as_u64() {
                Some(value) => Some(value),
                None => {
                    return failure(
                        request.request_id,
                        self.observed_generation(),
                        ErrorCode::ValidationFailed,
                        "invalid event cursor",
                        None,
                    );
                }
            },
        };
        let events = self
            .events
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let oldest = events.events.front().and_then(|event| event["id"].as_u64());
        let reset_required = cursor.is_some_and(|last| {
            last > events.next_id || oldest.is_some_and(|first| last.saturating_add(1) < first)
        });
        let items: Vec<_> = events
            .events
            .iter()
            .filter(|event| {
                cursor.is_none_or(|last| event["id"].as_u64().is_some_and(|id| id > last))
            })
            .cloned()
            .collect();
        ResponseEnvelope::success(
            request.request_id,
            self.observed_generation(),
            json!({"items": items, "reset_required": reset_required, "latest_event_id": events.next_id}),
        )
    }

    async fn list(&self, request: RequestEnvelope) -> ResponseEnvelope {
        if let Some(response) =
            require_capability(&request, "status:read", self.observed_generation())
        {
            return response;
        }
        let query = match AuthorizationListQuery::parse(&request.body) {
            Ok(query) => query,
            Err(message) => {
                return failure(
                    request.request_id,
                    self.observed_generation(),
                    ErrorCode::ValidationFailed,
                    message,
                    None,
                );
            }
        };
        let snapshot = match self.store.snapshot() {
            Ok(snapshot) => snapshot,
            Err(error) => return self.store_failure(request.request_id, error),
        };
        let runtime = (self.status_hook)().await.ok();
        let mut items: Vec<_> = snapshot
            .records()
            .map(|record| record_value(snapshot.egress_id().as_str(), record, runtime.as_ref()))
            .collect();
        items.retain(|item| {
            query
                .filters
                .iter()
                .all(|(key, expected)| item.get(key) == Some(expected))
        });
        items.sort_by(|left, right| {
            let compare = |value: &Value, key: &str| {
                value
                    .get(key)
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned()
            };
            compare(left, &query.sort)
                .cmp(&compare(right, &query.sort))
                .then_with(|| compare(left, "ingress_id").cmp(&compare(right, "ingress_id")))
        });
        if query.descending {
            items.reverse();
        }
        let end = query
            .offset
            .saturating_add(query.page_size)
            .min(items.len());
        let next = (end < items.len()).then(|| end.to_string());
        let items = items.get(query.offset..end).unwrap_or_default().to_vec();
        ResponseEnvelope::success(
            request.request_id,
            generation(snapshot.generation()),
            json!({"items": items, "next_page_token": next}),
        )
    }

    async fn get(&self, request: RequestEnvelope) -> ResponseEnvelope {
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
        let runtime = (self.status_hook)().await.ok();
        ResponseEnvelope::success(
            request.request_id,
            generation(snapshot.generation()),
            record_value(snapshot.egress_id().as_str(), record, runtime.as_ref()),
        )
    }

    async fn mutate(
        &self,
        request: RequestEnvelope,
        kind: MutationKind,
        source: ManagementSource,
    ) -> ResponseEnvelope {
        if let Some(response) =
            require_capability(&request, "authorization:write", self.observed_generation())
        {
            return response;
        }
        let expected_generation = match request.expected_generation.as_ref() {
            Some(expected) if expected.scope == AUTHORIZATION_SCOPE => expected.value,
            None if request
                .actor
                .capabilities
                .iter()
                .any(|value| value == "force") =>
            {
                self.store
                    .snapshot()
                    .map(|snapshot| snapshot.generation())
                    .unwrap_or(0)
            }
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
        let mut result = match self.store.mutate_from(
            AuthorizationMutationRequest {
                actor_id: request.actor.id,
                request_id: request.request_id.clone(),
                expected_generation,
                ingress_id: ingress_id.clone(),
                mutation,
            },
            source.as_str(),
        ) {
            Ok(result) => result,
            Err(error) => return self.store_failure(request.request_id, error),
        };
        let cleanup_was_pending = !result.cleanup_complete;
        if !result.replayed {
            self.emit_authorization_change(&ingress_id, &result);
        }
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
            if self
                .store
                .record_cleanup(&actor_id, &request.request_id, cleanup)
                .is_err()
            {
                return failure(
                    request.request_id,
                    generation(result.applied_generation),
                    ErrorCode::PersistenceUnavailable,
                    "authorization cleanup result is not durable",
                    Some(json!({"pending_apply": true})),
                );
            }
            result.cleanup = cleanup;
            result.cleanup_complete = true;
        }
        if cleanup_was_pending && result.cleanup_complete {
            self.emit_authorization_change(&ingress_id, &result);
        }
        self.mutation_success(request.request_id, &ingress_id, result)
    }

    fn emit_authorization_change(
        &self,
        ingress_id: &IngressId,
        result: &AuthorizationMutationResult,
    ) {
        self.emit_event("authorization.changed", ingress_id.as_str(), result.applied_generation,
            json!({"state": result.state.map(state_name), "cleanup_complete": result.cleanup_complete, "cleanup": {
                "paths": result.cleanup.paths, "sessions": result.cleanup.sessions,
                "streams": result.cleanup.streams, "target_connections": result.cleanup.target_connections
            }}));
    }

    fn emit_event(
        &self,
        event_type: &str,
        resource_id: &str,
        generation_value: u64,
        payload: Value,
    ) {
        let mut events = self
            .events
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        events.next_id = events.next_id.saturating_add(1);
        let event = json!({"id": events.next_id, "type": event_type,
            "generation": generation(generation_value), "emitted_at": now_ms(),
            "resource_type": if event_type == "audit.notice" {"audit"} else {"authorization"},
            "resource_id": resource_id, "payload": payload});
        events.events.push_back(event);
        while events.events.len() > MAX_AUTHORIZATION_EVENTS {
            events.events.pop_front();
        }
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
            AuthorizationStoreError::ResourceLimit => (
                ErrorCode::ResourceLimit,
                "authorization failure cache is full",
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

    async fn dispatch_from(
        &mut self,
        request: RequestEnvelope,
        source: ManagementSource,
    ) -> ResponseEnvelope {
        self.dispatch_with_source(request, source).await
    }

    async fn record_authentication_failure(&mut self, source: &str) {
        if self.store.record_authentication_failure(source).is_ok() {
            self.emit_event(
                "audit.notice",
                source,
                self.observed_generation().value,
                json!({"operation": "authentication.failure", "result": "denied"}),
            );
        }
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

fn is_authorization_mutation(operation: &str) -> bool {
    matches!(
        operation,
        "authorizations.enroll"
            | "authorizations.enable"
            | "authorizations.disable"
            | "authorizations.revoke"
            | "authorizations.delete"
    )
}

fn eligible_failure_cache(request: &RequestEnvelope) -> bool {
    is_authorization_mutation(&request.operation)
        && request.api_version == LOCAL_API_VERSION
        && !request.actor.id.is_empty()
        && request.actor.id.len() <= 255
        && !request.actor.id.chars().any(char::is_control)
        && !request.request_id.is_empty()
        && request.request_id.len() <= 255
        && !request.request_id.chars().any(char::is_control)
        && request
            .actor
            .capabilities
            .iter()
            .any(|value| value == "authorization:write")
}

fn authorization_request_fingerprint(request: &RequestEnvelope) -> String {
    let capabilities: std::collections::BTreeSet<_> = request.actor.capabilities.iter().collect();
    let canonical = json!({"api_version": request.api_version, "operation": request.operation,
        "expected_generation": request.expected_generation, "body": request.body, "capabilities": capabilities});
    crate::authorization_store::fingerprint_digest(&canonical.to_string())
}

fn cacheable_authorization_failure(response: &ResponseEnvelope) -> bool {
    response.error.as_ref().is_some_and(|error| {
        matches!(
            error.code,
            ErrorCode::ValidationFailed
                | ErrorCode::NotFound
                | ErrorCode::GenerationConflict
                | ErrorCode::UnsupportedOperation
        ) && !error.details.as_ref().is_some_and(|details| {
            details.get("pending_apply").and_then(Value::as_bool) == Some(true)
                || details.get("retryable").and_then(Value::as_bool) == Some(true)
        })
    })
}

fn sanitize_authorization_failure(response: &mut ResponseEnvelope) {
    let Some(error) = response.error.as_mut() else {
        return;
    };
    error.message = match error.code {
        ErrorCode::ValidationFailed => "authorization request is invalid".to_owned(),
        ErrorCode::NotFound => "authorization record was not found".to_owned(),
        ErrorCode::GenerationConflict => "authorization generation conflict".to_owned(),
        ErrorCode::UnsupportedOperation => "operation is unsupported".to_owned(),
        _ => return,
    };
    // Validation details can include caller-supplied field names. Keep only
    // numeric generation details constructed by the store itself.
    if error.code != ErrorCode::GenerationConflict {
        error.details = None;
    }
}

fn safe_audit_identifier(value: &str) -> &str {
    if !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._-:".contains(&byte))
    {
        value
    } else {
        "invalid"
    }
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

struct AuthorizationListQuery {
    page_size: usize,
    offset: usize,
    filters: BTreeMap<String, Value>,
    sort: String,
    descending: bool,
}

struct MetricListQuery {
    page_size: usize,
    offset: usize,
    filters: BTreeMap<String, Value>,
    sort: String,
    descending: bool,
}

impl MetricListQuery {
    fn parse(body: &Value, id_field: &str) -> Result<Self, &'static str> {
        let object = body.as_object().ok_or("list query must be an object")?;
        if object.keys().any(|key| {
            !matches!(
                key.as_str(),
                "page_size" | "page_token" | "filter" | "sort" | "direction"
            )
        }) {
            return Err("unknown metric query field");
        }
        let page_size = match object.get("page_size") {
            None => 100,
            Some(value) => value
                .as_u64()
                .and_then(|value| usize::try_from(value).ok())
                .filter(|value| (1..=1000).contains(value))
                .ok_or("invalid page_size")?,
        };
        let offset = match object.get("page_token") {
            None | Some(Value::Null) => 0,
            Some(Value::String(value)) => value.parse().map_err(|_| "invalid page_token")?,
            _ => return Err("invalid page_token"),
        };
        let allowed =
            |key: &str| key == id_field || matches!(key, "session_id" | "egress_id" | "state");
        let filters = match object.get("filter") {
            None | Some(Value::Null) => BTreeMap::new(),
            Some(Value::Object(filters))
                if filters
                    .iter()
                    .all(|(key, value)| allowed(key) && value.is_string()) =>
            {
                filters.clone().into_iter().collect()
            }
            _ => return Err("invalid metric filter"),
        };
        let sort = match object.get("sort") {
            None => id_field,
            Some(Value::String(value)) if allowed(value) => value,
            _ => return Err("invalid metric sort"),
        }
        .to_owned();
        let descending = match object.get("direction") {
            None => false,
            Some(Value::String(value)) if value == "asc" => false,
            Some(Value::String(value)) if value == "desc" => true,
            _ => return Err("invalid metric direction"),
        };
        Ok(Self {
            page_size,
            offset,
            filters,
            sort,
            descending,
        })
    }
}

impl AuthorizationListQuery {
    fn parse(body: &Value) -> Result<Self, &'static str> {
        let object = body.as_object().ok_or("list query must be an object")?;
        if object.keys().any(|key| {
            !matches!(
                key.as_str(),
                "page_size" | "page_token" | "filter" | "sort" | "direction"
            )
        }) {
            return Err("unknown authorization query field");
        }
        let page_size = match object.get("page_size") {
            None => 100,
            Some(value) => value
                .as_u64()
                .and_then(|value| usize::try_from(value).ok())
                .filter(|value| (1..=1000).contains(value))
                .ok_or("invalid page_size")?,
        };
        let offset = match object.get("page_token") {
            None | Some(Value::Null) => 0,
            Some(Value::String(value)) => value.parse().map_err(|_| "invalid page_token")?,
            _ => return Err("invalid page_token"),
        };
        let filters = match object.get("filter") {
            None | Some(Value::Null) => BTreeMap::new(),
            Some(Value::Object(filters)) => {
                if filters.iter().any(|(key, value)| {
                    !matches!(key.as_str(), "ingress_id" | "egress_id" | "state")
                        || !value.is_string()
                }) {
                    return Err("invalid authorization filter");
                }
                filters.clone().into_iter().collect()
            }
            _ => return Err("invalid authorization filter"),
        };
        let sort = match object.get("sort") {
            None => "ingress_id",
            Some(Value::String(value))
                if matches!(value.as_str(), "ingress_id" | "egress_id" | "state") =>
            {
                value
            }
            _ => return Err("invalid authorization sort"),
        }
        .to_owned();
        let descending = match object.get("direction") {
            None => false,
            Some(Value::String(value)) if value == "asc" => false,
            Some(Value::String(value)) if value == "desc" => true,
            _ => return Err("invalid authorization direction"),
        };
        Ok(Self {
            page_size,
            offset,
            filters,
            sort,
            descending,
        })
    }
}

fn record_value(egress_id: &str, record: &AuthorizationRecord, runtime: Option<&Value>) -> Value {
    let all_activity = runtime
        .and_then(|value| value.get("authorization_activity"))
        .and_then(Value::as_object);
    let activity = all_activity.and_then(|value| value.get(record.ingress_id.as_str()));
    let active_path_count = all_activity.map(|_| {
        activity
            .and_then(|value| value.get(0))
            .and_then(Value::as_u64)
            .unwrap_or(0)
    });
    let active_session_count = all_activity.map(|_| {
        activity
            .and_then(|value| value.get(1))
            .and_then(Value::as_u64)
            .unwrap_or(0)
    });
    json!({
        "ingress_id": record.ingress_id.as_str(),
        "egress_id": egress_id,
        "public_key": URL_SAFE_NO_PAD.encode(record.ingress_public_key),
        "state": state_name(record.state),
        "administrator_labels": record.administrator_labels,
        "generation": record.record_generation,
        "active_path_count": active_path_count,
        "active_session_count": active_session_count,
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
        let result = first.result.clone().expect("result");
        assert_eq!(result["resource"]["state"], "enabled");
        assert_eq!(result["cleanup"]["paths"], 0);

        let replay = dispatcher.dispatch(enroll).await;
        assert!(replay.ok);
        assert_eq!(replay, first);

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
    async fn authorization_list_and_events_reflect_live_mutations() {
        let dispatcher = dispatcher().with_status_hook(|| async {
            Ok(json!({
                "running": true, "active_sessions": 1, "active_paths": 2,
                "active_streams": 3, "active_target_connections": 1,
                "authorization_activity": {"ingress-a": [2, 1]}
            }))
        }).with_resources_hook(|| async {
            Ok(json!({
                "path_metrics": [{"path_id": "p1", "session_id": "s1", "egress_id": "egress-a", "state": "active"}],
                "stream_metrics": [{"stream_id": "1", "session_id": "s1", "egress_id": "egress-a", "state": "open"}]
            }))
        });
        for (index, id) in ["ingress-a", "ingress-b"].iter().enumerate() {
            let enroll = request(
                "authorizations.enroll",
                &format!("enroll-{index}"),
                Some(index as u64),
                json!({"ingress_id": id, "egress_id": "egress-a", "public_key": URL_SAFE_NO_PAD.encode([7 + index as u8; 32])}),
            );
            assert!(dispatcher.dispatch(enroll).await.ok);
        }
        let first = dispatcher
            .dispatch(request(
                "authorizations.list",
                "list",
                None,
                json!({"page_size": 1, "sort": "ingress_id", "filter": {"state": "enabled"}}),
            ))
            .await
            .result
            .unwrap();
        assert_eq!(first["items"][0]["active_path_count"], 2);
        assert_eq!(first["items"][0]["active_session_count"], 1);
        let second = dispatcher
            .dispatch(request(
                "authorizations.list",
                "list-next",
                None,
                json!({"page_size": 1, "page_token": first["next_page_token"]}),
            ))
            .await
            .result
            .unwrap();
        assert_eq!(second["items"][0]["ingress_id"], "ingress-b");
        assert_eq!(second["items"][0]["active_path_count"], 0);
        let mut events = request("events.subscribe", "events", None, json!({}));
        events.actor.capabilities.push("metrics:read".into());
        let result = dispatcher.dispatch(events).await.result.unwrap();
        assert_eq!(result["items"].as_array().unwrap().len(), 2);
        assert_eq!(result["items"][0]["type"], "authorization.changed");
        assert_eq!(result["items"][0]["generation"]["scope"], "authorization");
        let mut paths = request(
            "metrics.paths",
            "paths",
            None,
            json!({"filter": {"state": "active"}}),
        );
        paths.actor.capabilities.push("metrics:read".into());
        let paths = dispatcher.dispatch(paths).await.result.unwrap();
        assert_eq!(paths["items"][0]["path_id"], "p1");
        let denied = dispatcher
            .dispatch(request(
                "authorizations.disable",
                "stale",
                Some(0),
                json!({"ingress_id": "ingress-a"}),
            ))
            .await;
        assert_eq!(denied.error.unwrap().code, ErrorCode::GenerationConflict);
        let mut events = request(
            "events.subscribe",
            "events-after-denial",
            None,
            json!({"last_event_id": 2}),
        );
        events.actor.capabilities.push("metrics:read".into());
        let events = dispatcher.dispatch(events).await.result.unwrap();
        assert_eq!(events["items"][0]["type"], "audit.notice");
        assert_eq!(
            events["items"][0]["payload"]["reason"],
            "GENERATION_CONFLICT"
        );
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
    async fn pending_authorization_cleanup_emits_commit_and_recovery_events() {
        let calls = Arc::new(AtomicUsize::new(0));
        let hook_calls = Arc::clone(&calls);
        let dispatcher = dispatcher().with_cleanup_hook(move |_| {
            let attempt = hook_calls.fetch_add(1, Ordering::Relaxed);
            async move {
                if attempt == 0 {
                    Err("temporary".to_owned())
                } else {
                    Ok(AuthorizationCleanup::default())
                }
            }
        });
        assert!(dispatcher.dispatch(request("authorizations.enroll", "enroll", Some(0),
            json!({"ingress_id": "ingress-a", "egress_id": "egress-a", "public_key": URL_SAFE_NO_PAD.encode([7; 32])}))).await.ok);
        let disable = request(
            "authorizations.disable",
            "disable",
            Some(1),
            json!({"ingress_id": "ingress-a"}),
        );
        assert!(!dispatcher.dispatch(disable.clone()).await.ok);
        assert!(dispatcher.dispatch(disable).await.ok);
        let mut events = request(
            "events.subscribe",
            "events",
            None,
            json!({"last_event_id": 1}),
        );
        events.actor.capabilities.push("metrics:read".into());
        let items = dispatcher.dispatch(events).await.result.unwrap()["items"]
            .as_array()
            .unwrap()
            .clone();
        assert_eq!(items[0]["type"], "authorization.changed");
        assert_eq!(items[0]["payload"]["cleanup_complete"], false);
        assert_eq!(items.last().unwrap()["payload"]["cleanup_complete"], true);
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
