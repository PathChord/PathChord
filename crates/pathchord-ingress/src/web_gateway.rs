use std::collections::{BTreeMap, BTreeSet};
use std::convert::Infallible;
use std::future::Future;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use async_stream::stream;
use axum::extract::rejection::JsonRejection;
use axum::extract::{Path, Query, Request, State};
use axum::http::header::{
    ACCESS_CONTROL_ALLOW_HEADERS, ACCESS_CONTROL_ALLOW_METHODS, ACCESS_CONTROL_ALLOW_ORIGIN,
    AUTHORIZATION, CACHE_CONTROL, CONTENT_SECURITY_POLICY, CONTENT_TYPE, ORIGIN, RETRY_AFTER, VARY,
};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode};
use axum::middleware::{self, Next};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{delete, get, options, patch, post};
use axum::{Json, Router};
use getrandom::fill;
use pathchord_core::management::{ManagementDispatcher, ManagementSource};
use serde_json::{Map, Value, json};
use subtle::ConstantTimeEq;
use thiserror::Error;
use tokio::net::TcpListener;
use tokio::sync::{Mutex, Semaphore};
use zeroize::Zeroizing;

use crate::{
    Actor, ErrorCode, GenerationExpectation, LOCAL_API_VERSION, RequestEnvelope, ResponseEnvelope,
};

const INDEX_HTML: &str = include_str!("../web-assets/index.html");
const APP_CSS: &str = include_str!("../web-assets/app.css");
const APP_JS: &str = include_str!("../web-assets/app.js");
const MAX_WEB_REQUEST_BYTES: usize = 64 * 1024;

#[derive(Clone)]
pub struct WebBearerToken(Zeroizing<String>);

impl WebBearerToken {
    #[must_use]
    pub fn new(value: impl Into<String>) -> Self {
        Self(Zeroizing::new(value.into()))
    }

    fn matches(&self, candidate: &str) -> bool {
        let expected = self.0.as_bytes();
        let candidate = candidate.as_bytes();
        expected.len() == candidate.len() && bool::from(expected.ct_eq(candidate))
    }

    fn len(&self) -> usize {
        self.0.len()
    }
}

impl std::fmt::Debug for WebBearerToken {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("WebBearerToken([REDACTED])")
    }
}

#[derive(Clone)]
pub struct WebGatewayConfig {
    pub bind: SocketAddr,
    /// Exposes Egress-only authorization routes when the dispatcher owns an
    /// authorization store. Ingress dispatchers leave this disabled.
    pub authorizations_enabled: bool,
    pub bearer_token: Option<WebBearerToken>,
    pub allowed_origins: BTreeSet<String>,
    /// Confirms that an external TLS or equivalent protected channel terminates before this bind.
    pub protected_transport: bool,
    pub actor_id: String,
    pub actor_capabilities: BTreeSet<String>,
    pub max_concurrent_requests: usize,
    pub max_sse_clients: usize,
    pub max_requests_per_minute: u32,
    pub event_poll_interval: Duration,
    pub heartbeat_interval: Duration,
}

impl std::fmt::Debug for WebGatewayConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("WebGatewayConfig")
            .field("bind", &self.bind)
            .field("authorizations_enabled", &self.authorizations_enabled)
            .field("bearer_token", &self.bearer_token)
            .field("allowed_origins", &self.allowed_origins)
            .field("protected_transport", &self.protected_transport)
            .field("actor_id", &self.actor_id)
            .field("actor_capabilities", &self.actor_capabilities)
            .field("max_concurrent_requests", &self.max_concurrent_requests)
            .field("max_sse_clients", &self.max_sse_clients)
            .field("max_requests_per_minute", &self.max_requests_per_minute)
            .field("event_poll_interval", &self.event_poll_interval)
            .field("heartbeat_interval", &self.heartbeat_interval)
            .finish()
    }
}

impl Default for WebGatewayConfig {
    fn default() -> Self {
        Self {
            bind: "127.0.0.1:0".parse().expect("literal loopback address"),
            authorizations_enabled: false,
            bearer_token: None,
            allowed_origins: BTreeSet::new(),
            protected_transport: false,
            actor_id: "web-admin".to_owned(),
            actor_capabilities: BTreeSet::from([
                "authorization:write".to_owned(),
                "listeners:read".to_owned(),
                "metrics:read".to_owned(),
                "nodes:read".to_owned(),
                "nodes:write".to_owned(),
                "status:read".to_owned(),
                "subscriptions:write".to_owned(),
                "system_proxy:write".to_owned(),
            ]),
            max_concurrent_requests: 64,
            max_sse_clients: 8,
            max_requests_per_minute: 600,
            event_poll_interval: Duration::from_millis(500),
            heartbeat_interval: Duration::from_secs(15),
        }
    }
}

#[derive(Debug, Error)]
pub enum WebGatewayError {
    #[error("Web Gateway configuration is invalid: {0}")]
    InvalidConfig(&'static str),
    #[error("Web Gateway I/O failed: {0}")]
    Io(#[source] std::io::Error),
}

pub type SharedManagementDispatcher<D> = Arc<Mutex<D>>;

pub struct WebGateway {
    listener: TcpListener,
    app: Router,
}

impl std::fmt::Debug for WebGateway {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("WebGateway")
            .field("local_addr", &self.listener.local_addr().ok())
            .finish_non_exhaustive()
    }
}

impl WebGateway {
    pub async fn bind<D>(
        config: WebGatewayConfig,
        dispatcher: SharedManagementDispatcher<D>,
    ) -> Result<Self, WebGatewayError>
    where
        D: ManagementDispatcher,
    {
        validate_config(&config)?;
        let listener = TcpListener::bind(config.bind)
            .await
            .map_err(WebGatewayError::Io)?;
        let app = build_router(WebState::new(config, dispatcher));
        Ok(Self { listener, app })
    }

    pub fn local_addr(&self) -> Result<SocketAddr, WebGatewayError> {
        self.listener.local_addr().map_err(WebGatewayError::Io)
    }

    pub async fn run(self) -> Result<(), WebGatewayError> {
        self.run_until_shutdown(std::future::pending()).await
    }

    pub async fn run_until_shutdown<F>(self, shutdown: F) -> Result<(), WebGatewayError>
    where
        F: Future<Output = ()> + Send + 'static,
    {
        axum::serve(self.listener, self.app)
            .with_graceful_shutdown(shutdown)
            .await
            .map_err(WebGatewayError::Io)
    }
}

struct WebState<D> {
    dispatcher: SharedManagementDispatcher<D>,
    config: Arc<WebGatewayConfig>,
    requests: Arc<Semaphore>,
    sse_clients: Arc<Semaphore>,
    rate: Arc<StdMutex<RateWindow>>,
}

impl<D> Clone for WebState<D> {
    fn clone(&self) -> Self {
        Self {
            dispatcher: Arc::clone(&self.dispatcher),
            config: Arc::clone(&self.config),
            requests: Arc::clone(&self.requests),
            sse_clients: Arc::clone(&self.sse_clients),
            rate: Arc::clone(&self.rate),
        }
    }
}

impl<D> WebState<D> {
    fn new(config: WebGatewayConfig, dispatcher: SharedManagementDispatcher<D>) -> Self {
        let requests = Arc::new(Semaphore::new(config.max_concurrent_requests));
        let sse_clients = Arc::new(Semaphore::new(config.max_sse_clients));
        Self {
            dispatcher,
            config: Arc::new(config),
            requests,
            sse_clients,
            rate: Arc::new(StdMutex::new(RateWindow {
                started_at: Instant::now(),
                requests: 0,
            })),
        }
    }
}

#[derive(Debug)]
struct RateWindow {
    started_at: Instant,
    requests: u32,
}

fn validate_config(config: &WebGatewayConfig) -> Result<(), WebGatewayError> {
    if config.actor_id.is_empty()
        || config.max_concurrent_requests == 0
        || config.max_sse_clients == 0
        || config.max_requests_per_minute == 0
        || config.event_poll_interval.is_zero()
        || config.heartbeat_interval.is_zero()
    {
        return Err(WebGatewayError::InvalidConfig(
            "limits and actor must be non-zero",
        ));
    }
    if config
        .bearer_token
        .as_ref()
        .is_some_and(|token| token.len() < 16)
    {
        return Err(WebGatewayError::InvalidConfig("bearer token is too short"));
    }
    if !config.bind.ip().is_loopback()
        && (!config.protected_transport
            || config
                .bearer_token
                .as_ref()
                .is_none_or(|token| token.len() < 32)
            || config.allowed_origins.is_empty())
    {
        return Err(WebGatewayError::InvalidConfig(
            "non-loopback bind requires a 32-byte bearer token and allowed origins",
        ));
    }
    for origin in &config.allowed_origins {
        let parsed = url::Url::parse(origin)
            .map_err(|_| WebGatewayError::InvalidConfig("allowed origin is invalid"))?;
        if !matches!(parsed.scheme(), "http" | "https") || parsed.host_str().is_none() {
            return Err(WebGatewayError::InvalidConfig("allowed origin is invalid"));
        }
    }
    Ok(())
}

fn build_router<D>(state: WebState<D>) -> Router
where
    D: ManagementDispatcher,
{
    let mut api = Router::new()
        .route("/api/v1/status", get(get_status::<D>))
        .route("/api/v1/nodes", get(get_nodes::<D>))
        .route("/api/v1/nodes/{node_id}", get(get_node::<D>))
        .route(
            "/api/v1/nodes/{node_id}/labels",
            patch(patch_node_labels::<D>),
        )
        .route("/api/v1/nodes/{node_id}/tags", patch(patch_node_tags::<D>))
        .route("/api/v1/sessions", get(get_sessions::<D>))
        .route("/api/v1/sessions/{session_id}", get(get_session::<D>))
        .route("/api/v1/connections", get(get_connections::<D>))
        .route("/api/v1/listeners", get(get_listeners::<D>))
        .route(
            "/api/v1/subscriptions",
            get(get_subscriptions::<D>).post(create_subscription::<D>),
        )
        .route(
            "/api/v1/subscriptions/{subscription_id}",
            delete(delete_subscription::<D>),
        )
        .route(
            "/api/v1/subscriptions/{subscription_id}/refresh",
            post(refresh_subscription::<D>),
        )
        .route(
            "/api/v1/subscriptions/{subscription_id}/enable",
            post(enable_subscription::<D>),
        )
        .route(
            "/api/v1/subscriptions/{subscription_id}/disable",
            post(disable_subscription::<D>),
        )
        .route("/api/v1/metrics/snapshot", get(get_metrics::<D>))
        .route("/metrics", get(get_prometheus::<D>))
        .route("/api/v1/metrics/paths", get(get_path_metrics::<D>))
        .route("/api/v1/metrics/streams", get(get_stream_metrics::<D>))
        .route(
            "/api/v1/system-proxy",
            get(get_system_proxy::<D>)
                .put(enable_system_proxy::<D>)
                .delete(disable_system_proxy::<D>),
        )
        .route(
            "/api/v1/system-proxy/enable",
            post(enable_system_proxy::<D>),
        )
        .route(
            "/api/v1/system-proxy/disable",
            post(disable_system_proxy::<D>),
        )
        .route("/api/v1/events", get(events::<D>))
        .route("/api/v1/{*rest}", options(preflight));

    if state.config.authorizations_enabled {
        api = api
            .route(
                "/api/v1/authorizations",
                get(get_authorizations::<D>).post(enroll_authorization::<D>),
            )
            .route(
                "/api/v1/authorizations/{ingress_id}",
                get(get_authorization::<D>).delete(delete_authorization::<D>),
            )
            .route(
                "/api/v1/authorizations/{ingress_id}/enable",
                post(enable_authorization::<D>),
            )
            .route(
                "/api/v1/authorizations/{ingress_id}/disable",
                post(disable_authorization::<D>),
            )
            .route(
                "/api/v1/authorizations/{ingress_id}/revoke",
                post(revoke_authorization::<D>),
            );
    }

    api = api
        .layer(axum::extract::DefaultBodyLimit::max(MAX_WEB_REQUEST_BYTES))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            gateway_guard::<D>,
        ));

    Router::new()
        .route("/", get(index))
        .route("/assets/app.css", get(styles))
        .route("/assets/app.js", get(script))
        .merge(api)
        .with_state(state)
}

async fn gateway_guard<D>(
    State(state): State<WebState<D>>,
    request: Request,
    next: Next,
) -> Response
where
    D: ManagementDispatcher,
{
    let origin = request
        .headers()
        .get(ORIGIN)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    if origin
        .as_deref()
        .is_some_and(|value| !origin_allowed(&state.config, value))
    {
        state
            .dispatcher
            .lock()
            .await
            .record_authentication_failure("web-origin")
            .await;
        return gateway_failure(
            StatusCode::FORBIDDEN,
            "CAPABILITY_DENIED",
            "origin is not allowed",
        );
    }
    if request.method() == Method::OPTIONS {
        return cors_response(preflight().await, origin.as_deref());
    }
    if let Some(token) = &state.config.bearer_token {
        let supplied = request
            .headers()
            .get(AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.strip_prefix("Bearer "));
        if supplied.is_none_or(|value| !token.matches(value)) {
            state
                .dispatcher
                .lock()
                .await
                .record_authentication_failure("web-bearer")
                .await;
            return gateway_failure(
                StatusCode::UNAUTHORIZED,
                "AUTHENTICATION_REQUIRED",
                "bearer authentication is required",
            );
        }
    }
    if !take_rate_slot(&state) {
        let mut response = gateway_failure(
            StatusCode::TOO_MANY_REQUESTS,
            "RESOURCE_LIMIT",
            "request rate limit exceeded",
        );
        response
            .headers_mut()
            .insert(RETRY_AFTER, HeaderValue::from_static("60"));
        return response;
    }
    let permit = match Arc::clone(&state.requests).try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => {
            return gateway_failure(
                StatusCode::TOO_MANY_REQUESTS,
                "RESOURCE_LIMIT",
                "concurrent request limit exceeded",
            );
        }
    };
    let response = next.run(request).await;
    drop(permit);
    cors_response(response, origin.as_deref())
}

fn take_rate_slot<D>(state: &WebState<D>) -> bool {
    let mut rate = state
        .rate
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if rate.started_at.elapsed() >= Duration::from_secs(60) {
        rate.started_at = Instant::now();
        rate.requests = 0;
    }
    if rate.requests >= state.config.max_requests_per_minute {
        false
    } else {
        rate.requests += 1;
        true
    }
}

fn origin_allowed(config: &WebGatewayConfig, origin: &str) -> bool {
    if config.allowed_origins.contains(origin) {
        return true;
    }
    if !config.bind.ip().is_loopback() {
        return false;
    }
    url::Url::parse(origin).ok().is_some_and(|origin| {
        origin.host_str().is_some_and(|host| {
            host.eq_ignore_ascii_case("localhost")
                || host
                    .parse::<std::net::IpAddr>()
                    .is_ok_and(|ip| ip.is_loopback())
        })
    })
}

fn cors_response(mut response: Response, origin: Option<&str>) -> Response {
    if let Some(origin) = origin.and_then(|value| HeaderValue::from_str(value).ok()) {
        response
            .headers_mut()
            .insert(ACCESS_CONTROL_ALLOW_ORIGIN, origin);
        response
            .headers_mut()
            .insert(VARY, HeaderValue::from_static("Origin"));
    }
    response
}

async fn preflight() -> Response {
    let mut response = StatusCode::NO_CONTENT.into_response();
    response.headers_mut().insert(
        ACCESS_CONTROL_ALLOW_METHODS,
        HeaderValue::from_static("GET, POST, PUT, PATCH, DELETE, OPTIONS"),
    );
    response.headers_mut().insert(
        ACCESS_CONTROL_ALLOW_HEADERS,
        HeaderValue::from_static(
            "Authorization, Content-Type, Last-Event-ID, X-Request-ID, X-PathChord-Generation",
        ),
    );
    response
}

async fn index() -> Response {
    let mut response = Html(INDEX_HTML).into_response();
    secure_asset_headers(&mut response, "text/html; charset=utf-8");
    response
}

async fn styles() -> Response {
    let mut response = APP_CSS.into_response();
    secure_asset_headers(&mut response, "text/css; charset=utf-8");
    response
}

async fn script() -> Response {
    let mut response = APP_JS.into_response();
    secure_asset_headers(&mut response, "text/javascript; charset=utf-8");
    response
}

fn secure_asset_headers(response: &mut Response, content_type: &'static str) {
    response
        .headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static(content_type));
    response
        .headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response.headers_mut().insert(
        CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(
            "default-src 'self'; connect-src 'self'; img-src 'self'; style-src 'self'; script-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'",
        ),
    );
}

async fn get_status<D>(State(state): State<WebState<D>>, headers: HeaderMap) -> Response
where
    D: ManagementDispatcher,
{
    get_operation(&state, &headers, "status.get", Value::Object(Map::new())).await
}

async fn get_nodes<D>(
    State(state): State<WebState<D>>,
    headers: HeaderMap,
    Query(query): Query<BTreeMap<String, String>>,
) -> Response
where
    D: ManagementDispatcher,
{
    get_operation(&state, &headers, "nodes.list", query_body(query)).await
}

async fn get_node<D>(
    State(state): State<WebState<D>>,
    Path(node_id): Path<String>,
    headers: HeaderMap,
) -> Response
where
    D: ManagementDispatcher,
{
    get_operation(&state, &headers, "nodes.get", json!({"node_id": node_id})).await
}

async fn get_sessions<D>(
    State(state): State<WebState<D>>,
    headers: HeaderMap,
    Query(query): Query<BTreeMap<String, String>>,
) -> Response
where
    D: ManagementDispatcher,
{
    get_operation(&state, &headers, "sessions.list", query_body(query)).await
}

async fn get_session<D>(
    State(state): State<WebState<D>>,
    Path(session_id): Path<String>,
    headers: HeaderMap,
) -> Response
where
    D: ManagementDispatcher,
{
    get_operation(
        &state,
        &headers,
        "sessions.get",
        json!({"session_id": session_id}),
    )
    .await
}

async fn get_connections<D>(
    State(state): State<WebState<D>>,
    headers: HeaderMap,
    Query(query): Query<BTreeMap<String, String>>,
) -> Response
where
    D: ManagementDispatcher,
{
    get_operation(&state, &headers, "connections.list", query_body(query)).await
}

async fn get_listeners<D>(
    State(state): State<WebState<D>>,
    headers: HeaderMap,
    Query(query): Query<BTreeMap<String, String>>,
) -> Response
where
    D: ManagementDispatcher,
{
    get_operation(&state, &headers, "listeners.list", query_body(query)).await
}

async fn get_subscriptions<D>(
    State(state): State<WebState<D>>,
    headers: HeaderMap,
    Query(query): Query<BTreeMap<String, String>>,
) -> Response
where
    D: ManagementDispatcher,
{
    get_operation(&state, &headers, "subscriptions.list", query_body(query)).await
}

async fn get_metrics<D>(State(state): State<WebState<D>>, headers: HeaderMap) -> Response
where
    D: ManagementDispatcher,
{
    get_operation(
        &state,
        &headers,
        "metrics.snapshot",
        Value::Object(Map::new()),
    )
    .await
}

async fn get_prometheus<D>(State(state): State<WebState<D>>, headers: HeaderMap) -> Response
where
    D: ManagementDispatcher,
{
    let request = request_envelope(
        &state,
        "metrics.snapshot",
        request_id(&headers),
        None,
        json!({}),
    );
    let response = state
        .dispatcher
        .lock()
        .await
        .dispatch_from(request, ManagementSource::Web)
        .await;
    if !response.ok {
        let status = response
            .error
            .as_ref()
            .map_or(StatusCode::INTERNAL_SERVER_ERROR, |error| {
                error_status(error.code)
            });
        return (status, Json(response)).into_response();
    }
    let Some(snapshot) = response.result else {
        return gateway_failure(
            StatusCode::SERVICE_UNAVAILABLE,
            "UNAVAILABLE",
            "metric snapshot is unavailable",
        );
    };
    (
        [(CONTENT_TYPE, "text/plain; version=0.0.4; charset=utf-8")],
        crate::metrics_export::prometheus(&snapshot),
    )
        .into_response()
}

async fn get_path_metrics<D>(
    State(state): State<WebState<D>>,
    headers: HeaderMap,
    Query(query): Query<BTreeMap<String, String>>,
) -> Response
where
    D: ManagementDispatcher,
{
    get_operation(&state, &headers, "metrics.paths", query_body(query)).await
}

async fn get_stream_metrics<D>(
    State(state): State<WebState<D>>,
    headers: HeaderMap,
    Query(query): Query<BTreeMap<String, String>>,
) -> Response
where
    D: ManagementDispatcher,
{
    get_operation(&state, &headers, "metrics.streams", query_body(query)).await
}

async fn get_authorizations<D>(
    State(state): State<WebState<D>>,
    headers: HeaderMap,
    Query(query): Query<BTreeMap<String, String>>,
) -> Response
where
    D: ManagementDispatcher,
{
    get_operation(&state, &headers, "authorizations.list", query_body(query)).await
}

async fn get_authorization<D>(
    State(state): State<WebState<D>>,
    Path(ingress_id): Path<String>,
    headers: HeaderMap,
) -> Response
where
    D: ManagementDispatcher,
{
    get_operation(
        &state,
        &headers,
        "authorizations.get",
        json!({"ingress_id": ingress_id}),
    )
    .await
}

async fn get_system_proxy<D>(State(state): State<WebState<D>>, headers: HeaderMap) -> Response
where
    D: ManagementDispatcher,
{
    get_operation(
        &state,
        &headers,
        "system_proxy.get",
        Value::Object(Map::new()),
    )
    .await
}

async fn get_operation<D>(
    state: &WebState<D>,
    headers: &HeaderMap,
    operation: &'static str,
    body: Value,
) -> Response
where
    D: ManagementDispatcher,
{
    dispatch_http(state, operation, headers, body, false, StatusCode::OK).await
}

async fn patch_node_labels<D>(
    State(state): State<WebState<D>>,
    Path(node_id): Path<String>,
    headers: HeaderMap,
    payload: Result<Json<Value>, JsonRejection>,
) -> Response
where
    D: ManagementDispatcher,
{
    mutation_with_resource(
        &state,
        &headers,
        payload,
        "nodes.patch_labels",
        "node_id",
        node_id,
        StatusCode::OK,
    )
    .await
}

async fn patch_node_tags<D>(
    State(state): State<WebState<D>>,
    Path(node_id): Path<String>,
    headers: HeaderMap,
    payload: Result<Json<Value>, JsonRejection>,
) -> Response
where
    D: ManagementDispatcher,
{
    mutation_with_resource(
        &state,
        &headers,
        payload,
        "nodes.patch_tags",
        "node_id",
        node_id,
        StatusCode::OK,
    )
    .await
}

async fn create_subscription<D>(
    State(state): State<WebState<D>>,
    headers: HeaderMap,
    payload: Result<Json<Value>, JsonRejection>,
) -> Response
where
    D: ManagementDispatcher,
{
    let body = match json_body(payload) {
        Ok(body) => body,
        Err(response) => return *response,
    };
    dispatch_http(
        &state,
        "subscriptions.create",
        &headers,
        body,
        true,
        StatusCode::CREATED,
    )
    .await
}

async fn delete_subscription<D>(
    State(state): State<WebState<D>>,
    Path(subscription_id): Path<String>,
    headers: HeaderMap,
) -> Response
where
    D: ManagementDispatcher,
{
    dispatch_http(
        &state,
        "subscriptions.delete",
        &headers,
        json!({"id": subscription_id}),
        true,
        StatusCode::OK,
    )
    .await
}

async fn refresh_subscription<D>(
    State(state): State<WebState<D>>,
    Path(subscription_id): Path<String>,
    headers: HeaderMap,
    payload: Result<Json<Value>, JsonRejection>,
) -> Response
where
    D: ManagementDispatcher,
{
    mutation_with_resource(
        &state,
        &headers,
        payload,
        "subscriptions.refresh",
        "id",
        subscription_id,
        StatusCode::OK,
    )
    .await
}

async fn enable_subscription<D>(
    State(state): State<WebState<D>>,
    Path(subscription_id): Path<String>,
    headers: HeaderMap,
) -> Response
where
    D: ManagementDispatcher,
{
    subscription_state_mutation(&state, &headers, subscription_id, true).await
}

async fn disable_subscription<D>(
    State(state): State<WebState<D>>,
    Path(subscription_id): Path<String>,
    headers: HeaderMap,
) -> Response
where
    D: ManagementDispatcher,
{
    subscription_state_mutation(&state, &headers, subscription_id, false).await
}

async fn subscription_state_mutation<D>(
    state: &WebState<D>,
    headers: &HeaderMap,
    subscription_id: String,
    enabled: bool,
) -> Response
where
    D: ManagementDispatcher,
{
    dispatch_http(
        state,
        if enabled {
            "subscriptions.enable"
        } else {
            "subscriptions.disable"
        },
        headers,
        json!({"id": subscription_id}),
        true,
        StatusCode::OK,
    )
    .await
}

async fn enroll_authorization<D>(
    State(state): State<WebState<D>>,
    headers: HeaderMap,
    payload: Result<Json<Value>, JsonRejection>,
) -> Response
where
    D: ManagementDispatcher,
{
    let body = match json_body(payload) {
        Ok(body) => body,
        Err(response) => return *response,
    };
    dispatch_http(
        &state,
        "authorizations.enroll",
        &headers,
        body,
        true,
        StatusCode::CREATED,
    )
    .await
}

async fn enable_authorization<D>(
    State(state): State<WebState<D>>,
    Path(ingress_id): Path<String>,
    headers: HeaderMap,
) -> Response
where
    D: ManagementDispatcher,
{
    authorization_state_mutation(&state, &headers, ingress_id, "authorizations.enable").await
}

async fn disable_authorization<D>(
    State(state): State<WebState<D>>,
    Path(ingress_id): Path<String>,
    headers: HeaderMap,
) -> Response
where
    D: ManagementDispatcher,
{
    authorization_state_mutation(&state, &headers, ingress_id, "authorizations.disable").await
}

async fn revoke_authorization<D>(
    State(state): State<WebState<D>>,
    Path(ingress_id): Path<String>,
    headers: HeaderMap,
) -> Response
where
    D: ManagementDispatcher,
{
    authorization_state_mutation(&state, &headers, ingress_id, "authorizations.revoke").await
}

async fn delete_authorization<D>(
    State(state): State<WebState<D>>,
    Path(ingress_id): Path<String>,
    headers: HeaderMap,
) -> Response
where
    D: ManagementDispatcher,
{
    authorization_state_mutation(&state, &headers, ingress_id, "authorizations.delete").await
}

async fn authorization_state_mutation<D>(
    state: &WebState<D>,
    headers: &HeaderMap,
    ingress_id: String,
    operation: &'static str,
) -> Response
where
    D: ManagementDispatcher,
{
    dispatch_http(
        state,
        operation,
        headers,
        json!({"ingress_id": ingress_id}),
        true,
        StatusCode::OK,
    )
    .await
}

async fn enable_system_proxy<D>(
    State(state): State<WebState<D>>,
    headers: HeaderMap,
    payload: Result<Json<Value>, JsonRejection>,
) -> Response
where
    D: ManagementDispatcher,
{
    let body = match json_body(payload) {
        Ok(body) => body,
        Err(response) => return *response,
    };
    dispatch_http(
        &state,
        "system_proxy.enable",
        &headers,
        body,
        true,
        StatusCode::OK,
    )
    .await
}

async fn disable_system_proxy<D>(State(state): State<WebState<D>>, headers: HeaderMap) -> Response
where
    D: ManagementDispatcher,
{
    dispatch_http(
        &state,
        "system_proxy.disable",
        &headers,
        Value::Object(Map::new()),
        true,
        StatusCode::OK,
    )
    .await
}

async fn mutation_with_resource<D>(
    state: &WebState<D>,
    headers: &HeaderMap,
    payload: Result<Json<Value>, JsonRejection>,
    operation: &'static str,
    field: &'static str,
    resource_id: String,
    status: StatusCode,
) -> Response
where
    D: ManagementDispatcher,
{
    let mut body = match json_body(payload) {
        Ok(Value::Object(body)) => body,
        Ok(_) => {
            return gateway_failure(
                StatusCode::BAD_REQUEST,
                "MALFORMED_REQUEST",
                "JSON body must be an object",
            );
        }
        Err(response) => return *response,
    };
    body.insert(field.to_owned(), Value::String(resource_id));
    dispatch_http(state, operation, headers, Value::Object(body), true, status).await
}

fn json_body(payload: Result<Json<Value>, JsonRejection>) -> Result<Value, Box<Response>> {
    payload.map(|Json(value)| value).map_err(|_| {
        Box::new(gateway_failure(
            StatusCode::BAD_REQUEST,
            "MALFORMED_REQUEST",
            "JSON body is malformed",
        ))
    })
}

async fn dispatch_http<D>(
    state: &WebState<D>,
    operation: &'static str,
    headers: &HeaderMap,
    body: Value,
    mutation: bool,
    success_status: StatusCode,
) -> Response
where
    D: ManagementDispatcher,
{
    let request_id = request_id(headers);
    let expected_generation = if mutation {
        match expected_generation(headers, operation) {
            Ok(value) => value,
            Err(response) => return *response,
        }
    } else {
        None
    };
    let request = request_envelope(state, operation, request_id, expected_generation, body);
    let mut response = state
        .dispatcher
        .lock()
        .await
        .dispatch_from(request, ManagementSource::Web)
        .await;
    redact_response(operation, &state.config.actor_capabilities, &mut response);
    let status = if response.ok {
        success_status
    } else {
        response
            .error
            .as_ref()
            .map_or(StatusCode::INTERNAL_SERVER_ERROR, |error| {
                error_status(error.code)
            })
    };
    (status, Json(response)).into_response()
}

fn request_envelope<D>(
    state: &WebState<D>,
    operation: &'static str,
    request_id: String,
    expected_generation: Option<GenerationExpectation>,
    body: Value,
) -> RequestEnvelope {
    RequestEnvelope {
        api_version: LOCAL_API_VERSION.to_owned(),
        operation: operation.to_owned(),
        request_id,
        actor: Actor {
            id: state.config.actor_id.clone(),
            capabilities: state.config.actor_capabilities.iter().cloned().collect(),
        },
        expected_generation,
        body,
    }
}

fn request_id(headers: &HeaderMap) -> String {
    if let Some(value) = headers
        .get("x-request-id")
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.is_empty() && value.len() <= 128)
    {
        return value.to_owned();
    }
    let mut bytes = [0_u8; 16];
    if fill(&mut bytes).is_err() {
        return format!("web-{}", now_ms());
    }
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn expected_generation(
    headers: &HeaderMap,
    operation: &str,
) -> Result<Option<GenerationExpectation>, Box<Response>> {
    let Some(value) = headers.get("x-pathchord-generation") else {
        return Ok(None);
    };
    let value = value
        .to_str()
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .ok_or_else(|| {
            Box::new(gateway_failure(
                StatusCode::BAD_REQUEST,
                "VALIDATION_FAILED",
                "generation header is invalid",
            ))
        })?;
    Ok(Some(GenerationExpectation {
        scope: if operation.starts_with("authorizations.") {
            "authorization"
        } else {
            "configuration"
        }
        .to_owned(),
        value,
    }))
}

fn query_body(query: BTreeMap<String, String>) -> Value {
    Value::Object(
        query
            .into_iter()
            .map(|(key, value)| {
                let value = match key.as_str() {
                    "page_size" => value
                        .parse::<u64>()
                        .map(Value::from)
                        .unwrap_or(Value::String(value)),
                    "filter" => serde_json::from_str(&value).unwrap_or(Value::String(value)),
                    _ => Value::String(value),
                };
                (key, value)
            })
            .collect(),
    )
}

fn redact_response(
    operation: &str,
    capabilities: &BTreeSet<String>,
    response: &mut ResponseEnvelope,
) {
    if operation != "connections.list" || capabilities.contains("targets:read") {
        return;
    }
    let Some(items) = response
        .result
        .as_mut()
        .and_then(|value| value.get_mut("items"))
        .and_then(Value::as_array_mut)
    else {
        return;
    };
    for item in items {
        if let Some(item) = item.as_object_mut() {
            item.insert("target".to_owned(), Value::Null);
            item.insert(
                "target_redaction_reason".to_owned(),
                Value::String("capability_required".to_owned()),
            );
        }
    }
}

fn error_status(code: ErrorCode) -> StatusCode {
    match code {
        ErrorCode::MalformedRequest | ErrorCode::ValidationFailed => StatusCode::BAD_REQUEST,
        ErrorCode::AuthenticationRequired => StatusCode::UNAUTHORIZED,
        ErrorCode::CapabilityDenied => StatusCode::FORBIDDEN,
        ErrorCode::NotFound => StatusCode::NOT_FOUND,
        ErrorCode::GenerationConflict | ErrorCode::IdempotencyConflict => StatusCode::CONFLICT,
        ErrorCode::ResourceLimit => StatusCode::TOO_MANY_REQUESTS,
        ErrorCode::PersistenceUnavailable => StatusCode::SERVICE_UNAVAILABLE,
        ErrorCode::UnsupportedOperation => StatusCode::NOT_IMPLEMENTED,
    }
}

fn gateway_failure(status: StatusCode, code: &'static str, message: &'static str) -> Response {
    (
        status,
        Json(json!({
            "ok": false,
            "error": {"code": code, "message": message}
        })),
    )
        .into_response()
}

async fn events<D>(State(state): State<WebState<D>>, headers: HeaderMap) -> Response
where
    D: ManagementDispatcher,
{
    let permit = match Arc::clone(&state.sse_clients).try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => {
            return gateway_failure(
                StatusCode::TOO_MANY_REQUESTS,
                "RESOURCE_LIMIT",
                "SSE client limit exceeded",
            );
        }
    };
    let cursor = match headers
        .get("last-event-id")
        .and_then(|value| value.to_str().ok())
    {
        Some(value) => match value.parse::<u64>() {
            Ok(value) => Some(value),
            Err(_) => {
                return gateway_failure(
                    StatusCode::BAD_REQUEST,
                    "VALIDATION_FAILED",
                    "Last-Event-ID is invalid",
                );
            }
        },
        None => None,
    };
    let heartbeat = state.config.heartbeat_interval;
    let stream_state = state.clone();
    let event_stream = stream! {
        let _permit = permit;
        let mut cursor = cursor;
        let snapshot = dispatch_for_sse(&stream_state, "metrics.snapshot", Value::Object(Map::new())).await;
        if let Some(result) = snapshot.result {
            let value = json!({
                "type": "metrics.snapshot",
                "generation": snapshot.observed_generation,
                "emitted_at": now_ms(),
                "resource_type": "metrics",
                "resource_id": "runtime",
                "payload": result,
            });
            yield Ok::<Event, Infallible>(Event::default().event("metrics.snapshot").data(value.to_string()));
        }
        loop {
            let response = dispatch_for_sse(
                &stream_state,
                "events.subscribe",
                json!({"last_event_id": cursor}),
            ).await;
            let result = response.result.unwrap_or(Value::Null);
            if result.get("reset_required").and_then(Value::as_bool) == Some(true) {
                let boundary = result.get("latest_event_id").and_then(Value::as_u64).unwrap_or(0);
                let snapshot = complete_snapshot_for_sse(&stream_state).await;
                let value = json!({
                    "id": boundary,
                    "type": "metrics.snapshot",
                    "generation": snapshot.get("generation").cloned().unwrap_or(Value::Null),
                    "emitted_at": snapshot.pointer("/metrics/captured_at").cloned().unwrap_or(Value::Null),
                    "resource_type": "snapshot",
                    "resource_id": "runtime",
                    "payload": snapshot,
                });
                cursor = Some(boundary);
                yield Ok::<Event, Infallible>(Event::default().id(boundary.to_string()).event("metrics.snapshot").data(value.to_string()));
                continue;
            }
            let events = result
                .get("items").cloned()
                .and_then(|value| value.as_array().cloned())
                .unwrap_or_default();
            for item in events {
                let Some(id) = item.get("id").and_then(Value::as_u64) else { continue; };
                let event_type = canonical_event_type(
                    item.get("type").and_then(Value::as_str).unwrap_or("audit.notice")
                );
                let resource_id = item.get("resource_id").and_then(Value::as_str).unwrap_or("unknown");
                let generation = item
                    .get("generation")
                    .cloned()
                    .unwrap_or_else(|| json!({"scope": "observation", "value": 0}));
                let resource_type = event_type.split('.').next().unwrap_or("runtime");
                let value = json!({
                    "id": id,
                    "type": event_type,
                    "generation": generation,
                    "emitted_at": item.get("emitted_at").cloned().unwrap_or(Value::Null),
                    "resource_type": item.get("resource_type").and_then(Value::as_str).unwrap_or(resource_type),
                    "resource_id": resource_id,
                    "payload": item.get("payload").cloned().unwrap_or_else(|| json!({})),
                });
                cursor = Some(id);
                yield Ok::<Event, Infallible>(
                    Event::default()
                        .id(id.to_string())
                        .event(event_type)
                        .data(value.to_string())
                );
            }
            tokio::time::sleep(stream_state.config.event_poll_interval).await;
        }
    };
    Sse::new(event_stream)
        .keep_alive(KeepAlive::new().interval(heartbeat).text("heartbeat"))
        .into_response()
}

async fn complete_snapshot_for_sse<D>(state: &WebState<D>) -> Value
where
    D: ManagementDispatcher,
{
    let metrics = dispatch_for_sse(state, "metrics.snapshot", json!({})).await;
    let mut resources = Map::new();
    let mut operations = vec![
        ("nodes", "nodes.list"),
        ("listeners", "listeners.list"),
        ("sessions", "sessions.list"),
        ("connections", "connections.list"),
        ("subscriptions", "subscriptions.list"),
        ("paths", "metrics.paths"),
        ("streams", "metrics.streams"),
    ];
    if state.config.authorizations_enabled {
        operations.push(("authorizations", "authorizations.list"));
    }
    for (name, operation) in operations {
        let mut items = Vec::new();
        let mut token: Option<String> = None;
        let mut complete = false;
        for _ in 0..64 {
            let response = dispatch_for_sse(
                state,
                operation,
                json!({"page_size": 1000, "page_token": token}),
            )
            .await;
            if !response.ok {
                break;
            }
            let Some(result) = response.result else {
                break;
            };
            let Some(page) = result.get("items").and_then(Value::as_array) else {
                break;
            };
            items.extend(page.iter().cloned());
            token = result
                .get("next_page_token")
                .and_then(Value::as_str)
                .map(str::to_owned);
            if token.is_none() {
                complete = true;
                break;
            }
        }
        resources.insert(
            name.to_owned(),
            if complete {
                Value::Array(items)
            } else {
                Value::Null
            },
        );
    }
    json!({"generation": metrics.observed_generation, "metrics": metrics.result, "resources": resources})
}

async fn dispatch_for_sse<D>(
    state: &WebState<D>,
    operation: &'static str,
    body: Value,
) -> ResponseEnvelope
where
    D: ManagementDispatcher,
{
    let request = request_envelope(state, operation, request_id(&HeaderMap::new()), None, body);
    state
        .dispatcher
        .lock()
        .await
        .dispatch_from(request, ManagementSource::Web)
        .await
}

fn canonical_event_type(value: &str) -> &'static str {
    match value {
        "nodechanged" | "node.changed" => "node.changed",
        "subscriptionchanged" | "subscription.changed" => "subscription.changed",
        "subscriptionrefreshrequested" => "subscription.changed",
        "observationchanged" | "metrics.snapshot" => "metrics.snapshot",
        "systemproxychanged" | "system_proxy.changed" => "system_proxy.changed",
        "auditnotice" | "audit.notice" => "audit.notice",
        "authorizationchanged" | "authorization.changed" => "authorization.changed",
        "pathchanged" | "path.changed" => "path.changed",
        "sessionchanged" | "session.changed" => "session.changed",
        "streamchanged" | "stream.changed" => "stream.changed",
        "connectionchanged" | "connection.changed" => "connection.changed",
        _ => "audit.notice",
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis().min(u128::from(u64::MAX)) as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use pathchord_core::{SessionId, StreamId};
    use reqwest::Client;
    use tokio::sync::oneshot;

    use super::*;
    use crate::{
        ConnectionObservation, ConnectionState, FakePlatformProxyAdapter, ListenerDescriptor,
        ListenerId, ListenerKind, LocalControlDispatcher, NodeId, SystemProxyPlatform,
    };

    struct RunningGateway {
        address: SocketAddr,
        shutdown: Option<oneshot::Sender<()>>,
        task: tokio::task::JoinHandle<Result<(), WebGatewayError>>,
    }

    impl RunningGateway {
        fn url(&self, path: &str) -> String {
            format!("http://{}{}", self.address, path)
        }

        async fn stop(mut self) {
            if let Some(shutdown) = self.shutdown.take() {
                let _ = shutdown.send(());
            }
            self.task.await.unwrap().unwrap();
        }
    }

    fn dispatcher() -> SharedManagementDispatcher<LocalControlDispatcher> {
        let mut dispatcher = LocalControlDispatcher::with_platform_proxy(
            SystemProxyPlatform::Windows,
            Arc::new(FakePlatformProxyAdapter::new()),
        );
        dispatcher
            .service_mut()
            .add_node(NodeId::new("node-1").unwrap())
            .unwrap();
        dispatcher
            .service_mut()
            .register_listener(ListenerDescriptor {
                id: ListenerId::new("local-http"),
                kind: ListenerKind::Http,
                bind: Some("127.0.0.1:8080".parse().unwrap()),
                interface: None,
                address: None,
                mtu: None,
                flow_tags: std::collections::BTreeSet::new(),
                process_metadata: crate::ProcessMetadataRequest::default(),
                allowed_sources: vec!["127.0.0.1/32".into()],
                authentication_required: false,
            });
        dispatcher
            .service_mut()
            .set_connection_observation(ConnectionObservation {
                connection_id: "connection-1".into(),
                session_id: Some(SessionId::new(1)),
                stream_id: Some(StreamId::try_from(1).unwrap()),
                state: ConnectionState::Open,
                bytes_sent: 10,
                bytes_received: 20,
                target_display: Some("private.example.test:443".into()),
            })
            .unwrap();
        Arc::new(Mutex::new(dispatcher))
    }

    async fn start(
        config: WebGatewayConfig,
        dispatcher: SharedManagementDispatcher<LocalControlDispatcher>,
    ) -> RunningGateway {
        let gateway = WebGateway::bind(config, dispatcher).await.unwrap();
        let address = gateway.local_addr().unwrap();
        let (shutdown, signal) = oneshot::channel();
        let task = tokio::spawn(gateway.run_until_shutdown(async move {
            let _ = signal.await;
        }));
        RunningGateway {
            address,
            shutdown: Some(shutdown),
            task,
        }
    }

    async fn json(response: reqwest::Response) -> Value {
        response.json::<Value>().await.unwrap()
    }

    #[tokio::test]
    async fn serves_assets_resources_and_redacts_connection_targets() {
        let gateway = start(WebGatewayConfig::default(), dispatcher()).await;
        let client = Client::new();
        let index = client.get(gateway.url("/")).send().await.unwrap();
        assert_eq!(index.status(), StatusCode::OK);
        assert!(index.headers().get(CONTENT_SECURITY_POLICY).is_some());
        assert!(index.text().await.unwrap().contains("PathChord Console"));

        for path in [
            "/api/v1/status",
            "/api/v1/nodes",
            "/api/v1/sessions",
            "/api/v1/connections",
            "/api/v1/listeners",
            "/api/v1/subscriptions",
            "/api/v1/metrics/snapshot",
            "/api/v1/system-proxy",
        ] {
            assert_eq!(
                client.get(gateway.url(path)).send().await.unwrap().status(),
                StatusCode::OK,
                "resource {path}"
            );
        }
        let connections = json(
            client
                .get(gateway.url("/api/v1/connections"))
                .send()
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(connections["result"]["items"][0]["target"], Value::Null);
        assert_eq!(
            connections["result"]["items"][0]["target_redaction_reason"],
            "capability_required"
        );
        gateway.stop().await;
    }

    #[tokio::test]
    async fn prometheus_export_uses_the_gateway_authentication_and_metric_capability() {
        let gateway = start(
            WebGatewayConfig {
                bearer_token: Some(WebBearerToken::new("scrape-token-secret".to_owned())),
                ..WebGatewayConfig::default()
            },
            dispatcher(),
        )
        .await;
        let client = Client::new();
        assert_eq!(
            client
                .get(gateway.url("/metrics"))
                .send()
                .await
                .unwrap()
                .status(),
            StatusCode::UNAUTHORIZED
        );
        let response = client
            .get(gateway.url("/metrics"))
            .bearer_auth("scrape-token-secret")
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert!(
            response.headers()[CONTENT_TYPE]
                .to_str()
                .unwrap()
                .starts_with("text/plain; version=0.0.4")
        );
        let text = response.text().await.unwrap();
        assert!(text.contains("# TYPE pathchord_active_sessions gauge"));
        assert!(!text.contains("scrape-token-secret"));
        gateway.stop().await;
        let gateway = start(
            WebGatewayConfig {
                actor_capabilities: BTreeSet::from(["status:read".to_owned()]),
                ..WebGatewayConfig::default()
            },
            dispatcher(),
        )
        .await;
        assert_eq!(
            client
                .get(gateway.url("/metrics"))
                .send()
                .await
                .unwrap()
                .status(),
            StatusCode::FORBIDDEN
        );
        gateway.stop().await;
    }

    #[tokio::test]
    async fn ingress_gateway_does_not_advertise_egress_authorization_routes() {
        let gateway = start(WebGatewayConfig::default(), dispatcher()).await;
        let response = Client::new()
            .get(gateway.url("/api/v1/authorizations"))
            .send()
            .await
            .unwrap();
        assert!(matches!(
            response.status(),
            StatusCode::NOT_FOUND | StatusCode::METHOD_NOT_ALLOWED
        ));
        gateway.stop().await;
    }

    #[tokio::test]
    async fn mutation_preserves_generation_request_id_and_idempotency() {
        let gateway = start(WebGatewayConfig::default(), dispatcher()).await;
        let client = Client::new();
        let request = || {
            client
                .patch(gateway.url("/api/v1/nodes/node-1/labels"))
                .header("x-request-id", "same-request")
                .header("x-pathchord-generation", "0")
                .json(&json!({"set": {"admin.region": "jp"}, "remove": []}))
        };
        let first = request().send().await.unwrap();
        assert_eq!(first.status(), StatusCode::OK);
        let first = json(first).await;
        assert_eq!(first["request_id"], "same-request");
        assert_eq!(first["result"]["applied_generation"]["value"], 1);

        let replay = request().send().await.unwrap();
        assert_eq!(replay.status(), StatusCode::OK);
        let nodes = json(
            client
                .get(gateway.url("/api/v1/nodes"))
                .send()
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(
            nodes["result"]["items"][0]["admin"]["labels"]["admin.region"],
            "jp"
        );
        gateway.stop().await;
    }

    #[test]
    fn non_loopback_requires_strong_authentication_and_origins() {
        let mut config = WebGatewayConfig {
            bind: "0.0.0.0:8080".parse().unwrap(),
            ..WebGatewayConfig::default()
        };
        assert!(validate_config(&config).is_err());
        config.bearer_token = Some(WebBearerToken::new("0123456789abcdef0123456789abcdef"));
        assert!(validate_config(&config).is_err());
        config
            .allowed_origins
            .insert("https://console.example.test".into());
        config.protected_transport = true;
        assert!(validate_config(&config).is_ok());
    }

    #[tokio::test]
    async fn bearer_origin_and_rate_limits_fail_closed() {
        let config = WebGatewayConfig {
            bearer_token: Some(WebBearerToken::new("0123456789abcdef")),
            max_requests_per_minute: 1,
            ..WebGatewayConfig::default()
        };
        let gateway = start(config, dispatcher()).await;
        let client = Client::new();
        let preflight = client
            .request(Method::OPTIONS, gateway.url("/api/v1/status"))
            .header(ORIGIN, format!("http://{}", gateway.address))
            .send()
            .await
            .unwrap();
        assert_eq!(preflight.status(), StatusCode::NO_CONTENT);
        assert!(
            preflight
                .headers()
                .get(ACCESS_CONTROL_ALLOW_METHODS)
                .is_some()
        );
        assert_eq!(
            client
                .get(gateway.url("/api/v1/status"))
                .send()
                .await
                .unwrap()
                .status(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            client
                .get(gateway.url("/api/v1/status"))
                .bearer_auth("0123456789abcdef")
                .header(ORIGIN, "https://evil.example")
                .send()
                .await
                .unwrap()
                .status(),
            StatusCode::FORBIDDEN
        );
        let first = client
            .get(gateway.url("/api/v1/status"))
            .bearer_auth("0123456789abcdef")
            .send()
            .await
            .unwrap();
        assert_eq!(first.status(), StatusCode::OK);
        let second = client
            .get(gateway.url("/api/v1/status"))
            .bearer_auth("0123456789abcdef")
            .send()
            .await
            .unwrap();
        assert_eq!(second.status(), StatusCode::TOO_MANY_REQUESTS);
        gateway.stop().await;
    }

    async fn read_sse_until(mut response: reqwest::Response, needle: &str) -> String {
        let mut received = String::new();
        tokio::time::timeout(Duration::from_secs(3), async {
            while let Some(chunk) = response.chunk().await.unwrap() {
                received.push_str(&String::from_utf8_lossy(&chunk));
                if received.contains(needle) {
                    return;
                }
            }
        })
        .await
        .expect("SSE event timeout");
        received
    }

    #[tokio::test]
    async fn sse_replays_events_updates_after_mutation_and_bounds_clients() {
        let config = WebGatewayConfig {
            max_sse_clients: 1,
            event_poll_interval: Duration::from_millis(20),
            heartbeat_interval: Duration::from_millis(50),
            ..WebGatewayConfig::default()
        };
        let gateway = start(config, dispatcher()).await;
        let client = Client::new();
        let first_stream = client
            .get(gateway.url("/api/v1/events"))
            .send()
            .await
            .unwrap();
        assert_eq!(first_stream.status(), StatusCode::OK);
        let second = client
            .get(gateway.url("/api/v1/events"))
            .send()
            .await
            .unwrap();
        assert_eq!(second.status(), StatusCode::TOO_MANY_REQUESTS);
        drop(first_stream);

        let mutation = client
            .patch(gateway.url("/api/v1/nodes/node-1/tags"))
            .header("x-request-id", "event-request")
            .header("x-pathchord-generation", "0")
            .json(&json!({"add": ["preferred"], "remove": []}))
            .send()
            .await
            .unwrap();
        assert_eq!(mutation.status(), StatusCode::OK);

        let replay = client
            .get(gateway.url("/api/v1/events"))
            .header("last-event-id", "0")
            .send()
            .await
            .unwrap();
        let body = read_sse_until(replay, "node.changed").await;
        assert!(body.contains("metrics.snapshot"));
        assert!(body.contains("id: 1"));
        assert!(body.contains("node.changed"));
        gateway.stop().await;
    }

    #[tokio::test]
    async fn replay_gap_emits_a_resource_snapshot_at_a_new_cursor() {
        let gateway = start(
            WebGatewayConfig {
                event_poll_interval: Duration::from_millis(10),
                ..WebGatewayConfig::default()
            },
            dispatcher(),
        )
        .await;
        let stream = Client::new()
            .get(gateway.url("/api/v1/events"))
            .header("last-event-id", "9999")
            .send()
            .await
            .unwrap();
        let body = read_sse_until(stream, "\"resources\"").await;
        assert!(body.contains("id: 1"));
        assert!(body.contains("node-1"));
        assert!(body.contains("\"metrics\""));
        gateway.stop().await;
    }

    #[test]
    fn generation_header_uses_the_owner_of_the_operation() {
        let mut headers = HeaderMap::new();
        headers.insert("x-pathchord-generation", HeaderValue::from_static("7"));
        assert_eq!(
            expected_generation(&headers, "authorizations.enroll")
                .unwrap()
                .unwrap()
                .scope,
            "authorization"
        );
        assert_eq!(
            expected_generation(&headers, "nodes.patch_tags")
                .unwrap()
                .unwrap()
                .scope,
            "configuration"
        );
    }
}
