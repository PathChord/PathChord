use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use pathchord_policy::{
    Endpoint, FlowProtocol, RuntimeCatalog, RuntimeNodeState, SubscriptionConfig, SubscriptionId,
    SubscriptionSourceType, TransitProxyConfig, TransitProxyId, TransitProxyRuntimeStatus,
    TransitSource,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const MAX_SUBSCRIPTION_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_SUBSCRIPTION_NODES: usize = 10_000;
const MAX_CACHE_BYTES: u64 = 16 * 1024 * 1024;
const MAX_BACKOFF_SECONDS: u64 = 3_600;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubscriptionFetchRequest {
    pub url: String,
    pub credentials_ref: Option<String>,
    pub timeout: Duration,
    pub max_bytes: usize,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum SubscriptionError {
    #[error("subscription source format is not refreshable")]
    StaticSource,
    #[error("subscription URL is invalid or contains credentials")]
    InvalidUrl,
    #[error("subscription credential is unavailable")]
    MissingCredential,
    #[error("subscription request timed out")]
    Timeout,
    #[error("subscription HTTP request failed")]
    Fetch,
    #[error("subscription HTTP response returned status {0}")]
    HttpStatus(u16),
    #[error("subscription response exceeds {maximum} bytes")]
    ResponseTooLarge { maximum: usize },
    #[error("subscription document is malformed for {format}")]
    MalformedDocument { format: &'static str },
    #[error("subscription contains too many nodes")]
    TooManyNodes,
    #[error("subscription node {index} is invalid: {reason}")]
    InvalidNode { index: usize, reason: String },
    #[error("subscription protocol is not registered")]
    UnsupportedProtocol,
    #[error("subscription cache path is invalid")]
    InvalidCachePath,
    #[error("subscription cache I/O failed")]
    CacheIo,
    #[error("subscription cache document is invalid")]
    InvalidCache,
    #[error("subscription node identity conflicts with another source")]
    NodeIdentityConflict,
    #[error("system clock is before the Unix epoch")]
    Clock,
}

#[async_trait]
pub trait SubscriptionFetcher: Send + Sync {
    async fn fetch(&self, request: SubscriptionFetchRequest) -> Result<Vec<u8>, SubscriptionError>;
}

pub trait SubscriptionCredentialProvider: Send + Sync {
    fn bearer_token(&self, reference: &str) -> Option<String>;
}

#[derive(Debug, Default)]
pub struct NoSubscriptionCredentials;

impl SubscriptionCredentialProvider for NoSubscriptionCredentials {
    fn bearer_token(&self, _reference: &str) -> Option<String> {
        None
    }
}

pub struct HttpSubscriptionFetcher {
    client: reqwest::Client,
    credentials: Arc<dyn SubscriptionCredentialProvider>,
}

impl fmt::Debug for HttpSubscriptionFetcher {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HttpSubscriptionFetcher")
            .finish_non_exhaustive()
    }
}

impl HttpSubscriptionFetcher {
    pub fn new() -> Result<Self, SubscriptionError> {
        Self::with_credentials(Arc::new(NoSubscriptionCredentials))
    }

    pub fn with_credentials(
        credentials: Arc<dyn SubscriptionCredentialProvider>,
    ) -> Result<Self, SubscriptionError> {
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::limited(5))
            .build()
            .map_err(|_| SubscriptionError::Fetch)?;
        Ok(Self {
            client,
            credentials,
        })
    }
}

#[async_trait]
impl SubscriptionFetcher for HttpSubscriptionFetcher {
    async fn fetch(&self, request: SubscriptionFetchRequest) -> Result<Vec<u8>, SubscriptionError> {
        let parsed =
            reqwest::Url::parse(&request.url).map_err(|_| SubscriptionError::InvalidUrl)?;
        if !matches!(parsed.scheme(), "http" | "https")
            || !parsed.username().is_empty()
            || parsed.password().is_some()
        {
            return Err(SubscriptionError::InvalidUrl);
        }

        let mut builder = self.client.get(parsed).timeout(request.timeout);
        if let Some(reference) = request.credentials_ref.as_deref() {
            let token = self
                .credentials
                .bearer_token(reference)
                .ok_or(SubscriptionError::MissingCredential)?;
            builder = builder.bearer_auth(token);
        }
        let mut response = builder.send().await.map_err(|error| {
            if error.is_timeout() {
                SubscriptionError::Timeout
            } else {
                SubscriptionError::Fetch
            }
        })?;
        let status = response.status();
        if !status.is_success() {
            return Err(SubscriptionError::HttpStatus(status.as_u16()));
        }
        if response
            .content_length()
            .is_some_and(|length| length > request.max_bytes as u64)
        {
            return Err(SubscriptionError::ResponseTooLarge {
                maximum: request.max_bytes,
            });
        }

        let mut body = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| SubscriptionError::Fetch)?
        {
            if body.len().saturating_add(chunk.len()) > request.max_bytes {
                return Err(SubscriptionError::ResponseTooLarge {
                    maximum: request.max_bytes,
                });
            }
            body.extend_from_slice(&chunk);
        }
        Ok(body)
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubscriptionCredential {
    fields: BTreeMap<String, String>,
}

impl fmt::Debug for SubscriptionCredential {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SubscriptionCredential")
            .field("field_names", &self.fields.keys().collect::<Vec<_>>())
            .finish_non_exhaustive()
    }
}

impl SubscriptionCredential {
    #[must_use]
    pub fn new(fields: BTreeMap<String, String>) -> Self {
        Self { fields }
    }

    #[must_use]
    pub fn field(&self, name: &str) -> Option<&str> {
        self.fields.get(name).map(String::as_str)
    }

    pub(crate) fn fields(&self) -> BTreeMap<String, String> {
        self.fields.clone()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NodeUnavailableReason {
    AdapterUnavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DynamicNodeState {
    Active,
    Draining,
    Unavailable(NodeUnavailableReason),
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DynamicTransitNode {
    pub config: TransitProxyConfig,
    pub source_subscription: SubscriptionId,
    pub state: DynamicNodeState,
    credential: SubscriptionCredential,
}

impl fmt::Debug for DynamicTransitNode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DynamicTransitNode")
            .field("config", &self.config)
            .field("source_subscription", &self.source_subscription)
            .field("state", &self.state)
            .field("credential", &self.credential)
            .finish()
    }
}

impl DynamicTransitNode {
    #[must_use]
    pub fn credential(&self) -> &SubscriptionCredential {
        &self.credential
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DynamicTransitSnapshot {
    pub generation: u64,
    pub nodes: BTreeMap<TransitProxyId, DynamicTransitNode>,
}

impl DynamicTransitSnapshot {
    pub fn selectable_nodes(&self) -> impl Iterator<Item = &DynamicTransitNode> {
        self.nodes
            .values()
            .filter(|node| node.state == DynamicNodeState::Active)
    }

    /// Adds the current dynamic node configuration and admission state to an
    /// evaluation catalog without recompiling the immutable rule snapshot.
    pub fn extend_runtime_catalog(&self, catalog: &mut RuntimeCatalog) {
        for node in self.nodes.values() {
            let state = match node.state {
                DynamicNodeState::Active => RuntimeNodeState::Ready,
                DynamicNodeState::Draining => RuntimeNodeState::Draining,
                DynamicNodeState::Unavailable(_) => RuntimeNodeState::Down,
            };
            let capabilities = if node.state == DynamicNodeState::Active {
                BTreeSet::from([FlowProtocol::Tcp, FlowProtocol::Udp])
            } else {
                BTreeSet::new()
            };
            catalog.set_dynamic_transit_proxy(
                node.config.clone(),
                TransitProxyRuntimeStatus {
                    state,
                    capabilities,
                    labels: BTreeMap::new(),
                    tags: BTreeSet::new(),
                    selection_score: 1,
                },
            );
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SnapshotDiff {
    pub generation: u64,
    pub added: Vec<TransitProxyId>,
    pub updated: Vec<TransitProxyId>,
    pub draining: Vec<TransitProxyId>,
    pub unavailable: Vec<TransitProxyId>,
    pub removed: Vec<TransitProxyId>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RefreshOutcome {
    Published {
        attempts: u32,
        diff: SnapshotDiff,
    },
    Retained {
        generation: u64,
        attempts: u32,
        error: SubscriptionError,
    },
    Disabled {
        diff: SnapshotDiff,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CacheLoadOutcome {
    Loaded { diff: SnapshotDiff },
    NotConfigured,
    Missing,
    Expired,
    Disabled { diff: SnapshotDiff },
}

#[async_trait]
trait RetrySleeper: Send + Sync {
    async fn sleep(&self, duration: Duration);
}

#[derive(Debug)]
struct TokioRetrySleeper;

#[async_trait]
impl RetrySleeper for TokioRetrySleeper {
    async fn sleep(&self, duration: Duration) {
        tokio::time::sleep(duration).await;
    }
}

pub struct SubscriptionManager {
    fetcher: Arc<dyn SubscriptionFetcher>,
    sleeper: Arc<dyn RetrySleeper>,
    cache_root: PathBuf,
    available_adapters: BTreeSet<String>,
    snapshot: DynamicTransitSnapshot,
}

impl fmt::Debug for SubscriptionManager {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SubscriptionManager")
            .field("cache_root", &self.cache_root)
            .field("available_adapters", &self.available_adapters)
            .field("snapshot", &self.snapshot)
            .finish_non_exhaustive()
    }
}

impl SubscriptionManager {
    #[must_use]
    pub fn new(
        fetcher: Arc<dyn SubscriptionFetcher>,
        cache_root: impl Into<PathBuf>,
        available_adapters: BTreeSet<String>,
    ) -> Self {
        Self {
            fetcher,
            sleeper: Arc::new(TokioRetrySleeper),
            cache_root: cache_root.into(),
            available_adapters,
            snapshot: DynamicTransitSnapshot::default(),
        }
    }

    #[cfg(test)]
    fn with_sleeper(
        fetcher: Arc<dyn SubscriptionFetcher>,
        sleeper: Arc<dyn RetrySleeper>,
        cache_root: impl Into<PathBuf>,
        available_adapters: BTreeSet<String>,
    ) -> Self {
        Self {
            fetcher,
            sleeper,
            cache_root: cache_root.into(),
            available_adapters,
            snapshot: DynamicTransitSnapshot::default(),
        }
    }

    #[must_use]
    pub fn snapshot(&self) -> &DynamicTransitSnapshot {
        &self.snapshot
    }

    pub async fn refresh(&mut self, config: &SubscriptionConfig) -> RefreshOutcome {
        if !config.enabled {
            return RefreshOutcome::Disabled {
                diff: self.disable(&config.id),
            };
        }
        if config.source.source_type == SubscriptionSourceType::Static {
            return RefreshOutcome::Retained {
                generation: self.snapshot.generation,
                attempts: 0,
                error: SubscriptionError::StaticSource,
            };
        }

        let attempts = config.refresh.max_attempts.clamp(1, 10);
        let mut last_error = SubscriptionError::Fetch;
        for attempt in 1..=attempts {
            let request = SubscriptionFetchRequest {
                url: config.source.url.clone(),
                credentials_ref: config.source.credentials_ref.clone(),
                timeout: Duration::from_secs(config.refresh.timeout_seconds.clamp(1, 300)),
                max_bytes: MAX_SUBSCRIPTION_BYTES,
            };
            let fetched = tokio::time::timeout(request.timeout, self.fetcher.fetch(request)).await;
            let candidate = match fetched {
                Ok(Ok(body)) => normalize(config, &body, &self.available_adapters),
                Ok(Err(error)) => Err(error),
                Err(_) => Err(SubscriptionError::Timeout),
            };
            match candidate {
                Ok(nodes) => {
                    if let Some(cache) = &config.cache {
                        let published_at = match unix_seconds() {
                            Ok(value) => value,
                            Err(error) => {
                                return RefreshOutcome::Retained {
                                    generation: self.snapshot.generation,
                                    attempts: attempt,
                                    error,
                                };
                            }
                        };
                        if let Err(error) = self.write_cache(config, published_at, &nodes).await {
                            return RefreshOutcome::Retained {
                                generation: self.snapshot.generation,
                                attempts: attempt,
                                error,
                            };
                        }
                        debug_assert!(!cache.path.is_empty());
                    }
                    let diff = match self.publish(&config.id, nodes) {
                        Ok(diff) => diff,
                        Err(error) => {
                            return RefreshOutcome::Retained {
                                generation: self.snapshot.generation,
                                attempts: attempt,
                                error,
                            };
                        }
                    };
                    return RefreshOutcome::Published {
                        attempts: attempt,
                        diff,
                    };
                }
                Err(error) => last_error = error,
            }
            if attempt < attempts {
                self.sleeper
                    .sleep(backoff_delay(config.refresh.backoff_seconds, attempt))
                    .await;
            }
        }
        RefreshOutcome::Retained {
            generation: self.snapshot.generation,
            attempts,
            error: last_error,
        }
    }

    pub async fn load_cache(
        &mut self,
        config: &SubscriptionConfig,
    ) -> Result<CacheLoadOutcome, SubscriptionError> {
        if !config.enabled {
            return Ok(CacheLoadOutcome::Disabled {
                diff: self.disable(&config.id),
            });
        }
        let Some(cache) = &config.cache else {
            return Ok(CacheLoadOutcome::NotConfigured);
        };
        let path = resolve_cache_path(&self.cache_root, &cache.path)?;
        let metadata = match tokio::fs::metadata(&path).await {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(CacheLoadOutcome::Missing);
            }
            Err(_) => return Err(SubscriptionError::CacheIo),
        };
        if metadata.len() > MAX_CACHE_BYTES {
            return Err(SubscriptionError::InvalidCache);
        }
        let encoded = tokio::fs::read(&path)
            .await
            .map_err(|_| SubscriptionError::CacheIo)?;
        let cached: CacheEnvelope =
            serde_json::from_slice(&encoded).map_err(|_| SubscriptionError::InvalidCache)?;
        let now = unix_seconds()?;
        if now.saturating_sub(cached.published_at_unix_seconds) > cache.max_age_seconds {
            return Ok(CacheLoadOutcome::Expired);
        }
        if cached.version != 1
            || cached.subscription_id != config.id
            || cached.nodes.len() > MAX_SUBSCRIPTION_NODES
        {
            return Err(SubscriptionError::InvalidCache);
        }
        for node in &cached.nodes {
            if node.source_subscription != config.id {
                return Err(SubscriptionError::InvalidCache);
            }
        }
        let nodes = cached
            .nodes
            .into_iter()
            .map(|node| NormalizedNode {
                config: node.config,
                credential: node.credential,
                state: adapter_state(&node.protocol, &self.available_adapters),
            })
            .collect();
        let diff = self.publish(&config.id, nodes)?;
        Ok(CacheLoadOutcome::Loaded { diff })
    }

    pub fn reconcile(&mut self, configured: &[SubscriptionConfig]) -> SnapshotDiff {
        let enabled: BTreeSet<_> = configured
            .iter()
            .filter(|config| config.enabled)
            .map(|config| config.id.clone())
            .collect();
        let mut draining = Vec::new();
        for (id, node) in &mut self.snapshot.nodes {
            if !enabled.contains(&node.source_subscription)
                && node.state != DynamicNodeState::Draining
            {
                node.state = DynamicNodeState::Draining;
                draining.push(id.clone());
            }
        }
        if !draining.is_empty() {
            self.snapshot.generation = self.snapshot.generation.saturating_add(1);
        }
        SnapshotDiff {
            generation: self.snapshot.generation,
            draining,
            ..SnapshotDiff::default()
        }
    }

    pub fn complete_draining(&mut self, completed: &BTreeSet<TransitProxyId>) -> SnapshotDiff {
        let mut removed = Vec::new();
        self.snapshot.nodes.retain(|id, node| {
            let remove = node.state == DynamicNodeState::Draining && completed.contains(id);
            if remove {
                removed.push(id.clone());
            }
            !remove
        });
        if !removed.is_empty() {
            self.snapshot.generation = self.snapshot.generation.saturating_add(1);
        }
        SnapshotDiff {
            generation: self.snapshot.generation,
            removed,
            ..SnapshotDiff::default()
        }
    }

    fn disable(&mut self, id: &SubscriptionId) -> SnapshotDiff {
        let mut draining = Vec::new();
        for (node_id, node) in &mut self.snapshot.nodes {
            if &node.source_subscription == id && node.state != DynamicNodeState::Draining {
                node.state = DynamicNodeState::Draining;
                draining.push(node_id.clone());
            }
        }
        if !draining.is_empty() {
            self.snapshot.generation = self.snapshot.generation.saturating_add(1);
        }
        SnapshotDiff {
            generation: self.snapshot.generation,
            draining,
            ..SnapshotDiff::default()
        }
    }

    fn publish(
        &mut self,
        subscription_id: &SubscriptionId,
        nodes: Vec<NormalizedNode>,
    ) -> Result<SnapshotDiff, SubscriptionError> {
        let mut candidate_ids = BTreeSet::new();
        for node in &nodes {
            if !candidate_ids.insert(node.config.id.clone()) {
                return Err(SubscriptionError::NodeIdentityConflict);
            }
            if self
                .snapshot
                .nodes
                .get(&node.config.id)
                .is_some_and(|existing| &existing.source_subscription != subscription_id)
            {
                return Err(SubscriptionError::NodeIdentityConflict);
            }
        }

        let mut diff = SnapshotDiff::default();
        let existing_ids: Vec<_> = self
            .snapshot
            .nodes
            .iter()
            .filter(|(_, node)| &node.source_subscription == subscription_id)
            .map(|(id, _)| id.clone())
            .collect();
        for id in existing_ids {
            if !candidate_ids.contains(&id) {
                let node = self.snapshot.nodes.get_mut(&id).expect("existing node");
                if node.state != DynamicNodeState::Draining {
                    node.state = DynamicNodeState::Draining;
                    diff.draining.push(id);
                }
            }
        }
        for normalized in nodes {
            let id = normalized.config.id.clone();
            let node = DynamicTransitNode {
                config: normalized.config,
                source_subscription: subscription_id.clone(),
                state: normalized.state,
                credential: normalized.credential,
            };
            match self.snapshot.nodes.insert(id.clone(), node) {
                Some(previous) if self.snapshot.nodes[&id] != previous => {
                    diff.updated.push(id.clone())
                }
                Some(_) => {}
                None => diff.added.push(id.clone()),
            }
            if matches!(
                self.snapshot.nodes[&id].state,
                DynamicNodeState::Unavailable(_)
            ) {
                diff.unavailable.push(id);
            }
        }
        self.snapshot.generation = self.snapshot.generation.saturating_add(1);
        diff.generation = self.snapshot.generation;
        Ok(diff)
    }

    async fn write_cache(
        &self,
        config: &SubscriptionConfig,
        published_at_unix_seconds: u64,
        nodes: &[NormalizedNode],
    ) -> Result<(), SubscriptionError> {
        let cache = config
            .cache
            .as_ref()
            .ok_or(SubscriptionError::InvalidCachePath)?;
        let path = resolve_cache_path(&self.cache_root, &cache.path)?;
        let cached_nodes = nodes
            .iter()
            .map(|node| CachedNode {
                config: node.config.clone(),
                source_subscription: config.id.clone(),
                protocol: node.config.protocol.clone(),
                credential: node.credential.clone(),
            })
            .collect();
        let envelope = CacheEnvelope {
            version: 1,
            published_at_unix_seconds,
            subscription_id: config.id.clone(),
            nodes: cached_nodes,
        };
        let encoded = serde_json::to_vec(&envelope).map_err(|_| SubscriptionError::InvalidCache)?;
        if encoded.len() as u64 > MAX_CACHE_BYTES {
            return Err(SubscriptionError::InvalidCache);
        }
        atomic_write(&path, &encoded).await
    }
}

#[derive(Debug, Clone)]
struct NormalizedNode {
    config: TransitProxyConfig,
    credential: SubscriptionCredential,
    state: DynamicNodeState,
}

#[derive(Debug, Serialize, Deserialize)]
struct CacheEnvelope {
    version: u8,
    published_at_unix_seconds: u64,
    subscription_id: SubscriptionId,
    nodes: Vec<CachedNode>,
}

#[derive(Debug, Serialize, Deserialize)]
struct CachedNode {
    config: TransitProxyConfig,
    source_subscription: SubscriptionId,
    protocol: String,
    credential: SubscriptionCredential,
}

fn normalize(
    config: &SubscriptionConfig,
    body: &[u8],
    available_adapters: &BTreeSet<String>,
) -> Result<Vec<NormalizedNode>, SubscriptionError> {
    if body.len() > MAX_SUBSCRIPTION_BYTES {
        return Err(SubscriptionError::ResponseTooLarge {
            maximum: MAX_SUBSCRIPTION_BYTES,
        });
    }
    match config.source.source_type {
        SubscriptionSourceType::Clash => normalize_clash(config, body, available_adapters),
        SubscriptionSourceType::Sip008 => normalize_sip008(config, body, available_adapters),
        SubscriptionSourceType::Static => Err(SubscriptionError::StaticSource),
    }
}

#[derive(Debug, Deserialize)]
struct ClashDocument {
    proxies: Vec<ClashNode>,
}

#[derive(Debug, Deserialize)]
struct ClashNode {
    name: String,
    #[serde(rename = "type")]
    protocol: String,
    server: String,
    port: u16,
    #[serde(default)]
    tags: BTreeSet<String>,
    #[serde(default = "default_weight")]
    weight: u32,
    username: Option<String>,
    password: Option<String>,
    cipher: Option<String>,
    uuid: Option<String>,
    #[serde(rename = "alterId")]
    alter_id: Option<u64>,
    tls: Option<bool>,
    servername: Option<String>,
    network: Option<String>,
    flow: Option<String>,
    plugin: Option<String>,
    #[serde(rename = "plugin-opts")]
    plugin_opts: Option<serde_yaml::Value>,
}

fn normalize_clash(
    config: &SubscriptionConfig,
    body: &[u8],
    available_adapters: &BTreeSet<String>,
) -> Result<Vec<NormalizedNode>, SubscriptionError> {
    let document: ClashDocument = serde_yaml::from_slice(body)
        .map_err(|_| SubscriptionError::MalformedDocument { format: "clash" })?;
    if document.proxies.len() > MAX_SUBSCRIPTION_NODES {
        return Err(SubscriptionError::TooManyNodes);
    }
    let mut used = BTreeSet::new();
    document
        .proxies
        .into_iter()
        .enumerate()
        .map(|(index, node)| {
            validate_node(index, &node.protocol, &node.server, node.port, node.weight)?;
            validate_display_name(index, &node.name)?;
            validate_tags(index, &node.tags)?;
            let protocol = node.protocol.to_ascii_lowercase();
            validate_registered_protocol(&protocol)?;
            let mut credentials = BTreeMap::new();
            insert_optional(&mut credentials, "username", node.username);
            insert_optional(&mut credentials, "password", node.password);
            insert_optional(&mut credentials, "cipher", node.cipher);
            insert_optional(&mut credentials, "uuid", node.uuid);
            insert_optional(
                &mut credentials,
                "alter_id",
                node.alter_id.map(|value| value.to_string()),
            );
            insert_optional(
                &mut credentials,
                "tls",
                node.tls.map(|value| value.to_string()),
            );
            insert_optional(&mut credentials, "servername", node.servername);
            insert_optional(&mut credentials, "network", node.network);
            insert_optional(&mut credentials, "flow", node.flow);
            insert_optional(&mut credentials, "plugin", node.plugin);
            if let Some(plugin_opts) = node.plugin_opts {
                let encoded = serde_yaml::to_string(&plugin_opts).map_err(|_| {
                    SubscriptionError::InvalidNode {
                        index,
                        reason: "plugin options are invalid".into(),
                    }
                })?;
                credentials.insert("plugin_opts".into(), encoded);
            }
            validate_credentials(index, &protocol, &credentials)?;
            let id = unique_node_id(config.id.as_str(), &node.name, index, &mut used);
            Ok(NormalizedNode {
                config: TransitProxyConfig {
                    id: TransitProxyId::new(id),
                    source: Some(TransitSource {
                        source_type: "clash".into(),
                        subscription: config.id.as_str().to_owned(),
                    }),
                    protocol: protocol.clone(),
                    endpoint: Endpoint {
                        host: node.server,
                        port: node.port,
                    },
                    credentials_ref: None,
                    labels: BTreeMap::from([
                        ("source.name".into(), node.name),
                        ("source.format".into(), "clash".into()),
                    ]),
                    tags: node.tags,
                    weight: node.weight,
                },
                credential: SubscriptionCredential {
                    fields: credentials,
                },
                state: adapter_state(&protocol, available_adapters),
            })
        })
        .collect()
}

#[derive(Debug, Deserialize)]
struct Sip008Node {
    remarks: Option<String>,
    server: String,
    server_port: u16,
    method: String,
    password: String,
    plugin: Option<String>,
    plugin_opts: Option<String>,
}

fn normalize_sip008(
    config: &SubscriptionConfig,
    body: &[u8],
    available_adapters: &BTreeSet<String>,
) -> Result<Vec<NormalizedNode>, SubscriptionError> {
    let document: Vec<Sip008Node> = serde_json::from_slice(body)
        .map_err(|_| SubscriptionError::MalformedDocument { format: "sip008" })?;
    if document.len() > MAX_SUBSCRIPTION_NODES {
        return Err(SubscriptionError::TooManyNodes);
    }
    let mut used = BTreeSet::new();
    document
        .into_iter()
        .enumerate()
        .map(|(index, node)| {
            validate_node(index, "ss", &node.server, node.server_port, 100)?;
            if node.method.is_empty() || node.password.is_empty() {
                return Err(SubscriptionError::InvalidNode {
                    index,
                    reason: "method and password are required".into(),
                });
            }
            let name = node
                .remarks
                .filter(|value| !value.is_empty())
                .unwrap_or_else(|| format!("node-{}", index + 1));
            validate_display_name(index, &name)?;
            let id = unique_node_id(config.id.as_str(), &name, index, &mut used);
            let mut credentials = BTreeMap::from([
                ("cipher".into(), node.method.clone()),
                ("password".into(), node.password),
            ]);
            insert_optional(&mut credentials, "plugin", node.plugin);
            insert_optional(&mut credentials, "plugin_opts", node.plugin_opts);
            Ok(NormalizedNode {
                config: TransitProxyConfig {
                    id: TransitProxyId::new(id),
                    source: Some(TransitSource {
                        source_type: "sip008".into(),
                        subscription: config.id.as_str().to_owned(),
                    }),
                    protocol: "ss".into(),
                    endpoint: Endpoint {
                        host: node.server,
                        port: node.server_port,
                    },
                    credentials_ref: None,
                    labels: BTreeMap::from([
                        ("source.name".into(), name),
                        ("source.format".into(), "sip008".into()),
                        ("source.method".into(), node.method),
                    ]),
                    tags: BTreeSet::new(),
                    weight: 100,
                },
                credential: SubscriptionCredential {
                    fields: credentials,
                },
                state: adapter_state("ss", available_adapters),
            })
        })
        .collect()
}

fn validate_node(
    index: usize,
    protocol: &str,
    host: &str,
    port: u16,
    weight: u32,
) -> Result<(), SubscriptionError> {
    if protocol.is_empty()
        || host.is_empty()
        || host.len() > 255
        || host.chars().any(char::is_control)
    {
        return Err(SubscriptionError::InvalidNode {
            index,
            reason: "protocol and server must be non-empty".into(),
        });
    }
    if port == 0 || !(1..=1_000_000).contains(&weight) {
        return Err(SubscriptionError::InvalidNode {
            index,
            reason: "port or weight is outside its allowed range".into(),
        });
    }
    Ok(())
}

fn validate_display_name(index: usize, name: &str) -> Result<(), SubscriptionError> {
    if name.is_empty() || name.len() > 256 || name.chars().any(char::is_control) {
        Err(SubscriptionError::InvalidNode {
            index,
            reason: "node name is invalid".into(),
        })
    } else {
        Ok(())
    }
}

fn validate_tags(index: usize, tags: &BTreeSet<String>) -> Result<(), SubscriptionError> {
    if tags.len() > 256
        || tags
            .iter()
            .any(|tag| tag.is_empty() || tag.len() > 64 || tag.chars().any(char::is_control))
    {
        Err(SubscriptionError::InvalidNode {
            index,
            reason: "node tags are invalid".into(),
        })
    } else {
        Ok(())
    }
}

fn validate_registered_protocol(protocol: &str) -> Result<(), SubscriptionError> {
    if ["http", "https", "socks5", "ss", "vless", "vmess", "xtls"].contains(&protocol) {
        Ok(())
    } else {
        Err(SubscriptionError::UnsupportedProtocol)
    }
}

fn validate_credentials(
    index: usize,
    protocol: &str,
    fields: &BTreeMap<String, String>,
) -> Result<(), SubscriptionError> {
    let required: &[&str] = match protocol {
        "ss" => &["cipher", "password"],
        "vless" | "xtls" | "vmess" => &["uuid"],
        _ => &[],
    };
    if required
        .iter()
        .any(|field| fields.get(*field).is_none_or(String::is_empty))
    {
        return Err(SubscriptionError::InvalidNode {
            index,
            reason: format!("{protocol} credentials are incomplete"),
        });
    }
    Ok(())
}

fn insert_optional(fields: &mut BTreeMap<String, String>, name: &str, value: Option<String>) {
    if let Some(value) = value {
        fields.insert(name.to_owned(), value);
    }
}

fn default_weight() -> u32 {
    100
}

fn unique_node_id(
    subscription: &str,
    display_name: &str,
    index: usize,
    used: &mut BTreeSet<String>,
) -> String {
    let prefix = canonical_segment(subscription, 24);
    let name = canonical_segment(display_name, 28);
    let base = format!("{prefix}-{name}");
    let mut candidate = base.clone();
    let mut suffix = index + 1;
    while !used.insert(candidate.clone()) {
        candidate = format!("{base}-{suffix}");
        candidate.truncate(63);
        candidate = candidate.trim_end_matches('-').to_owned();
        suffix += 1;
    }
    candidate
}

fn canonical_segment(value: &str, maximum: usize) -> String {
    let mut result = String::new();
    let mut separator = false;
    for character in value.chars() {
        let mapped = character.to_ascii_lowercase();
        if mapped.is_ascii_lowercase() || mapped.is_ascii_digit() {
            if separator && !result.is_empty() {
                result.push('-');
            }
            separator = false;
            result.push(mapped);
        } else {
            separator = true;
        }
        if result.len() >= maximum {
            break;
        }
    }
    let result = result.trim_matches('-');
    if result.is_empty() {
        "node".into()
    } else {
        result.to_owned()
    }
}

fn adapter_state(protocol: &str, available_adapters: &BTreeSet<String>) -> DynamicNodeState {
    if available_adapters.contains(protocol) {
        DynamicNodeState::Active
    } else {
        DynamicNodeState::Unavailable(NodeUnavailableReason::AdapterUnavailable)
    }
}

fn backoff_delay(base_seconds: u64, failed_attempt: u32) -> Duration {
    let exponent = failed_attempt.saturating_sub(1).min(31);
    let multiplier = 1_u64 << exponent;
    Duration::from_secs(
        base_seconds
            .clamp(1, MAX_BACKOFF_SECONDS)
            .saturating_mul(multiplier)
            .min(MAX_BACKOFF_SECONDS),
    )
}

fn unix_seconds() -> Result<u64, SubscriptionError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| SubscriptionError::Clock)
}

fn resolve_cache_path(root: &Path, configured: &str) -> Result<PathBuf, SubscriptionError> {
    let path = Path::new(configured);
    if path.as_os_str().is_empty() {
        return Err(SubscriptionError::InvalidCachePath);
    }
    if path.is_absolute() {
        return Ok(path.to_owned());
    }
    if path.components().any(|component| {
        matches!(
            component,
            Component::ParentDir | Component::RootDir | Component::Prefix(_)
        )
    }) {
        return Err(SubscriptionError::InvalidCachePath);
    }
    Ok(root.join(path))
}

async fn atomic_write(path: &Path, contents: &[u8]) -> Result<(), SubscriptionError> {
    use std::io::Write as _;

    let path = path.to_owned();
    let contents = contents.to_vec();
    tokio::task::spawn_blocking(move || {
        let parent = path.parent().ok_or(SubscriptionError::InvalidCachePath)?;
        std::fs::create_dir_all(parent).map_err(|_| SubscriptionError::CacheIo)?;
        #[allow(unused_mut)]
        let mut options = atomic_write_file::OpenOptions::new();
        #[cfg(unix)]
        {
            use atomic_write_file::unix::OpenOptionsExt as _;
            use std::os::unix::fs::OpenOptionsExt as _;
            options.preserve_mode(false).mode(0o600);
        }
        let mut file = options
            .open(&path)
            .map_err(|_| SubscriptionError::CacheIo)?;
        file.write_all(&contents)
            .map_err(|_| SubscriptionError::CacheIo)?;
        file.commit().map_err(|_| SubscriptionError::CacheIo)
    })
    .await
    .map_err(|_| SubscriptionError::CacheIo)?
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicU64, Ordering};

    use pathchord_policy::{SubscriptionCache, SubscriptionRefresh, SubscriptionSource};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    use super::*;

    static TEST_DIRECTORY_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    #[derive(Debug)]
    struct ScriptedFetcher {
        results: Mutex<VecDeque<Result<Vec<u8>, SubscriptionError>>>,
    }

    impl ScriptedFetcher {
        fn new(results: impl IntoIterator<Item = Result<Vec<u8>, SubscriptionError>>) -> Self {
            Self {
                results: Mutex::new(results.into_iter().collect()),
            }
        }
    }

    #[async_trait]
    impl SubscriptionFetcher for ScriptedFetcher {
        async fn fetch(
            &self,
            _request: SubscriptionFetchRequest,
        ) -> Result<Vec<u8>, SubscriptionError> {
            self.results
                .lock()
                .expect("fetch queue")
                .pop_front()
                .expect("scripted fetch result")
        }
    }

    #[derive(Debug, Default)]
    struct RecordingSleeper {
        durations: Mutex<Vec<Duration>>,
    }

    #[async_trait]
    impl RetrySleeper for RecordingSleeper {
        async fn sleep(&self, duration: Duration) {
            self.durations.lock().expect("durations").push(duration);
        }
    }

    fn config(
        source_type: SubscriptionSourceType,
        cache: Option<SubscriptionCache>,
    ) -> SubscriptionConfig {
        SubscriptionConfig {
            id: SubscriptionId::new("provider-a"),
            enabled: true,
            source: SubscriptionSource {
                source_type,
                url: "https://subscription.example.test/nodes".into(),
                credentials_ref: None,
            },
            refresh: SubscriptionRefresh {
                interval_seconds: 3_600,
                timeout_seconds: 1,
                max_attempts: 3,
                backoff_seconds: 5,
            },
            cache,
        }
    }

    fn temp_directory(label: &str) -> PathBuf {
        let sequence = TEST_DIRECTORY_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "pathchord-transit-{label}-{}-{sequence}",
            std::process::id()
        ));
        std::fs::create_dir_all(&path).expect("temporary directory");
        path
    }

    const CLASH: &str = r#"
proxies:
  - name: Tokyo VLESS
    type: vless
    server: jp.example.test
    port: 443
    uuid: 11111111-1111-1111-1111-111111111111
    tags: [gaming]
    weight: 200
  - name: Local SS
    type: ss
    server: 192.0.2.10
    port: 8388
    cipher: aes-256-gcm
    password: secret-value
"#;

    const SIP008: &str = r#"[
      {
        "remarks": "SIP node",
        "server": "198.51.100.10",
        "server_port": 8388,
        "method": "aes-256-gcm",
        "password": "secret-value"
      }
    ]"#;

    #[tokio::test]
    async fn normalizes_clash_nodes_and_keeps_credentials_redacted() {
        let fetcher = Arc::new(ScriptedFetcher::new([Ok(CLASH.as_bytes().to_vec())]));
        let mut manager = SubscriptionManager::new(
            fetcher,
            temp_directory("clash"),
            BTreeSet::from(["vless".into(), "ss".into()]),
        );
        let outcome = manager
            .refresh(&config(SubscriptionSourceType::Clash, None))
            .await;
        assert!(matches!(
            outcome,
            RefreshOutcome::Published { attempts: 1, .. }
        ));
        assert_eq!(manager.snapshot().generation, 1);
        assert_eq!(manager.snapshot().selectable_nodes().count(), 2);
        let ss = manager
            .snapshot()
            .nodes
            .values()
            .find(|node| node.config.protocol == "ss")
            .expect("SS node");
        assert_eq!(ss.credential().field("cipher"), Some("aes-256-gcm"));
        assert_eq!(ss.credential().field("password"), Some("secret-value"));
        let debug = format!("{ss:?}");
        assert!(!debug.contains("secret-value"));
        assert_eq!(
            ss.config.source.as_ref().unwrap().subscription,
            "provider-a"
        );
    }

    #[tokio::test]
    async fn sip008_is_typed_unavailable_without_an_ss_adapter() {
        let fetcher = Arc::new(ScriptedFetcher::new([Ok(SIP008.as_bytes().to_vec())]));
        let mut manager =
            SubscriptionManager::new(fetcher, temp_directory("sip008"), BTreeSet::new());
        let outcome = manager
            .refresh(&config(SubscriptionSourceType::Sip008, None))
            .await;
        let RefreshOutcome::Published { diff, .. } = outcome else {
            panic!("expected publication");
        };
        assert_eq!(diff.unavailable.len(), 1);
        let node = manager.snapshot().nodes.values().next().expect("node");
        assert_eq!(node.config.protocol, "ss");
        assert_eq!(
            node.state,
            DynamicNodeState::Unavailable(NodeUnavailableReason::AdapterUnavailable)
        );
        assert_eq!(manager.snapshot().selectable_nodes().count(), 0);
    }

    #[tokio::test]
    async fn failed_refresh_retains_last_good_snapshot_and_generation() {
        let fetcher = Arc::new(ScriptedFetcher::new([
            Ok(CLASH.as_bytes().to_vec()),
            Err(SubscriptionError::Fetch),
            Err(SubscriptionError::Fetch),
            Err(SubscriptionError::Fetch),
        ]));
        let sleeper = Arc::new(RecordingSleeper::default());
        let mut manager = SubscriptionManager::with_sleeper(
            fetcher,
            sleeper.clone(),
            temp_directory("retain"),
            BTreeSet::from(["vless".into(), "ss".into()]),
        );
        let subscription = config(SubscriptionSourceType::Clash, None);
        assert!(matches!(
            manager.refresh(&subscription).await,
            RefreshOutcome::Published { .. }
        ));
        let before = manager.snapshot().clone();
        let outcome = manager.refresh(&subscription).await;
        assert_eq!(
            outcome,
            RefreshOutcome::Retained {
                generation: 1,
                attempts: 3,
                error: SubscriptionError::Fetch,
            }
        );
        assert_eq!(manager.snapshot(), &before);
        assert_eq!(
            *sleeper.durations.lock().unwrap(),
            [Duration::from_secs(5), Duration::from_secs(10)]
        );
    }

    #[tokio::test]
    async fn cache_is_atomic_private_and_respects_max_age() {
        let directory = temp_directory("cache");
        let cache = SubscriptionCache {
            path: "nested/provider.snapshot".into(),
            max_age_seconds: 86_400,
        };
        let subscription = config(SubscriptionSourceType::Clash, Some(cache.clone()));
        let fetcher = Arc::new(ScriptedFetcher::new([Ok(CLASH.as_bytes().to_vec())]));
        let mut manager = SubscriptionManager::new(
            fetcher,
            &directory,
            BTreeSet::from(["vless".into(), "ss".into()]),
        );
        assert!(matches!(
            manager.refresh(&subscription).await,
            RefreshOutcome::Published { .. }
        ));
        let cache_path = directory.join(&cache.path);
        assert!(cache_path.is_file());
        let entries: Vec<_> = std::fs::read_dir(cache_path.parent().unwrap())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert_eq!(entries, [cache_path.file_name().unwrap()]);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&cache_path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }

        let mut restored = SubscriptionManager::new(
            Arc::new(ScriptedFetcher::new([])),
            &directory,
            BTreeSet::from(["vless".into(), "ss".into()]),
        );
        assert!(matches!(
            restored.load_cache(&subscription).await.unwrap(),
            CacheLoadOutcome::Loaded { .. }
        ));
        assert_eq!(restored.snapshot().selectable_nodes().count(), 2);

        let mut envelope: CacheEnvelope =
            serde_json::from_slice(&std::fs::read(&cache_path).unwrap()).unwrap();
        envelope.published_at_unix_seconds = 1;
        atomic_write(&cache_path, &serde_json::to_vec(&envelope).unwrap())
            .await
            .unwrap();
        let mut expired = SubscriptionManager::new(
            Arc::new(ScriptedFetcher::new([])),
            &directory,
            BTreeSet::new(),
        );
        assert_eq!(
            expired.load_cache(&subscription).await.unwrap(),
            CacheLoadOutcome::Expired
        );
    }

    #[tokio::test]
    async fn oversized_document_is_rejected_without_publication() {
        let fetcher = Arc::new(ScriptedFetcher::new([Ok(vec![
            b'x';
            MAX_SUBSCRIPTION_BYTES + 1
        ])]));
        let mut subscription = config(SubscriptionSourceType::Clash, None);
        subscription.refresh.max_attempts = 1;
        let mut manager =
            SubscriptionManager::new(fetcher, temp_directory("bounds"), BTreeSet::new());
        assert_eq!(
            manager.refresh(&subscription).await,
            RefreshOutcome::Retained {
                generation: 0,
                attempts: 1,
                error: SubscriptionError::ResponseTooLarge {
                    maximum: MAX_SUBSCRIPTION_BYTES,
                },
            }
        );
        assert!(manager.snapshot().nodes.is_empty());
    }

    #[tokio::test]
    async fn disabled_and_deleted_subscriptions_mark_nodes_draining() {
        let fetcher = Arc::new(ScriptedFetcher::new([Ok(CLASH.as_bytes().to_vec())]));
        let mut manager = SubscriptionManager::new(
            fetcher,
            temp_directory("drain"),
            BTreeSet::from(["vless".into(), "ss".into()]),
        );
        let subscription = config(SubscriptionSourceType::Clash, None);
        manager.refresh(&subscription).await;
        let first_id = manager.snapshot().nodes.keys().next().unwrap().clone();
        let mut ready_catalog = RuntimeCatalog::default();
        manager
            .snapshot()
            .extend_runtime_catalog(&mut ready_catalog);
        assert!(
            ready_catalog
                .transit_proxy(&first_id)
                .is_some_and(|status| status.state == RuntimeNodeState::Ready)
        );
        let diff = manager.reconcile(&[]);
        assert_eq!(diff.draining.len(), 2);
        assert!(
            manager
                .snapshot()
                .nodes
                .values()
                .all(|node| node.state == DynamicNodeState::Draining)
        );
        let mut draining_catalog = RuntimeCatalog::default();
        manager
            .snapshot()
            .extend_runtime_catalog(&mut draining_catalog);
        assert!(
            draining_catalog
                .transit_proxy(&first_id)
                .is_some_and(|status| status.state == RuntimeNodeState::Draining)
        );
        let completed = manager.snapshot().nodes.keys().cloned().collect();
        let removed = manager.complete_draining(&completed);
        assert_eq!(removed.removed.len(), 2);
        assert!(manager.snapshot().nodes.is_empty());
    }

    #[tokio::test]
    async fn production_http_fetcher_enforces_declared_length_bound() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0_u8; 1024];
            let _ = stream.read(&mut request).await.unwrap();
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 1024\r\n\r\n")
                .await
                .unwrap();
        });
        let fetcher = HttpSubscriptionFetcher::new().unwrap();
        let result = fetcher
            .fetch(SubscriptionFetchRequest {
                url: format!("http://{address}/nodes"),
                credentials_ref: None,
                timeout: Duration::from_secs(1),
                max_bytes: 16,
            })
            .await;
        assert_eq!(
            result,
            Err(SubscriptionError::ResponseTooLarge { maximum: 16 })
        );
        server.await.unwrap();
    }
}
