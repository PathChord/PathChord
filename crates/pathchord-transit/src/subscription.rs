use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use pathchord_policy::{
    DEFAULT_SUBSCRIPTION_USER_AGENT, Endpoint, FlowProtocol, RuntimeCatalog, RuntimeNodeState,
    SubscriptionConfig, SubscriptionId, SubscriptionSourceType, TransitProxyConfig, TransitProxyId,
    TransitProxyRuntimeStatus, TransitSource,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::Zeroize;

#[path = "subscription_import.rs"]
mod import;
#[path = "subscription_providers.rs"]
mod providers;
#[path = "subscription_usage.rs"]
mod usage;
pub use usage::{SubscriptionDocument, SubscriptionUsage};

pub const MAX_SUBSCRIPTION_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_SUBSCRIPTION_NODES: usize = 10_000;
const MAX_CACHE_BYTES: u64 = 16 * 1024 * 1024;
const CACHE_ENVELOPE_VERSION: u8 = 3;
const CACHE_INCOMPATIBLE_CODE: &str = "cache_incompatible";
const MAX_BACKOFF_SECONDS: u64 = 3_600;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubscriptionFetchRequest {
    pub url: String,
    pub credentials_ref: Option<String>,
    pub user_agent: Option<String>,
    pub timeout: Duration,
    pub max_bytes: usize,
}

/// One body-byte allowance shared by root fetches, providers, and retries.
/// Charges survive cancellation and failed or malformed HTTP responses.
#[derive(Debug)]
pub struct SubscriptionDownloadBudget {
    maximum: usize,
    remaining: AtomicUsize,
}

impl SubscriptionDownloadBudget {
    #[must_use]
    pub fn new(maximum: usize) -> Self {
        Self {
            maximum,
            remaining: AtomicUsize::new(maximum),
        }
    }

    #[must_use]
    pub fn remaining(&self) -> usize {
        self.remaining.load(Ordering::Relaxed)
    }

    /// Charges bytes as they are consumed, exhausting the allowance on overflow.
    pub fn charge(&self, bytes: usize) -> Result<(), SubscriptionError> {
        let previous = self
            .remaining
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |remaining| {
                Some(remaining.saturating_sub(bytes))
            })
            .unwrap_or_default();
        if bytes > previous {
            return Err(self.exhausted());
        }
        Ok(())
    }

    fn exhausted(&self) -> SubscriptionError {
        SubscriptionError::ResponseTooLarge {
            maximum: self.maximum,
        }
    }

    fn refund(&self, bytes: usize) {
        self.remaining.fetch_add(bytes, Ordering::Relaxed);
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum SubscriptionError {
    #[error("subscription source format is not refreshable")]
    StaticSource,
    #[error("subscription URL is invalid or contains credentials")]
    InvalidUrl,
    #[error("subscription credential is unavailable")]
    MissingCredential,
    #[error("subscription User-Agent is invalid")]
    InvalidUserAgent,
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
    #[error("subscription refresh candidate is no longer current")]
    StaleCandidate,
    #[error("subscription control commit failed")]
    ControlCommit,
    #[error("subscription node identity conflicts with another source")]
    NodeIdentityConflict,
    #[error("system clock is before the Unix epoch")]
    Clock,
}

#[async_trait]
pub trait SubscriptionFetcher: Send + Sync {
    async fn fetch(&self, request: SubscriptionFetchRequest) -> Result<Vec<u8>, SubscriptionError>;

    async fn fetch_document(
        &self,
        request: SubscriptionFetchRequest,
    ) -> Result<SubscriptionDocument, SubscriptionError> {
        self.fetch(request)
            .await
            .map(|body| SubscriptionDocument { body, usage: None })
    }

    /// Streaming fetchers override this method and charge each consumed chunk.
    /// Legacy implementations reserve their whole request allowance before I/O;
    /// an unknown partial failure or cancellation cannot release that allowance.
    async fn fetch_document_with_budget(
        &self,
        mut request: SubscriptionFetchRequest,
        budget: &SubscriptionDownloadBudget,
    ) -> Result<SubscriptionDocument, SubscriptionError> {
        let reserved = request.max_bytes.min(budget.remaining());
        if reserved == 0 {
            return Err(budget.exhausted());
        }
        budget.charge(reserved)?;
        request.max_bytes = reserved;
        let document = self.fetch_document(request).await?;
        if document.body.len() > reserved {
            return Err(budget.exhausted());
        }
        budget.refund(reserved - document.body.len());
        Ok(document)
    }
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
            .user_agent(DEFAULT_SUBSCRIPTION_USER_AGENT)
            .build()
            .map_err(|_| SubscriptionError::Fetch)?;
        Ok(Self {
            client,
            credentials,
        })
    }
}

impl HttpSubscriptionFetcher {
    async fn request_document(
        &self,
        request: SubscriptionFetchRequest,
        budget: Option<&SubscriptionDownloadBudget>,
    ) -> Result<SubscriptionDocument, SubscriptionError> {
        let parsed =
            reqwest::Url::parse(&request.url).map_err(|_| SubscriptionError::InvalidUrl)?;
        if !matches!(parsed.scheme(), "http" | "https")
            || !parsed.username().is_empty()
            || parsed.password().is_some()
        {
            return Err(SubscriptionError::InvalidUrl);
        }

        let mut builder = self.client.get(parsed).timeout(request.timeout);
        if let Some(user_agent) = &request.user_agent {
            if !pathchord_policy::valid_subscription_user_agent(user_agent) {
                return Err(SubscriptionError::InvalidUserAgent);
            }
            let value = reqwest::header::HeaderValue::from_str(user_agent)
                .map_err(|_| SubscriptionError::InvalidUserAgent)?;
            builder = builder.header(reqwest::header::USER_AGENT, value);
        }
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

        let usage = usage::parse_usage(response.headers());
        let mut body = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| SubscriptionError::Fetch)?
        {
            if let Some(budget) = budget {
                budget.charge(chunk.len())?;
            }
            if body.len().saturating_add(chunk.len()) > request.max_bytes {
                return Err(SubscriptionError::ResponseTooLarge {
                    maximum: request.max_bytes,
                });
            }
            body.extend_from_slice(&chunk);
        }
        Ok(SubscriptionDocument { body, usage })
    }
}

#[async_trait]
impl SubscriptionFetcher for HttpSubscriptionFetcher {
    async fn fetch(&self, request: SubscriptionFetchRequest) -> Result<Vec<u8>, SubscriptionError> {
        self.request_document(request, None)
            .await
            .map(|document| document.body)
    }
    async fn fetch_document(
        &self,
        request: SubscriptionFetchRequest,
    ) -> Result<SubscriptionDocument, SubscriptionError> {
        self.request_document(request, None).await
    }

    async fn fetch_document_with_budget(
        &self,
        request: SubscriptionFetchRequest,
        budget: &SubscriptionDownloadBudget,
    ) -> Result<SubscriptionDocument, SubscriptionError> {
        if budget.remaining() == 0 {
            return Err(budget.exhausted());
        }
        self.request_document(request, Some(budget)).await
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

impl Drop for SubscriptionCredential {
    fn drop(&mut self) {
        for value in self.fields.values_mut() {
            value.zeroize();
        }
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
    InvalidNode,
    UnsupportedProtocol,
    UnsupportedParameters,
}

/// Sanitized import diagnostics. Field names are bounded; values and parse
/// error text from secret-bearing source documents never enter this model.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeDiagnostic {
    pub code: NodeUnavailableReason,
    pub fields: Vec<String>,
    pub message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DynamicNodeState {
    /// Imported or restored configuration awaiting adapter preparation.
    Pending,
    Active,
    Draining,
    Unavailable(NodeUnavailableReason),
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DynamicTransitNode {
    pub config: TransitProxyConfig,
    pub source_subscription: SubscriptionId,
    pub state: DynamicNodeState,
    #[serde(default)]
    pub diagnostic: Option<NodeDiagnostic>,
    #[serde(default)]
    pub usage: Option<SubscriptionUsage>,
    #[serde(default)]
    source_fingerprint: String,
    credential: SubscriptionCredential,
}

impl fmt::Debug for DynamicTransitNode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DynamicTransitNode")
            .field("config", &self.config)
            .field("source_subscription", &self.source_subscription)
            .field("state", &self.state)
            .field("diagnostic", &self.diagnostic)
            .field("usage", &self.usage)
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

/// Shared revocation fence for one validated adapter admission.
#[derive(Clone, Debug)]
pub struct AdmissionRevocation(Arc<AtomicBool>);

impl AdmissionRevocation {
    #[must_use]
    pub fn is_valid(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
    pub fn revoke(&self) {
        self.0.store(false, Ordering::Release);
    }
    #[must_use]
    pub fn same(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

/// An adapter and its immutable validated node identity share one revocation fence.
#[derive(Clone)]
pub struct ValidatedTransitAdapter {
    config: TransitProxyConfig,
    source_fingerprint: String,
    credential: SubscriptionCredential,
    adapter: Arc<dyn crate::TransitAdapter>,
    revocation: AdmissionRevocation,
}

impl fmt::Debug for ValidatedTransitAdapter {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ValidatedTransitAdapter")
            .finish_non_exhaustive()
    }
}

impl ValidatedTransitAdapter {
    #[must_use]
    pub fn matches_config(&self, config: &TransitProxyConfig) -> bool {
        self.revocation.is_valid() && &self.config == config
    }
    #[must_use]
    pub fn adapter(&self) -> Arc<dyn crate::TransitAdapter> {
        Arc::clone(&self.adapter)
    }
    #[must_use]
    pub fn revocation(&self) -> AdmissionRevocation {
        self.revocation.clone()
    }
    #[must_use]
    pub fn same_connection(&self, other: &Self) -> bool {
        self.config == other.config
            && self.source_fingerprint == other.source_fingerprint
            && self.credential == other.credential
    }
}

#[derive(Clone)]
struct AdmittedNode {
    original: DynamicTransitNode,
    adapter: Arc<dyn crate::TransitAdapter>,
    capabilities: BTreeSet<FlowProtocol>,
    valid: AdmissionRevocation,
}

impl fmt::Debug for AdmittedNode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AdmittedNode")
            .field("capabilities", &self.capabilities)
            .finish_non_exhaustive()
    }
}

impl PartialEq for AdmittedNode {
    fn eq(&self, other: &Self) -> bool {
        self.original == other.original
            && self.capabilities == other.capabilities
            && Arc::ptr_eq(&self.adapter, &other.adapter)
            && self.valid.same(&other.valid)
    }
}
impl Eq for AdmittedNode {}

impl AdmittedNode {
    fn matches(&self, node: &DynamicTransitNode) -> bool {
        self.valid.is_valid()
            && node.state == DynamicNodeState::Active
            && node.diagnostic.is_none()
            && node.config == self.original.config
            && node.source_subscription == self.original.source_subscription
            && node.source_fingerprint == self.original.source_fingerprint
            && node.credential == self.original.credential
    }

    fn revoke(&self) {
        self.valid.revoke();
    }
}

/// Opaque adapter preparation bound to one subscription snapshot.
type PreparedAdapterResult = (
    DynamicTransitNode,
    Result<Arc<dyn crate::TransitAdapter>, ()>,
);

pub struct PreparedDynamicSnapshot {
    generation: u64,
    nodes: Vec<PreparedAdapterResult>,
}

impl fmt::Debug for PreparedDynamicSnapshot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedDynamicSnapshot")
            .field("generation", &self.generation)
            .field("node_count", &self.nodes.len())
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DynamicTransitSnapshot {
    pub generation: u64,
    pub nodes: BTreeMap<TransitProxyId, DynamicTransitNode>,
    admissions: BTreeMap<TransitProxyId, AdmittedNode>,
}

impl DynamicTransitSnapshot {
    #[cfg(test)]
    fn candidate_nodes(&self) -> impl Iterator<Item = &DynamicTransitNode> {
        self.nodes.values().filter(|node| {
            matches!(
                node.state,
                DynamicNodeState::Pending | DynamicNodeState::Active
            )
        })
    }
    pub fn selectable_nodes(&self) -> impl Iterator<Item = &DynamicTransitNode> {
        self.nodes.iter().filter_map(|(id, node)| {
            self.admissions
                .get(id)
                .filter(|admission| admission.matches(node))
                .map(|_| node)
        })
    }

    /// Returns the exact prepared adapter only while its source and node are current.
    pub fn validated_adapter(&self, id: &TransitProxyId) -> Option<Arc<dyn crate::TransitAdapter>> {
        let node = self.nodes.get(id)?;
        let admission = self
            .admissions
            .get(id)
            .filter(|admission| admission.matches(node))?;
        Some(Arc::clone(&admission.adapter))
    }

    pub fn validated_admission(&self, id: &TransitProxyId) -> Option<ValidatedTransitAdapter> {
        let node = self.nodes.get(id)?;
        let admission = self
            .admissions
            .get(id)
            .filter(|admission| admission.matches(node))?;
        Some(ValidatedTransitAdapter {
            config: node.config.clone(),
            source_fingerprint: node.source_fingerprint.clone(),
            credential: node.credential.clone(),
            adapter: Arc::clone(&admission.adapter),
            revocation: admission.valid.clone(),
        })
    }

    /// Prepare pending candidates without mutating the live snapshot.
    pub async fn prepare_adapters<P>(
        &self,
        registry: &crate::AdapterRegistry<P>,
    ) -> PreparedDynamicSnapshot
    where
        P: crate::TransitCredentialProvider + 'static,
    {
        self.prepare_source_adapters(registry, None).await
    }

    /// Prepare pending candidates from one source, or every source if absent.
    pub async fn prepare_source_adapters<P>(
        &self,
        registry: &crate::AdapterRegistry<P>,
        source: Option<&SubscriptionId>,
    ) -> PreparedDynamicSnapshot
    where
        P: crate::TransitCredentialProvider + 'static,
    {
        use futures_util::{StreamExt, stream};
        let nodes = stream::iter(
            self.nodes
                .values()
                .filter(|node| {
                    node.state == DynamicNodeState::Pending
                        && source.is_none_or(|source| &node.source_subscription == source)
                })
                .cloned(),
        )
        .map(|node| async move {
            let result = registry.prepare_dynamic(&node).await.map_err(|_| ());
            (node, result)
        })
        .buffer_unordered(16)
        .collect()
        .await;
        PreparedDynamicSnapshot {
            generation: self.generation,
            nodes,
        }
    }

    /// Adds the current dynamic node configuration and admission state to an
    /// evaluation catalog without recompiling the immutable rule snapshot.
    pub fn extend_runtime_catalog(&self, catalog: &mut RuntimeCatalog) {
        for node in self.nodes.values() {
            let state = match node.state {
                DynamicNodeState::Active
                    if self
                        .admissions
                        .get(&node.config.id)
                        .is_some_and(|admission| admission.matches(node)) =>
                {
                    RuntimeNodeState::Ready
                }
                DynamicNodeState::Pending | DynamicNodeState::Active => RuntimeNodeState::Down,
                DynamicNodeState::Draining => RuntimeNodeState::Draining,
                DynamicNodeState::Unavailable(_) => RuntimeNodeState::Down,
            };
            let capabilities = self
                .admissions
                .get(&node.config.id)
                .filter(|admission| admission.matches(node))
                .map_or_else(BTreeSet::new, |admission| admission.capabilities.clone());
            catalog.set_dynamic_transit_proxy(
                node.config.clone(),
                TransitProxyRuntimeStatus {
                    state,
                    capabilities,
                    labels: BTreeMap::new(),
                    tags: BTreeSet::new(),
                    selection_score: 1,
                    quota_remaining: node
                        .usage
                        .as_ref()
                        .and_then(SubscriptionUsage::remaining_bytes),
                    traffic_multiplier_basis_points: node
                        .usage
                        .as_ref()
                        .and_then(|usage| usage.traffic_multiplier_basis_points),
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
    Incompatible { code: &'static str },
    NotConfigured,
    Missing,
    Expired,
    SourceMismatch,
    UnverifiedSource,
    Disabled { diff: SnapshotDiff },
}

/// Private staged candidate. Dropping it discards the temporary cache file.
pub struct PreparedSubscriptionRefresh {
    config: SubscriptionConfig,
    source_fingerprint: String,
    captured_control_generation: u64,
    attempts: u32,
    nodes: Vec<NormalizedNode>,
    staged_cache: Option<atomic_write_file::AtomicWriteFile>,
}

impl fmt::Debug for PreparedSubscriptionRefresh {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedSubscriptionRefresh")
            .field("subscription_id", &self.config.id)
            .field(
                "captured_control_generation",
                &self.captured_control_generation,
            )
            .field("attempts", &self.attempts)
            .field("nodes", &self.nodes.len())
            .finish_non_exhaustive()
    }
}

impl PreparedSubscriptionRefresh {
    /// Existing node IDs whose effective adapter identity changes or disappears.
    #[must_use]
    pub fn invalidated_adapters(&self, snapshot: &DynamicTransitSnapshot) -> Vec<TransitProxyId> {
        let next: BTreeMap<_, _> = self
            .nodes
            .iter()
            .map(|node| (&node.config.id, node))
            .collect();
        snapshot
            .nodes
            .iter()
            .filter_map(|(id, previous)| {
                if previous.source_subscription != self.config.id {
                    return None;
                }
                let unchanged = next.get(id).is_some_and(|candidate| {
                    matches!(
                        candidate.state,
                        DynamicNodeState::Active | DynamicNodeState::Pending
                    ) && candidate.diagnostic.is_none()
                        && candidate.config == previous.config
                        && candidate.credential == previous.credential
                        && previous.source_fingerprint == self.source_fingerprint
                });
                (!unchanged).then(|| id.clone())
            })
            .collect()
    }
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
    current_sources: BTreeMap<SubscriptionId, String>,
    pending_nodes: BTreeMap<SubscriptionId, PendingSubscriptionNodes>,
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
            current_sources: BTreeMap::new(),
            pending_nodes: BTreeMap::new(),
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
            current_sources: BTreeMap::new(),
            pending_nodes: BTreeMap::new(),
        }
    }

    #[must_use]
    pub fn snapshot(&self) -> &DynamicTransitSnapshot {
        &self.snapshot
    }

    /// Publish adapter preparation only if the complete captured snapshot and
    /// its subscription sources are still current.
    pub fn commit_prepared_adapters(
        &mut self,
        prepared: PreparedDynamicSnapshot,
    ) -> Result<(), SubscriptionError> {
        if self.snapshot.generation != prepared.generation {
            return Err(SubscriptionError::StaleCandidate);
        }
        for (candidate, _) in &prepared.nodes {
            if self.snapshot.nodes.get(&candidate.config.id) != Some(candidate)
                || self.current_sources.get(&candidate.source_subscription)
                    != Some(&candidate.source_fingerprint)
            {
                return Err(SubscriptionError::StaleCandidate);
            }
        }
        let changed = !prepared.nodes.is_empty();
        for (candidate, result) in prepared.nodes {
            let id = candidate.config.id.clone();
            let node = self
                .snapshot
                .nodes
                .get_mut(&id)
                .expect("candidate was checked");
            match result {
                Ok(adapter) => {
                    let mut capabilities = BTreeSet::new();
                    if adapter.supports_tcp() {
                        capabilities.insert(FlowProtocol::Tcp);
                    }
                    if adapter.supports_udp() && candidate.config.options.udp != Some(false) {
                        capabilities.insert(FlowProtocol::Udp);
                    }
                    node.state = DynamicNodeState::Active;
                    self.snapshot.admissions.insert(
                        id,
                        AdmittedNode {
                            original: candidate,
                            adapter,
                            capabilities,
                            valid: AdmissionRevocation(Arc::new(AtomicBool::new(true))),
                        },
                    );
                }
                Err(()) => {
                    node.state =
                        DynamicNodeState::Unavailable(NodeUnavailableReason::AdapterUnavailable);
                    node.diagnostic = Some(adapter_diagnostic());
                }
            }
        }
        if changed {
            self.snapshot.generation = self.snapshot.generation.saturating_add(1);
        }
        Ok(())
    }

    /// Revoke an admission that the data plane could not install.
    pub fn reject_admitted_adapter(&mut self, id: &TransitProxyId) {
        self.revoke_admission(id);
        if let Some(node) = self.snapshot.nodes.get_mut(id) {
            node.state = DynamicNodeState::Unavailable(NodeUnavailableReason::AdapterUnavailable);
            node.diagnostic = Some(adapter_diagnostic());
            self.snapshot.generation = self.snapshot.generation.saturating_add(1);
        }
    }

    /// Fence the old adapters while a source refresh is being committed.
    pub fn suspend_source_admissions(&mut self, source: &SubscriptionId) {
        let mut suspended = Vec::new();
        for (id, node) in &mut self.snapshot.nodes {
            if &node.source_subscription == source && node.state == DynamicNodeState::Active {
                node.state = DynamicNodeState::Pending;
                suspended.push(id.clone());
            }
        }
        for id in &suspended {
            self.revoke_admission(id);
        }
        if !suspended.is_empty() {
            self.snapshot.generation = self.snapshot.generation.saturating_add(1);
        }
    }

    fn revoke_admission(&mut self, id: &TransitProxyId) {
        if let Some(admission) = self.snapshot.admissions.remove(id) {
            admission.revoke();
        }
    }

    pub async fn refresh(&mut self, config: &SubscriptionConfig) -> RefreshOutcome {
        if config
            .source
            .user_agent
            .as_deref()
            .is_some_and(|value| !pathchord_policy::valid_subscription_user_agent(value))
        {
            return RefreshOutcome::Retained {
                generation: self.snapshot.generation,
                attempts: 0,
                error: SubscriptionError::InvalidUserAgent,
            };
        }
        if !config.enabled {
            return RefreshOutcome::Disabled {
                diff: self.disable(&config.id),
            };
        }
        let fingerprint = subscription_source_fingerprint(config);
        self.set_current_source(&config.id, &fingerprint);
        match self.prepare_refresh(config, 0).await {
            Ok(prepared) => self.commit_prepared_refresh(prepared, 0).await,
            Err(outcome) => outcome,
        }
    }

    /// Fetch and validate a candidate without publishing it or replacing the
    /// live cache. The caller must fence the captured control generation.
    #[allow(clippy::result_large_err)]
    pub async fn prepare_refresh(
        &self,
        config: &SubscriptionConfig,
        captured_control_generation: u64,
    ) -> Result<PreparedSubscriptionRefresh, RefreshOutcome> {
        if config
            .source
            .user_agent
            .as_deref()
            .is_some_and(|value| !pathchord_policy::valid_subscription_user_agent(value))
        {
            return Err(RefreshOutcome::Retained {
                generation: self.snapshot.generation,
                attempts: 0,
                error: SubscriptionError::InvalidUserAgent,
            });
        }
        if !config.enabled || config.source.source_type == SubscriptionSourceType::Static {
            return Err(RefreshOutcome::Retained {
                generation: self.snapshot.generation,
                attempts: 0,
                error: SubscriptionError::StaticSource,
            });
        }
        let source_fingerprint = subscription_source_fingerprint(config);
        let attempts = config.refresh.max_attempts.clamp(1, 10);
        let mut last_error = SubscriptionError::Fetch;
        let budget = SubscriptionDownloadBudget::new(MAX_SUBSCRIPTION_BYTES);
        let mut attempted = 0;
        for attempt in 1..=attempts {
            if budget.remaining() == 0 {
                break;
            }
            attempted = attempt;
            let request = SubscriptionFetchRequest {
                url: config.source.url.clone(),
                credentials_ref: config.source.credentials_ref.clone(),
                user_agent: config.source.user_agent.clone(),
                timeout: Duration::from_secs(config.refresh.timeout_seconds.clamp(1, 300)),
                max_bytes: budget.remaining(),
            };
            let fetched = tokio::time::timeout(
                request.timeout,
                self.fetcher.fetch_document_with_budget(request, &budget),
            )
            .await;
            let candidate = match fetched {
                Ok(Ok(document)) => {
                    providers::normalize_fetched(self, config, document, &budget).await
                }
                Ok(Err(error)) => Err(error),
                Err(_) => Err(SubscriptionError::Timeout),
            };
            match candidate {
                Ok(nodes) => {
                    if let Err(error) = self.validate_candidate(&config.id, &nodes) {
                        return Err(RefreshOutcome::Retained {
                            generation: self.snapshot.generation,
                            attempts: attempt,
                            error,
                        });
                    }
                    let staged_cache = match self.prepare_cache(config, &nodes).await {
                        Ok(cache) => cache,
                        Err(error) => {
                            return Err(RefreshOutcome::Retained {
                                generation: self.snapshot.generation,
                                attempts: attempt,
                                error,
                            });
                        }
                    };
                    return Ok(PreparedSubscriptionRefresh {
                        config: config.clone(),
                        source_fingerprint,
                        captured_control_generation,
                        attempts: attempt,
                        nodes,
                        staged_cache,
                    });
                }
                Err(error) => last_error = error,
            }
            if attempt < attempts && budget.remaining() > 0 {
                self.sleeper
                    .sleep(backoff_delay(config.refresh.backoff_seconds, attempt))
                    .await;
            }
        }
        Err(RefreshOutcome::Retained {
            generation: self.snapshot.generation,
            attempts: attempted,
            error: last_error,
        })
    }

    pub async fn commit_prepared_refresh(
        &mut self,
        prepared: PreparedSubscriptionRefresh,
        current_control_generation: u64,
    ) -> RefreshOutcome {
        self.commit_prepared_refresh_with(prepared, current_control_generation, || Ok(()))
            .await
    }

    /// The caller holds its control lock across this call. `commit_control`
    /// durably records success after validation, before cache replacement.
    pub async fn commit_prepared_refresh_with<F>(
        &mut self,
        prepared: PreparedSubscriptionRefresh,
        current_control_generation: u64,
        commit_control: F,
    ) -> RefreshOutcome
    where
        F: FnOnce() -> Result<(), SubscriptionError>,
    {
        let PreparedSubscriptionRefresh {
            config,
            source_fingerprint,
            captured_control_generation,
            attempts,
            nodes,
            staged_cache,
        } = prepared;
        if captured_control_generation != current_control_generation
            || self.current_sources.get(&config.id) != Some(&source_fingerprint)
        {
            return RefreshOutcome::Retained {
                generation: self.snapshot.generation,
                attempts,
                error: SubscriptionError::StaleCandidate,
            };
        }
        if let Err(error) = self.validate_candidate(&config.id, &nodes) {
            return RefreshOutcome::Retained {
                generation: self.snapshot.generation,
                attempts,
                error,
            };
        }
        if let Err(error) = commit_control() {
            return RefreshOutcome::Retained {
                generation: self.snapshot.generation,
                attempts,
                error,
            };
        }
        if let Some(cache) = staged_cache {
            let result = tokio::task::spawn_blocking(move || cache.commit()).await;
            if !matches!(result, Ok(Ok(()))) {
                return RefreshOutcome::Retained {
                    generation: self.snapshot.generation,
                    attempts,
                    error: SubscriptionError::CacheIo,
                };
            }
        }
        match self.publish(&config.id, &source_fingerprint, nodes) {
            Ok(diff) => RefreshOutcome::Published { attempts, diff },
            Err(error) => RefreshOutcome::Retained {
                generation: self.snapshot.generation,
                attempts,
                error,
            },
        }
    }

    pub async fn load_cache(
        &mut self,
        config: &SubscriptionConfig,
    ) -> Result<CacheLoadOutcome, SubscriptionError> {
        if config
            .source
            .user_agent
            .as_deref()
            .is_some_and(|value| !pathchord_policy::valid_subscription_user_agent(value))
        {
            return Err(SubscriptionError::InvalidUserAgent);
        }
        if !config.enabled {
            return Ok(CacheLoadOutcome::Disabled {
                diff: self.disable(&config.id),
            });
        }
        let source_fingerprint = subscription_source_fingerprint(config);
        self.set_current_source(&config.id, &source_fingerprint);
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
        let envelope: serde_json::Value =
            serde_json::from_slice(&encoded).map_err(|_| SubscriptionError::InvalidCache)?;
        let version = envelope
            .get("version")
            .and_then(serde_json::Value::as_u64)
            .ok_or(SubscriptionError::InvalidCache)?;
        let subscription_id = envelope
            .get("subscription_id")
            .and_then(serde_json::Value::as_str)
            .ok_or(SubscriptionError::InvalidCache)?;
        if subscription_id != config.id.as_str() {
            return Err(SubscriptionError::InvalidCache);
        }
        if version == 1 {
            return Ok(CacheLoadOutcome::UnverifiedSource);
        }
        if version != u64::from(CACHE_ENVELOPE_VERSION)
            || has_retired_native_option_fields(&envelope)
        {
            return Ok(CacheLoadOutcome::Incompatible {
                code: CACHE_INCOMPATIBLE_CODE,
            });
        }
        let cached: CacheEnvelope =
            serde_json::from_value(envelope).map_err(|_| SubscriptionError::InvalidCache)?;
        match cached.source_fingerprint.as_deref() {
            None => return Ok(CacheLoadOutcome::UnverifiedSource),
            Some(fingerprint) if fingerprint != source_fingerprint => {
                return Ok(CacheLoadOutcome::SourceMismatch);
            }
            Some(_) => {}
        }
        let now = unix_seconds()?;
        if now.saturating_sub(cached.published_at_unix_seconds) > cache.max_age_seconds {
            return Ok(CacheLoadOutcome::Expired);
        }
        if cached.nodes.len() > MAX_SUBSCRIPTION_NODES {
            return Err(SubscriptionError::InvalidCache);
        }
        for node in &cached.nodes {
            if node.source_subscription != config.id
                || node.config.id.namespace() != config.id.namespace()
                || node
                    .config
                    .source
                    .as_ref()
                    .is_none_or(|source| source.subscription != config.id.as_str())
                || node.protocol != node.config.protocol
            {
                return Err(SubscriptionError::InvalidCache);
            }
        }
        let nodes = cached
            .nodes
            .into_iter()
            .map(|node| {
                let state = node.diagnostic.as_ref().map_or_else(
                    || {
                        if node.credential.field("sing_box_outbound").is_some() {
                            DynamicNodeState::Unavailable(NodeUnavailableReason::AdapterUnavailable)
                        } else {
                            adapter_state(&node.protocol, &self.available_adapters)
                        }
                    },
                    |diagnostic| DynamicNodeState::Unavailable(diagnostic.code),
                );
                NormalizedNode {
                    config: node.config,
                    credential: node.credential,
                    state,
                    diagnostic: node.diagnostic,
                    usage: node.usage,
                }
            })
            .collect();
        let diff = self.publish(&config.id, &source_fingerprint, nodes)?;
        Ok(CacheLoadOutcome::Loaded { diff })
    }

    pub fn reconcile(&mut self, configured: &[SubscriptionConfig]) -> SnapshotDiff {
        let enabled: BTreeMap<_, _> = configured
            .iter()
            .filter(|config| config.enabled)
            .map(|config| (config.id.clone(), subscription_source_fingerprint(config)))
            .collect();
        self.pending_nodes
            .retain(|id, pending| enabled.get(id) == Some(&pending.source_fingerprint));
        let mut draining = Vec::new();
        for (id, node) in &mut self.snapshot.nodes {
            if enabled.get(&node.source_subscription) != Some(&node.source_fingerprint)
                && node.state != DynamicNodeState::Draining
            {
                node.state = DynamicNodeState::Draining;
                draining.push(id.clone());
            }
        }
        for id in &draining {
            self.revoke_admission(id);
        }
        self.current_sources = enabled;
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
        let removed_ids: BTreeSet<_> = removed.iter().cloned().collect();
        for id in &removed {
            self.revoke_admission(id);
        }
        let mut promoted = Vec::new();
        for (subscription_id, pending) in &mut self.pending_nodes {
            if self.current_sources.get(subscription_id) != Some(&pending.source_fingerprint) {
                continue;
            }
            for id in &removed_ids {
                if let Some(node) = pending.nodes.remove(id) {
                    promoted.push((
                        subscription_id.clone(),
                        pending.source_fingerprint.clone(),
                        id.clone(),
                        node,
                    ));
                }
            }
        }
        self.pending_nodes
            .retain(|_, pending| !pending.nodes.is_empty());
        let mut added = Vec::new();
        let mut unavailable = Vec::new();
        for (subscription_id, source_fingerprint, id, normalized) in promoted {
            if matches!(normalized.state, DynamicNodeState::Unavailable(_)) {
                unavailable.push(id.clone());
            }
            self.snapshot.nodes.insert(
                id.clone(),
                DynamicTransitNode {
                    config: normalized.config,
                    source_subscription: subscription_id,
                    state: pending_state(normalized.state),
                    diagnostic: normalized.diagnostic,
                    usage: normalized.usage,
                    source_fingerprint,
                    credential: normalized.credential,
                },
            );
            added.push(id);
        }
        if !removed.is_empty() || !added.is_empty() {
            self.snapshot.generation = self.snapshot.generation.saturating_add(1);
        }
        SnapshotDiff {
            generation: self.snapshot.generation,
            removed,
            added,
            unavailable,
            ..SnapshotDiff::default()
        }
    }

    fn set_current_source(&mut self, id: &SubscriptionId, fingerprint: &str) {
        self.current_sources
            .insert(id.clone(), fingerprint.to_owned());
        if self
            .pending_nodes
            .get(id)
            .is_some_and(|pending| pending.source_fingerprint != fingerprint)
        {
            self.pending_nodes.remove(id);
        }
        let mut draining = Vec::new();
        for (node_id, node) in &mut self.snapshot.nodes {
            if &node.source_subscription == id
                && node.source_fingerprint != fingerprint
                && node.state != DynamicNodeState::Draining
            {
                node.state = DynamicNodeState::Draining;
                draining.push(node_id.clone());
            }
        }
        for node_id in &draining {
            self.revoke_admission(node_id);
        }
        if !draining.is_empty() {
            self.snapshot.generation = self.snapshot.generation.saturating_add(1);
        }
    }

    fn disable(&mut self, id: &SubscriptionId) -> SnapshotDiff {
        self.current_sources.remove(id);
        self.pending_nodes.remove(id);
        let mut draining = Vec::new();
        for (node_id, node) in &mut self.snapshot.nodes {
            if &node.source_subscription == id && node.state != DynamicNodeState::Draining {
                node.state = DynamicNodeState::Draining;
                draining.push(node_id.clone());
            }
        }
        for node_id in &draining {
            self.revoke_admission(node_id);
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

    fn validate_candidate(
        &self,
        subscription_id: &SubscriptionId,
        nodes: &[NormalizedNode],
    ) -> Result<(), SubscriptionError> {
        let mut candidate_ids = BTreeSet::new();
        for node in nodes {
            if node.config.id.namespace() != subscription_id.namespace()
                || node
                    .config
                    .source
                    .as_ref()
                    .is_none_or(|source| source.subscription != subscription_id.as_str())
                || !candidate_ids.insert(node.config.id.clone())
            {
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
        Ok(())
    }

    fn publish(
        &mut self,
        subscription_id: &SubscriptionId,
        source_fingerprint: &str,
        nodes: Vec<NormalizedNode>,
    ) -> Result<SnapshotDiff, SubscriptionError> {
        self.validate_candidate(subscription_id, &nodes)?;
        let candidate_ids: BTreeSet<_> = nodes.iter().map(|node| node.config.id.clone()).collect();

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
        for id in &diff.draining {
            self.revoke_admission(id);
        }
        let mut deferred = BTreeMap::new();
        for normalized in nodes {
            let id = normalized.config.id.clone();
            if self
                .snapshot
                .nodes
                .get(&id)
                .is_some_and(|existing| existing.state == DynamicNodeState::Draining)
            {
                deferred.insert(id, normalized);
                continue;
            }
            let mut node = DynamicTransitNode {
                config: normalized.config,
                source_subscription: subscription_id.clone(),
                state: normalized.state,
                diagnostic: normalized.diagnostic,
                usage: normalized.usage,
                source_fingerprint: source_fingerprint.to_owned(),
                credential: normalized.credential,
            };
            if matches!(
                node.state,
                DynamicNodeState::Active | DynamicNodeState::Pending
            ) {
                node.state = DynamicNodeState::Active;
                if !self
                    .snapshot
                    .admissions
                    .get(&id)
                    .is_some_and(|admission| admission.matches(&node))
                {
                    self.revoke_admission(&id);
                    node.state = DynamicNodeState::Pending;
                }
            } else {
                self.revoke_admission(&id);
            }
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
        self.pending_nodes.remove(subscription_id);
        if !deferred.is_empty() {
            self.pending_nodes.insert(
                subscription_id.clone(),
                PendingSubscriptionNodes {
                    source_fingerprint: source_fingerprint.to_owned(),
                    nodes: deferred,
                },
            );
        }
        self.snapshot.generation = self.snapshot.generation.saturating_add(1);
        diff.generation = self.snapshot.generation;
        Ok(diff)
    }

    async fn prepare_cache(
        &self,
        config: &SubscriptionConfig,
        nodes: &[NormalizedNode],
    ) -> Result<Option<atomic_write_file::AtomicWriteFile>, SubscriptionError> {
        let Some(cache) = config.cache.as_ref() else {
            return Ok(None);
        };
        let path = resolve_cache_path(&self.cache_root, &cache.path)?;
        let cached_nodes = nodes
            .iter()
            .map(|node| CachedNode {
                config: node.config.clone(),
                source_subscription: config.id.clone(),
                protocol: node.config.protocol.clone(),
                credential: node.credential.clone(),
                diagnostic: node.diagnostic.clone(),
                usage: node.usage.clone(),
            })
            .collect();
        let envelope = CacheEnvelope {
            version: CACHE_ENVELOPE_VERSION,
            published_at_unix_seconds: unix_seconds()?,
            subscription_id: config.id.clone(),
            source_fingerprint: Some(subscription_source_fingerprint(config)),
            nodes: cached_nodes,
        };
        let encoded = serde_json::to_vec(&envelope).map_err(|_| SubscriptionError::InvalidCache)?;
        if encoded.len() as u64 > MAX_CACHE_BYTES {
            return Err(SubscriptionError::InvalidCache);
        }
        stage_atomic_write(path, encoded).await.map(Some)
    }
}

#[derive(Debug, Clone)]
struct NormalizedNode {
    config: TransitProxyConfig,
    credential: SubscriptionCredential,
    state: DynamicNodeState,
    diagnostic: Option<NodeDiagnostic>,
    usage: Option<SubscriptionUsage>,
}

#[derive(Debug)]
struct PendingSubscriptionNodes {
    source_fingerprint: String,
    nodes: BTreeMap<TransitProxyId, NormalizedNode>,
}

#[derive(Debug, Serialize, Deserialize)]
struct CacheEnvelope {
    version: u8,
    published_at_unix_seconds: u64,
    subscription_id: SubscriptionId,
    #[serde(default)]
    source_fingerprint: Option<String>,
    nodes: Vec<CachedNode>,
}

fn has_retired_native_option_fields(envelope: &serde_json::Value) -> bool {
    envelope
        .get("nodes")
        .and_then(serde_json::Value::as_array)
        .is_some_and(|nodes| {
            nodes.iter().any(|node| {
                let Some(options) = node.pointer("/config/options") else {
                    return false;
                };
                options.get("udpOverTcp").is_some()
                    || options.pointer("/tls/certificate").is_some()
                    || options.pointer("/tls/clientCertificate").is_some()
                    || options.pointer("/tls/fingerprint").is_some()
                    || options.pointer("/transport/host").is_some()
                    || options.pointer("/transport/maxEarlyData").is_some()
            })
        })
}

fn subscription_source_fingerprint(config: &SubscriptionConfig) -> String {
    use std::fmt::Write as _;
    let mut digest = Sha256::new();
    digest.update(b"PathChord/subscription-source/v2\0");
    for value in [
        Some(config.source.source_type.as_str()),
        Some(config.source.url.as_str()),
        config.source.credentials_ref.as_deref(),
    ] {
        match value {
            Some(value) => {
                digest.update([1]);
                digest.update((value.len() as u64).to_be_bytes());
                digest.update(value.as_bytes());
            }
            None => digest.update([0]),
        }
    }
    // The older cache format had no default User-Agent. Even the default now
    // changes the representation requested from a provider, so old hashes
    // must not be accepted for this source.
    let user_agent = config
        .source
        .user_agent
        .as_deref()
        .unwrap_or(DEFAULT_SUBSCRIPTION_USER_AGENT);
    digest.update(b"\0PathChord/subscription-user-agent/v1\0");
    digest.update((user_agent.len() as u64).to_be_bytes());
    digest.update(user_agent.as_bytes());
    let mut result = String::with_capacity(64);
    for byte in digest.finalize() {
        write!(result, "{byte:02x}").expect("writing to a String cannot fail");
    }
    result
}

#[derive(Debug, Serialize, Deserialize)]
struct CachedNode {
    config: TransitProxyConfig,
    source_subscription: SubscriptionId,
    protocol: String,
    credential: SubscriptionCredential,
    #[serde(default)]
    diagnostic: Option<NodeDiagnostic>,
    #[serde(default)]
    usage: Option<SubscriptionUsage>,
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
    import::normalize(config, body, available_adapters)
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

fn unique_node_id(
    subscription: &SubscriptionId,
    display_name: &str,
    index: usize,
    used: &mut BTreeSet<String>,
) -> String {
    use base64::Engine as _;
    let source_name = subscription.resource_name();
    let canonical_source = canonical_segment(source_name, 24);
    let needs_owner_digest = canonical_source != source_name;
    let (prefix, maximum_name) = if !needs_owner_digest {
        // Preserve published/cache identities for ordinary short resource names.
        (canonical_source, 28)
    } else {
        // Canonicalization/truncation must not collapse distinct source owners.
        // The complete 256-bit digest fits a bounded node ID; `s_` cannot be
        // produced by the legacy lowercase/hyphen canonicalization.
        let mut digest = Sha256::new();
        digest.update(b"PathChord/subscription-node-owner/v1\0");
        digest.update(subscription.as_str().as_bytes());
        (
            format!(
                "s_{}",
                base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest.finalize())
            ),
            17,
        )
    };
    let mut name = canonical_segment(display_name, maximum_name);
    if needs_owner_digest {
        // A pending separator in legacy canonicalization can add one byte.
        // Bound the new representation without changing existing short IDs.
        name.truncate(maximum_name);
    }
    let base = format!("{prefix}-{name}");
    let mut candidate = base.clone();
    let mut suffix = index + 1;
    while !used.insert(candidate.clone()) {
        let ending = format!("-{suffix}");
        let maximum_base = 63 - ending.len();
        candidate = format!(
            "{}{ending}",
            base[..base.len().min(maximum_base)].trim_end_matches('-')
        );
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

fn pending_state(state: DynamicNodeState) -> DynamicNodeState {
    if state == DynamicNodeState::Active {
        DynamicNodeState::Pending
    } else {
        state
    }
}

fn adapter_diagnostic() -> NodeDiagnostic {
    NodeDiagnostic {
        code: NodeUnavailableReason::AdapterUnavailable,
        fields: Vec::new(),
        message: "node adapter could not be prepared".to_owned(),
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

#[cfg(test)]
async fn atomic_write(path: &Path, contents: &[u8]) -> Result<(), SubscriptionError> {
    let file = stage_atomic_write(path.to_owned(), contents.to_vec()).await?;
    tokio::task::spawn_blocking(move || file.commit())
        .await
        .map_err(|_| SubscriptionError::CacheIo)?
        .map_err(|_| SubscriptionError::CacheIo)
}

async fn stage_atomic_write(
    path: PathBuf,
    contents: Vec<u8>,
) -> Result<atomic_write_file::AtomicWriteFile, SubscriptionError> {
    use std::io::Write as _;
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
        file.sync_all().map_err(|_| SubscriptionError::CacheIo)?;
        Ok(file)
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

        async fn fetch_document_with_budget(
            &self,
            request: SubscriptionFetchRequest,
            budget: &SubscriptionDownloadBudget,
        ) -> Result<SubscriptionDocument, SubscriptionError> {
            // Scripted failures perform no I/O and consume no response bytes.
            let document = self.fetch_document(request).await?;
            budget.charge(document.body.len())?;
            Ok(document)
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
                user_agent: None,
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

    #[tokio::test]
    async fn stale_prepared_refresh_cannot_publish_after_source_replacement() {
        let fetcher = Arc::new(ScriptedFetcher::new([
            Ok(CLASH.as_bytes().to_vec()),
            Ok(CLASH.as_bytes().to_vec()),
        ]));
        let mut manager = SubscriptionManager::new(
            fetcher,
            temp_directory("stale-prepared-refresh"),
            BTreeSet::from(["http".into(), "ss".into()]),
        );
        let first = config(SubscriptionSourceType::Clash, None);
        manager.reconcile(std::slice::from_ref(&first));
        let prepared = manager
            .prepare_refresh(&first, 0)
            .await
            .expect("first candidate");

        let mut replacement = first.clone();
        replacement.source.url = "https://subscription.example.test/replacement".into();
        manager.reconcile(std::slice::from_ref(&replacement));
        let stale = manager.commit_prepared_refresh(prepared, 1).await;
        assert!(matches!(
            stale,
            RefreshOutcome::Retained {
                error: SubscriptionError::StaleCandidate,
                ..
            }
        ));
        assert!(manager.snapshot().nodes.is_empty());

        let prepared = manager
            .prepare_refresh(&replacement, 1)
            .await
            .expect("replacement candidate");
        let published = manager.commit_prepared_refresh(prepared, 1).await;
        assert!(matches!(published, RefreshOutcome::Published { .. }));
        assert!(!manager.snapshot().nodes.is_empty());
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
    async fn imported_nodes_are_not_selectable_until_their_adapters_are_prepared() {
        let fetcher = Arc::new(ScriptedFetcher::new([Ok(CLASH.as_bytes().to_vec())]));
        let mut manager = SubscriptionManager::new(
            fetcher,
            temp_directory("unprepared-nodes"),
            BTreeSet::from(["vless".into(), "ss".into()]),
        );
        assert!(matches!(
            manager
                .refresh(&config(SubscriptionSourceType::Clash, None))
                .await,
            RefreshOutcome::Published { .. }
        ));
        assert_eq!(manager.snapshot().nodes.len(), 2);
        assert_eq!(manager.snapshot().selectable_nodes().count(), 0);
        let mut catalog = RuntimeCatalog::default();
        manager.snapshot().extend_runtime_catalog(&mut catalog);
        for node in manager.snapshot().nodes.values() {
            let status = catalog.transit_proxy(&node.config.id).unwrap();
            assert_ne!(status.state, RuntimeNodeState::Ready);
            assert!(status.capabilities.is_empty());
        }
    }

    #[tokio::test]
    async fn only_prepared_adapters_become_selectable_with_real_capabilities() {
        let document = br#"proxies:
  - {name: tcp, type: http, server: proxy.test, port: 8080}
  - {name: no-udp, type: socks5, server: proxy.test, port: 1080, udp: false}
  - {name: invalid, type: vless, server: proxy.test, port: 443, uuid: not-a-uuid}
"#;
        let mut manager = SubscriptionManager::new(
            Arc::new(ScriptedFetcher::new([Ok(document.to_vec())])),
            temp_directory("prepared-adapters"),
            BTreeSet::from(["http".into(), "socks5".into(), "vless".into()]),
        );
        manager
            .refresh(&config(SubscriptionSourceType::Clash, None))
            .await;
        let registry = crate::AdapterRegistry::for_configs(
            Arc::new(crate::NoTransitCredentials),
            Duration::from_secs(1),
            manager.snapshot().nodes.values().map(|node| &node.config),
        )
        .unwrap();
        let prepared = manager.snapshot().prepare_adapters(&registry).await;
        manager.commit_prepared_adapters(prepared).unwrap();
        let selected: Vec<_> = manager.snapshot().selectable_nodes().collect();
        assert_eq!(selected.len(), 2);
        let mut catalog = RuntimeCatalog::default();
        manager.snapshot().extend_runtime_catalog(&mut catalog);
        for node in &selected {
            let status = catalog.transit_proxy(&node.config.id).unwrap();
            assert_eq!(status.state, RuntimeNodeState::Ready);
            assert_eq!(status.capabilities, BTreeSet::from([FlowProtocol::Tcp]));
        }
        let invalid = manager
            .snapshot()
            .nodes
            .values()
            .find(|node| node.config.protocol == "vless")
            .unwrap();
        assert_eq!(
            invalid.state,
            DynamicNodeState::Unavailable(NodeUnavailableReason::AdapterUnavailable)
        );
        assert!(!format!("{:?}", invalid.diagnostic).contains("not-a-uuid"));

        let mut changed = manager.snapshot().clone();
        let id = selected
            .iter()
            .find(|node| node.config.protocol == "http")
            .unwrap()
            .config
            .id
            .clone();
        changed.nodes.get_mut(&id).unwrap().config.endpoint.port = 9999;
        assert_eq!(changed.selectable_nodes().count(), 1);
        assert!(changed.validated_adapter(&id).is_none());
        let old = manager.snapshot().clone();
        manager.reconcile(&[]);
        assert_eq!(old.selectable_nodes().count(), 0);
    }

    #[tokio::test]
    async fn stale_prepared_adapters_cannot_survive_a_source_change_or_disable() {
        for disable in [false, true] {
            let mut manager = SubscriptionManager::new(
                Arc::new(ScriptedFetcher::new([Ok(CLASH.as_bytes().to_vec())])),
                temp_directory("stale-adapters"),
                BTreeSet::from(["vless".into(), "ss".into()]),
            );
            let current = config(SubscriptionSourceType::Clash, None);
            manager.refresh(&current).await;
            let registry = crate::AdapterRegistry::for_configs(
                Arc::new(crate::NoTransitCredentials),
                Duration::from_secs(1),
                manager.snapshot().nodes.values().map(|node| &node.config),
            )
            .unwrap();
            let prepared = manager.snapshot().prepare_adapters(&registry).await;
            if disable {
                manager.reconcile(&[]);
            } else {
                let mut replacement = current.clone();
                replacement.source.url = "https://replacement.example.test/subscription".into();
                manager.reconcile(&[replacement]);
            }
            assert_eq!(
                manager.commit_prepared_adapters(prepared),
                Err(SubscriptionError::StaleCandidate)
            );
            assert_eq!(manager.snapshot().selectable_nodes().count(), 0);
        }
    }

    #[tokio::test]
    async fn cache_reload_requires_fresh_adapter_preparation() {
        let directory = temp_directory("adapter-cache-revalidation");
        let cache = SubscriptionCache {
            path: "nodes.json".into(),
            max_age_seconds: 3600,
        };
        let subscription = config(SubscriptionSourceType::Clash, Some(cache));
        let mut manager = SubscriptionManager::new(
            Arc::new(ScriptedFetcher::new([Ok(CLASH.as_bytes().to_vec())])),
            &directory,
            BTreeSet::from(["vless".into(), "ss".into()]),
        );
        manager.refresh(&subscription).await;
        let registry = crate::AdapterRegistry::for_configs(
            Arc::new(crate::NoTransitCredentials),
            Duration::from_secs(1),
            manager.snapshot().nodes.values().map(|node| &node.config),
        )
        .unwrap();
        let prepared = manager.snapshot().prepare_adapters(&registry).await;
        manager.commit_prepared_adapters(prepared).unwrap();
        assert_eq!(manager.snapshot().selectable_nodes().count(), 2);
        let mut restored = SubscriptionManager::new(
            Arc::new(ScriptedFetcher::new([])),
            &directory,
            BTreeSet::from(["vless".into(), "ss".into()]),
        );
        assert!(matches!(
            restored.load_cache(&subscription).await,
            Ok(CacheLoadOutcome::Loaded { .. })
        ));
        assert_eq!(restored.snapshot().selectable_nodes().count(), 0);
        let prepared = restored.snapshot().prepare_adapters(&registry).await;
        restored.commit_prepared_adapters(prepared).unwrap();
        assert_eq!(restored.snapshot().selectable_nodes().count(), 2);

        let mut changed_backend = SubscriptionManager::new(
            Arc::new(ScriptedFetcher::new([])),
            &directory,
            BTreeSet::from(["vless".into()]),
        );
        assert!(matches!(
            changed_backend.load_cache(&subscription).await,
            Ok(CacheLoadOutcome::Loaded { .. })
        ));
        assert_eq!(changed_backend.snapshot().selectable_nodes().count(), 0);
        let prepared = changed_backend.snapshot().prepare_adapters(&registry).await;
        changed_backend.commit_prepared_adapters(prepared).unwrap();
        assert_eq!(changed_backend.snapshot().selectable_nodes().count(), 1);
        let unsupported = changed_backend
            .snapshot()
            .nodes
            .values()
            .find(|node| node.config.protocol == "ss")
            .unwrap();
        assert_eq!(
            unsupported.state,
            DynamicNodeState::Unavailable(NodeUnavailableReason::AdapterUnavailable)
        );
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[tokio::test]
    async fn same_id_credential_replacement_revokes_old_proofs_and_stale_preparations() {
        let first = b"proxies: [{name: node, type: http, server: proxy.test, port: 8080, username: user, password: first-secret}]";
        let second = b"proxies: [{name: node, type: http, server: proxy.test, port: 8080, username: user, password: second-secret}]";
        let mut manager = SubscriptionManager::new(
            Arc::new(ScriptedFetcher::new([
                Ok(first.to_vec()),
                Ok(second.to_vec()),
                Ok(first.to_vec()),
            ])),
            temp_directory("replacement-admission"),
            BTreeSet::from(["http".into()]),
        );
        let config = config(SubscriptionSourceType::Clash, None);
        manager.refresh(&config).await;
        let registry = crate::AdapterRegistry::for_configs(
            Arc::new(crate::NoTransitCredentials),
            Duration::from_secs(1),
            manager.snapshot().nodes.values().map(|node| &node.config),
        )
        .unwrap();
        let stale = manager.snapshot().prepare_adapters(&registry).await;
        manager.refresh(&config).await;
        assert_eq!(
            manager.commit_prepared_adapters(stale),
            Err(SubscriptionError::StaleCandidate)
        );
        let current = manager.snapshot().prepare_adapters(&registry).await;
        manager.commit_prepared_adapters(current).unwrap();
        let before = manager.snapshot().clone();
        assert_eq!(before.selectable_nodes().count(), 1);
        let expected = before.selectable_nodes().next().unwrap().config.id.clone();
        let replacement = manager.prepare_refresh(&config, 0).await.unwrap();
        assert_eq!(replacement.invalidated_adapters(&before), vec![expected]);
        assert!(matches!(
            manager.commit_prepared_refresh(replacement, 0).await,
            RefreshOutcome::Published { .. }
        ));
        assert_eq!(before.selectable_nodes().count(), 0);
        assert_eq!(manager.snapshot().selectable_nodes().count(), 0);
        assert!(
            manager
                .snapshot()
                .nodes
                .values()
                .all(|node| node.state == DynamicNodeState::Pending)
        );
        let current = manager.snapshot().prepare_adapters(&registry).await;
        manager.commit_prepared_adapters(current).unwrap();
        assert_eq!(manager.snapshot().selectable_nodes().count(), 1);
    }

    #[tokio::test]
    async fn overlapping_refresh_rejects_an_old_inflight_adapter_preparation() {
        struct BlockingAdapter {
            entered: Arc<tokio::sync::Notify>,
            release: Arc<tokio::sync::Notify>,
        }
        #[async_trait]
        impl crate::TransitAdapter for BlockingAdapter {
            fn metadata(&self) -> &crate::TransitMetadata {
                panic!("metadata is not used")
            }
            async fn prepare(&self) -> Result<(), crate::TransitError> {
                self.entered.notify_one();
                self.release.notified().await;
                Ok(())
            }
            async fn connect(
                &self,
                _: crate::ConnectRequest,
            ) -> Result<crate::BoxedTransitConnection, crate::TransitError> {
                panic!("connections are not opened by this test")
            }
        }
        let first=b"proxies: [{name: node, type: http, server: proxy.test, port: 8080, username: user, password: first}]";
        let second=b"proxies: [{name: node, type: http, server: proxy.test, port: 8080, username: user, password: second}]";
        let mut manager = SubscriptionManager::new(
            Arc::new(ScriptedFetcher::new([
                Ok(first.to_vec()),
                Ok(second.to_vec()),
            ])),
            temp_directory("overlap-preparation"),
            BTreeSet::from(["http".into()]),
        );
        let config = config(SubscriptionSourceType::Clash, None);
        manager.refresh(&config).await;
        let snapshot = manager.snapshot().clone();
        let candidate = snapshot.nodes.values().next().unwrap().clone();
        let entered = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(tokio::sync::Notify::new());
        let adapter: Arc<dyn crate::TransitAdapter> = Arc::new(BlockingAdapter {
            entered: Arc::clone(&entered),
            release: Arc::clone(&release),
        });
        let pending = tokio::spawn(async move {
            crate::adapter_registry::prepare_adapter(adapter.as_ref(), Duration::from_secs(2))
                .await
                .unwrap();
            PreparedDynamicSnapshot {
                generation: snapshot.generation,
                nodes: vec![(candidate, Ok(adapter))],
            }
        });
        tokio::time::timeout(Duration::from_secs(1), entered.notified())
            .await
            .unwrap();
        manager.refresh(&config).await;
        release.notify_one();
        let stale = pending.await.unwrap();
        assert_eq!(
            manager.commit_prepared_adapters(stale),
            Err(SubscriptionError::StaleCandidate)
        );
        assert_eq!(manager.snapshot().selectable_nodes().count(), 0);
    }

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
        assert_eq!(manager.snapshot().candidate_nodes().count(), 2);
        assert_eq!(manager.snapshot().selectable_nodes().count(), 0);
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
        let envelope: CacheEnvelope =
            serde_json::from_slice(&std::fs::read(&cache_path).unwrap()).unwrap();
        assert_eq!(envelope.version, CACHE_ENVELOPE_VERSION);
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
        assert_eq!(restored.snapshot().candidate_nodes().count(), 2);
        assert_eq!(restored.snapshot().selectable_nodes().count(), 0);

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
    async fn incompatible_normalized_cache_is_not_decoded_or_published() {
        let directory = temp_directory("incompatible-cache");
        let cache = SubscriptionCache {
            path: "provider.snapshot".into(),
            max_age_seconds: 86_400,
        };
        let subscription = config(SubscriptionSourceType::Clash, Some(cache.clone()));
        let cache_path = directory.join(&cache.path);
        for version in [2, CACHE_ENVELOPE_VERSION] {
            let old_envelope = serde_json::json!({
                "version": version,
                "subscription_id": subscription.id.as_str(),
                "nodes": [{
                    "config": {
                        "options": {
                            "udpOverTcp": 2,
                            "tls": {"fingerprint": "chrome"},
                            "transport": {"type": "ws", "maxEarlyData": 4096}
                        }
                    }
                }]
            });
            atomic_write(&cache_path, &serde_json::to_vec(&old_envelope).unwrap())
                .await
                .unwrap();

            let mut manager = SubscriptionManager::new(
                Arc::new(ScriptedFetcher::new([])),
                &directory,
                BTreeSet::from(["vless".into()]),
            );
            assert_eq!(
                manager.load_cache(&subscription).await.unwrap(),
                CacheLoadOutcome::Incompatible {
                    code: CACHE_INCOMPATIBLE_CODE,
                }
            );
            assert!(manager.snapshot().nodes.is_empty());
        }
    }

    #[tokio::test]
    async fn cache_is_bound_to_the_complete_subscription_source() {
        let directory = temp_directory("source-fingerprint");
        let cache = SubscriptionCache {
            path: "provider.snapshot".into(),
            max_age_seconds: 86_400,
        };
        let subscription = config(SubscriptionSourceType::Clash, Some(cache.clone()));
        let old_fingerprint = "f5ca1fabc6f80a87d8717c2ff1b5696c00b0ec3c25a21a7c674779970721c053";
        assert_ne!(
            subscription_source_fingerprint(&subscription),
            old_fingerprint
        );
        let mut explicit_default = subscription.clone();
        explicit_default.source.user_agent = Some("clash.meta".into());
        assert_eq!(
            subscription_source_fingerprint(&subscription),
            subscription_source_fingerprint(&explicit_default)
        );
        let mut manager = SubscriptionManager::new(
            Arc::new(ScriptedFetcher::new([Ok(CLASH.as_bytes().to_vec())])),
            &directory,
            BTreeSet::from(["vless".into(), "ss".into()]),
        );
        assert!(matches!(
            manager.refresh(&subscription).await,
            RefreshOutcome::Published { .. }
        ));

        let mut restored = SubscriptionManager::new(
            Arc::new(ScriptedFetcher::new([])),
            &directory,
            BTreeSet::from(["vless".into(), "ss".into()]),
        );
        assert!(matches!(
            restored.load_cache(&subscription).await.unwrap(),
            CacheLoadOutcome::Loaded { .. }
        ));

        let mut changed_url = subscription.clone();
        changed_url.source.url = "https://subscription.example.test/changed?token=private".into();
        let mut changed = SubscriptionManager::new(
            Arc::new(ScriptedFetcher::new([])),
            &directory,
            BTreeSet::from(["vless".into(), "ss".into()]),
        );
        assert_eq!(
            changed.load_cache(&changed_url).await.unwrap(),
            CacheLoadOutcome::SourceMismatch
        );
        let mut changed_agent = subscription.clone();
        changed_agent.source.user_agent = Some("CustomClient/1.0".into());
        assert_eq!(
            changed.load_cache(&changed_agent).await.unwrap(),
            CacheLoadOutcome::SourceMismatch
        );

        let cache_path = directory.join(&cache.path);
        let mut envelope: CacheEnvelope =
            serde_json::from_slice(&std::fs::read(&cache_path).unwrap()).unwrap();
        envelope.source_fingerprint = Some(old_fingerprint.to_owned());
        atomic_write(&cache_path, &serde_json::to_vec(&envelope).unwrap())
            .await
            .unwrap();
        let mut old_cache = SubscriptionManager::new(
            Arc::new(ScriptedFetcher::new([])),
            &directory,
            BTreeSet::from(["vless".into(), "ss".into()]),
        );
        assert_eq!(
            old_cache.load_cache(&subscription).await.unwrap(),
            CacheLoadOutcome::SourceMismatch
        );
        assert!(old_cache.snapshot().nodes.is_empty());
        envelope.version = 1;
        envelope.source_fingerprint = None;
        atomic_write(&cache_path, &serde_json::to_vec(&envelope).unwrap())
            .await
            .unwrap();
        let mut legacy = SubscriptionManager::new(
            Arc::new(ScriptedFetcher::new([])),
            &directory,
            BTreeSet::from(["vless".into(), "ss".into()]),
        );
        assert_eq!(
            legacy.load_cache(&subscription).await.unwrap(),
            CacheLoadOutcome::UnverifiedSource
        );
    }

    #[tokio::test]
    async fn changing_user_agent_invalidates_prepared_refresh_even_at_same_control_generation() {
        let fetcher = Arc::new(ScriptedFetcher::new([Ok(CLASH.as_bytes().to_vec())]));
        let mut manager =
            SubscriptionManager::new(fetcher, temp_directory("ua-candidate"), BTreeSet::new());
        let original = config(SubscriptionSourceType::Clash, None);
        manager.reconcile(std::slice::from_ref(&original));
        let prepared = manager.prepare_refresh(&original, 7).await.unwrap();
        let mut invalid = original.clone();
        invalid.source.user_agent = Some("invalid\r\nheader".into());
        assert!(matches!(
            manager.refresh(&invalid).await,
            RefreshOutcome::Retained {
                error: SubscriptionError::InvalidUserAgent,
                attempts: 0,
                ..
            }
        ));
        assert!(manager.snapshot().nodes.is_empty());
        let mut changed = original.clone();
        changed.source.user_agent = Some("CustomClient/1.0".into());
        manager.reconcile(&[changed]);
        assert!(matches!(
            manager.commit_prepared_refresh(prepared, 7).await,
            RefreshOutcome::Retained {
                error: SubscriptionError::StaleCandidate,
                ..
            }
        ));
        assert!(manager.snapshot().nodes.is_empty());
    }

    #[tokio::test]
    async fn source_change_drains_old_nodes_and_promotes_new_nodes_after_release() {
        let fetcher = Arc::new(ScriptedFetcher::new([
            Ok(CLASH.as_bytes().to_vec()),
            Ok(CLASH.as_bytes().to_vec()),
        ]));
        let mut manager = SubscriptionManager::new(
            fetcher,
            temp_directory("source-drain"),
            BTreeSet::from(["vless".into(), "ss".into()]),
        );
        let first = config(SubscriptionSourceType::Clash, None);
        assert!(matches!(
            manager.refresh(&first).await,
            RefreshOutcome::Published { .. }
        ));
        let old_ids: BTreeSet<_> = manager.snapshot.nodes.keys().cloned().collect();
        let mut changed = first.clone();
        changed.source.url = "https://subscription.example.test/other".into();
        changed.refresh.max_attempts = 1;
        assert!(matches!(
            manager.refresh(&changed).await,
            RefreshOutcome::Published { .. }
        ));
        assert!(
            manager
                .snapshot
                .nodes
                .values()
                .all(|node| node.state == DynamicNodeState::Draining)
        );
        let promoted = manager.complete_draining(&old_ids);
        assert_eq!(promoted.added.len(), old_ids.len());
        assert!(manager.snapshot.candidate_nodes().count() == old_ids.len());
        assert!(
            manager
                .snapshot
                .nodes
                .values()
                .all(|node| node.source_fingerprint == subscription_source_fingerprint(&changed))
        );
    }

    #[tokio::test]
    async fn failed_provider_refresh_does_not_resurrect_draining_nodes_from_an_old_source() {
        let fetcher = Arc::new(ScriptedFetcher::new([
            Ok(CLASH.as_bytes().to_vec()),
            Err(SubscriptionError::Fetch),
            Err(SubscriptionError::Fetch),
            Err(SubscriptionError::Fetch),
        ]));
        let mut manager = SubscriptionManager::new(
            fetcher,
            temp_directory("source-provider-drain"),
            BTreeSet::from(["vless".into(), "ss".into()]),
        );
        let first = config(SubscriptionSourceType::Clash, None);
        assert!(matches!(
            manager.refresh(&first).await,
            RefreshOutcome::Published { .. }
        ));
        let mut changed = first.clone();
        changed.source.url = "https://subscription.example.test/other".into();
        changed.refresh.max_attempts = 1;
        assert!(matches!(
            manager.refresh(&changed).await,
            RefreshOutcome::Retained { .. }
        ));
        assert!(
            manager
                .snapshot
                .nodes
                .values()
                .all(|node| node.state == DynamicNodeState::Draining)
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
        let registry = crate::AdapterRegistry::for_configs(
            Arc::new(crate::NoTransitCredentials),
            Duration::from_secs(1),
            manager.snapshot().nodes.values().map(|node| &node.config),
        )
        .unwrap();
        let prepared = manager.snapshot().prepare_adapters(&registry).await;
        manager.commit_prepared_adapters(prepared).unwrap();
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
                user_agent: None,
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

    #[tokio::test]
    async fn shared_http_fetcher_sends_per_request_user_agents_without_cross_talk() {
        tokio::time::timeout(Duration::from_secs(5), async {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let server = tokio::spawn(async move {
                for _ in 0..3 {
                    let (mut stream, _) = listener.accept().await.unwrap();
                    let mut request = Vec::new();
                    while !request.ends_with(b"\r\n\r\n") && request.len() < 8192 {
                        request.push(stream.read_u8().await.unwrap());
                    }
                    let request = String::from_utf8(request).unwrap();
                    let agent = request
                        .lines()
                        .find_map(|line| {
                            let (name, value) = line.split_once(':')?;
                            name.eq_ignore_ascii_case("user-agent")
                                .then(|| value.trim())
                        })
                        .expect("User-Agent header");
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{agent}",
                        agent.len()
                    );
                    stream.write_all(response.as_bytes()).await.unwrap();
                }
            });
            let fetcher = HttpSubscriptionFetcher::new().unwrap();
            let request = |user_agent: Option<&str>| SubscriptionFetchRequest {
                url: format!("http://{address}/sub"),
                credentials_ref: None,
                user_agent: user_agent.map(str::to_owned),
                timeout: Duration::from_secs(2),
                max_bytes: 1024,
            };
            let (default, first, second) = tokio::join!(
                fetcher.fetch(request(None)),
                fetcher.fetch(request(Some("Client-A/1"))),
                fetcher.fetch(request(Some("Client-B/2"))),
            );
            assert_eq!(default.unwrap(), b"clash.meta");
            assert_eq!(first.unwrap(), b"Client-A/1");
            assert_eq!(second.unwrap(), b"Client-B/2");
            let invalid = fetcher.fetch(request(Some("bad\r\nInjected: x"))).await;
            assert_eq!(invalid, Err(SubscriptionError::InvalidUserAgent));
            server.await.unwrap();
        })
        .await
        .expect("HTTP User-Agent test timed out");
    }

    #[tokio::test]
    async fn concurrent_subscriptions_import_the_format_selected_by_their_user_agent() {
        tokio::time::timeout(Duration::from_secs(5), async {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let cases = [
                (
                    "clash.meta",
                    "clash",
                    "yaml-node",
                    "http",
                    r#"
proxies:
  - {name: yaml-node, type: http, server: proxy.test, port: 8080}
proxy-providers:
  local: {type: file, path: ./fixture-proxies.yaml}
"#,
                    Some(("local", "proxy-providers")),
                ),
                (
                    "shadowsocks",
                    "sip008",
                    "sip-node",
                    "ss",
                    r#"{
  "version": 1,
  "servers": [
    {"id":"11111111-1111-4111-8111-111111111111","remarks":"sip-node",
     "server":"proxy.test","server_port":8388,"method":"aes-256-gcm",
     "password":"fixture-password","plugin":"","plugin_opts":""},
    {"id":"22222222-2222-4222-8222-222222222222","remarks":"sip-invalid",
     "server":"proxy.test","server_port":8389,"method":"aes-256-gcm"}
  ]
}"#,
                    Some(("sip-invalid", "password")),
                ),
                (
                    "sing-box",
                    "sing_box",
                    "box-node",
                    "http",
                    r#"{
  "outbounds": [
    {"type":"http","tag":"box-node","server":"proxy.test","server_port":8082,
     "username":"fixture-user","password":"fixture-password"},
    {"type":"http","tag":"box-chain","server":"proxy.test","server_port":8083,
     "password":"fixture-password","detour":"box-node"},
    {"type":"selector","tag":"selection","outbounds":["box-node"]}
  ]
}"#,
                    Some(("box-chain", "sing_box_outbound")),
                ),
                (
                    "v2rayn",
                    "uri",
                    "uri-node",
                    "http",
                    "http://proxy.test:8081#uri-node",
                    None,
                ),
            ];
            let server_cases = cases;
            let server = tokio::spawn(async move {
                for _ in 0..server_cases.len() {
                    let (mut stream, _) = listener.accept().await.unwrap();
                    let mut request = Vec::new();
                    while !request.ends_with(b"\r\n\r\n") && request.len() < 8192 {
                        request.push(stream.read_u8().await.unwrap());
                    }
                    let request = String::from_utf8(request).unwrap().to_ascii_lowercase();
                    let (_, _, _, _, body, _) = server_cases
                        .iter()
                        .find(|(agent, ..)| {
                            request.contains(&format!("\r\nuser-agent: {agent}\r\n"))
                        })
                        .expect("configured User-Agent");
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    stream.write_all(response.as_bytes()).await.unwrap();
                }
            });
            let fetcher = Arc::new(HttpSubscriptionFetcher::new().unwrap());
            let mut clients = tokio::task::JoinSet::new();
            for (agent, format, name, protocol, _, unavailable) in cases.iter().copied() {
                let mut subscription = config(SubscriptionSourceType::Auto, None);
                subscription.id = SubscriptionId::new(format.replace('_', "-"));
                subscription.source.url = format!("http://{address}/sub");
                subscription.source.user_agent = Some(agent.to_owned());
                let mut manager = SubscriptionManager::new(
                    fetcher.clone(),
                    std::env::temp_dir(),
                    BTreeSet::from(["http".into(), "ss".into()]),
                );
                clients.spawn(async move {
                    let outcome = manager.refresh(&subscription).await;
                    assert!(matches!(outcome, RefreshOutcome::Published { .. }));
                    let snapshot = manager.snapshot();
                    let mut candidates = snapshot.candidate_nodes();
                    let node = candidates.next().expect("supported sibling");
                    assert_eq!(node.config.labels["source.name"], name);
                    assert_eq!(node.config.labels["source.format"], format);
                    assert_eq!(node.config.protocol, protocol);
                    assert!(candidates.next().is_none());
                    assert_eq!(snapshot.nodes.len(), 1 + usize::from(unavailable.is_some()));
                    if let Some((name, field)) = unavailable {
                        let node = snapshot
                            .nodes
                            .values()
                            .find(|node| node.config.labels["source.name"] == name)
                            .expect("unavailable sibling");
                        assert!(matches!(node.state, DynamicNodeState::Unavailable(_)));
                        assert_eq!(node.diagnostic.as_ref().unwrap().fields, [field]);
                    }
                    assert!(!format!("{snapshot:?}").contains("fixture-password"));
                });
            }
            while let Some(result) = clients.join_next().await {
                result.unwrap();
            }
            server.await.unwrap();
        })
        .await
        .expect("parallel subscription test timed out");
    }

    struct LegacyUnknownFailure;

    #[async_trait]
    impl SubscriptionFetcher for LegacyUnknownFailure {
        async fn fetch(&self, _: SubscriptionFetchRequest) -> Result<Vec<u8>, SubscriptionError> {
            Err(SubscriptionError::Fetch)
        }
    }

    struct LegacyPendingFetcher;

    #[async_trait]
    impl SubscriptionFetcher for LegacyPendingFetcher {
        async fn fetch(&self, _: SubscriptionFetchRequest) -> Result<Vec<u8>, SubscriptionError> {
            std::future::pending().await
        }
    }

    #[tokio::test]
    async fn legacy_fetcher_unknown_failures_and_cancellation_cannot_release_reserved_bytes() {
        let request = SubscriptionFetchRequest {
            url: "https://provider.invalid/sub".into(),
            credentials_ref: None,
            user_agent: None,
            timeout: Duration::from_secs(1),
            max_bytes: 1024,
        };
        let budget = SubscriptionDownloadBudget::new(2048);
        assert_eq!(
            LegacyUnknownFailure
                .fetch_document_with_budget(request.clone(), &budget)
                .await,
            Err(SubscriptionError::Fetch)
        );
        assert_eq!(budget.remaining(), 1024);
        assert!(
            tokio::time::timeout(
                Duration::from_millis(1),
                LegacyPendingFetcher.fetch_document_with_budget(request, &budget)
            )
            .await
            .is_err()
        );
        assert_eq!(budget.remaining(), 0);
    }

    #[tokio::test]
    async fn malformed_root_retries_share_the_refresh_body_budget() {
        struct MalformedFetcher {
            requests: Mutex<Vec<usize>>,
        }
        #[async_trait]
        impl SubscriptionFetcher for MalformedFetcher {
            async fn fetch(
                &self,
                request: SubscriptionFetchRequest,
            ) -> Result<Vec<u8>, SubscriptionError> {
                self.requests.lock().unwrap().push(request.max_bytes);
                Ok(vec![b'x'; MAX_SUBSCRIPTION_BYTES / 2 + 1])
            }
        }
        let fetcher = Arc::new(MalformedFetcher {
            requests: Mutex::new(Vec::new()),
        });
        let mut manager = SubscriptionManager::with_sleeper(
            fetcher.clone(),
            Arc::new(RecordingSleeper::default()),
            std::env::temp_dir(),
            BTreeSet::new(),
        );
        assert!(matches!(
            manager
                .refresh(&config(SubscriptionSourceType::Clash, None))
                .await,
            RefreshOutcome::Retained {
                attempts: 2,
                error: SubscriptionError::ResponseTooLarge { .. },
                ..
            }
        ));
        assert_eq!(
            *fetcher.requests.lock().unwrap(),
            [MAX_SUBSCRIPTION_BYTES, MAX_SUBSCRIPTION_BYTES / 2 - 1]
        );
    }
}
