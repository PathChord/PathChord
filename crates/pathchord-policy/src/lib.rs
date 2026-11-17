//! Typed policy inputs and immutable compiled snapshots.
//!
//! The design fixes the domain model, not the serialized configuration shape.
//! These types therefore must not be treated as a stable YAML or API contract.

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use thiserror::Error;

mod compiled;
mod config;
pub mod geodata;
mod resource;
mod service_config;
mod transit_options;
pub use service_config::{EgressServiceSpec, EgressWebSettings, NodeProbePolicySpec};

pub use transit_options::{
    TransitMultiplex, TransitOptions, TransitReality, TransitTls, TransitTransport,
    TransitVmessOptions, parse_certificate_sha256,
};

pub use compiled::{
    CompileError, CompiledPolicy, EgressRouteCandidate, EgressRoutePlan, EgressRuntimeStatus,
    Evaluation, ProxyRoutePlan, RejectReason, RoutePlan, RuntimeCatalog, RuntimeNodeState,
    TransitCandidate, TransitProxyRuntimeStatus,
};
pub use config::{ConfigError, KubeConfig, KubeResource, ObjectMeta};
pub use resource::ResourceIdentity;

macro_rules! id_type {
    ($name:ident) => {
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Self {
                Self(value.into())
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }

            pub fn in_namespace(namespace: &str, name: impl AsRef<str>) -> Self {
                Self(
                    ResourceIdentity {
                        namespace,
                        name: name.as_ref(),
                    }
                    .into_id(),
                )
            }

            pub fn identity(&self) -> ResourceIdentity<'_> {
                ResourceIdentity::from_id(&self.0)
            }

            pub fn namespace(&self) -> &str {
                self.identity().namespace
            }

            pub fn resource_name(&self) -> &str {
                self.identity().name
            }

            pub fn storage_component(&self) -> String {
                self.identity().storage_component()
            }
        }
    };
}

id_type!(EgressId);
id_type!(TransitProxyId);
id_type!(RuleId);
id_type!(TrafficPolicyId);
id_type!(ListenerId);
id_type!(SubscriptionId);
id_type!(DnsPolicyId);
id_type!(GeoSiteDatabaseId);
id_type!(GeoIpDatabaseId);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Generation(u64);

impl Generation {
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    pub const fn get(self) -> u64 {
        self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Endpoint {
    pub host: String,
    pub port: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FlowProtocol {
    Tcp,
    Udp,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessMetadata {
    pub process_id: Option<u32>,
    pub executable: Option<String>,
    #[serde(default)]
    pub user_id: Option<u32>,
    #[serde(default)]
    pub group_id: Option<u32>,
}

/// Listener-requested process facts. Disabled fields are never probed.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProcessMetadataRequest {
    #[serde(default)]
    pub executable: bool,
    #[serde(default)]
    pub user: bool,
    #[serde(default)]
    pub group: bool,
}

impl ProcessMetadataRequest {
    #[must_use]
    pub const fn is_empty(self) -> bool {
        !self.executable && !self.user && !self.group
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TargetHost {
    Hostname(String),
    Ip(IpAddr),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TargetEndpoint {
    pub host: TargetHost,
    pub port: u16,
}

/// Typed facts made available to the policy evaluator for one new flow.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyContext {
    pub flow_tags: BTreeSet<String>,
    pub listener_id: ListenerId,
    pub source: SocketAddr,
    pub authentication_identity: Option<String>,
    pub process: Option<ProcessMetadata>,
    pub protocol: FlowProtocol,
    pub target: TargetEndpoint,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Capabilities {
    pub tcp: bool,
    pub udp: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EgressConfig {
    pub id: EgressId,
    pub endpoints: Vec<Endpoint>,
    pub public_key: String,
    pub labels: BTreeMap<String, String>,
    pub capabilities: Capabilities,
    pub path_pool: EgressPathPoolConfig,
    pub admission: EgressAdmission,
    /// One Transit binding is shared by every Session for this Egress.
    #[serde(default)]
    pub transit: EgressTransitBinding,
    /// One TrafficPolicy is captured when a Session is attached.
    #[serde(default)]
    pub traffic_policy: Option<TrafficPolicyId>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EgressPathPoolConfig {
    pub min_usable_paths: u32,
    pub target_usable_paths: Option<u32>,
}

impl Default for EgressPathPoolConfig {
    fn default() -> Self {
        Self {
            min_usable_paths: 1,
            target_usable_paths: None,
        }
    }
}

impl EgressPathPoolConfig {
    #[must_use]
    pub fn requested_target_usable_paths(&self) -> u64 {
        self.target_usable_paths
            .map(u64::from)
            .unwrap_or_else(|| u64::from(self.min_usable_paths).saturating_add(1))
    }
}

impl PartialEq for EgressPathPoolConfig {
    fn eq(&self, other: &Self) -> bool {
        self.min_usable_paths == other.min_usable_paths
            && self.requested_target_usable_paths() == other.requested_target_usable_paths()
    }
}

impl Eq for EgressPathPoolConfig {}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EgressAdmission {
    pub required_capabilities: BTreeSet<FlowProtocol>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EgressTransitBinding {
    pub require: Selector,
    pub reject_tags: BTreeSet<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransitSource {
    pub source_type: String,
    pub subscription: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SubscriptionSourceType {
    Static,
    Clash,
    Sip008,
    Auto,
    Uri,
    SingBox,
    Surge,
    Quantumult,
    Loon,
}

impl SubscriptionSourceType {
    pub fn from_name(name: &str) -> Option<Self> {
        Some(match name {
            "static" => Self::Static,
            "clash" | "mihomo" => Self::Clash,
            "sip008" => Self::Sip008,
            "auto" => Self::Auto,
            "uri" | "base64" | "v2ray" => Self::Uri,
            "sing_box" | "sing-box" | "singbox" => Self::SingBox,
            "surge" => Self::Surge,
            "quantumult" | "quantumult_x" | "quantumult-x" => Self::Quantumult,
            "loon" => Self::Loon,
            _ => return None,
        })
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Static => "static",
            Self::Clash => "clash",
            Self::Sip008 => "sip008",
            Self::Auto => "auto",
            Self::Uri => "uri",
            Self::SingBox => "sing_box",
            Self::Surge => "surge",
            Self::Quantumult => "quantumult",
            Self::Loon => "loon",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubscriptionSource {
    pub source_type: SubscriptionSourceType,
    pub url: String,
    pub credentials_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_agent: Option<String>,
}

pub const DEFAULT_SUBSCRIPTION_USER_AGENT: &str = "clash.meta";

/// Keep configured User-Agent values bounded and valid as HTTP header values.
#[must_use]
pub fn valid_subscription_user_agent(value: &str) -> bool {
    !value.trim().is_empty()
        && value.len() <= 1024
        && value.bytes().all(|byte| (b' '..=b'~').contains(&byte))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubscriptionRefresh {
    pub interval_seconds: u64,
    pub timeout_seconds: u64,
    pub max_attempts: u32,
    pub backoff_seconds: u64,
}

impl Default for SubscriptionRefresh {
    fn default() -> Self {
        Self {
            interval_seconds: 3_600,
            timeout_seconds: 30,
            max_attempts: 3,
            backoff_seconds: 5,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubscriptionCache {
    pub path: String,
    pub max_age_seconds: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubscriptionConfig {
    pub id: SubscriptionId,
    pub enabled: bool,
    pub source: SubscriptionSource,
    pub refresh: SubscriptionRefresh,
    pub cache: Option<SubscriptionCache>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DnsRoute {
    Local,
    Transit,
    Egress,
    Blocked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DnsBlockedResponse {
    Nxdomain,
    Refused,
    Servfail,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsLocalConfig {
    pub servers: Vec<Endpoint>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsCacheConfig {
    pub enabled: bool,
    pub max_entries: u32,
    pub max_ttl_seconds: u32,
}

impl Default for DnsCacheConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            max_entries: 100_000,
            max_ttl_seconds: 86_400,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsPolicyConfig {
    pub id: DnsPolicyId,
    pub default_route: DnsRoute,
    pub local: Option<DnsLocalConfig>,
    pub transit_proxy_selector: Option<Selector>,
    pub transit_servers: Vec<Endpoint>,
    pub egress_selector: Option<Selector>,
    pub egress_servers: Vec<Endpoint>,
    pub blocked_response: DnsBlockedResponse,
    pub timeout_seconds: u64,
    pub max_inflight: u32,
    pub cache: DnsCacheConfig,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransitProxyConfig {
    pub id: TransitProxyId,
    pub source: Option<TransitSource>,
    pub protocol: String,
    pub endpoint: Endpoint,
    /// Opaque reference resolved only by a local secret adapter.
    pub credentials_ref: Option<String>,
    pub labels: BTreeMap<String, String>,
    pub tags: BTreeSet<String>,
    pub weight: u32,
    #[serde(default)]
    pub options: TransitOptions,
}

/// Runtime-owned observations are deliberately separate from imported config.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct TransitProxyRuntime {
    pub connected: bool,
    pub rtt_ms: Option<u64>,
    pub jitter_ms: Option<u64>,
    pub loss_rate: Option<f64>,
    pub effective_capacity_bps: Option<u64>,
    pub quota_remaining_ratio: Option<f64>,
    pub quota_reset_at: Option<String>,
    pub traffic_multiplier: Option<f64>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlowMatch {
    pub flow_tags: BTreeSet<String>,
    pub protocols: BTreeSet<FlowProtocol>,
    pub listener_ids: BTreeSet<ListenerId>,
    pub source_networks: Vec<String>,
    pub authentication_identities: BTreeSet<String>,
    pub process_executables: BTreeSet<String>,
    pub target_hosts: BTreeSet<String>,
    /// Canonical geosite set names, optionally followed by `@attribute`.
    #[serde(default)]
    pub target_geo_sites: BTreeSet<String>,
    /// Canonical geoip set names.
    #[serde(default)]
    pub target_geo_ips: BTreeSet<String>,
    pub target_ports: BTreeSet<u16>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Selector {
    pub labels: BTreeMap<String, String>,
    pub tags: BTreeSet<String>,
    pub capabilities: BTreeSet<FlowProtocol>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EgressSelection {
    Id(EgressId),
    Selector(Selector),
    None,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EgressRule {
    pub id: RuleId,
    pub matches: FlowMatch,
    pub egress: EgressSelection,
    pub min_usable_paths: u32,
    pub required_capabilities: BTreeSet<FlowProtocol>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransitRule {
    pub id: RuleId,
    pub egress: EgressId,
    pub matches: FlowMatch,
    pub require: Selector,
    pub reject_tags: BTreeSet<String>,
    pub weight: u32,
    pub traffic_policy: TrafficPolicyId,
    #[serde(default)]
    pub traffic_class: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProxySelection {
    Any,
    Selector(Selector),
    Direct,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProxyRule {
    pub id: RuleId,
    pub matches: FlowMatch,
    pub require: Selector,
    pub select: ProxySelection,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Scheduler {
    #[serde(rename = "effectiveCapacityWeighted")]
    EffectiveCapacityWeighted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RetransmissionReplication {
    Allowed,
    Disabled,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrafficPolicy {
    pub id: TrafficPolicyId,
    pub scheduler: Scheduler,
    pub session_replication_budget_bps: u64,
    pub class_replication_budget_bps: Option<u64>,
    pub retransmission_replication: RetransmissionReplication,
    pub classes: BTreeMap<String, TrafficClass>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrafficClass {
    pub priority: u8,
    pub share: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ListenerKind {
    #[serde(alias = "socks")]
    Socks5,
    Http,
    Mixed,
    Tproxy,
    Redirect,
    Tun,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthenticationMode {
    Required,
    Disabled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum TransparentBackend {
    #[default]
    Tproxy,
    Ebpf,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListenerConfig {
    pub id: ListenerId,
    pub kind: ListenerKind,
    pub platform: String,
    /// Socket bind for socket-based listeners; TUN listeners use their
    /// interface/address fields in the source configuration instead.
    pub bind: Option<Endpoint>,
    pub allowed_sources: Vec<String>,
    pub authentication: AuthenticationMode,
    pub backend: TransparentBackend,
    /// Opaque local secret reference; never contains credential material.
    pub credentials_ref: Option<String>,
    pub mark: Option<u32>,
    pub route_table: Option<u32>,
    pub protocols: BTreeSet<FlowProtocol>,
    pub interface: Option<String>,
    pub address: Option<String>,
    pub mtu: Option<u32>,
    pub bypass: Vec<String>,
    pub proxy_ref: Option<String>,
    pub flow_tags: BTreeSet<String>,
    pub process_metadata: ProcessMetadataRequest,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FallbackAction {
    Reject,
    Direct,
}

/// A namespace-owned, operator-provided V2Fly geosite database.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GeoSiteDatabaseConfig {
    pub id: GeoSiteDatabaseId,
    pub path: String,
}

/// A namespace-owned, operator-provided V2Fly geoip database.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GeoIpDatabaseConfig {
    pub id: GeoIpDatabaseId,
    pub path: String,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct PolicyConfig {
    pub node_probe: Option<NodeProbePolicySpec>,
    pub egresses: Vec<EgressConfig>,
    pub transit_proxies: Vec<TransitProxyConfig>,
    pub subscriptions: Vec<SubscriptionConfig>,
    #[serde(default)]
    pub geo_site_databases: Vec<GeoSiteDatabaseConfig>,
    #[serde(default)]
    pub geo_ip_databases: Vec<GeoIpDatabaseConfig>,
    pub egress_rules: Vec<EgressRule>,
    pub transit_rules: Vec<TransitRule>,
    pub proxy_rules: Vec<ProxyRule>,
    pub traffic_policies: Vec<TrafficPolicy>,
    pub listeners: Vec<ListenerConfig>,
    pub dns_policy: Option<DnsPolicyConfig>,
    /// `None` is accepted only as an unvalidated input so validation can report it.
    pub fallback: Option<FallbackAction>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyDecision {
    Egress {
        selection: EgressSelection,
        proxy_selector: Selector,
        traffic_policy: TrafficPolicyId,
    },
    Proxy {
        selector: Selector,
    },
    Fallback(FallbackAction),
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ValidationError {
    #[error("Egress {egress_id} has an invalid Path-pool field {field}")]
    InvalidEgressPathPool {
        egress_id: String,
        field: &'static str,
    },
    #[error("rule {rule_id} references unknown traffic class {class}")]
    UnknownTrafficClass { rule_id: String, class: String },

    #[error("Transit Proxy {proxy_id} has invalid connection options: {reason}")]
    InvalidTransitOptions {
        proxy_id: String,
        reason: &'static str,
    },
    #[error("global fallback is required")]
    MissingFallback,
    #[error("{kind} id must not be empty")]
    EmptyId { kind: &'static str },
    #[error("{kind} identity or namespace exceeds the 255-byte internal resource limit")]
    ResourceIdentityLimit { kind: &'static str },
    #[error("duplicate {kind} id: {id}")]
    DuplicateId { kind: &'static str, id: String },
    #[error("{kind} {id} uses invalid port 0")]
    InvalidPort { kind: &'static str, id: String },
    #[error("traffic policy {id} class budget {class_bps} exceeds session budget {session_bps}")]
    ClassBudgetExceedsSession {
        id: String,
        class_bps: u64,
        session_bps: u64,
    },
    #[error("Egress rule {rule_id} must require at least one usable Path")]
    ZeroMinUsablePaths { rule_id: String },
    #[error("imported Transit Proxy {proxy_id} label {label} uses a reserved namespace")]
    ReservedImportedLabelNamespace { proxy_id: String, label: String },
    #[error("Transit Proxy {proxy_id} has an invalid credentialsRef")]
    InvalidTransitCredentialReference { proxy_id: String },
    #[error("rule {rule_id} references unknown egress {egress_id}")]
    UnknownEgress { rule_id: String, egress_id: String },
    #[error("rule {rule_id} references unknown traffic policy {policy_id}")]
    UnknownTrafficPolicy { rule_id: String, policy_id: String },
    #[error("Transit Proxy {proxy_id} references unknown subscription {subscription_id}")]
    UnknownSubscription {
        proxy_id: String,
        subscription_id: String,
    },
    #[error("subscription {subscription_id} is invalid: {reason}")]
    InvalidSubscription {
        subscription_id: String,
        reason: &'static str,
    },
    #[error("DNS policy {policy_id} is invalid: {reason}")]
    InvalidDnsPolicy {
        policy_id: String,
        reason: &'static str,
    },
    #[error("geodata configuration for {owner} is invalid: {reason}")]
    InvalidGeoData { owner: String, reason: &'static str },
}

/// Immutable, validated configuration input for [`CompiledPolicy`].
#[derive(Debug, Clone)]
pub struct ValidatedPolicySnapshot {
    generation: Generation,
    config: Arc<PolicyConfig>,
    fallback: FallbackAction,
}

impl ValidatedPolicySnapshot {
    pub fn new(generation: Generation, mut config: PolicyConfig) -> Result<Self, ValidationError> {
        for rule in &mut config.egress_rules {
            normalize_flow_geodata(&mut rule.matches, rule.id.as_str())?;
        }
        for rule in &mut config.transit_rules {
            normalize_flow_geodata(&mut rule.matches, rule.id.as_str())?;
        }
        for rule in &mut config.proxy_rules {
            normalize_flow_geodata(&mut rule.matches, rule.id.as_str())?;
        }
        validate(&config)?;
        let fallback = config.fallback.ok_or(ValidationError::MissingFallback)?;
        Ok(Self {
            generation,
            config: Arc::new(config),
            fallback,
        })
    }

    pub const fn generation(&self) -> Generation {
        self.generation
    }

    pub fn config(&self) -> &PolicyConfig {
        &self.config
    }

    pub const fn fallback(&self) -> FallbackAction {
        self.fallback
    }
}

fn validate(config: &PolicyConfig) -> Result<(), ValidationError> {
    if config.fallback.is_none() {
        return Err(ValidationError::MissingFallback);
    }

    validate_unique(
        "egress",
        config.egresses.iter().map(|item| item.id.as_str()),
    )?;
    for egress in &config.egresses {
        if egress.path_pool.min_usable_paths == 0 {
            return Err(ValidationError::InvalidEgressPathPool {
                egress_id: egress.id.as_str().to_owned(),
                field: "pathPool.minUsablePaths",
            });
        }
        if let Some(target) = egress.path_pool.target_usable_paths
            && (target == 0 || target < egress.path_pool.min_usable_paths)
        {
            return Err(ValidationError::InvalidEgressPathPool {
                egress_id: egress.id.as_str().to_owned(),
                field: "pathPool.targetUsablePaths",
            });
        }
    }
    validate_unique(
        "Transit Proxy",
        config.transit_proxies.iter().map(|item| item.id.as_str()),
    )?;
    validate_unique(
        "subscription",
        config.subscriptions.iter().map(|item| item.id.as_str()),
    )?;
    validate_unique(
        "Egress rule",
        config.egress_rules.iter().map(|item| item.id.as_str()),
    )?;
    validate_unique(
        "Transit rule",
        config.transit_rules.iter().map(|item| item.id.as_str()),
    )?;
    validate_unique(
        "Proxy rule",
        config.proxy_rules.iter().map(|item| item.id.as_str()),
    )?;
    validate_unique(
        "traffic policy",
        config.traffic_policies.iter().map(|item| item.id.as_str()),
    )?;
    validate_unique(
        "listener",
        config.listeners.iter().map(|item| item.id.as_str()),
    )?;
    validate_unique(
        "geosite database",
        config
            .geo_site_databases
            .iter()
            .map(|item| item.id.as_str()),
    )?;
    validate_unique(
        "geoip database",
        config.geo_ip_databases.iter().map(|item| item.id.as_str()),
    )?;

    let mut site_namespaces = HashSet::new();
    for database in &config.geo_site_databases {
        validate_geodata_path(database.id.as_str(), &database.path)?;
        if !site_namespaces.insert(database.id.namespace()) {
            return Err(ValidationError::InvalidGeoData {
                owner: database.id.as_str().to_owned(),
                reason: "only one geosite database is permitted per namespace",
            });
        }
    }
    let mut ip_namespaces = HashSet::new();
    for database in &config.geo_ip_databases {
        validate_geodata_path(database.id.as_str(), &database.path)?;
        if !ip_namespaces.insert(database.id.namespace()) {
            return Err(ValidationError::InvalidGeoData {
                owner: database.id.as_str().to_owned(),
                reason: "only one geoip database is permitted per namespace",
            });
        }
    }
    for (id, matches) in config
        .egress_rules
        .iter()
        .map(|rule| (&rule.id, &rule.matches))
        .chain(
            config
                .transit_rules
                .iter()
                .map(|rule| (&rule.id, &rule.matches)),
        )
        .chain(
            config
                .proxy_rules
                .iter()
                .map(|rule| (&rule.id, &rule.matches)),
        )
    {
        validate_flow_geodata(matches, id.as_str())?;
        if !matches.target_geo_sites.is_empty() && !site_namespaces.contains(id.namespace()) {
            return Err(ValidationError::InvalidGeoData {
                owner: id.as_str().to_owned(),
                reason: "targetGeoSites requires a geosite database in the rule namespace",
            });
        }
        if !matches.target_geo_ips.is_empty() && !ip_namespaces.contains(id.namespace()) {
            return Err(ValidationError::InvalidGeoData {
                owner: id.as_str().to_owned(),
                reason: "targetGeoIps requires a geoip database in the rule namespace",
            });
        }
    }

    for egress in &config.egresses {
        if egress.endpoints.is_empty() {
            return Err(ValidationError::InvalidPort {
                kind: "egress",
                id: egress.id.as_str().to_owned(),
            });
        }
        for endpoint in &egress.endpoints {
            validate_port("egress", egress.id.as_str(), endpoint.port)?;
        }
    }
    for proxy in &config.transit_proxies {
        proxy
            .options
            .validate()
            .map_err(|reason| ValidationError::InvalidTransitOptions {
                proxy_id: proxy.id.as_str().to_owned(),
                reason,
            })?;
        validate_port("Transit Proxy", proxy.id.as_str(), proxy.endpoint.port)?;
        if proxy.credentials_ref.as_ref().is_some_and(|reference| {
            reference.is_empty() || reference.len() > 256 || reference.chars().any(char::is_control)
        }) {
            return Err(ValidationError::InvalidTransitCredentialReference {
                proxy_id: proxy.id.as_str().to_owned(),
            });
        }
        if proxy.source.is_some() {
            for label in proxy.labels.keys() {
                if is_reserved_imported_namespace(label) {
                    return Err(ValidationError::ReservedImportedLabelNamespace {
                        proxy_id: proxy.id.as_str().to_owned(),
                        label: label.clone(),
                    });
                }
            }
        }
    }
    for listener in &config.listeners {
        if let Some(bind) = &listener.bind {
            validate_port("listener", listener.id.as_str(), bind.port)?;
        }
    }
    for subscription in &config.subscriptions {
        validate_subscription(subscription)?;
    }
    if let Some(dns_policy) = &config.dns_policy {
        validate_dns_policy(dns_policy)?;
    }
    for policy in &config.traffic_policies {
        for (name, class) in &policy.classes {
            if name.is_empty()
                || name.len() > 128
                || !name
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
                || !(1..=1_000_000).contains(&class.share)
            {
                return Err(ValidationError::UnknownTrafficClass {
                    rule_id: policy.id.as_str().to_owned(),
                    class: name.clone(),
                });
            }
        }
        if let Some(class_bps) = policy.class_replication_budget_bps
            && class_bps > policy.session_replication_budget_bps
        {
            return Err(ValidationError::ClassBudgetExceedsSession {
                id: policy.id.as_str().to_owned(),
                class_bps,
                session_bps: policy.session_replication_budget_bps,
            });
        }
    }
    for rule in &config.egress_rules {
        if rule.min_usable_paths == 0 {
            return Err(ValidationError::ZeroMinUsablePaths {
                rule_id: rule.id.as_str().to_owned(),
            });
        }
    }

    let egress_ids: HashSet<_> = config
        .egresses
        .iter()
        .map(|item| item.id.as_str())
        .collect();
    for rule in &config.egress_rules {
        if let EgressSelection::Id(egress_id) = &rule.egress {
            validate_egress_reference(rule.id.as_str(), egress_id.as_str(), &egress_ids)?;
            if egress_id.namespace() != rule.id.namespace() {
                return Err(ValidationError::UnknownEgress {
                    rule_id: rule.id.as_str().to_owned(),
                    egress_id: egress_id.as_str().to_owned(),
                });
            }
        }
    }
    for rule in &config.transit_rules {
        validate_egress_reference(rule.id.as_str(), rule.egress.as_str(), &egress_ids)?;
        if rule.egress.namespace() != rule.id.namespace() {
            return Err(ValidationError::UnknownEgress {
                rule_id: rule.id.as_str().to_owned(),
                egress_id: rule.egress.as_str().to_owned(),
            });
        }
    }

    let policy_ids: HashSet<_> = config
        .traffic_policies
        .iter()
        .map(|item| item.id.as_str())
        .collect();
    for egress in &config.egresses {
        if let Some(policy_id) = &egress.traffic_policy
            && (!policy_ids.contains(policy_id.as_str())
                || policy_id.namespace() != egress.id.namespace())
        {
            return Err(ValidationError::UnknownTrafficPolicy {
                rule_id: egress.id.as_str().to_owned(),
                policy_id: policy_id.as_str().to_owned(),
            });
        }
    }
    for rule in &config.transit_rules {
        if !policy_ids.contains(rule.traffic_policy.as_str())
            || rule.traffic_policy.namespace() != rule.id.namespace()
        {
            return Err(ValidationError::UnknownTrafficPolicy {
                rule_id: rule.id.as_str().to_owned(),
                policy_id: rule.traffic_policy.as_str().to_owned(),
            });
        }
    }

    for rule in &config.transit_rules {
        if let Some(class) = &rule.traffic_class {
            let policy = config
                .traffic_policies
                .iter()
                .find(|policy| policy.id == rule.traffic_policy);
            if class.is_empty()
                || class.len() > 128
                || !class
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
                || !policy.is_some_and(|policy| policy.classes.contains_key(class))
            {
                return Err(ValidationError::UnknownTrafficClass {
                    rule_id: rule.id.as_str().to_owned(),
                    class: class.clone(),
                });
            }
        }
    }
    let subscription_ids: HashSet<_> = config
        .subscriptions
        .iter()
        .map(|item| item.id.as_str())
        .collect();
    for proxy in &config.transit_proxies {
        if let Some(source) = &proxy.source
            && source.source_type != "static"
            && (!subscription_ids.contains(source.subscription.as_str())
                || proxy.id.namespace()
                    != ResourceIdentity::from_id(&source.subscription).namespace)
        {
            return Err(ValidationError::UnknownSubscription {
                proxy_id: proxy.id.as_str().to_owned(),
                subscription_id: source.subscription.clone(),
            });
        }
    }

    Ok(())
}

fn validate_geodata_path(owner: &str, path: &str) -> Result<(), ValidationError> {
    if path.trim().is_empty() || path.len() > 4096 || path.chars().any(char::is_control) {
        return Err(ValidationError::InvalidGeoData {
            owner: owner.to_owned(),
            reason: "database path must be non-empty, bounded and contain no control characters",
        });
    }
    Ok(())
}

/// Normalizes a conventional prefixed or bare geodata set reference.
pub fn normalize_geodata_reference(value: &str, geosite: bool) -> Result<String, &'static str> {
    let value = value.to_ascii_lowercase();
    let prefix = if geosite { "geosite:" } else { "geoip:" };
    let value = value.strip_prefix(prefix).unwrap_or(&value);
    let valid_part = |part: &str| {
        !part.is_empty()
            && part.len() <= 255
            && part
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"._-!".contains(&byte))
    };
    let mut parts = value.split('@');
    if !valid_part(parts.next().unwrap_or_default()) {
        return Err("invalid set name");
    }
    if let Some(attribute) = parts.next()
        && (!geosite || !valid_part(attribute) || parts.next().is_some())
    {
        return Err("invalid attribute");
    }
    Ok(value.to_owned())
}

fn normalize_flow_geodata(matches: &mut FlowMatch, owner: &str) -> Result<(), ValidationError> {
    for (values, geosite) in [
        (&mut matches.target_geo_sites, true),
        (&mut matches.target_geo_ips, false),
    ] {
        if values.len() > 256 {
            return Err(ValidationError::InvalidGeoData {
                owner: owner.to_owned(),
                reason: "a geodata match field exceeds 256 references",
            });
        }
        let mut normalized = BTreeSet::new();
        for value in std::mem::take(values) {
            let value = normalize_geodata_reference(&value, geosite).map_err(|reason| {
                ValidationError::InvalidGeoData {
                    owner: owner.to_owned(),
                    reason,
                }
            })?;
            if !normalized.insert(value) {
                return Err(ValidationError::InvalidGeoData {
                    owner: owner.to_owned(),
                    reason: "duplicate geodata reference after normalization",
                });
            }
        }
        *values = normalized;
    }
    Ok(())
}

fn validate_flow_geodata(matches: &FlowMatch, owner: &str) -> Result<(), ValidationError> {
    let mut matches = matches.clone();
    normalize_flow_geodata(&mut matches, owner)
}

fn validate_unique<'a>(
    kind: &'static str,
    ids: impl IntoIterator<Item = &'a str>,
) -> Result<(), ValidationError> {
    let mut seen = HashSet::new();
    for id in ids {
        if id.is_empty() {
            return Err(ValidationError::EmptyId { kind });
        }
        if !ResourceIdentity::from_id(id).is_representable() {
            return Err(ValidationError::ResourceIdentityLimit { kind });
        }
        if !seen.insert(id) {
            return Err(ValidationError::DuplicateId {
                kind,
                id: id.to_owned(),
            });
        }
    }
    Ok(())
}

fn validate_port(kind: &'static str, id: &str, port: u16) -> Result<(), ValidationError> {
    if port == 0 {
        return Err(ValidationError::InvalidPort {
            kind,
            id: id.to_owned(),
        });
    }
    Ok(())
}

fn is_reserved_imported_namespace(label: &str) -> bool {
    ["admin.", "observed.", "quota."]
        .iter()
        .any(|prefix| label.starts_with(prefix))
}

fn validate_egress_reference(
    rule_id: &str,
    egress_id: &str,
    known: &HashSet<&str>,
) -> Result<(), ValidationError> {
    if !known.contains(egress_id) {
        return Err(ValidationError::UnknownEgress {
            rule_id: rule_id.to_owned(),
            egress_id: egress_id.to_owned(),
        });
    }
    Ok(())
}

fn validate_subscription(subscription: &SubscriptionConfig) -> Result<(), ValidationError> {
    let parsed = url::Url::parse(&subscription.source.url).map_err(|_| {
        ValidationError::InvalidSubscription {
            subscription_id: subscription.id.as_str().to_owned(),
            reason: "source URL is invalid",
        }
    })?;
    if !matches!(parsed.scheme(), "http" | "https")
        || !parsed.username().is_empty()
        || parsed.password().is_some()
    {
        return Err(ValidationError::InvalidSubscription {
            subscription_id: subscription.id.as_str().to_owned(),
            reason: "source URL must use HTTP(S) without embedded credentials",
        });
    }
    if subscription
        .source
        .user_agent
        .as_deref()
        .is_some_and(|value| !valid_subscription_user_agent(value))
    {
        return Err(ValidationError::InvalidSubscription {
            subscription_id: subscription.id.as_str().to_owned(),
            reason: "source User-Agent is invalid",
        });
    }
    let refresh = &subscription.refresh;
    if !(60..=604_800).contains(&refresh.interval_seconds)
        || !(1..=300).contains(&refresh.timeout_seconds)
        || !(1..=10).contains(&refresh.max_attempts)
        || !(1..=3_600).contains(&refresh.backoff_seconds)
    {
        return Err(ValidationError::InvalidSubscription {
            subscription_id: subscription.id.as_str().to_owned(),
            reason: "refresh values are outside their allowed ranges",
        });
    }
    if let Some(cache) = &subscription.cache
        && (cache.path.is_empty()
            || cache.path.chars().any(char::is_control)
            || !(60..=2_592_000).contains(&cache.max_age_seconds))
    {
        return Err(ValidationError::InvalidSubscription {
            subscription_id: subscription.id.as_str().to_owned(),
            reason: "cache values are outside their allowed ranges",
        });
    }
    Ok(())
}

fn validate_dns_policy(policy: &DnsPolicyConfig) -> Result<(), ValidationError> {
    if !policy.id.identity().is_representable() {
        return Err(ValidationError::ResourceIdentityLimit { kind: "DNS policy" });
    }
    let invalid = |reason| ValidationError::InvalidDnsPolicy {
        policy_id: policy.id.as_str().to_owned(),
        reason,
    };
    if !(1..=60).contains(&policy.timeout_seconds)
        || !(1..=100_000).contains(&policy.max_inflight)
        || policy.cache.max_entries > 1_000_000
        || !(1..=604_800).contains(&policy.cache.max_ttl_seconds)
    {
        return Err(invalid("limits are outside their allowed ranges"));
    }
    match policy.default_route {
        DnsRoute::Local => {
            let servers = policy.local.as_ref().map(|local| &local.servers);
            if servers.is_none_or(Vec::is_empty) {
                return Err(invalid("local route requires at least one server"));
            }
        }
        DnsRoute::Transit
            if policy
                .transit_proxy_selector
                .as_ref()
                .is_none_or(selector_is_empty)
                || policy.transit_servers.is_empty() =>
        {
            return Err(invalid(
                "transit route requires a proxy selector and server",
            ));
        }
        DnsRoute::Egress
            if policy
                .egress_selector
                .as_ref()
                .is_none_or(selector_is_empty)
                || policy.egress_servers.is_empty() =>
        {
            return Err(invalid(
                "egress route requires an Egress selector and server",
            ));
        }
        _ => {}
    }
    if let Some(local) = &policy.local {
        for server in &local.servers {
            if server.host.is_empty() || server.port == 0 {
                return Err(invalid("local DNS server endpoint is invalid"));
            }
        }
    }
    for server in policy
        .transit_servers
        .iter()
        .chain(policy.egress_servers.iter())
    {
        if server.host.is_empty() || server.port == 0 {
            return Err(invalid("remote DNS server endpoint is invalid"));
        }
    }
    Ok(())
}

fn selector_is_empty(selector: &Selector) -> bool {
    selector.labels.is_empty() && selector.tags.is_empty() && selector.capabilities.is_empty()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_config() -> PolicyConfig {
        PolicyConfig {
            egresses: vec![EgressConfig {
                id: EgressId::new("jp-1"),
                endpoints: vec![Endpoint {
                    host: "egress.example.net".into(),
                    port: 443,
                }],
                public_key: "test-key".into(),
                labels: BTreeMap::new(),
                capabilities: Capabilities {
                    tcp: true,
                    udp: true,
                },
                path_pool: EgressPathPoolConfig::default(),
                admission: EgressAdmission::default(),
                transit: EgressTransitBinding::default(),
                traffic_policy: None,
            }],
            traffic_policies: vec![TrafficPolicy {
                id: TrafficPolicyId::new("default"),
                scheduler: Scheduler::EffectiveCapacityWeighted,
                session_replication_budget_bps: 2_000_000,
                class_replication_budget_bps: Some(1_000_000),
                retransmission_replication: RetransmissionReplication::Allowed,
                classes: BTreeMap::new(),
            }],
            fallback: Some(FallbackAction::Reject),
            ..PolicyConfig::default()
        }
    }

    #[test]
    fn validates_an_immutable_generation_snapshot() {
        let snapshot =
            ValidatedPolicySnapshot::new(Generation::new(7), base_config()).expect("valid config");

        assert_eq!(snapshot.generation().get(), 7);
        assert_eq!(snapshot.fallback(), FallbackAction::Reject);
        assert_eq!(snapshot.config().egresses[0].id.as_str(), "jp-1");
    }

    #[test]
    fn constructed_geodata_configuration_is_normalized_and_namespace_checked() {
        let mut config = base_config();
        config.geo_site_databases.push(GeoSiteDatabaseConfig {
            id: GeoSiteDatabaseId::in_namespace("tenant-a", "domains"),
            path: "../geosite.dat".into(),
        });
        config.proxy_rules.push(ProxyRule {
            id: RuleId::in_namespace("tenant-a", "site-route"),
            matches: FlowMatch {
                target_geo_sites: BTreeSet::from(["GeoSite:HuggingFace".into()]),
                ..Default::default()
            },
            require: Selector::default(),
            select: ProxySelection::Direct,
        });
        let snapshot = ValidatedPolicySnapshot::new(Generation::new(1), config.clone()).unwrap();
        assert_eq!(
            snapshot.config().proxy_rules[0].matches.target_geo_sites,
            BTreeSet::from(["huggingface".into()])
        );
        config.proxy_rules[0].id = RuleId::in_namespace("tenant-b", "site-route");
        assert!(matches!(
            ValidatedPolicySnapshot::new(Generation::new(1), config),
            Err(ValidationError::InvalidGeoData { .. })
        ));
    }

    #[test]
    fn requires_an_explicit_global_fallback() {
        let mut config = base_config();
        config.fallback = None;

        assert_eq!(
            ValidatedPolicySnapshot::new(Generation::new(1), config).unwrap_err(),
            ValidationError::MissingFallback
        );
    }

    #[test]
    fn rejects_duplicate_ids_and_port_zero() {
        let mut duplicate = base_config();
        duplicate.egresses.push(duplicate.egresses[0].clone());
        assert!(matches!(
            ValidatedPolicySnapshot::new(Generation::new(1), duplicate),
            Err(ValidationError::DuplicateId { kind: "egress", .. })
        ));

        let mut invalid_port = base_config();
        invalid_port.egresses[0].endpoints[0].port = 0;
        assert!(matches!(
            ValidatedPolicySnapshot::new(Generation::new(1), invalid_port),
            Err(ValidationError::InvalidPort { kind: "egress", .. })
        ));
    }

    #[test]
    fn rejects_invalid_programmatic_egress_path_pools() {
        let mut config = base_config();
        config.egresses[0].path_pool.min_usable_paths = 0;
        assert!(matches!(
            ValidatedPolicySnapshot::new(Generation::new(1), config),
            Err(ValidationError::InvalidEgressPathPool {
                field: "pathPool.minUsablePaths",
                ..
            })
        ));

        let mut config = base_config();
        config.egresses[0].path_pool = EgressPathPoolConfig {
            min_usable_paths: 2,
            target_usable_paths: Some(1),
        };
        assert!(matches!(
            ValidatedPolicySnapshot::new(Generation::new(1), config),
            Err(ValidationError::InvalidEgressPathPool {
                field: "pathPool.targetUsablePaths",
                ..
            })
        ));
    }

    #[test]
    fn class_replication_budget_cannot_exceed_session_budget() {
        let mut config = base_config();
        config.traffic_policies[0].class_replication_budget_bps = Some(2_000_001);

        assert!(matches!(
            ValidatedPolicySnapshot::new(Generation::new(1), config),
            Err(ValidationError::ClassBudgetExceedsSession { .. })
        ));
    }

    #[test]
    fn egress_rule_requires_at_least_one_usable_path() {
        let mut config = base_config();
        config.egress_rules.push(EgressRule {
            id: RuleId::new("zero-paths"),
            matches: FlowMatch::default(),
            egress: EgressSelection::Id(EgressId::new("jp-1")),
            min_usable_paths: 0,
            required_capabilities: BTreeSet::new(),
        });

        assert_eq!(
            ValidatedPolicySnapshot::new(Generation::new(1), config).unwrap_err(),
            ValidationError::ZeroMinUsablePaths {
                rule_id: "zero-paths".into(),
            }
        );
    }

    #[test]
    fn imported_proxy_cannot_claim_runtime_or_administrator_namespaces() {
        for reserved_label in ["admin.owner", "observed.rtt_ms", "quota.remaining_ratio"] {
            let mut config = base_config();
            config.transit_proxies.push(TransitProxyConfig {
                options: Default::default(),
                id: TransitProxyId::new("provider-node"),
                source: Some(TransitSource {
                    source_type: "clash".into(),
                    subscription: "provider-a".into(),
                }),
                protocol: "socks5".into(),
                endpoint: Endpoint {
                    host: "proxy.example.net".into(),
                    port: 443,
                },
                credentials_ref: None,
                labels: BTreeMap::from([(reserved_label.into(), "spoofed".into())]),
                tags: BTreeSet::new(),
                weight: 100,
            });

            assert_eq!(
                ValidatedPolicySnapshot::new(Generation::new(1), config).unwrap_err(),
                ValidationError::ReservedImportedLabelNamespace {
                    proxy_id: "provider-node".into(),
                    label: reserved_label.into(),
                }
            );
        }
    }

    #[test]
    fn imported_proxy_requires_a_known_subscription() {
        let mut config = base_config();
        config.transit_proxies.push(TransitProxyConfig {
            options: Default::default(),
            id: TransitProxyId::new("provider-node"),
            source: Some(TransitSource {
                source_type: "clash".into(),
                subscription: "missing-provider".into(),
            }),
            protocol: "socks5".into(),
            endpoint: Endpoint {
                host: "proxy.example.net".into(),
                port: 443,
            },
            credentials_ref: None,
            labels: BTreeMap::new(),
            tags: BTreeSet::new(),
            weight: 100,
        });

        assert_eq!(
            ValidatedPolicySnapshot::new(Generation::new(1), config).unwrap_err(),
            ValidationError::UnknownSubscription {
                proxy_id: "provider-node".into(),
                subscription_id: "missing-provider".into(),
            }
        );
    }

    #[test]
    fn transit_credentials_reference_must_be_opaque_and_non_empty() {
        let mut config = base_config();
        config.transit_proxies.push(TransitProxyConfig {
            options: Default::default(),
            id: TransitProxyId::new("private-proxy"),
            source: None,
            protocol: "socks5".into(),
            endpoint: Endpoint {
                host: "proxy.example.net".into(),
                port: 1080,
            },
            credentials_ref: Some(String::new()),
            labels: BTreeMap::new(),
            tags: BTreeSet::new(),
            weight: 100,
        });
        assert_eq!(
            ValidatedPolicySnapshot::new(Generation::new(1), config).unwrap_err(),
            ValidationError::InvalidTransitCredentialReference {
                proxy_id: "private-proxy".into(),
            }
        );
    }

    #[test]
    fn policy_context_and_decision_are_typed_and_mutually_exclusive() {
        let context = PolicyContext {
            flow_tags: BTreeSet::from(["gaming".into()]),
            listener_id: ListenerId::new("lan-socks"),
            source: "192.168.1.10:12345".parse().expect("source address"),
            authentication_identity: Some("alice".into()),
            process: Some(ProcessMetadata {
                process_id: Some(42),
                executable: Some("game.exe".into()),
                user_id: Some(1000),
                group_id: Some(1000),
            }),
            protocol: FlowProtocol::Udp,
            target: TargetEndpoint {
                host: TargetHost::Hostname("game.example".into()),
                port: 443,
            },
        };
        let decision = PolicyDecision::Egress {
            selection: EgressSelection::Id(EgressId::new("jp-1")),
            proxy_selector: Selector::default(),
            traffic_policy: TrafficPolicyId::new("default"),
        };

        assert_eq!(context.protocol, FlowProtocol::Udp);
        assert!(matches!(decision, PolicyDecision::Egress { .. }));
    }

    #[test]
    fn represents_documented_context_and_capability_selectors() {
        let mut config = base_config();
        config.egress_rules.push(EgressRule {
            id: RuleId::new("context-aware"),
            matches: FlowMatch {
                flow_tags: BTreeSet::from(["gaming".into()]),
                protocols: BTreeSet::from([FlowProtocol::Udp]),
                listener_ids: BTreeSet::from([ListenerId::new("lan-socks")]),
                source_networks: vec!["192.168.1.0/24".into()],
                authentication_identities: BTreeSet::from(["alice".into()]),
                process_executables: BTreeSet::from(["game.exe".into()]),
                target_hosts: BTreeSet::from(["game.example".into()]),
                target_ports: BTreeSet::from([443]),
                ..FlowMatch::default()
            },
            egress: EgressSelection::Selector(Selector {
                labels: BTreeMap::from([("region".into(), "jp".into())]),
                tags: BTreeSet::new(),
                capabilities: BTreeSet::from([FlowProtocol::Udp]),
            }),
            min_usable_paths: 1,
            required_capabilities: BTreeSet::new(),
        });

        assert!(ValidatedPolicySnapshot::new(Generation::new(1), config).is_ok());
    }
}
