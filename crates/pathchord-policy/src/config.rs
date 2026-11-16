//! Kubernetes-style `pathchord.io/v1` configuration parsing.
//!
//! The wire/domain model in `lib.rs` remains useful to callers that construct
//! policy snapshots directly. This module owns the human-authored YAML shape,
//! including strict object envelopes and the conversion into that domain model.

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::net::{IpAddr, SocketAddr};

use base64::Engine as _;
use serde::{Deserialize, Serialize};
use serde_yaml::Value;
use thiserror::Error;
use url::Url;

use crate::{
    AuthenticationMode, Capabilities, DnsBlockedResponse, DnsCacheConfig, DnsLocalConfig,
    DnsPolicyConfig, DnsPolicyId, DnsRoute, EgressConfig, EgressId, EgressRule, EgressSelection,
    EgressTransitBinding, Endpoint, FallbackAction, FlowMatch, FlowProtocol, Generation,
    GeoIpDatabaseConfig, GeoIpDatabaseId, GeoSiteDatabaseConfig, GeoSiteDatabaseId, ListenerConfig,
    ListenerId, ListenerKind, PolicyConfig, ProcessMetadataRequest, ProxyRule, ProxySelection,
    RetransmissionReplication, RuleId, Scheduler, Selector, SubscriptionCache, SubscriptionConfig,
    SubscriptionId, SubscriptionRefresh, SubscriptionSource, SubscriptionSourceType, TrafficPolicy,
    TrafficPolicyId, TransitProxyConfig, TransitProxyId, TransitRule, TransitSource,
    TransparentBackend, ValidatedPolicySnapshot,
};

pub const API_VERSION: &str = "pathchord.io/v1";

const MAX_MAP_ENTRIES: usize = 256;
const MAX_MAP_KEY_BYTES: usize = 64;
const MAX_MAP_VALUE_BYTES: usize = 256;
const MAX_WEIGHT: u32 = 1_000_000;
const MAX_EGRESS_ENDPOINTS: usize = 32;
/// Internal marker for a rule without an explicit trafficPolicyRef. Its name
/// cannot be authored as a Kubernetes-style resource name.
pub(crate) const IMPLICIT_SINGLE_TRANSIT_POLICY: &str = "__pathchord_implicit_single_transit";

fn default_namespace() -> String {
    "default".to_owned()
}

fn empty_map() -> BTreeMap<String, String> {
    BTreeMap::new()
}

/// Kubernetes-compatible resource metadata used by all desired objects.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ObjectMeta {
    pub name: String,
    #[serde(default = "default_namespace")]
    pub namespace: String,
    #[serde(default = "empty_map")]
    pub labels: BTreeMap<String, String>,
    #[serde(default = "empty_map")]
    pub annotations: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Resource<T> {
    api_version: String,
    kind: String,
    metadata: ObjectMeta,
    spec: T,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ResourceList {
    api_version: String,
    kind: String,
    metadata: ObjectMeta,
    items: Vec<Value>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EgressSpec {
    address: Option<String>,
    port: Option<u16>,
    #[serde(default)]
    endpoints: Option<Vec<EgressEndpointSpec>>,
    public_key: String,
    #[serde(default)]
    capabilities: Capabilities,
    #[serde(default)]
    status_requirements: RequirementsSpec,
    transit: Option<EgressTransitSpec>,
    traffic_policy_ref: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct EgressEndpointSpec {
    address: String,
    port: u16,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct EgressTransitSpec {
    #[serde(default)]
    require: SelectorSpec,
    #[serde(default)]
    reject: EgressTransitRejectSpec,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct EgressTransitRejectSpec {
    #[serde(default)]
    tags: BTreeSet<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TransitSourceSpec {
    #[serde(rename = "type")]
    source_type: String,
    subscription_ref: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TransitProxySpec {
    source: Option<TransitSourceSpec>,
    protocol: String,
    address: Option<String>,
    port: Option<u16>,
    #[serde(default)]
    tags: BTreeSet<String>,
    #[serde(default = "default_weight")]
    weight: u32,
    credentials_ref: Option<String>,
    #[serde(default)]
    options: crate::TransitOptions,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SubscriptionSourceSpec {
    #[serde(rename = "type")]
    source_type: String,
    url: String,
    credentials_ref: Option<String>,
    user_agent: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RefreshSpec {
    #[serde(default = "default_refresh_interval")]
    interval_seconds: u64,
    #[serde(default = "default_refresh_timeout")]
    timeout_seconds: u64,
    #[serde(default = "default_refresh_attempts")]
    max_attempts: u32,
    #[serde(default = "default_refresh_backoff")]
    backoff_seconds: u64,
}

fn default_refresh_interval() -> u64 {
    3600
}
fn default_refresh_timeout() -> u64 {
    30
}
fn default_refresh_attempts() -> u32 {
    3
}
fn default_refresh_backoff() -> u64 {
    5
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CacheSpec {
    path: String,
    #[serde(default = "default_cache_age")]
    max_age_seconds: u64,
}

fn default_cache_age() -> u64 {
    86_400
}

fn default_weight() -> u32 {
    100
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FlowMatchSpec {
    #[serde(default)]
    flow_tags: BTreeSet<String>,
    #[serde(default)]
    protocols: BTreeSet<FlowProtocol>,
    #[serde(default)]
    listener_refs: BTreeSet<ListenerId>,
    #[serde(default)]
    source_networks: Vec<String>,
    #[serde(default)]
    authentication_identities: BTreeSet<String>,
    #[serde(default)]
    process_executables: BTreeSet<String>,
    #[serde(default)]
    target_hosts: BTreeSet<String>,
    #[serde(default, deserialize_with = "deserialize_geodata_list")]
    target_geo_sites: Option<Vec<String>>,
    #[serde(default, deserialize_with = "deserialize_geodata_list")]
    target_geo_ips: Option<Vec<String>>,
    #[serde(default)]
    target_ports: BTreeSet<u16>,
}

fn deserialize_geodata_list<'de, D>(deserializer: D) -> Result<Option<Vec<String>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Vec::<String>::deserialize(deserializer).map(Some)
}

impl From<FlowMatchSpec> for FlowMatch {
    fn from(value: FlowMatchSpec) -> Self {
        Self {
            flow_tags: value.flow_tags,
            protocols: value.protocols,
            listener_ids: value.listener_refs,
            source_networks: value.source_networks,
            authentication_identities: value.authentication_identities,
            process_executables: value.process_executables,
            target_hosts: value.target_hosts,
            target_geo_sites: value
                .target_geo_sites
                .unwrap_or_default()
                .into_iter()
                .map(|value| crate::normalize_geodata_reference(&value, true).unwrap_or(value))
                .collect(),
            target_geo_ips: value
                .target_geo_ips
                .unwrap_or_default()
                .into_iter()
                .map(|value| crate::normalize_geodata_reference(&value, false).unwrap_or(value))
                .collect(),
            target_ports: value.target_ports,
        }
    }
}

fn qualified_match(value: Option<FlowMatchSpec>, namespace: &str) -> FlowMatch {
    let mut matches: FlowMatch = value.unwrap_or_default().into();
    matches.listener_ids = matches
        .listener_ids
        .into_iter()
        .map(|id| ListenerId::in_namespace(namespace, id.as_str()))
        .collect();
    matches
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SelectorSpec {
    #[serde(default)]
    labels: BTreeMap<String, String>,
    #[serde(default)]
    tags: BTreeSet<String>,
    #[serde(default)]
    capabilities: BTreeSet<FlowProtocol>,
}

impl From<SelectorSpec> for Selector {
    fn from(value: SelectorSpec) -> Self {
        Self {
            labels: value.labels,
            tags: value.tags,
            capabilities: value.capabilities,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RequirementsSpec {
    #[serde(default = "default_min_paths")]
    min_usable_paths: u32,
    #[serde(default)]
    capabilities: BTreeSet<FlowProtocol>,
}

fn default_min_paths() -> u32 {
    1
}

impl Default for RequirementsSpec {
    fn default() -> Self {
        Self {
            min_usable_paths: 1,
            capabilities: BTreeSet::new(),
        }
    }
}

impl From<RequirementsSpec> for crate::EgressStatusRequirements {
    fn from(value: RequirementsSpec) -> Self {
        Self {
            min_usable_paths: value.min_usable_paths,
            capabilities: value.capabilities,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EgressRuleSpec {
    order: u32,
    #[serde(rename = "match")]
    matches: Option<FlowMatchSpec>,
    egress_ref: Option<String>,
    egress_selector: Option<SelectorSpec>,
    mode: Option<String>,
    #[serde(default)]
    requirements: Option<RequirementsSpec>,
    #[serde(default)]
    catch_all: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TransitRuleSpec {
    order: u32,
    egress_ref: String,
    #[serde(rename = "match")]
    matches: Option<FlowMatchSpec>,
    #[serde(default)]
    require: SelectorSpec,
    #[serde(default)]
    reject: SelectorSpec,
    #[serde(default = "default_weight")]
    weight: u32,
    traffic_policy_ref: Option<String>,
    #[serde(default)]
    traffic_class_ref: Option<String>,
    #[serde(default)]
    catch_all: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProxyRuleSpec {
    order: u32,
    #[serde(rename = "match")]
    matches: Option<FlowMatchSpec>,
    #[serde(default)]
    require: SelectorSpec,
    select: Option<ProxySelectSpec>,
    proxy: Option<String>,
    #[serde(default)]
    catch_all: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(untagged)]
pub enum ProxySelectSpec {
    Any(String),
    Selector(SelectorSpec),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
enum ReplicationSpec {
    Allowed,
    Disabled,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TrafficPolicySpec {
    #[serde(default = "default_scheduler")]
    scheduler: String,
    #[serde(default)]
    session_replication_budget_bps: u64,
    class_replication_budget_bps: Option<u64>,
    #[serde(default = "default_replication")]
    retransmission_replication: ReplicationSpec,
    #[serde(default)]
    classes: Option<BTreeMap<String, ClassSpec>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ClassSpec {
    priority: u8,
    share: u32,
}

fn default_scheduler() -> String {
    "effectiveCapacityWeighted".to_owned()
}

fn default_replication() -> ReplicationSpec {
    ReplicationSpec::Disabled
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthenticationSpec {
    #[serde(rename = "mode")]
    mode: AuthenticationMode,
    credentials_ref: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ListenerSpec {
    #[serde(rename = "type")]
    kind: ListenerKind,
    #[serde(default = "default_platform")]
    platform: String,
    #[serde(default)]
    bind: Option<BindSpec>,
    #[serde(default)]
    allowed_sources: Vec<String>,
    #[serde(default)]
    backend: TransparentBackend,
    #[serde(default = "default_authentication_value")]
    authentication: AuthenticationValue,
    #[serde(default)]
    mark: Option<u32>,
    #[serde(default)]
    route_table: Option<u32>,
    #[serde(default)]
    protocols: BTreeSet<FlowProtocol>,
    #[serde(default)]
    interface: Option<String>,
    #[serde(default)]
    address: Option<String>,
    #[serde(default)]
    mtu: Option<u32>,
    #[serde(default)]
    bypass: Vec<String>,
    #[serde(default)]
    proxy_ref: Option<String>,
    #[serde(default)]
    flow_tags: BTreeSet<String>,
    #[serde(default)]
    process_metadata: Option<ProcessMetadataRequest>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(untagged)]
enum BindSpec {
    Address(String),
    Endpoint(Endpoint),
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(untagged)]
enum AuthenticationValue {
    Mode(AuthenticationMode),
    Object(AuthenticationSpec),
}

fn default_authentication_value() -> AuthenticationValue {
    AuthenticationValue::Mode(AuthenticationMode::Disabled)
}

fn default_platform() -> String {
    "any".to_owned()
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DnsLocalSpec {
    servers: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DnsPolicySpec {
    #[serde(default = "default_dns_route")]
    default_route: String,
    local: Option<DnsLocalSpec>,
    transit: Option<DnsSelectorSpec>,
    egress: Option<DnsSelectorSpec>,
    #[serde(default = "default_blocked_response")]
    blocked_response: Option<String>,
    #[serde(default = "default_dns_timeout")]
    timeout_seconds: Option<u64>,
    #[serde(default = "default_dns_max_inflight")]
    max_inflight: Option<u64>,
    cache: Option<DnsCacheSpec>,
}

fn default_dns_route() -> String {
    "local".to_owned()
}

fn default_blocked_response() -> Option<String> {
    Some("refused".to_owned())
}

fn default_dns_timeout() -> Option<u64> {
    Some(5)
}

fn default_dns_max_inflight() -> Option<u64> {
    Some(1024)
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DnsSelectorSpec {
    proxy_selector: Option<SelectorSpec>,
    egress_selector: Option<SelectorSpec>,
    #[serde(default)]
    servers: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DnsCacheSpec {
    #[serde(default)]
    enabled: bool,
    max_entries: Option<u64>,
    max_ttl_seconds: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FallbackPolicySpec {
    action: FallbackAction,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SubscriptionSpec {
    #[serde(default = "default_enabled")]
    enabled: bool,
    source: Option<SubscriptionSourceSpec>,
    refresh: Option<RefreshSpec>,
    cache: Option<CacheSpec>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GeoDataDatabaseSpec {
    path: String,
}

fn default_enabled() -> bool {
    true
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KubeResource {
    EgressService(Resource<crate::EgressServiceSpec>),
    NodeProbePolicy(Resource<crate::NodeProbePolicySpec>),
    Egress(Resource<EgressSpec>),
    TransitProxy(Resource<TransitProxySpec>),
    Subscription(Resource<SubscriptionSpec>),
    GeoSiteDatabase(Resource<GeoDataDatabaseSpec>),
    GeoIpDatabase(Resource<GeoDataDatabaseSpec>),
    EgressRule(Resource<EgressRuleSpec>),
    TransitRule(Resource<TransitRuleSpec>),
    ProxyRule(Resource<ProxyRuleSpec>),
    TrafficPolicy(Resource<TrafficPolicySpec>),
    Listener(Resource<ListenerSpec>),
    DnsPolicy(Resource<DnsPolicySpec>),
    FallbackPolicy(Resource<FallbackPolicySpec>),
}

impl KubeResource {
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::EgressService(_) => "EgressService",
            Self::NodeProbePolicy(_) => "NodeProbePolicy",
            Self::Egress(_) => "Egress",
            Self::TransitProxy(_) => "TransitProxy",
            Self::Subscription(_) => "Subscription",
            Self::GeoSiteDatabase(_) => "GeoSiteDatabase",
            Self::GeoIpDatabase(_) => "GeoIpDatabase",
            Self::EgressRule(_) => "EgressRule",
            Self::TransitRule(_) => "TransitRule",
            Self::ProxyRule(_) => "ProxyRule",
            Self::TrafficPolicy(_) => "TrafficPolicy",
            Self::Listener(_) => "Listener",
            Self::DnsPolicy(_) => "DNSPolicy",
            Self::FallbackPolicy(_) => "FallbackPolicy",
        }
    }

    fn key(&self) -> (&str, &str, &str) {
        match self {
            Self::EgressService(value) => {
                (&value.metadata.namespace, &value.kind, &value.metadata.name)
            }
            Self::NodeProbePolicy(value) => {
                (&value.metadata.namespace, &value.kind, &value.metadata.name)
            }
            Self::Egress(value) => (&value.metadata.namespace, &value.kind, &value.metadata.name),
            Self::TransitProxy(value) => {
                (&value.metadata.namespace, &value.kind, &value.metadata.name)
            }
            Self::Subscription(value) => {
                (&value.metadata.namespace, &value.kind, &value.metadata.name)
            }
            Self::GeoSiteDatabase(value) | Self::GeoIpDatabase(value) => {
                (&value.metadata.namespace, &value.kind, &value.metadata.name)
            }
            Self::EgressRule(value) => {
                (&value.metadata.namespace, &value.kind, &value.metadata.name)
            }
            Self::TransitRule(value) => {
                (&value.metadata.namespace, &value.kind, &value.metadata.name)
            }
            Self::ProxyRule(value) => {
                (&value.metadata.namespace, &value.kind, &value.metadata.name)
            }
            Self::TrafficPolicy(value) => {
                (&value.metadata.namespace, &value.kind, &value.metadata.name)
            }
            Self::Listener(value) => (&value.metadata.namespace, &value.kind, &value.metadata.name),
            Self::DnsPolicy(value) => {
                (&value.metadata.namespace, &value.kind, &value.metadata.name)
            }
            Self::FallbackPolicy(value) => {
                (&value.metadata.namespace, &value.kind, &value.metadata.name)
            }
        }
    }

    fn metadata(&self) -> &ObjectMeta {
        match self {
            Self::EgressService(value) => &value.metadata,
            Self::NodeProbePolicy(value) => &value.metadata,
            Self::Egress(value) => &value.metadata,
            Self::TransitProxy(value) => &value.metadata,
            Self::Subscription(value) => &value.metadata,
            Self::GeoSiteDatabase(value) | Self::GeoIpDatabase(value) => &value.metadata,
            Self::EgressRule(value) => &value.metadata,
            Self::TransitRule(value) => &value.metadata,
            Self::ProxyRule(value) => &value.metadata,
            Self::TrafficPolicy(value) => &value.metadata,
            Self::Listener(value) => &value.metadata,
            Self::DnsPolicy(value) => &value.metadata,
            Self::FallbackPolicy(value) => &value.metadata,
        }
    }

    pub fn egress_service(&self) -> Option<(&ObjectMeta, &crate::EgressServiceSpec)> {
        match self {
            Self::EgressService(value) => Some((&value.metadata, &value.spec)),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KubeConfig {
    pub resources: Vec<KubeResource>,
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("YAML decode failed: {0}")]
    Yaml(#[from] serde_yaml::Error),
    #[error("resource envelope is invalid: {0}")]
    InvalidEnvelope(String),
    #[error("unsupported apiVersion: {0}")]
    UnsupportedApiVersion(String),
    #[error("unsupported resource kind: {0}")]
    UnsupportedKind(String),
    #[error("duplicate resource {kind}/{namespace}/{name}")]
    DuplicateResource {
        kind: String,
        namespace: String,
        name: String,
    },
    #[error("resource {kind}/{name} has invalid spec: {reason}")]
    InvalidSpec {
        kind: String,
        name: String,
        reason: String,
    },
    #[error("resource validation failed: {0}")]
    Validation(#[from] crate::ValidationError),
}

impl KubeConfig {
    pub fn from_yaml(input: &str) -> Result<Self, ConfigError> {
        Self::from_documents([input])
    }

    /// Parses independent source files before validating their combined graph.
    pub fn from_documents<'a>(
        inputs: impl IntoIterator<Item = &'a str>,
    ) -> Result<Self, ConfigError> {
        Self::parse_documents(inputs, true)
    }

    pub fn from_service_documents<'a>(
        inputs: impl IntoIterator<Item = &'a str>,
    ) -> Result<Self, ConfigError> {
        Self::parse_documents(inputs, false)
    }

    fn parse_documents<'a>(
        inputs: impl IntoIterator<Item = &'a str>,
        require_ingress: bool,
    ) -> Result<Self, ConfigError> {
        let mut values = Vec::new();
        for input in inputs {
            for value in serde_yaml::from_str_multi::<Value>(input)? {
                if value == Value::Null {
                    continue;
                }
                if kind_of(&value)? == "List" {
                    let list: ResourceList = serde_yaml::from_value(value)?;
                    check_api_version(&list.api_version)?;
                    if list.kind != "List" {
                        return Err(ConfigError::InvalidEnvelope("kind must be List".into()));
                    }
                    values.extend(list.items);
                } else {
                    values.push(value);
                }
            }
        }

        let mut resources = Vec::with_capacity(values.len());
        let mut keys = HashSet::new();
        for value in values {
            let resource = parse_resource(value)?;
            let (namespace, kind, name) = resource.key();
            if !keys.insert((namespace.to_owned(), kind.to_owned(), name.to_owned())) {
                return Err(ConfigError::DuplicateResource {
                    kind: kind.to_owned(),
                    namespace: namespace.to_owned(),
                    name: name.to_owned(),
                });
            }
            resources.push(resource);
        }
        resources.sort_by(|left, right| left.key().cmp(&right.key()));
        validate_resource_set(&resources, require_ingress)?;
        Ok(Self { resources })
    }

    pub fn into_policy_config(self) -> Result<PolicyConfig, ConfigError> {
        let mut config = PolicyConfig::default();
        let mut egress_rules = Vec::new();
        let mut transit_rules = Vec::new();
        let mut proxy_rules = Vec::new();
        let mut rule_orders = HashSet::new();
        let mut implicit_single_transit_namespaces = BTreeSet::new();
        for resource in self.resources {
            let namespace = resource.metadata().namespace.clone();
            match resource {
                KubeResource::GeoSiteDatabase(value) => {
                    config.geo_site_databases.push(GeoSiteDatabaseConfig {
                        id: GeoSiteDatabaseId::in_namespace(&namespace, &value.metadata.name),
                        path: value.spec.path,
                    });
                }
                KubeResource::GeoIpDatabase(value) => {
                    config.geo_ip_databases.push(GeoIpDatabaseConfig {
                        id: GeoIpDatabaseId::in_namespace(&namespace, &value.metadata.name),
                        path: value.spec.path,
                    });
                }
                KubeResource::Egress(value) => {
                    let policy_name = value
                        .spec
                        .traffic_policy_ref
                        .as_ref()
                        .ok_or_else(|| {
                            invalid_spec(
                                &value.kind,
                                &value.metadata.name,
                                "trafficPolicyRef is required",
                            )
                        })?
                        .clone();
                    let endpoints =
                        normalize_egress_endpoints(&value.spec, &value.kind, &value.metadata.name)?;
                    config.egresses.push(EgressConfig {
                        id: EgressId::in_namespace(&namespace, &value.metadata.name),
                        endpoints,
                        public_key: value.spec.public_key,
                        labels: value.metadata.labels,
                        capabilities: value.spec.capabilities,
                        status_requirements: value.spec.status_requirements.into(),
                        transit: {
                            let transit = value.spec.transit.ok_or_else(|| {
                                invalid_spec(
                                    &value.kind,
                                    &value.metadata.name,
                                    "transit binding is required",
                                )
                            })?;
                            EgressTransitBinding {
                                require: transit.require.into(),
                                reject_tags: transit.reject.tags,
                            }
                        },
                        traffic_policy: Some(TrafficPolicyId::in_namespace(
                            &namespace,
                            &policy_name,
                        )),
                    });
                }
                KubeResource::TransitProxy(value) => {
                    let source = value.spec.source.map(|source| TransitSource {
                        source_type: source.source_type,
                        subscription: source
                            .subscription_ref
                            .map(|name| {
                                SubscriptionId::in_namespace(&namespace, &name)
                                    .as_str()
                                    .to_owned()
                            })
                            .unwrap_or_default(),
                    });
                    let port = value.spec.port.unwrap_or(443);
                    config.transit_proxies.push(TransitProxyConfig {
                        id: TransitProxyId::in_namespace(&namespace, &value.metadata.name),
                        source,
                        protocol: value.spec.protocol,
                        endpoint: Endpoint {
                            host: value.spec.address.unwrap_or_default(),
                            port,
                        },
                        credentials_ref: value.spec.credentials_ref,
                        labels: value.metadata.labels,
                        tags: value.spec.tags,
                        weight: value.spec.weight,
                        options: value.spec.options,
                    });
                }
                KubeResource::EgressRule(value) => {
                    if !rule_orders.insert(value.spec.order) {
                        return Err(ConfigError::InvalidSpec {
                            kind: value.kind,
                            name: value.metadata.name,
                            reason: "duplicate rule order".into(),
                        });
                    }
                    let egress = match (
                        value.spec.egress_ref,
                        value.spec.egress_selector,
                        value.spec.mode,
                    ) {
                        (Some(id), None, None) => {
                            EgressSelection::Id(EgressId::in_namespace(&namespace, &id))
                        }
                        (None, Some(selector), None) => {
                            if selector_empty(&selector) {
                                return Err(ConfigError::InvalidSpec {
                                    kind: value.kind,
                                    name: value.metadata.name,
                                    reason: "egressSelector must contain a criterion".into(),
                                });
                            }
                            EgressSelection::Selector(selector.into())
                        }
                        (None, None, Some(mode)) if mode == "none" => EgressSelection::None,
                        _ => return Err(ConfigError::InvalidSpec {
                            kind: value.kind,
                            name: value.metadata.name,
                            reason:
                                "exactly one of egressRef, egressSelector, or mode:none is required"
                                    .into(),
                        }),
                    };
                    let requirements = value.spec.requirements.unwrap_or_default();
                    egress_rules.push((
                        value.spec.order,
                        EgressRule {
                            id: RuleId::in_namespace(&namespace, &value.metadata.name),
                            matches: qualified_match(value.spec.matches, &namespace),
                            egress,
                            min_usable_paths: requirements.min_usable_paths,
                            required_capabilities: requirements.capabilities,
                        },
                    ));
                }
                KubeResource::TransitRule(value) => {
                    if !rule_orders.insert(value.spec.order) {
                        return Err(ConfigError::InvalidSpec {
                            kind: value.kind,
                            name: value.metadata.name,
                            reason: "duplicate rule order".into(),
                        });
                    }
                    let policy = value.spec.traffic_policy_ref.unwrap_or_else(|| {
                        implicit_single_transit_namespaces.insert(namespace.clone());
                        IMPLICIT_SINGLE_TRANSIT_POLICY.to_owned()
                    });
                    transit_rules.push((
                        value.spec.order,
                        TransitRule {
                            id: RuleId::in_namespace(&namespace, &value.metadata.name),
                            egress: EgressId::in_namespace(&namespace, &value.spec.egress_ref),
                            matches: qualified_match(value.spec.matches, &namespace),
                            require: value.spec.require.into(),
                            reject_tags: value.spec.reject.tags,
                            weight: value.spec.weight,
                            traffic_policy: TrafficPolicyId::in_namespace(&namespace, &policy),
                            traffic_class: value.spec.traffic_class_ref,
                        },
                    ));
                }
                KubeResource::ProxyRule(value) => {
                    if !rule_orders.insert(value.spec.order) {
                        return Err(ConfigError::InvalidSpec {
                            kind: value.kind,
                            name: value.metadata.name,
                            reason: "duplicate rule order".into(),
                        });
                    }
                    if value.spec.proxy.is_some() && value.spec.select.is_some() {
                        return Err(ConfigError::InvalidSpec {
                            kind: value.kind,
                            name: value.metadata.name,
                            reason: "proxy and select are mutually exclusive".into(),
                        });
                    }
                    if value
                        .spec
                        .proxy
                        .as_deref()
                        .is_some_and(|proxy| proxy != "direct")
                    {
                        return Err(ConfigError::InvalidSpec {
                            kind: value.kind,
                            name: value.metadata.name,
                            reason: "proxy must be direct".into(),
                        });
                    }
                    let direct = value.spec.proxy.as_deref() == Some("direct");
                    let select = match (direct, value.spec.select) {
                        (true, None) => ProxySelection::Direct,
                        (false, None) => ProxySelection::Any,
                        (false, Some(ProxySelectSpec::Any(candidate))) if candidate == "any" => {
                            ProxySelection::Any
                        }
                        (false, Some(ProxySelectSpec::Any(selection))) => {
                            return Err(ConfigError::InvalidSpec {
                                kind: value.kind.clone(),
                                name: value.metadata.name.clone(),
                                reason: format!(
                                    "select must be any or a selector, got {selection}"
                                ),
                            });
                        }
                        (false, Some(ProxySelectSpec::Selector(selector))) => {
                            ProxySelection::Selector(selector.into())
                        }
                        (true, Some(_)) => {
                            unreachable!("proxy and select were validated as exclusive")
                        }
                    };
                    proxy_rules.push((
                        value.spec.order,
                        ProxyRule {
                            id: RuleId::in_namespace(&namespace, &value.metadata.name),
                            matches: qualified_match(value.spec.matches, &namespace),
                            require: value.spec.require.into(),
                            select,
                        },
                    ));
                }
                KubeResource::TrafficPolicy(value) => {
                    if value.spec.scheduler != "effectiveCapacityWeighted" {
                        return Err(ConfigError::InvalidSpec {
                            kind: value.kind,
                            name: value.metadata.name,
                            reason: "scheduler must be effectiveCapacityWeighted".into(),
                        });
                    }
                    if value.spec.class_replication_budget_bps.is_some()
                        || value.spec.classes.is_some()
                    {
                        return Err(invalid_spec(
                            &value.kind,
                            &value.metadata.name,
                            "TrafficPolicy class fields are retired",
                        ));
                    }
                    config.traffic_policies.push(TrafficPolicy {
                        id: TrafficPolicyId::in_namespace(&namespace, &value.metadata.name),
                        scheduler: Scheduler::EffectiveCapacityWeighted,
                        session_replication_budget_bps: value.spec.session_replication_budget_bps,
                        class_replication_budget_bps: value.spec.class_replication_budget_bps,
                        retransmission_replication: match value.spec.retransmission_replication {
                            ReplicationSpec::Allowed => RetransmissionReplication::Allowed,
                            ReplicationSpec::Disabled => RetransmissionReplication::Disabled,
                        },
                        classes: BTreeMap::new(),
                    });
                }
                KubeResource::Listener(value) => {
                    if value.spec.platform != "any" && value.spec.platform != std::env::consts::OS {
                        return Err(ConfigError::InvalidSpec {
                            kind: value.kind,
                            name: value.metadata.name,
                            reason: format!(
                                "listener platform {} is not supported by this build",
                                value.spec.platform
                            ),
                        });
                    }
                    validate_listener_kind_for_platform(&value, std::env::consts::OS)?;
                    let bind = match value.spec.bind.as_ref() {
                        Some(bind) => {
                            Some(parse_bind(bind).map_err(|reason| ConfigError::InvalidSpec {
                                kind: value.kind.clone(),
                                name: value.metadata.name.clone(),
                                reason,
                            })?)
                        }
                        None => None,
                    };
                    let (authentication, credentials_ref) = match value.spec.authentication {
                        AuthenticationValue::Mode(mode) => (mode, None),
                        AuthenticationValue::Object(auth) => {
                            if auth.mode == AuthenticationMode::Required
                                && auth.credentials_ref.as_deref().is_none_or(str::is_empty)
                            {
                                return Err(ConfigError::InvalidSpec {
                                    kind: value.kind,
                                    name: value.metadata.name,
                                    reason: "credentialsRef is required when authentication mode is required".into(),
                                });
                            }
                            (auth.mode, auth.credentials_ref)
                        }
                    };
                    let protocols = if value.spec.protocols.is_empty() {
                        match value.spec.kind {
                            ListenerKind::Http | ListenerKind::Socks5 | ListenerKind::Redirect => {
                                BTreeSet::from([FlowProtocol::Tcp])
                            }
                            ListenerKind::Mixed | ListenerKind::Tproxy | ListenerKind::Tun => {
                                BTreeSet::from([FlowProtocol::Tcp, FlowProtocol::Udp])
                            }
                        }
                    } else {
                        value.spec.protocols
                    };
                    config.listeners.push(ListenerConfig {
                        id: ListenerId::in_namespace(&namespace, &value.metadata.name),
                        kind: value.spec.kind,
                        platform: value.spec.platform,
                        bind,
                        allowed_sources: value.spec.allowed_sources,
                        authentication,
                        backend: value.spec.backend,
                        credentials_ref,
                        mark: value.spec.mark,
                        route_table: value.spec.route_table,
                        protocols,
                        interface: value.spec.interface,
                        address: value.spec.address,
                        mtu: value.spec.mtu,
                        bypass: value.spec.bypass,
                        proxy_ref: value.spec.proxy_ref.map(|name| {
                            TransitProxyId::in_namespace(&namespace, &name)
                                .as_str()
                                .to_owned()
                        }),
                        flow_tags: value.spec.flow_tags,
                        process_metadata: value.spec.process_metadata.unwrap_or_default(),
                    });
                }
                KubeResource::Subscription(value) => {
                    let source = value
                        .spec
                        .source
                        .expect("validated Subscription source is present");
                    let source_type = SubscriptionSourceType::from_name(&source.source_type)
                        .expect("validated Subscription source type");
                    let refresh = value
                        .spec
                        .refresh
                        .map(|refresh| SubscriptionRefresh {
                            interval_seconds: refresh.interval_seconds,
                            timeout_seconds: refresh.timeout_seconds,
                            max_attempts: refresh.max_attempts,
                            backoff_seconds: refresh.backoff_seconds,
                        })
                        .unwrap_or_default();
                    let cache = value.spec.cache.map(|cache| SubscriptionCache {
                        path: cache.path,
                        max_age_seconds: cache.max_age_seconds,
                    });
                    config.subscriptions.push(SubscriptionConfig {
                        id: SubscriptionId::in_namespace(&namespace, &value.metadata.name),
                        enabled: value.spec.enabled,
                        source: SubscriptionSource {
                            source_type,
                            url: source.url,
                            credentials_ref: source.credentials_ref,
                            user_agent: source.user_agent,
                        },
                        refresh,
                        cache,
                    });
                }
                KubeResource::DnsPolicy(value) => {
                    let convert_servers = |servers: &[String]| {
                        servers
                            .iter()
                            .map(|server| {
                                parse_dns_server(server).map_err(|reason| {
                                    invalid_spec(&value.kind, &value.metadata.name, reason)
                                })
                            })
                            .collect::<Result<Vec<_>, _>>()
                    };
                    let default_route = match value.spec.default_route.as_str() {
                        "local" => DnsRoute::Local,
                        "transit" => DnsRoute::Transit,
                        "egress" => DnsRoute::Egress,
                        "blocked" => DnsRoute::Blocked,
                        _ => unreachable!("validated DNS route"),
                    };
                    let local = value
                        .spec
                        .local
                        .map(|local| {
                            convert_servers(&local.servers)
                                .map(|servers| DnsLocalConfig { servers })
                        })
                        .transpose()?;
                    let transit_proxy_selector = value
                        .spec
                        .transit
                        .as_ref()
                        .and_then(|selector| selector.proxy_selector.clone())
                        .map(Selector::from);
                    let transit_servers = value
                        .spec
                        .transit
                        .as_ref()
                        .map(|route| convert_servers(&route.servers))
                        .transpose()?
                        .unwrap_or_default();
                    let egress_selector = value
                        .spec
                        .egress
                        .as_ref()
                        .and_then(|selector| selector.egress_selector.clone())
                        .map(Selector::from);
                    let egress_servers = value
                        .spec
                        .egress
                        .as_ref()
                        .map(|route| convert_servers(&route.servers))
                        .transpose()?
                        .unwrap_or_default();
                    let blocked_response = match value.spec.blocked_response.as_deref() {
                        Some("nxdomain") => DnsBlockedResponse::Nxdomain,
                        Some("servfail") => DnsBlockedResponse::Servfail,
                        Some("refused") | None => DnsBlockedResponse::Refused,
                        Some(_) => unreachable!("validated blocked response"),
                    };
                    let cache = value
                        .spec
                        .cache
                        .map_or_else(DnsCacheConfig::default, |cache| DnsCacheConfig {
                            enabled: cache.enabled,
                            max_entries: cache.max_entries.unwrap_or(100_000) as u32,
                            max_ttl_seconds: cache.max_ttl_seconds.unwrap_or(86_400) as u32,
                        });
                    config.dns_policy = Some(DnsPolicyConfig {
                        id: DnsPolicyId::in_namespace(&namespace, &value.metadata.name),
                        default_route,
                        local,
                        transit_proxy_selector,
                        transit_servers,
                        egress_selector,
                        egress_servers,
                        blocked_response,
                        timeout_seconds: value.spec.timeout_seconds.unwrap_or(5),
                        max_inflight: value.spec.max_inflight.unwrap_or(1_024) as u32,
                        cache,
                    });
                }
                KubeResource::FallbackPolicy(value) => config.fallback = Some(value.spec.action),
                KubeResource::EgressService(_) => {}
                KubeResource::NodeProbePolicy(value) => config.node_probe = Some(value.spec),
            }
        }
        for namespace in implicit_single_transit_namespaces {
            let mut implicit = config
                .traffic_policies
                .iter()
                .find(|policy| policy.id == TrafficPolicyId::in_namespace(&namespace, "default"))
                .cloned()
                .unwrap_or_else(|| TrafficPolicy {
                    id: TrafficPolicyId::in_namespace(&namespace, IMPLICIT_SINGLE_TRANSIT_POLICY),
                    scheduler: Scheduler::EffectiveCapacityWeighted,
                    session_replication_budget_bps: 0,
                    class_replication_budget_bps: None,
                    retransmission_replication: RetransmissionReplication::Disabled,
                    classes: BTreeMap::new(),
                });
            implicit.id = TrafficPolicyId::in_namespace(&namespace, IMPLICIT_SINGLE_TRANSIT_POLICY);
            config.traffic_policies.push(implicit);
        }
        egress_rules.sort_by_key(|(order, _)| *order);
        transit_rules.sort_by_key(|(order, _)| *order);
        proxy_rules.sort_by_key(|(order, _)| *order);
        config.egress_rules = egress_rules.into_iter().map(|(_, rule)| rule).collect();
        config.transit_rules = transit_rules.into_iter().map(|(_, rule)| rule).collect();
        config.proxy_rules = proxy_rules.into_iter().map(|(_, rule)| rule).collect();
        crate::validate(&config)?;
        Ok(config)
    }

    pub fn into_validated_snapshot(
        self,
        generation: Generation,
    ) -> Result<ValidatedPolicySnapshot, ConfigError> {
        Ok(ValidatedPolicySnapshot::new(
            generation,
            self.into_policy_config()?,
        )?)
    }
}

fn check_api_version(version: &str) -> Result<(), ConfigError> {
    if version == API_VERSION {
        Ok(())
    } else {
        Err(ConfigError::UnsupportedApiVersion(version.to_owned()))
    }
}

fn parse_bind(bind: &BindSpec) -> Result<Endpoint, String> {
    match bind {
        BindSpec::Endpoint(endpoint) => Ok(endpoint.clone()),
        BindSpec::Address(value) => {
            if let Ok(socket) = value.parse::<SocketAddr>() {
                return Ok(Endpoint {
                    host: socket.ip().to_string(),
                    port: socket.port(),
                });
            }
            let (host, port) = value
                .rsplit_once(':')
                .ok_or_else(|| "bind must be host:port".to_owned())?;
            let port = port
                .parse::<u16>()
                .map_err(|_| "bind port is invalid".to_owned())?;
            if port == 0 || host.is_empty() {
                return Err("bind must contain a non-zero port and host".to_owned());
            }
            Ok(Endpoint {
                host: host
                    .trim_start_matches('[')
                    .trim_end_matches(']')
                    .to_owned(),
                port,
            })
        }
    }
}

fn kind_of(value: &Value) -> Result<String, ConfigError> {
    let map = value
        .as_mapping()
        .ok_or_else(|| ConfigError::InvalidEnvelope("object must be a mapping".into()))?;
    map.get("kind")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| ConfigError::InvalidEnvelope("kind is required".into()))
}

fn parse_resource(value: Value) -> Result<KubeResource, ConfigError> {
    let kind = kind_of(&value)?;
    macro_rules! parse {
        ($ty:ty, $variant:ident) => {{
            let resource: Resource<$ty> = serde_yaml::from_value(value)?;
            check_api_version(&resource.api_version)?;
            if resource.kind != kind {
                return Err(ConfigError::InvalidEnvelope("kind mismatch".into()));
            }
            Ok(KubeResource::$variant(resource))
        }};
    }
    match kind.as_str() {
        "EgressService" => parse!(crate::EgressServiceSpec, EgressService),
        "NodeProbePolicy" => parse!(crate::NodeProbePolicySpec, NodeProbePolicy),
        "Egress" => parse!(EgressSpec, Egress),
        "TransitProxy" => parse!(TransitProxySpec, TransitProxy),
        "Subscription" => parse!(SubscriptionSpec, Subscription),
        "GeoSiteDatabase" => parse!(GeoDataDatabaseSpec, GeoSiteDatabase),
        "GeoIpDatabase" => parse!(GeoDataDatabaseSpec, GeoIpDatabase),
        "EgressRule" => parse!(EgressRuleSpec, EgressRule),
        "TransitRule" => parse!(TransitRuleSpec, TransitRule),
        "ProxyRule" => parse!(ProxyRuleSpec, ProxyRule),
        "TrafficPolicy" => parse!(TrafficPolicySpec, TrafficPolicy),
        "Listener" => parse!(ListenerSpec, Listener),
        "DNSPolicy" => parse!(DnsPolicySpec, DnsPolicy),
        "FallbackPolicy" => parse!(FallbackPolicySpec, FallbackPolicy),
        other => Err(ConfigError::UnsupportedKind(other.to_owned())),
    }
}

fn validate_resource_set(
    resources: &[KubeResource],
    require_ingress: bool,
) -> Result<(), ConfigError> {
    let resource_keys: HashSet<_> = resources.iter().map(KubeResource::key).collect();
    let dns = resources
        .iter()
        .filter(|resource| matches!(resource, KubeResource::DnsPolicy(_)))
        .count();
    let fallback = resources
        .iter()
        .filter(|resource| matches!(resource, KubeResource::FallbackPolicy(_)))
        .count();
    if require_ingress && dns != 1 {
        return Err(ConfigError::InvalidEnvelope(
            "exactly one DNSPolicy is required".into(),
        ));
    }
    if require_ingress && fallback != 1 {
        return Err(ConfigError::InvalidEnvelope(
            "exactly one FallbackPolicy is required".into(),
        ));
    }
    let mut rule_orders = HashSet::new();
    let mut geo_site_namespaces = HashSet::new();
    let mut geo_ip_namespaces = HashSet::new();
    for resource in resources {
        let (database, namespaces, kind) = match resource {
            KubeResource::GeoSiteDatabase(value) => {
                (value, &mut geo_site_namespaces, "GeoSiteDatabase")
            }
            KubeResource::GeoIpDatabase(value) => (value, &mut geo_ip_namespaces, "GeoIpDatabase"),
            _ => continue,
        };
        if database.spec.path.trim().is_empty()
            || database.spec.path.len() > 4096
            || contains_control(&database.spec.path)
        {
            return Err(invalid_spec(
                kind,
                &database.metadata.name,
                "path is empty or invalid",
            ));
        }
        if !namespaces.insert(database.metadata.namespace.as_str()) {
            return Err(invalid_spec(
                kind,
                &database.metadata.name,
                "at most one database of this kind is permitted per namespace",
            ));
        }
    }
    if resources
        .iter()
        .filter(|resource| matches!(resource, KubeResource::NodeProbePolicy(_)))
        .count()
        > 1
    {
        return Err(ConfigError::InvalidEnvelope(
            "at most one NodeProbePolicy is permitted".to_owned(),
        ));
    }
    for resource in resources {
        validate_metadata(resource.metadata())?;
        let matches = match resource {
            KubeResource::EgressRule(value) => value.spec.matches.as_ref(),
            KubeResource::TransitRule(value) => value.spec.matches.as_ref(),
            KubeResource::ProxyRule(value) => value.spec.matches.as_ref(),
            _ => None,
        };
        if let Some(matches) = matches {
            if matches.target_geo_sites.is_some()
                && !geo_site_namespaces.contains(resource.metadata().namespace.as_str())
            {
                return Err(invalid_spec(
                    resource.key().1,
                    resource.key().2,
                    "targetGeoSites requires a GeoSiteDatabase in this namespace",
                ));
            }
            if matches.target_geo_ips.is_some()
                && !geo_ip_namespaces.contains(resource.metadata().namespace.as_str())
            {
                return Err(invalid_spec(
                    resource.key().1,
                    resource.key().2,
                    "targetGeoIps requires a GeoIpDatabase in this namespace",
                ));
            }
            for listener in &matches.listener_refs {
                if !resource_keys.contains(&(
                    resource.metadata().namespace.as_str(),
                    "Listener",
                    listener.as_str(),
                )) {
                    return Err(invalid_spec(
                        resource.key().1,
                        resource.key().2,
                        "listenerRefs references an unknown Listener in this namespace",
                    ));
                }
            }
        }
        match resource {
            KubeResource::EgressService(value) => value
                .spec
                .validate()
                .map_err(|reason| invalid_spec(&value.kind, &value.metadata.name, reason))?,
            KubeResource::NodeProbePolicy(value) => value
                .spec
                .validate()
                .map_err(|reason| invalid_spec(&value.kind, &value.metadata.name, reason))?,
            KubeResource::Egress(value) => {
                validate_egress_spec(value)?;
                if value
                    .spec
                    .traffic_policy_ref
                    .as_deref()
                    .is_none_or(str::is_empty)
                {
                    return Err(invalid_spec(
                        &value.kind,
                        &value.metadata.name,
                        "trafficPolicyRef is required",
                    ));
                }
                if value.spec.transit.is_none() {
                    return Err(invalid_spec(
                        &value.kind,
                        &value.metadata.name,
                        "transit binding is required",
                    ));
                }
            }
            KubeResource::TransitProxy(value) => {
                validate_transit_proxy_spec(value)?;
            }
            KubeResource::Subscription(value) => {
                validate_subscription_spec(value)?;
            }
            KubeResource::EgressRule(value) => {
                if value.spec.requirements.is_some() {
                    return Err(invalid_spec(
                        &value.kind,
                        &value.metadata.name,
                        "EgressRule requirements are retired; configure the Egress minimum",
                    ));
                }
                validate_flow_match(
                    value.spec.matches.as_ref(),
                    &value.kind,
                    &value.metadata.name,
                )?;
                validate_rule_spec(
                    value.kind.as_str(),
                    &value.metadata.name,
                    value.spec.order,
                    value.spec.matches.as_ref(),
                    value.spec.catch_all,
                )?;
            }
            KubeResource::TransitRule(value) => {
                return Err(invalid_spec(
                    &value.kind,
                    &value.metadata.name,
                    "TransitRule resources are retired; configure Transit on the Egress",
                ));
            }
            KubeResource::ProxyRule(value) => {
                validate_flow_match(
                    value.spec.matches.as_ref(),
                    &value.kind,
                    &value.metadata.name,
                )?;
                validate_rule_spec(
                    value.kind.as_str(),
                    &value.metadata.name,
                    value.spec.order,
                    value.spec.matches.as_ref(),
                    value.spec.catch_all,
                )?;
            }
            KubeResource::TrafficPolicy(value) => {
                validate_traffic_policy_spec(value)?;
            }
            KubeResource::Listener(value) => {
                validate_listener_spec(value)?;
            }
            _ => {}
        }
        let order = match resource {
            KubeResource::EgressRule(value) => Some(value.spec.order),
            KubeResource::TransitRule(value) => Some(value.spec.order),
            KubeResource::ProxyRule(value) => Some(value.spec.order),
            _ => None,
        };
        if let Some(order) = order
            && !rule_orders.insert(order)
        {
            return Err(ConfigError::InvalidSpec {
                kind: resource.key().1.to_owned(),
                name: resource.key().2.to_owned(),
                reason: "duplicate rule order".into(),
            });
        }
        if let KubeResource::DnsPolicy(value) = resource {
            validate_dns_policy_spec(value)?;
        }
        if let KubeResource::TransitProxy(value) = resource
            && let Some(source) = &value.spec.source
            && source.source_type != "static"
            && source.subscription_ref.as_deref().is_none_or(str::is_empty)
        {
            return Err(ConfigError::InvalidSpec {
                kind: value.kind.clone(),
                name: value.metadata.name.clone(),
                reason: "subscriptionRef is required for non-static proxy source".into(),
            });
        }
    }
    Ok(())
}

fn validate_metadata(metadata: &ObjectMeta) -> Result<(), ConfigError> {
    let name = &metadata.name;
    let namespace = &metadata.namespace;
    let valid_name = valid_resource_name(name);
    if namespace.is_empty() || contains_control(namespace) {
        return Err(ConfigError::InvalidEnvelope(format!(
            "invalid metadata name or namespace: {namespace}/{name}"
        )));
    }
    if !valid_name {
        return Err(ConfigError::InvalidEnvelope(format!(
            "invalid metadata name or namespace: {namespace}/{name}"
        )));
    }
    let identity = crate::ResourceIdentity { namespace, name };
    if !identity.is_representable() {
        return Err(ConfigError::Validation(
            crate::ValidationError::ResourceIdentityLimit { kind: "resource" },
        ));
    }
    validate_string_map("metadata.labels", &metadata.labels).map_err(|reason| {
        ConfigError::InvalidSpec {
            kind: "metadata".into(),
            name: name.clone(),
            reason,
        }
    })?;
    validate_string_map("metadata.annotations", &metadata.annotations).map_err(|reason| {
        ConfigError::InvalidSpec {
            kind: "metadata".into(),
            name: name.clone(),
            reason,
        }
    })?;
    Ok(())
}

fn valid_resource_name(value: &str) -> bool {
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && value.len() <= 63
        && bytes
            .first()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        && bytes
            .last()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
}

fn valid_spec_identifier(value: &str) -> bool {
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 128
        && bytes
            .first()
            .is_some_and(|byte| byte.is_ascii_alphanumeric())
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(*byte, b'.' | b'_' | b'-'))
}

fn validate_tag_set(field: &str, values: &BTreeSet<String>) -> Result<(), String> {
    if values.len() > MAX_MAP_ENTRIES {
        return Err(format!("{field} has too many entries"));
    }
    if values.iter().any(|value| !valid_spec_identifier(value)) {
        return Err(format!("{field} contains an invalid tag"));
    }
    Ok(())
}

fn validate_string_map(field: &str, values: &BTreeMap<String, String>) -> Result<(), String> {
    if values.len() > MAX_MAP_ENTRIES {
        return Err(format!("{field} has too many entries"));
    }
    for (key, value) in values {
        if key.is_empty() || key.len() > MAX_MAP_KEY_BYTES {
            return Err(format!("{field} key length is invalid"));
        }
        if value.len() > MAX_MAP_VALUE_BYTES {
            return Err(format!("{field}.{key} value is too long"));
        }
        if contains_control(key) || contains_control(value) {
            return Err(format!("{field}.{key} contains a control character"));
        }
    }
    Ok(())
}

fn contains_control(value: &str) -> bool {
    value.chars().any(char::is_control)
}

fn invalid_spec(resource: &str, name: &str, reason: impl Into<String>) -> ConfigError {
    ConfigError::InvalidSpec {
        kind: resource.to_owned(),
        name: name.to_owned(),
        reason: reason.into(),
    }
}

fn validate_host(field: &str, host: &str) -> Result<(), String> {
    if host.is_empty() || host.len() > 255 || contains_control(host) {
        return Err(format!(
            "{field} must be a non-empty hostname or IP literal"
        ));
    }
    if host.parse::<IpAddr>().is_ok() {
        return Ok(());
    }
    for label in host.trim_end_matches('.').split('.') {
        if label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err(format!("{field} is not a valid DNS hostname"));
        }
    }
    Ok(())
}

fn validate_public_key(key: &str) -> Result<(), String> {
    if key.contains('=') {
        return Err("publicKey must be unpadded base64url".into());
    }
    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(key)
        .map_err(|_| "publicKey must be unpadded base64url".to_owned())?;
    if decoded.len() != 32 {
        return Err("publicKey must decode to exactly 32 bytes".into());
    }
    Ok(())
}

fn validate_egress_spec(value: &Resource<EgressSpec>) -> Result<(), ConfigError> {
    let kind = value.kind.as_str();
    let name = value.metadata.name.as_str();
    normalize_egress_endpoints(&value.spec, kind, name)?;
    validate_public_key(&value.spec.public_key)
        .map_err(|reason| invalid_spec(kind, name, reason))?;
    if !value.spec.capabilities.tcp && !value.spec.capabilities.udp {
        return Err(invalid_spec(
            kind,
            name,
            "at least one Egress capability must be enabled",
        ));
    }
    Ok(())
}

fn normalize_egress_endpoints(
    spec: &EgressSpec,
    kind: &str,
    name: &str,
) -> Result<Vec<Endpoint>, ConfigError> {
    let legacy_present = spec.address.is_some() || spec.port.is_some();
    if legacy_present && spec.endpoints.is_some() {
        return Err(invalid_spec(
            kind,
            name,
            "address/port and endpoints are mutually exclusive",
        ));
    }

    let raw = if let Some(endpoints) = &spec.endpoints {
        if endpoints.is_empty() || endpoints.len() > MAX_EGRESS_ENDPOINTS {
            return Err(invalid_spec(
                kind,
                name,
                "endpoints must contain between 1 and 32 entries",
            ));
        }
        endpoints
            .iter()
            .map(|endpoint| (&endpoint.address, endpoint.port))
            .collect::<Vec<_>>()
    } else {
        match (&spec.address, spec.port) {
            (Some(address), Some(port)) => vec![(address, port)],
            (None, None) => {
                return Err(invalid_spec(
                    kind,
                    name,
                    "address/port or endpoints is required",
                ));
            }
            _ => {
                return Err(invalid_spec(
                    kind,
                    name,
                    "address and port must be supplied together",
                ));
            }
        }
    };

    let mut seen = BTreeSet::new();
    let mut normalized = Vec::with_capacity(raw.len());
    for (address, port) in raw {
        validate_host("address", address).map_err(|reason| invalid_spec(kind, name, reason))?;
        if port == 0 {
            return Err(invalid_spec(kind, name, "endpoint port must be non-zero"));
        }
        let host = normalize_endpoint_host(address);
        if !seen.insert((host.clone(), port)) {
            return Err(invalid_spec(
                kind,
                name,
                "endpoints contain a duplicate address and port",
            ));
        }
        normalized.push(Endpoint { host, port });
    }
    Ok(normalized)
}

fn normalize_endpoint_host(host: &str) -> String {
    if let Ok(address) = host.parse::<IpAddr>() {
        address.to_string()
    } else {
        host.trim_end_matches('.').to_ascii_lowercase()
    }
}

fn validate_transit_proxy_spec(value: &Resource<TransitProxySpec>) -> Result<(), ConfigError> {
    let kind = value.kind.as_str();
    let name = value.metadata.name.as_str();
    value
        .spec
        .options
        .validate()
        .map_err(|reason| invalid_spec(kind, name, reason))?;
    const PROTOCOLS: &[&str] = &[
        "direct",
        "http",
        "https",
        "socks4",
        "socks4a",
        "socks5",
        "ss",
        "vless",
        "vmess",
        "xtls",
        "trojan",
        "hysteria",
        "hysteria2",
        "tuic",
        "wireguard",
        "ssh",
        "shadowtls",
        "anytls",
        "snell",
    ];
    if !PROTOCOLS.contains(&value.spec.protocol.as_str()) {
        return Err(invalid_spec(
            kind,
            name,
            "protocol is not a registered adapter",
        ));
    }
    if !(1..=MAX_WEIGHT).contains(&value.spec.weight) {
        return Err(invalid_spec(kind, name, "weight must be in 1..=1000000"));
    }
    if value
        .spec
        .credentials_ref
        .as_ref()
        .is_some_and(|reference| {
            reference.is_empty()
                || reference.len() > MAX_MAP_VALUE_BYTES
                || contains_control(reference)
        })
    {
        return Err(invalid_spec(
            kind,
            name,
            "credentialsRef must be a non-empty opaque reference",
        ));
    }
    if let Some(source) = &value.spec.source {
        if SubscriptionSourceType::from_name(&source.source_type).is_none() {
            return Err(invalid_spec(
                kind,
                name,
                "source.type is not a recognized subscription format",
            ));
        }
        if source.source_type != "static"
            && source.subscription_ref.as_deref().is_none_or(str::is_empty)
        {
            return Err(invalid_spec(
                kind,
                name,
                "subscriptionRef is required for non-static source",
            ));
        }
    }
    if value.spec.protocol != "direct" {
        let address = value.spec.address.as_deref().unwrap_or_default();
        validate_host("address", address).map_err(|reason| invalid_spec(kind, name, reason))?;
        if value.spec.port.is_none_or(|port| port == 0) {
            return Err(invalid_spec(
                kind,
                name,
                "port is required and must be non-zero",
            ));
        }
    }
    Ok(())
}

fn validate_subscription_spec(value: &Resource<SubscriptionSpec>) -> Result<(), ConfigError> {
    let kind = value.kind.as_str();
    let name = value.metadata.name.as_str();
    let source = value
        .spec
        .source
        .as_ref()
        .ok_or_else(|| invalid_spec(kind, name, "source is required"))?;
    if SubscriptionSourceType::from_name(&source.source_type).is_none() {
        return Err(invalid_spec(
            kind,
            name,
            "source.type is not a recognized subscription format",
        ));
    }
    let parsed = Url::parse(&source.url)
        .map_err(|_| invalid_spec(kind, name, "source.url must be a valid URL"))?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return Err(invalid_spec(
            kind,
            name,
            "source.url must use http or https",
        ));
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(invalid_spec(
            kind,
            name,
            "source.url must not contain credentials",
        ));
    }
    if source
        .user_agent
        .as_deref()
        .is_some_and(|value| !crate::valid_subscription_user_agent(value))
    {
        return Err(invalid_spec(kind, name, "source.userAgent is invalid"));
    }
    if let Some(refresh) = &value.spec.refresh
        && (!(60..=604_800).contains(&refresh.interval_seconds)
            || !(1..=300).contains(&refresh.timeout_seconds)
            || !(1..=10).contains(&refresh.max_attempts)
            || !(1..=3600).contains(&refresh.backoff_seconds))
    {
        return Err(invalid_spec(
            kind,
            name,
            "refresh values are outside their allowed ranges",
        ));
    }
    if let Some(cache) = &value.spec.cache
        && (cache.path.is_empty()
            || contains_control(&cache.path)
            || cache.max_age_seconds < 60
            || cache.max_age_seconds > 2_592_000)
    {
        return Err(invalid_spec(
            kind,
            name,
            "cache values are outside their allowed ranges",
        ));
    }
    Ok(())
}

fn validate_traffic_policy_spec(value: &Resource<TrafficPolicySpec>) -> Result<(), ConfigError> {
    let kind = value.kind.as_str();
    let name = value.metadata.name.as_str();
    if value.spec.session_replication_budget_bps > 1_000_000_000_000
        || value
            .spec
            .class_replication_budget_bps
            .is_some_and(|budget| budget > 1_000_000_000_000)
    {
        return Err(invalid_spec(
            kind,
            name,
            "replication budgets must not exceed 10^12",
        ));
    }
    if value.spec.classes.is_some() {
        return Err(invalid_spec(
            kind,
            name,
            "TrafficPolicy class fields are retired",
        ));
    }
    Ok(())
}

fn validate_listener_spec(value: &Resource<ListenerSpec>) -> Result<(), ConfigError> {
    let kind = value.kind.as_str();
    let name = value.metadata.name.as_str();
    if !matches!(
        value.spec.platform.as_str(),
        "any" | "linux" | "windows" | "freebsd"
    ) {
        return Err(invalid_spec(
            kind,
            name,
            "platform must be any, linux, windows, or freebsd",
        ));
    }
    validate_listener_kind_for_platform(value, &value.spec.platform)?;
    if value.spec.backend == TransparentBackend::Ebpf
        && (!matches!(value.spec.kind, ListenerKind::Tproxy) || value.spec.platform != "linux")
    {
        return Err(invalid_spec(
            kind,
            name,
            "ebpf backend requires a Linux tproxy listener",
        ));
    }
    match value.spec.kind {
        ListenerKind::Tun => {
            if value.spec.backend != TransparentBackend::Tproxy {
                return Err(invalid_spec(
                    kind,
                    name,
                    "tun listeners do not accept an interception backend",
                ));
            }
            if value.spec.interface.as_deref().is_none_or(str::is_empty)
                || value.spec.address.as_deref().is_none_or(str::is_empty)
            {
                return Err(invalid_spec(
                    kind,
                    name,
                    "tun interface and address are required",
                ));
            }
            validate_prefix(value.spec.address.as_deref().unwrap())
                .map_err(|reason| invalid_spec(kind, name, reason))?;
            if value
                .spec
                .mtu
                .is_some_and(|mtu| !(576..=65_535).contains(&mtu))
            {
                return Err(invalid_spec(kind, name, "tun mtu must be in 576..=65535"));
            }
        }
        ListenerKind::Tproxy => {
            if value.spec.mark.is_none() || value.spec.route_table.is_none() {
                return Err(invalid_spec(
                    kind,
                    name,
                    "tproxy mark and routeTable are required",
                ));
            }
            if value.spec.route_table == Some(0) {
                return Err(invalid_spec(kind, name, "routeTable must be non-zero"));
            }
            if value.spec.backend == TransparentBackend::Ebpf {
                if value.spec.interface.as_deref().is_none_or(str::is_empty) {
                    return Err(invalid_spec(
                        kind,
                        name,
                        "ebpf backend requires an interface",
                    ));
                }
                if value.spec.allowed_sources.is_empty() {
                    return Err(invalid_spec(
                        kind,
                        name,
                        "ebpf backend requires allowedSources",
                    ));
                }
            }
        }
        ListenerKind::Redirect => {
            if value.spec.backend != TransparentBackend::Tproxy {
                return Err(invalid_spec(
                    kind,
                    name,
                    "redirect listeners do not accept an interception backend",
                ));
            }
            if value.spec.protocols.contains(&FlowProtocol::Udp) {
                return Err(invalid_spec(
                    kind,
                    name,
                    "redirect listeners support TCP only",
                ));
            }
        }
        ListenerKind::Mixed => {
            if value.spec.backend != TransparentBackend::Tproxy {
                return Err(invalid_spec(
                    kind,
                    name,
                    "mixed listeners do not accept an interception backend",
                ));
            }
            if !value.spec.protocols.is_empty()
                && !value.spec.protocols.contains(&FlowProtocol::Tcp)
            {
                return Err(invalid_spec(kind, name, "mixed listeners require TCP"));
            }
            if value.spec.mark.is_some()
                || value.spec.route_table.is_some()
                || value.spec.interface.is_some()
                || value.spec.address.is_some()
                || value.spec.mtu.is_some()
                || !value.spec.bypass.is_empty()
                || value.spec.proxy_ref.is_some()
            {
                return Err(invalid_spec(
                    kind,
                    name,
                    "mixed listeners do not accept transparent, TUN, or proxyRef fields",
                ));
            }
        }
        ListenerKind::Http | ListenerKind::Socks5 => {
            if value.spec.backend != TransparentBackend::Tproxy {
                return Err(invalid_spec(
                    kind,
                    name,
                    "proxy listeners do not accept an interception backend",
                ));
            }
        }
    }
    let bind_required = !matches!(value.spec.kind, ListenerKind::Tun);
    if bind_required && value.spec.bind.is_none() {
        return Err(invalid_spec(
            kind,
            name,
            "bind is required for this listener type",
        ));
    }
    if !bind_required && value.spec.bind.is_some() {
        return Err(invalid_spec(
            kind,
            name,
            "bind is forbidden for tun listeners",
        ));
    }
    if value.spec.allowed_sources.len() > MAX_MAP_ENTRIES {
        return Err(invalid_spec(
            kind,
            name,
            "allowedSources has too many entries",
        ));
    }
    for source in &value.spec.allowed_sources {
        if validate_cidr(source).is_err() {
            return Err(invalid_spec(
                kind,
                name,
                "allowedSources contains an invalid CIDR",
            ));
        }
    }
    validate_tag_set("flowTags", &value.spec.flow_tags)
        .map_err(|reason| invalid_spec(kind, name, reason))?;
    if value
        .spec
        .process_metadata
        .is_some_and(ProcessMetadataRequest::is_empty)
    {
        return Err(invalid_spec(
            kind,
            name,
            "processMetadata must request executable, user, or group",
        ));
    }
    Ok(())
}

fn validate_listener_kind_for_platform(
    value: &Resource<ListenerSpec>,
    platform: &str,
) -> Result<(), ConfigError> {
    if platform == "freebsd"
        && !matches!(
            value.spec.kind,
            ListenerKind::Http | ListenerKind::Socks5 | ListenerKind::Mixed
        )
    {
        return Err(invalid_spec(
            &value.kind,
            &value.metadata.name,
            "freebsd listeners support http, socks5, and mixed only",
        ));
    }
    if platform == "windows"
        && matches!(
            value.spec.kind,
            ListenerKind::Tproxy | ListenerKind::Redirect
        )
    {
        return Err(invalid_spec(
            &value.kind,
            &value.metadata.name,
            "windows listeners do not support tproxy or redirect",
        ));
    }
    Ok(())
}

fn validate_flow_match(
    matches: Option<&FlowMatchSpec>,
    kind: &str,
    name: &str,
) -> Result<(), ConfigError> {
    let Some(matches) = matches else {
        return Ok(());
    };
    for (field, values, geosite) in [
        ("targetGeoSites", &matches.target_geo_sites, true),
        ("targetGeoIps", &matches.target_geo_ips, false),
    ] {
        let Some(values) = values else { continue };
        if values.is_empty() || values.len() > 256 {
            return Err(invalid_spec(
                kind,
                name,
                format!("{field} must have between 1 and 256 references"),
            ));
        }
        let mut seen = BTreeSet::new();
        for value in values {
            let normalized = crate::normalize_geodata_reference(value, geosite)
                .map_err(|reason| invalid_spec(kind, name, format!("{field}: {reason}")))?;
            if !seen.insert(normalized) {
                return Err(invalid_spec(
                    kind,
                    name,
                    format!("{field} contains duplicate references"),
                ));
            }
        }
    }
    if matches.source_networks.len() > 10_000 {
        return Err(invalid_spec(
            kind,
            name,
            "sourceNetworks has too many entries",
        ));
    }
    for network in &matches.source_networks {
        validate_cidr(network)
            .map_err(|reason| invalid_spec(kind, name, format!("sourceNetworks: {reason}")))?;
    }
    Ok(())
}

fn validate_cidr(value: &str) -> Result<(), String> {
    let (address, prefix) = value
        .split_once('/')
        .ok_or_else(|| "CIDR must contain an address and prefix length".to_owned())?;
    let address = address
        .parse::<IpAddr>()
        .map_err(|_| "CIDR address is invalid".to_owned())?;
    let prefix = prefix
        .parse::<u8>()
        .map_err(|_| "CIDR prefix length is invalid".to_owned())?;
    let maximum = match address {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    };
    if prefix > maximum {
        return Err("CIDR prefix length is outside the address family".to_owned());
    }
    Ok(())
}

fn validate_prefix(value: &str) -> Result<(), String> {
    validate_cidr(value)
}

fn validate_dns_policy_spec(value: &Resource<DnsPolicySpec>) -> Result<(), ConfigError> {
    let kind = value.kind.as_str();
    let name = value.metadata.name.as_str();
    for (field, servers) in value
        .spec
        .local
        .iter()
        .map(|route| ("local.servers", &route.servers))
        .chain(
            value
                .spec
                .transit
                .iter()
                .map(|route| ("transit.servers", &route.servers)),
        )
        .chain(
            value
                .spec
                .egress
                .iter()
                .map(|route| ("egress.servers", &route.servers)),
        )
    {
        if servers.len() > MAX_MAP_ENTRIES {
            return Err(invalid_spec(
                kind,
                name,
                format!("{field} has too many entries"),
            ));
        }
        for server in servers {
            validate_dns_server(server)
                .map_err(|reason| invalid_spec(kind, name, format!("{field}: {reason}")))?;
        }
    }
    if !matches!(
        value.spec.default_route.as_str(),
        "local" | "transit" | "egress" | "blocked"
    ) {
        return Err(invalid_spec(
            kind,
            name,
            "defaultRoute must be local, transit, egress, or blocked",
        ));
    }
    if value.spec.default_route == "local" {
        let servers = value.spec.local.as_ref().map(|local| &local.servers);
        if servers.is_none_or(Vec::is_empty) {
            return Err(invalid_spec(
                kind,
                name,
                "local.servers is required for local DNS route",
            ));
        }
    }
    if value.spec.default_route == "transit"
        && value
            .spec
            .transit
            .as_ref()
            .is_none_or(|selector| selector.proxy_selector.is_none())
    {
        return Err(invalid_spec(
            kind,
            name,
            "transit.proxySelector is required for transit route",
        ));
    }
    if value.spec.default_route == "transit" {
        let servers = &value
            .spec
            .transit
            .as_ref()
            .expect("selector requirement checked above")
            .servers;
        if servers.is_empty() {
            return Err(invalid_spec(
                kind,
                name,
                "transit.servers is required for transit route",
            ));
        }
    }
    if value
        .spec
        .transit
        .as_ref()
        .and_then(|selector| selector.proxy_selector.as_ref())
        .is_some_and(selector_empty)
    {
        return Err(invalid_spec(
            kind,
            name,
            "transit.proxySelector must contain a criterion",
        ));
    }
    if value.spec.default_route == "egress"
        && value
            .spec
            .egress
            .as_ref()
            .is_none_or(|selector| selector.egress_selector.is_none())
    {
        return Err(invalid_spec(
            kind,
            name,
            "egress.egressSelector is required for egress route",
        ));
    }
    if value.spec.default_route == "egress" {
        let servers = &value
            .spec
            .egress
            .as_ref()
            .expect("selector requirement checked above")
            .servers;
        if servers.is_empty() {
            return Err(invalid_spec(
                kind,
                name,
                "egress.servers is required for egress route",
            ));
        }
    }
    if value
        .spec
        .egress
        .as_ref()
        .and_then(|selector| selector.egress_selector.as_ref())
        .is_some_and(selector_empty)
    {
        return Err(invalid_spec(
            kind,
            name,
            "egress.egressSelector must contain a criterion",
        ));
    }
    if value
        .spec
        .blocked_response
        .as_deref()
        .is_some_and(|response| !matches!(response, "nxdomain" | "refused" | "servfail"))
    {
        return Err(invalid_spec(
            kind,
            name,
            "blockedResponse must be nxdomain, refused, or servfail",
        ));
    }
    if value
        .spec
        .timeout_seconds
        .is_none_or(|seconds| !(1..=60).contains(&seconds))
        || value
            .spec
            .max_inflight
            .is_none_or(|count| !(1..=100_000).contains(&count))
    {
        return Err(invalid_spec(
            kind,
            name,
            "DNS limits are outside their allowed ranges",
        ));
    }
    if let Some(cache) = &value.spec.cache
        && (cache.max_entries.is_some_and(|count| count > 1_000_000)
            || cache
                .max_ttl_seconds
                .is_some_and(|seconds| !(1..=604_800).contains(&seconds)))
    {
        return Err(invalid_spec(
            kind,
            name,
            "DNS cache limits are outside their allowed ranges",
        ));
    }
    Ok(())
}

fn validate_dns_server(server: &str) -> Result<(), String> {
    parse_dns_server(server).map(|_| ())
}

fn parse_dns_server(server: &str) -> Result<Endpoint, String> {
    if let Ok(address) = server.parse::<SocketAddr>() {
        if address.port() == 0 {
            return Err("DNS server port must be non-zero".to_owned());
        }
        return Ok(Endpoint {
            host: address.ip().to_string(),
            port: address.port(),
        });
    }

    let literal = server.trim_matches(['[', ']']);
    if let Ok(address) = literal.parse::<IpAddr>() {
        return Ok(Endpoint {
            host: address.to_string(),
            port: 53,
        });
    }

    let (host, port) = match server.rsplit_once(':') {
        Some((host, port)) => {
            let port = port
                .parse::<u16>()
                .map_err(|_| "DNS server port is invalid".to_owned())?;
            (host.trim_matches(['[', ']']), port)
        }
        None => (server, 53),
    };
    validate_host("DNS server host", host)?;
    if port == 0 {
        return Err("DNS server port must be non-zero".to_owned());
    }
    Ok(Endpoint {
        host: host.to_owned(),
        port,
    })
}

fn validate_rule_spec(
    kind: &str,
    name: &str,
    order: u32,
    matches: Option<&FlowMatchSpec>,
    catch_all: bool,
) -> Result<(), ConfigError> {
    if matches.is_some_and(|value| value == &FlowMatchSpec::default()) {
        return Err(ConfigError::InvalidSpec {
            kind: kind.into(),
            name: name.into(),
            reason: "empty match is not allowed; omit match for catchAll:true".into(),
        });
    }
    if catch_all && matches.is_some() {
        return Err(ConfigError::InvalidSpec {
            kind: kind.into(),
            name: name.into(),
            reason: "catchAll:true cannot be combined with match".into(),
        });
    }
    if order == 0 {
        return Err(ConfigError::InvalidSpec {
            kind: kind.into(),
            name: name.into(),
            reason: "order must be positive".into(),
        });
    }
    Ok(())
}

fn selector_empty(value: &SelectorSpec) -> bool {
    value.labels.is_empty() && value.tags.is_empty() && value.capabilities.is_empty()
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID: &str = r#"
apiVersion: pathchord.io/v1
kind: List
metadata:
  name: default
items:
  - apiVersion: pathchord.io/v1
    kind: Egress
    metadata:
      name: jp-1
    spec:
      address: egress.example.net
      port: 443
      publicKey: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
      capabilities: {tcp: true, udp: true}
      transit: {}
      trafficPolicyRef: default-policy
  - apiVersion: pathchord.io/v1
    kind: TrafficPolicy
    metadata:
      name: default-policy
    spec:
      scheduler: effectiveCapacityWeighted
  - apiVersion: pathchord.io/v1
    kind: DNSPolicy
    metadata:
      name: default-dns
    spec:
      defaultRoute: local
      local:
        servers: [192.0.2.53:53]
  - apiVersion: pathchord.io/v1
    kind: FallbackPolicy
    metadata:
      name: default-fallback
    spec:
      action: reject
  - apiVersion: pathchord.io/v1
    kind: Listener
    metadata:
      name: local-http
    spec:
      type: http
      bind: 127.0.0.1:8080
      authentication:
        mode: required
        credentialsRef: local-users
      flowTags: [interactive.local]
      processMetadata:
        executable: true
        user: true
        group: true
"#;

    #[test]
    fn parses_list_and_converts_to_domain_config() {
        let config = KubeConfig::from_yaml(VALID).expect("valid config");
        let policy = config.into_policy_config().expect("policy conversion");
        assert_eq!(policy.egresses[0].id.as_str(), "jp-1");
        assert_eq!(policy.egresses[0].endpoints.len(), 1);
        assert_eq!(policy.egresses[0].endpoints[0].port, 443);
        assert_eq!(policy.fallback, Some(FallbackAction::Reject));
        assert_eq!(policy.listeners[0].id.as_str(), "local-http");
        assert_eq!(policy.listeners[0].bind.as_ref().expect("bind").port, 8080);
        let dns = policy.dns_policy.as_ref().expect("DNS policy");
        assert_eq!(dns.default_route, DnsRoute::Local);
        assert_eq!(dns.timeout_seconds, 5);
        assert_eq!(dns.max_inflight, 1_024);
        assert_eq!(dns.blocked_response, DnsBlockedResponse::Refused);
        assert_eq!(dns.local.as_ref().expect("local DNS").servers[0].port, 53);
        assert_eq!(
            policy.listeners[0].authentication,
            AuthenticationMode::Required
        );
        assert_eq!(
            policy.listeners[0].flow_tags,
            BTreeSet::from(["interactive.local".to_owned()])
        );
        assert_eq!(
            policy.listeners[0].process_metadata,
            ProcessMetadataRequest {
                executable: true,
                user: true,
                group: true,
            }
        );
    }

    #[test]
    fn normalizes_multiple_egress_endpoints_and_preserves_order() {
        let input = VALID.replace(
            "      address: egress.example.net\n      port: 443",
            "      endpoints:\n        - address: Egress-V4.Example.net.\n          port: 7443\n        - address: 2001:0db8::10\n          port: 8443\n        - address: egress.example.net\n          port: 443",
        );
        let policy = KubeConfig::from_yaml(&input)
            .expect("multiple endpoints parse")
            .into_policy_config()
            .expect("multiple endpoints convert");
        assert_eq!(
            policy.egresses[0].endpoints,
            vec![
                Endpoint {
                    host: "egress-v4.example.net".into(),
                    port: 7443,
                },
                Endpoint {
                    host: "2001:db8::10".into(),
                    port: 8443,
                },
                Endpoint {
                    host: "egress.example.net".into(),
                    port: 443,
                },
            ]
        );
    }

    #[test]
    fn rejects_ambiguous_or_invalid_egress_endpoint_forms() {
        let cases = [
            (
                "      address: egress.example.net\n      port: 443\n      endpoints: [{address: other.example.net, port: 443}]",
                "mutually exclusive",
            ),
            ("      address: egress.example.net", "supplied together"),
            (
                "      endpoints: [{address: egress.example.net, port: 443}, {address: EGRESS.EXAMPLE.NET., port: 443}]",
                "duplicate",
            ),
            (
                "      endpoints: [{address: '[2001:db8::10]', port: 443}]",
                "valid DNS hostname",
            ),
            (
                "      endpoints: [{address: egress.example.net, port: 0}]",
                "non-zero",
            ),
        ];
        for (replacement, expected) in cases {
            let input = VALID.replace(
                "      address: egress.example.net\n      port: 443",
                replacement,
            );
            let error = KubeConfig::from_yaml(&input).expect_err("invalid endpoint form");
            assert!(error.to_string().contains(expected), "{error}");
        }
    }

    #[test]
    fn rejects_more_than_32_egress_endpoints() {
        let endpoints = (0..33)
            .map(|index| {
                format!(
                    "        - address: egress-{index}.example.net\n          port: {}",
                    7000 + index
                )
            })
            .collect::<Vec<_>>()
            .join("\n");
        let input = VALID.replace(
            "      address: egress.example.net\n      port: 443",
            &format!("      endpoints:\n{endpoints}"),
        );
        let error = KubeConfig::from_yaml(&input).expect_err("endpoint bound");
        assert!(error.to_string().contains("between 1 and 32"), "{error}");
    }

    #[test]
    fn geodata_resources_and_rule_references_are_namespace_scoped_and_normalized() {
        let extra = r#"
---
apiVersion: pathchord.io/v1
kind: GeoSiteDatabase
metadata: {name: domains, namespace: tenant}
spec: {path: ../geodata/dlc.dat}
---
apiVersion: pathchord.io/v1
kind: GeoIpDatabase
metadata: {name: addresses, namespace: tenant}
spec: {path: ../geodata/geoip.dat}
---
apiVersion: pathchord.io/v1
kind: ProxyRule
metadata: {name: geodata-route, namespace: tenant}
spec:
  order: 10
  match:
    targetGeoSites: ["GeoSite:HuggingFace@Ads"]
    targetGeoIps: ["GeoIP:CN"]
  select: any
"#;
        let policy = KubeConfig::from_yaml(&format!("{VALID}{extra}"))
            .unwrap()
            .into_policy_config()
            .unwrap();
        assert_eq!(policy.geo_site_databases[0].id.namespace(), "tenant");
        assert_eq!(policy.geo_site_databases[0].path, "../geodata/dlc.dat");
        assert_eq!(policy.geo_ip_databases[0].id.namespace(), "tenant");
        assert_eq!(
            policy.proxy_rules[0].matches.target_geo_sites,
            BTreeSet::from(["huggingface@ads".to_owned()])
        );
        assert_eq!(
            policy.proxy_rules[0].matches.target_geo_ips,
            BTreeSet::from(["cn".to_owned()])
        );
    }

    #[test]
    fn invalid_geodata_configuration_is_rejected_before_normalization() {
        let databases = r#"
---
apiVersion: pathchord.io/v1
kind: GeoSiteDatabase
metadata: {name: domains, namespace: tenant}
spec: {path: ../geodata/dlc.dat}
---
apiVersion: pathchord.io/v1
kind: GeoIpDatabase
metadata: {name: addresses, namespace: tenant}
spec: {path: ../geodata/geoip.dat}
"#;
        let proxy = |matching: &str| {
            format!(
                r#"
---
apiVersion: pathchord.io/v1
kind: ProxyRule
metadata: {{name: geo, namespace: tenant}}
spec: {{order: 11, match: {{{matching}}}, select: any}}
"#
            )
        };
        for matching in [
            "targetGeoSites: []",
            "targetGeoIps: []",
            "targetGeoSites: null, targetHosts: [example.test]",
            "targetGeoSites: ['site@']",
            "targetGeoSites: ['site@one@two']",
            "targetGeoIps: ['cn@x']",
            "targetGeoSites: ['Geosite:HF', 'hf']",
            "targetGeoIps: ['CN', 'geoip:cn']",
        ] {
            let input = format!("{VALID}{databases}{}", proxy(matching));
            assert!(KubeConfig::from_yaml(&input).is_err(), "{matching}");
        }
        let names = (0..=256)
            .map(|index| format!("site-{index}"))
            .collect::<Vec<_>>()
            .join(", ");
        let input = format!(
            "{VALID}{databases}{}",
            proxy(&format!("targetGeoSites: [{names}]"))
        );
        assert!(KubeConfig::from_yaml(&input).is_err());
        let missing = format!("{VALID}{}", proxy("targetGeoSites: [huggingface]"));
        assert!(KubeConfig::from_yaml(&missing).is_err());
        let wrong_namespace = databases.replace("namespace: tenant", "namespace: other");
        let cross = format!("{VALID}{wrong_namespace}{}", proxy("targetGeoSites: [hf]"));
        assert!(KubeConfig::from_yaml(&cross).is_err());
        let duplicate = r#"
---
apiVersion: pathchord.io/v1
kind: GeoSiteDatabase
metadata: {name: another, namespace: tenant}
spec: {path: ../geodata/another.dat}
"#;
        let error = KubeConfig::from_yaml(&format!("{VALID}{databases}{duplicate}"))
            .unwrap_err()
            .to_string();
        assert!(error.contains("at most one database"));
        let bad_path = databases.replace("../geodata/dlc.dat", "''");
        assert!(KubeConfig::from_yaml(&format!("{VALID}{bad_path}")).is_err());
    }

    #[test]
    fn deployment_examples_compile_into_validated_policy() {
        for source in [
            include_str!("../../../examples/ingress-direct.yaml"),
            include_str!("../../../examples/ingress-subscriptions.yaml"),
            include_str!("../../../examples/ingress-egress.yaml"),
        ] {
            let source = source.replace(
                "REPLACE_WITH_EGRESS_PUBLIC_KEY",
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            );
            KubeConfig::from_yaml(&source)
                .unwrap()
                .into_validated_snapshot(Generation::new(1))
                .unwrap();
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_transparent_and_tun_examples_compile_into_validated_policy() {
        for source in [
            include_str!("../../../examples/ingress-tproxy.yaml"),
            include_str!("../../../examples/ingress-tproxy-ebpf.yaml"),
            include_str!("../../../examples/ingress-tun.yaml"),
        ] {
            KubeConfig::from_yaml(source)
                .unwrap()
                .into_validated_snapshot(Generation::new(1))
                .unwrap();
        }
    }

    #[test]
    fn typed_tls_and_transport_options_are_preserved_and_unknown_fields_rejected() {
        let source = format!(
            "{VALID}\n---\napiVersion: pathchord.io/v1\nkind: TransitProxy\nmetadata: {{name: tls-node}}\nspec:\n  protocol: vless\n  address: proxy.example\n  port: 443\n  credentialsRef: node-secret\n  options:\n    tls: {{enabled: true, serverName: verified.example, alpn: [http/1.1], reality: {{publicKey: public-example, shortId: abcd}}}}\n    transport: {{type: ws, path: /proxy, headers: {{Host: ws.example}}}}\n    udp: false\n"
        );
        let policy = KubeConfig::from_yaml(&source)
            .unwrap()
            .into_policy_config()
            .unwrap();
        let node = policy
            .transit_proxies
            .iter()
            .find(|node| node.id.as_str() == "tls-node")
            .unwrap();
        assert_eq!(
            node.options.tls.as_ref().unwrap().server_name.as_deref(),
            Some("verified.example")
        );
        assert_eq!(node.options.transport.as_ref().unwrap().kind, "ws");
        assert_eq!(node.options.udp, Some(false));
        assert!(KubeConfig::from_yaml(&source.replace("serverName:", "silentlyIgnored:")).is_err());
        assert!(KubeConfig::from_yaml(&source.replace("enabled: true", "enabled: false")).is_err());
    }

    #[test]
    fn listener_process_metadata_and_flow_tags_are_strictly_validated() {
        let string_value = VALID.replace("executable: true", "executable: /usr/bin/browser");
        assert!(KubeConfig::from_yaml(&string_value).is_err());

        let unknown_field = VALID.replace("        executable: true", "        pid: true");
        assert!(KubeConfig::from_yaml(&unknown_field).is_err());

        let empty_request = VALID.replace(
            "      processMetadata:\n        executable: true\n        user: true\n        group: true",
            "      processMetadata: {}",
        );
        let error = KubeConfig::from_yaml(&empty_request)
            .unwrap_err()
            .to_string();
        assert!(error.contains("processMetadata"));

        let invalid_tag = VALID.replace("interactive.local", "not/a/tag");
        let error = KubeConfig::from_yaml(&invalid_tag).unwrap_err().to_string();
        assert!(error.contains("flowTags"));

        let too_many = (0..=MAX_MAP_ENTRIES)
            .map(|index| format!("tag-{index}"))
            .collect::<Vec<_>>()
            .join(", ");
        let error = KubeConfig::from_yaml(&VALID.replace(
            "flowTags: [interactive.local]",
            &format!("flowTags: [{too_many}]"),
        ))
        .unwrap_err()
        .to_string();
        assert!(error.contains("flowTags"));
    }

    #[test]
    fn dns_server_without_port_defaults_to_53() {
        let input = VALID.replace("servers: [192.0.2.53:53]", "servers: [192.0.2.53]");
        let policy = KubeConfig::from_yaml(&input)
            .expect("valid default DNS port")
            .into_policy_config()
            .expect("policy conversion");
        assert_eq!(
            policy
                .dns_policy
                .as_ref()
                .unwrap()
                .local
                .as_ref()
                .unwrap()
                .servers[0],
            Endpoint {
                host: "192.0.2.53".into(),
                port: 53,
            }
        );
    }

    #[test]
    fn conversion_sorts_rules_and_preserves_direct_proxy_action() {
        let input = format!(
            r#"{VALID}
---
apiVersion: pathchord.io/v1
kind: ProxyRule
metadata:
  name: later
spec:
  order: 30
  match:
    flowTags: [later]
  select: any
---
apiVersion: pathchord.io/v1
kind: ProxyRule
metadata:
  name: direct-first
spec:
  order: 10
  match:
    flowTags: [direct]
  proxy: direct
"#
        );
        let policy = KubeConfig::from_yaml(&input)
            .expect("valid rules")
            .into_policy_config()
            .expect("policy conversion");

        assert_eq!(policy.proxy_rules[0].id.as_str(), "direct-first");
        assert_eq!(policy.proxy_rules[0].select, ProxySelection::Direct);
        assert_eq!(policy.proxy_rules[1].id.as_str(), "later");
        assert_eq!(policy.proxy_rules[1].select, ProxySelection::Any);
    }

    #[test]
    fn conversion_preserves_subscription_defaults_and_secret_reference() {
        let input = format!(
            r#"{VALID}
---
apiVersion: pathchord.io/v1
kind: Subscription
metadata:
  name: provider-a
spec:
  source:
    type: clash
    url: https://example.invalid/subscription
    credentialsRef: provider-a-token
    userAgent: CustomClient/1.0
  cache:
    path: provider-a.snapshot
"#
        );
        let policy = KubeConfig::from_yaml(&input)
            .expect("valid subscription")
            .into_policy_config()
            .expect("policy conversion");
        let subscription = &policy.subscriptions[0];
        assert_eq!(subscription.id.as_str(), "provider-a");
        assert!(subscription.enabled);
        assert_eq!(
            subscription.source.source_type,
            SubscriptionSourceType::Clash
        );
        assert_eq!(
            subscription.source.credentials_ref.as_deref(),
            Some("provider-a-token")
        );
        assert_eq!(
            subscription.source.user_agent.as_deref(),
            Some("CustomClient/1.0")
        );
        assert_eq!(subscription.refresh, SubscriptionRefresh::default());
        assert_eq!(
            subscription.cache.as_ref().expect("cache").max_age_seconds,
            86_400
        );
    }

    #[test]
    fn subscription_user_agent_must_be_a_safe_http_header_value() {
        for value in ["''", "'   '", r#""bad\nheader""#, "'猫'"] {
            let input = format!(
                "{VALID}\n---\napiVersion: pathchord.io/v1\nkind: Subscription\nmetadata: {{name: provider}}\nspec:\n  source:\n    type: clash\n    url: https://example.invalid/sub\n    userAgent: {value}\n"
            );
            assert!(
                KubeConfig::from_yaml(&input).is_err(),
                "accepted invalid User-Agent: {value}"
            );
        }
    }

    #[test]
    fn conversion_preserves_opaque_transit_credentials_reference() {
        let input = format!(
            r#"{VALID}
---
apiVersion: pathchord.io/v1
kind: TransitProxy
metadata:
  name: private-socks
spec:
  protocol: socks5
  address: proxy.example.test
  port: 1080
  credentialsRef: local-socks-secret
"#
        );
        let policy = KubeConfig::from_yaml(&input)
            .expect("valid Transit credentials reference")
            .into_policy_config()
            .expect("policy conversion");
        assert_eq!(
            policy.transit_proxies[0].credentials_ref.as_deref(),
            Some("local-socks-secret")
        );
    }

    #[test]
    fn rejects_local_dns_without_servers() {
        let input = VALID.replace("        servers: [192.0.2.53:53]\n", "");
        let error = KubeConfig::from_yaml(&input).unwrap_err().to_string();
        assert!(error.contains("local.servers"));
    }

    #[test]
    fn rejects_unknown_fields_and_duplicate_names() {
        let unknown = VALID.replace(
            "spec:\n      address",
            "spec:\n      unknown: true\n      address",
        );
        assert!(KubeConfig::from_yaml(&unknown).is_err());
        let duplicate = VALID.replace("  - apiVersion: pathchord.io/v1\n    kind: DNSPolicy", "  - apiVersion: pathchord.io/v1\n    kind: Egress\n    metadata:\n      name: jp-1\n    spec:\n      address: egress2.example.net\n      port: 443\n      publicKey: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n      capabilities: {tcp: true, udp: true}\n  - apiVersion: pathchord.io/v1\n    kind: DNSPolicy");
        assert!(KubeConfig::from_yaml(&duplicate).is_err());
    }

    #[test]
    fn rule_order_is_required_and_duplicate_orders_are_rejected() {
        let input = format!(
            "{VALID}\n---\napiVersion: pathchord.io/v1\nkind: EgressRule\nmetadata:\n  name: r1\nspec:\n  match: {{flowTags: [x]}}\n  egressRef: jp-1\n"
        );
        assert!(KubeConfig::from_yaml(&input).is_err());
    }

    #[test]
    fn traffic_class_configuration_is_retired() {
        let input = format!(
            r#"{VALID}
---
apiVersion: pathchord.io/v1
kind: TrafficPolicy
metadata: {{name: gaming}}
spec:
  classes:
    interactive: {{priority: 200, share: 3}}
---
apiVersion: pathchord.io/v1
kind: TransitRule
metadata: {{name: classified}}
spec: {{order: 99, catchAll: true, egressRef: jp-1, trafficPolicyRef: gaming, trafficClassRef: interactive}}
"#
        );
        let error = KubeConfig::from_yaml(&input).unwrap_err().to_string();
        assert!(
            error.contains("TrafficPolicy class fields are retired"),
            "{error}"
        );
        let transit = format!(
            "{VALID}\n---\napiVersion: pathchord.io/v1\nkind: TransitRule\nmetadata: {{name: retired}}\nspec: {{order: 99, catchAll: true, egressRef: jp-1}}\n"
        );
        let error = KubeConfig::from_yaml(&transit).unwrap_err().to_string();
        assert!(
            error.contains("TransitRule resources are retired"),
            "{error}"
        );
    }

    #[test]
    fn accepts_multiple_yaml_documents() {
        let input = r#"
apiVersion: pathchord.io/v1
kind: Egress
metadata:
  name: jp-1
spec:
  address: egress.example.net
  port: 443
  publicKey: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
  capabilities: {tcp: true, udp: true}
  transit: {}
  trafficPolicyRef: default-policy
---
apiVersion: pathchord.io/v1
kind: TrafficPolicy
metadata:
  name: default-policy
spec: {}
---
apiVersion: pathchord.io/v1
kind: DNSPolicy
metadata:
  name: default-dns
spec:
  defaultRoute: local
  local:
    servers: [192.0.2.53:53]
---
apiVersion: pathchord.io/v1
kind: FallbackPolicy
metadata:
  name: default-fallback
spec:
  action: reject
"#;
        let config = KubeConfig::from_yaml(input).expect("multi-document config");
        assert_eq!(config.resources.len(), 4);
    }

    #[test]
    fn independent_documents_form_one_validated_resource_graph() {
        let base = include_str!("../../../examples/ingress-direct.yaml");
        let split: Vec<_> = base.split("\n---\n").collect();
        assert!(
            split
                .iter()
                .all(|source| KubeConfig::from_yaml(source).is_err())
        );
        let policy = KubeConfig::from_documents(split.iter().copied())
            .unwrap()
            .into_validated_snapshot(Generation::new(1))
            .unwrap();
        assert_eq!(policy.config().listeners.len(), 1);
        let duplicate = KubeConfig::from_documents([base, split[0]]).unwrap_err();
        assert!(matches!(duplicate, ConfigError::DuplicateResource { .. }));
        let forward = KubeConfig::from_documents(split.iter().copied())
            .unwrap()
            .into_policy_config()
            .unwrap();
        let reversed = KubeConfig::from_documents(split.iter().rev().copied())
            .unwrap()
            .into_policy_config()
            .unwrap();
        assert_eq!(
            forward, reversed,
            "source filename order must not alter resource identity or restart semantics"
        );
    }

    #[test]
    fn rejects_invalid_egress_key_and_capabilities() {
        let invalid_key = VALID.replace(
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "not-a-public-key",
        );
        let error = KubeConfig::from_yaml(&invalid_key).unwrap_err().to_string();
        assert!(error.contains("publicKey"));

        let no_capabilities = VALID.replace(
            "capabilities: {tcp: true, udp: true}",
            "capabilities: {tcp: false, udp: false}",
        );
        let error = KubeConfig::from_yaml(&no_capabilities)
            .unwrap_err()
            .to_string();
        assert!(error.contains("capability"));
    }

    #[test]
    fn capability_fields_default_independently_and_unknown_fields_are_rejected() {
        for (mapping, tcp, udp) in [("{tcp: true}", true, false), ("{udp: true}", false, true)] {
            let input = VALID.replace("{tcp: true, udp: true}", mapping);
            let policy = KubeConfig::from_yaml(&input)
                .unwrap()
                .into_policy_config()
                .unwrap();
            assert_eq!(policy.egresses[0].capabilities, Capabilities { tcp, udp });
        }
        let input = VALID.replace(
            "{tcp: true, udp: true}",
            "{tcp: true, udp: true, udpp: true}",
        );
        assert!(
            KubeConfig::from_yaml(&input)
                .unwrap_err()
                .to_string()
                .contains("udpp")
        );
    }

    #[test]
    fn omitted_match_is_a_catch_all_and_empty_match_is_rejected() {
        for (kind, action) in [
            ("EgressRule", "egressRef: jp-1"),
            ("ProxyRule", "proxy: direct"),
        ] {
            let input = format!(
                "{VALID}\n---\napiVersion: pathchord.io/v1\nkind: {kind}\nmetadata: {{name: all}}\nspec: {{order: 1, {action}}}\n"
            );
            KubeConfig::from_yaml(&input)
                .unwrap()
                .into_policy_config()
                .unwrap();
            let empty = input.replace(
                &format!("order: 1, {action}"),
                &format!("order: 1, match: {{}}, {action}"),
            );
            assert!(
                KubeConfig::from_yaml(&empty)
                    .unwrap_err()
                    .to_string()
                    .contains("empty match")
            );
        }
        let retired = format!(
            "{VALID}\n---\napiVersion: pathchord.io/v1\nkind: TransitRule\nmetadata: {{name: retired}}\nspec: {{order: 1, catchAll: true, egressRef: jp-1}}\n"
        );
        assert!(
            KubeConfig::from_yaml(&retired)
                .unwrap_err()
                .to_string()
                .contains("TransitRule resources are retired")
        );
    }

    #[test]
    fn validates_endpoints_of_every_supplied_dns_route() {
        for route in [
            "local: {servers: [invalid:port]}",
            "transit: {servers: [invalid:port]}",
            "egress: {servers: [invalid:port]}",
        ] {
            let input = format!(
                "apiVersion: pathchord.io/v1\nkind: DNSPolicy\nmetadata: {{name: dns}}\nspec: {{defaultRoute: blocked, {route}}}\n---\napiVersion: pathchord.io/v1\nkind: FallbackPolicy\nmetadata: {{name: fallback}}\nspec: {{action: reject}}\n"
            );
            let error = KubeConfig::from_yaml(&input).unwrap_err().to_string();
            assert!(error.contains("DNS server port"), "{error}");
        }
    }

    fn namespaced_resources(namespace: &str, order: u32, port: u16) -> String {
        format!(
            r#"
apiVersion: pathchord.io/v1
kind: Egress
metadata: {{name: edge, namespace: {namespace}, labels: {{region: jp}}}}
spec: {{address: 127.0.0.1, port: 7443, publicKey: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA, capabilities: {{tcp: true}}, transit: {{}}, trafficPolicyRef: traffic}}
---
apiVersion: pathchord.io/v1
kind: Listener
metadata: {{name: local, namespace: {namespace}}}
spec: {{type: mixed, bind: "127.0.0.1:{port}", authentication: {{mode: required, credentialsRef: "{namespace}-listener-secret"}}}}
---
apiVersion: pathchord.io/v1
kind: Subscription
metadata: {{name: provider, namespace: {namespace}}}
spec: {{source: {{type: clash, url: "https://example.test/subscription", credentialsRef: "{namespace}-subscription-secret"}}}}
---
apiVersion: pathchord.io/v1
kind: TransitProxy
metadata: {{name: node, namespace: {namespace}, labels: {{region: jp}}}}
spec: {{protocol: direct, source: {{type: clash, subscriptionRef: provider}}, credentialsRef: "{namespace}-node-secret"}}
---
apiVersion: pathchord.io/v1
kind: TrafficPolicy
metadata: {{name: traffic, namespace: {namespace}}}
spec: {{}}
---
apiVersion: pathchord.io/v1
kind: EgressRule
metadata: {{name: route, namespace: {namespace}}}
spec: {{order: {order}, match: {{listenerRefs: [local]}}, egressRef: edge}}
---
apiVersion: pathchord.io/v1
kind: ProxyRule
metadata: {{name: route, namespace: {namespace}}}
spec: {{order: {}, require: {{labels: {{region: jp}}}}}}
"#,
            order + 1,
        )
    }

    fn namespaced_bundle(namespaces: &[&str]) -> String {
        let mut documents = vec!["apiVersion: pathchord.io/v1\nkind: DNSPolicy\nmetadata: {name: dns}\nspec: {defaultRoute: blocked}\n---\napiVersion: pathchord.io/v1\nkind: FallbackPolicy\nmetadata: {name: fallback}\nspec: {action: reject}\n".to_owned()];
        documents.extend(namespaces.iter().enumerate().map(|(index, namespace)| {
            namespaced_resources(namespace, 10 * (index as u32 + 1), 19000 + index as u16)
        }));
        documents.join("\n---\n")
    }

    #[test]
    fn namespaced_graph_keeps_same_names_and_resolves_owners_without_rewriting_secrets() {
        let input = namespaced_bundle(&["alpha", "beta"]);
        let policy = KubeConfig::from_yaml(&input)
            .unwrap()
            .into_policy_config()
            .unwrap();
        assert_eq!(policy.egresses.len(), 2);
        assert_ne!(policy.egresses[0].id, policy.egresses[1].id);
        for namespace in ["alpha", "beta"] {
            let egress = EgressId::in_namespace(namespace, "edge");
            let configured_egress = policy
                .egresses
                .iter()
                .find(|value| value.id == egress)
                .unwrap();
            assert_eq!(
                configured_egress.traffic_policy,
                Some(TrafficPolicyId::in_namespace(namespace, "traffic"))
            );
            let proxy = policy
                .transit_proxies
                .iter()
                .find(|proxy| proxy.id.namespace() == namespace)
                .unwrap();
            assert_eq!(
                proxy.source.as_ref().unwrap().subscription,
                SubscriptionId::in_namespace(namespace, "provider").as_str()
            );
            assert_eq!(
                proxy.credentials_ref.as_deref(),
                Some(format!("{namespace}-node-secret").as_str())
            );
            let listener = policy
                .listeners
                .iter()
                .find(|listener| listener.id.namespace() == namespace)
                .unwrap();
            assert_eq!(
                listener.credentials_ref.as_deref(),
                Some(format!("{namespace}-listener-secret").as_str())
            );
            let subscription = policy
                .subscriptions
                .iter()
                .find(|subscription| subscription.id.namespace() == namespace)
                .unwrap();
            assert_eq!(
                subscription.source.credentials_ref.as_deref(),
                Some(format!("{namespace}-subscription-secret").as_str())
            );
        }
        let reversed = input
            .split("\n---\n")
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect::<Vec<_>>()
            .join("\n---\n");
        assert_eq!(
            policy,
            KubeConfig::from_yaml(&reversed)
                .unwrap()
                .into_policy_config()
                .unwrap()
        );
    }

    #[test]
    fn namespace_capacity_is_checked_for_authored_and_programmatic_resource_graphs() {
        let namespace = "n".repeat(127);
        let input = namespaced_bundle(&[&namespace]);
        let policy = KubeConfig::from_yaml(&input)
            .unwrap()
            .into_policy_config()
            .unwrap();
        assert_eq!(policy.subscriptions[0].id.namespace(), namespace);
        let unavailable_namespace = "n".repeat(187);
        let input = namespaced_bundle(&[&unavailable_namespace]);
        assert!(matches!(
            KubeConfig::from_yaml(&input),
            Err(ConfigError::Validation(
                crate::ValidationError::ResourceIdentityLimit { .. }
            ))
        ));

        let mut candidate = policy.clone();
        candidate.subscriptions[0].id = SubscriptionId::in_namespace(&unavailable_namespace, "x");
        assert!(matches!(
            ValidatedPolicySnapshot::new(Generation::new(2), candidate),
            Err(crate::ValidationError::ResourceIdentityLimit { .. })
        ));
        let mut candidate = policy;
        candidate.dns_policy.as_mut().unwrap().id =
            DnsPolicyId::in_namespace(&unavailable_namespace, "x");
        assert!(matches!(
            ValidatedPolicySnapshot::new(Generation::new(2), candidate),
            Err(crate::ValidationError::ResourceIdentityLimit { .. })
        ));
    }

    #[test]
    fn references_cannot_resolve_another_namespaces_same_name() {
        let input = namespaced_bundle(&["alpha"]);
        for (kind, name) in [
            ("Egress", "edge"),
            ("TrafficPolicy", "traffic"),
            ("Listener", "local"),
            ("Subscription", "provider"),
        ] {
            let original = format!("kind: {kind}\nmetadata: {{name: {name}, namespace: alpha");
            let foreign = format!("kind: {kind}\nmetadata: {{name: {name}, namespace: beta");
            let invalid = input.replace(&original, &foreign);
            assert!(
                KubeConfig::from_yaml(&invalid)
                    .and_then(KubeConfig::into_policy_config)
                    .is_err(),
                "cross-namespace {kind} reference was accepted"
            );
        }
    }

    #[test]
    fn selectors_and_catch_all_rules_stay_in_their_own_namespace() {
        let input = namespaced_bundle(&["alpha", "beta"]);
        let policy = KubeConfig::from_yaml(&input)
            .unwrap()
            .into_validated_snapshot(Generation::new(1))
            .unwrap();
        let compiled = policy.compile().unwrap();
        let mut runtime = crate::RuntimeCatalog::default();
        for namespace in ["alpha", "beta"] {
            runtime.set_transit_proxy(
                TransitProxyId::in_namespace(namespace, "node"),
                crate::TransitProxyRuntimeStatus {
                    state: crate::RuntimeNodeState::Ready,
                    capabilities: BTreeSet::from([FlowProtocol::Tcp]),
                    selection_score: if namespace == "beta" { 1_000_000 } else { 1 },
                    ..Default::default()
                },
            );
        }
        let context = crate::PolicyContext {
            listener_id: ListenerId::in_namespace("alpha", "local"),
            source: "127.0.0.1:1234".parse().unwrap(),
            authentication_identity: None,
            process: None,
            flow_tags: BTreeSet::new(),
            protocol: FlowProtocol::Tcp,
            target: crate::TargetEndpoint {
                host: crate::TargetHost::Hostname("example.test".into()),
                port: 443,
            },
        };
        let crate::Evaluation::Route(crate::RoutePlan::Proxy(route)) =
            compiled.evaluate(&context, &runtime)
        else {
            panic!("expected ordinary proxy route")
        };
        assert_eq!(
            route.transit_proxy_id,
            TransitProxyId::in_namespace("alpha", "node")
        );
        runtime.set_transit_proxy(
            TransitProxyId::in_namespace("alpha", "node"),
            crate::TransitProxyRuntimeStatus::default(),
        );
        assert!(matches!(
            compiled.evaluate(&context, &runtime),
            crate::Evaluation::Reject { .. }
        ));

        let input = input.replace(
            "egressRef: edge}",
            "egressSelector: {labels: {region: jp}}}",
        );
        let policy = KubeConfig::from_yaml(&input)
            .unwrap()
            .into_validated_snapshot(Generation::new(2))
            .unwrap();
        let compiled = policy.compile().unwrap();
        runtime.set_egress(
            EgressId::in_namespace("beta", "edge"),
            crate::EgressRuntimeStatus {
                state: crate::RuntimeNodeState::Ready,
                usable_paths: 1,
                ..Default::default()
            },
        );
        assert!(matches!(
            compiled.evaluate(&context, &runtime),
            crate::Evaluation::Reject { .. }
        ));
    }

    #[test]
    fn rejects_invalid_dns_limits_and_empty_match() {
        let invalid_dns = VALID.replace(
            "defaultRoute: local",
            "defaultRoute: local\n      timeoutSeconds: 0",
        );
        let error = KubeConfig::from_yaml(&invalid_dns).unwrap_err().to_string();
        assert!(error.contains("DNS limits"));

        let empty_match = format!(
            "{VALID}\n---\napiVersion: pathchord.io/v1\nkind: ProxyRule\nmetadata:\n  name: empty-match\nspec:\n  order: 40\n  match: {{}}\n  catchAll: true\n"
        );
        let error = KubeConfig::from_yaml(&empty_match).unwrap_err().to_string();
        assert!(error.contains("empty match"));
    }

    fn platform_listener_yaml(kind: &str, platform: &str, fields: &str) -> String {
        format!(
            "{VALID}\n---\napiVersion: pathchord.io/v1\nkind: Listener\nmetadata:\n  name: platform-listener\nspec:\n  type: {kind}\n  platform: {platform}\n{fields}"
        )
    }

    #[test]
    fn accepts_freebsd_http_and_socks5_listener_specs() {
        for (kind, protocols) in [("http", "[tcp]"), ("socks5", "[tcp, udp]")] {
            let input = platform_listener_yaml(
                kind,
                "freebsd",
                &format!("  bind: 127.0.0.1:1080\n  protocols: {protocols}\n"),
            );
            let config = KubeConfig::from_yaml(&input).expect("FreeBSD listener spec");
            let listener = config
                .resources
                .iter()
                .find_map(|resource| match resource {
                    KubeResource::Listener(value) if value.metadata.name == "platform-listener" => {
                        Some(value)
                    }
                    _ => None,
                })
                .expect("FreeBSD listener resource");
            assert_eq!(listener.spec.platform, "freebsd");
            assert_eq!(
                listener.spec.kind,
                if kind == "http" {
                    ListenerKind::Http
                } else {
                    ListenerKind::Socks5
                }
            );
            if cfg!(target_os = "freebsd") {
                let policy = config.into_policy_config().expect("native FreeBSD policy");
                let listener = policy
                    .listeners
                    .iter()
                    .find(|listener| listener.id.as_str() == "platform-listener")
                    .expect("FreeBSD listener");
                assert_eq!(listener.platform, "freebsd");
                assert_eq!(
                    listener.protocols.contains(&FlowProtocol::Udp),
                    kind == "socks5"
                );
            }
        }
    }

    #[test]
    fn ebpf_backend_requires_linux_interface_and_source_bounds() {
        let input = platform_listener_yaml(
            "tproxy",
            "linux",
            "  backend: ebpf\n  bind: 0.0.0.0:15001\n  interface: lan0\n  allowedSources: [192.168.1.0/24]\n  mark: 1\n  routeTable: 100\n  protocols: [tcp, udp]\n",
        );
        let policy = KubeConfig::from_yaml(&input)
            .unwrap()
            .into_policy_config()
            .unwrap();
        let listener = policy
            .listeners
            .iter()
            .find(|listener| listener.id.as_str() == "platform-listener")
            .unwrap();
        assert_eq!(listener.backend, TransparentBackend::Ebpf);

        let missing_source = platform_listener_yaml(
            "tproxy",
            "linux",
            "  backend: ebpf\n  bind: 0.0.0.0:15001\n  interface: lan0\n  mark: 1\n  routeTable: 100\n",
        );
        let error = KubeConfig::from_yaml(&missing_source)
            .unwrap_err()
            .to_string();
        assert!(error.contains("allowedSources"));
    }

    #[test]
    fn rejects_freebsd_transparent_and_tun_listener_specs() {
        for (kind, fields) in [
            (
                "tproxy",
                "  bind: 127.0.0.1:15000\n  mark: 1\n  routeTable: 100\n",
            ),
            ("redirect", "  bind: 127.0.0.1:15000\n"),
            ("tun", "  interface: PathChord\n  address: 198.18.0.1/30\n"),
        ] {
            let input = platform_listener_yaml(kind, "freebsd", fields);
            let error = KubeConfig::from_yaml(&input).unwrap_err().to_string();
            assert!(
                error.contains("freebsd listeners support http, socks5, and mixed only"),
                "{kind}: {error}"
            );
        }
    }

    #[test]
    fn rejects_windows_transparent_listener_specs_during_validation() {
        for (kind, fields) in [
            (
                "tproxy",
                "  bind: 127.0.0.1:15000\n  mark: 1\n  routeTable: 100\n",
            ),
            ("redirect", "  bind: 127.0.0.1:15000\n"),
        ] {
            let input = platform_listener_yaml(kind, "windows", fields);
            let error = KubeConfig::from_yaml(&input).unwrap_err().to_string();
            assert!(
                error.contains("windows listeners do not support tproxy or redirect"),
                "{kind}: {error}"
            );
        }
    }

    #[test]
    fn rejects_foreign_listener_platform_when_building_policy() {
        for platform in ["linux", "windows", "freebsd"] {
            if platform == std::env::consts::OS {
                continue;
            }
            let input = platform_listener_yaml("http", platform, "  bind: 127.0.0.1:1080\n");
            let error = KubeConfig::from_yaml(&input)
                .expect("recognized listener platform")
                .into_policy_config()
                .unwrap_err()
                .to_string();
            assert!(
                error.contains(&format!(
                    "listener platform {platform} is not supported by this build"
                )),
                "{error}"
            );
        }
    }

    #[test]
    fn accepts_any_http_and_socks5_listeners_on_native_platform() {
        for (kind, protocols) in [("http", "[tcp]"), ("socks5", "[tcp, udp]")] {
            let input = platform_listener_yaml(
                kind,
                "any",
                &format!("  bind: 127.0.0.1:1080\n  protocols: {protocols}\n"),
            );
            let policy = KubeConfig::from_yaml(&input)
                .expect("portable listener spec")
                .into_policy_config()
                .expect("native listener policy");
            let listener = policy
                .listeners
                .iter()
                .find(|listener| listener.id.as_str() == "platform-listener")
                .expect("portable listener");
            assert_eq!(listener.platform, "any");
            assert_eq!(
                listener.protocols.contains(&FlowProtocol::Udp),
                kind == "socks5"
            );
        }
    }

    #[test]
    fn socks_listener_alias_preserves_the_canonical_kind_and_protocols() {
        let input = platform_listener_yaml(
            "socks",
            "any",
            "  bind: 127.0.0.1:1080\n  protocols: [tcp, udp]\n",
        );
        let policy = KubeConfig::from_yaml(&input)
            .expect("SOCKS listener alias")
            .into_policy_config()
            .expect("native SOCKS listener");
        let listener = policy
            .listeners
            .iter()
            .find(|listener| listener.id.as_str() == "platform-listener")
            .unwrap();
        assert_eq!(listener.kind, ListenerKind::Socks5);
        assert_eq!(
            listener.protocols,
            BTreeSet::from([FlowProtocol::Tcp, FlowProtocol::Udp])
        );
        assert_eq!(
            serde_yaml::to_string(&listener.kind).unwrap().trim(),
            "socks5"
        );
    }

    #[test]
    fn mixed_listener_preserves_credentials_and_flow_context_with_both_protocols() {
        let input = platform_listener_yaml(
            "mixed",
            "any",
            "  bind: 127.0.0.1:17890\n  allowedSources: [127.0.0.1/32]\n  flowTags: [interactive]\n  processMetadata: {executable: true, user: true}\n  authentication: {mode: required, credentialsRef: mixed-users}\n",
        );
        let policy = KubeConfig::from_yaml(&input)
            .expect("mixed listener config")
            .into_policy_config()
            .expect("native mixed listener");
        let listener = policy
            .listeners
            .iter()
            .find(|listener| listener.id.as_str() == "platform-listener")
            .unwrap();
        assert_eq!(listener.kind, ListenerKind::Mixed);
        assert_eq!(
            listener.protocols,
            BTreeSet::from([FlowProtocol::Tcp, FlowProtocol::Udp])
        );
        assert_eq!(listener.authentication, AuthenticationMode::Required);
        assert_eq!(listener.credentials_ref.as_deref(), Some("mixed-users"));
        assert_eq!(listener.allowed_sources, ["127.0.0.1/32"]);
        assert_eq!(
            listener.flow_tags,
            BTreeSet::from(["interactive".to_owned()])
        );
        assert!(listener.process_metadata.executable);
        assert!(listener.process_metadata.user);
        assert!(!listener.process_metadata.group);
        assert_eq!(
            serde_yaml::to_string(&listener.kind).unwrap().trim(),
            "mixed"
        );
    }

    #[test]
    fn mixed_listener_accepts_supported_platforms_and_tcp_only_selection() {
        for platform in ["any", "linux", "windows", "freebsd"] {
            let input = platform_listener_yaml(
                "mixed",
                platform,
                "  bind: 127.0.0.1:17890\n  protocols: [tcp]\n",
            );
            let config = KubeConfig::from_yaml(&input).expect("supported mixed platform");
            if platform == "any" || platform == std::env::consts::OS {
                let policy = config.into_policy_config().expect("native mixed platform");
                let listener = policy
                    .listeners
                    .iter()
                    .find(|listener| listener.id.as_str() == "platform-listener")
                    .unwrap();
                assert_eq!(listener.kind, ListenerKind::Mixed);
                assert_eq!(listener.protocols, BTreeSet::from([FlowProtocol::Tcp]));
            } else {
                let error = config.into_policy_config().unwrap_err().to_string();
                assert!(error.contains("is not supported by this build"));
            }
        }
    }

    #[test]
    fn mixed_listener_rejects_udp_only_and_inapplicable_platform_fields() {
        let input = platform_listener_yaml(
            "mixed",
            "any",
            "  bind: 127.0.0.1:17890\n  protocols: [udp]\n",
        );
        let error = KubeConfig::from_yaml(&input).unwrap_err().to_string();
        assert!(error.contains("mixed listeners require TCP"));
        for field in [
            "mark: 1",
            "routeTable: 100",
            "interface: PathChord",
            "address: 198.18.0.1/30",
            "mtu: 1500",
            "bypass: [192.0.2.1/32]",
            "proxyRef: a-proxy",
        ] {
            let input = platform_listener_yaml(
                "mixed",
                "any",
                &format!("  bind: 127.0.0.1:17890\n  {field}\n"),
            );
            let error = KubeConfig::from_yaml(&input).unwrap_err().to_string();
            assert!(
                error.contains("mixed listeners do not accept"),
                "{field}: {error}"
            );
        }
    }

    #[cfg(target_os = "freebsd")]
    #[test]
    fn rejects_any_transparent_and_tun_listeners_on_freebsd() {
        for (kind, fields) in [
            (
                "tproxy",
                "  bind: 127.0.0.1:15000\n  mark: 1\n  routeTable: 100\n",
            ),
            ("redirect", "  bind: 127.0.0.1:15000\n"),
            ("tun", "  interface: PathChord\n  address: 198.18.0.1/30\n"),
        ] {
            let input = platform_listener_yaml(kind, "any", fields);
            let error = KubeConfig::from_yaml(&input)
                .expect("platform-neutral listener spec")
                .into_policy_config()
                .unwrap_err()
                .to_string();
            assert!(
                error.contains("freebsd listeners support http, socks5, and mixed only"),
                "{kind}: {error}"
            );
        }
    }

    #[cfg(not(target_os = "freebsd"))]
    #[test]
    fn accepts_tun_listener_without_bind() {
        let input = format!(
            "{VALID}\n---\napiVersion: pathchord.io/v1\nkind: Listener\nmetadata:\n  name: test-tun\nspec:\n  type: tun\n  platform: any\n  interface: PathChord\n  address: 198.18.0.1/30\n  mtu: 1500\n  protocols: [tcp, udp]\n"
        );
        let config = KubeConfig::from_yaml(&input).expect("TUN config");
        let policy = config.into_policy_config().expect("policy conversion");
        let tun = policy
            .listeners
            .iter()
            .find(|listener| listener.id.as_str() == "test-tun")
            .expect("TUN listener");
        assert_eq!(tun.kind, ListenerKind::Tun);
        assert_eq!(tun.bind, None);
        assert_eq!(tun.platform, "any");
        assert_eq!(tun.interface.as_deref(), Some("PathChord"));
        assert_eq!(tun.address.as_deref(), Some("198.18.0.1/30"));
        assert_eq!(tun.mtu, Some(1500));
        assert_eq!(
            tun.protocols,
            BTreeSet::from([FlowProtocol::Tcp, FlowProtocol::Udp])
        );
    }

    #[test]
    fn rejects_tun_listener_with_bind() {
        let input = format!(
            "{VALID}\n---\napiVersion: pathchord.io/v1\nkind: Listener\nmetadata:\n  name: test-tun\nspec:\n  type: tun\n  platform: any\n  bind: 127.0.0.1:15000\n  interface: PathChord\n  address: 198.18.0.1/30\n"
        );
        let error = KubeConfig::from_yaml(&input).unwrap_err().to_string();
        assert!(error.contains("bind is forbidden"));
    }

    #[test]
    fn rejects_proxy_listener_without_bind() {
        let input = format!(
            "{VALID}\n---\napiVersion: pathchord.io/v1\nkind: Listener\nmetadata:\n  name: missing-bind\nspec:\n  type: http\n  authentication: disabled\n"
        );
        let error = KubeConfig::from_yaml(&input).unwrap_err().to_string();
        assert!(error.contains("bind is required"));
    }

    #[test]
    fn rejects_non_tun_listener_without_bind() {
        let input = format!(
            "{VALID}\n---\napiVersion: pathchord.io/v1\nkind: Listener\nmetadata:\n  name: missing-bind\nspec:\n  type: http\n  platform: any\n"
        );
        let error = KubeConfig::from_yaml(&input).unwrap_err().to_string();
        assert!(error.contains("bind is required"));
    }

    #[test]
    fn rejects_invalid_allowed_source_cidr() {
        let input = VALID.replace(
            "      bind: 127.0.0.1:8080\n",
            "      bind: 127.0.0.1:8080\n      allowedSources: [192.0.2.0/not-a-prefix]\n",
        );
        let error = KubeConfig::from_yaml(&input).unwrap_err().to_string();
        assert!(error.contains("allowedSources"));
    }

    #[test]
    fn rejects_proxy_and_select_together() {
        let input = format!(
            "{VALID}\n---\napiVersion: pathchord.io/v1\nkind: ProxyRule\nmetadata:\n  name: conflicting-action\nspec:\n  order: 40\n  match:\n    flowTags: [web]\n  proxy: direct\n  select: any\n"
        );
        let error = KubeConfig::from_yaml(&input)
            .expect("parse configuration")
            .into_policy_config()
            .unwrap_err()
            .to_string();
        assert!(error.contains("mutually exclusive"));
    }
}
