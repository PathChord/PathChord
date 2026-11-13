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
    AuthenticationMode, Capabilities, EgressConfig, EgressId, EgressRule, EgressSelection,
    Endpoint, FallbackAction, FlowMatch, FlowProtocol, Generation, ListenerConfig, ListenerId,
    ListenerKind, PolicyConfig, ProxyRule, ProxySelection, RetransmissionReplication, RuleId,
    Scheduler, Selector, TrafficPolicy, TrafficPolicyId, TransitProxyConfig, TransitProxyId,
    TransitRule, TransitSource, ValidatedPolicySnapshot,
};

pub const API_VERSION: &str = "pathchord.io/v1";

const MAX_MAP_ENTRIES: usize = 256;
const MAX_MAP_KEY_BYTES: usize = 64;
const MAX_MAP_VALUE_BYTES: usize = 256;
const MAX_WEIGHT: u32 = 1_000_000;

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
    address: String,
    port: u16,
    public_key: String,
    #[serde(default)]
    capabilities: Capabilities,
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
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SubscriptionSourceSpec {
    #[serde(rename = "type")]
    source_type: String,
    url: String,
    credentials_ref: Option<String>,
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
    #[serde(default)]
    target_ports: BTreeSet<u16>,
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
            target_ports: value.target_ports,
        }
    }
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
    requirements: RequirementsSpec,
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
    classes: BTreeMap<String, ClassSpec>,
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
    process_metadata: Option<ProcessMetadataSpec>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ProcessMetadataSpec {
    executable: Option<String>,
    user: Option<String>,
    group: Option<String>,
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

fn default_enabled() -> bool {
    true
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KubeResource {
    Egress(Resource<EgressSpec>),
    TransitProxy(Resource<TransitProxySpec>),
    Subscription(Resource<SubscriptionSpec>),
    EgressRule(Resource<EgressRuleSpec>),
    TransitRule(Resource<TransitRuleSpec>),
    ProxyRule(Resource<ProxyRuleSpec>),
    TrafficPolicy(Resource<TrafficPolicySpec>),
    Listener(Resource<ListenerSpec>),
    DnsPolicy(Resource<DnsPolicySpec>),
    FallbackPolicy(Resource<FallbackPolicySpec>),
}

impl KubeResource {
    fn key(&self) -> (&str, &str, &str) {
        match self {
            Self::Egress(value) => (&value.metadata.namespace, &value.kind, &value.metadata.name),
            Self::TransitProxy(value) => {
                (&value.metadata.namespace, &value.kind, &value.metadata.name)
            }
            Self::Subscription(value) => {
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
            Self::Egress(value) => &value.metadata,
            Self::TransitProxy(value) => &value.metadata,
            Self::Subscription(value) => &value.metadata,
            Self::EgressRule(value) => &value.metadata,
            Self::TransitRule(value) => &value.metadata,
            Self::ProxyRule(value) => &value.metadata,
            Self::TrafficPolicy(value) => &value.metadata,
            Self::Listener(value) => &value.metadata,
            Self::DnsPolicy(value) => &value.metadata,
            Self::FallbackPolicy(value) => &value.metadata,
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
        let mut values = Vec::new();
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
        validate_resource_set(&resources)?;
        Ok(Self { resources })
    }

    pub fn into_policy_config(self) -> Result<PolicyConfig, ConfigError> {
        let mut config = PolicyConfig::default();
        let mut rule_orders = HashSet::new();
        let mut default_policy = false;
        for resource in self.resources {
            match resource {
                KubeResource::Egress(value) => config.egresses.push(EgressConfig {
                    id: EgressId::new(value.metadata.name),
                    endpoint: Endpoint {
                        host: value.spec.address,
                        port: value.spec.port,
                    },
                    public_key: value.spec.public_key,
                    labels: value.metadata.labels,
                    capabilities: value.spec.capabilities,
                }),
                KubeResource::TransitProxy(value) => {
                    let source = value.spec.source.map(|source| TransitSource {
                        source_type: source.source_type,
                        subscription: source.subscription_ref.unwrap_or_default(),
                    });
                    let port = value.spec.port.unwrap_or(443);
                    config.transit_proxies.push(TransitProxyConfig {
                        id: TransitProxyId::new(value.metadata.name),
                        source,
                        protocol: value.spec.protocol,
                        endpoint: Endpoint {
                            host: value.spec.address.unwrap_or_default(),
                            port,
                        },
                        labels: value.metadata.labels,
                        tags: value.spec.tags,
                        weight: value.spec.weight,
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
                        (Some(id), None, None) => EgressSelection::Id(EgressId::new(id)),
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
                    config.egress_rules.push(EgressRule {
                        id: RuleId::new(value.metadata.name),
                        matches: value.spec.matches.unwrap_or_default().into(),
                        egress,
                        min_usable_paths: value.spec.requirements.min_usable_paths,
                    });
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
                        default_policy = true;
                        "default".to_owned()
                    });
                    config.transit_rules.push(TransitRule {
                        id: RuleId::new(value.metadata.name),
                        egress: EgressId::new(value.spec.egress_ref),
                        matches: value.spec.matches.unwrap_or_default().into(),
                        require: value.spec.require.into(),
                        reject_tags: value.spec.reject.tags,
                        weight: value.spec.weight,
                        traffic_policy: TrafficPolicyId::new(policy),
                    });
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
                    let select = match value.spec.select {
                        None => ProxySelection::Any,
                        Some(ProxySelectSpec::Any(candidate)) if candidate == "any" => {
                            ProxySelection::Any
                        }
                        Some(ProxySelectSpec::Any(selection)) => {
                            return Err(ConfigError::InvalidSpec {
                                kind: value.kind.clone(),
                                name: value.metadata.name.clone(),
                                reason: format!(
                                    "select must be any or a selector, got {selection}"
                                ),
                            });
                        }
                        Some(ProxySelectSpec::Selector(selector)) => {
                            ProxySelection::Selector(selector.into())
                        }
                    };
                    config.proxy_rules.push(ProxyRule {
                        id: RuleId::new(value.metadata.name),
                        matches: value.spec.matches.unwrap_or_default().into(),
                        require: value.spec.require.into(),
                        select,
                    });
                }
                KubeResource::TrafficPolicy(value) => {
                    if value.spec.scheduler != "effectiveCapacityWeighted" {
                        return Err(ConfigError::InvalidSpec {
                            kind: value.kind,
                            name: value.metadata.name,
                            reason: "scheduler must be effectiveCapacityWeighted".into(),
                        });
                    }
                    config.traffic_policies.push(TrafficPolicy {
                        id: TrafficPolicyId::new(value.metadata.name),
                        scheduler: Scheduler::EffectiveCapacityWeighted,
                        session_replication_budget_bps: value.spec.session_replication_budget_bps,
                        class_replication_budget_bps: value.spec.class_replication_budget_bps,
                        retransmission_replication: match value.spec.retransmission_replication {
                            ReplicationSpec::Allowed => RetransmissionReplication::Allowed,
                            ReplicationSpec::Disabled => RetransmissionReplication::Disabled,
                        },
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
                    let authentication = match value.spec.authentication {
                        AuthenticationValue::Mode(mode) => mode,
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
                            auth.mode
                        }
                    };
                    config.listeners.push(ListenerConfig {
                        id: ListenerId::new(value.metadata.name),
                        kind: value.spec.kind,
                        bind,
                        allowed_sources: value.spec.allowed_sources,
                        authentication,
                    });
                }
                KubeResource::FallbackPolicy(value) => config.fallback = Some(value.spec.action),
                KubeResource::Subscription(_) | KubeResource::DnsPolicy(_) => {}
            }
        }
        if default_policy
            && config
                .traffic_policies
                .iter()
                .all(|policy| policy.id.as_str() != "default")
        {
            config.traffic_policies.push(TrafficPolicy {
                id: TrafficPolicyId::new("default"),
                scheduler: Scheduler::EffectiveCapacityWeighted,
                session_replication_budget_bps: 0,
                class_replication_budget_bps: None,
                retransmission_replication: RetransmissionReplication::Disabled,
            });
        }
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
        "Egress" => parse!(EgressSpec, Egress),
        "TransitProxy" => parse!(TransitProxySpec, TransitProxy),
        "Subscription" => parse!(SubscriptionSpec, Subscription),
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

fn validate_resource_set(resources: &[KubeResource]) -> Result<(), ConfigError> {
    let dns = resources
        .iter()
        .filter(|resource| matches!(resource, KubeResource::DnsPolicy(_)))
        .count();
    let fallback = resources
        .iter()
        .filter(|resource| matches!(resource, KubeResource::FallbackPolicy(_)))
        .count();
    if dns != 1 {
        return Err(ConfigError::InvalidEnvelope(
            "exactly one DNSPolicy is required".into(),
        ));
    }
    if fallback != 1 {
        return Err(ConfigError::InvalidEnvelope(
            "exactly one FallbackPolicy is required".into(),
        ));
    }
    let mut rule_orders = HashSet::new();
    for resource in resources {
        validate_metadata(resource.metadata())?;
        match resource {
            KubeResource::Egress(value) => {
                validate_egress_spec(value)?;
            }
            KubeResource::TransitProxy(value) => {
                validate_transit_proxy_spec(value)?;
            }
            KubeResource::Subscription(value) => {
                validate_subscription_spec(value)?;
            }
            KubeResource::EgressRule(value) => {
                validate_rule_spec(
                    value.kind.as_str(),
                    &value.metadata.name,
                    value.spec.order,
                    value.spec.matches.as_ref(),
                    value.spec.catch_all,
                )?;
            }
            KubeResource::TransitRule(value) => {
                validate_rule_spec(
                    value.kind.as_str(),
                    &value.metadata.name,
                    value.spec.order,
                    value.spec.matches.as_ref(),
                    value.spec.catch_all,
                )?;
            }
            KubeResource::ProxyRule(value) => {
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
    validate_host("address", &value.spec.address)
        .map_err(|reason| invalid_spec(kind, name, reason))?;
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

fn validate_transit_proxy_spec(value: &Resource<TransitProxySpec>) -> Result<(), ConfigError> {
    let kind = value.kind.as_str();
    let name = value.metadata.name.as_str();
    const PROTOCOLS: [&str; 7] = [
        "direct", "http", "https", "socks5", "vless", "vmess", "xtls",
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
    if let Some(source) = &value.spec.source {
        if !["static", "clash", "sip008"].contains(&source.source_type.as_str()) {
            return Err(invalid_spec(
                kind,
                name,
                "source.type must be static, clash, or sip008",
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
    if !["static", "clash", "sip008"].contains(&source.source_type.as_str()) {
        return Err(invalid_spec(
            kind,
            name,
            "source.type must be static, clash, or sip008",
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
    if value.spec.classes.len() > MAX_MAP_ENTRIES
        || value.spec.classes.values().any(|class| class.share == 0)
    {
        return Err(invalid_spec(kind, name, "classes contain an invalid share"));
    }
    Ok(())
}

fn validate_listener_spec(value: &Resource<ListenerSpec>) -> Result<(), ConfigError> {
    let kind = value.kind.as_str();
    let name = value.metadata.name.as_str();
    if !matches!(value.spec.platform.as_str(), "any" | "linux" | "windows") {
        return Err(invalid_spec(
            kind,
            name,
            "platform must be any, linux, or windows",
        ));
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
        if source.is_empty() || contains_control(source) {
            return Err(invalid_spec(
                kind,
                name,
                "allowedSources contains an invalid CIDR",
            ));
        }
    }
    Ok(())
}

fn validate_dns_policy_spec(value: &Resource<DnsPolicySpec>) -> Result<(), ConfigError> {
    let kind = value.kind.as_str();
    let name = value.metadata.name.as_str();
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
        for server in servers.expect("checked above") {
            validate_dns_server(server).map_err(|reason| invalid_spec(kind, name, reason))?;
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
    if let Ok(address) = server.parse::<SocketAddr>() {
        return (address.port() != 0)
            .then_some(())
            .ok_or_else(|| "DNS server port must be non-zero".to_owned());
    }
    let (host, port) = server
        .rsplit_once(':')
        .ok_or_else(|| "DNS server must be host:port".to_owned())?;
    let port = port
        .parse::<u16>()
        .map_err(|_| "DNS server port is invalid".to_owned())?;
    validate_host("DNS server host", host.trim_matches(['[', ']']))?;
    if port == 0 {
        return Err("DNS server port must be non-zero".to_owned());
    }
    Ok(())
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
    if matches.is_none() && !catch_all {
        return Err(ConfigError::InvalidSpec {
            kind: kind.into(),
            name: name.into(),
            reason: "match is required unless catchAll:true".into(),
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
"#;

    #[test]
    fn parses_list_and_converts_to_domain_config() {
        let config = KubeConfig::from_yaml(VALID).expect("valid config");
        let policy = config.into_policy_config().expect("policy conversion");
        assert_eq!(policy.egresses[0].id.as_str(), "jp-1");
        assert_eq!(policy.fallback, Some(FallbackAction::Reject));
        assert_eq!(policy.listeners[0].id.as_str(), "local-http");
        assert_eq!(policy.listeners[0].bind.as_ref().expect("bind").port, 8080);
        assert_eq!(
            policy.listeners[0].authentication,
            AuthenticationMode::Required
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
        assert_eq!(config.resources.len(), 3);
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
