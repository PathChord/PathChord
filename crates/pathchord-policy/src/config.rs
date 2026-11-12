//! Kubernetes-style `pathchord.io/v1` configuration parsing.
//!
//! The wire/domain model in `lib.rs` remains useful to callers that construct
//! policy snapshots directly. This module owns the human-authored YAML shape,
//! including strict object envelopes and the conversion into that domain model.

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::net::SocketAddr;

use serde::{Deserialize, Serialize};
use serde_yaml::Value;
use thiserror::Error;

use crate::{
    AuthenticationMode, Capabilities, EgressConfig, EgressId, EgressRule, EgressSelection,
    Endpoint, FallbackAction, FlowMatch, FlowProtocol, Generation, ListenerConfig, ListenerId,
    ListenerKind, PolicyConfig, ProxyRule, ProxySelection, RetransmissionReplication, RuleId,
    Scheduler, Selector, TrafficPolicy, TrafficPolicyId, TransitProxyConfig, TransitProxyId,
    TransitRule, TransitSource, ValidatedPolicySnapshot,
};

pub const API_VERSION: &str = "pathchord.io/v1";

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
    bind: BindSpec,
    #[serde(default)]
    allowed_sources: Vec<String>,
    #[serde(default = "default_authentication_value")]
    authentication: AuthenticationValue,
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
    default_route: String,
    local: Option<DnsLocalSpec>,
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
        for document in serde_yaml::Deserializer::from_str(input) {
            let value = Value::deserialize(document)?;
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
                        (None, Some(selector), None) => EgressSelection::Selector(selector.into()),
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
                    let bind = parse_bind(&value.spec.bind).map_err(|reason| {
                        ConfigError::InvalidSpec {
                            kind: value.kind.clone(),
                            name: value.metadata.name.clone(),
                            reason,
                        }
                    })?;
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
    map.get(Value::String("kind".into()))
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
        let (namespace, _, name) = resource.key();
        validate_metadata(namespace, name)?;
        match resource {
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
        if let KubeResource::DnsPolicy(value) = resource
            && value.spec.default_route == "local"
            && value
                .spec
                .local
                .as_ref()
                .is_none_or(|local| local.servers.is_empty())
        {
            return Err(ConfigError::InvalidSpec {
                kind: value.kind.clone(),
                name: value.metadata.name.clone(),
                reason: "local.servers is required for local DNS route".into(),
            });
        }
        if let KubeResource::DnsPolicy(value) = resource
            && !matches!(
                value.spec.default_route.as_str(),
                "local" | "transit" | "egress" | "blocked"
            )
        {
            return Err(ConfigError::InvalidSpec {
                kind: value.kind.clone(),
                name: value.metadata.name.clone(),
                reason: "defaultRoute must be local, transit, egress, or blocked".into(),
            });
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

fn validate_metadata(namespace: &str, name: &str) -> Result<(), ConfigError> {
    let bytes = name.as_bytes();
    let valid = !bytes.is_empty()
        && name.len() <= 63
        && bytes
            .first()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        && bytes
            .last()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-');
    if namespace.is_empty() || !valid {
        return Err(ConfigError::InvalidEnvelope(format!(
            "invalid metadata name or namespace: {namespace}/{name}"
        )));
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
    if matches.is_some_and(|value| value == &FlowMatchSpec::default()) && !catch_all {
        return Err(ConfigError::InvalidSpec {
            kind: kind.into(),
            name: name.into(),
            reason: "empty match requires catchAll:true".into(),
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
      publicKey: test-key
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
        assert_eq!(policy.listeners[0].bind.port, 8080);
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
        let duplicate = VALID.replace("  - apiVersion: pathchord.io/v1\n    kind: DNSPolicy", "  - apiVersion: pathchord.io/v1\n    kind: Egress\n    metadata:\n      name: jp-1\n    spec:\n      address: egress2.example.net\n      port: 443\n      publicKey: test-key\n      capabilities: {tcp: true, udp: true}\n  - apiVersion: pathchord.io/v1\n    kind: DNSPolicy");
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
  publicKey: test-key
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
}
