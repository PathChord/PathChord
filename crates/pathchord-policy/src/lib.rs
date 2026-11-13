//! Typed policy inputs and immutable compiled snapshots.
//!
//! The design fixes the domain model, not the serialized configuration shape.
//! These types therefore must not be treated as a stable YAML or API contract.

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use thiserror::Error;

mod config;

pub use config::{ConfigError, KubeConfig, KubeResource, ObjectMeta};

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
        }
    };
}

id_type!(EgressId);
id_type!(TransitProxyId);
id_type!(RuleId);
id_type!(TrafficPolicyId);
id_type!(ListenerId);

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
pub struct Capabilities {
    pub tcp: bool,
    pub udp: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EgressConfig {
    pub id: EgressId,
    pub endpoint: Endpoint,
    pub public_key: String,
    pub labels: BTreeMap<String, String>,
    pub capabilities: Capabilities,
    pub status_requirements: EgressStatusRequirements,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EgressStatusRequirements {
    pub min_usable_paths: u32,
    pub capabilities: BTreeSet<FlowProtocol>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransitSource {
    pub source_type: String,
    pub subscription: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransitProxyConfig {
    pub id: TransitProxyId,
    pub source: Option<TransitSource>,
    pub protocol: String,
    pub endpoint: Endpoint,
    pub labels: BTreeMap<String, String>,
    pub tags: BTreeSet<String>,
    pub weight: u32,
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
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProxySelection {
    Any,
    Selector(Selector),
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
    Socks5,
    Http,
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListenerConfig {
    pub id: ListenerId,
    pub kind: ListenerKind,
    /// Socket bind for socket-based listeners; TUN listeners use their
    /// interface/address fields in the source configuration instead.
    pub bind: Option<Endpoint>,
    pub allowed_sources: Vec<String>,
    pub authentication: AuthenticationMode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FallbackAction {
    Reject,
    Direct,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct PolicyConfig {
    pub egresses: Vec<EgressConfig>,
    pub transit_proxies: Vec<TransitProxyConfig>,
    pub egress_rules: Vec<EgressRule>,
    pub transit_rules: Vec<TransitRule>,
    pub proxy_rules: Vec<ProxyRule>,
    pub traffic_policies: Vec<TrafficPolicy>,
    pub listeners: Vec<ListenerConfig>,
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
    #[error("global fallback is required")]
    MissingFallback,
    #[error("{kind} id must not be empty")]
    EmptyId { kind: &'static str },
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
    #[error("rule {rule_id} references unknown egress {egress_id}")]
    UnknownEgress { rule_id: String, egress_id: String },
    #[error("rule {rule_id} references unknown traffic policy {policy_id}")]
    UnknownTrafficPolicy { rule_id: String, policy_id: String },
}

/// Immutable, validated Phase-0 configuration input.
///
/// This is not a compiled rule evaluator. Phase 3 will lower these models into
/// an ordered executable policy snapshot.
#[derive(Debug, Clone)]
pub struct ValidatedPolicySnapshot {
    generation: Generation,
    config: Arc<PolicyConfig>,
    fallback: FallbackAction,
}

impl ValidatedPolicySnapshot {
    pub fn new(generation: Generation, config: PolicyConfig) -> Result<Self, ValidationError> {
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
    validate_unique(
        "Transit Proxy",
        config.transit_proxies.iter().map(|item| item.id.as_str()),
    )?;
    validate_unique(
        "rule",
        config
            .egress_rules
            .iter()
            .map(|item| item.id.as_str())
            .chain(config.transit_rules.iter().map(|item| item.id.as_str()))
            .chain(config.proxy_rules.iter().map(|item| item.id.as_str())),
    )?;
    validate_unique(
        "traffic policy",
        config.traffic_policies.iter().map(|item| item.id.as_str()),
    )?;
    validate_unique(
        "listener",
        config.listeners.iter().map(|item| item.id.as_str()),
    )?;

    for egress in &config.egresses {
        validate_port("egress", egress.id.as_str(), egress.endpoint.port)?;
    }
    for proxy in &config.transit_proxies {
        validate_port("Transit Proxy", proxy.id.as_str(), proxy.endpoint.port)?;
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
    for policy in &config.traffic_policies {
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
        }
    }
    for rule in &config.transit_rules {
        validate_egress_reference(rule.id.as_str(), rule.egress.as_str(), &egress_ids)?;
    }

    let policy_ids: HashSet<_> = config
        .traffic_policies
        .iter()
        .map(|item| item.id.as_str())
        .collect();
    for rule in &config.transit_rules {
        if !policy_ids.contains(rule.traffic_policy.as_str()) {
            return Err(ValidationError::UnknownTrafficPolicy {
                rule_id: rule.id.as_str().to_owned(),
                policy_id: rule.traffic_policy.as_str().to_owned(),
            });
        }
    }

    Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;

    fn base_config() -> PolicyConfig {
        PolicyConfig {
            egresses: vec![EgressConfig {
                id: EgressId::new("jp-1"),
                endpoint: Endpoint {
                    host: "egress.example.net".into(),
                    port: 443,
                },
                public_key: "test-key".into(),
                labels: BTreeMap::new(),
                capabilities: Capabilities {
                    tcp: true,
                    udp: true,
                },
                status_requirements: EgressStatusRequirements::default(),
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
        invalid_port.egresses[0].endpoint.port = 0;
        assert!(matches!(
            ValidatedPolicySnapshot::new(Generation::new(1), invalid_port),
            Err(ValidationError::InvalidPort { kind: "egress", .. })
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
                id: TransitProxyId::new("provider-node"),
                source: Some(TransitSource {
                    source_type: "clash".into(),
                    subscription: "provider-a".into(),
                }),
                protocol: "vless".into(),
                endpoint: Endpoint {
                    host: "proxy.example.net".into(),
                    port: 443,
                },
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
    fn policy_context_and_decision_are_typed_and_mutually_exclusive() {
        let context = PolicyContext {
            flow_tags: BTreeSet::from(["gaming".into()]),
            listener_id: ListenerId::new("lan-socks"),
            source: "192.168.1.10:12345".parse().expect("source address"),
            authentication_identity: Some("alice".into()),
            process: Some(ProcessMetadata {
                process_id: Some(42),
                executable: Some("game.exe".into()),
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
