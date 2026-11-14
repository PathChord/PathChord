use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

use thiserror::Error;

use crate::{
    Capabilities, EgressConfig, EgressId, EgressRule, EgressSelection, FlowMatch, FlowProtocol,
    Generation, ListenerId, PolicyContext, ProxyRule, ProxySelection, RuleId, Selector,
    TargetEndpoint, TargetHost, TrafficPolicy, TrafficPolicyId, TransitProxyConfig, TransitProxyId,
    TransitRule, ValidatedPolicySnapshot,
};

/// Runtime state that controls whether a configured node can admit new work.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum RuntimeNodeState {
    Ready,
    Degraded,
    Draining,
    #[default]
    Down,
}

impl RuntimeNodeState {
    const fn admits_new_work(self) -> bool {
        matches!(self, Self::Ready | Self::Degraded)
    }
}

/// Runtime-owned Egress facts used during one immutable policy evaluation.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EgressRuntimeStatus {
    pub state: RuntimeNodeState,
    pub usable_paths: u32,
    /// Runtime and administrator labels override static labels with the same key.
    pub labels: BTreeMap<String, String>,
    pub tags: BTreeSet<String>,
}

/// Runtime-owned Transit Proxy facts used during one immutable policy evaluation.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TransitProxyRuntimeStatus {
    pub state: RuntimeNodeState,
    pub capabilities: BTreeSet<FlowProtocol>,
    /// Runtime and administrator labels override static labels with the same key.
    pub labels: BTreeMap<String, String>,
    pub tags: BTreeSet<String>,
    /// A precomputed, bounded score derived from published observations.
    pub selection_score: u64,
    pub quota_remaining: Option<u64>,
    pub traffic_multiplier_basis_points: Option<u32>,
}

/// Published runtime state captured once at the beginning of rule evaluation.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RuntimeCatalog {
    egresses: BTreeMap<EgressId, EgressRuntimeStatus>,
    transit_proxies: BTreeMap<TransitProxyId, TransitProxyRuntimeStatus>,
    dynamic_transit_proxies: BTreeMap<TransitProxyId, TransitProxyConfig>,
}

impl RuntimeCatalog {
    pub fn set_egress(&mut self, id: EgressId, status: EgressRuntimeStatus) {
        self.egresses.insert(id, status);
    }

    pub fn set_transit_proxy(&mut self, id: TransitProxyId, status: TransitProxyRuntimeStatus) {
        self.transit_proxies.insert(id, status);
    }

    pub fn set_dynamic_transit_proxy(
        &mut self,
        config: TransitProxyConfig,
        status: TransitProxyRuntimeStatus,
    ) {
        self.transit_proxies.insert(config.id.clone(), status);
        self.dynamic_transit_proxies
            .insert(config.id.clone(), config);
    }

    pub fn remove_dynamic_transit_proxy(&mut self, id: &TransitProxyId) {
        self.dynamic_transit_proxies.remove(id);
        self.transit_proxies.remove(id);
    }

    #[must_use]
    pub fn egress(&self, id: &EgressId) -> Option<&EgressRuntimeStatus> {
        self.egresses.get(id)
    }

    #[must_use]
    pub fn transit_proxy(&self, id: &TransitProxyId) -> Option<&TransitProxyRuntimeStatus> {
        self.transit_proxies.get(id)
    }

    fn dynamic_transit_proxies(&self) -> &BTreeMap<TransitProxyId, TransitProxyConfig> {
        &self.dynamic_transit_proxies
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransitCandidate {
    pub id: TransitProxyId,
    pub relationship_weight: u32,
    pub selection_score: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EgressRouteCandidate {
    pub egress_id: EgressId,
    pub transit_rule_id: RuleId,
    pub traffic_policy_id: TrafficPolicyId,
    pub traffic_class: Option<String>,
    pub transit_proxies: Vec<TransitCandidate>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EgressRoutePlan {
    pub generation: Generation,
    pub egress_rule_id: RuleId,
    pub min_usable_paths: u32,
    pub required_capabilities: BTreeSet<FlowProtocol>,
    pub candidates: Vec<EgressRouteCandidate>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyRoutePlan {
    pub generation: Generation,
    pub proxy_rule_id: RuleId,
    pub transit_proxy_id: TransitProxyId,
    pub selection_score: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RoutePlan {
    Egress(EgressRoutePlan),
    Proxy(ProxyRoutePlan),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RejectReason {
    GlobalFallback,
    /// A rule without an explicit traffic policy admitted more than one
    /// Transit relationship for this flow.
    MissingTrafficPolicy,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Evaluation {
    Route(RoutePlan),
    Direct {
        generation: Generation,
    },
    Reject {
        generation: Generation,
        reason: RejectReason,
    },
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum CompileError {
    #[error("rule {rule_id} contains invalid source network {network}")]
    InvalidSourceNetwork { rule_id: String, network: String },
    #[error("rule {rule_id} contains an empty selector")]
    EmptySelector { rule_id: String },
}

#[derive(Debug, Clone)]
struct CompiledMatch {
    namespace: String,
    source: FlowMatch,
    source_networks: Vec<Network>,
}

impl CompiledMatch {
    fn compile(rule_id: &RuleId, source: &FlowMatch) -> Result<Self, CompileError> {
        let source_networks = source
            .source_networks
            .iter()
            .map(|value| {
                Network::parse(value).ok_or_else(|| CompileError::InvalidSourceNetwork {
                    rule_id: rule_id.as_str().to_owned(),
                    network: value.clone(),
                })
            })
            .collect::<Result<_, _>>()?;
        Ok(Self {
            namespace: rule_id.namespace().to_owned(),
            source: source.clone(),
            source_networks,
        })
    }

    fn matches(&self, context: &PolicyContext) -> bool {
        context.listener_id.namespace() == self.namespace
            && (self.source.flow_tags.is_empty()
                || !self.source.flow_tags.is_disjoint(&context.flow_tags))
            && (self.source.protocols.is_empty()
                || self.source.protocols.contains(&context.protocol))
            && (self.source.listener_ids.is_empty()
                || self.source.listener_ids.contains(&context.listener_id))
            && (self.source_networks.is_empty()
                || self
                    .source_networks
                    .iter()
                    .any(|network| network.contains(context.source.ip())))
            && (self.source.authentication_identities.is_empty()
                || context
                    .authentication_identity
                    .as_ref()
                    .is_some_and(|identity| {
                        self.source.authentication_identities.contains(identity)
                    }))
            && (self.source.process_executables.is_empty()
                || context
                    .process
                    .as_ref()
                    .and_then(|process| process.executable.as_ref())
                    .is_some_and(|executable| self.source.process_executables.contains(executable)))
            && (self.source.target_hosts.is_empty()
                || self
                    .source
                    .target_hosts
                    .iter()
                    .any(|candidate| target_host_matches(candidate, &context.target.host)))
            && (self.source.target_ports.is_empty()
                || self.source.target_ports.contains(&context.target.port))
    }
}

#[derive(Debug, Clone)]
struct CompiledEgressRule {
    rule: EgressRule,
    matches: CompiledMatch,
}

#[derive(Debug, Clone)]
struct CompiledTransitRule {
    rule: TransitRule,
    matches: CompiledMatch,
}

#[derive(Debug, Clone)]
struct CompiledProxyRule {
    rule: ProxyRule,
    matches: CompiledMatch,
}

/// Immutable, deterministic and I/O-free evaluator for one configuration generation.
#[derive(Debug, Clone)]
pub struct CompiledPolicy {
    generation: Generation,
    fallback: crate::FallbackAction,
    egresses: BTreeMap<EgressId, EgressConfig>,
    transit_proxies: BTreeMap<TransitProxyId, TransitProxyConfig>,
    traffic_policies: BTreeMap<TrafficPolicyId, TrafficPolicy>,
    egress_rules: Vec<CompiledEgressRule>,
    transit_rules: Vec<CompiledTransitRule>,
    proxy_rules: Vec<CompiledProxyRule>,
}

impl CompiledPolicy {
    pub fn compile(snapshot: &ValidatedPolicySnapshot) -> Result<Self, CompileError> {
        let config = snapshot.config();
        let egress_rules = config
            .egress_rules
            .iter()
            .map(|rule| {
                if let EgressSelection::Selector(selector) = &rule.egress {
                    ensure_selector(rule.id.as_str(), selector)?;
                }
                Ok(CompiledEgressRule {
                    matches: CompiledMatch::compile(&rule.id, &rule.matches)?,
                    rule: rule.clone(),
                })
            })
            .collect::<Result<_, CompileError>>()?;
        let transit_rules = config
            .transit_rules
            .iter()
            .map(|rule| {
                Ok(CompiledTransitRule {
                    matches: CompiledMatch::compile(&rule.id, &rule.matches)?,
                    rule: rule.clone(),
                })
            })
            .collect::<Result<_, CompileError>>()?;
        let proxy_rules = config
            .proxy_rules
            .iter()
            .map(|rule| {
                if let ProxySelection::Selector(selector) = &rule.select {
                    ensure_selector(rule.id.as_str(), selector)?;
                }
                Ok(CompiledProxyRule {
                    matches: CompiledMatch::compile(&rule.id, &rule.matches)?,
                    rule: rule.clone(),
                })
            })
            .collect::<Result<_, CompileError>>()?;

        Ok(Self {
            generation: snapshot.generation(),
            fallback: snapshot.fallback(),
            egresses: config
                .egresses
                .iter()
                .cloned()
                .map(|egress| (egress.id.clone(), egress))
                .collect(),
            transit_proxies: config
                .transit_proxies
                .iter()
                .cloned()
                .map(|proxy| (proxy.id.clone(), proxy))
                .collect(),
            traffic_policies: config
                .traffic_policies
                .iter()
                .cloned()
                .map(|policy| (policy.id.clone(), policy))
                .collect(),
            egress_rules,
            transit_rules,
            proxy_rules,
        })
    }

    #[must_use]
    pub const fn generation(&self) -> Generation {
        self.generation
    }

    #[must_use]
    pub fn traffic_policy(&self, id: &TrafficPolicyId) -> Option<&TrafficPolicy> {
        self.traffic_policies.get(id)
    }

    #[must_use]
    pub fn traffic_policies(&self) -> BTreeMap<TrafficPolicyId, TrafficPolicy> {
        self.traffic_policies.clone()
    }

    #[must_use]
    pub fn evaluate(&self, context: &PolicyContext, runtime: &RuntimeCatalog) -> Evaluation {
        for compiled in &self.egress_rules {
            if !compiled.matches.matches(context) {
                continue;
            }
            if compiled.rule.egress == EgressSelection::None {
                break;
            }

            let candidates = match self.egress_candidates(&compiled.rule, context, runtime) {
                Ok(candidates) => candidates,
                Err(reason) => {
                    return Evaluation::Reject {
                        generation: self.generation,
                        reason,
                    };
                }
            };
            if !candidates.is_empty() {
                return Evaluation::Route(RoutePlan::Egress(EgressRoutePlan {
                    generation: self.generation,
                    egress_rule_id: compiled.rule.id.clone(),
                    min_usable_paths: compiled.rule.min_usable_paths,
                    required_capabilities: compiled.rule.required_capabilities.clone(),
                    candidates,
                }));
            }
        }

        for compiled in &self.proxy_rules {
            if !compiled.matches.matches(context) {
                continue;
            }
            if compiled.rule.select == ProxySelection::Direct {
                return Evaluation::Direct {
                    generation: self.generation,
                };
            }
            if let Some(route) = self.ordinary_proxy_candidate(&compiled.rule, context, runtime) {
                return Evaluation::Route(RoutePlan::Proxy(route));
            }
        }

        match self.fallback {
            crate::FallbackAction::Direct => Evaluation::Direct {
                generation: self.generation,
            },
            crate::FallbackAction::Reject => Evaluation::Reject {
                generation: self.generation,
                reason: RejectReason::GlobalFallback,
            },
        }
    }

    /// Return only rule-derived warmup routes. This deliberately uses a
    /// synthetic empty-tag context, so a Transit that is eligible only for a
    /// different flow selector is not counted by namespace-wide warmup.
    pub fn warmup_routes(
        &self,
        protocol: FlowProtocol,
        runtime: &RuntimeCatalog,
    ) -> Vec<(EgressId, u32, EgressRouteCandidate)> {
        let mut routes = Vec::new();
        for compiled in &self.egress_rules {
            let context = PolicyContext {
                flow_tags: BTreeSet::new(),
                listener_id: ListenerId::in_namespace(
                    compiled.matches.namespace.as_str(),
                    "__pathchord_warmup",
                ),
                source: "0.0.0.0:0".parse().expect("warmup source address"),
                authentication_identity: None,
                process: None,
                protocol,
                target: TargetEndpoint {
                    host: TargetHost::Hostname("__pathchord_warmup__".into()),
                    port: 0,
                },
            };
            if !compiled.matches.matches(&context) {
                continue;
            }
            let egresses: Vec<_> = match &compiled.rule.egress {
                EgressSelection::Id(id) => self.egresses.get(id).into_iter().collect(),
                EgressSelection::Selector(selector) => self
                    .egresses
                    .values()
                    .filter(|egress| {
                        egress.id.namespace() == compiled.matches.namespace
                            && selector.labels.iter().all(|(key, value)| {
                                egress.labels.get(key).is_some_and(|actual| actual == value)
                            })
                            && selector.tags.is_empty()
                            && selector.capabilities.iter().all(|capability| {
                                egress_supports(&egress.capabilities, *capability)
                            })
                    })
                    .collect(),
                EgressSelection::None => Vec::new(),
            };
            for egress in egresses {
                if !egress_supports(&egress.capabilities, protocol)
                    || !compiled
                        .rule
                        .required_capabilities
                        .iter()
                        .all(|capability| egress_supports(&egress.capabilities, *capability))
                {
                    continue;
                }
                if let Ok(Some(candidate)) = self.transit_candidate(egress, &context, runtime) {
                    routes.push((egress.id.clone(), compiled.rule.min_usable_paths, candidate));
                }
            }
        }
        routes
    }

    fn egress_candidates(
        &self,
        rule: &EgressRule,
        context: &PolicyContext,
        runtime: &RuntimeCatalog,
    ) -> Result<Vec<EgressRouteCandidate>, RejectReason> {
        let egresses: Vec<_> = match &rule.egress {
            EgressSelection::Id(id) => self.egresses.get(id).into_iter().collect(),
            EgressSelection::Selector(selector) => self
                .egresses
                .values()
                .filter(|egress| {
                    egress.id.namespace() == rule.id.namespace()
                        && runtime
                            .egress(&egress.id)
                            .is_some_and(|status| egress_selector_matches(selector, egress, status))
                })
                .collect(),
            EgressSelection::None => Vec::new(),
        };

        let mut candidates = Vec::new();
        for egress in egresses {
            let Some(status) = runtime.egress(&egress.id) else {
                continue;
            };
            if !egress_is_usable(rule, egress, status, context.protocol) {
                continue;
            }
            if let Some(candidate) = self.transit_candidate(egress, context, runtime)? {
                candidates.push(candidate);
            }
        }
        Ok(candidates)
    }

    fn transit_candidate(
        &self,
        egress: &EgressConfig,
        context: &PolicyContext,
        runtime: &RuntimeCatalog,
    ) -> Result<Option<EgressRouteCandidate>, RejectReason> {
        let Some(compiled) = self.transit_rules.iter().find(|compiled| {
            compiled.rule.egress == egress.id && compiled.matches.matches(context)
        }) else {
            return Ok(None);
        };
        let mut transit_proxies: Vec<_> = self
            .transit_proxy_configs(runtime)
            .filter_map(|proxy| {
                if proxy.id.namespace() != compiled.rule.id.namespace() {
                    return None;
                }
                let status = runtime.transit_proxy(&proxy.id)?;
                if !transit_is_usable(&compiled.rule, proxy, status, context.protocol) {
                    return None;
                }
                Some(TransitCandidate {
                    id: proxy.id.clone(),
                    relationship_weight: compiled.rule.weight,
                    selection_score: weighted_score(proxy.weight, status.selection_score),
                })
            })
            .collect();
        if transit_proxies.is_empty() {
            return Ok(None);
        }
        if transit_proxies.len() > 1
            && compiled.rule.traffic_policy.resource_name()
                == crate::config::IMPLICIT_SINGLE_TRANSIT_POLICY
        {
            return Err(RejectReason::MissingTrafficPolicy);
        }
        transit_proxies.sort_by(|left, right| left.id.cmp(&right.id));
        Ok(Some(EgressRouteCandidate {
            egress_id: egress.id.clone(),
            transit_rule_id: compiled.rule.id.clone(),
            traffic_policy_id: compiled.rule.traffic_policy.clone(),
            traffic_class: compiled.rule.traffic_class.clone(),
            transit_proxies,
        }))
    }

    fn ordinary_proxy_candidate(
        &self,
        rule: &ProxyRule,
        context: &PolicyContext,
        runtime: &RuntimeCatalog,
    ) -> Option<ProxyRoutePlan> {
        let selected = match &rule.select {
            ProxySelection::Any => None,
            ProxySelection::Selector(selector) => Some(selector),
            ProxySelection::Direct => return None,
        };
        let mut candidates: Vec<_> = self
            .transit_proxy_configs(runtime)
            .filter_map(|proxy| {
                if proxy.id.namespace() != rule.id.namespace() {
                    return None;
                }
                let status = runtime.transit_proxy(&proxy.id)?;
                if !ordinary_proxy_is_usable(rule, selected, proxy, status, context.protocol) {
                    return None;
                }
                Some((proxy, weighted_score(proxy.weight, status.selection_score)))
            })
            .collect();
        candidates.sort_by(|(left_proxy, left_score), (right_proxy, right_score)| {
            right_score
                .cmp(left_score)
                .then_with(|| left_proxy.id.cmp(&right_proxy.id))
        });
        let (proxy, selection_score) = candidates.into_iter().next()?;
        Some(ProxyRoutePlan {
            generation: self.generation,
            proxy_rule_id: rule.id.clone(),
            transit_proxy_id: proxy.id.clone(),
            selection_score,
        })
    }

    fn transit_proxy_configs<'a>(
        &'a self,
        runtime: &'a RuntimeCatalog,
    ) -> impl Iterator<Item = &'a TransitProxyConfig> {
        self.transit_proxies
            .values()
            .filter(|proxy| !runtime.dynamic_transit_proxies().contains_key(&proxy.id))
            .chain(runtime.dynamic_transit_proxies().values())
    }
}

impl ValidatedPolicySnapshot {
    pub fn compile(&self) -> Result<CompiledPolicy, CompileError> {
        CompiledPolicy::compile(self)
    }
}

fn ensure_selector(rule_id: &str, selector: &Selector) -> Result<(), CompileError> {
    if selector.labels.is_empty() && selector.tags.is_empty() && selector.capabilities.is_empty() {
        Err(CompileError::EmptySelector {
            rule_id: rule_id.to_owned(),
        })
    } else {
        Ok(())
    }
}

fn egress_is_usable(
    rule: &EgressRule,
    egress: &EgressConfig,
    status: &EgressRuntimeStatus,
    protocol: FlowProtocol,
) -> bool {
    let min_paths = rule
        .min_usable_paths
        .max(egress.status_requirements.min_usable_paths);
    status.state.admits_new_work()
        && status.usable_paths >= min_paths
        && egress_supports(&egress.capabilities, protocol)
        && rule
            .required_capabilities
            .iter()
            .chain(egress.status_requirements.capabilities.iter())
            .all(|capability| egress_supports(&egress.capabilities, *capability))
}

fn egress_selector_matches(
    selector: &Selector,
    egress: &EgressConfig,
    status: &EgressRuntimeStatus,
) -> bool {
    labels_match(&selector.labels, &egress.labels, &status.labels)
        && selector.tags.is_subset(&status.tags)
        && selector
            .capabilities
            .iter()
            .all(|capability| egress_supports(&egress.capabilities, *capability))
}

fn transit_is_usable(
    rule: &TransitRule,
    proxy: &TransitProxyConfig,
    status: &TransitProxyRuntimeStatus,
    _protocol: FlowProtocol,
) -> bool {
    status.state.admits_new_work()
        && status.capabilities.contains(&FlowProtocol::Tcp)
        && labels_match(&rule.require.labels, &proxy.labels, &status.labels)
        && tags_match(&rule.require.tags, &proxy.tags, &status.tags)
        && rule.require.capabilities.is_subset(&status.capabilities)
        && rule
            .reject_tags
            .iter()
            .all(|tag| !proxy.tags.contains(tag) && !status.tags.contains(tag))
}

fn ordinary_proxy_is_usable(
    rule: &ProxyRule,
    selected: Option<&Selector>,
    proxy: &TransitProxyConfig,
    status: &TransitProxyRuntimeStatus,
    protocol: FlowProtocol,
) -> bool {
    status.state.admits_new_work()
        && status.capabilities.contains(&protocol)
        && selector_matches(&rule.require, proxy, status)
        && selected.is_none_or(|selector| selector_matches(selector, proxy, status))
}

fn selector_matches(
    selector: &Selector,
    proxy: &TransitProxyConfig,
    status: &TransitProxyRuntimeStatus,
) -> bool {
    labels_match(&selector.labels, &proxy.labels, &status.labels)
        && tags_match(&selector.tags, &proxy.tags, &status.tags)
        && selector.capabilities.is_subset(&status.capabilities)
}

fn labels_match(
    required: &BTreeMap<String, String>,
    configured: &BTreeMap<String, String>,
    runtime: &BTreeMap<String, String>,
) -> bool {
    required.iter().all(|(key, value)| {
        runtime
            .get(key)
            .or_else(|| configured.get(key))
            .is_some_and(|candidate| candidate == value)
    })
}

fn tags_match(
    required: &BTreeSet<String>,
    configured: &BTreeSet<String>,
    runtime: &BTreeSet<String>,
) -> bool {
    required
        .iter()
        .all(|tag| configured.contains(tag) || runtime.contains(tag))
}

const fn egress_supports(capabilities: &Capabilities, protocol: FlowProtocol) -> bool {
    match protocol {
        FlowProtocol::Tcp => capabilities.tcp,
        FlowProtocol::Udp => capabilities.udp,
    }
}

fn target_host_matches(candidate: &str, target: &crate::TargetHost) -> bool {
    match target {
        crate::TargetHost::Hostname(hostname) => candidate.eq_ignore_ascii_case(hostname),
        crate::TargetHost::Ip(address) => candidate == address.to_string(),
    }
}

fn weighted_score(weight: u32, runtime_score: u64) -> u64 {
    u64::from(weight).saturating_mul(runtime_score)
}

#[derive(Debug, Clone, Copy)]
enum Network {
    V4 { network: u32, mask: u32 },
    V6 { network: u128, mask: u128 },
}

impl Network {
    fn parse(value: &str) -> Option<Self> {
        let (address, prefix) = value.split_once('/')?;
        let address = address.parse::<IpAddr>().ok()?;
        let prefix = prefix.parse::<u8>().ok()?;
        match address {
            IpAddr::V4(address) if prefix <= 32 => {
                let mask = prefix_mask_u32(prefix);
                Some(Self::V4 {
                    network: u32::from(address) & mask,
                    mask,
                })
            }
            IpAddr::V6(address) if prefix <= 128 => {
                let mask = prefix_mask_u128(prefix);
                Some(Self::V6 {
                    network: u128::from(address) & mask,
                    mask,
                })
            }
            _ => None,
        }
    }

    fn contains(self, address: IpAddr) -> bool {
        match (self, address) {
            (Self::V4 { network, mask }, IpAddr::V4(address)) => {
                u32::from(address) & mask == network
            }
            (Self::V6 { network, mask }, IpAddr::V6(address)) => {
                u128::from(address) & mask == network
            }
            _ => false,
        }
    }
}

const fn prefix_mask_u32(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    }
}

const fn prefix_mask_u128(prefix: u8) -> u128 {
    if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - prefix)
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use super::*;
    use crate::{
        Endpoint, FallbackAction, FlowProtocol, PolicyConfig, ProcessMetadata, ProxySelection,
        RetransmissionReplication, Scheduler, TargetEndpoint, TargetHost, TrafficPolicy,
    };

    fn egress(id: &str, labels: &[(&str, &str)], tcp: bool, udp: bool) -> EgressConfig {
        EgressConfig {
            id: EgressId::new(id),
            endpoint: Endpoint {
                host: format!("{id}.example.test"),
                port: 443,
            },
            public_key: "test-key".into(),
            labels: labels
                .iter()
                .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
                .collect(),
            capabilities: Capabilities { tcp, udp },
            status_requirements: crate::EgressStatusRequirements {
                min_usable_paths: 1,
                capabilities: BTreeSet::new(),
            },
        }
    }

    fn proxy(id: &str, labels: &[(&str, &str)], tags: &[&str], weight: u32) -> TransitProxyConfig {
        TransitProxyConfig {
            options: Default::default(),
            id: TransitProxyId::new(id),
            source: None,
            protocol: "direct".into(),
            endpoint: Endpoint {
                host: "127.0.0.1".into(),
                port: 443,
            },
            credentials_ref: None,
            labels: labels
                .iter()
                .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
                .collect(),
            tags: tags.iter().map(|tag| (*tag).to_owned()).collect(),
            weight,
        }
    }

    fn traffic_policy(id: &str) -> crate::TrafficPolicy {
        TrafficPolicy {
            id: TrafficPolicyId::new(id),
            scheduler: Scheduler::EffectiveCapacityWeighted,
            session_replication_budget_bps: 0,
            class_replication_budget_bps: None,
            retransmission_replication: RetransmissionReplication::Disabled,
            classes: BTreeMap::new(),
        }
    }

    fn egress_rule(id: &str, egress: &str, min_usable_paths: u32) -> EgressRule {
        EgressRule {
            id: RuleId::new(id),
            matches: FlowMatch::default(),
            egress: EgressSelection::Id(EgressId::new(egress)),
            min_usable_paths,
            required_capabilities: BTreeSet::new(),
        }
    }

    fn transit_rule(id: &str, egress: &str, require: Selector) -> TransitRule {
        TransitRule {
            id: RuleId::new(id),
            egress: EgressId::new(egress),
            matches: FlowMatch::default(),
            require,
            reject_tags: BTreeSet::new(),
            weight: 100,
            traffic_policy: TrafficPolicyId::new("default"),
            traffic_class: None,
        }
    }

    fn context() -> PolicyContext {
        PolicyContext {
            flow_tags: BTreeSet::from(["web".into()]),
            listener_id: crate::ListenerId::new("local-http"),
            source: "192.168.1.42:12345".parse::<SocketAddr>().unwrap(),
            authentication_identity: Some("alice".into()),
            process: Some(ProcessMetadata {
                process_id: Some(42),
                executable: Some("browser".into()),
                user_id: Some(1000),
                group_id: Some(1000),
            }),
            protocol: FlowProtocol::Tcp,
            target: TargetEndpoint {
                host: TargetHost::Hostname("www.example.test".into()),
                port: 443,
            },
        }
    }

    fn ready_egress(paths: u32) -> EgressRuntimeStatus {
        EgressRuntimeStatus {
            state: RuntimeNodeState::Ready,
            usable_paths: paths,
            ..EgressRuntimeStatus::default()
        }
    }

    fn ready_proxy(protocols: &[FlowProtocol], score: u64) -> TransitProxyRuntimeStatus {
        TransitProxyRuntimeStatus {
            state: RuntimeNodeState::Ready,
            capabilities: protocols.iter().copied().collect(),
            selection_score: score,
            ..TransitProxyRuntimeStatus::default()
        }
    }

    fn compile(config: PolicyConfig) -> CompiledPolicy {
        ValidatedPolicySnapshot::new(Generation::new(7), config)
            .unwrap()
            .compile()
            .unwrap()
    }

    #[test]
    fn implicit_transit_policy_allows_one_candidate_but_rejects_dynamic_multipath() {
        let input = r#"
apiVersion: pathchord.io/v1
kind: Egress
metadata: {name: edge}
spec:
  address: edge.example.test
  port: 443
  publicKey: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
  capabilities: {tcp: true, udp: true}
---
apiVersion: pathchord.io/v1
kind: TransitProxy
metadata: {name: first}
spec: {protocol: direct}
---
apiVersion: pathchord.io/v1
kind: EgressRule
metadata: {name: route}
spec: {order: 10, catchAll: true, egressRef: edge}
---
apiVersion: pathchord.io/v1
kind: TransitRule
metadata: {name: paths}
spec: {order: 20, catchAll: true, egressRef: edge}
---
apiVersion: pathchord.io/v1
kind: DNSPolicy
metadata: {name: dns}
spec: {defaultRoute: blocked}
---
apiVersion: pathchord.io/v1
kind: FallbackPolicy
metadata: {name: fallback}
spec: {action: direct}
"#;
        let implicit = crate::KubeConfig::from_yaml(input)
            .unwrap()
            .into_validated_snapshot(Generation::new(7))
            .unwrap()
            .compile()
            .unwrap();
        let mut runtime = RuntimeCatalog::default();
        runtime.set_egress(EgressId::new("edge"), ready_egress(1));
        runtime.set_transit_proxy(
            TransitProxyId::new("first"),
            ready_proxy(&[FlowProtocol::Tcp], 1),
        );
        assert!(matches!(
            implicit.evaluate(&context(), &runtime),
            Evaluation::Route(RoutePlan::Egress(_))
        ));
        // A subscription refresh may add a second matching relationship after
        // validation. This must fail closed even when the fallback is direct.
        runtime.set_dynamic_transit_proxy(
            proxy("second", &[], &[], 100),
            ready_proxy(&[FlowProtocol::Tcp], 1),
        );
        assert_eq!(
            implicit.evaluate(&context(), &runtime),
            Evaluation::Reject {
                generation: Generation::new(7),
                reason: RejectReason::MissingTrafficPolicy,
            }
        );

        let explicit_input = input.replace(
            "spec: {order: 20, catchAll: true, egressRef: edge}",
            "spec: {order: 20, catchAll: true, egressRef: edge, trafficPolicyRef: default}\n---\napiVersion: pathchord.io/v1\nkind: TrafficPolicy\nmetadata: {name: default}\nspec: {}",
        );
        let explicit = crate::KubeConfig::from_yaml(&explicit_input)
            .unwrap()
            .into_validated_snapshot(Generation::new(7))
            .unwrap()
            .compile()
            .unwrap();
        let Evaluation::Route(RoutePlan::Egress(route)) = explicit.evaluate(&context(), &runtime)
        else {
            panic!("explicit traffic policy must allow the multipath route");
        };
        assert_eq!(route.candidates[0].transit_proxies.len(), 2);
    }

    #[test]
    fn first_fully_usable_egress_rule_wins() {
        let policy = compile(PolicyConfig {
            egresses: vec![
                egress("first", &[], true, false),
                egress("second", &[], true, false),
            ],
            transit_proxies: vec![proxy("direct", &[], &[], 100)],
            subscriptions: Vec::new(),
            egress_rules: vec![
                egress_rule("first-rule", "first", 2),
                egress_rule("second-rule", "second", 1),
            ],
            transit_rules: vec![
                transit_rule("first-transit", "first", Selector::default()),
                transit_rule("second-transit", "second", Selector::default()),
            ],
            proxy_rules: Vec::new(),
            traffic_policies: vec![traffic_policy("default")],
            listeners: Vec::new(),
            dns_policy: None,
            node_probe: None,
            fallback: Some(FallbackAction::Reject),
        });
        let mut runtime = RuntimeCatalog::default();
        runtime.set_egress(EgressId::new("first"), ready_egress(1));
        runtime.set_egress(EgressId::new("second"), ready_egress(1));
        runtime.set_transit_proxy(
            TransitProxyId::new("direct"),
            ready_proxy(&[FlowProtocol::Tcp], 1),
        );

        let Evaluation::Route(RoutePlan::Egress(route)) = policy.evaluate(&context(), &runtime)
        else {
            panic!("expected an Egress route");
        };
        assert_eq!(route.egress_rule_id.as_str(), "second-rule");
        assert_eq!(route.candidates[0].egress_id.as_str(), "second");
    }

    #[test]
    fn warmup_routes_keep_transit_rule_eligibility() {
        let mut rule = transit_rule("selected-transit", "edge", Selector::default());
        rule.require.tags.insert("eligible".into());
        let policy = compile(PolicyConfig {
            egresses: vec![egress("edge", &[], true, false)],
            transit_proxies: vec![
                proxy("ineligible", &[], &[], 100),
                proxy("eligible", &[], &["eligible"], 100),
            ],
            subscriptions: Vec::new(),
            egress_rules: vec![egress_rule("edge-rule", "edge", 1)],
            transit_rules: vec![rule],
            proxy_rules: Vec::new(),
            traffic_policies: vec![traffic_policy("default")],
            listeners: Vec::new(),
            dns_policy: None,
            node_probe: None,
            fallback: Some(FallbackAction::Reject),
        });
        let mut runtime = RuntimeCatalog::default();
        runtime.set_transit_proxy(
            TransitProxyId::new("ineligible"),
            ready_proxy(&[FlowProtocol::Tcp], 1),
        );
        runtime.set_transit_proxy(
            TransitProxyId::new("eligible"),
            ready_proxy(&[FlowProtocol::Tcp], 1),
        );
        let routes = policy.warmup_routes(FlowProtocol::Tcp, &runtime);
        assert_eq!(routes.len(), 1);
        assert_eq!(
            routes[0].2.transit_proxies[0].id,
            TransitProxyId::new("eligible")
        );
    }

    #[test]
    fn udp_over_egress_needs_a_tcp_transit_but_ordinary_udp_needs_native_support() {
        let policy = compile(PolicyConfig {
            egresses: vec![egress("egress", &[], true, true)],
            transit_proxies: vec![proxy("tcp-only", &[], &[], 100)],
            egress_rules: vec![egress_rule("egress-route", "egress", 1)],
            transit_rules: vec![transit_rule("transit", "egress", Selector::default())],
            traffic_policies: vec![traffic_policy("default")],
            fallback: Some(FallbackAction::Reject),
            ..PolicyConfig::default()
        });
        let mut runtime = RuntimeCatalog::default();
        runtime.set_egress(EgressId::new("egress"), ready_egress(1));
        runtime.set_transit_proxy(
            TransitProxyId::new("tcp-only"),
            ready_proxy(&[FlowProtocol::Tcp], 1),
        );
        let mut udp = context();
        udp.protocol = FlowProtocol::Udp;
        assert!(matches!(
            policy.evaluate(&udp, &runtime),
            Evaluation::Route(RoutePlan::Egress(_))
        ));
        let rule = ProxyRule {
            id: RuleId::new("ordinary"),
            matches: FlowMatch::default(),
            require: Selector::default(),
            select: ProxySelection::Any,
        };
        let ordinary = compile(PolicyConfig {
            transit_proxies: vec![proxy("tcp-only", &[], &[], 100)],
            proxy_rules: vec![rule],
            fallback: Some(FallbackAction::Reject),
            ..PolicyConfig::default()
        });
        assert!(matches!(
            ordinary.evaluate(&udp, &runtime),
            Evaluation::Reject { .. }
        ));
    }

    #[test]
    fn selectors_capabilities_and_runtime_label_overrides_are_applied() {
        let mut rule = egress_rule("selector", "unused", 1);
        rule.egress = EgressSelection::Selector(Selector {
            labels: BTreeMap::from([("region".into(), "jp".into())]),
            tags: BTreeSet::from(["preferred".into()]),
            capabilities: BTreeSet::from([FlowProtocol::Tcp]),
        });
        let policy = compile(PolicyConfig {
            egresses: vec![egress("selected", &[("region", "us")], true, false)],
            transit_proxies: vec![proxy("direct", &[], &[], 100)],
            subscriptions: Vec::new(),
            egress_rules: vec![rule],
            transit_rules: vec![transit_rule(
                "selected-transit",
                "selected",
                Selector::default(),
            )],
            proxy_rules: Vec::new(),
            traffic_policies: vec![traffic_policy("default")],
            listeners: Vec::new(),
            dns_policy: None,
            node_probe: None,
            fallback: Some(FallbackAction::Reject),
        });
        let mut status = ready_egress(1);
        status.labels.insert("region".into(), "jp".into());
        status.tags.insert("preferred".into());
        let mut runtime = RuntimeCatalog::default();
        runtime.set_egress(EgressId::new("selected"), status);
        runtime.set_transit_proxy(
            TransitProxyId::new("direct"),
            ready_proxy(&[FlowProtocol::Tcp], 1),
        );

        assert!(matches!(
            policy.evaluate(&context(), &runtime),
            Evaluation::Route(RoutePlan::Egress(_))
        ));
    }

    #[test]
    fn a_failed_first_transit_rule_advances_to_the_next_egress_rule() {
        let mut rejected = transit_rule(
            "rejected",
            "first",
            Selector {
                tags: BTreeSet::from(["gaming".into()]),
                ..Selector::default()
            },
        );
        rejected.reject_tags.insert("exhausted".into());
        let policy = compile(PolicyConfig {
            egresses: vec![
                egress("first", &[], true, false),
                egress("second", &[], true, false),
            ],
            transit_proxies: vec![
                proxy("bad", &[], &["gaming", "exhausted"], 100),
                proxy("good", &[], &[], 100),
            ],
            subscriptions: Vec::new(),
            egress_rules: vec![
                egress_rule("first-rule", "first", 1),
                egress_rule("second-rule", "second", 1),
            ],
            transit_rules: vec![
                rejected,
                transit_rule("rescue-must-not-run", "first", Selector::default()),
                transit_rule("second-transit", "second", Selector::default()),
            ],
            proxy_rules: Vec::new(),
            traffic_policies: vec![traffic_policy("default")],
            listeners: Vec::new(),
            dns_policy: None,
            node_probe: None,
            fallback: Some(FallbackAction::Reject),
        });
        let mut runtime = RuntimeCatalog::default();
        runtime.set_egress(EgressId::new("first"), ready_egress(1));
        runtime.set_egress(EgressId::new("second"), ready_egress(1));
        runtime.set_transit_proxy(
            TransitProxyId::new("bad"),
            ready_proxy(&[FlowProtocol::Tcp], 1),
        );
        runtime.set_transit_proxy(
            TransitProxyId::new("good"),
            ready_proxy(&[FlowProtocol::Tcp], 1),
        );

        let Evaluation::Route(RoutePlan::Egress(route)) = policy.evaluate(&context(), &runtime)
        else {
            panic!("expected an Egress route");
        };
        assert_eq!(route.egress_rule_id.as_str(), "second-rule");
    }

    #[test]
    fn flow_match_fields_are_anded_and_values_are_ored() {
        let rule = ProxyRule {
            id: RuleId::new("direct-web"),
            matches: FlowMatch {
                flow_tags: BTreeSet::from(["gaming".into(), "web".into()]),
                protocols: BTreeSet::from([FlowProtocol::Tcp]),
                listener_ids: BTreeSet::from([crate::ListenerId::new("local-http")]),
                source_networks: vec!["192.168.1.0/24".into()],
                authentication_identities: BTreeSet::from(["alice".into()]),
                process_executables: BTreeSet::from(["browser".into()]),
                target_hosts: BTreeSet::from(["WWW.EXAMPLE.TEST".into()]),
                target_ports: BTreeSet::from([443]),
            },
            require: Selector::default(),
            select: ProxySelection::Direct,
        };
        let policy = compile(PolicyConfig {
            proxy_rules: vec![rule],
            fallback: Some(FallbackAction::Reject),
            ..PolicyConfig::default()
        });
        assert_eq!(
            policy.evaluate(&context(), &RuntimeCatalog::default()),
            Evaluation::Direct {
                generation: Generation::new(7)
            }
        );

        let mut outside = context();
        outside.source = "192.168.2.42:12345".parse().unwrap();
        assert!(matches!(
            policy.evaluate(&outside, &RuntimeCatalog::default()),
            Evaluation::Reject { .. }
        ));
    }

    #[test]
    fn ordinary_proxy_uses_score_then_canonical_id() {
        let policy = compile(PolicyConfig {
            transit_proxies: vec![
                proxy("b", &[("region", "jp")], &[], 100),
                proxy("a", &[("region", "jp")], &[], 100),
                proxy("excluded", &[("region", "us")], &[], 1000),
            ],
            proxy_rules: vec![ProxyRule {
                id: RuleId::new("jp-proxy"),
                matches: FlowMatch::default(),
                require: Selector {
                    labels: BTreeMap::from([("region".into(), "jp".into())]),
                    ..Selector::default()
                },
                select: ProxySelection::Any,
            }],
            fallback: Some(FallbackAction::Reject),
            ..PolicyConfig::default()
        });
        let mut runtime = RuntimeCatalog::default();
        for id in ["a", "b", "excluded"] {
            runtime.set_transit_proxy(
                TransitProxyId::new(id),
                ready_proxy(&[FlowProtocol::Tcp], 5),
            );
        }

        let Evaluation::Route(RoutePlan::Proxy(route)) = policy.evaluate(&context(), &runtime)
        else {
            panic!("expected ordinary Proxy route");
        };
        assert_eq!(route.transit_proxy_id.as_str(), "a");
        assert_eq!(route.selection_score, 500);
    }

    #[test]
    fn runtime_catalog_can_publish_dynamic_proxy_configuration() {
        let policy = compile(PolicyConfig {
            proxy_rules: vec![ProxyRule {
                id: RuleId::new("dynamic"),
                matches: FlowMatch::default(),
                require: Selector::default(),
                select: ProxySelection::Any,
            }],
            fallback: Some(FallbackAction::Reject),
            ..PolicyConfig::default()
        });
        let mut runtime = RuntimeCatalog::default();
        runtime.set_dynamic_transit_proxy(
            proxy("subscription-node", &[], &[], 100),
            ready_proxy(&[FlowProtocol::Tcp], 3),
        );

        let Evaluation::Route(RoutePlan::Proxy(route)) = policy.evaluate(&context(), &runtime)
        else {
            panic!("expected dynamic ordinary Proxy route");
        };
        assert_eq!(route.transit_proxy_id.as_str(), "subscription-node");
    }

    #[test]
    fn mode_none_enters_proxy_phase_without_considering_later_egress_rules() {
        let policy = compile(PolicyConfig {
            egresses: vec![egress("unused", &[], true, false)],
            transit_proxies: vec![proxy("direct", &[], &[], 100)],
            subscriptions: Vec::new(),
            egress_rules: vec![
                EgressRule {
                    id: RuleId::new("ordinary-mode"),
                    matches: FlowMatch::default(),
                    egress: EgressSelection::None,
                    min_usable_paths: 1,
                    required_capabilities: BTreeSet::new(),
                },
                egress_rule("must-not-run", "unused", 1),
            ],
            transit_rules: vec![transit_rule(
                "unused-transit",
                "unused",
                Selector::default(),
            )],
            proxy_rules: vec![ProxyRule {
                id: RuleId::new("direct"),
                matches: FlowMatch::default(),
                require: Selector::default(),
                select: ProxySelection::Direct,
            }],
            traffic_policies: vec![traffic_policy("default")],
            listeners: Vec::new(),
            dns_policy: None,
            node_probe: None,
            fallback: Some(FallbackAction::Reject),
        });
        let mut runtime = RuntimeCatalog::default();
        runtime.set_egress(EgressId::new("unused"), ready_egress(1));
        runtime.set_transit_proxy(
            TransitProxyId::new("direct"),
            ready_proxy(&[FlowProtocol::Tcp], 1),
        );

        assert!(matches!(
            policy.evaluate(&context(), &runtime),
            Evaluation::Direct { .. }
        ));
    }

    #[test]
    fn mandatory_fallback_is_typed() {
        for (fallback, expected_direct) in [
            (FallbackAction::Direct, true),
            (FallbackAction::Reject, false),
        ] {
            let policy = compile(PolicyConfig {
                fallback: Some(fallback),
                ..PolicyConfig::default()
            });
            let evaluation = policy.evaluate(&context(), &RuntimeCatalog::default());
            assert_eq!(
                matches!(evaluation, Evaluation::Direct { .. }),
                expected_direct
            );
            assert_eq!(
                matches!(evaluation, Evaluation::Reject { .. }),
                !expected_direct
            );
        }
    }

    #[test]
    fn compile_rejects_invalid_programmatic_cidr() {
        let snapshot = ValidatedPolicySnapshot::new(
            Generation::new(1),
            PolicyConfig {
                proxy_rules: vec![ProxyRule {
                    id: RuleId::new("invalid-cidr"),
                    matches: FlowMatch {
                        source_networks: vec!["192.0.2.1/99".into()],
                        ..FlowMatch::default()
                    },
                    require: Selector::default(),
                    select: ProxySelection::Direct,
                }],
                fallback: Some(FallbackAction::Reject),
                ..PolicyConfig::default()
            },
        )
        .unwrap();
        assert_eq!(
            snapshot.compile().unwrap_err(),
            CompileError::InvalidSourceNetwork {
                rule_id: "invalid-cidr".into(),
                network: "192.0.2.1/99".into(),
            }
        );
    }
}
