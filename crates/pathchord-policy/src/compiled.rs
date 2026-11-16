use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use thiserror::Error;

use crate::geodata::{
    CompileBudget, GeoIpDatabase, GeoIpMatcher, GeoSiteDatabase, GeoSiteMatcher, GeodataError,
    MAX_DATABASE_BYTES,
};
use crate::{
    Capabilities, EgressConfig, EgressId, EgressRule, EgressSelection, EgressTransitBinding,
    FlowMatch, FlowProtocol, Generation, PolicyConfig, PolicyContext, ProxyRule, ProxySelection,
    RuleId, Selector, TargetHost, TrafficPolicy, TrafficPolicyId, TransitProxyConfig,
    TransitProxyId, TransitRule, ValidatedPolicySnapshot,
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
    pub transit_proxies: Vec<TransitCandidate>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EgressRoutePlan {
    pub generation: Generation,
    pub egress_rule_id: RuleId,
    pub candidates: Vec<EgressRouteCandidate>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyRoutePlan {
    pub generation: Generation,
    pub proxy_rule_id: RuleId,
    pub transit_proxy_id: TransitProxyId,
    pub selection_score: u64,
    /// All eligible nodes, in the same preference order as the first choice.
    pub candidates: Vec<TransitProxyId>,
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
    #[error("geodata database {database} {reason}")]
    InvalidGeodata {
        database: String,
        set: Option<String>,
        reason: &'static str,
    },
}

#[derive(Debug, Clone)]
struct CompiledMatch {
    namespace: String,
    source: FlowMatch,
    source_networks: Vec<Network>,
    geo_sites: Vec<GeoSiteMatcher>,
    geo_ips: Vec<GeoIpMatcher>,
}

impl CompiledMatch {
    fn compile(
        rule_id: &RuleId,
        source: &FlowMatch,
        geodata: &CompiledGeodata,
    ) -> Result<Self, CompileError> {
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
            geo_sites: source
                .target_geo_sites
                .iter()
                .map(|set| {
                    geodata
                        .sites
                        .get(&(rule_id.namespace().to_owned(), set.clone()))
                        .cloned()
                        .ok_or_else(|| CompileError::InvalidGeodata {
                            database: rule_id.namespace().to_owned(),
                            set: Some(set.clone()),
                            reason: "has an unavailable geosite set",
                        })
                })
                .collect::<Result<_, _>>()?,
            geo_ips: source
                .target_geo_ips
                .iter()
                .map(|set| {
                    geodata
                        .ips
                        .get(&(rule_id.namespace().to_owned(), set.clone()))
                        .cloned()
                        .ok_or_else(|| CompileError::InvalidGeodata {
                            database: rule_id.namespace().to_owned(),
                            set: Some(set.clone()),
                            reason: "has an unavailable geoip set",
                        })
                })
                .collect::<Result<_, _>>()?,
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
            && (self.geo_sites.is_empty()
                || match &context.target.host {
                    TargetHost::Hostname(hostname) => self
                        .geo_sites
                        .iter()
                        .any(|matcher| matcher.matches(hostname)),
                    TargetHost::Ip(_) => false,
                })
            && (self.geo_ips.is_empty()
                || match &context.target.host {
                    TargetHost::Ip(ip) => self
                        .geo_ips
                        .iter()
                        .any(|matcher| matcher.matches(Some(*ip))),
                    TargetHost::Hostname(_) => false,
                })
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

#[derive(Debug, Default)]
struct CompiledGeodata {
    sites: BTreeMap<(String, String), GeoSiteMatcher>,
    ips: BTreeMap<(String, String), GeoIpMatcher>,
    fingerprint: BTreeMap<String, [u8; 32]>,
}

fn referenced_sets(
    config: &PolicyConfig,
) -> (
    BTreeMap<String, BTreeSet<String>>,
    BTreeMap<String, BTreeSet<String>>,
) {
    let mut sites: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut ips: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for (id, matches) in config
        .egress_rules
        .iter()
        .map(|r| (&r.id, &r.matches))
        .chain(config.transit_rules.iter().map(|r| (&r.id, &r.matches)))
        .chain(config.proxy_rules.iter().map(|r| (&r.id, &r.matches)))
    {
        if !matches.target_geo_sites.is_empty() {
            sites
                .entry(id.namespace().to_owned())
                .or_default()
                .extend(matches.target_geo_sites.iter().cloned());
        }
        if !matches.target_geo_ips.is_empty() {
            ips.entry(id.namespace().to_owned())
                .or_default()
                .extend(matches.target_geo_ips.iter().cloned());
        }
    }
    (sites, ips)
}

fn geodata_error(database: &str, set: Option<&str>, reason: &'static str) -> CompileError {
    CompileError::InvalidGeodata {
        database: database.to_owned(),
        set: set.map(str::to_owned),
        reason,
    }
}

fn geodata_failure_reason(error: &GeodataError) -> &'static str {
    match error {
        GeodataError::DatabaseTooLarge | GeodataError::LimitExceeded(_) => {
            "exceeds a geodata resource limit"
        }
        GeodataError::Malformed => "contains malformed or unsupported geodata",
        GeodataError::DuplicateSet(_) => "contains duplicate geodata sets",
        GeodataError::InvalidReference => "contains an invalid set reference",
        GeodataError::UnknownSet(_) => "does not contain the referenced set",
        GeodataError::UnknownAttribute { .. } => "does not contain the referenced attribute",
        GeodataError::UnsupportedAttribute { .. } => "contains an unsupported attribute",
        GeodataError::InvalidRegex(_) => "contains an unsupported regular expression",
    }
}

/// Resolve the containing directory to a stable watch target, while keeping
/// the database filename itself available for atomic file replacements.
fn geodata_path(
    path: &str,
    source_dir: Option<&Path>,
    database: &str,
) -> Result<PathBuf, CompileError> {
    let path = Path::new(path);
    let full = if path.is_absolute() {
        path.to_path_buf()
    } else {
        source_dir
            .ok_or_else(|| {
                geodata_error(database, None, "requires a configuration source directory")
            })?
            .join(path)
    };
    let name = full
        .file_name()
        .ok_or_else(|| geodata_error(database, None, "has an invalid source"))?;
    let parent = full
        .parent()
        .ok_or_else(|| geodata_error(database, None, "has an invalid source"))?;
    let parent = std::fs::canonicalize(parent)
        .map_err(|_| geodata_error(database, None, "source directory is unavailable"))?;
    Ok(parent.join(name))
}

/// Read a bounded complete file and reject a candidate if its identity or
/// metadata changes during the read, including an atomic replacement.
fn read_geodata(path: &Path, database: &str) -> Result<Vec<u8>, CompileError> {
    let error = || {
        geodata_error(
            database,
            None,
            "source is unavailable or changed during reading",
        )
    };
    let before = std::fs::symlink_metadata(path).map_err(|_| error())?;
    if before.file_type().is_symlink() || !before.is_file() {
        return Err(error());
    }
    if before.len() > MAX_DATABASE_BYTES as u64 {
        return Err(geodata_error(database, None, "exceeds the file limit"));
    }
    let file = std::fs::File::open(path).map_err(|_| error())?;
    let opened = file.metadata().map_err(|_| error())?;
    if !same_file_metadata(&before, &opened) {
        return Err(error());
    }
    let mut bytes = Vec::with_capacity(opened.len() as usize);
    let mut reader = file.take(MAX_DATABASE_BYTES as u64 + 1);
    reader.read_to_end(&mut bytes).map_err(|_| error())?;
    if bytes.len() > MAX_DATABASE_BYTES {
        return Err(geodata_error(database, None, "exceeds the file limit"));
    }
    let after_handle = reader.into_inner().metadata().map_err(|_| error())?;
    let after_path = std::fs::symlink_metadata(path).map_err(|_| error())?;
    if !same_file_metadata(&opened, &after_handle)
        || !same_file_metadata(&opened, &after_path)
        || bytes.len() as u64 != opened.len()
    {
        return Err(error());
    }
    Ok(bytes)
}

fn same_file_metadata(a: &std::fs::Metadata, b: &std::fs::Metadata) -> bool {
    if !a.is_file() || !b.is_file() || a.len() != b.len() || a.modified().ok() != b.modified().ok()
    {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if a.dev() != b.dev()
            || a.ino() != b.ino()
            || a.ctime() != b.ctime()
            || a.ctime_nsec() != b.ctime_nsec()
        {
            return false;
        }
    }
    true
}

impl CompiledGeodata {
    fn load(config: &PolicyConfig, source_dir: Option<&Path>) -> Result<Self, CompileError> {
        let (site_refs, ip_refs) = referenced_sets(config);
        let mut result = Self::default();
        let mut budget = CompileBudget::default();
        for database in &config.geo_site_databases {
            let Some(sets) = site_refs.get(database.id.namespace()) else {
                continue;
            };
            let id = database.id.as_str();
            let path = geodata_path(&database.path, source_dir, id)?;
            let bytes = read_geodata(&path, id)?;
            let digest = orion::hazardous::hash::sha2::sha256::Sha256::digest(&bytes)
                .map_err(|_| geodata_error(id, None, "could not be hashed"))?;
            result.fingerprint.insert(
                format!("site:{id}"),
                digest.as_ref().try_into().expect("SHA-256 length"),
            );
            let data = GeoSiteDatabase::decode(&bytes)
                .map_err(|error| geodata_error(id, None, geodata_failure_reason(&error)))?;
            for set in sets {
                let matcher = data
                    .compile_with_budget(set, &mut budget)
                    .map_err(|error| {
                        geodata_error(id, Some(set), geodata_failure_reason(&error))
                    })?;
                result
                    .sites
                    .insert((database.id.namespace().to_owned(), set.clone()), matcher);
            }
        }
        for database in &config.geo_ip_databases {
            let Some(sets) = ip_refs.get(database.id.namespace()) else {
                continue;
            };
            let id = database.id.as_str();
            let path = geodata_path(&database.path, source_dir, id)?;
            let bytes = read_geodata(&path, id)?;
            let digest = orion::hazardous::hash::sha2::sha256::Sha256::digest(&bytes)
                .map_err(|_| geodata_error(id, None, "could not be hashed"))?;
            result.fingerprint.insert(
                format!("ip:{id}"),
                digest.as_ref().try_into().expect("SHA-256 length"),
            );
            let data = GeoIpDatabase::decode(&bytes)
                .map_err(|error| geodata_error(id, None, geodata_failure_reason(&error)))?;
            for set in sets {
                let matcher = data
                    .compile_with_budget(set, &mut budget)
                    .map_err(|error| {
                        geodata_error(id, Some(set), geodata_failure_reason(&error))
                    })?;
                result
                    .ips
                    .insert((database.id.namespace().to_owned(), set.clone()), matcher);
            }
        }
        Ok(result)
    }
}

/// Immutable, deterministic and I/O-free evaluator for one configuration generation.
#[derive(Debug, Clone)]
pub struct CompiledPolicy {
    generation: Generation,
    source_config: Arc<PolicyConfig>,
    geodata_fingerprint: BTreeMap<String, [u8; 32]>,
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
        Self::compile_with_source(snapshot, None)
    }

    pub fn compile_with_source(
        snapshot: &ValidatedPolicySnapshot,
        source_dir: Option<&Path>,
    ) -> Result<Self, CompileError> {
        let config = snapshot.config();
        let geodata = CompiledGeodata::load(config, source_dir)?;
        let egress_rules = config
            .egress_rules
            .iter()
            .map(|rule| {
                if let EgressSelection::Selector(selector) = &rule.egress {
                    ensure_selector(rule.id.as_str(), selector)?;
                }
                Ok(CompiledEgressRule {
                    matches: CompiledMatch::compile(&rule.id, &rule.matches, &geodata)?,
                    rule: rule.clone(),
                })
            })
            .collect::<Result<_, CompileError>>()?;
        let transit_rules = config
            .transit_rules
            .iter()
            .map(|rule| {
                Ok(CompiledTransitRule {
                    matches: CompiledMatch::compile(&rule.id, &rule.matches, &geodata)?,
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
                    matches: CompiledMatch::compile(&rule.id, &rule.matches, &geodata)?,
                    rule: rule.clone(),
                })
            })
            .collect::<Result<_, CompileError>>()?;

        Ok(Self {
            generation: snapshot.generation(),
            source_config: Arc::clone(&snapshot.config),
            geodata_fingerprint: geodata.fingerprint,
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

    /// Ensure a precompiled policy and its validated resource graph belong to
    /// the same generation before publishing them together.
    #[must_use]
    pub fn matches_snapshot(&self, snapshot: &ValidatedPolicySnapshot) -> bool {
        self.generation == snapshot.generation() && self.source_config == snapshot.config
    }

    #[must_use]
    pub fn geodata_fingerprint(&self) -> &BTreeMap<String, [u8; 32]> {
        &self.geodata_fingerprint
    }

    /// Resolve the referenced files for watching without reading their
    /// contents. The loader uses the same paths to build the generation.
    pub fn referenced_geodata_paths(
        config: &PolicyConfig,
        source_dir: Option<&Path>,
    ) -> Result<BTreeSet<PathBuf>, CompileError> {
        let (sites, ips) = referenced_sets(config);
        let mut paths = BTreeSet::new();
        for database in &config.geo_site_databases {
            if sites.contains_key(database.id.namespace()) {
                paths.insert(geodata_path(
                    &database.path,
                    source_dir,
                    database.id.as_str(),
                )?);
            }
        }
        for database in &config.geo_ip_databases {
            if ips.contains_key(database.id.namespace()) {
                paths.insert(geodata_path(
                    &database.path,
                    source_dir,
                    database.id.as_str(),
                )?);
            }
        }
        Ok(paths)
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
            if !egress_is_usable(egress, status, context.protocol) {
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
        // New configurations bind Transit selection directly to the Egress.
        // Keep the legacy branch for programmatic PolicyConfig fixtures while
        // callers migrate; the YAML adapter rejects TransitRule resources.
        let legacy = self.transit_rules.iter().find(|compiled| {
            compiled.rule.egress == egress.id && compiled.matches.matches(context)
        });
        let binding = &egress.transit;
        let mut transit_proxies: Vec<_> = self
            .transit_proxy_configs(runtime)
            .filter_map(|proxy| {
                if proxy.id.namespace() != egress.id.namespace() {
                    return None;
                }
                let status = runtime.transit_proxy(&proxy.id)?;
                let eligible = if binding != &EgressTransitBinding::default() {
                    transit_binding_is_usable(binding, proxy, status)
                } else if let Some(compiled) = legacy {
                    transit_is_usable(&compiled.rule, proxy, status, context.protocol)
                } else {
                    transit_binding_is_usable(binding, proxy, status)
                };
                if !eligible {
                    return None;
                }
                Some(TransitCandidate {
                    id: proxy.id.clone(),
                    relationship_weight: legacy
                        .map_or(proxy.weight, |compiled| compiled.rule.weight),
                    selection_score: weighted_score(proxy.weight, status.selection_score),
                })
            })
            .collect();
        if transit_proxies.is_empty() {
            return Ok(None);
        }
        transit_proxies.sort_by(|left, right| left.id.cmp(&right.id));
        Ok(Some(EgressRouteCandidate {
            egress_id: egress.id.clone(),
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
        let (proxy, selection_score) = candidates.first()?;
        Some(ProxyRoutePlan {
            generation: self.generation,
            proxy_rule_id: rule.id.clone(),
            transit_proxy_id: proxy.id.clone(),
            selection_score: *selection_score,
            candidates: candidates
                .into_iter()
                .map(|(proxy, _)| proxy.id.clone())
                .collect(),
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
    egress: &EgressConfig,
    status: &EgressRuntimeStatus,
    protocol: FlowProtocol,
) -> bool {
    let min_paths = egress.status_requirements.min_usable_paths;
    status.state.admits_new_work()
        && status.usable_paths >= min_paths
        && egress_supports(&egress.capabilities, protocol)
        && egress
            .status_requirements
            .capabilities
            .iter()
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

fn transit_binding_is_usable(
    binding: &EgressTransitBinding,
    proxy: &TransitProxyConfig,
    status: &TransitProxyRuntimeStatus,
) -> bool {
    status.state.admits_new_work()
        && status.capabilities.contains(&FlowProtocol::Tcp)
        && labels_match(&binding.require.labels, &proxy.labels, &status.labels)
        && tags_match(&binding.require.tags, &proxy.tags, &status.tags)
        && binding.require.capabilities.is_subset(&status.capabilities)
        && binding
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
            transit: crate::EgressTransitBinding::default(),
            traffic_policy: None,
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
    fn geodata_predicates_apply_to_all_rule_kinds_without_resolving_hosts() {
        fn field(tag: u8, bytes: &[u8]) -> Vec<u8> {
            assert!(bytes.len() < 128);
            let mut out = vec![tag, bytes.len() as u8];
            out.extend_from_slice(bytes);
            out
        }
        let mut site_rule = vec![8, 2]; // RootDomain
        site_rule.extend(field(18, b"hf.co"));
        let mut site = field(10, b"huggingface");
        site.extend(field(18, &site_rule));
        let site_db = GeoSiteDatabase::decode(&field(10, &site)).unwrap();
        let mut cidr = field(10, &[192, 0, 2, 0]);
        cidr.extend([16, 24]);
        let mut ip = field(10, b"example");
        ip.extend(field(18, &cidr));
        let ip_db = GeoIpDatabase::decode(&field(10, &ip)).unwrap();
        let mut geodata = CompiledGeodata::default();
        geodata.sites.insert(
            ("default".into(), "huggingface".into()),
            site_db.compile("huggingface").unwrap(),
        );
        geodata.ips.insert(
            ("default".into(), "example".into()),
            ip_db.compile("example").unwrap(),
        );

        let site_match = FlowMatch {
            target_geo_sites: BTreeSet::from(["huggingface".into()]),
            ..Default::default()
        };
        let ip_match = FlowMatch {
            target_geo_ips: BTreeSet::from(["example".into()]),
            ..Default::default()
        };
        for prefix in ["egress", "transit", "proxy"] {
            let site = CompiledMatch::compile(
                &RuleId::new(format!("{prefix}-site")),
                &site_match,
                &geodata,
            )
            .unwrap();
            let ip =
                CompiledMatch::compile(&RuleId::new(format!("{prefix}-ip")), &ip_match, &geodata)
                    .unwrap();
            for protocol in [FlowProtocol::Tcp, FlowProtocol::Udp] {
                let mut ctx = context();
                ctx.protocol = protocol;
                ctx.target.host = TargetHost::Hostname("US.AWS.CDN.HF.CO".into());
                assert!(site.matches(&ctx));
                assert!(!ip.matches(&ctx), "hostname alone must not trigger DNS");
                ctx.target.host = TargetHost::Hostname("nothf.co".into());
                assert!(!site.matches(&ctx));
                ctx.target.host = TargetHost::Ip("192.0.2.42".parse().unwrap());
                assert!(ip.matches(&ctx));
                assert!(!site.matches(&ctx));
                ctx.target.host = TargetHost::Ip("192.0.3.42".parse().unwrap());
                assert!(!ip.matches(&ctx));
            }
        }
    }

    #[test]
    fn compiled_geodata_participates_in_ordered_egress_and_proxy_routes() {
        fn field(tag: u8, bytes: &[u8]) -> Vec<u8> {
            assert!(bytes.len() < 128);
            let mut out = vec![tag, bytes.len() as u8];
            out.extend_from_slice(bytes);
            out
        }
        let mut domain = vec![8, 2];
        domain.extend(field(18, b"hf.co"));
        let mut site = field(10, b"huggingface");
        site.extend(field(18, &domain));
        let mut cidr = field(10, &[192, 0, 2, 0]);
        cidr.extend([16, 24]);
        let mut ip = field(10, b"example");
        ip.extend(field(18, &cidr));
        let dir = std::env::temp_dir().join(format!(
            "pathchord-geodata-routing-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("sites.dat"), field(10, &site)).unwrap();
        std::fs::write(dir.join("ips.dat"), field(10, &ip)).unwrap();

        let mut route = egress_rule("geo-egress", "edge", 1);
        route.matches.target_geo_sites.insert("huggingface".into());
        let mut transit = transit_rule("geo-transit", "edge", Selector::default());
        transit
            .matches
            .target_geo_sites
            .insert("huggingface".into());
        let config = PolicyConfig {
            egresses: vec![egress("edge", &[], true, true)],
            transit_proxies: vec![proxy("node", &[], &[], 100)],
            geo_site_databases: vec![crate::GeoSiteDatabaseConfig {
                id: crate::GeoSiteDatabaseId::new("sites"),
                path: "sites.dat".into(),
            }],
            geo_ip_databases: vec![crate::GeoIpDatabaseConfig {
                id: crate::GeoIpDatabaseId::new("ips"),
                path: "ips.dat".into(),
            }],
            egress_rules: vec![route],
            transit_rules: vec![transit],
            proxy_rules: vec![ProxyRule {
                id: RuleId::new("geo-proxy"),
                matches: FlowMatch {
                    target_geo_ips: BTreeSet::from(["example".into()]),
                    ..Default::default()
                },
                require: Selector::default(),
                select: ProxySelection::Any,
            }],
            traffic_policies: vec![traffic_policy("default")],
            fallback: Some(crate::FallbackAction::Reject),
            ..Default::default()
        };
        let snapshot = ValidatedPolicySnapshot::new(Generation::new(1), config.clone()).unwrap();
        let compiled = CompiledPolicy::compile_with_source(&snapshot, Some(&dir)).unwrap();
        let mut runtime = RuntimeCatalog::default();
        runtime.set_egress(EgressId::new("edge"), ready_egress(1));
        runtime.set_transit_proxy(
            TransitProxyId::new("node"),
            ready_proxy(&[FlowProtocol::Tcp, FlowProtocol::Udp], 1),
        );
        for protocol in [FlowProtocol::Tcp, FlowProtocol::Udp] {
            let mut ctx = context();
            ctx.protocol = protocol;
            ctx.target.host = TargetHost::Hostname("us.aws.cdn.hf.co".into());
            assert!(matches!(
                compiled.evaluate(&ctx, &runtime),
                Evaluation::Route(RoutePlan::Egress(_))
            ));
            ctx.target.host = TargetHost::Ip("192.0.2.42".parse().unwrap());
            assert!(matches!(
                compiled.evaluate(&ctx, &runtime),
                Evaluation::Route(RoutePlan::Proxy(_))
            ));
            ctx.target.host = TargetHost::Hostname("unknown.test".into());
            assert!(matches!(
                compiled.evaluate(&ctx, &runtime),
                Evaluation::Reject {
                    reason: RejectReason::GlobalFallback,
                    ..
                }
            ));
        }
        let mut invalid = config;
        invalid.egress_rules[0].matches.target_geo_sites = BTreeSet::from(["missing".into()]);
        let snapshot = ValidatedPolicySnapshot::new(Generation::new(2), invalid).unwrap();
        assert!(matches!(
            CompiledPolicy::compile_with_source(&snapshot, Some(&dir)),
            Err(CompileError::InvalidGeodata { set: Some(_), .. })
        ));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn egress_binding_allows_dynamic_multipath_without_a_transit_rule() {
        let input = r#"
apiVersion: pathchord.io/v1
kind: Egress
metadata: {name: edge}
spec:
  address: edge.example.test
  port: 443
  publicKey: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
  capabilities: {tcp: true, udp: true}
  transit: {}
  trafficPolicyRef: default
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
kind: TrafficPolicy
metadata: {name: default}
spec: {}
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
        // validation. The Egress binding owns the common pool, so it remains
        // eligible without a flow-specific TransitRule.
        runtime.set_dynamic_transit_proxy(
            proxy("second", &[], &[], 100),
            ready_proxy(&[FlowProtocol::Tcp], 1),
        );
        let Evaluation::Route(RoutePlan::Egress(route)) = implicit.evaluate(&context(), &runtime)
        else {
            panic!("Egress binding must allow the multipath route");
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
            ..PolicyConfig::default()
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
        assert_eq!(route.egress_rule_id.as_str(), "first-rule");
        assert_eq!(route.candidates[0].egress_id.as_str(), "first");
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
            ..PolicyConfig::default()
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
            ..PolicyConfig::default()
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
                ..FlowMatch::default()
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
        let mut foreign = proxy("outside", &[("region", "jp")], &["allowed"], 1000);
        foreign.id = TransitProxyId::in_namespace("foreign", "outside");
        let policy = compile(PolicyConfig {
            transit_proxies: vec![
                proxy("b", &[("region", "jp")], &["allowed"], 100),
                proxy("a", &[("region", "jp")], &["allowed"], 100),
                proxy("c", &[("region", "jp")], &["allowed"], 50),
                proxy("wrong-region", &[("region", "us")], &["allowed"], 1000),
                proxy("wrong-tag", &[("region", "jp")], &[], 1000),
                foreign,
            ],
            proxy_rules: vec![ProxyRule {
                id: RuleId::new("jp-proxy"),
                matches: FlowMatch::default(),
                require: Selector {
                    labels: BTreeMap::from([("region".into(), "jp".into())]),
                    ..Selector::default()
                },
                select: ProxySelection::Selector(Selector {
                    tags: BTreeSet::from(["allowed".into()]),
                    ..Selector::default()
                }),
            }],
            fallback: Some(FallbackAction::Reject),
            ..PolicyConfig::default()
        });
        let mut runtime = RuntimeCatalog::default();
        for id in ["a", "b", "c", "wrong-region", "wrong-tag"] {
            runtime.set_transit_proxy(
                TransitProxyId::new(id),
                ready_proxy(&[FlowProtocol::Tcp], 5),
            );
        }
        runtime.set_transit_proxy(
            TransitProxyId::in_namespace("foreign", "outside"),
            ready_proxy(&[FlowProtocol::Tcp], 5),
        );

        let Evaluation::Route(RoutePlan::Proxy(route)) = policy.evaluate(&context(), &runtime)
        else {
            panic!("expected ordinary Proxy route");
        };
        assert_eq!(route.transit_proxy_id.as_str(), "a");
        assert_eq!(route.selection_score, 500);
        assert_eq!(
            route.candidates,
            vec![
                TransitProxyId::new("a"),
                TransitProxyId::new("b"),
                TransitProxyId::new("c")
            ]
        );
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
            ..PolicyConfig::default()
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
