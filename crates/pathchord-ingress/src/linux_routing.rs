//! Owned Linux policy-routing setup for TPROXY listeners.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum IpFamily {
    Ipv4,
    Ipv6,
}

impl IpFamily {
    const ALL: [Self; 2] = [Self::Ipv4, Self::Ipv6];

    const fn argument(self) -> &'static str {
        match self {
            Self::Ipv4 => "-4",
            Self::Ipv6 => "-6",
        }
    }

    const fn default_route(self) -> &'static str {
        match self {
            Self::Ipv4 => "0.0.0.0/0",
            Self::Ipv6 => "::/0",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinuxTransparentRouteConfig {
    pub mark: u32,
    pub table: u32,
    pub priority: u32,
    pub protocol: u8,
}

impl LinuxTransparentRouteConfig {
    pub fn from_listener(
        listener: &pathchord_policy::ListenerConfig,
        priority: u32,
        protocol: u8,
    ) -> Result<Self, LinuxRoutingError> {
        if listener.kind != pathchord_policy::ListenerKind::Tproxy {
            return Err(LinuxRoutingError::InvalidConfig);
        }
        Self {
            mark: listener.mark.ok_or(LinuxRoutingError::InvalidConfig)?,
            table: listener
                .route_table
                .ok_or(LinuxRoutingError::InvalidConfig)?,
            priority,
            protocol,
        }
        .validate()
    }

    pub fn validate(self) -> Result<Self, LinuxRoutingError> {
        if self.mark == 0 || self.table == 0 || self.priority == 0 || self.protocol == 0 {
            return Err(LinuxRoutingError::InvalidConfig);
        }
        Ok(self)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteObjectState {
    Absent,
    Exact,
    Conflict,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum LinuxRoutingError {
    #[error("Linux transparent routing configuration is invalid")]
    InvalidConfig,
    #[error("Linux transparent routing ownership conflicts with an existing rule or route")]
    OwnershipConflict,
    #[error("Linux ip command failed: {0}")]
    Command(String),
    #[error("Linux routing journal failed: {0}")]
    Journal(String),
    #[error("Linux transparent routing rollback failed after apply error: {0}")]
    Rollback(String),
    #[error("Linux routing manager lock is unavailable")]
    Lock,
}

pub trait LinuxRouteAdapter: std::fmt::Debug + Send + Sync {
    fn inspect_rule(
        &self,
        family: IpFamily,
        config: LinuxTransparentRouteConfig,
    ) -> Result<RouteObjectState, LinuxRoutingError>;

    fn inspect_route(
        &self,
        family: IpFamily,
        config: LinuxTransparentRouteConfig,
    ) -> Result<RouteObjectState, LinuxRoutingError>;

    fn add_rule(
        &self,
        family: IpFamily,
        config: LinuxTransparentRouteConfig,
    ) -> Result<(), LinuxRoutingError>;

    fn add_route(
        &self,
        family: IpFamily,
        config: LinuxTransparentRouteConfig,
    ) -> Result<(), LinuxRoutingError>;

    fn delete_rule(
        &self,
        family: IpFamily,
        config: LinuxTransparentRouteConfig,
    ) -> Result<(), LinuxRoutingError>;

    fn delete_route(
        &self,
        family: IpFamily,
        config: LinuxTransparentRouteConfig,
    ) -> Result<(), LinuxRoutingError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
enum OwnedObjectKind {
    Rule,
    Route,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
struct OwnedObject {
    family: IpFamily,
    kind: OwnedObjectKind,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct RoutingJournal {
    config: LinuxTransparentRouteConfig,
    /// Each entry was absent during the pre-apply snapshot. Recovery may delete
    /// it only when the live object still exactly matches `config`.
    owned: Vec<OwnedObject>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LinuxRoutingEffect {
    pub replayed: bool,
    pub restored_objects: usize,
}

pub struct LinuxTransparentRouteManager {
    adapter: Arc<dyn LinuxRouteAdapter>,
    journal_path: PathBuf,
    active: Mutex<Option<LinuxTransparentRouteConfig>>,
}

impl std::fmt::Debug for LinuxTransparentRouteManager {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("LinuxTransparentRouteManager")
            .field("journal_path", &self.journal_path)
            .finish_non_exhaustive()
    }
}

impl LinuxTransparentRouteManager {
    #[must_use]
    pub fn new(adapter: Arc<dyn LinuxRouteAdapter>, journal_path: impl Into<PathBuf>) -> Self {
        Self {
            adapter,
            journal_path: journal_path.into(),
            active: Mutex::new(None),
        }
    }

    pub fn apply(
        &self,
        config: LinuxTransparentRouteConfig,
    ) -> Result<LinuxRoutingEffect, LinuxRoutingError> {
        let config = config.validate()?;
        let active = self.active.lock().map_err(|_| LinuxRoutingError::Lock)?;
        if let Some(current) = *active {
            return if current == config {
                Ok(LinuxRoutingEffect {
                    replayed: true,
                    restored_objects: 0,
                })
            } else {
                Err(LinuxRoutingError::OwnershipConflict)
            };
        }
        drop(active);

        self.recover()?;
        let journal = self.preflight(config)?;
        atomic_write_json(&self.journal_path, &journal)?;
        for object in &journal.owned {
            let result = match object.kind {
                OwnedObjectKind::Rule => self.adapter.add_rule(object.family, config),
                OwnedObjectKind::Route => self.adapter.add_route(object.family, config),
            };
            if let Err(error) = result {
                return match self.restore_journal() {
                    Ok(_) => Err(error),
                    Err(rollback) => Err(LinuxRoutingError::Rollback(rollback.to_string())),
                };
            }
        }
        *self.active.lock().map_err(|_| LinuxRoutingError::Lock)? = Some(config);
        Ok(LinuxRoutingEffect {
            replayed: false,
            restored_objects: 0,
        })
    }

    pub fn recover(&self) -> Result<LinuxRoutingEffect, LinuxRoutingError> {
        if !self.journal_path.exists() {
            return Ok(LinuxRoutingEffect {
                replayed: false,
                restored_objects: 0,
            });
        }
        self.restore_journal()
    }

    pub fn restore(&self) -> Result<LinuxRoutingEffect, LinuxRoutingError> {
        let result = self.recover()?;
        *self.active.lock().map_err(|_| LinuxRoutingError::Lock)? = None;
        Ok(result)
    }

    fn preflight(
        &self,
        config: LinuxTransparentRouteConfig,
    ) -> Result<RoutingJournal, LinuxRoutingError> {
        let mut owned = Vec::with_capacity(4);
        for family in IpFamily::ALL {
            if self.adapter.inspect_rule(family, config)? != RouteObjectState::Absent
                || self.adapter.inspect_route(family, config)? != RouteObjectState::Absent
            {
                return Err(LinuxRoutingError::OwnershipConflict);
            }
            owned.push(OwnedObject {
                family,
                kind: OwnedObjectKind::Rule,
            });
            owned.push(OwnedObject {
                family,
                kind: OwnedObjectKind::Route,
            });
        }
        Ok(RoutingJournal { config, owned })
    }

    fn restore_journal(&self) -> Result<LinuxRoutingEffect, LinuxRoutingError> {
        let encoded = std::fs::read(&self.journal_path)
            .map_err(|error| LinuxRoutingError::Journal(error.to_string()))?;
        let journal: RoutingJournal = serde_json::from_slice(&encoded)
            .map_err(|error| LinuxRoutingError::Journal(error.to_string()))?;
        let mut restored = 0;
        for object in journal.owned.iter().rev() {
            let state = match object.kind {
                OwnedObjectKind::Rule => {
                    self.adapter.inspect_rule(object.family, journal.config)?
                }
                OwnedObjectKind::Route => {
                    self.adapter.inspect_route(object.family, journal.config)?
                }
            };
            match state {
                RouteObjectState::Absent => {}
                RouteObjectState::Conflict => return Err(LinuxRoutingError::OwnershipConflict),
                RouteObjectState::Exact => {
                    match object.kind {
                        OwnedObjectKind::Rule => {
                            self.adapter.delete_rule(object.family, journal.config)?
                        }
                        OwnedObjectKind::Route => {
                            self.adapter.delete_route(object.family, journal.config)?
                        }
                    }
                    restored += 1;
                }
            }
        }
        std::fs::remove_file(&self.journal_path)
            .map_err(|error| LinuxRoutingError::Journal(error.to_string()))?;
        *self.active.lock().map_err(|_| LinuxRoutingError::Lock)? = None;
        Ok(LinuxRoutingEffect {
            replayed: false,
            restored_objects: restored,
        })
    }
}

impl Drop for LinuxTransparentRouteManager {
    fn drop(&mut self) {
        let _ = self.restore();
    }
}

#[derive(Debug, Clone)]
pub struct IpCommandRouteAdapter {
    program: PathBuf,
}

impl IpCommandRouteAdapter {
    #[must_use]
    pub fn new(program: impl Into<PathBuf>) -> Self {
        Self {
            program: program.into(),
        }
    }

    #[must_use]
    pub fn system() -> Self {
        Self::new("ip")
    }

    fn query(&self, arguments: &[String]) -> Result<Vec<Value>, LinuxRoutingError> {
        let output = Command::new(&self.program)
            .arg("-N")
            .args(arguments)
            .output()
            .map_err(|error| LinuxRoutingError::Command(error.to_string()))?;
        if !output.status.success() {
            return Err(LinuxRoutingError::Command(
                String::from_utf8_lossy(&output.stderr).trim().to_owned(),
            ));
        }
        serde_json::from_slice(&output.stdout)
            .map_err(|error| LinuxRoutingError::Command(error.to_string()))
    }

    fn query_route(&self, arguments: &[String]) -> Result<Vec<Value>, LinuxRoutingError> {
        match self.query(arguments) {
            Ok(values) => Ok(values),
            Err(LinuxRoutingError::Command(message)) if missing_route_table(&message) => {
                // `ip route show table N` returns status 2 when N has never
                // been created, even though that is the empty state needed by
                // the ownership preflight. Treat only this exact condition as
                // an absent table; permission and syntax failures remain fatal.
                Ok(Vec::new())
            }
            Err(error) => Err(error),
        }
    }

    fn mutate(&self, arguments: &[String]) -> Result<(), LinuxRoutingError> {
        let output = Command::new(&self.program)
            .args(arguments)
            .output()
            .map_err(|error| LinuxRoutingError::Command(error.to_string()))?;
        if output.status.success() {
            Ok(())
        } else {
            Err(LinuxRoutingError::Command(
                String::from_utf8_lossy(&output.stderr).trim().to_owned(),
            ))
        }
    }

    fn rule_query_args(family: IpFamily, config: LinuxTransparentRouteConfig) -> Vec<String> {
        vec![
            "-json".to_owned(),
            family.argument().to_owned(),
            "rule".to_owned(),
            "show".to_owned(),
            "priority".to_owned(),
            config.priority.to_string(),
        ]
    }

    fn route_query_args(family: IpFamily, config: LinuxTransparentRouteConfig) -> Vec<String> {
        vec![
            "-json".to_owned(),
            family.argument().to_owned(),
            "route".to_owned(),
            "show".to_owned(),
            "table".to_owned(),
            config.table.to_string(),
        ]
    }

    fn rule_mutation_args(
        verb: &str,
        family: IpFamily,
        config: LinuxTransparentRouteConfig,
    ) -> Vec<String> {
        vec![
            family.argument().to_owned(),
            "rule".to_owned(),
            verb.to_owned(),
            "priority".to_owned(),
            config.priority.to_string(),
            "fwmark".to_owned(),
            format!("0x{:x}", config.mark),
            "lookup".to_owned(),
            config.table.to_string(),
            "protocol".to_owned(),
            config.protocol.to_string(),
        ]
    }

    fn route_mutation_args(
        verb: &str,
        family: IpFamily,
        config: LinuxTransparentRouteConfig,
    ) -> Vec<String> {
        vec![
            family.argument().to_owned(),
            "route".to_owned(),
            verb.to_owned(),
            "table".to_owned(),
            config.table.to_string(),
            "proto".to_owned(),
            config.protocol.to_string(),
            "local".to_owned(),
            family.default_route().to_owned(),
            "dev".to_owned(),
            "lo".to_owned(),
        ]
    }
}

impl LinuxRouteAdapter for IpCommandRouteAdapter {
    fn inspect_rule(
        &self,
        family: IpFamily,
        config: LinuxTransparentRouteConfig,
    ) -> Result<RouteObjectState, LinuxRoutingError> {
        Ok(classify_rule(
            &self.query(&Self::rule_query_args(family, config))?,
            config,
        ))
    }

    fn inspect_route(
        &self,
        family: IpFamily,
        config: LinuxTransparentRouteConfig,
    ) -> Result<RouteObjectState, LinuxRoutingError> {
        Ok(classify_route(
            &self.query_route(&Self::route_query_args(family, config))?,
            family,
            config,
        ))
    }

    fn add_rule(
        &self,
        family: IpFamily,
        config: LinuxTransparentRouteConfig,
    ) -> Result<(), LinuxRoutingError> {
        self.mutate(&Self::rule_mutation_args("add", family, config))
    }

    fn add_route(
        &self,
        family: IpFamily,
        config: LinuxTransparentRouteConfig,
    ) -> Result<(), LinuxRoutingError> {
        self.mutate(&Self::route_mutation_args("add", family, config))
    }

    fn delete_rule(
        &self,
        family: IpFamily,
        config: LinuxTransparentRouteConfig,
    ) -> Result<(), LinuxRoutingError> {
        self.mutate(&Self::rule_mutation_args("del", family, config))
    }

    fn delete_route(
        &self,
        family: IpFamily,
        config: LinuxTransparentRouteConfig,
    ) -> Result<(), LinuxRoutingError> {
        self.mutate(&Self::route_mutation_args("del", family, config))
    }
}

fn missing_route_table(message: &str) -> bool {
    let message = message.to_ascii_lowercase();
    message.contains("fib table does not exist") || message.contains("table does not exist")
}

fn classify_rule(values: &[Value], config: LinuxTransparentRouteConfig) -> RouteObjectState {
    if values.is_empty() {
        return RouteObjectState::Absent;
    }
    let exact = values.iter().all(|value| {
        value_u64(value, "priority") == Some(u64::from(config.priority))
            && value_u64(value, "table") == Some(u64::from(config.table))
            && value_u64(value, "protocol") == Some(u64::from(config.protocol))
            && value_mark(value.get("fwmark")) == Some(config.mark)
            && value
                .get("fwmask")
                .is_none_or(|mask| value_mark(Some(mask)) == Some(u32::MAX))
            && ["src", "dst"].iter().all(|field| {
                value
                    .get(*field)
                    .is_none_or(|field| field.as_str() == Some("all"))
            })
            && value.as_object().is_some_and(|fields| {
                fields.keys().all(|field| {
                    matches!(
                        field.as_str(),
                        "priority" | "src" | "dst" | "fwmark" | "fwmask" | "table" | "protocol"
                    )
                })
            })
    });
    if exact {
        RouteObjectState::Exact
    } else {
        RouteObjectState::Conflict
    }
}

fn classify_route(
    values: &[Value],
    family: IpFamily,
    config: LinuxTransparentRouteConfig,
) -> RouteObjectState {
    if values.is_empty() {
        return RouteObjectState::Absent;
    }
    let exact = values.iter().all(|value| {
        let destination = value.get("dst").and_then(Value::as_str);
        (matches!(
            value.get("type").and_then(Value::as_str),
            Some("local" | "2")
        ) || value_u64(value, "type") == Some(2))
            && value.get("dev").and_then(Value::as_str) == Some("lo")
            && value_u64(value, "protocol") == Some(u64::from(config.protocol))
            && (destination == Some("default") || destination == Some(family.default_route()))
            && value
                .get("flags")
                .is_none_or(|flags| flags.as_array().is_some_and(Vec::is_empty))
            && value.get("scope").is_none_or(|scope| {
                matches!(scope.as_str(), Some("host" | "254")) || scope.as_u64() == Some(254)
            })
            && value.get("metric").is_none_or(|_| {
                family == IpFamily::Ipv6 && value_u64(value, "metric") == Some(1024)
            })
            && value
                .get("pref")
                .is_none_or(|pref| pref.as_str() == Some("medium"))
            && value
                .get("table")
                .is_none_or(|_| value_u64(value, "table") == Some(u64::from(config.table)))
            && value.as_object().is_some_and(|fields| {
                fields.keys().all(|field| {
                    matches!(
                        field.as_str(),
                        "type"
                            | "dst"
                            | "dev"
                            | "protocol"
                            | "scope"
                            | "flags"
                            | "metric"
                            | "pref"
                            | "table"
                    )
                })
            })
    });
    if exact {
        RouteObjectState::Exact
    } else {
        RouteObjectState::Conflict
    }
}

fn value_u64(value: &Value, field: &str) -> Option<u64> {
    value.get(field).and_then(|value| {
        value
            .as_u64()
            .or_else(|| value.as_str().and_then(|value| value.parse().ok()))
    })
}

fn value_mark(value: Option<&Value>) -> Option<u32> {
    let value = value?;
    if let Some(value) = value.as_u64() {
        return u32::try_from(value).ok();
    }
    let value = value.as_str()?;
    let value = value.split('/').next().unwrap_or(value);
    value
        .strip_prefix("0x")
        .and_then(|value| u32::from_str_radix(value, 16).ok())
        .or_else(|| value.parse().ok())
}

fn atomic_write_json<T: Serialize>(path: &Path, value: &T) -> Result<(), LinuxRoutingError> {
    use std::io::Write as _;

    let parent = path
        .parent()
        .ok_or_else(|| LinuxRoutingError::Journal("journal has no parent directory".to_owned()))?;
    std::fs::create_dir_all(parent)
        .map_err(|error| LinuxRoutingError::Journal(error.to_string()))?;
    let mut options = atomic_write_file::OpenOptions::new();
    use atomic_write_file::unix::OpenOptionsExt as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    options.preserve_mode(false).mode(0o600);
    let mut file = options
        .open(path)
        .map_err(|error| LinuxRoutingError::Journal(error.to_string()))?;
    let encoded =
        serde_json::to_vec(value).map_err(|error| LinuxRoutingError::Journal(error.to_string()))?;
    file.write_all(&encoded)
        .map_err(|error| LinuxRoutingError::Journal(error.to_string()))?;
    file.commit()
        .map_err(|error| LinuxRoutingError::Journal(error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_JOURNAL: AtomicU64 = AtomicU64::new(0);

    #[derive(Debug, Default)]
    struct FakeState {
        objects: BTreeMap<(IpFamily, OwnedObjectKind), LinuxTransparentRouteConfig>,
        foreign: BTreeMap<(IpFamily, OwnedObjectKind), bool>,
        mutations: usize,
        fail_at: Option<usize>,
    }

    #[derive(Debug, Default)]
    struct FakeRouteAdapter {
        state: Mutex<FakeState>,
    }

    impl FakeRouteAdapter {
        fn fail_at(&self, mutation: usize) {
            self.state.lock().unwrap().fail_at = Some(mutation);
        }

        fn set_foreign(&self, family: IpFamily, kind: OwnedObjectKind) {
            self.state
                .lock()
                .unwrap()
                .foreign
                .insert((family, kind), true);
        }

        fn clear_foreign(&self, family: IpFamily, kind: OwnedObjectKind) {
            self.state.lock().unwrap().foreign.remove(&(family, kind));
        }

        fn object_count(&self) -> usize {
            self.state.lock().unwrap().objects.len()
        }

        fn inspect(
            &self,
            family: IpFamily,
            kind: OwnedObjectKind,
            config: LinuxTransparentRouteConfig,
        ) -> RouteObjectState {
            let state = self.state.lock().unwrap();
            if state.foreign.get(&(family, kind)).copied().unwrap_or(false) {
                RouteObjectState::Conflict
            } else {
                match state.objects.get(&(family, kind)) {
                    None => RouteObjectState::Absent,
                    Some(value) if *value == config => RouteObjectState::Exact,
                    Some(_) => RouteObjectState::Conflict,
                }
            }
        }

        fn add(
            &self,
            family: IpFamily,
            kind: OwnedObjectKind,
            config: LinuxTransparentRouteConfig,
        ) -> Result<(), LinuxRoutingError> {
            let mut state = self.state.lock().unwrap();
            state.mutations += 1;
            if state.fail_at == Some(state.mutations) {
                return Err(LinuxRoutingError::Command("injected".to_owned()));
            }
            state.objects.insert((family, kind), config);
            Ok(())
        }

        fn delete(&self, family: IpFamily, kind: OwnedObjectKind) -> Result<(), LinuxRoutingError> {
            self.state.lock().unwrap().objects.remove(&(family, kind));
            Ok(())
        }
    }

    impl LinuxRouteAdapter for FakeRouteAdapter {
        fn inspect_rule(
            &self,
            family: IpFamily,
            config: LinuxTransparentRouteConfig,
        ) -> Result<RouteObjectState, LinuxRoutingError> {
            Ok(self.inspect(family, OwnedObjectKind::Rule, config))
        }

        fn inspect_route(
            &self,
            family: IpFamily,
            config: LinuxTransparentRouteConfig,
        ) -> Result<RouteObjectState, LinuxRoutingError> {
            Ok(self.inspect(family, OwnedObjectKind::Route, config))
        }

        fn add_rule(
            &self,
            family: IpFamily,
            config: LinuxTransparentRouteConfig,
        ) -> Result<(), LinuxRoutingError> {
            self.add(family, OwnedObjectKind::Rule, config)
        }

        fn add_route(
            &self,
            family: IpFamily,
            config: LinuxTransparentRouteConfig,
        ) -> Result<(), LinuxRoutingError> {
            self.add(family, OwnedObjectKind::Route, config)
        }

        fn delete_rule(
            &self,
            family: IpFamily,
            _config: LinuxTransparentRouteConfig,
        ) -> Result<(), LinuxRoutingError> {
            self.delete(family, OwnedObjectKind::Rule)
        }

        fn delete_route(
            &self,
            family: IpFamily,
            _config: LinuxTransparentRouteConfig,
        ) -> Result<(), LinuxRoutingError> {
            self.delete(family, OwnedObjectKind::Route)
        }
    }

    fn config() -> LinuxTransparentRouteConfig {
        LinuxTransparentRouteConfig {
            mark: 1,
            table: 100,
            priority: 30_100,
            protocol: 186,
        }
    }

    fn journal_path() -> PathBuf {
        let id = NEXT_JOURNAL.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "pathchord-routing-{}-{id}.json",
            std::process::id()
        ))
    }

    #[test]
    fn apply_is_idempotent_and_restore_removes_only_owned_objects() {
        let adapter = Arc::new(FakeRouteAdapter::default());
        let path = journal_path();
        let manager = LinuxTransparentRouteManager::new(adapter.clone(), &path);
        assert!(!manager.apply(config()).unwrap().replayed);
        assert_eq!(adapter.object_count(), 4);
        assert!(manager.apply(config()).unwrap().replayed);
        assert_eq!(manager.restore().unwrap().restored_objects, 4);
        assert_eq!(adapter.object_count(), 0);
        assert!(!path.exists());
    }

    #[test]
    fn preexisting_or_changed_objects_are_never_deleted() {
        let adapter = Arc::new(FakeRouteAdapter::default());
        adapter.set_foreign(IpFamily::Ipv4, OwnedObjectKind::Rule);
        let path = journal_path();
        let manager = LinuxTransparentRouteManager::new(adapter.clone(), &path);
        assert_eq!(
            manager.apply(config()),
            Err(LinuxRoutingError::OwnershipConflict)
        );
        assert_eq!(adapter.object_count(), 0);
        assert!(!path.exists());
    }

    #[test]
    fn failed_apply_rolls_back_and_crash_journal_recovers() {
        let adapter = Arc::new(FakeRouteAdapter::default());
        adapter.fail_at(3);
        let path = journal_path();
        let manager = LinuxTransparentRouteManager::new(adapter.clone(), &path);
        assert!(matches!(
            manager.apply(config()),
            Err(LinuxRoutingError::Command(_))
        ));
        assert_eq!(adapter.object_count(), 0);
        assert!(!path.exists());

        adapter.state.lock().unwrap().fail_at = None;
        assert!(!manager.apply(config()).unwrap().replayed);
        assert_eq!(adapter.object_count(), 4);
        std::mem::forget(manager);

        let recovered = LinuxTransparentRouteManager::new(adapter.clone(), &path);
        assert_eq!(recovered.recover().unwrap().restored_objects, 4);
        assert_eq!(adapter.object_count(), 0);
        assert!(!path.exists());
    }

    #[test]
    fn crash_recovery_stops_on_changed_ownership_and_keeps_journal() {
        let adapter = Arc::new(FakeRouteAdapter::default());
        let path = journal_path();
        let manager = LinuxTransparentRouteManager::new(adapter.clone(), &path);
        manager.apply(config()).unwrap();
        std::mem::forget(manager);

        adapter.set_foreign(IpFamily::Ipv6, OwnedObjectKind::Route);
        let recovered = LinuxTransparentRouteManager::new(adapter.clone(), &path);
        assert_eq!(
            recovered.recover(),
            Err(LinuxRoutingError::OwnershipConflict)
        );
        assert!(path.exists());
        adapter.clear_foreign(IpFamily::Ipv6, OwnedObjectKind::Route);
        assert_eq!(recovered.recover().unwrap().restored_objects, 4);
        assert_eq!(adapter.object_count(), 0);
        assert!(!path.exists());
    }

    #[test]
    fn json_classification_requires_every_ownership_field() {
        let rule = serde_json::json!([{
            "priority": 30100,
            "fwmark": "0x1",
            "table": 100,
            "protocol": 186
        }]);
        assert_eq!(
            classify_rule(rule.as_array().unwrap(), config()),
            RouteObjectState::Exact
        );
        let conflicting_rule = serde_json::json!([{
            "priority": 30100,
            "fwmark": "0x2",
            "table": 100,
            "protocol": 186
        }]);
        assert_eq!(
            classify_rule(conflicting_rule.as_array().unwrap(), config()),
            RouteObjectState::Conflict
        );

        let route = serde_json::json!([{
            "type": "local",
            "dst": "default",
            "dev": "lo",
            "protocol": "186"
        }]);
        assert_eq!(
            classify_route(route.as_array().unwrap(), IpFamily::Ipv4, config()),
            RouteObjectState::Exact
        );
    }

    #[test]
    fn numeric_ip_inventory_matches_ownership_but_changed_selectors_do_not() {
        let mut rule = serde_json::json!({"priority":30100,"src":"all","fwmark":"0x1","table":"100","protocol":"186"});
        assert_eq!(
            classify_rule(&[rule.clone()], config()),
            RouteObjectState::Exact
        );
        rule["fwmask"] = serde_json::json!("0xff");
        assert_eq!(
            classify_rule(&[rule.clone()], config()),
            RouteObjectState::Conflict
        );
        rule.as_object_mut().unwrap().remove("fwmask");
        rule["src"] = serde_json::json!("192.0.2.0/24");
        assert_eq!(classify_rule(&[rule], config()), RouteObjectState::Conflict);
        let mut route = serde_json::json!({"type":"2","dst":"default","dev":"lo","protocol":"186","metric":1024,"flags":[],"pref":"medium"});
        assert_eq!(
            classify_route(&[route.clone()], IpFamily::Ipv6, config()),
            RouteObjectState::Exact
        );
        route["metric"] = serde_json::json!(1025);
        assert_eq!(
            classify_route(&[route], IpFamily::Ipv6, config()),
            RouteObjectState::Conflict
        );
    }

    #[test]
    fn missing_route_table_errors_are_treated_as_absent() {
        assert!(missing_route_table(
            "Error: ipv4: FIB table does not exist.\nDump terminated"
        ));
        assert!(missing_route_table("table does not exist"));
        assert!(!missing_route_table(
            "RTNETLINK answers: Operation not permitted"
        ));
    }
}
