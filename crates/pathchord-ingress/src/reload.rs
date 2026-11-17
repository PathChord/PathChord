use std::collections::BTreeSet;
use std::future::Future;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use pathchord_policy::{
    CompileError, CompiledPolicy, ConfigError, Generation, KubeConfig, PolicyConfig,
    ValidationError,
};
use serde::Serialize;
use thiserror::Error;
use tokio::sync::mpsc;

use pathchord_config::{ConfigurationError, ConfigurationSource, is_configuration_file};

const MAX_WATCH_EVENTS: usize = 64;
const RELOAD_DEBOUNCE: std::time::Duration = std::time::Duration::from_millis(40);

#[derive(Debug, Clone)]
pub struct ReloadSnapshot {
    pub generation: u64,
    pub config: Arc<PolicyConfig>,
    pub compiled: Arc<CompiledPolicy>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReloadState {
    Pending,
    Applied,
    Rejected,
    RestartRequired,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReloadStatus {
    pub state: ReloadState,
    pub active_generation: u64,
    pub observed_at_ms: u64,
    pub reason: Option<String>,
    pub diagnostic: Option<ReloadDiagnostic>,
}

/// Safe, stable reload diagnostics. The field path is a schema location,
/// optionally qualified by a validated resource identity. Input values,
/// filesystem paths, and third-party error text are never included.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ReloadDiagnostic {
    pub code: &'static str,
    pub field_path: String,
    pub message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReloadOutcome {
    Pending { generation: u64 },
    Applied { generation: u64 },
    Rejected { active_generation: u64 },
    RestartRequired { active_generation: u64 },
}

#[derive(Debug, Error)]
pub enum ReloadError {
    #[error("configuration source I/O failed")]
    Io,
    #[error("configuration exceeds the size bound")]
    TooLarge,
    #[error("configuration directory contains too many files")]
    TooManyFiles,
    #[error("configuration directory exceeds the recursion depth bound")]
    TooDeep,
    #[error("configuration directory contains no supported files")]
    EmptyDirectory,
    #[error("configuration source must contain regular files and directories")]
    UnsupportedSource,
    #[error("configuration directory entries must not be symbolic links")]
    Symlink,
    #[error("configuration watcher failed")]
    Notify,
    #[error("initial configuration is invalid")]
    InvalidInitialConfiguration,
    #[error("initial geodata configuration is invalid: {field_path}")]
    InvalidInitialGeodata { field_path: String },
    #[error("control-plane reload transaction was rejected")]
    ControlCommit,
    #[error("configuration reload state lock is unavailable")]
    Lock,
}

impl From<ConfigurationError> for ReloadError {
    fn from(error: ConfigurationError) -> Self {
        match error {
            ConfigurationError::Io => Self::Io,
            ConfigurationError::TooLarge => Self::TooLarge,
            ConfigurationError::TooManyFiles => Self::TooManyFiles,
            ConfigurationError::TooDeep => Self::TooDeep,
            ConfigurationError::EmptyDirectory => Self::EmptyDirectory,
            ConfigurationError::UnsupportedSource => Self::UnsupportedSource,
            ConfigurationError::Symlink => Self::Symlink,
        }
    }
}

#[derive(Clone)]
pub struct ConfigReloadHandle {
    state: Arc<RwLock<ReloadData>>,
    reload_gate: Arc<std::sync::Mutex<()>>,
}

struct ReloadData {
    active: ReloadSnapshot,
    source_dir: Option<PathBuf>,
    status: ReloadStatus,
    runtime_managed: bool,
    next_generation: u64,
    pending: Option<ReloadSnapshot>,
}

impl std::fmt::Debug for ConfigReloadHandle {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ConfigReloadHandle")
            .field("status", &self.status())
            .finish_non_exhaustive()
    }
}

impl ConfigReloadHandle {
    pub fn from_yaml(input: &str, generation: u64) -> Result<Self, ReloadError> {
        Self::from_documents([input], generation)
    }

    pub fn from_documents<'a>(
        inputs: impl IntoIterator<Item = &'a str>,
        generation: u64,
    ) -> Result<Self, ReloadError> {
        Self::from_documents_with_source(inputs, generation, None)
    }

    fn from_documents_with_source<'a>(
        inputs: impl IntoIterator<Item = &'a str>,
        generation: u64,
        source_dir: Option<PathBuf>,
    ) -> Result<Self, ReloadError> {
        let active = compile_candidate_documents(inputs, generation, source_dir.as_deref())
            .map_err(|diagnostic| {
                if diagnostic.code == "CONFIG_GEODATA_INVALID" {
                    ReloadError::InvalidInitialGeodata {
                        field_path: diagnostic.field_path,
                    }
                } else {
                    ReloadError::InvalidInitialConfiguration
                }
            })?;
        Ok(Self {
            state: Arc::new(RwLock::new(ReloadData {
                active,
                source_dir,
                status: ReloadStatus {
                    state: ReloadState::Applied,
                    active_generation: generation,
                    observed_at_ms: now_ms(),
                    reason: None,
                    diagnostic: None,
                },
                runtime_managed: false,
                next_generation: generation,
                pending: None,
            })),
            reload_gate: Arc::new(std::sync::Mutex::new(())),
        })
    }

    pub fn snapshot(&self) -> Result<ReloadSnapshot, ReloadError> {
        self.state
            .read()
            .map(|state| state.active.clone())
            .map_err(|_| ReloadError::Lock)
    }

    #[must_use]
    pub fn status(&self) -> ReloadStatus {
        self.state
            .read()
            .map_or_else(|_| failed_lock_status(), |state| state.status.clone())
    }

    /// The runtime prepares adapters before acknowledging a candidate. Enable
    /// this before starting the filesystem watcher.
    pub fn enable_runtime_commit(&self) -> Result<(), ReloadError> {
        self.state
            .write()
            .map_err(|_| ReloadError::Lock)?
            .runtime_managed = true;
        Ok(())
    }

    pub fn pending_snapshot(&self) -> Result<Option<ReloadSnapshot>, ReloadError> {
        self.state
            .read()
            .map(|state| state.pending.clone())
            .map_err(|_| ReloadError::Lock)
    }

    /// Run a synchronous durable hook while the candidate identity is locked.
    /// A superseded candidate never reaches the hook. The caller holds its
    /// runtime publication locks, so no await can split the commit.
    pub fn commit_runtime_candidate<F>(
        &self,
        generation: u64,
        durable_commit: F,
    ) -> Result<bool, ReloadError>
    where
        F: FnOnce() -> Result<(), ReloadError>,
    {
        let mut state = self.state.write().map_err(|_| ReloadError::Lock)?;
        if state
            .pending
            .as_ref()
            .is_none_or(|candidate| candidate.generation != generation)
        {
            return Ok(false);
        }
        durable_commit()?;
        state.active = state.pending.take().expect("candidate checked under lock");
        state.status = ReloadStatus {
            state: ReloadState::Applied,
            active_generation: generation,
            observed_at_ms: now_ms(),
            reason: None,
            diagnostic: None,
        };
        Ok(true)
    }

    pub fn reject_runtime_candidate(
        &self,
        generation: u64,
        _reason: impl Into<String>,
    ) -> Result<(), ReloadError> {
        let mut state = self.state.write().map_err(|_| ReloadError::Lock)?;
        if state
            .pending
            .as_ref()
            .is_some_and(|candidate| candidate.generation == generation)
        {
            state.pending = None;
            state.status = ReloadStatus {
                state: ReloadState::Rejected,
                active_generation: state.active.generation,
                observed_at_ms: now_ms(),
                reason: Some("runtime rejected configuration candidate".to_owned()),
                diagnostic: Some(reload_diagnostic(
                    "CONFIG_RUNTIME_REJECTED",
                    "$".to_owned(),
                    "runtime rejected configuration candidate",
                )),
            };
        }
        Ok(())
    }

    pub fn reload_text(&self, input: &str) -> ReloadOutcome {
        self.reload_documents([input])
    }

    pub fn reload_documents<'a>(&self, inputs: impl IntoIterator<Item = &'a str>) -> ReloadOutcome {
        // Serialize candidate preparation without blocking readers of the
        // active snapshot. This also prevents an older compile finishing
        // after a newer reload and replacing it.
        let Ok(_reload) = self.reload_gate.lock() else {
            return ReloadOutcome::Rejected {
                active_generation: 0,
            };
        };
        let (generation, source_dir) = {
            let Ok(mut state) = self.state.write() else {
                return ReloadOutcome::Rejected {
                    active_generation: 0,
                };
            };
            let active_generation = state.active.generation;
            let previous_generation = if state.runtime_managed {
                state.next_generation
            } else {
                active_generation
            };
            let Some(generation) = previous_generation.checked_add(1) else {
                state.pending = None;
                state.status = ReloadStatus {
                    state: ReloadState::Rejected,
                    active_generation,
                    observed_at_ms: now_ms(),
                    reason: Some("configuration generation is exhausted".to_owned()),
                    diagnostic: Some(reload_diagnostic(
                        "CONFIG_GENERATION_EXHAUSTED",
                        "$".to_owned(),
                        "configuration generation is exhausted",
                    )),
                };
                return ReloadOutcome::Rejected { active_generation };
            };
            state.next_generation = generation;
            (generation, state.source_dir.clone())
        };
        // Dataset loading and compilation can be substantial. Keep the
        // published snapshot readable while a candidate is prepared.
        let result = compile_candidate_documents(inputs, generation, source_dir.as_deref());
        let Ok(mut state) = self.state.write() else {
            return ReloadOutcome::Rejected {
                active_generation: 0,
            };
        };
        let active_generation = state.active.generation;
        let candidate = match result {
            Ok(candidate) => candidate,
            Err(diagnostic) => {
                state.pending = None;
                state.status = ReloadStatus {
                    state: ReloadState::Rejected,
                    active_generation,
                    observed_at_ms: now_ms(),
                    reason: Some(diagnostic.message.clone()),
                    diagnostic: Some(diagnostic),
                };
                return ReloadOutcome::Rejected { active_generation };
            }
        };
        if candidate.config == state.active.config
            && candidate.compiled.geodata_fingerprint()
                == state.active.compiled.geodata_fingerprint()
        {
            state.pending = None;
            state.status = ReloadStatus {
                state: ReloadState::Applied,
                active_generation,
                observed_at_ms: now_ms(),
                reason: None,
                diagnostic: None,
            };
            return ReloadOutcome::Applied {
                generation: active_generation,
            };
        }
        if startup_fields_changed(&state.active.config, &candidate.config) {
            state.pending = None;
            state.status = ReloadStatus {
                state: ReloadState::RestartRequired,
                active_generation,
                observed_at_ms: now_ms(),
                reason: Some("static Egress/key, DNS or Listener fields changed".to_owned()),
                diagnostic: None,
            };
            return ReloadOutcome::RestartRequired { active_generation };
        }
        if state.runtime_managed {
            if let Some(pending) = &state.pending
                && candidate.config == pending.config
                && candidate.compiled.geodata_fingerprint()
                    == pending.compiled.geodata_fingerprint()
            {
                return ReloadOutcome::Pending {
                    generation: pending.generation,
                };
            }
            state.pending = Some(candidate);
            state.status = ReloadStatus {
                state: ReloadState::Pending,
                active_generation,
                observed_at_ms: now_ms(),
                reason: None,
                diagnostic: None,
            };
            ReloadOutcome::Pending { generation }
        } else {
            state.active = candidate;
            state.status = ReloadStatus {
                state: ReloadState::Applied,
                active_generation: generation,
                observed_at_ms: now_ms(),
                reason: None,
                diagnostic: None,
            };
            ReloadOutcome::Applied { generation }
        }
    }

    fn replace_status(&self, next: ReloadStatus) {
        if let Ok(mut state) = self.state.write() {
            state.pending = None;
            state.status = next;
        }
    }
}

pub struct ConfigHotReloader {
    source: ConfigurationSource,
    directories: BTreeSet<PathBuf>,
    geodata_paths: BTreeSet<PathBuf>,
    geodata_watch_dirs: BTreeSet<PathBuf>,
    handle: ConfigReloadHandle,
    events: mpsc::Receiver<Result<Event, notify::Error>>,
    watcher: RecommendedWatcher,
}

impl std::fmt::Debug for ConfigHotReloader {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ConfigHotReloader")
            .field("status", &self.handle.status())
            .finish_non_exhaustive()
    }
}

impl ConfigHotReloader {
    pub async fn bind(path: impl Into<PathBuf>, generation: u64) -> Result<Self, ReloadError> {
        let source = ConfigurationSource::bind(path.into()).await?;
        let (sender, events) = mpsc::channel(MAX_WATCH_EVENTS);
        let mut watcher = notify::recommended_watcher(move |event| {
            let _ = sender.try_send(event);
        })
        .map_err(|_| ReloadError::Notify)?;
        // Watching the containing directory survives atomic file replacement.
        watcher
            .watch(
                source
                    .path()
                    .parent()
                    .ok_or(ReloadError::UnsupportedSource)?,
                RecursiveMode::NonRecursive,
            )
            .map_err(|_| ReloadError::Notify)?;
        if source.is_directory() {
            watcher
                .watch(source.path(), RecursiveMode::Recursive)
                .map_err(|_| ReloadError::Notify)?;
        }
        let loaded = source.load().await?;
        // Establish external parent watches before reading dataset bytes.
        // File replacements occurring while initial compilation runs are then
        // queued and re-evaluated when the watcher task starts.
        let initial_candidate =
            KubeConfig::from_documents(loaded.documents.iter().map(String::as_str))
                .and_then(|kube| kube.into_validated_snapshot(Generation::new(generation)))
                .map_err(|_| ReloadError::InvalidInitialConfiguration)?;
        let geodata_paths = CompiledPolicy::referenced_geodata_paths(
            initial_candidate.config(),
            Some(source.base_directory()),
        )
        .map_err(|_| ReloadError::InvalidInitialConfiguration)?;
        let config_parent = source
            .path()
            .parent()
            .ok_or(ReloadError::UnsupportedSource)?;
        let geodata_watch_dirs: BTreeSet<_> = geodata_paths
            .iter()
            .filter_map(|path| path.parent())
            .filter(|parent| {
                *parent != config_parent
                    && !(source.is_directory() && parent.starts_with(source.path()))
            })
            .map(std::path::Path::to_path_buf)
            .collect();
        for directory in &geodata_watch_dirs {
            watcher
                .watch(directory, RecursiveMode::NonRecursive)
                .map_err(|_| ReloadError::Notify)?;
        }
        let handle = ConfigReloadHandle::from_documents_with_source(
            loaded.documents.iter().map(String::as_str),
            generation,
            Some(source.base_directory().to_owned()),
        )?;
        Ok(Self {
            source,
            directories: loaded.directories,
            geodata_paths,
            geodata_watch_dirs,
            handle,
            events,
            watcher,
        })
    }

    #[must_use]
    pub fn handle(&self) -> ConfigReloadHandle {
        self.handle.clone()
    }

    pub async fn run_until_shutdown<F>(mut self, shutdown: F) -> Result<(), ReloadError>
    where
        F: Future<Output = ()> + Send,
    {
        let mut shutdown = Box::pin(shutdown);
        loop {
            tokio::select! {
                () = shutdown.as_mut() => return Ok(()),
                event = self.events.recv() => {
                    let Some(event) = event else {
                        return Err(ReloadError::Notify);
                    };
                    let event = match event {
                        Ok(event) => event,
                        Err(_) => {
                            self.handle.replace_status(ReloadStatus {
                                state: ReloadState::Rejected,
                                active_generation: self.handle.status().active_generation,
                                observed_at_ms: now_ms(),
                                reason: Some("filesystem watcher error".to_owned()),
                                diagnostic: Some(reload_diagnostic(
                                    "CONFIG_WATCH_FAILED", "$".to_owned(), "filesystem watcher error",
                                )),
                            });
                            continue;
                        }
                    };
                    if !self.reload_event(&event) {
                        continue;
                    }
                    // Coalesce editor rename/write bursts before reading the
                    // whole candidate. Cancellation also interrupts pending I/O.
                    tokio::select! {
                        () = shutdown.as_mut() => return Ok(()),
                        () = tokio::time::sleep(RELOAD_DEBOUNCE) => {},
                    }
                    for _ in 0..MAX_WATCH_EVENTS {
                        if self.events.try_recv().is_err() { break; }
                    }
                    if self.rearm_directory_watch().is_err() {
                        self.handle.replace_status(ReloadStatus {
                            state: ReloadState::Rejected,
                            active_generation: self.handle.status().active_generation,
                            observed_at_ms: now_ms(),
                            reason: Some("configuration directory watcher could not be restored".to_owned()),
                            diagnostic: Some(reload_diagnostic(
                                "CONFIG_WATCH_FAILED", "$".to_owned(), "configuration directory watcher could not be restored",
                            )),
                        });
                        continue;
                    }
                    let loaded = tokio::select! {
                        () = shutdown.as_mut() => return Ok(()),
                        loaded = self.source.load() => loaded,
                    };
                    match loaded {
                        Ok(loaded) => {
                            self.directories = loaded.directories;
                            // Watch both the active files and a syntactically
                            // valid new candidate before compiling it, so an
                            // atomic replacement or recovery from a bad file
                            // cannot be missed between reading and watching.
                            let mut paths = CompiledPolicy::referenced_geodata_paths(
                                &self.handle.snapshot()?.config,
                                Some(self.source.base_directory()),
                            ).unwrap_or_else(|_| self.geodata_paths.clone());
                            if let Ok(candidate) = KubeConfig::from_documents(loaded.documents.iter().map(String::as_str))
                                .and_then(|kube| kube.into_validated_snapshot(Generation::new(1)))
                                && let Ok(candidate_paths) = CompiledPolicy::referenced_geodata_paths(
                                    candidate.config(),
                                    Some(self.source.base_directory()),
                                )
                            {
                                paths.extend(candidate_paths);
                            }
                            if self.update_geodata_watches(paths).is_err() {
                                self.handle.replace_status(ReloadStatus {
                                    state: ReloadState::Rejected,
                                    active_generation: self.handle.status().active_generation,
                                    observed_at_ms: now_ms(),
                                    reason: Some("geodata watcher could not be established".to_owned()),
                                    diagnostic: Some(reload_diagnostic(
                                        "CONFIG_WATCH_FAILED", "$.GeoDataDatabase.spec.path".to_owned(), "geodata watcher could not be established",
                                    )),
                                });
                                continue;
                            }
                            let handle = self.handle.clone();
                            let documents = loaded.documents;
                            tokio::task::spawn_blocking(move || {
                                handle.reload_documents(documents.iter().map(String::as_str))
                            })
                            .await
                            .map_err(|_| ReloadError::Lock)?;
                        }
                        Err(_) => {
                            self.handle.replace_status(ReloadStatus {
                                state: ReloadState::Rejected,
                                active_generation: self.handle.status().active_generation,
                                observed_at_ms: now_ms(),
                                reason: Some("configuration bundle read failed".to_owned()),
                                diagnostic: Some(reload_diagnostic(
                                    "CONFIG_SOURCE_UNAVAILABLE", "$".to_owned(), "configuration bundle read failed",
                                )),
                            });
                        }
                    }
                }
            }
        }
    }

    fn rearm_directory_watch(&mut self) -> Result<(), ReloadError> {
        if self.source.is_directory() {
            let _ = self.watcher.unwatch(self.source.path());
            if self
                .source
                .path()
                .symlink_metadata()
                .is_ok_and(|metadata| metadata.is_dir() && !metadata.file_type().is_symlink())
            {
                self.watcher
                    .watch(self.source.path(), RecursiveMode::Recursive)
                    .map_err(|_| ReloadError::Notify)?;
            }
        }
        Ok(())
    }

    fn update_geodata_watches(&mut self, paths: BTreeSet<PathBuf>) -> Result<(), ReloadError> {
        let config_parent = self
            .source
            .path()
            .parent()
            .ok_or(ReloadError::UnsupportedSource)?;
        let desired: BTreeSet<_> = paths
            .iter()
            .filter_map(|path| path.parent())
            .filter(|parent| {
                *parent != config_parent
                    && !(self.source.is_directory() && parent.starts_with(self.source.path()))
            })
            .map(std::path::Path::to_path_buf)
            .collect();
        let mut added: Vec<PathBuf> = Vec::new();
        for path in desired.difference(&self.geodata_watch_dirs) {
            if self
                .watcher
                .watch(path, RecursiveMode::NonRecursive)
                .is_err()
            {
                for path in added {
                    let _ = self.watcher.unwatch(&path);
                }
                return Err(ReloadError::Notify);
            }
            added.push(path.clone());
        }
        for path in self.geodata_watch_dirs.difference(&desired) {
            let _ = self.watcher.unwatch(path);
        }
        self.geodata_watch_dirs = desired;
        self.geodata_paths = paths;
        Ok(())
    }

    fn reload_event(&self, event: &Event) -> bool {
        if !matches!(
            event.kind,
            EventKind::Create(_) | EventKind::Modify(_) | EventKind::Remove(_)
        ) {
            return false;
        }
        if event.paths.is_empty() {
            return true;
        }
        event.paths.iter().any(|path| {
            if self.geodata_paths.contains(path) {
                return true;
            }
            if path == self.source.path() {
                return true;
            }
            if !self.source.is_directory() || !self.source.visible_descendant(path) {
                return false;
            }
            is_configuration_file(path)
                || self.directories.contains(path)
                || path
                    .symlink_metadata()
                    .is_ok_and(|metadata| metadata.is_dir() || metadata.file_type().is_symlink())
        })
    }
}

fn compile_candidate_documents<'a>(
    inputs: impl IntoIterator<Item = &'a str>,
    generation: u64,
    source_dir: Option<&std::path::Path>,
) -> Result<ReloadSnapshot, ReloadDiagnostic> {
    let kube = KubeConfig::from_documents(inputs).map_err(config_diagnostic)?;
    let validated = kube
        .into_validated_snapshot(Generation::new(generation))
        .map_err(config_diagnostic)?;
    let config = Arc::new(validated.config().clone());
    let compiled = Arc::new(
        CompiledPolicy::compile_with_source(&validated, source_dir).map_err(compile_diagnostic)?,
    );
    Ok(ReloadSnapshot {
        generation,
        config,
        compiled,
    })
}

fn reload_diagnostic(
    code: &'static str,
    field_path: String,
    message: impl Into<String>,
) -> ReloadDiagnostic {
    ReloadDiagnostic {
        code,
        field_path,
        message: message.into(),
    }
}

fn config_diagnostic(error: ConfigError) -> ReloadDiagnostic {
    match error {
        ConfigError::Yaml(_) => reload_diagnostic(
            "CONFIG_PARSE_ERROR",
            "$".to_owned(),
            "configuration document could not be parsed",
        ),
        ConfigError::InvalidEnvelope(_) => reload_diagnostic(
            "CONFIG_INVALID_ENVELOPE",
            "$".to_owned(),
            "configuration resource envelope is invalid",
        ),
        ConfigError::UnsupportedApiVersion(_) => reload_diagnostic(
            "CONFIG_UNSUPPORTED_API_VERSION",
            "$.apiVersion".to_owned(),
            "configuration API version is unsupported",
        ),
        ConfigError::UnsupportedKind(_) => reload_diagnostic(
            "CONFIG_UNSUPPORTED_KIND",
            "$.kind".to_owned(),
            "configuration resource kind is unsupported",
        ),
        ConfigError::DuplicateResource { kind, name, .. } => reload_diagnostic(
            "CONFIG_DUPLICATE_RESOURCE",
            resource_field(&kind, &name, "metadata.name"),
            "configuration resource identity is duplicated",
        ),
        ConfigError::RetiredField {
            kind,
            name,
            field_path,
            replacement,
        } => reload_diagnostic(
            "CONFIG_RETIRED_FIELD",
            resource_field(&kind, &name, &field_path),
            format!("configuration field is retired; use {replacement}"),
        ),
        ConfigError::InvalidSpec { kind, name, reason } => reload_diagnostic(
            "CONFIG_INVALID_FIELD",
            resource_field(&kind, &name, spec_error_field(&kind, &reason)),
            "configuration field is invalid",
        ),
        ConfigError::Validation(error) => validation_diagnostic(error),
    }
}

fn validation_diagnostic(error: ValidationError) -> ReloadDiagnostic {
    let (code, field_path) = match error {
        ValidationError::InvalidEgressPathPool { egress_id, field } => (
            "CONFIG_INVALID_FIELD",
            resource_field("Egress", &egress_id, field),
        ),
        ValidationError::MissingFallback => ("CONFIG_MISSING_RESOURCE", "$.FallbackPolicy".into()),
        ValidationError::EmptyId { .. } => {
            ("CONFIG_INVALID_FIELD", "$.resources[].metadata.name".into())
        }
        ValidationError::ResourceIdentityLimit { .. } => (
            "CONFIG_RESOURCE_LIMIT",
            "$.resources[].metadata.namespace".into(),
        ),
        ValidationError::DuplicateId { kind, id } => (
            "CONFIG_DUPLICATE_RESOURCE",
            resource_field(kind, &id, "metadata.name"),
        ),
        ValidationError::InvalidPort { kind, id } => (
            "CONFIG_INVALID_FIELD",
            resource_field(kind, &id, "spec.port"),
        ),
        ValidationError::ClassBudgetExceedsSession { id, .. } => (
            "CONFIG_INVALID_FIELD",
            resource_field("TrafficPolicy", &id, "spec.classReplicationBudgetBps"),
        ),
        ValidationError::ZeroMinUsablePaths { rule_id } => (
            "CONFIG_INVALID_FIELD",
            resource_field("EgressRule", &rule_id, "spec.requirements.minUsablePaths"),
        ),
        ValidationError::InvalidTransitOptions { proxy_id, .. } => (
            "CONFIG_INVALID_FIELD",
            resource_field("TransitProxy", &proxy_id, "spec.options"),
        ),
        ValidationError::ReservedImportedLabelNamespace { proxy_id, .. } => (
            "CONFIG_INVALID_FIELD",
            resource_field("TransitProxy", &proxy_id, "metadata.labels"),
        ),
        ValidationError::InvalidTransitCredentialReference { proxy_id } => (
            "CONFIG_INVALID_FIELD",
            resource_field("TransitProxy", &proxy_id, "spec.credentialsRef"),
        ),
        ValidationError::UnknownEgress { rule_id, .. } => (
            "CONFIG_UNKNOWN_REFERENCE",
            resource_field("Rule", &rule_id, "spec.egressRef"),
        ),
        ValidationError::UnknownTrafficPolicy { rule_id, .. } => (
            "CONFIG_UNKNOWN_REFERENCE",
            resource_field("Egress", &rule_id, "spec.trafficPolicyRef"),
        ),
        ValidationError::UnknownTrafficClass { rule_id, .. } => (
            "CONFIG_UNKNOWN_REFERENCE",
            resource_field("Resource", &rule_id, "spec"),
        ),
        ValidationError::UnknownSubscription { proxy_id, .. } => (
            "CONFIG_UNKNOWN_REFERENCE",
            resource_field("TransitProxy", &proxy_id, "spec.source.subscriptionRef"),
        ),
        ValidationError::InvalidSubscription {
            subscription_id, ..
        } => (
            "CONFIG_INVALID_FIELD",
            resource_field("Subscription", &subscription_id, "spec"),
        ),
        ValidationError::InvalidDnsPolicy { policy_id, .. } => (
            "CONFIG_INVALID_FIELD",
            resource_field("DNSPolicy", &policy_id, "spec"),
        ),
        ValidationError::InvalidGeoData { owner, .. } => (
            "CONFIG_INVALID_GEODATA",
            resource_field("Resource", &owner, "spec"),
        ),
    };
    reload_diagnostic(code, field_path, "configuration validation failed")
}

fn compile_diagnostic(error: CompileError) -> ReloadDiagnostic {
    if let CompileError::InvalidGeodata {
        database,
        set,
        reason,
    } = &error
    {
        let mut field = resource_field("GeoDataDatabase", database, "spec.path");
        if let Some(set) = set {
            // Set names have already passed schema validation and are
            // bounded. Do not expose the database path or pattern contents.
            field.push_str(" set=");
            field.push_str(set);
        }
        return reload_diagnostic("CONFIG_GEODATA_INVALID", field, *reason);
    }
    let (rule_id, field) = match error {
        CompileError::InvalidSourceNetwork { rule_id, .. } => {
            (rule_id, "spec.match.sourceNetworks")
        }
        CompileError::EmptySelector { rule_id } => (rule_id, "spec.selector"),
        CompileError::InvalidGeodata { .. } => unreachable!("handled above"),
    };
    reload_diagnostic(
        "CONFIG_COMPILE_ERROR",
        resource_field("Rule", &rule_id, field),
        "configuration policy compilation failed",
    )
}

fn resource_field(kind: &str, name: &str, field: &str) -> String {
    let kind = match kind {
        "Egress" | "egress" => "Egress",
        "TransitProxy" | "Transit Proxy" => "TransitProxy",
        "Subscription" | "subscription" => "Subscription",
        "EgressRule" => "EgressRule",
        "TransitRule" => "TransitRule",
        "ProxyRule" => "ProxyRule",
        "TrafficPolicy" | "traffic policy" => "TrafficPolicy",
        "Listener" | "listener" => "Listener",
        "DNSPolicy" => "DNSPolicy",
        "FallbackPolicy" => "FallbackPolicy",
        "EgressService" => "EgressService",
        "GeoDataDatabase" => "GeoDataDatabase",
        "NodeProbePolicy" => "NodeProbePolicy",
        "Rule" | "rule" => "Rule",
        "metadata" => "Resource",
        _ => "Resource",
    };
    // Resource identities are bounded and validated before they are used to
    // qualify a path. Do not echo arbitrary parser input or control bytes.
    let safe_name = !name.is_empty()
        && name.len() <= 63
        && name
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-');
    if safe_name {
        format!("$.resources.{kind}[{name}].{field}")
    } else {
        format!("$.resources.{kind}[].{field}")
    }
}

fn spec_error_field(kind: &str, reason: &str) -> &'static str {
    if kind == "Egress" && reason.contains("endpoints[].host") {
        return "spec.endpoints[].host";
    }
    if kind == "TransitProxy" {
        for (needle, field) in [
            ("options.transport.hosts", "spec.options.transport.hosts"),
            (
                "options.transport.maxEarlyDataBytes",
                "spec.options.transport.maxEarlyDataBytes",
            ),
            ("options.tls.certificates", "spec.options.tls.certificates"),
            (
                "options.tls.clientCertificates",
                "spec.options.tls.clientCertificates",
            ),
            (
                "options.tls.clientHelloFingerprint",
                "spec.options.tls.clientHelloFingerprint",
            ),
            (
                "options.udpOverTcpVersion",
                "spec.options.udpOverTcpVersion",
            ),
        ] {
            if reason.contains(needle) {
                return field;
            }
        }
        if reason.contains("options.") {
            return "spec.options";
        }
    }
    for (needle, field) in [
        ("pathPool.minUsablePaths", "spec.pathPool.minUsablePaths"),
        (
            "pathPool.targetUsablePaths",
            "spec.pathPool.targetUsablePaths",
        ),
        (
            "requiredCapabilities",
            "spec.admission.requiredCapabilities",
        ),
        ("endpoints[].host", "spec.endpoints[].host"),
        ("metadata.labels", "metadata.labels"),
        ("metadata.annotations", "metadata.annotations"),
        ("trafficPolicyRef", "spec.trafficPolicyRef"),
        ("trafficClassRef", "spec.trafficClassRef"),
        ("source.url", "spec.source.url"),
        ("source.type", "spec.source.type"),
        ("subscriptionRef", "spec.source.subscriptionRef"),
        ("defaultRoute", "spec.defaultRoute"),
        ("local.servers", "spec.local.servers"),
        ("transit.servers", "spec.transit.servers"),
        ("egress.servers", "spec.egress.servers"),
        ("routeTable", "spec.routeTable"),
        ("allowedSources", "spec.allowedSources"),
        ("processMetadata", "spec.processMetadata"),
        ("flowTags", "spec.flowTags"),
        ("credentialsRef", "spec.credentialsRef"),
        ("sourceNetworks", "spec.match.sourceNetworks"),
        ("egressSelector", "spec.egressSelector"),
        ("catchAll", "spec.catchAll"),
        ("order", "spec.order"),
        ("protocol", "spec.protocol"),
        ("platform", "spec.platform"),
        ("backend", "spec.backend"),
        ("mtu", "spec.mtu"),
        ("weight", "spec.weight"),
        ("publicKey", "spec.publicKey"),
        ("port is", "spec.port"),
        ("port must", "spec.port"),
        ("address", "spec.address"),
        ("pathPool", "spec.pathPool"),
        ("host", "spec.host"),
        ("bind", "spec.bind"),
        ("match", "spec.match"),
    ] {
        if reason.contains(needle) {
            return if needle == "credentialsRef" && kind == "Listener" {
                "spec.authentication.credentialsRef"
            } else {
                field
            };
        }
    }
    "spec"
}

fn startup_fields_changed(current: &PolicyConfig, candidate: &PolicyConfig) -> bool {
    current.listeners != candidate.listeners
        || current.egresses != candidate.egresses
        || current.dns_policy != candidate.dns_policy
}

fn failed_lock_status() -> ReloadStatus {
    ReloadStatus {
        state: ReloadState::Rejected,
        active_generation: 0,
        observed_at_ms: now_ms(),
        reason: Some("reload status lock failed".to_owned()),
        diagnostic: Some(reload_diagnostic(
            "CONFIG_STATUS_UNAVAILABLE",
            "$".to_owned(),
            "reload status lock failed",
        )),
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| {
            duration.as_millis().min(u128::from(u64::MAX)) as u64
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

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
      host: egress.example.net
      port: 443
      publicKey: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
      capabilities: {tcp: true, udp: true}
      transit: {}
      trafficPolicyRef: default-policy
  - apiVersion: pathchord.io/v1
    kind: TrafficPolicy
    metadata:
      name: default-policy
    spec: {}
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
        mode: disabled
"#;

    static NEXT_FILE: AtomicUsize = AtomicUsize::new(0);

    fn config_path() -> PathBuf {
        std::env::temp_dir().join(format!(
            "pathchord-reload-{}-{}.yaml",
            std::process::id(),
            NEXT_FILE.fetch_add(1, Ordering::Relaxed)
        ))
    }

    #[test]
    fn managed_reload_waits_for_runtime_and_durable_commit() {
        let handle = ConfigReloadHandle::from_yaml(VALID, 7).unwrap();
        handle.enable_runtime_commit().unwrap();
        let changed = VALID.replace("action: reject", "action: direct");
        assert_eq!(
            handle.reload_text(&changed),
            ReloadOutcome::Pending { generation: 8 }
        );
        assert_eq!(handle.snapshot().unwrap().generation, 7);
        assert_eq!(handle.status().state, ReloadState::Pending);
        assert!(
            handle
                .commit_runtime_candidate(8, || Err(ReloadError::ControlCommit))
                .is_err()
        );
        assert_eq!(handle.snapshot().unwrap().generation, 7);
        assert!(handle.commit_runtime_candidate(8, || Ok(())).unwrap());
        assert_eq!(handle.snapshot().unwrap().generation, 8);
        assert_eq!(handle.status().state, ReloadState::Applied);
    }

    #[test]
    fn invalid_or_superseded_candidate_cannot_commit_or_reject_newer_pending() {
        let handle = ConfigReloadHandle::from_yaml(VALID, 1).unwrap();
        handle.enable_runtime_commit().unwrap();
        let changed = VALID.replace("action: reject", "action: direct");
        handle.reload_text(&changed);
        handle.reload_text("malformed: [");
        assert!(
            !handle
                .commit_runtime_candidate(2, || panic!("stale durable hook"))
                .unwrap()
        );
        assert_eq!(
            handle.reload_text(&changed),
            ReloadOutcome::Pending { generation: 4 }
        );
        handle.reject_runtime_candidate(2, "old failure").unwrap();
        assert_eq!(handle.pending_snapshot().unwrap().unwrap().generation, 4);
        assert!(
            !handle
                .commit_runtime_candidate(2, || panic!("stale durable hook"))
                .unwrap()
        );
        handle
            .reject_runtime_candidate(4, "adapter unavailable")
            .unwrap();
        assert!(handle.pending_snapshot().unwrap().is_none());
        assert_eq!(handle.status().state, ReloadState::Rejected);
        assert_eq!(handle.snapshot().unwrap().generation, 1);
    }

    #[test]
    fn rejected_candidate_retains_the_last_good_snapshot() {
        let handle = ConfigReloadHandle::from_yaml(VALID, 1).unwrap();
        let before = handle.snapshot().unwrap();
        assert_eq!(
            handle.reload_text("not: [valid"),
            ReloadOutcome::Rejected {
                active_generation: 1
            }
        );
        assert_eq!(handle.snapshot().unwrap().generation, before.generation);
        assert_eq!(handle.status().state, ReloadState::Rejected);
        let diagnostic = handle.status().diagnostic.unwrap();
        assert_eq!(diagnostic.code, "CONFIG_PARSE_ERROR");
        assert_eq!(diagnostic.field_path, "$");
    }

    #[test]
    fn invalid_inactive_dns_route_retains_snapshot_and_next_valid_reload_applies() {
        let handle = ConfigReloadHandle::from_yaml(VALID, 1).unwrap();
        for route in ["transit", "egress"] {
            let invalid = VALID.replace(
                "defaultRoute: local",
                &format!("defaultRoute: local\n      {route}: {{servers: [invalid:port]}}"),
            );
            assert_eq!(
                handle.reload_text(&invalid),
                ReloadOutcome::Rejected {
                    active_generation: 1
                }
            );
            assert_eq!(handle.snapshot().unwrap().generation, 1);
            assert_eq!(handle.status().state, ReloadState::Rejected);
        }
        let valid = VALID.replace("action: reject", "action: direct");
        assert_eq!(
            handle.reload_text(&valid),
            ReloadOutcome::Applied { generation: 2 }
        );
        assert_eq!(handle.snapshot().unwrap().generation, 2);
        assert_eq!(handle.status().state, ReloadState::Applied);
    }

    #[test]
    fn reload_preserves_namespaced_nodes_and_changes_only_the_owning_resource() {
        let input = format!(
            "{VALID}\n---\napiVersion: pathchord.io/v1\nkind: TransitProxy\nmetadata: {{name: shared, namespace: alpha}}\nspec: {{protocol: direct, tags: [alpha-old]}}\n---\napiVersion: pathchord.io/v1\nkind: TransitProxy\nmetadata: {{name: shared, namespace: beta}}\nspec: {{protocol: direct, tags: [beta-old]}}\n"
        );
        let handle = ConfigReloadHandle::from_yaml(&input, 1).unwrap();
        let changed = input.replace("alpha-old", "alpha-new");
        assert_eq!(
            handle.reload_text(&changed),
            ReloadOutcome::Applied { generation: 2 }
        );
        let snapshot = handle.snapshot().unwrap();
        let nodes = &snapshot.config.transit_proxies;
        assert_eq!(nodes.len(), 2);
        let alpha = nodes
            .iter()
            .find(|node| node.id.namespace() == "alpha")
            .unwrap();
        let beta = nodes
            .iter()
            .find(|node| node.id.namespace() == "beta")
            .unwrap();
        assert_eq!(alpha.id.resource_name(), "shared");
        assert_eq!(alpha.tags, BTreeSet::from(["alpha-new".to_owned()]));
        assert_eq!(beta.tags, BTreeSet::from(["beta-old".to_owned()]));
    }

    #[test]
    fn oversized_namespace_rejects_candidate_and_keeps_future_generated_ids_bounded() {
        let handle = ConfigReloadHandle::from_yaml(VALID, 1).unwrap();
        let namespace = "n".repeat(187);
        let invalid = format!(
            "{VALID}\n---\napiVersion: pathchord.io/v1\nkind: Subscription\nmetadata: {{name: x, namespace: {namespace}}}\nspec: {{source: {{type: clash, url: https://example.test/sub}}}}\n"
        );
        assert_eq!(
            handle.reload_text(&invalid),
            ReloadOutcome::Rejected {
                active_generation: 1
            }
        );
        assert_eq!(handle.snapshot().unwrap().generation, 1);
        assert_eq!(
            handle.status().diagnostic.unwrap().code,
            "CONFIG_RESOURCE_LIMIT"
        );
        let valid = VALID.replace("action: reject", "action: direct");
        assert_eq!(
            handle.reload_text(&valid),
            ReloadOutcome::Applied { generation: 2 }
        );
    }

    #[test]
    fn invalid_fields_produce_safe_structured_diagnostics_and_keep_last_good_snapshot() {
        let handle = ConfigReloadHandle::from_yaml(VALID, 7).unwrap();
        let invalid_key = VALID.replace(
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "sensitive-key-value",
        );
        assert!(matches!(
            handle.reload_text(&invalid_key),
            ReloadOutcome::Rejected {
                active_generation: 7
            }
        ));
        let status = handle.status();
        let diagnostic = status.diagnostic.as_ref().unwrap();
        assert_eq!(diagnostic.code, "CONFIG_INVALID_FIELD");
        assert_eq!(
            diagnostic.field_path,
            "$.resources.Egress[jp-1].spec.publicKey"
        );
        assert!(!format!("{status:?}").contains("sensitive-key-value"));
        assert_eq!(handle.snapshot().unwrap().generation, 7);

        let invalid_subscription = format!(
            "{VALID}\n---\napiVersion: pathchord.io/v1\nkind: Subscription\nmetadata: {{name: provider}}\nspec:\n  source: {{type: clash, url: 'https://user:secret-password@example.invalid/sub'}}\n"
        );
        handle.reload_text(&invalid_subscription);
        let status = handle.status();
        let diagnostic = status.diagnostic.as_ref().unwrap();
        assert_eq!(diagnostic.code, "CONFIG_INVALID_FIELD");
        assert_eq!(
            diagnostic.field_path,
            "$.resources.Subscription[provider].spec.source.url"
        );
        assert!(!format!("{status:?}").contains("secret-password"));

        handle.reload_text(VALID);
        assert!(handle.status().diagnostic.is_none());
    }

    #[test]
    fn retired_native_fields_report_the_canonical_replacement_without_values() {
        let handle = ConfigReloadHandle::from_yaml(VALID, 7).unwrap();
        let retired = VALID.replace(
            "      host: egress.example.net",
            "      address: sensitive-endpoint.example.net",
        );
        assert_eq!(
            handle.reload_text(&retired),
            ReloadOutcome::Rejected {
                active_generation: 7
            }
        );
        let status = handle.status();
        let diagnostic = status.diagnostic.as_ref().unwrap();
        assert_eq!(diagnostic.code, "CONFIG_RETIRED_FIELD");
        assert_eq!(
            diagnostic.field_path,
            "$.resources.Egress[jp-1].spec.address"
        );
        assert!(diagnostic.message.contains("spec.host"));
        assert!(!format!("{status:?}").contains("sensitive-endpoint.example.net"));
        assert_eq!(handle.snapshot().unwrap().generation, 7);
    }

    #[test]
    fn unknown_reference_and_runtime_failure_have_stable_redacted_diagnostics() {
        let handle = ConfigReloadHandle::from_yaml(VALID, 1).unwrap();
        let candidate = VALID.replace(
            "trafficPolicyRef: default-policy",
            "trafficPolicyRef: absent",
        );
        handle.reload_text(&candidate);
        let diagnostic = handle.status().diagnostic.unwrap();
        assert_eq!(diagnostic.code, "CONFIG_UNKNOWN_REFERENCE");
        assert_eq!(
            diagnostic.field_path,
            "$.resources.Egress[jp-1].spec.trafficPolicyRef"
        );

        handle.enable_runtime_commit().unwrap();
        let changed = VALID.replace("action: reject", "action: direct");
        let ReloadOutcome::Pending { generation } = handle.reload_text(&changed) else {
            panic!("expected runtime candidate");
        };
        handle
            .reject_runtime_candidate(generation, "secret token /private/path")
            .unwrap();
        let status = handle.status();
        assert_eq!(
            status.diagnostic.as_ref().unwrap().code,
            "CONFIG_RUNTIME_REJECTED"
        );
        assert!(!format!("{status:?}").contains("secret token"));
        assert!(!format!("{status:?}").contains("/private/path"));
    }

    #[test]
    fn mutable_policy_change_publishes_one_atomic_generation() {
        let handle = ConfigReloadHandle::from_yaml(VALID, 7).unwrap();
        let changed = VALID.replace("action: reject", "action: direct");
        assert_eq!(
            handle.reload_text(&changed),
            ReloadOutcome::Applied { generation: 8 }
        );
        let snapshot = handle.snapshot().unwrap();
        assert_eq!(snapshot.generation, 8);
        assert_eq!(handle.status().state, ReloadState::Applied);
        assert_eq!(
            handle.reload_text(&changed),
            ReloadOutcome::Applied { generation: 8 }
        );
        assert_eq!(handle.snapshot().unwrap().generation, 8);
    }

    #[test]
    fn moving_unchanged_resources_between_files_does_not_require_restart() {
        let base = include_str!("../../../examples/ingress-direct.yaml");
        let listener = "apiVersion: pathchord.io/v1\nkind: Listener\nmetadata: {name: another}\nspec: {type: http, bind: '127.0.0.1:7891'}\n";
        let handle = ConfigReloadHandle::from_documents([base, listener], 1).unwrap();
        assert_eq!(
            handle.reload_documents([listener, base]),
            ReloadOutcome::Applied { generation: 1 }
        );
        assert_eq!(handle.status().state, ReloadState::Applied);
    }

    #[test]
    fn startup_listener_change_requires_restart_without_publication() {
        let handle = ConfigReloadHandle::from_yaml(VALID, 3).unwrap();
        let changed = VALID.replace("127.0.0.1:8080", "127.0.0.1:8081");
        assert_eq!(
            handle.reload_text(&changed),
            ReloadOutcome::RestartRequired {
                active_generation: 3
            }
        );
        assert_eq!(handle.snapshot().unwrap().generation, 3);
        assert_eq!(handle.status().state, ReloadState::RestartRequired);
    }

    #[tokio::test]
    async fn notify_watcher_reloads_a_complete_candidate() {
        let path = config_path();
        std::fs::write(&path, VALID).unwrap();
        let reloader = ConfigHotReloader::bind(&path, 1).await.unwrap();
        let handle = reloader.handle();
        let (shutdown, shutdown_rx) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(reloader.run_until_shutdown(async move {
            let _ = shutdown_rx.await;
        }));
        std::fs::write(&path, VALID.replace("action: reject", "action: direct")).unwrap();
        for _ in 0..100 {
            if handle.snapshot().unwrap().generation == 2 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert_eq!(handle.snapshot().unwrap().generation, 2);
        shutdown.send(()).unwrap();
        task.await.unwrap().unwrap();
        std::fs::remove_file(path).unwrap();
    }

    struct Directory(PathBuf);
    impl Directory {
        fn new() -> Self {
            let path = config_path().with_extension("directory");
            std::fs::create_dir(&path).unwrap();
            Self(path)
        }
    }
    impl Drop for Directory {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    async fn wait_until(handle: &ConfigReloadHandle, generation: u64, state: ReloadState) {
        tokio::time::timeout(std::time::Duration::from_secs(4), async {
            loop {
                let status = handle.status();
                if status.active_generation == generation && status.state == state {
                    return;
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("reload status did not converge: {:?}", handle.status()));
    }

    fn proxy(name: &str, port: u16) -> String {
        format!(
            "apiVersion: pathchord.io/v1\nkind: TransitProxy\nmetadata: {{name: {name}}}\nspec: {{protocol: socks5, host: 127.0.0.1, port: {port}}}\n"
        )
    }

    fn start(
        reloader: ConfigHotReloader,
    ) -> (
        tokio::sync::oneshot::Sender<()>,
        tokio::task::JoinHandle<Result<(), ReloadError>>,
    ) {
        let (shutdown, signal) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(reloader.run_until_shutdown(async move {
            let _ = signal.await;
        }));
        (shutdown, task)
    }

    async fn stop(
        shutdown: tokio::sync::oneshot::Sender<()>,
        task: tokio::task::JoinHandle<Result<(), ReloadError>>,
    ) {
        shutdown.send(()).unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(2), task)
            .await
            .expect("bounded watcher shutdown")
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn directory_fragments_resolve_cross_file_references_and_global_duplicates() {
        let root = Directory::new();
        let base = VALID.replace(
            "trafficPolicyRef: default-policy",
            "trafficPolicyRef: traffic",
        );
        std::fs::write(root.0.join("base.yaml"), base).unwrap();
        std::fs::create_dir(root.0.join("routes")).unwrap();
        std::fs::write(
            root.0.join("routes/policy.yml"),
            r#"apiVersion: pathchord.io/v1
kind: TrafficPolicy
metadata: {name: traffic}
spec: {scheduler: effectiveCapacityWeighted}
---
"#,
        )
        .unwrap();
        std::fs::write(root.0.join("proxy.JSON"),r#"{"apiVersion":"pathchord.io/v1","kind":"TransitProxy","metadata":{"name":"relay"},"spec":{"protocol":"socks5","host":"127.0.0.1","port":1080}}"#).unwrap();
        let reloader = ConfigHotReloader::bind(root.0.clone(), 1).await.unwrap();
        let snapshot = reloader.handle().snapshot().unwrap();
        assert_eq!(
            snapshot.config.egresses[0]
                .traffic_policy
                .as_ref()
                .unwrap()
                .as_str(),
            "traffic"
        );
        assert_eq!(snapshot.config.transit_proxies[0].id.as_str(), "relay");
        std::fs::write(root.0.join("duplicate.yaml"), proxy("relay", 1081)).unwrap();
        assert!(matches!(
            ConfigHotReloader::bind(root.0.clone(), 1).await,
            Err(ReloadError::InvalidInitialConfiguration)
        ));
    }

    #[tokio::test]
    async fn directory_watcher_applies_add_update_rename_remove_and_retains_invalid_candidates() {
        let root = Directory::new();
        let base = root.0.join("base.yaml");
        std::fs::write(&base, VALID).unwrap();
        let reloader = ConfigHotReloader::bind(root.0.clone(), 1).await.unwrap();
        let handle = reloader.handle();
        let (shutdown, task) = start(reloader);
        let node = root.0.join("node.yaml");
        std::fs::write(&node, proxy("one", 1080)).unwrap();
        wait_until(&handle, 2, ReloadState::Applied).await;
        assert_eq!(handle.snapshot().unwrap().config.transit_proxies.len(), 1);
        std::fs::write(&node, proxy("one", 1081)).unwrap();
        wait_until(&handle, 3, ReloadState::Applied).await;
        assert_eq!(
            handle.snapshot().unwrap().config.transit_proxies[0]
                .endpoint
                .port,
            1081
        );
        let malformed = root.0.join("broken.json");
        std::fs::write(&malformed, "{invalid").unwrap();
        wait_until(&handle, 3, ReloadState::Rejected).await;
        assert_eq!(
            handle.snapshot().unwrap().config.transit_proxies[0]
                .endpoint
                .port,
            1081
        );
        std::fs::remove_file(&malformed).unwrap();
        wait_until(&handle, 3, ReloadState::Applied).await;
        let duplicate = root.0.join("duplicate.yml");
        std::fs::write(&duplicate, proxy("one", 1082)).unwrap();
        wait_until(&handle, 3, ReloadState::Rejected).await;
        std::fs::remove_file(&duplicate).unwrap();
        wait_until(&handle, 3, ReloadState::Applied).await;
        let nested = root.0.join("nested");
        std::fs::create_dir(&nested).unwrap();
        std::fs::rename(&node, nested.join("renamed.YAML")).unwrap();
        // Renaming preserves the same semantic bundle and generation.
        tokio::time::sleep(std::time::Duration::from_millis(120)).await;
        assert_eq!(handle.snapshot().unwrap().generation, 3);
        std::fs::write(nested.join("renamed.YAML"), proxy("renamed", 1083)).unwrap();
        wait_until(&handle, 4, ReloadState::Applied).await;
        assert_eq!(
            handle.snapshot().unwrap().config.transit_proxies[0]
                .id
                .as_str(),
            "renamed"
        );
        std::fs::remove_file(nested.join("renamed.YAML")).unwrap();
        wait_until(&handle, 5, ReloadState::Applied).await;
        assert!(handle.snapshot().unwrap().config.transit_proxies.is_empty());
        std::fs::remove_file(&base).unwrap();
        wait_until(&handle, 5, ReloadState::Rejected).await;
        assert_eq!(handle.snapshot().unwrap().config.listeners.len(), 1);
        stop(shutdown, task).await;
    }

    #[tokio::test]
    async fn file_watcher_survives_atomic_replacement_and_ignores_other_files() {
        let root = Directory::new();
        let path = root.0.join("active.yaml");
        std::fs::write(&path, VALID).unwrap();
        let reloader = ConfigHotReloader::bind(&path, 1).await.unwrap();
        let handle = reloader.handle();
        let (shutdown, task) = start(reloader);
        let temporary = root.0.join(".replacement.tmp");
        std::fs::write(
            &temporary,
            VALID.replace("action: reject", "action: direct"),
        )
        .unwrap();
        std::fs::rename(&temporary, &path).unwrap();
        wait_until(&handle, 2, ReloadState::Applied).await;
        std::fs::write(&path, VALID).unwrap();
        wait_until(&handle, 3, ReloadState::Applied).await;
        std::fs::write(root.0.join("other.yaml"), "invalid").unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        assert_eq!(handle.snapshot().unwrap().generation, 3);
        assert_eq!(handle.status().state, ReloadState::Applied);
        stop(shutdown, task).await;
    }

    #[tokio::test]
    async fn geodata_file_replacement_publishes_atomically_and_retains_last_good_data() {
        fn field(tag: u8, bytes: &[u8]) -> Vec<u8> {
            assert!(bytes.len() < 128);
            let mut out = vec![tag, bytes.len() as u8];
            out.extend_from_slice(bytes);
            out
        }
        fn database(root_domain: &str) -> Vec<u8> {
            let mut rule = vec![8, 2];
            rule.extend(field(18, root_domain.as_bytes()));
            let mut set = field(10, b"service");
            set.extend(field(18, &rule));
            field(10, &set)
        }
        fn context(host: &str) -> pathchord_policy::PolicyContext {
            pathchord_policy::PolicyContext {
                flow_tags: BTreeSet::new(),
                listener_id: pathchord_policy::ListenerId::new("test"),
                source: "127.0.0.1:12345".parse().unwrap(),
                authentication_identity: None,
                process: None,
                protocol: pathchord_policy::FlowProtocol::Tcp,
                target: pathchord_policy::TargetEndpoint {
                    host: pathchord_policy::TargetHost::Hostname(host.into()),
                    port: 443,
                },
            }
        }
        fn matched(snapshot: &ReloadSnapshot, host: &str) -> bool {
            matches!(
                snapshot
                    .compiled
                    .evaluate(&context(host), &Default::default()),
                pathchord_policy::Evaluation::Direct { .. }
            )
        }
        let root = Directory::new();
        let configs = root.0.join("config");
        let data = root.0.join("data");
        std::fs::create_dir_all(&configs).unwrap();
        std::fs::create_dir_all(&data).unwrap();
        let config = format!(
            "{VALID}\n---\napiVersion: pathchord.io/v1\nkind: GeoSiteDatabase\nmetadata: {{name: sites}}\nspec: {{path: ../data/sites.dat}}\n---\napiVersion: pathchord.io/v1\nkind: ProxyRule\nmetadata: {{name: geo}}\nspec: {{order: 10, match: {{targetGeoSites: [service]}}, proxy: direct}}\n"
        );
        std::fs::write(configs.join("bundle.yaml"), &config).unwrap();
        let db = data.join("sites.dat");
        assert!(matches!(
            ConfigHotReloader::bind(&configs, 1).await,
            Err(ReloadError::InvalidInitialGeodata { .. })
        ));
        std::fs::write(&db, database("first.test")).unwrap();
        let reloader = ConfigHotReloader::bind(&configs, 1).await.unwrap();
        let handle = reloader.handle();
        let old = handle.snapshot().unwrap();
        assert!(matched(&old, "cdn.first.test"));
        assert!(!matched(&old, "second.test"));
        let (shutdown, task) = start(reloader);
        let replacement = data.join("next.tmp");
        std::fs::write(&replacement, database("second.test")).unwrap();
        std::fs::rename(&replacement, &db).unwrap();
        wait_until(&handle, 2, ReloadState::Applied).await;
        let new = handle.snapshot().unwrap();
        assert!(matched(&new, "second.test"));
        assert!(!matched(&new, "first.test"));
        assert!(
            matched(&old, "first.test"),
            "captured generation remains immutable"
        );
        std::fs::write(&replacement, b"\xff").unwrap();
        std::fs::rename(&replacement, &db).unwrap();
        wait_until(&handle, 2, ReloadState::Rejected).await;
        assert!(matched(&handle.snapshot().unwrap(), "second.test"));
        assert_eq!(
            handle.status().diagnostic.unwrap().code,
            "CONFIG_GEODATA_INVALID"
        );
        std::fs::write(&replacement, database("third.test")).unwrap();
        std::fs::rename(&replacement, &db).unwrap();
        wait_until(&handle, 3, ReloadState::Applied).await;
        assert!(matched(&handle.snapshot().unwrap(), "third.test"));
        stop(shutdown, task).await;
    }

    #[tokio::test]
    async fn directory_replacement_rearms_recursive_watches_and_ignores_runtime_files() {
        let parent = Directory::new();
        let path = parent.0.join("active");
        std::fs::create_dir(&path).unwrap();
        std::fs::write(path.join("base.yaml"), VALID).unwrap();
        let reloader = ConfigHotReloader::bind(&path, 1).await.unwrap();
        let handle = reloader.handle();
        let (shutdown, task) = start(reloader);
        let backup = parent.0.join("previous");
        std::fs::rename(&path, &backup).unwrap();
        std::fs::create_dir(&path).unwrap();
        std::fs::write(
            path.join("base.yaml"),
            VALID.replace("action: reject", "action: direct"),
        )
        .unwrap();
        wait_until(&handle, 2, ReloadState::Applied).await;
        std::fs::write(path.join("base.yaml"), VALID).unwrap();
        wait_until(&handle, 3, ReloadState::Applied).await;
        let observed = handle.status().observed_at_ms;
        std::fs::write(path.join("runtime.db"), "state").unwrap();
        std::fs::write(path.join("debug.log"), "log").unwrap();
        std::fs::write(path.join(".editor.yaml"), "invalid").unwrap();
        std::fs::write(path.join("draft.yaml~"), "invalid").unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(120)).await;
        assert_eq!(
            handle.status().observed_at_ms,
            observed,
            "unrelated events must not reload the bundle"
        );
        stop(shutdown, task).await;
    }
}
