use std::collections::BTreeSet;
use std::future::Future;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use pathchord_policy::{CompiledPolicy, Generation, KubeConfig, PolicyConfig};
use thiserror::Error;
use tokio::sync::mpsc;

use crate::configuration_source::{ConfigurationSource, is_configuration_file};

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
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReloadOutcome {
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
    #[error("configuration reload state lock is unavailable")]
    Lock,
}

#[derive(Clone)]
pub struct ConfigReloadHandle {
    active: Arc<RwLock<ReloadSnapshot>>,
    status: Arc<RwLock<ReloadStatus>>,
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
        let snapshot = compile_candidate_documents(inputs, generation)
            .map_err(|_| ReloadError::InvalidInitialConfiguration)?;
        Ok(Self {
            active: Arc::new(RwLock::new(snapshot)),
            status: Arc::new(RwLock::new(ReloadStatus {
                state: ReloadState::Applied,
                active_generation: generation,
                observed_at_ms: now_ms(),
                reason: None,
            })),
        })
    }

    pub fn snapshot(&self) -> Result<ReloadSnapshot, ReloadError> {
        self.active
            .read()
            .map(|snapshot| snapshot.clone())
            .map_err(|_| ReloadError::Lock)
    }

    #[must_use]
    pub fn status(&self) -> ReloadStatus {
        self.status
            .read()
            .map_or_else(|_| failed_lock_status(), |status| status.clone())
    }

    pub fn reload_text(&self, input: &str) -> ReloadOutcome {
        self.reload_documents([input])
    }

    pub fn reload_documents<'a>(&self, inputs: impl IntoIterator<Item = &'a str>) -> ReloadOutcome {
        let active = match self.active.read() {
            Ok(active) => active.clone(),
            Err(_) => {
                return ReloadOutcome::Rejected {
                    active_generation: 0,
                };
            }
        };
        let Some(generation) = active.generation.checked_add(1) else {
            self.replace_status(ReloadStatus {
                state: ReloadState::Rejected,
                active_generation: active.generation,
                observed_at_ms: now_ms(),
                reason: Some("configuration generation is exhausted".to_owned()),
            });
            return ReloadOutcome::Rejected {
                active_generation: active.generation,
            };
        };
        let candidate = match compile_candidate_documents(inputs, generation) {
            Ok(candidate) => candidate,
            Err(reason) => {
                self.replace_status(ReloadStatus {
                    state: ReloadState::Rejected,
                    active_generation: active.generation,
                    observed_at_ms: now_ms(),
                    reason: Some(reason.to_owned()),
                });
                return ReloadOutcome::Rejected {
                    active_generation: active.generation,
                };
            }
        };
        if candidate.config == active.config {
            self.replace_status(ReloadStatus {
                state: ReloadState::Applied,
                active_generation: active.generation,
                observed_at_ms: now_ms(),
                reason: None,
            });
            return ReloadOutcome::Applied {
                generation: active.generation,
            };
        }
        if startup_fields_changed(&active.config, &candidate.config) {
            self.replace_status(ReloadStatus {
                state: ReloadState::RestartRequired,
                active_generation: active.generation,
                observed_at_ms: now_ms(),
                reason: Some("static Egress/key or Listener fields changed".to_owned()),
            });
            return ReloadOutcome::RestartRequired {
                active_generation: active.generation,
            };
        }
        match self.active.write() {
            Ok(mut active) => *active = candidate,
            Err(_) => {
                return ReloadOutcome::Rejected {
                    active_generation: active.generation,
                };
            }
        }
        self.replace_status(ReloadStatus {
            state: ReloadState::Applied,
            active_generation: generation,
            observed_at_ms: now_ms(),
            reason: None,
        });
        ReloadOutcome::Applied { generation }
    }

    fn replace_status(&self, next: ReloadStatus) {
        if let Ok(mut status) = self.status.write() {
            *status = next;
        }
    }
}

pub struct ConfigHotReloader {
    source: ConfigurationSource,
    directories: BTreeSet<PathBuf>,
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
        let handle = ConfigReloadHandle::from_documents(
            loaded.documents.iter().map(String::as_str),
            generation,
        )?;
        Ok(Self {
            source,
            directories: loaded.directories,
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
                            self.handle.reload_documents(loaded.documents.iter().map(String::as_str));
                        }
                        Err(_) => {
                            self.handle.replace_status(ReloadStatus {
                                state: ReloadState::Rejected,
                                active_generation: self.handle.status().active_generation,
                                observed_at_ms: now_ms(),
                                reason: Some("configuration bundle read failed".to_owned()),
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
) -> Result<ReloadSnapshot, &'static str> {
    let kube = KubeConfig::from_documents(inputs)
        .map_err(|_| "configuration parse or validation failed")?;
    let validated = kube
        .into_validated_snapshot(Generation::new(generation))
        .map_err(|_| "configuration conversion failed")?;
    let config = Arc::new(validated.config().clone());
    let compiled = Arc::new(
        validated
            .compile()
            .map_err(|_| "configuration policy compilation failed")?,
    );
    Ok(ReloadSnapshot {
        generation,
        config,
        compiled,
    })
}

fn startup_fields_changed(current: &PolicyConfig, candidate: &PolicyConfig) -> bool {
    if current.listeners != candidate.listeners
        || current.egresses != candidate.egresses
        || current.dns_policy != candidate.dns_policy
    {
        return true;
    }
    false
}

fn failed_lock_status() -> ReloadStatus {
    ReloadStatus {
        state: ReloadState::Rejected,
        active_generation: 0,
        observed_at_ms: now_ms(),
        reason: Some("reload status lock failed".to_owned()),
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
            "apiVersion: pathchord.io/v1\nkind: TransitProxy\nmetadata: {{name: {name}}}\nspec: {{protocol: socks5, address: 127.0.0.1, port: {port}}}\n"
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
        std::fs::write(root.0.join("base.yaml"), VALID).unwrap();
        std::fs::create_dir(root.0.join("routes")).unwrap();
        std::fs::write(
            root.0.join("routes/policy.yml"),
            r#"apiVersion: pathchord.io/v1
kind: TrafficPolicy
metadata: {name: traffic}
spec: {scheduler: effectiveCapacityWeighted}
---
apiVersion: pathchord.io/v1
kind: TransitRule
metadata: {name: through-japan}
spec: {order: 20, catchAll: true, egressRef: jp-1, trafficPolicyRef: traffic}
"#,
        )
        .unwrap();
        std::fs::write(root.0.join("proxy.JSON"),r#"{"apiVersion":"pathchord.io/v1","kind":"TransitProxy","metadata":{"name":"relay"},"spec":{"protocol":"socks5","address":"127.0.0.1","port":1080}}"#).unwrap();
        let reloader = ConfigHotReloader::bind(root.0.clone(), 1).await.unwrap();
        let snapshot = reloader.handle().snapshot().unwrap();
        assert_eq!(snapshot.config.transit_rules[0].egress.as_str(), "jp-1");
        assert_eq!(
            snapshot.config.transit_rules[0].traffic_policy.as_str(),
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
