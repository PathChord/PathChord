use std::future::Future;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use pathchord_policy::{CompiledPolicy, Generation, KubeConfig, PolicyConfig};
use thiserror::Error;
use tokio::sync::mpsc;

const MAX_CONFIGURATION_BYTES: u64 = 4 * 1024 * 1024;
const MAX_WATCH_EVENTS: usize = 64;

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
    #[error("configuration file I/O failed")]
    Io,
    #[error("configuration exceeds the size bound")]
    TooLarge,
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
        let snapshot = compile_candidate(input, generation)
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
        let candidate = match compile_candidate(input, generation) {
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
    path: PathBuf,
    handle: ConfigReloadHandle,
    events: mpsc::Receiver<Result<Event, notify::Error>>,
    _watcher: RecommendedWatcher,
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
        let path = path.into();
        let input = read_bounded(&path).await?;
        let handle = ConfigReloadHandle::from_yaml(&input, generation)?;
        let (sender, events) = mpsc::channel(MAX_WATCH_EVENTS);
        let mut watcher = notify::recommended_watcher(move |event| {
            let _ = sender.try_send(event);
        })
        .map_err(|_| ReloadError::Notify)?;
        watcher
            .watch(&path, RecursiveMode::NonRecursive)
            .map_err(|_| ReloadError::Notify)?;
        Ok(Self {
            path,
            handle,
            events,
            _watcher: watcher,
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
                    if !reload_event(&event, &self.path) {
                        continue;
                    }
                    match read_bounded(&self.path).await {
                        Ok(input) => {
                            self.handle.reload_text(&input);
                        }
                        Err(_) => {
                            self.handle.replace_status(ReloadStatus {
                                state: ReloadState::Rejected,
                                active_generation: self.handle.status().active_generation,
                                observed_at_ms: now_ms(),
                                reason: Some("configuration file read failed".to_owned()),
                            });
                        }
                    }
                }
            }
        }
    }
}

fn compile_candidate(input: &str, generation: u64) -> Result<ReloadSnapshot, &'static str> {
    let kube =
        KubeConfig::from_yaml(input).map_err(|_| "configuration parse or validation failed")?;
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

fn reload_event(event: &Event, path: &Path) -> bool {
    matches!(
        event.kind,
        EventKind::Create(_) | EventKind::Modify(_) | EventKind::Remove(_)
    ) && (event.paths.is_empty() || event.paths.iter().any(|candidate| candidate == path))
}

async fn read_bounded(path: &Path) -> Result<String, ReloadError> {
    let metadata = tokio::fs::metadata(path)
        .await
        .map_err(|_| ReloadError::Io)?;
    if metadata.len() > MAX_CONFIGURATION_BYTES {
        return Err(ReloadError::TooLarge);
    }
    let bytes = tokio::fs::read(path).await.map_err(|_| ReloadError::Io)?;
    if bytes.len() as u64 > MAX_CONFIGURATION_BYTES {
        return Err(ReloadError::TooLarge);
    }
    String::from_utf8(bytes).map_err(|_| ReloadError::Io)
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
}
