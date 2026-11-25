//! Typed runtime observations shared by Ingress and Egress.

use std::collections::VecDeque;
use std::io::Write;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, SystemTime};

use pathchord_core::{PathId, PathState, SessionId, StreamId};
use tokio::time::Instant;

macro_rules! diagnostic_codes {
    ($name:ident { $($variant:ident => $code:literal),+ $(,)? }) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub enum $name { $($variant),+ }

        impl $name {
            pub const ALL: &'static [Self] = &[$(Self::$variant),+];

            pub const fn as_str(self) -> &'static str {
                match self { $(Self::$variant => $code),+ }
            }
        }
    };
}

diagnostic_codes!(DiagnosticRole { Ingress => "ingress", Egress => "egress" });
diagnostic_codes!(DiagnosticStage {
    Listener => "listener", Policy => "policy", Dns => "dns",
    Configuration => "configuration", Authorization => "authorization",
    Subscription => "subscription", Adapter => "adapter", Transit => "transit",
    PathEstablishment => "path_establishment", Session => "session", Path => "path",
    Scheduling => "scheduling", FlowControl => "flow_control", Stream => "stream",
    Target => "target", Resources => "resources", Supervision => "supervision",
});
diagnostic_codes!(DiagnosticOutcome {
    Success => "success", Failure => "failure", Timeout => "timeout",
    Cancelled => "cancelled", Skipped => "skipped",
});
diagnostic_codes!(PathTerminationReason {
    WriteTimeout => "write_timeout", WriteError => "write_error",
    ReadError => "read_error", PeerEof => "peer_eof",
    HeartbeatTimeout => "heartbeat_timeout", ProtocolError => "protocol_error",
    Drained => "drained", AdministrativeClose => "administrative_close",
    SessionClosed => "session_closed", Unknown => "unknown",
});
diagnostic_codes!(DiagnosticReason {
    Rejected => "rejected", NoRoute => "no_route", InvalidInput => "invalid_input",
    Unavailable => "unavailable", Io => "io", Timeout => "timeout",
    Authentication => "authentication", Protocol => "protocol",
    ResourceLimit => "resource_limit", Stale => "stale", WindowExhausted => "window_exhausted",
    Cancelled => "cancelled", Unknown => "unknown",
});

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PathAttribution {
    pub transit_proxy_id: Option<String>,
    pub transit_proxy_name: Option<String>,
    pub transit_subscription_id: Option<String>,
    pub transit_protocol: Option<String>,
    pub egress_endpoint_index: Option<usize>,
}

impl PathAttribution {
    pub fn fields(&self) -> serde_json::Value {
        serde_json::json!({
            "transit_proxy_id": self.transit_proxy_id,
            "transit_proxy_name": self.transit_proxy_name,
            "transit_subscription_id": self.transit_subscription_id,
            "transit_protocol": self.transit_protocol,
            "egress_endpoint_index": self.egress_endpoint_index,
        })
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DiagnosticIds {
    pub egress_id: Option<String>,
    pub session_id: Option<SessionId>,
    pub path_id: Option<PathId>,
    pub stream_id: Option<StreamId>,
    /// Ingress-owned. Egress has no authoritative Transit Proxy identity.
    pub transit_proxy_id: Option<String>,
    pub attribution: Option<PathAttribution>,
    /// Scoped to the emitting process.
    pub attempt_id: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DiagnosticCursor {
    pub process_instance: [u8; 16],
    pub sequence: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiagnosticDetail {
    PathTermination {
        state: PathState,
        reason: PathTerminationReason,
        write_elapsed_ms: Option<u64>,
        heartbeat_age_ms: Option<u64>,
    },
    SessionTermination {
        outcome: DiagnosticOutcome,
        reason: Option<DiagnosticReason>,
    },
    Stage {
        stage: DiagnosticStage,
        outcome: DiagnosticOutcome,
        reason: Option<DiagnosticReason>,
        elapsed_ms: Option<u64>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiagnosticRecord {
    pub cursor: DiagnosticCursor,
    pub role: DiagnosticRole,
    pub observed_at: SystemTime,
    pub ids: DiagnosticIds,
    pub detail: DiagnosticDetail,
}

diagnostic_codes!(DiagnosticLevel {
    Fatal => "FATAL", Error => "ERROR", Warn => "WARN", Info => "INFO",
    Debug => "DEBUG", Trace => "TRACE",
});

struct DiagnosticLog {
    level: Option<DiagnosticLevel>,
    process_instance: [u8; 16],
    sender: Option<std::sync::mpsc::SyncSender<serde_json::Value>>,
    dropped: Arc<AtomicU64>,
}

static LOG: OnceLock<DiagnosticLog> = OnceLock::new();

fn parse_log_level(value: &str) -> std::io::Result<Option<DiagnosticLevel>> {
    if value.eq_ignore_ascii_case("off") {
        return Ok(None);
    }
    DiagnosticLevel::ALL
        .iter()
        .copied()
        .find(|level| value.eq_ignore_ascii_case(level.as_str()))
        .map(Some)
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "PATHCHORD_LOG_LEVEL must be off, fatal, error, warn, info, debug, or trace",
            )
        })
}

fn log_record(
    level: DiagnosticLevel,
    role: DiagnosticRole,
    process_instance: Option<[u8; 16]>,
    event: &'static str,
    fields: serde_json::Value,
) -> serde_json::Value {
    serde_json::json!({
        "level": level.as_str(),
        "event": event,
        "role": role.as_str(),
        "process_instance": process_instance.map(|id| format!("{:032x}", u128::from_be_bytes(id))),
        "observed_at_unix_ms": unix_ms(SystemTime::now()),
        "fields": fields,
    })
}

/// Lifecycle records use the same threshold and schema as runtime records.
/// Write them directly so the record can be delivered before process exit.
pub fn log_service_event(
    role: DiagnosticRole,
    level: DiagnosticLevel,
    event: &'static str,
    reason: Option<&'static str>,
) {
    let enabled = LOG.get().map_or(level == DiagnosticLevel::Fatal, |log| {
        log.level.is_some_and(|threshold| threshold >= level)
    });
    if enabled {
        let record = log_record(
            level,
            role,
            LOG.get().map(|log| log.process_instance),
            event,
            serde_json::json!({"reason":reason}),
        );
        let _ = writeln!(std::io::stderr().lock(), "{record}");
    }
}

/// Initialize the service stderr sink before starting runtime tasks.
pub fn configure_diagnostic_logging(role: DiagnosticRole) -> std::io::Result<()> {
    if LOG.get().is_some() {
        return Ok(());
    }
    let level = match std::env::var("PATHCHORD_LOG_LEVEL") {
        Err(std::env::VarError::NotPresent) => Some(DiagnosticLevel::Info),
        Ok(value) => parse_log_level(&value)?,
        Err(_) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "PATHCHORD_LOG_LEVEL must be valid UTF-8",
            ));
        }
    };
    let mut process_instance = [0; 16];
    getrandom::fill(&mut process_instance).map_err(std::io::Error::other)?;
    let dropped = Arc::new(AtomicU64::new(0));
    let sender = if level.is_some() {
        let (sender, receiver) = std::sync::mpsc::sync_channel::<serde_json::Value>(4096);
        let loss = Arc::clone(&dropped);
        std::thread::Builder::new()
            .name("pathchord-diagnostics".into())
            .spawn(move || {
                let mut reported = 0;
                loop {
                    let total = loss.load(Ordering::Relaxed);
                    if total != reported
                        && level.is_some_and(|threshold| threshold >= DiagnosticLevel::Warn)
                    {
                        let notice = log_record(
                            DiagnosticLevel::Warn,
                            role,
                            Some(process_instance),
                            "diagnostic_log_loss",
                            serde_json::json!({"dropped_total":total}),
                        );
                        if writeln!(std::io::stderr().lock(), "{notice}").is_err() {
                            loss.fetch_add(
                                receiver.try_iter().take(4096).count() as u64,
                                Ordering::Relaxed,
                            );
                            break;
                        }
                        reported = total;
                    }
                    match receiver.recv_timeout(Duration::from_secs(1)) {
                        Ok(event) => {
                            if writeln!(std::io::stderr().lock(), "{event}").is_err() {
                                loss.fetch_add(
                                    1 + receiver.try_iter().take(4096).count() as u64,
                                    Ordering::Relaxed,
                                );
                                break;
                            }
                        }
                        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
                        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
                    }
                }
            })?;
        Some(sender)
    } else {
        None
    };
    let _ = LOG.set(DiagnosticLog {
        level,
        process_instance,
        sender,
        dropped,
    });
    Ok(())
}

const HISTORY_LIMIT: usize = 1_024;
const HISTORY_AGE: Duration = Duration::from_secs(15 * 60);

#[derive(Debug)]
pub struct DiagnosticHistory {
    role: DiagnosticRole,
    process_instance: [u8; 16],
    started_at: SystemTime,
    history: Mutex<History>,
    producer_drops: AtomicU64,
    path_terminations: [AtomicU64; PathTerminationReason::ALL.len()],
    capture: Mutex<CaptureState>,
}

#[derive(Debug, Default)]
struct CaptureState {
    active: bool,
    expires_at: Option<Instant>,
    records: VecDeque<DiagnosticRecord>,
    dropped: u64,
    max_records: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaptureStatus {
    pub active: bool,
    pub expires_at_unix_ms: Option<u64>,
    pub records: Vec<DiagnosticRecord>,
    pub dropped: u64,
}

#[derive(Debug, Default)]
struct History {
    next_sequence: u64,
    records: VecDeque<(Instant, DiagnosticRecord)>,
    expired: u64,
    evicted: u64,
}

#[derive(Debug, Clone)]
pub struct DiagnosticSnapshot {
    pub process_instance: [u8; 16],
    pub started_at: SystemTime,
    pub records: Vec<DiagnosticRecord>,
    pub expired: u64,
    pub evicted: u64,
    pub producer_drops: u64,
    pub path_terminations: Vec<(PathTerminationReason, u64)>,
}

impl DiagnosticSnapshot {
    /// Compact structured summary for the existing role-local status operation.
    pub fn path_summary(&self) -> serde_json::Value {
        let last_path_termination = self.records.iter().rev().find_map(|record| {
            let DiagnosticDetail::PathTermination {
                state,
                reason,
                write_elapsed_ms,
                heartbeat_age_ms,
            } = record.detail
            else {
                return None;
            };
            Some(serde_json::json!({
                "sequence": record.cursor.sequence,
                "observed_at_unix_ms": unix_ms(record.observed_at),
                "role": record.role.as_str(),
                "egress_id": record.ids.egress_id,
                "session_id": record.ids.session_id.map(|id| id.to_string()),
                "path_id": record.ids.path_id.map(|id| id.to_string()),
                "transit_proxy_id": record.ids.transit_proxy_id,
                "transit": record.ids.attribution.as_ref().map(PathAttribution::fields),
                "state": if state == PathState::Closed { "closed" } else { "failed" },
                "reason": reason.as_str(),
                "write_elapsed_ms": write_elapsed_ms,
                "heartbeat_age_ms": heartbeat_age_ms,
            }))
        });
        let counters: serde_json::Map<_, _> = self
            .path_terminations
            .iter()
            .map(|(reason, count)| (reason.as_str().to_owned(), (*count).into()))
            .collect();
        serde_json::json!({
            "process_instance": format!("{:032x}", u128::from_be_bytes(self.process_instance)),
            "started_at_unix_ms": unix_ms(self.started_at),
            "last_path_termination": last_path_termination,
            "path_terminations": counters,
            "expired": self.expired,
            "evicted": self.evicted,
            "producer_drops": self.producer_drops,
            "log_drops": LOG.get().map(|log| log.dropped.load(Ordering::Relaxed)),
            "records": self.records.iter().map(|record| serde_json::json!({
                "sequence": record.cursor.sequence,
                "observed_at_unix_ms": unix_ms(record.observed_at),
                "role": record.role.as_str(),
                "ids": {
                    "egress_id": record.ids.egress_id,
                    "session_id": record.ids.session_id.map(|id| id.to_string()),
                    "path_id": record.ids.path_id.map(|id| id.to_string()),
                    "stream_id": record.ids.stream_id.map(|id| id.to_string()),
                    "transit_proxy_id": record.ids.transit_proxy_id,
                    "transit": record.ids.attribution.as_ref().map(PathAttribution::fields),
                    "attempt_id": record.ids.attempt_id,
                },
                "detail": format!("{:?}", record.detail),
            })).collect::<Vec<_>>(),
        })
    }
}

fn unix_ms(time: SystemTime) -> Option<u64> {
    time.duration_since(SystemTime::UNIX_EPOCH)
        .ok()
        .and_then(|elapsed| elapsed.as_millis().try_into().ok())
}

impl History {
    fn expire(&mut self, now: Instant) {
        while self
            .records
            .front()
            .is_some_and(|(inserted, _)| now.saturating_duration_since(*inserted) >= HISTORY_AGE)
        {
            self.records.pop_front();
            self.expired = self.expired.saturating_add(1);
        }
    }
}

impl DiagnosticHistory {
    pub fn new(role: DiagnosticRole) -> Result<Self, getrandom::Error> {
        let process_instance = if let Some(log) = LOG.get() {
            log.process_instance
        } else {
            let mut id = [0; 16];
            getrandom::fill(&mut id)?;
            id
        };
        Ok(Self {
            role,
            process_instance,
            started_at: SystemTime::now(),
            history: Mutex::new(History::default()),
            producer_drops: AtomicU64::new(0),
            path_terminations: Default::default(),
            capture: Mutex::new(CaptureState::default()),
        })
    }

    pub fn log(
        &self,
        level: DiagnosticLevel,
        event: &'static str,
        fields: impl FnOnce() -> serde_json::Value,
    ) {
        let Some(log) = LOG
            .get()
            .filter(|log| log.level.is_some_and(|threshold| threshold >= level))
        else {
            return;
        };
        let Some(sender) = &log.sender else { return };
        let value = log_record(
            level,
            self.role,
            Some(self.process_instance),
            event,
            fields(),
        );
        if sender.try_send(value).is_err() {
            log.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn record_stage(
        &self,
        ids: DiagnosticIds,
        stage: DiagnosticStage,
        outcome: DiagnosticOutcome,
        reason: Option<DiagnosticReason>,
        elapsed_ms: Option<u64>,
    ) {
        self.record(
            ids,
            DiagnosticDetail::Stage {
                stage,
                outcome,
                reason,
                elapsed_ms,
            },
        );
    }

    pub fn start_capture(&self, duration: Duration, max_records: usize) -> bool {
        let Ok(mut capture) = self.capture.lock() else {
            return false;
        };
        if capture.active {
            return false;
        }
        capture.active = true;
        capture.expires_at = Instant::now().checked_add(duration);
        capture.records.clear();
        capture.dropped = 0;
        capture.max_records = max_records.max(1);
        true
    }

    pub fn stop_capture(&self) -> CaptureStatus {
        let mut capture = self
            .capture
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        capture.active = false;
        CaptureStatus {
            active: false,
            expires_at_unix_ms: None,
            records: capture.records.iter().cloned().collect(),
            dropped: capture.dropped,
        }
    }

    pub fn capture_status(&self) -> CaptureStatus {
        let mut capture = self
            .capture
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if capture.active
            && capture
                .expires_at
                .is_some_and(|expires| Instant::now() >= expires)
        {
            capture.active = false;
        }
        CaptureStatus {
            active: capture.active,
            expires_at_unix_ms: capture
                .expires_at
                .map(|_| unix_ms(SystemTime::now()).unwrap_or(0)),
            records: capture.records.iter().cloned().collect(),
            dropped: capture.dropped,
        }
    }

    pub fn record(&self, ids: DiagnosticIds, detail: DiagnosticDetail) {
        let level = match &detail {
            DiagnosticDetail::PathTermination {
                reason:
                    PathTerminationReason::Drained
                    | PathTerminationReason::AdministrativeClose
                    | PathTerminationReason::SessionClosed,
                ..
            } => DiagnosticLevel::Info,
            DiagnosticDetail::PathTermination { .. } => DiagnosticLevel::Warn,
            DiagnosticDetail::SessionTermination {
                outcome: DiagnosticOutcome::Failure,
                ..
            } => DiagnosticLevel::Error,
            DiagnosticDetail::SessionTermination { .. } => DiagnosticLevel::Info,
            DiagnosticDetail::Stage {
                outcome: DiagnosticOutcome::Failure | DiagnosticOutcome::Timeout,
                ..
            } => DiagnosticLevel::Warn,
            DiagnosticDetail::Stage { .. } => DiagnosticLevel::Debug,
        };
        self.log(level, "runtime_diagnostic", || {
            serde_json::json!({
                "egress_id": ids.egress_id,
                "session_id": ids.session_id.map(|id| id.to_string()),
                "path_id": ids.path_id.map(|id| id.to_string()),
                "stream_id": ids.stream_id.map(|id| id.to_string()),
                "transit_proxy_id": ids.transit_proxy_id,
                "transit": ids.attribution.as_ref().map(PathAttribution::fields),
                "detail": format!("{detail:?}"),
            })
        });
        if let DiagnosticDetail::PathTermination { reason, .. } = &detail {
            self.path_terminations[*reason as usize].fetch_add(1, Ordering::Relaxed);
        }
        let Ok(mut history) = self.history.try_lock() else {
            self.producer_drops.fetch_add(1, Ordering::Relaxed);
            return;
        };
        let now = Instant::now();
        if let Ok(mut capture) = self.capture.lock() {
            if capture.active && capture.expires_at.is_some_and(|expires| now >= expires) {
                capture.active = false;
            }
            if capture.active {
                let record = DiagnosticRecord {
                    cursor: DiagnosticCursor {
                        process_instance: self.process_instance,
                        sequence: history.next_sequence.saturating_add(1),
                    },
                    role: self.role,
                    observed_at: SystemTime::now(),
                    ids: ids.clone(),
                    detail: detail.clone(),
                };
                if capture.records.len() >= capture.max_records {
                    capture.dropped = capture.dropped.saturating_add(1);
                } else {
                    capture.records.push_back(record);
                }
            }
        }
        history.expire(now);
        if history.records.len() == HISTORY_LIMIT {
            history.records.pop_front();
            history.evicted = history.evicted.saturating_add(1);
        }
        history.next_sequence += 1;
        let sequence = history.next_sequence;
        history.records.push_back((
            now,
            DiagnosticRecord {
                cursor: DiagnosticCursor {
                    process_instance: self.process_instance,
                    sequence,
                },
                role: self.role,
                observed_at: SystemTime::now(),
                ids,
                detail,
            },
        ));
    }

    pub fn snapshot(&self) -> DiagnosticSnapshot {
        let mut history = self
            .history
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        history.expire(Instant::now());
        DiagnosticSnapshot {
            process_instance: self.process_instance,
            started_at: self.started_at,
            records: history
                .records
                .iter()
                .map(|(_, record)| record.clone())
                .collect(),
            expired: history.expired,
            evicted: history.evicted,
            producer_drops: self.producer_drops.load(Ordering::Relaxed),
            path_terminations: PathTerminationReason::ALL
                .iter()
                .copied()
                .map(|reason| {
                    (
                        reason,
                        self.path_terminations[reason as usize].load(Ordering::Relaxed),
                    )
                })
                .collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn log_levels_are_case_insensitive_and_ordered_by_verbosity() {
        let expected = [
            DiagnosticLevel::Fatal,
            DiagnosticLevel::Error,
            DiagnosticLevel::Warn,
            DiagnosticLevel::Info,
            DiagnosticLevel::Debug,
            DiagnosticLevel::Trace,
        ];
        for (index, level) in expected.iter().enumerate() {
            let threshold = parse_log_level(&level.as_str().to_ascii_lowercase())
                .unwrap()
                .unwrap();
            assert_eq!(threshold, *level);
            assert_eq!(
                expected.iter().filter(|event| **event <= threshold).count(),
                index + 1
            );
        }
        assert_eq!(parse_log_level("Off").unwrap(), None);
        assert!(parse_log_level("invalid").is_err());
    }

    fn path_ids() -> DiagnosticIds {
        DiagnosticIds {
            egress_id: Some("egress-a".to_owned()),
            session_id: Some(SessionId::new(1)),
            path_id: Some(PathId::new(2)),
            stream_id: None,
            transit_proxy_id: None,
            attribution: None,
            attempt_id: None,
        }
    }

    fn termination(reason: PathTerminationReason) -> DiagnosticDetail {
        DiagnosticDetail::PathTermination {
            state: PathState::Failed,
            reason,
            write_elapsed_ms: None,
            heartbeat_age_ms: None,
        }
    }

    #[tokio::test(start_paused = true)]
    async fn expiry_eviction_and_contention_preserve_termination_counts() {
        let history = DiagnosticHistory::new(DiagnosticRole::Ingress).unwrap();
        for _ in 0..=HISTORY_LIMIT {
            history.record(path_ids(), termination(PathTerminationReason::WriteTimeout));
        }
        assert_eq!(history.snapshot().evicted, 1);
        {
            let _reader = history.history.lock().unwrap();
            history.record(path_ids(), termination(PathTerminationReason::WriteTimeout));
        }
        let retained = history.snapshot();
        assert_eq!(retained.records.len(), HISTORY_LIMIT);
        assert_eq!(retained.producer_drops, 1);
        tokio::time::advance(HISTORY_AGE).await;
        let expired = history.snapshot();
        assert!(expired.records.is_empty());
        assert_eq!(expired.expired, HISTORY_LIMIT as u64);
        assert_eq!(expired.path_terminations[0].1, HISTORY_LIMIT as u64 + 2);
    }

    #[tokio::test(start_paused = true)]
    async fn bounded_capture_expires_and_reports_drops() {
        let history = DiagnosticHistory::new(DiagnosticRole::Ingress).unwrap();
        assert!(history.start_capture(Duration::from_secs(2), 1));
        let ids = path_ids();
        history.record_stage(
            ids.clone(),
            DiagnosticStage::Scheduling,
            DiagnosticOutcome::Success,
            None,
            Some(1),
        );
        history.record_stage(
            ids,
            DiagnosticStage::FlowControl,
            DiagnosticOutcome::Timeout,
            Some(DiagnosticReason::WindowExhausted),
            Some(2),
        );
        let active = history.capture_status();
        assert!(active.active);
        assert_eq!(active.records.len(), 1);
        assert_eq!(active.dropped, 1);
        tokio::time::advance(Duration::from_secs(2)).await;
        assert!(!history.capture_status().active);
        assert_eq!(history.stop_capture().records.len(), 1);
    }

    #[test]
    fn stage_records_distinguish_flow_control_and_write_timeout() {
        let history = DiagnosticHistory::new(DiagnosticRole::Ingress).unwrap();
        let ids = path_ids();
        history.record_stage(
            ids.clone(),
            DiagnosticStage::FlowControl,
            DiagnosticOutcome::Timeout,
            Some(DiagnosticReason::WindowExhausted),
            Some(100),
        );
        history.record(
            ids,
            DiagnosticDetail::PathTermination {
                state: PathState::Failed,
                reason: PathTerminationReason::WriteTimeout,
                write_elapsed_ms: Some(1000),
                heartbeat_age_ms: Some(3000),
            },
        );
        let snapshot = history.snapshot();
        assert_eq!(snapshot.records.len(), 2);
        assert!(matches!(
            snapshot.records[0].detail,
            DiagnosticDetail::Stage {
                stage: DiagnosticStage::FlowControl,
                reason: Some(DiagnosticReason::WindowExhausted),
                ..
            }
        ));
        assert!(matches!(
            snapshot.records[1].detail,
            DiagnosticDetail::PathTermination {
                reason: PathTerminationReason::WriteTimeout,
                ..
            }
        ));
        assert_ne!(snapshot.process_instance, [0; 16]);
    }

    #[test]
    fn shared_ids_correlate_independent_role_timelines() {
        let ingress = DiagnosticHistory::new(DiagnosticRole::Ingress).unwrap();
        let egress = DiagnosticHistory::new(DiagnosticRole::Egress).unwrap();
        ingress.record(path_ids(), termination(PathTerminationReason::PeerEof));
        egress.record(path_ids(), termination(PathTerminationReason::WriteTimeout));
        let left = ingress.snapshot().records.pop().unwrap();
        let right = egress.snapshot().records.pop().unwrap();
        assert_eq!(left.ids.session_id, right.ids.session_id);
        assert_eq!(left.ids.path_id, right.ids.path_id);
        assert_ne!(left.cursor, right.cursor);
        assert_ne!(left.role, right.role);
        assert_ne!(left.detail, right.detail);
        assert_eq!(
            PathTerminationReason::WriteTimeout.as_str(),
            "write_timeout"
        );
        assert!(left.ids.transit_proxy_id.is_none());
    }
}
