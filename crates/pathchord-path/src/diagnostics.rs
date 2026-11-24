//! Typed runtime observations shared by Ingress and Egress.

use std::collections::VecDeque;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiagnosticIds {
    pub egress_id: Option<String>,
    pub session_id: Option<SessionId>,
    pub path_id: Option<PathId>,
    pub stream_id: Option<StreamId>,
    /// Ingress-owned. Egress has no authoritative Transit Proxy identity.
    pub transit_proxy_id: Option<String>,
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

const HISTORY_LIMIT: usize = 1_024;
const HISTORY_AGE: Duration = Duration::from_secs(15 * 60);

pub struct DiagnosticHistory {
    role: DiagnosticRole,
    process_instance: [u8; 16],
    started_at: SystemTime,
    history: Mutex<History>,
    producer_drops: AtomicU64,
    path_terminations: [AtomicU64; PathTerminationReason::ALL.len()],
}

#[derive(Default)]
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
        let mut process_instance = [0; 16];
        getrandom::fill(&mut process_instance)?;
        Ok(Self {
            role,
            process_instance,
            started_at: SystemTime::now(),
            history: Mutex::new(History::default()),
            producer_drops: AtomicU64::new(0),
            path_terminations: Default::default(),
        })
    }

    pub fn record(&self, ids: DiagnosticIds, detail: DiagnosticDetail) {
        if let DiagnosticDetail::PathTermination { reason, .. } = &detail {
            self.path_terminations[*reason as usize].fetch_add(1, Ordering::Relaxed);
        }
        let Ok(mut history) = self.history.try_lock() else {
            self.producer_drops.fetch_add(1, Ordering::Relaxed);
            return;
        };
        let now = Instant::now();
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

    fn path_ids() -> DiagnosticIds {
        DiagnosticIds {
            egress_id: Some("egress-a".to_owned()),
            session_id: Some(SessionId::new(1)),
            path_id: Some(PathId::new(2)),
            stream_id: None,
            transit_proxy_id: None,
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
