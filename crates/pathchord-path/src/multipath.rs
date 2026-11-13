//! Transport-neutral multipath scheduling and cross-Path retransmission plans.

use std::collections::{BTreeMap, HashMap};

use pathchord_core::{
    EgressServiceState, PathId, PathState, SessionId, SessionState, StatusReport,
    StatusReportDisposition, StatusReportTracker, StreamAck, StreamData, StreamId,
};
use thiserror::Error;

const QUOTA_ZERO_WEIGHT_FLOOR_BASIS_POINTS: u128 = 1_000;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MultipathConfig {
    pub max_paths: usize,
    pub traffic_class: Option<pathchord_core::TrafficClassConfig>,
    pub session_replication_budget_bytes: u64,
    pub default_stream_replication_budget_bytes: u64,
    pub class_replication_budget_bytes: BTreeMap<String, u64>,
    pub retransmission_replication_enabled: bool,
    pub require_fresh_status_report: bool,
}

impl Default for MultipathConfig {
    fn default() -> Self {
        Self {
            max_paths: 8,
            traffic_class: None,
            session_replication_budget_bytes: 8 * 1024 * 1024,
            default_stream_replication_budget_bytes: 2 * 1024 * 1024,
            class_replication_budget_bytes: BTreeMap::new(),
            retransmission_replication_enabled: true,
            require_fresh_status_report: false,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MultipathPathObservation {
    pub effective_capacity_bps: u64,
    /// Administrative scheduling weight in basis points.
    pub weight_basis_points: u16,
    pub rtt_ms: u64,
    pub jitter_ms: u64,
    pub loss_basis_points: u16,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PathEconomicStatus {
    pub hard_available: bool,
    pub quota_remaining: Option<u64>,
    pub traffic_multiplier_basis_points: u32,
}

impl Default for PathEconomicStatus {
    fn default() -> Self {
        Self {
            hard_available: true,
            quota_remaining: None,
            traffic_multiplier_basis_points: 10_000,
        }
    }
}

impl Default for MultipathPathObservation {
    fn default() -> Self {
        Self {
            effective_capacity_bps: 1,
            weight_basis_points: 10_000,
            rtt_ms: 1,
            jitter_ms: 0,
            loss_basis_points: 0,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScheduleDirection {
    Upstream,
    Downstream,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PathSchedule {
    pub path_id: PathId,
    pub score: u128,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StreamRetransmission {
    pub path_id: PathId,
    pub data: StreamData,
    pub attempt: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PathFailureOutcome {
    pub session_closed: bool,
    pub remaining_ready_paths: usize,
    pub retransmissions: Vec<StreamRetransmission>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum MultipathError {
    #[error("multipath capacity must be non-zero")]
    ZeroCapacity,
    #[error("multipath Path limit is reached")]
    PathLimit,
    #[error("Path {0} is already registered")]
    DuplicatePath(PathId),
    #[error("Path {0} is not registered")]
    UnknownPath(PathId),
    #[error("Session is closed")]
    SessionClosed,
    #[error("no schedulable Path is available")]
    NoSchedulablePath,
    #[error("Path observation is outside its valid range")]
    InvalidObservation,
    #[error("class replication budget exceeds the Session budget")]
    InvalidReplicationBudget,
    #[error("replication budget is exhausted")]
    ReplicationBudgetExhausted,
    #[error("retained Stream range conflicts with existing bytes")]
    ConflictingRetainedRange,
    #[error("Stream offset arithmetic overflowed")]
    OffsetOverflow,
}

struct ManagedPath {
    state: PathState,
    observation: MultipathPathObservation,
    status: StatusReportTracker,
    status_elapsed_ms: u64,
    upstream_scheduled_bytes: u64,
    downstream_scheduled_bytes: u64,
    economics: PathEconomicStatus,
}

struct RetainedRange {
    data: StreamData,
    traffic_class: String,
    last_path: PathId,
    attempts: u32,
}

pub struct MultipathSession {
    session_id: SessionId,
    state: SessionState,
    config: MultipathConfig,
    paths: BTreeMap<PathId, ManagedPath>,
    retained: BTreeMap<(StreamId, u64), RetainedRange>,
    session_replication_used: u64,
    stream_replication_used: HashMap<StreamId, u64>,
    class_replication_used: HashMap<String, u64>,
}

impl std::fmt::Debug for MultipathSession {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("MultipathSession")
            .field("session_id", &self.session_id)
            .field("state", &self.state)
            .field("path_count", &self.paths.len())
            .field("retained_range_count", &self.retained.len())
            .field("session_replication_used", &self.session_replication_used)
            .finish_non_exhaustive()
    }
}

impl MultipathSession {
    pub fn new(session_id: SessionId, config: MultipathConfig) -> Result<Self, MultipathError> {
        if config.max_paths == 0
            || config.session_replication_budget_bytes == 0
            || config.default_stream_replication_budget_bytes == 0
        {
            return Err(MultipathError::ZeroCapacity);
        }
        if config
            .class_replication_budget_bytes
            .values()
            .any(|budget| *budget > config.session_replication_budget_bytes)
        {
            return Err(MultipathError::InvalidReplicationBudget);
        }
        Ok(Self {
            session_id,
            state: SessionState::Configured,
            config,
            paths: BTreeMap::new(),
            retained: BTreeMap::new(),
            session_replication_used: 0,
            stream_replication_used: HashMap::new(),
            class_replication_used: HashMap::new(),
        })
    }

    pub fn reconfigure(&mut self, config: MultipathConfig) -> Result<(), MultipathError> {
        if config.max_paths == 0
            || config.session_replication_budget_bytes == 0
            || config.default_stream_replication_budget_bytes == 0
        {
            return Err(MultipathError::ZeroCapacity);
        }
        if config
            .class_replication_budget_bytes
            .values()
            .any(|budget| *budget > config.session_replication_budget_bytes)
        {
            return Err(MultipathError::InvalidReplicationBudget);
        }
        if !config.retransmission_replication_enabled {
            self.retained.clear();
            self.session_replication_used = 0;
            self.stream_replication_used.clear();
            self.class_replication_used.clear();
        }
        self.config = config;
        Ok(())
    }

    #[must_use]
    pub const fn session_id(&self) -> SessionId {
        self.session_id
    }

    #[must_use]
    pub const fn retransmission_replication_enabled(&self) -> bool {
        self.config.retransmission_replication_enabled
    }

    #[must_use]
    pub const fn state(&self) -> SessionState {
        self.state
    }

    #[must_use]
    pub fn ready_path_count(&self) -> usize {
        self.paths
            .values()
            .filter(|path| self.path_is_schedulable(path))
            .count()
    }

    #[must_use]
    pub fn degraded_path_count(&self) -> usize {
        self.paths
            .values()
            .filter(|path| path.state == PathState::Degraded)
            .count()
    }

    #[must_use]
    pub fn effective_capacity_bps(&self) -> u64 {
        self.paths
            .values()
            .filter(|path| self.path_is_schedulable(path))
            .map(|path| {
                let weighted = u128::from(path.observation.effective_capacity_bps)
                    * u128::from(path.observation.weight_basis_points)
                    / 10_000;
                let delivered =
                    weighted * u128::from(10_000 - path.observation.loss_basis_points) / 10_000;
                let adjusted =
                    delivered * u128::from(path.economics.traffic_multiplier_basis_points) / 10_000;
                let adjusted = if path.economics.quota_remaining == Some(0) {
                    adjusted * QUOTA_ZERO_WEIGHT_FLOOR_BASIS_POINTS / 10_000
                } else {
                    adjusted
                };
                adjusted.min(u128::from(u64::MAX)) as u64
            })
            .fold(0_u64, u64::saturating_add)
    }

    #[must_use]
    pub fn ready_path_ids(&self) -> Vec<PathId> {
        self.paths
            .iter()
            .filter(|(_, path)| self.path_is_schedulable(path))
            .map(|(path_id, _)| *path_id)
            .collect()
    }

    pub fn add_path(
        &mut self,
        path_id: PathId,
        observation: MultipathPathObservation,
    ) -> Result<(), MultipathError> {
        if self.state == SessionState::Closed {
            return Err(MultipathError::SessionClosed);
        }
        validate_observation(&observation)?;
        if self.paths.len() >= self.config.max_paths {
            return Err(MultipathError::PathLimit);
        }
        if self.paths.contains_key(&path_id) {
            return Err(MultipathError::DuplicatePath(path_id));
        }
        self.paths.insert(
            path_id,
            ManagedPath {
                state: PathState::Active,
                observation,
                status: StatusReportTracker::new(),
                status_elapsed_ms: 0,
                upstream_scheduled_bytes: 0,
                downstream_scheduled_bytes: 0,
                economics: PathEconomicStatus::default(),
            },
        );
        self.state = SessionState::Active;
        Ok(())
    }

    pub fn drain_path(&mut self, path_id: PathId) -> Result<(), MultipathError> {
        let path = self
            .paths
            .get_mut(&path_id)
            .ok_or(MultipathError::UnknownPath(path_id))?;
        path.state = match path.state {
            PathState::Active | PathState::Degraded => PathState::Draining,
            state => state,
        };
        if self.ready_path_count() == 0 {
            self.state = SessionState::Draining;
        }
        Ok(())
    }

    pub fn remove_path(&mut self, path_id: PathId) -> Result<PathFailureOutcome, MultipathError> {
        if !self.paths.contains_key(&path_id) {
            return Err(MultipathError::UnknownPath(path_id));
        }
        self.paths.remove(&path_id);
        let remaining_ready_paths = self.ready_path_count();
        let session_closed = remaining_ready_paths == 0;
        let retransmissions = if session_closed {
            Vec::new()
        } else {
            self.plan_retransmissions(path_id, ScheduleDirection::Upstream)?
        };
        self.state = if session_closed {
            SessionState::Closed
        } else {
            SessionState::Degraded
        };
        Ok(PathFailureOutcome {
            session_closed,
            remaining_ready_paths,
            retransmissions,
        })
    }

    pub fn fail_path(&mut self, path_id: PathId) -> Result<PathFailureOutcome, MultipathError> {
        self.fail_path_in_direction(path_id, ScheduleDirection::Upstream)
    }

    pub fn fail_path_in_direction(
        &mut self,
        path_id: PathId,
        direction: ScheduleDirection,
    ) -> Result<PathFailureOutcome, MultipathError> {
        let mut outcome = self.mark_path_failed(path_id)?;
        if !outcome.session_closed {
            outcome.retransmissions = self.plan_retransmissions(path_id, direction)?;
        }
        Ok(outcome)
    }

    pub fn mark_path_failed(
        &mut self,
        path_id: PathId,
    ) -> Result<PathFailureOutcome, MultipathError> {
        let path = self
            .paths
            .get_mut(&path_id)
            .ok_or(MultipathError::UnknownPath(path_id))?;
        path.state = PathState::Failed;
        let remaining_ready_paths = self.ready_path_count();
        let session_closed = remaining_ready_paths == 0;
        self.state = if session_closed {
            SessionState::Closed
        } else {
            SessionState::Degraded
        };
        Ok(PathFailureOutcome {
            session_closed,
            remaining_ready_paths,
            retransmissions: Vec::new(),
        })
    }

    pub fn update_observation(
        &mut self,
        path_id: PathId,
        observation: MultipathPathObservation,
    ) -> Result<(), MultipathError> {
        validate_observation(&observation)?;
        self.paths
            .get_mut(&path_id)
            .ok_or(MultipathError::UnknownPath(path_id))?
            .observation = observation;
        Ok(())
    }

    pub fn update_economic_status(
        &mut self,
        path_id: PathId,
        status: PathEconomicStatus,
    ) -> Result<(), MultipathError> {
        if status.traffic_multiplier_basis_points == 0 {
            return Err(MultipathError::InvalidObservation);
        }
        let path = self
            .paths
            .get_mut(&path_id)
            .ok_or(MultipathError::UnknownPath(path_id))?;
        if !status.hard_available {
            path.state = PathState::Failed;
        }
        path.economics = status;
        Ok(())
    }

    pub fn degrade_path(&mut self, path_id: PathId) -> Result<(), MultipathError> {
        let path = self
            .paths
            .get_mut(&path_id)
            .ok_or(MultipathError::UnknownPath(path_id))?;
        if path.state == PathState::Active {
            path.state = PathState::Degraded;
        }
        self.state = SessionState::Degraded;
        Ok(())
    }

    pub fn activate_path(&mut self, path_id: PathId) -> Result<(), MultipathError> {
        let path = self
            .paths
            .get_mut(&path_id)
            .ok_or(MultipathError::UnknownPath(path_id))?;
        if path.state == PathState::Degraded && path.economics.hard_available {
            path.state = PathState::Active;
        }
        if self.ready_path_count() > 0 {
            self.state = SessionState::Active;
        }
        Ok(())
    }

    pub fn apply_status_report(
        &mut self,
        path_id: PathId,
        report: StatusReport,
    ) -> Result<StatusReportDisposition, MultipathError> {
        let path = self
            .paths
            .get_mut(&path_id)
            .ok_or(MultipathError::UnknownPath(path_id))?;
        let disposition = path.status.apply(report.clone());
        if disposition == StatusReportDisposition::Accepted {
            path.status_elapsed_ms = 0;
            if report.capacity_bps > 0 {
                path.observation.effective_capacity_bps = report.capacity_bps;
            }
            if matches!(path.state, PathState::Active | PathState::Degraded) {
                path.state = match report.service_state {
                    EgressServiceState::Up if report.connected => PathState::Active,
                    EgressServiceState::Draining => PathState::Draining,
                    _ => PathState::Degraded,
                };
            }
        } else if disposition == StatusReportDisposition::Expired {
            path.status_elapsed_ms = path
                .status
                .latest()
                .map_or(0, |latest| latest.expires_after_ms.saturating_add(1));
        }
        Ok(disposition)
    }

    pub fn advance_status_age(&mut self, elapsed_ms: u64) {
        for path in self.paths.values_mut() {
            path.status_elapsed_ms = path.status_elapsed_ms.saturating_add(elapsed_ms);
        }
    }

    pub fn schedule(
        &mut self,
        direction: ScheduleDirection,
        bytes: usize,
    ) -> Result<PathSchedule, MultipathError> {
        self.schedule_excluding(direction, bytes, None, None)
    }

    pub fn schedule_eligible(
        &mut self,
        direction: ScheduleDirection,
        bytes: usize,
        eligible: &BTreeMap<PathId, u32>,
    ) -> Result<PathSchedule, MultipathError> {
        self.schedule_excluding(direction, bytes, None, Some(eligible))
    }

    pub fn retain_stream_data(
        &mut self,
        data: StreamData,
        traffic_class: impl Into<String>,
        path_id: PathId,
    ) -> Result<(), MultipathError> {
        if !self.paths.contains_key(&path_id) {
            return Err(MultipathError::UnknownPath(path_id));
        }
        if !self.config.retransmission_replication_enabled {
            return Ok(());
        }
        let key = (data.stream_id, data.offset);
        if let Some(existing) = self.retained.get(&key) {
            if existing.data == data {
                return Ok(());
            }
            return Err(MultipathError::ConflictingRetainedRange);
        }
        data.offset
            .checked_add(data.data.len() as u64)
            .ok_or(MultipathError::OffsetOverflow)?;
        self.retained.insert(
            key,
            RetainedRange {
                data,
                traffic_class: traffic_class.into(),
                last_path: path_id,
                attempts: 0,
            },
        );
        Ok(())
    }

    pub fn acknowledge(&mut self, ack: &StreamAck) -> usize {
        let before = self.retained.len();
        self.retained.retain(|(stream_id, offset), retained| {
            if *stream_id != ack.stream_id || retained.data.data.is_empty() {
                return true;
            }
            let end = *offset + retained.data.data.len() as u64 - 1;
            !ack.ranges
                .iter()
                .any(|range| range.contains(*offset) && range.contains(end))
        });
        before - self.retained.len()
    }

    #[must_use]
    pub const fn replication_used(&self) -> u64 {
        self.session_replication_used
    }

    pub fn retransmit_range(
        &mut self,
        stream_id: StreamId,
        offset: u64,
        excluded_path: Option<PathId>,
        direction: ScheduleDirection,
        eligible: Option<&BTreeMap<PathId, u32>>,
    ) -> Result<StreamRetransmission, MultipathError> {
        if !self.config.retransmission_replication_enabled {
            return Err(MultipathError::ReplicationBudgetExhausted);
        }
        let key = (stream_id, offset);
        let (length, traffic_class) = {
            let retained = self
                .retained
                .get(&key)
                .ok_or(MultipathError::ConflictingRetainedRange)?;
            (
                retained.data.data.len() as u64,
                retained.traffic_class.clone(),
            )
        };
        self.consume_replication_budget(stream_id, &traffic_class, length)?;
        let schedule =
            self.schedule_excluding(direction, length as usize, excluded_path, eligible)?;
        let retained = self
            .retained
            .get_mut(&key)
            .expect("retained range was resolved above");
        retained.last_path = schedule.path_id;
        retained.attempts = retained.attempts.saturating_add(1);
        Ok(StreamRetransmission {
            path_id: schedule.path_id,
            data: retained.data.clone(),
            attempt: retained.attempts,
        })
    }

    pub fn retransmission_timeout_ms(
        &self,
        path_id: PathId,
        minimum_ms: u64,
        maximum_ms: u64,
    ) -> Result<u64, MultipathError> {
        let path = self
            .paths
            .get(&path_id)
            .ok_or(MultipathError::UnknownPath(path_id))?;
        Ok(path
            .observation
            .rtt_ms
            .saturating_add(path.observation.jitter_ms.saturating_mul(4))
            .clamp(minimum_ms, maximum_ms))
    }

    fn plan_retransmissions(
        &mut self,
        failed_path: PathId,
        direction: ScheduleDirection,
    ) -> Result<Vec<StreamRetransmission>, MultipathError> {
        let keys: Vec<_> = self
            .retained
            .iter()
            .filter(|(_, retained)| retained.last_path == failed_path)
            .map(|(key, _)| *key)
            .collect();
        let mut plans = Vec::new();
        for key in keys {
            plans.push(self.retransmit_range(key.0, key.1, Some(failed_path), direction, None)?);
        }
        Ok(plans)
    }

    fn consume_replication_budget(
        &mut self,
        stream_id: StreamId,
        traffic_class: &str,
        bytes: u64,
    ) -> Result<(), MultipathError> {
        let session_next = self
            .session_replication_used
            .checked_add(bytes)
            .ok_or(MultipathError::ReplicationBudgetExhausted)?;
        let stream_used = self
            .stream_replication_used
            .get(&stream_id)
            .copied()
            .unwrap_or(0);
        let stream_next = stream_used
            .checked_add(bytes)
            .ok_or(MultipathError::ReplicationBudgetExhausted)?;
        let class_used = self
            .class_replication_used
            .get(traffic_class)
            .copied()
            .unwrap_or(0);
        let class_next = class_used
            .checked_add(bytes)
            .ok_or(MultipathError::ReplicationBudgetExhausted)?;
        let class_budget = self
            .config
            .class_replication_budget_bytes
            .get(traffic_class)
            .copied()
            .unwrap_or(self.config.session_replication_budget_bytes);
        if session_next > self.config.session_replication_budget_bytes
            || stream_next > self.config.default_stream_replication_budget_bytes
            || class_next > class_budget
        {
            return Err(MultipathError::ReplicationBudgetExhausted);
        }
        self.session_replication_used = session_next;
        self.stream_replication_used.insert(stream_id, stream_next);
        self.class_replication_used
            .insert(traffic_class.to_owned(), class_next);
        Ok(())
    }

    fn schedule_excluding(
        &mut self,
        direction: ScheduleDirection,
        bytes: usize,
        excluded: Option<PathId>,
        eligible: Option<&BTreeMap<PathId, u32>>,
    ) -> Result<PathSchedule, MultipathError> {
        if self.state == SessionState::Closed {
            return Err(MultipathError::SessionClosed);
        }
        let mut candidates: Vec<_> = self
            .paths
            .iter()
            .filter(|(path_id, path)| {
                Some(**path_id) != excluded
                    && eligible.is_none_or(|eligible| eligible.contains_key(path_id))
                    && self.path_is_schedulable(path)
            })
            .map(|(path_id, path)| {
                let relationship_weight = eligible
                    .and_then(|eligible| eligible.get(path_id))
                    .copied()
                    .unwrap_or(100)
                    .max(1);
                let score = path_score(&path.observation, &path.economics)
                    .saturating_mul(u128::from(relationship_weight));
                let scheduled = match direction {
                    ScheduleDirection::Upstream => path.upstream_scheduled_bytes,
                    ScheduleDirection::Downstream => path.downstream_scheduled_bytes,
                };
                let normalized_load = (u128::from(scheduled) + 1) * 1_000_000 / score.max(1);
                (*path_id, score, normalized_load)
            })
            .collect();
        candidates.sort_by_key(|(path_id, _, normalized)| (*normalized, *path_id));
        let Some((path_id, score, _)) = candidates.first().copied() else {
            return Err(MultipathError::NoSchedulablePath);
        };
        let path = self
            .paths
            .get_mut(&path_id)
            .expect("scheduled Path came from the same map");
        let scheduled = match direction {
            ScheduleDirection::Upstream => &mut path.upstream_scheduled_bytes,
            ScheduleDirection::Downstream => &mut path.downstream_scheduled_bytes,
        };
        *scheduled = scheduled.saturating_add(bytes as u64);
        Ok(PathSchedule { path_id, score })
    }

    fn path_is_schedulable(&self, path: &ManagedPath) -> bool {
        if !path.state.can_admit_business() {
            return false;
        }
        if !path.economics.hard_available {
            return false;
        }
        let Some(status) = path.status.latest() else {
            return !self.config.require_fresh_status_report;
        };
        status.connected
            && matches!(
                status.service_state,
                EgressServiceState::Up | EgressServiceState::Degraded
            )
            && status.sample_age_ms.saturating_add(path.status_elapsed_ms)
                <= status.expires_after_ms
    }
}

fn validate_observation(observation: &MultipathPathObservation) -> Result<(), MultipathError> {
    if observation.effective_capacity_bps == 0
        || observation.weight_basis_points == 0
        || observation.weight_basis_points > 10_000
        || observation.loss_basis_points > 10_000
    {
        return Err(MultipathError::InvalidObservation);
    }
    Ok(())
}

fn path_score(observation: &MultipathPathObservation, economics: &PathEconomicStatus) -> u128 {
    let weighted_capacity = u128::from(observation.effective_capacity_bps)
        * u128::from(observation.weight_basis_points)
        / 10_000;
    let delivered = weighted_capacity * u128::from(10_000 - observation.loss_basis_points) / 10_000;
    let latency = u128::from(
        observation
            .rtt_ms
            .saturating_add(observation.jitter_ms)
            .saturating_add(1),
    );
    let multiplier_adjusted =
        delivered * u128::from(economics.traffic_multiplier_basis_points) / 10_000;
    let quota_adjusted = if economics.quota_remaining == Some(0) {
        multiplier_adjusted * QUOTA_ZERO_WEIGHT_FLOOR_BASIS_POINTS / 10_000
    } else {
        multiplier_adjusted
    };
    (quota_adjusted / latency).max(1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use pathchord_core::{AckRange, EgressServiceState, StreamReceiveBuffer};

    fn stream_id() -> StreamId {
        StreamId::new(1).expect("StreamID")
    }

    fn observation(capacity: u64, rtt: u64, loss: u16) -> MultipathPathObservation {
        MultipathPathObservation {
            effective_capacity_bps: capacity,
            weight_basis_points: 10_000,
            rtt_ms: rtt,
            jitter_ms: 1,
            loss_basis_points: loss,
        }
    }

    #[test]
    fn scheduler_uses_capacity_latency_loss_and_both_directions() {
        let mut session =
            MultipathSession::new(SessionId::new(1), MultipathConfig::default()).unwrap();
        session
            .add_path(PathId::new(1), observation(10_000, 100, 500))
            .unwrap();
        session
            .add_path(PathId::new(2), observation(100_000, 10, 0))
            .unwrap();
        assert_eq!(
            session
                .schedule(ScheduleDirection::Upstream, 4096)
                .unwrap()
                .path_id,
            PathId::new(2)
        );
        assert_eq!(
            session
                .schedule(ScheduleDirection::Downstream, 4096)
                .unwrap()
                .path_id,
            PathId::new(2)
        );
    }

    #[test]
    fn failed_path_retransmits_plaintext_range_on_another_path() {
        let mut session =
            MultipathSession::new(SessionId::new(1), MultipathConfig::default()).unwrap();
        session
            .add_path(PathId::new(1), observation(100_000, 10, 0))
            .unwrap();
        session
            .add_path(PathId::new(2), observation(90_000, 12, 0))
            .unwrap();
        let data = StreamData {
            stream_id: stream_id(),
            offset: 128,
            flags: 0,
            data: b"retained bytes".to_vec(),
        };
        session
            .retain_stream_data(data.clone(), "bulk", PathId::new(1))
            .unwrap();
        let outcome = session.fail_path(PathId::new(1)).unwrap();
        assert!(!outcome.session_closed);
        assert_eq!(outcome.retransmissions.len(), 1);
        assert_eq!(outcome.retransmissions[0].path_id, PathId::new(2));
        assert_eq!(outcome.retransmissions[0].data, data);
        assert_eq!(outcome.retransmissions[0].attempt, 1);
        assert!(session.replication_used() > 0);
    }

    #[test]
    fn ack_deduplicates_and_releases_retained_ranges() {
        let mut session =
            MultipathSession::new(SessionId::new(1), MultipathConfig::default()).unwrap();
        session
            .add_path(PathId::new(1), observation(1_000, 10, 0))
            .unwrap();
        let data = StreamData {
            stream_id: stream_id(),
            offset: 5,
            flags: 0,
            data: b"hello".to_vec(),
        };
        session
            .retain_stream_data(data.clone(), "default", PathId::new(1))
            .unwrap();
        session
            .retain_stream_data(data, "default", PathId::new(1))
            .unwrap();
        assert_eq!(
            session.acknowledge(&StreamAck {
                stream_id: stream_id(),
                ranges: vec![AckRange { start: 5, end: 9 }],
            }),
            1
        );
    }

    #[test]
    fn replication_budgets_are_hard_limits() {
        let mut session = MultipathSession::new(
            SessionId::new(1),
            MultipathConfig {
                session_replication_budget_bytes: 4,
                default_stream_replication_budget_bytes: 4,
                ..MultipathConfig::default()
            },
        )
        .unwrap();
        session
            .add_path(PathId::new(1), observation(1_000, 10, 0))
            .unwrap();
        session
            .add_path(PathId::new(2), observation(1_000, 10, 0))
            .unwrap();
        session
            .retain_stream_data(
                StreamData {
                    stream_id: stream_id(),
                    offset: 0,
                    flags: 0,
                    data: b"exceeds".to_vec(),
                },
                "default",
                PathId::new(1),
            )
            .unwrap();
        assert_eq!(
            session.fail_path(PathId::new(1)),
            Err(MultipathError::ReplicationBudgetExhausted)
        );
    }

    #[test]
    fn disabled_retransmission_replication_does_not_retain_ranges() {
        let mut session = MultipathSession::new(
            SessionId::new(1),
            MultipathConfig {
                retransmission_replication_enabled: false,
                ..MultipathConfig::default()
            },
        )
        .unwrap();
        session
            .add_path(PathId::new(1), observation(1_000, 10, 0))
            .unwrap();
        session
            .add_path(PathId::new(2), observation(1_000, 10, 0))
            .unwrap();
        session
            .retain_stream_data(
                StreamData {
                    stream_id: stream_id(),
                    offset: 0,
                    flags: 0,
                    data: b"no retry".to_vec(),
                },
                "default",
                PathId::new(1),
            )
            .unwrap();
        assert_eq!(session.replication_used(), 0);
        assert_eq!(
            session.fail_path(PathId::new(1)).unwrap().retransmissions,
            Vec::new()
        );
    }

    #[test]
    fn traffic_class_replication_budget_cannot_borrow_from_session_capacity() {
        let mut session = MultipathSession::new(
            SessionId::new(1),
            MultipathConfig {
                session_replication_budget_bytes: 1024,
                default_stream_replication_budget_bytes: 1024,
                class_replication_budget_bytes: BTreeMap::from([("latency".to_owned(), 4)]),
                ..MultipathConfig::default()
            },
        )
        .unwrap();
        session
            .add_path(PathId::new(1), observation(1_000, 10, 0))
            .unwrap();
        session
            .add_path(PathId::new(2), observation(1_000, 10, 0))
            .unwrap();
        session
            .retain_stream_data(
                StreamData {
                    stream_id: stream_id(),
                    offset: 0,
                    flags: 0,
                    data: b"12345".to_vec(),
                },
                "latency",
                PathId::new(1),
            )
            .unwrap();
        assert_eq!(
            session.fail_path(PathId::new(1)),
            Err(MultipathError::ReplicationBudgetExhausted)
        );
    }

    #[test]
    fn only_the_last_ready_path_closes_the_session() {
        let mut session =
            MultipathSession::new(SessionId::new(1), MultipathConfig::default()).unwrap();
        session
            .add_path(PathId::new(1), observation(1_000, 10, 0))
            .unwrap();
        session
            .add_path(PathId::new(2), observation(1_000, 10, 0))
            .unwrap();
        assert!(!session.fail_path(PathId::new(1)).unwrap().session_closed);
        assert!(session.fail_path(PathId::new(2)).unwrap().session_closed);
        assert_eq!(session.state(), SessionState::Closed);
    }

    #[test]
    fn stale_status_removes_a_path_from_admission() {
        let mut session = MultipathSession::new(
            SessionId::new(1),
            MultipathConfig {
                require_fresh_status_report: true,
                ..MultipathConfig::default()
            },
        )
        .unwrap();
        session
            .add_path(PathId::new(1), observation(1_000, 10, 0))
            .unwrap();
        let report = StatusReport {
            connected: true,
            service_state: EgressServiceState::Up,
            load_basis_points: 0,
            connection_utilization_basis_points: 0,
            bandwidth_utilization_basis_points: 0,
            active_sessions: 1,
            active_streams: 0,
            active_target_connections: 0,
            capacity_bps: 10_000,
            recommended_path_count: 1,
            report_seqno: 1,
            sample_age_ms: 0,
            expires_after_ms: 100,
        };
        assert_eq!(
            session.apply_status_report(PathId::new(1), report).unwrap(),
            StatusReportDisposition::Accepted
        );
        assert!(session.schedule(ScheduleDirection::Upstream, 1).is_ok());
        session.advance_status_age(101);
        assert_eq!(
            session.schedule(ScheduleDirection::Upstream, 1),
            Err(MultipathError::NoSchedulablePath)
        );
    }

    #[test]
    fn quota_uses_nonzero_floor_multiplier_reweights_and_hard_state_excludes() {
        let mut session =
            MultipathSession::new(SessionId::new(1), MultipathConfig::default()).unwrap();
        session
            .add_path(PathId::new(1), observation(10_000, 10, 0))
            .unwrap();
        session
            .add_path(PathId::new(2), observation(10_000, 10, 0))
            .unwrap();
        session
            .update_economic_status(
                PathId::new(2),
                PathEconomicStatus {
                    traffic_multiplier_basis_points: 50_000,
                    ..PathEconomicStatus::default()
                },
            )
            .unwrap();
        assert_eq!(
            session
                .schedule(ScheduleDirection::Upstream, 1)
                .unwrap()
                .path_id,
            PathId::new(2)
        );
        session
            .update_economic_status(
                PathId::new(1),
                PathEconomicStatus {
                    quota_remaining: Some(0),
                    ..PathEconomicStatus::default()
                },
            )
            .unwrap();
        assert_eq!(
            session
                .schedule(ScheduleDirection::Upstream, 1)
                .unwrap()
                .path_id,
            PathId::new(2)
        );
        session
            .update_economic_status(
                PathId::new(2),
                PathEconomicStatus {
                    hard_available: false,
                    ..PathEconomicStatus::default()
                },
            )
            .unwrap();
        assert_eq!(
            session
                .schedule(ScheduleDirection::Upstream, 1)
                .unwrap()
                .path_id,
            PathId::new(1)
        );
        session
            .update_economic_status(
                PathId::new(1),
                PathEconomicStatus {
                    hard_available: false,
                    quota_remaining: Some(0),
                    ..PathEconomicStatus::default()
                },
            )
            .unwrap();
        assert_eq!(
            session.schedule(ScheduleDirection::Upstream, 1),
            Err(MultipathError::NoSchedulablePath)
        );
    }

    #[test]
    fn two_x_traffic_multiplier_doubles_path_score() {
        let mut session =
            MultipathSession::new(SessionId::new(1), MultipathConfig::default()).unwrap();
        session
            .add_path(PathId::new(1), observation(100_000, 10, 0))
            .unwrap();
        let baseline = session
            .schedule(ScheduleDirection::Upstream, 1)
            .unwrap()
            .score;
        session
            .update_economic_status(
                PathId::new(1),
                PathEconomicStatus {
                    traffic_multiplier_basis_points: 20_000,
                    ..PathEconomicStatus::default()
                },
            )
            .unwrap();
        let doubled = session
            .schedule(ScheduleDirection::Upstream, 1)
            .unwrap()
            .score;
        assert_eq!(doubled, baseline * 2);
        session
            .update_economic_status(
                PathId::new(1),
                PathEconomicStatus {
                    quota_remaining: Some(0),
                    ..PathEconomicStatus::default()
                },
            )
            .unwrap();
        assert!(session.effective_capacity_bps() > 0);
    }

    #[test]
    fn per_stream_relationship_weight_controls_only_the_eligible_set() {
        let mut session =
            MultipathSession::new(SessionId::new(1), MultipathConfig::default()).unwrap();
        for path_id in [PathId::new(1), PathId::new(2), PathId::new(3)] {
            session
                .add_path(path_id, observation(10_000, 10, 0))
                .unwrap();
        }
        let eligible = BTreeMap::from([(PathId::new(1), 1), (PathId::new(2), 100)]);
        assert_eq!(
            session
                .schedule_eligible(ScheduleDirection::Upstream, 1, &eligible)
                .unwrap()
                .path_id,
            PathId::new(2)
        );
    }

    #[test]
    fn loss_duplicate_reorder_and_failure_recover_across_paths() {
        let mut session =
            MultipathSession::new(SessionId::new(1), MultipathConfig::default()).unwrap();
        session
            .add_path(PathId::new(1), observation(10_000, 10, 0))
            .unwrap();
        session
            .add_path(PathId::new(2), observation(9_000, 12, 0))
            .unwrap();
        let first = StreamData {
            stream_id: stream_id(),
            offset: 0,
            flags: 0,
            data: b"first".to_vec(),
        };
        let second = StreamData {
            stream_id: stream_id(),
            offset: 5,
            flags: 0,
            data: b"second".to_vec(),
        };
        session
            .retain_stream_data(first.clone(), "bulk", PathId::new(1))
            .unwrap();
        session
            .retain_stream_data(second.clone(), "bulk", PathId::new(1))
            .unwrap();

        let mut receiver = StreamReceiveBuffer::new(64).unwrap();
        assert!(
            receiver
                .insert(second.offset, &second.data)
                .unwrap()
                .delivered
                .is_empty()
        );
        assert!(
            receiver
                .insert(second.offset, &second.data)
                .unwrap()
                .duplicate
        );

        let retransmissions = session.fail_path(PathId::new(1)).unwrap().retransmissions;
        assert_eq!(retransmissions.len(), 2);
        assert!(
            retransmissions
                .iter()
                .all(|plan| plan.path_id == PathId::new(2))
        );
        let mut delivered = Vec::new();
        for plan in retransmissions {
            delivered.extend(
                receiver
                    .insert(plan.data.offset, &plan.data.data)
                    .unwrap()
                    .delivered,
            );
        }
        assert_eq!(delivered, b"firstsecond");
        assert_eq!(
            session.acknowledge(&StreamAck {
                stream_id: stream_id(),
                ranges: vec![AckRange { start: 0, end: 10 }],
            }),
            2
        );
    }
}
