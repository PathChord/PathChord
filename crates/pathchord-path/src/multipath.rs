//! Transport-neutral multipath scheduling and cross-Path retransmission plans.

use std::cmp::Ordering;
use std::collections::{BTreeMap, HashMap};
use std::time::Duration;

use pathchord_core::{
    EgressServiceState, LifecycleTransitionEvent, PathId, PathState, SessionId,
    SessionPathLifecycle, SessionState, StateTransitionError, StatusReport,
    StatusReportDisposition, StatusReportTracker, StreamAck, StreamData, StreamId,
};
use thiserror::Error;
use tokio::time::Instant;

const QUOTA_ZERO_WEIGHT_FLOOR_BASIS_POINTS: u128 = 1_000;
// Bound Path frame, record and authentication overhead when charging a copy.
const REPLICATION_COPY_OVERHEAD_BYTES: u64 = 128;
pub const MAX_DEMAND_KEYS: usize = 128;

pub const DEFAULT_SESSION_REPLICATION_BUDGET_BYTES_PER_SECOND: u64 = 8 * 1024 * 1024;

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct DemandKey {
    pub rule_id: String,
    pub policy_id: String,
    pub traffic_class: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MultipathConfig {
    pub max_paths: usize,
    pub traffic_class: Option<pathchord_core::TrafficClassConfig>,
    pub demand_key: Option<DemandKey>,
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
            demand_key: None,
            session_replication_budget_bytes: DEFAULT_SESSION_REPLICATION_BUDGET_BYTES_PER_SECOND,
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
    /// Optional directional measurements; absent values fall back to the
    /// aggregate capacity until that direction has evidence.
    pub upstream_effective_capacity_bps: Option<u64>,
    pub downstream_effective_capacity_bps: Option<u64>,
    /// Administrative scheduling weight in basis points.
    pub weight_basis_points: u16,
    pub rtt_ms: u64,
    pub jitter_ms: u64,
    pub loss_basis_points: u16,
    /// Measured fraction of reordered data frames; unknown until a sample exists.
    pub reordering_basis_points: Option<u16>,
    /// Available congestion window from a transport that exposes it.
    pub congestion_window_bytes: Option<u64>,
    /// Measured marginal capacity contributed by this Path.
    pub incremental_capacity_bps: Option<u64>,
    /// Measured scheduling and protocol overhead for this Path.
    pub scheduling_overhead_bps: Option<u64>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PathQualityExclusionReason {
    IncrementalCapacityBelowOverhead,
    CongestionWindowExhausted,
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
            upstream_effective_capacity_bps: None,
            downstream_effective_capacity_bps: None,
            weight_basis_points: 10_000,
            rtt_ms: 1,
            jitter_ms: 0,
            loss_basis_points: 0,
            reordering_basis_points: None,
            congestion_window_bytes: None,
            incremental_capacity_bps: None,
            scheduling_overhead_bps: None,
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
    #[error(transparent)]
    Lifecycle(#[from] StateTransitionError),
}

struct ManagedPath {
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
    stream_budget_bytes: u64,
    class_budget_bytes: u64,
    last_path: PathId,
    attempts: u32,
}

pub struct MultipathSession {
    session_id: SessionId,
    lifecycle: SessionPathLifecycle,
    config: MultipathConfig,
    paths: BTreeMap<PathId, ManagedPath>,
    retained: BTreeMap<(StreamId, u64), RetainedRange>,
    session_replication_used: u64,
    stream_replication_used: HashMap<StreamId, u64>,
    class_replication_used: HashMap<String, u64>,
    replication_window_started: Instant,
}

impl std::fmt::Debug for MultipathSession {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("MultipathSession")
            .field("session_id", &self.session_id)
            .field("state", &self.lifecycle.session_state())
            .field("path_count", &self.paths.len())
            .field("retained_range_count", &self.retained.len())
            .field("session_replication_used", &self.session_replication_used)
            .finish_non_exhaustive()
    }
}

impl MultipathSession {
    pub fn new(session_id: SessionId, config: MultipathConfig) -> Result<Self, MultipathError> {
        if config.max_paths == 0
            || (config.retransmission_replication_enabled
                && (config.session_replication_budget_bytes == 0
                    || config.default_stream_replication_budget_bytes == 0))
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
        let mut lifecycle = SessionPathLifecycle::new();
        lifecycle.transition_session(SessionState::Connecting)?;
        Ok(Self {
            session_id,
            lifecycle,
            config,
            paths: BTreeMap::new(),
            retained: BTreeMap::new(),
            session_replication_used: 0,
            stream_replication_used: HashMap::new(),
            class_replication_used: HashMap::new(),
            replication_window_started: Instant::now(),
        })
    }

    pub fn reconfigure(&mut self, config: MultipathConfig) -> Result<(), MultipathError> {
        if config.max_paths == 0
            || (config.retransmission_replication_enabled
                && (config.session_replication_budget_bytes == 0
                    || config.default_stream_replication_budget_bytes == 0))
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
    pub const fn session_replication_budget_bytes(&self) -> u64 {
        self.config.session_replication_budget_bytes
    }

    #[must_use]
    pub const fn state(&self) -> SessionState {
        self.lifecycle.session_state()
    }

    #[must_use]
    pub fn ready_path_count(&self) -> usize {
        self.lifecycle.schedulable_path_count()
    }

    #[must_use]
    pub fn degraded_path_count(&self) -> usize {
        self.paths
            .keys()
            .filter(|path_id| self.lifecycle.path_state(**path_id) == Some(PathState::Degraded))
            .count()
    }

    #[must_use]
    pub fn effective_capacity_bps(&self) -> u64 {
        self.directional_effective_capacity_bps(ScheduleDirection::Upstream)
            .max(self.directional_effective_capacity_bps(ScheduleDirection::Downstream))
    }

    #[must_use]
    pub fn directional_effective_capacity_bps(&self, direction: ScheduleDirection) -> u64 {
        self.paths
            .iter()
            .filter(|(path_id, path)| {
                self.path_is_schedulable_by_id(**path_id, path)
                    && quality_exclusion(&path.observation).is_none()
            })
            .map(|(_, path)| {
                let weighted = effective_capacity_for_direction(&path.observation, direction)
                    * u128::from(path.observation.weight_basis_points)
                    / 10_000;
                let delivered =
                    weighted * u128::from(10_000 - path.observation.loss_basis_points) / 10_000;
                let delivered = delivered
                    * u128::from(10_000 - path.observation.reordering_basis_points.unwrap_or(0))
                    / 10_000;
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
            .filter(|(path_id, path)| self.path_is_schedulable_by_id(**path_id, path))
            .map(|(path_id, _)| *path_id)
            .collect()
    }

    #[must_use]
    pub fn path_states(&self) -> BTreeMap<PathId, PathState> {
        self.lifecycle.path_states()
    }

    /// Drain lifecycle events emitted by the Session/Path owner.
    pub fn take_lifecycle_events(&mut self) -> Vec<LifecycleTransitionEvent> {
        self.lifecycle.take_events()
    }

    pub fn add_path(
        &mut self,
        path_id: PathId,
        observation: MultipathPathObservation,
    ) -> Result<(), MultipathError> {
        if self.lifecycle.session_state() == SessionState::Closed {
            return Err(MultipathError::SessionClosed);
        }
        validate_observation(&observation)?;
        if self.paths.len() >= self.config.max_paths {
            return Err(MultipathError::PathLimit);
        }
        if self.paths.contains_key(&path_id) {
            return Err(MultipathError::DuplicatePath(path_id));
        }
        self.lifecycle.register_path(path_id, PathState::Active)?;
        self.paths.insert(
            path_id,
            ManagedPath {
                observation,
                status: StatusReportTracker::new(),
                status_elapsed_ms: 0,
                upstream_scheduled_bytes: 0,
                downstream_scheduled_bytes: 0,
                economics: PathEconomicStatus::default(),
            },
        );
        self.lifecycle.transition_session(SessionState::Active)?;
        Ok(())
    }

    pub fn drain_path(&mut self, path_id: PathId) -> Result<(), MultipathError> {
        if !self.paths.contains_key(&path_id) {
            return Err(MultipathError::UnknownPath(path_id));
        }
        let state = self
            .lifecycle
            .path_state(path_id)
            .ok_or(MultipathError::UnknownPath(path_id))?;
        if matches!(state, PathState::Active | PathState::Degraded) {
            self.lifecycle
                .transition_path(path_id, PathState::Draining)?;
        }
        if self.ready_path_count() == 0 {
            self.lifecycle.transition_session(SessionState::Draining)?;
        }
        Ok(())
    }

    pub fn remove_path(&mut self, path_id: PathId) -> Result<PathFailureOutcome, MultipathError> {
        if !self.paths.contains_key(&path_id) {
            return Err(MultipathError::UnknownPath(path_id));
        }
        self.lifecycle.unregister_path(path_id)?;
        self.paths.remove(&path_id);
        let remaining_ready_paths = self.ready_path_count();
        let session_closed = remaining_ready_paths == 0;
        let retransmissions = if session_closed {
            Vec::new()
        } else {
            self.plan_retransmissions(path_id, ScheduleDirection::Upstream)?
        };
        if session_closed {
            self.lifecycle.transition_session(SessionState::Closed)?;
        } else if self.lifecycle.session_state() != SessionState::Draining {
            self.lifecycle.transition_session(SessionState::Degraded)?;
        }
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
        self.mark_path_terminal(path_id, PathState::Failed)
    }

    pub fn mark_path_closed(
        &mut self,
        path_id: PathId,
    ) -> Result<PathFailureOutcome, MultipathError> {
        self.mark_path_terminal(path_id, PathState::Closed)
    }

    fn mark_path_terminal(
        &mut self,
        path_id: PathId,
        state: PathState,
    ) -> Result<PathFailureOutcome, MultipathError> {
        if !self.paths.contains_key(&path_id) {
            return Err(MultipathError::UnknownPath(path_id));
        }
        self.transition_path_terminal(path_id, state)?;
        let remaining_ready_paths = self.ready_path_count();
        let session_closed = remaining_ready_paths == 0;
        if session_closed {
            self.lifecycle.transition_session(SessionState::Closed)?;
        } else if self.lifecycle.session_state() != SessionState::Draining {
            self.lifecycle.transition_session(SessionState::Degraded)?;
        }
        Ok(PathFailureOutcome {
            session_closed,
            remaining_ready_paths,
            retransmissions: Vec::new(),
        })
    }

    fn transition_path_terminal(
        &mut self,
        path_id: PathId,
        target: PathState,
    ) -> Result<(), MultipathError> {
        let current = self
            .lifecycle
            .path_state(path_id)
            .ok_or(MultipathError::UnknownPath(path_id))?;
        match target {
            PathState::Failed => match current {
                PathState::Active | PathState::Degraded | PathState::Probing => {
                    self.lifecycle.transition_path(path_id, PathState::Failed)?;
                }
                PathState::Draining => {
                    self.lifecycle.transition_path(path_id, PathState::Closed)?;
                }
                PathState::Failed | PathState::Closed => {}
                PathState::Discovered => {
                    self.lifecycle
                        .transition_path(path_id, PathState::Probing)?;
                    self.lifecycle.transition_path(path_id, PathState::Failed)?;
                }
            },
            PathState::Closed => match current {
                PathState::Closed => {}
                PathState::Draining | PathState::Failed => {
                    self.lifecycle.transition_path(path_id, PathState::Closed)?;
                }
                PathState::Active | PathState::Degraded => {
                    self.lifecycle
                        .transition_path(path_id, PathState::Draining)?;
                    self.lifecycle.transition_path(path_id, PathState::Closed)?;
                }
                PathState::Discovered | PathState::Probing => {
                    self.lifecycle.transition_path(path_id, PathState::Closed)?;
                }
            },
            _ => {
                self.lifecycle.transition_path(path_id, target)?;
            }
        };
        Ok(())
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

    /// Reports only quality-based exclusion; control traffic can still use a
    /// ready Path while business scheduling excludes it.
    pub fn quality_exclusion(
        &self,
        path_id: PathId,
    ) -> Result<Option<PathQualityExclusionReason>, MultipathError> {
        let path = self
            .paths
            .get(&path_id)
            .ok_or(MultipathError::UnknownPath(path_id))?;
        Ok(quality_exclusion(&path.observation))
    }

    pub fn update_economic_status(
        &mut self,
        path_id: PathId,
        status: PathEconomicStatus,
    ) -> Result<(), MultipathError> {
        if status.traffic_multiplier_basis_points == 0 {
            return Err(MultipathError::InvalidObservation);
        }
        if !status.hard_available {
            self.lifecycle.transition_path(path_id, PathState::Failed)?;
        }
        let path = self
            .paths
            .get_mut(&path_id)
            .ok_or(MultipathError::UnknownPath(path_id))?;
        path.economics = status;
        Ok(())
    }

    pub fn degrade_path(&mut self, path_id: PathId) -> Result<(), MultipathError> {
        let state = self
            .lifecycle
            .path_state(path_id)
            .ok_or(MultipathError::UnknownPath(path_id))?;
        if state == PathState::Active {
            self.lifecycle
                .transition_path(path_id, PathState::Degraded)?;
        }
        self.lifecycle.transition_session(SessionState::Degraded)?;
        Ok(())
    }

    pub fn activate_path(&mut self, path_id: PathId) -> Result<(), MultipathError> {
        let path = self
            .paths
            .get(&path_id)
            .ok_or(MultipathError::UnknownPath(path_id))?;
        let state = self
            .lifecycle
            .path_state(path_id)
            .ok_or(MultipathError::UnknownPath(path_id))?;
        if state == PathState::Degraded && path.economics.hard_available {
            self.lifecycle.transition_path(path_id, PathState::Active)?;
        } else if state == PathState::Draining {
            return Err(MultipathError::Lifecycle(
                StateTransitionError::InvalidPath {
                    from: PathState::Draining,
                    to: PathState::Active,
                },
            ));
        }
        if self.ready_path_count() > 0 {
            self.lifecycle.transition_session(SessionState::Active)?;
        }
        Ok(())
    }

    pub fn apply_status_report(
        &mut self,
        path_id: PathId,
        report: StatusReport,
    ) -> Result<StatusReportDisposition, MultipathError> {
        let disposition;
        let next_state = {
            let path = self
                .paths
                .get_mut(&path_id)
                .ok_or(MultipathError::UnknownPath(path_id))?;
            disposition = path.status.apply(report.clone());
            if disposition == StatusReportDisposition::Accepted {
                path.status_elapsed_ms = 0;
                let effective_capacity = if report.effective_capacity_bps > 0 {
                    report.effective_capacity_bps
                } else {
                    report.configured_capacity_bps
                };
                if effective_capacity > 0 {
                    path.observation.effective_capacity_bps = effective_capacity;
                }
            } else if disposition == StatusReportDisposition::Expired {
                path.status_elapsed_ms = path
                    .status
                    .latest()
                    .map_or(0, |latest| latest.expires_after_ms.saturating_add(1));
            }
            if disposition == StatusReportDisposition::Accepted {
                let current_state = self
                    .lifecycle
                    .path_state(path_id)
                    .ok_or(MultipathError::UnknownPath(path_id))?;
                matches!(current_state, PathState::Active | PathState::Degraded).then(|| {
                    match report.service_state {
                        EgressServiceState::Up if report.connected => PathState::Active,
                        EgressServiceState::Draining => PathState::Draining,
                        _ => PathState::Degraded,
                    }
                })
            } else {
                None
            }
        };
        if let Some(next_state) = next_state {
            self.lifecycle.transition_path(path_id, next_state)?;
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
        let traffic_class = traffic_class.into();
        let budget = self.config.default_stream_replication_budget_bytes;
        let class_budget = self
            .config
            .class_replication_budget_bytes
            .get(&traffic_class)
            .copied()
            .unwrap_or(budget);
        self.retain_stream_data_with_budget(data, traffic_class, path_id, budget, class_budget)
    }

    pub fn retain_stream_data_with_budget(
        &mut self,
        data: StreamData,
        traffic_class: impl Into<String>,
        path_id: PathId,
        stream_budget_bytes: u64,
        class_budget_bytes: u64,
    ) -> Result<(), MultipathError> {
        if !self.paths.contains_key(&path_id) {
            return Err(MultipathError::UnknownPath(path_id));
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
                stream_budget_bytes,
                class_budget_bytes: class_budget_bytes.min(stream_budget_bytes),
                last_path: path_id,
                attempts: 0,
            },
        );
        Ok(())
    }

    pub fn forget_retained(&mut self, stream_id: StreamId, offset: u64) {
        self.retained.remove(&(stream_id, offset));
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
        let key = (stream_id, offset);
        let length = {
            let retained = self
                .retained
                .get(&key)
                .ok_or(MultipathError::ConflictingRetainedRange)?;
            retained.data.data.len() as u64
        };
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

    /// Plans an additional copy of a retained range. This is separate from
    /// ordinary loss recovery and consumes the configured replication budget.
    pub fn replicate_range(
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
        let (data, class, attempt, stream_budget, class_budget) = {
            let retained = self
                .retained
                .get(&(stream_id, offset))
                .ok_or(MultipathError::ConflictingRetainedRange)?;
            (
                retained.data.clone(),
                retained.traffic_class.clone(),
                retained.attempts.saturating_add(1),
                retained.stream_budget_bytes,
                retained.class_budget_bytes,
            )
        };
        self.refresh_replication_window();
        let charge = (data.data.len() as u64).saturating_add(REPLICATION_COPY_OVERHEAD_BYTES);
        let (session_next, stream_next, class_next) =
            self.replication_totals(stream_id, &class, charge, stream_budget, class_budget)?;
        let schedule =
            self.schedule_excluding(direction, data.data.len(), excluded_path, eligible)?;
        self.session_replication_used = session_next;
        self.stream_replication_used.insert(stream_id, stream_next);
        self.class_replication_used.insert(class, class_next);
        Ok(StreamRetransmission {
            path_id: schedule.path_id,
            data,
            attempt,
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

    fn replication_totals(
        &self,
        stream_id: StreamId,
        traffic_class: &str,
        bytes: u64,
        stream_budget: u64,
        class_budget: u64,
    ) -> Result<(u64, u64, u64), MultipathError> {
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
        if session_next > self.config.session_replication_budget_bytes
            || stream_next > stream_budget
            || class_next > class_budget
        {
            return Err(MultipathError::ReplicationBudgetExhausted);
        }
        Ok((session_next, stream_next, class_next))
    }

    #[cfg(test)]
    fn consume_replication_budget(
        &mut self,
        stream_id: StreamId,
        class: &str,
        bytes: u64,
    ) -> Result<(), MultipathError> {
        self.refresh_replication_window();
        let stream_budget = self.config.default_stream_replication_budget_bytes;
        let class_budget = self
            .config
            .class_replication_budget_bytes
            .get(class)
            .copied()
            .unwrap_or(stream_budget);
        let (session, stream, class_used) =
            self.replication_totals(stream_id, class, bytes, stream_budget, class_budget)?;
        self.session_replication_used = session;
        self.stream_replication_used.insert(stream_id, stream);
        self.class_replication_used
            .insert(class.to_owned(), class_used);
        Ok(())
    }

    /// Charges one additional control copy to the shared Session budget.
    pub(crate) fn charge_control_replication(&mut self, bytes: u64) -> bool {
        self.refresh_replication_window();
        let Some(next) = self.session_replication_used.checked_add(bytes) else {
            return false;
        };
        if next > self.config.session_replication_budget_bytes {
            return false;
        }
        self.session_replication_used = next;
        true
    }

    fn refresh_replication_window(&mut self) {
        if self.replication_window_started.elapsed() >= Duration::from_secs(1) {
            self.replication_window_started = Instant::now();
            self.session_replication_used = 0;
            self.stream_replication_used.clear();
            self.class_replication_used.clear();
        }
    }

    fn schedule_excluding(
        &mut self,
        direction: ScheduleDirection,
        bytes: usize,
        excluded: Option<PathId>,
        eligible: Option<&BTreeMap<PathId, u32>>,
    ) -> Result<PathSchedule, MultipathError> {
        if self.lifecycle.session_state() == SessionState::Closed {
            return Err(MultipathError::SessionClosed);
        }
        let mut candidates: Vec<_> = self
            .paths
            .iter()
            .filter(|(path_id, path)| {
                Some(**path_id) != excluded
                    && eligible.is_none_or(|eligible| eligible.contains_key(path_id))
                    && self.path_is_schedulable_by_id(**path_id, path)
                    && quality_exclusion(&path.observation).is_none()
            })
            .map(|(path_id, path)| {
                // An eligible map owns the relationship weight for this flow.
                // Otherwise use the Path's default weight. Applying both would
                // square the same relationship preference.
                let weight = eligible
                    .and_then(|eligible| eligible.get(path_id))
                    .copied()
                    .unwrap_or(u32::from(path.observation.weight_basis_points))
                    .max(1);
                let score = path_score(&path.observation, &path.economics, weight, direction);
                let scheduled = match direction {
                    ScheduleDirection::Upstream => path.upstream_scheduled_bytes,
                    ScheduleDirection::Downstream => path.downstream_scheduled_bytes,
                };
                (*path_id, score, u128::from(scheduled) + 1)
            })
            .collect();
        candidates.sort_by(
            |(left_id, left_score, left_scheduled), (right_id, right_score, right_scheduled)| {
                compare_ratios(*left_scheduled, *left_score, *right_scheduled, *right_score)
                    .then_with(|| left_id.cmp(right_id))
            },
        );
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

    fn path_is_schedulable_by_id(&self, path_id: PathId, path: &ManagedPath) -> bool {
        if !self
            .lifecycle
            .path_state(path_id)
            .is_some_and(PathState::can_admit_business)
        {
            return false;
        }
        if !path.economics.hard_available {
            return false;
        }
        let Some(status) = path.status.latest() else {
            return !self.config.require_fresh_status_report;
        };
        status.connected
            && status.admission_allowed
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
        || observation
            .upstream_effective_capacity_bps
            .is_some_and(|capacity| capacity == 0)
        || observation
            .downstream_effective_capacity_bps
            .is_some_and(|capacity| capacity == 0)
        || observation.weight_basis_points == 0
        || observation.weight_basis_points > 10_000
        || observation.loss_basis_points > 10_000
        || observation
            .reordering_basis_points
            .is_some_and(|ratio| ratio > 10_000)
    {
        return Err(MultipathError::InvalidObservation);
    }
    Ok(())
}

fn path_score(
    observation: &MultipathPathObservation,
    economics: &PathEconomicStatus,
    relationship_weight: u32,
    direction: ScheduleDirection,
) -> u128 {
    let weighted_capacity =
        effective_capacity_for_direction(observation, direction) * u128::from(relationship_weight);
    let delivered = weighted_capacity * u128::from(10_000 - observation.loss_basis_points) / 10_000;
    let delivered =
        delivered * u128::from(10_000 - observation.reordering_basis_points.unwrap_or(0)) / 10_000;
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

fn effective_capacity_for_direction(
    observation: &MultipathPathObservation,
    direction: ScheduleDirection,
) -> u128 {
    let capacity = u128::from(match direction {
        ScheduleDirection::Upstream => observation
            .upstream_effective_capacity_bps
            .unwrap_or(observation.effective_capacity_bps),
        ScheduleDirection::Downstream => observation
            .downstream_effective_capacity_bps
            .unwrap_or(observation.effective_capacity_bps),
    });
    observation
        .congestion_window_bytes
        .map_or(capacity, |window| {
            // One congestion window per measured RTT is the transport's upper
            // bound. Unknown windows never acquire an invented value.
            let window_capacity =
                u128::from(window).saturating_mul(8_000) / u128::from(observation.rtt_ms.max(1));
            capacity.min(window_capacity)
        })
}

fn quality_exclusion(observation: &MultipathPathObservation) -> Option<PathQualityExclusionReason> {
    if observation.congestion_window_bytes == Some(0) {
        return Some(PathQualityExclusionReason::CongestionWindowExhausted);
    }
    if let (Some(capacity), Some(overhead)) = (
        observation.incremental_capacity_bps,
        observation.scheduling_overhead_bps,
    ) && capacity < overhead
    {
        return Some(PathQualityExclusionReason::IncrementalCapacityBelowOverhead);
    }
    None
}

/// Compare positive fractions exactly without overflow or quantizing busy
/// high-capacity Paths to the same score.
fn compare_ratios(mut a: u128, mut b: u128, mut c: u128, mut d: u128) -> Ordering {
    let mut reverse = false;
    loop {
        let (left, right) = (a / b, c / d);
        if left != right {
            return if reverse {
                right.cmp(&left)
            } else {
                left.cmp(&right)
            };
        }
        let (left_remainder, right_remainder) = (a % b, c % d);
        if left_remainder == 0 || right_remainder == 0 {
            let order = match (left_remainder == 0, right_remainder == 0) {
                (true, true) => Ordering::Equal,
                (true, false) => Ordering::Less,
                (false, true) => Ordering::Greater,
                (false, false) => unreachable!(),
            };
            return if reverse { order.reverse() } else { order };
        }
        (a, b) = (b, left_remainder);
        (c, d) = (d, right_remainder);
        reverse = !reverse;
    }
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
            ..MultipathPathObservation::default()
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
        assert_eq!(session.replication_used(), 0);
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
            session.replicate_range(
                stream_id(),
                0,
                Some(PathId::new(1)),
                ScheduleDirection::Upstream,
                None
            ),
            Err(MultipathError::ReplicationBudgetExhausted)
        );
    }

    #[test]
    fn refused_replica_does_not_consume_path_scheduling_capacity() {
        let mut session = MultipathSession::new(
            SessionId::new(1),
            MultipathConfig {
                session_replication_budget_bytes: 4,
                default_stream_replication_budget_bytes: 4,
                ..MultipathConfig::default()
            },
        )
        .unwrap();
        for id in [1, 2] {
            session
                .add_path(PathId::new(id), observation(1_000, 10, 0))
                .unwrap();
        }
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
            session.replicate_range(
                stream_id(),
                0,
                Some(PathId::new(1)),
                ScheduleDirection::Upstream,
                None
            ),
            Err(MultipathError::ReplicationBudgetExhausted)
        );
        assert_eq!(
            session
                .schedule(ScheduleDirection::Upstream, 1)
                .unwrap()
                .path_id,
            PathId::new(1)
        );
        assert_eq!(
            session
                .schedule(ScheduleDirection::Upstream, 1)
                .unwrap()
                .path_id,
            PathId::new(2)
        );
    }

    #[test]
    fn disabled_replication_still_retransmits_lost_ranges() {
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
            session.replicate_range(
                stream_id(),
                0,
                Some(PathId::new(1)),
                ScheduleDirection::Upstream,
                None
            ),
            Err(MultipathError::ReplicationBudgetExhausted)
        );
        assert_eq!(
            session
                .fail_path(PathId::new(1))
                .unwrap()
                .retransmissions
                .len(),
            1
        );
        assert_eq!(session.replication_used(), 0);
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
            session.replicate_range(
                stream_id(),
                0,
                Some(PathId::new(1)),
                ScheduleDirection::Upstream,
                None
            ),
            Err(MultipathError::ReplicationBudgetExhausted)
        );
    }

    #[test]
    fn independent_flow_replication_budgets_share_only_the_session_cap() {
        let mut session = MultipathSession::new(
            SessionId::new(1),
            MultipathConfig {
                session_replication_budget_bytes: 1_000,
                default_stream_replication_budget_bytes: 1_000,
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
        let low = StreamId::new(1).unwrap();
        let high = StreamId::new(2).unwrap();
        session
            .retain_stream_data_with_budget(
                StreamData {
                    stream_id: low,
                    offset: 0,
                    flags: 0,
                    data: vec![1; 32],
                },
                "low",
                PathId::new(1),
                200,
                200,
            )
            .unwrap();
        session
            .retain_stream_data_with_budget(
                StreamData {
                    stream_id: high,
                    offset: 0,
                    flags: 0,
                    data: vec![2; 32],
                },
                "high",
                PathId::new(1),
                600,
                600,
            )
            .unwrap();
        assert!(
            session
                .replicate_range(
                    low,
                    0,
                    Some(PathId::new(1)),
                    ScheduleDirection::Upstream,
                    None
                )
                .is_ok()
        );
        assert_eq!(
            session.replicate_range(
                low,
                0,
                Some(PathId::new(1)),
                ScheduleDirection::Upstream,
                None
            ),
            Err(MultipathError::ReplicationBudgetExhausted)
        );
        assert!(
            session
                .replicate_range(
                    high,
                    0,
                    Some(PathId::new(1)),
                    ScheduleDirection::Upstream,
                    None
                )
                .is_ok()
        );
    }

    #[tokio::test(start_paused = true)]
    async fn class_and_session_replication_budgets_are_independent_and_reset_each_second() {
        let mut session = MultipathSession::new(
            SessionId::new(1),
            MultipathConfig {
                session_replication_budget_bytes: 6,
                default_stream_replication_budget_bytes: 6,
                class_replication_budget_bytes: BTreeMap::from([
                    ("policy:a".to_owned(), 2),
                    ("policy:b".to_owned(), 2),
                    ("policy:disabled".to_owned(), 0),
                ]),
                ..MultipathConfig::default()
            },
        )
        .unwrap();
        let a = StreamId::new(1).unwrap();
        let b = StreamId::new(2).unwrap();
        let disabled = StreamId::new(3).unwrap();
        session
            .consume_replication_budget(a, "policy:a", 2)
            .unwrap();
        assert_eq!(
            session.consume_replication_budget(a, "policy:a", 1),
            Err(MultipathError::ReplicationBudgetExhausted)
        );
        session
            .consume_replication_budget(b, "policy:b", 2)
            .unwrap();
        assert_eq!(
            session.consume_replication_budget(disabled, "policy:disabled", 1),
            Err(MultipathError::ReplicationBudgetExhausted)
        );
        assert_eq!(session.replication_used(), 4);
        assert!(session.charge_control_replication(1));
        assert_eq!(
            session.consume_replication_budget(disabled, "other", 2),
            Err(MultipathError::ReplicationBudgetExhausted),
            "business traffic cannot borrow the Session budget used by control"
        );
        tokio::time::advance(Duration::from_millis(999)).await;
        assert_eq!(
            session.consume_replication_budget(a, "policy:a", 1),
            Err(MultipathError::ReplicationBudgetExhausted)
        );
        tokio::time::advance(Duration::from_millis(1)).await;
        session
            .consume_replication_budget(a, "policy:a", 2)
            .unwrap();
        assert_eq!(session.replication_used(), 2);
        session
            .consume_replication_budget(b, "policy:b", 2)
            .unwrap();
        assert_eq!(session.replication_used(), 4);
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
            admission_allowed: true,
            admission_reason: pathchord_core::AdmissionReason::None,
            load_basis_points: 0,
            connection_utilization_basis_points: 0,
            bandwidth_utilization_basis_points: 0,
            active_sessions: 1,
            active_streams: 0,
            active_target_connections: 0,
            configured_capacity_bps: 10_000,
            effective_capacity_bps: 10_000,
            current_wire_rate_bps: 0,
            replication_allowance_bps: 10_000,
            capacity_state: pathchord_core::CapacityState::Measured,
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
    fn lifecycle_owner_guards_draining_paths_and_emits_one_event_per_change() {
        let mut session =
            MultipathSession::new(SessionId::new(1), MultipathConfig::default()).unwrap();
        let path_id = PathId::new(1);
        session
            .add_path(path_id, observation(10_000, 10, 0))
            .unwrap();
        let admitted = session.take_lifecycle_events();
        assert_eq!(admitted.len(), 3);

        session.drain_path(path_id).unwrap();
        let drained = session.take_lifecycle_events();
        assert_eq!(drained.len(), 2);
        assert!(drained.iter().any(|event| {
            event.entity == pathchord_core::LifecycleEntity::Path(path_id)
                && event.to == pathchord_core::LifecycleState::Path(PathState::Draining)
        }));
        assert!(drained.iter().any(|event| {
            event.entity == pathchord_core::LifecycleEntity::Session
                && event.to == pathchord_core::LifecycleState::Session(SessionState::Draining)
        }));
        assert!(matches!(
            session.activate_path(path_id),
            Err(MultipathError::Lifecycle(
                StateTransitionError::InvalidPath {
                    from: PathState::Draining,
                    to: PathState::Active,
                }
            ))
        ));
        assert!(session.take_lifecycle_events().is_empty());
    }

    #[test]
    fn directional_capacity_keeps_upstream_and_downstream_observations_separate() {
        let mut session =
            MultipathSession::new(SessionId::new(1), MultipathConfig::default()).unwrap();
        let mut upstream = observation(1_000, 10, 0);
        upstream.upstream_effective_capacity_bps = Some(10_000);
        upstream.downstream_effective_capacity_bps = Some(1_000);
        let mut downstream = observation(1_000, 10, 0);
        downstream.upstream_effective_capacity_bps = Some(1_000);
        downstream.downstream_effective_capacity_bps = Some(10_000);
        session.add_path(PathId::new(1), upstream).unwrap();
        session.add_path(PathId::new(2), downstream).unwrap();

        assert_eq!(
            session.directional_effective_capacity_bps(ScheduleDirection::Upstream),
            11_000
        );
        assert_eq!(
            session.directional_effective_capacity_bps(ScheduleDirection::Downstream),
            11_000
        );
        assert_eq!(
            session
                .schedule(ScheduleDirection::Upstream, 1)
                .unwrap()
                .path_id,
            PathId::new(1)
        );
        assert_eq!(
            session
                .schedule(ScheduleDirection::Downstream, 1)
                .unwrap()
                .path_id,
            PathId::new(2)
        );
    }

    #[test]
    fn per_flow_relationship_weight_is_applied_once_with_large_capacity() {
        let mut session =
            MultipathSession::new(SessionId::new(1), MultipathConfig::default()).unwrap();
        let mut low = observation(1_000_000_000, 10, 0);
        low.weight_basis_points = 2_500;
        let high = observation(1_000_000_000, 10, 0);
        session.add_path(PathId::new(1), low).unwrap();
        session.add_path(PathId::new(2), high).unwrap();
        let eligible = BTreeMap::from([(PathId::new(1), 1), (PathId::new(2), 4)]);
        let mut counts = [0_usize; 2];
        for _ in 0..1_000 {
            let selected = session
                .schedule_eligible(ScheduleDirection::Upstream, 4_096, &eligible)
                .unwrap()
                .path_id;
            counts[usize::from(selected == PathId::new(2))] += 1;
        }
        assert_eq!(counts, [200, 800]);
    }

    #[test]
    fn measured_reordering_and_congestion_window_reduce_score_without_fabricating_unknowns() {
        let unknown = observation(100_000_000, 10, 0);
        let economics = PathEconomicStatus::default();
        let baseline = path_score(&unknown, &economics, 100, ScheduleDirection::Upstream);
        let mut reordered = unknown.clone();
        reordered.reordering_basis_points = Some(5_000);
        let reordered_score = path_score(&reordered, &economics, 100, ScheduleDirection::Upstream);
        assert!(reordered_score < baseline);
        let mut limited_window = unknown.clone();
        limited_window.congestion_window_bytes = Some(1_500);
        assert!(
            path_score(
                &limited_window,
                &economics,
                100,
                ScheduleDirection::Upstream
            ) < baseline
        );
        assert!(unknown.reordering_basis_points.is_none());
        assert!(unknown.congestion_window_bytes.is_none());
        reordered.reordering_basis_points = Some(10_001);
        assert_eq!(
            validate_observation(&reordered),
            Err(MultipathError::InvalidObservation)
        );
    }

    #[test]
    fn path_below_overhead_is_excluded_from_business_but_remains_ready_for_control() {
        let mut session =
            MultipathSession::new(SessionId::new(1), MultipathConfig::default()).unwrap();
        let mut inefficient = observation(10_000, 10, 0);
        inefficient.incremental_capacity_bps = Some(99);
        inefficient.scheduling_overhead_bps = Some(100);
        session
            .add_path(PathId::new(1), inefficient.clone())
            .unwrap();
        session
            .add_path(PathId::new(2), observation(10_000, 10, 0))
            .unwrap();
        assert_eq!(session.ready_path_count(), 2);
        assert_eq!(session.ready_path_ids(), [PathId::new(1), PathId::new(2)]);
        assert_eq!(
            session.quality_exclusion(PathId::new(1)),
            Ok(Some(
                PathQualityExclusionReason::IncrementalCapacityBelowOverhead
            ))
        );
        assert_eq!(session.quality_exclusion(PathId::new(2)), Ok(None));
        assert_eq!(
            session
                .schedule(ScheduleDirection::Upstream, 10)
                .unwrap()
                .path_id,
            PathId::new(2)
        );
        assert!(matches!(
            session.schedule_eligible(
                ScheduleDirection::Upstream,
                10,
                &BTreeMap::from([(PathId::new(1), 100)])
            ),
            Err(MultipathError::NoSchedulablePath)
        ));
        inefficient.incremental_capacity_bps = Some(100);
        session
            .update_observation(PathId::new(1), inefficient.clone())
            .unwrap();
        assert_eq!(session.quality_exclusion(PathId::new(1)), Ok(None));
        assert!(
            session
                .schedule_eligible(
                    ScheduleDirection::Upstream,
                    10,
                    &BTreeMap::from([(PathId::new(1), 100)])
                )
                .is_ok()
        );
        inefficient.congestion_window_bytes = Some(0);
        session
            .update_observation(PathId::new(1), inefficient)
            .unwrap();
        assert_eq!(
            session.quality_exclusion(PathId::new(1)),
            Ok(Some(PathQualityExclusionReason::CongestionWindowExhausted))
        );
    }

    #[test]
    fn fraction_comparison_stays_exact_at_large_values() {
        assert_eq!(
            compare_ratios(u128::MAX - 1, u128::MAX, u128::MAX - 2, u128::MAX),
            Ordering::Greater
        );
        assert_eq!(compare_ratios(2, 4, 1, 2), Ordering::Equal);
        assert_eq!(compare_ratios(1, 3, 1, 2), Ordering::Less);
        assert_eq!(compare_ratios(11, 10, 12, 10), Ordering::Less);
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
