use std::collections::{BTreeMap, VecDeque};
use std::error::Error;
use std::fmt;

use crate::PathId;

/// Lifecycle of one authenticated physical Path.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum PathState {
    Discovered,
    Probing,
    Active,
    Degraded,
    Draining,
    Failed,
    Closed,
}

impl PathState {
    pub fn transition(self, next: Self) -> Result<Self, StateTransitionError> {
        let valid = self == next
            || matches!(
                (self, next),
                (Self::Discovered, Self::Probing)
                    | (Self::Probing, Self::Active | Self::Failed)
                    | (Self::Active, Self::Degraded | Self::Draining | Self::Failed)
                    | (Self::Degraded, Self::Active | Self::Draining | Self::Failed)
                    | (Self::Draining | Self::Failed, Self::Closed)
            );
        if valid {
            Ok(next)
        } else {
            Err(StateTransitionError::InvalidPath {
                from: self,
                to: next,
            })
        }
    }

    /// Only a `PATH_READY` Path may admit newly scheduled business traffic.
    pub const fn can_admit_business(self) -> bool {
        matches!(self, Self::Active | Self::Degraded)
    }

    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Closed)
    }
}

/// Lifecycle of one live Ingress-to-Egress Session.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum SessionState {
    Configured,
    Connecting,
    Active,
    Degraded,
    Draining,
    Closed,
}

impl SessionState {
    pub fn transition(self, next: Self, ready_paths: usize) -> Result<Self, StateTransitionError> {
        let valid = self == next
            || matches!(
                (self, next),
                (Self::Configured, Self::Connecting | Self::Closed)
                    | (Self::Connecting, Self::Active | Self::Closed)
                    | (Self::Active, Self::Degraded | Self::Draining | Self::Closed)
                    | (Self::Degraded, Self::Active | Self::Draining | Self::Closed)
                    | (Self::Draining, Self::Closed)
            );
        if !valid {
            return Err(StateTransitionError::InvalidSession {
                from: self,
                to: next,
            });
        }

        if matches!(next, Self::Active | Self::Degraded | Self::Draining) && ready_paths == 0 {
            return Err(StateTransitionError::SessionRequiresReadyPath { state: next });
        }

        Ok(next)
    }

    pub const fn can_open_stream(self) -> bool {
        matches!(self, Self::Active | Self::Degraded)
    }
}

/// The state-machine entity that produced a lifecycle transition.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum LifecycleEntity {
    Session,
    Path(PathId),
}

/// A state value carried by a lifecycle transition event.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum LifecycleState {
    Session(SessionState),
    Path(PathState),
}

/// One accepted Session or Path transition.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct LifecycleTransitionEvent {
    pub sequence: u64,
    pub entity: LifecycleEntity,
    pub from: Option<LifecycleState>,
    pub to: LifecycleState,
}

/// Single owner for the lifecycle state of one Session and its PathSet.
///
/// Callers submit requested transitions here instead of assigning state in a
/// protocol handler or scheduler. Accepted changes are recorded exactly once
/// in the event queue; rejected changes leave both the state and queue intact.
#[derive(Debug)]
pub struct SessionPathLifecycle {
    session: SessionState,
    paths: BTreeMap<PathId, PathState>,
    events: VecDeque<LifecycleTransitionEvent>,
    next_sequence: u64,
}

impl Default for SessionPathLifecycle {
    fn default() -> Self {
        Self::new()
    }
}

impl SessionPathLifecycle {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            session: SessionState::Configured,
            paths: BTreeMap::new(),
            events: VecDeque::new(),
            next_sequence: 0,
        }
    }

    #[must_use]
    pub const fn session_state(&self) -> SessionState {
        self.session
    }

    #[must_use]
    pub fn path_state(&self, path_id: PathId) -> Option<PathState> {
        self.paths.get(&path_id).copied()
    }

    #[must_use]
    pub fn path_states(&self) -> BTreeMap<PathId, PathState> {
        self.paths.clone()
    }

    /// Counts authenticated Paths that are still ready for Session liveness.
    /// Draining Paths remain ready for this purpose, but cannot admit new work.
    #[must_use]
    pub fn ready_path_count(&self) -> usize {
        self.paths
            .values()
            .filter(|state| {
                matches!(
                    state,
                    PathState::Active | PathState::Degraded | PathState::Draining
                )
            })
            .count()
    }

    /// Counts Paths that may admit new business work.
    #[must_use]
    pub fn schedulable_path_count(&self) -> usize {
        self.paths
            .values()
            .filter(|state| state.can_admit_business())
            .count()
    }

    /// Register an admitted Path and emit its admission event.
    pub fn register_path(
        &mut self,
        path_id: PathId,
        state: PathState,
    ) -> Result<(), StateTransitionError> {
        if self.paths.contains_key(&path_id) {
            return Err(StateTransitionError::DuplicateLifecyclePath(path_id));
        }
        self.paths.insert(path_id, state);
        self.emit(
            LifecycleEntity::Path(path_id),
            None,
            LifecycleState::Path(state),
        )?;
        Ok(())
    }

    pub fn transition_path(
        &mut self,
        path_id: PathId,
        next: PathState,
    ) -> Result<PathState, StateTransitionError> {
        let current = self
            .paths
            .get(&path_id)
            .copied()
            .ok_or(StateTransitionError::UnknownLifecyclePath(path_id))?;
        let next = current.transition(next)?;
        if current != next {
            self.paths.insert(path_id, next);
            self.emit(
                LifecycleEntity::Path(path_id),
                Some(LifecycleState::Path(current)),
                LifecycleState::Path(next),
            )?;
        }
        Ok(next)
    }

    pub fn transition_session(
        &mut self,
        next: SessionState,
    ) -> Result<SessionState, StateTransitionError> {
        let current = self.session;
        let next = current.transition(next, self.ready_path_count())?;
        if current != next {
            self.session = next;
            self.emit(
                LifecycleEntity::Session,
                Some(LifecycleState::Session(current)),
                LifecycleState::Session(next),
            )?;
        }
        Ok(next)
    }

    pub fn unregister_path(&mut self, path_id: PathId) -> Result<PathState, StateTransitionError> {
        let current = self
            .paths
            .get(&path_id)
            .copied()
            .ok_or(StateTransitionError::UnknownLifecyclePath(path_id))?;
        if current != PathState::Closed {
            match current {
                PathState::Active | PathState::Degraded => {
                    self.transition_path(path_id, PathState::Draining)?;
                    self.transition_path(path_id, PathState::Closed)?;
                }
                PathState::Discovered => {
                    self.transition_path(path_id, PathState::Probing)?;
                    self.transition_path(path_id, PathState::Failed)?;
                    self.transition_path(path_id, PathState::Closed)?;
                }
                PathState::Probing => {
                    self.transition_path(path_id, PathState::Failed)?;
                    self.transition_path(path_id, PathState::Closed)?;
                }
                PathState::Draining | PathState::Failed => {
                    self.transition_path(path_id, PathState::Closed)?;
                }
                PathState::Closed => {}
            }
        }
        self.paths
            .remove(&path_id)
            .ok_or(StateTransitionError::UnknownLifecyclePath(path_id))
    }

    /// Drain accepted transition events in sequence order.
    pub fn take_events(&mut self) -> Vec<LifecycleTransitionEvent> {
        self.events.drain(..).collect()
    }

    fn emit(
        &mut self,
        entity: LifecycleEntity,
        from: Option<LifecycleState>,
        to: LifecycleState,
    ) -> Result<(), StateTransitionError> {
        let sequence = self
            .next_sequence
            .checked_add(1)
            .ok_or(StateTransitionError::LifecycleEventSequenceExhausted)?;
        self.next_sequence = sequence;
        self.events.push_back(LifecycleTransitionEvent {
            sequence,
            entity,
            from,
            to,
        });
        Ok(())
    }
}

/// Lifecycle of one TCP Stream.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum StreamState {
    New,
    Opening,
    Open,
    /// The Ingress-to-Egress direction has been half-closed.
    IngressHalfClosed,
    /// The Egress-to-Ingress direction has been half-closed.
    EgressHalfClosed,
    Closed,
    Reset,
}

impl StreamState {
    pub fn transition(self, next: Self) -> Result<Self, StateTransitionError> {
        let valid = self == next
            || matches!(
                (self, next),
                (Self::New, Self::Opening | Self::Closed | Self::Reset)
                    | (Self::Opening, Self::Open | Self::Closed | Self::Reset)
                    | (
                        Self::Open,
                        Self::IngressHalfClosed
                            | Self::EgressHalfClosed
                            | Self::Closed
                            | Self::Reset
                    )
                    | (Self::IngressHalfClosed, Self::Closed | Self::Reset)
                    | (Self::EgressHalfClosed, Self::Closed | Self::Reset)
            );
        if valid {
            Ok(next)
        } else {
            Err(StateTransitionError::InvalidStream {
                from: self,
                to: next,
            })
        }
    }

    pub const fn can_send_ingress_to_egress(self) -> bool {
        matches!(self, Self::Open | Self::EgressHalfClosed)
    }

    pub const fn can_send_egress_to_ingress(self) -> bool {
        matches!(self, Self::Open | Self::IngressHalfClosed)
    }
}

/// Lifecycle of the Ingress relationship to one configured Egress.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum EgressRelationshipState {
    Configured,
    Connecting,
    Connected,
    Degraded,
    Draining,
    Down,
}

impl EgressRelationshipState {
    pub fn transition(self, next: Self) -> Result<Self, StateTransitionError> {
        let valid = self == next
            || matches!(
                (self, next),
                (Self::Configured, Self::Connecting)
                    | (Self::Connecting, Self::Connected | Self::Down)
                    | (
                        Self::Connected,
                        Self::Degraded | Self::Draining | Self::Down
                    )
                    | (
                        Self::Degraded,
                        Self::Connected | Self::Draining | Self::Down
                    )
                    | (Self::Draining, Self::Down)
                    | (Self::Down, Self::Connecting)
            );
        if valid {
            Ok(next)
        } else {
            Err(StateTransitionError::InvalidEgressRelationship {
                from: self,
                to: next,
            })
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum EgressServiceState {
    Up,
    Degraded,
    Draining,
    Down,
}

impl EgressServiceState {
    /// Returns the wire-profile-v1 status code.
    pub const fn wire_code(self) -> u8 {
        match self {
            Self::Down => 0,
            Self::Up => 1,
            Self::Degraded => 2,
            Self::Draining => 3,
        }
    }

    /// Decodes the wire-profile-v1 status code.
    pub const fn from_wire_code(code: u8) -> Option<Self> {
        match code {
            0 => Some(Self::Down),
            1 => Some(Self::Up),
            2 => Some(Self::Degraded),
            3 => Some(Self::Draining),
            _ => None,
        }
    }
}

/// Runtime facts used to derive the externally visible Egress service state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EgressRuntime {
    connected: bool,
    admission_requirements_met: bool,
    draining: bool,
    admin_shutdown: bool,
}

impl EgressRuntime {
    pub const fn new(
        connected: bool,
        admission_requirements_met: bool,
        draining: bool,
        admin_shutdown: bool,
    ) -> Self {
        Self {
            connected,
            admission_requirements_met,
            draining,
            admin_shutdown,
        }
    }

    pub const fn service_state(self) -> EgressServiceState {
        if self.admin_shutdown || !self.connected {
            EgressServiceState::Down
        } else if self.draining {
            EgressServiceState::Draining
        } else if self.admission_requirements_met {
            EgressServiceState::Up
        } else {
            EgressServiceState::Degraded
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StateTransitionError {
    InvalidPath {
        from: PathState,
        to: PathState,
    },
    InvalidSession {
        from: SessionState,
        to: SessionState,
    },
    SessionRequiresReadyPath {
        state: SessionState,
    },
    InvalidStream {
        from: StreamState,
        to: StreamState,
    },
    InvalidEgressRelationship {
        from: EgressRelationshipState,
        to: EgressRelationshipState,
    },
    UnknownLifecyclePath(PathId),
    DuplicateLifecyclePath(PathId),
    LifecycleEventSequenceExhausted,
}

impl fmt::Display for StateTransitionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPath { from, to } => {
                write!(formatter, "invalid Path transition from {from:?} to {to:?}")
            }
            Self::InvalidSession { from, to } => {
                write!(
                    formatter,
                    "invalid Session transition from {from:?} to {to:?}"
                )
            }
            Self::SessionRequiresReadyPath { state } => {
                write!(formatter, "Session state {state:?} requires a ready Path")
            }
            Self::InvalidStream { from, to } => {
                write!(
                    formatter,
                    "invalid Stream transition from {from:?} to {to:?}"
                )
            }
            Self::InvalidEgressRelationship { from, to } => write!(
                formatter,
                "invalid Egress relationship transition from {from:?} to {to:?}"
            ),
            Self::UnknownLifecyclePath(path_id) => {
                write!(formatter, "lifecycle Path {path_id} is not registered")
            }
            Self::DuplicateLifecyclePath(path_id) => {
                write!(formatter, "lifecycle Path {path_id} is already registered")
            }
            Self::LifecycleEventSequenceExhausted => {
                write!(formatter, "lifecycle event sequence is exhausted")
            }
        }
    }
}

impl Error for StateTransitionError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_follows_discovery_probe_active_order() {
        let state = PathState::Discovered
            .transition(PathState::Probing)
            .unwrap()
            .transition(PathState::Active)
            .unwrap();
        assert!(state.can_admit_business());
        assert_eq!(
            PathState::Discovered.transition(PathState::Active),
            Err(StateTransitionError::InvalidPath {
                from: PathState::Discovered,
                to: PathState::Active
            })
        );
    }

    #[test]
    fn failed_path_must_close_before_becoming_terminal() {
        assert!(!PathState::Failed.is_terminal());
        assert_eq!(
            PathState::Failed.transition(PathState::Closed),
            Ok(PathState::Closed)
        );
        assert!(PathState::Closed.is_terminal());
        assert!(PathState::Closed.transition(PathState::Active).is_err());
    }

    #[test]
    fn live_session_requires_a_ready_path() {
        assert_eq!(
            SessionState::Connecting.transition(SessionState::Active, 0),
            Err(StateTransitionError::SessionRequiresReadyPath {
                state: SessionState::Active
            })
        );
        assert_eq!(
            SessionState::Connecting.transition(SessionState::Active, 1),
            Ok(SessionState::Active)
        );
    }

    #[test]
    fn closed_session_never_opens_new_streams() {
        assert!(!SessionState::Closed.can_open_stream());
        assert!(SessionState::Degraded.can_open_stream());
        assert_eq!(
            SessionState::Closed.transition(SessionState::Active, 0),
            Err(StateTransitionError::InvalidSession {
                from: SessionState::Closed,
                to: SessionState::Active,
            })
        );
    }

    #[test]
    fn half_close_preserves_the_opposite_direction() {
        let ingress_closed = StreamState::Open
            .transition(StreamState::IngressHalfClosed)
            .unwrap();
        assert!(!ingress_closed.can_send_ingress_to_egress());
        assert!(ingress_closed.can_send_egress_to_ingress());

        let egress_closed = StreamState::Open
            .transition(StreamState::EgressHalfClosed)
            .unwrap();
        assert!(egress_closed.can_send_ingress_to_egress());
        assert!(!egress_closed.can_send_egress_to_ingress());
    }

    #[test]
    fn stream_opens_through_the_documented_states() {
        let state = StreamState::New
            .transition(StreamState::Opening)
            .unwrap()
            .transition(StreamState::Open)
            .unwrap();
        assert_eq!(state, StreamState::Open);
        assert!(StreamState::New.transition(StreamState::Open).is_err());
    }

    #[test]
    fn session_recovery_never_reuses_a_closed_protocol_session() {
        assert_eq!(
            SessionState::Degraded.transition(SessionState::Active, 1),
            Ok(SessionState::Active)
        );
        assert!(
            SessionState::Closed
                .transition(SessionState::Connecting, 0)
                .is_err()
        );
    }

    #[test]
    fn egress_relationship_follows_runtime_lifecycle() {
        let state = EgressRelationshipState::Configured
            .transition(EgressRelationshipState::Connecting)
            .unwrap()
            .transition(EgressRelationshipState::Connected)
            .unwrap()
            .transition(EgressRelationshipState::Degraded)
            .unwrap()
            .transition(EgressRelationshipState::Draining)
            .unwrap()
            .transition(EgressRelationshipState::Down)
            .unwrap();
        assert_eq!(state, EgressRelationshipState::Down);
        assert!(
            EgressRelationshipState::Configured
                .transition(EgressRelationshipState::Connected)
                .is_err()
        );
    }

    #[test]
    fn egress_state_is_derived_from_runtime_facts() {
        let cases = [
            (
                EgressRuntime::new(true, true, false, false),
                EgressServiceState::Up,
            ),
            (
                EgressRuntime::new(true, false, false, false),
                EgressServiceState::Degraded,
            ),
            (
                EgressRuntime::new(true, true, true, false),
                EgressServiceState::Draining,
            ),
            (
                EgressRuntime::new(false, true, false, false),
                EgressServiceState::Down,
            ),
            (
                EgressRuntime::new(true, true, false, true),
                EgressServiceState::Down,
            ),
        ];

        for (runtime, expected) in cases {
            assert_eq!(runtime.service_state(), expected);
        }
    }

    #[test]
    fn lifecycle_owner_rejects_draining_to_active_and_emits_once_per_transition() {
        let path_id = PathId::new(7);
        let mut owner = SessionPathLifecycle::new();
        owner
            .register_path(path_id, PathState::Active)
            .expect("register Path");
        owner
            .transition_session(SessionState::Connecting)
            .expect("connect Session");
        owner
            .transition_session(SessionState::Active)
            .expect("activate Session");
        owner
            .transition_path(path_id, PathState::Draining)
            .expect("drain Path");
        assert_eq!(
            owner.transition_path(path_id, PathState::Active),
            Err(StateTransitionError::InvalidPath {
                from: PathState::Draining,
                to: PathState::Active,
            })
        );
        owner
            .transition_session(SessionState::Draining)
            .expect("drain Session");
        assert_eq!(
            owner.transition_session(SessionState::Active),
            Err(StateTransitionError::InvalidSession {
                from: SessionState::Draining,
                to: SessionState::Active,
            })
        );
        let events = owner.take_events();
        assert_eq!(events.len(), 5);
        assert_eq!(
            events
                .iter()
                .map(|event| event.sequence)
                .collect::<Vec<_>>(),
            vec![1, 2, 3, 4, 5]
        );
        assert!(owner.take_events().is_empty());
    }
}
