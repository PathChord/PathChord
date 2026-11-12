//! Ingress listener and Session-manager boundaries.
//!
//! Phase 0 provides no SOCKS, HTTP, TPROXY, or TUN implementation. The
//! reconnecting `SessionSlot` is deliberately separate from a protocol
//! `SessionId`. The Session manager must allocate a fresh random ID for each
//! attachment; the slot rejects immediate accidental reuse without retaining
//! unbounded process-lifetime history.
//!
//! The transport-neutral [`IngressControlService`] is the shared foundation
//! for the local management protocol and future REST/SSE or GraphQL adapters.

use std::net::SocketAddr;

use async_trait::async_trait;
use getrandom::fill;
use pathchord_core::{SessionId, SessionState, StateTransitionError};
use pathchord_policy::{EgressId, PolicyContext};
pub use pathchord_policy::{FlowProtocol, ListenerId, ProcessMetadata, TargetEndpoint, TargetHost};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite};

mod control;
mod control_views;
mod local_dispatch;
mod local_protocol;
mod local_server;

pub use control::{
    ConnectionObservation, ConnectionState, ControlError, ControlEvent, ControlEventKind,
    IngressControlService, IngressControlSnapshot, MAX_CONNECTION_OBSERVATIONS, MAX_EVENT_COUNT,
    MAX_NODE_COUNT, MAX_REFRESH_QUEUE_COUNT, MAX_REQUEST_CACHE_COUNT, MAX_SUBSCRIPTION_COUNT,
    MutationReceipt, NodeAdminPatch, NodeAdminState, NodeHealthState, NodeId, NodeObservation,
    ObservationSnapshot, RuntimeCounts, SubscriptionId, SubscriptionRefreshState, SubscriptionSpec,
    SubscriptionState, SystemProxyMutation, SystemProxyPlatform, SystemProxyState,
    SystemProxyStatus,
};
pub use control_views::{
    ListenerInventory, ListenerSelectionError, ListenerView, ListenerViewState,
    SystemProxyPlatformEffect, SystemProxyRestorationState, SystemProxyStatusView,
};
pub use local_dispatch::LocalControlDispatcher;
pub use local_protocol::{
    Actor, ErrorBody, ErrorCode, GenerationExpectation, LOCAL_API_VERSION, LocalProtocolError,
    MAX_ENVELOPE_BYTES, RequestEnvelope, ResponseEnvelope, decode_object, encode_object,
    read_object, write_object,
};
pub use local_server::{LocalControlServer, LocalServerError};

pub trait LocalConnection: AsyncRead + AsyncWrite + Send + Unpin {}

impl<T> LocalConnection for T where T: AsyncRead + AsyncWrite + Send + Unpin {}

pub type BoxedLocalConnection = Box<dyn LocalConnection>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListenerKind {
    Socks5,
    Http,
    Tproxy,
    Redirect,
    Tun,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListenerDescriptor {
    pub id: ListenerId,
    pub kind: ListenerKind,
    pub bind: SocketAddr,
    pub authentication_required: bool,
}

pub type TargetAddress = TargetEndpoint;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionContext {
    pub listener_id: ListenerId,
    pub source: SocketAddr,
    pub authentication_identity: Option<String>,
    pub process: Option<ProcessMetadata>,
    pub protocol: FlowProtocol,
    pub target: TargetAddress,
}

impl ConnectionContext {
    /// Converts listener facts into the policy crate's typed evaluator input.
    #[must_use]
    pub fn policy_context(&self, flow_tags: std::collections::BTreeSet<String>) -> PolicyContext {
        PolicyContext {
            flow_tags,
            listener_id: self.listener_id.clone(),
            source: self.source,
            authentication_identity: self.authentication_identity.clone(),
            process: self.process.clone(),
            protocol: self.protocol,
            target: self.target.clone(),
        }
    }
}

pub struct AcceptedConnection {
    pub io: BoxedLocalConnection,
    pub context: ConnectionContext,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ListenerError {
    #[error("listener is not implemented in the Phase 0 bootstrap: {0}")]
    NotImplemented(String),
    #[error("listener failed: {0}")]
    Accept(String),
}

#[async_trait]
pub trait IngressListener: Send + Sync {
    fn descriptor(&self) -> &ListenerDescriptor;

    async fn accept(&self) -> Result<AcceptedConnection, ListenerError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionSlotPhase {
    Configured,
    Connecting,
    Active,
    Draining,
    WaitingForEgress,
    AuthorizationBlocked,
    Stopped,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionCloseReason {
    LastPathLost,
    EgressUnavailable,
    AuthorizationDisabled,
    AuthorizationRevoked,
    EndpointRestart,
    DrainComplete,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionClosure {
    pub session_id: SessionId,
    pub reason: SessionCloseReason,
    /// Protocol closure requires all associated business Streams to close.
    pub close_business_streams: bool,
    /// Egress must also close the corresponding target connections.
    pub close_target_connections: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct LiveSession {
    id: SessionId,
    state: SessionState,
    ready_paths: usize,
}

/// Supplies fresh random Session IDs owned by the Ingress Session manager.
///
/// Implementations must not repeat an ID during one process lifetime. Production
/// code uses [`OsRandomSessionIdSource`]; deterministic sources are injectable
/// for tests.
pub trait SessionIdSource {
    fn next_session_id(&mut self) -> Result<SessionId, SessionIdGenerationError>;
}

#[derive(Debug, Default)]
pub struct OsRandomSessionIdSource;

impl SessionIdSource for OsRandomSessionIdSource {
    fn next_session_id(&mut self) -> Result<SessionId, SessionIdGenerationError> {
        loop {
            let mut bytes = [0_u8; 16];
            fill(&mut bytes)
                .map_err(|error| SessionIdGenerationError::Entropy(error.to_string()))?;
            let session_id = SessionId::from_be_bytes(bytes);
            if session_id.get() != 0 {
                return Ok(session_id);
            }
        }
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SessionIdGenerationError {
    #[error("operating-system randomness failed: {0}")]
    Entropy(String),
    #[error("deterministic Session ID source is exhausted")]
    Exhausted,
}

#[derive(Debug)]
pub struct SessionSlot<S = OsRandomSessionIdSource> {
    egress_id: EgressId,
    phase: SessionSlotPhase,
    live: Option<LiveSession>,
    id_source: S,
}

impl SessionSlot<OsRandomSessionIdSource> {
    pub fn new(egress_id: EgressId) -> Self {
        Self::with_id_source(egress_id, OsRandomSessionIdSource)
    }
}

impl<S> SessionSlot<S>
where
    S: SessionIdSource,
{
    pub fn with_id_source(egress_id: EgressId, id_source: S) -> Self {
        Self {
            egress_id,
            phase: SessionSlotPhase::Configured,
            live: None,
            id_source,
        }
    }

    pub fn egress_id(&self) -> &EgressId {
        &self.egress_id
    }

    pub const fn phase(&self) -> SessionSlotPhase {
        self.phase
    }

    pub fn current_session_id(&self) -> Option<SessionId> {
        self.live.map(|session| session.id)
    }

    pub fn ready_path_count(&self) -> Option<usize> {
        self.live.map(|session| session.ready_paths)
    }

    pub fn begin_connecting(&mut self) -> Result<(), SessionSlotError> {
        if self.phase != SessionSlotPhase::Configured {
            return Err(SessionSlotError::InvalidManagerTransition {
                from: self.phase,
                to: SessionSlotPhase::Connecting,
            });
        }
        self.phase = SessionSlotPhase::Connecting;
        Ok(())
    }

    pub fn attach(&mut self, ready_paths: usize) -> Result<SessionId, SessionSlotError> {
        if self.phase != SessionSlotPhase::Connecting {
            return Err(SessionSlotError::NotConnecting { phase: self.phase });
        }
        if self.live.is_some() {
            return Err(SessionSlotError::AlreadyLive);
        }

        let state = SessionState::Configured
            .transition(SessionState::Connecting, 0)?
            .transition(SessionState::Active, ready_paths)?;
        let session_id = self.id_source.next_session_id()?;
        self.live = Some(LiveSession {
            id: session_id,
            state,
            ready_paths,
        });
        self.phase = SessionSlotPhase::Active;
        Ok(session_id)
    }

    pub fn begin_draining(&mut self) -> Result<(), SessionSlotError> {
        let live = self.live.as_mut().ok_or(SessionSlotError::NoLiveSession)?;
        live.state = live
            .state
            .transition(SessionState::Draining, live.ready_paths)?;
        self.phase = SessionSlotPhase::Draining;
        Ok(())
    }

    pub fn add_ready_path(&mut self) -> Result<usize, SessionSlotError> {
        if self.phase != SessionSlotPhase::Active {
            return Err(SessionSlotError::PathAdmissionClosed { phase: self.phase });
        }
        let live = self.live.as_mut().ok_or(SessionSlotError::NoLiveSession)?;
        live.ready_paths = live
            .ready_paths
            .checked_add(1)
            .ok_or(SessionSlotError::ReadyPathCountOverflow)?;
        Ok(live.ready_paths)
    }

    /// Removes one ready Path and closes the protocol Session on the `1 -> 0`
    /// transition. Losing any earlier Path leaves the Session alive.
    pub fn lose_ready_path(&mut self) -> Result<Option<SessionClosure>, SessionSlotError> {
        let ready_paths = self
            .live
            .as_ref()
            .ok_or(SessionSlotError::NoLiveSession)?
            .ready_paths;
        match ready_paths {
            0 => Err(SessionSlotError::NoReadyPath),
            1 => {
                let (reason, next_phase) = if self.phase == SessionSlotPhase::Draining {
                    (
                        SessionCloseReason::DrainComplete,
                        SessionSlotPhase::Configured,
                    )
                } else {
                    (
                        SessionCloseReason::LastPathLost,
                        SessionSlotPhase::Connecting,
                    )
                };
                self.close_live(reason, next_phase).map(Some)
            }
            _ => {
                let live = self.live.as_mut().ok_or(SessionSlotError::NoLiveSession)?;
                live.ready_paths -= 1;
                Ok(None)
            }
        }
    }

    pub fn close_for(
        &mut self,
        reason: SessionCloseReason,
    ) -> Result<SessionClosure, SessionSlotError> {
        let next_phase = match reason {
            SessionCloseReason::LastPathLost => SessionSlotPhase::Connecting,
            SessionCloseReason::EgressUnavailable => SessionSlotPhase::WaitingForEgress,
            SessionCloseReason::AuthorizationDisabled
            | SessionCloseReason::AuthorizationRevoked => SessionSlotPhase::AuthorizationBlocked,
            SessionCloseReason::EndpointRestart => SessionSlotPhase::Stopped,
            SessionCloseReason::DrainComplete => SessionSlotPhase::Configured,
        };
        self.close_live(reason, next_phase)
    }

    pub fn egress_online(&mut self) -> Result<(), SessionSlotError> {
        self.resume_from(
            SessionSlotPhase::WaitingForEgress,
            SessionSlotPhase::Connecting,
        )
    }

    pub fn authorization_enabled(&mut self) -> Result<(), SessionSlotError> {
        self.resume_from(
            SessionSlotPhase::AuthorizationBlocked,
            SessionSlotPhase::Connecting,
        )
    }

    pub fn stop(&mut self) -> Result<Option<SessionClosure>, SessionSlotError> {
        let closure = if self.live.is_some() {
            Some(self.close_live(
                SessionCloseReason::EndpointRestart,
                SessionSlotPhase::Stopped,
            )?)
        } else {
            self.phase = SessionSlotPhase::Stopped;
            None
        };
        Ok(closure)
    }

    fn resume_from(
        &mut self,
        expected: SessionSlotPhase,
        next: SessionSlotPhase,
    ) -> Result<(), SessionSlotError> {
        if self.phase != expected {
            return Err(SessionSlotError::InvalidManagerTransition {
                from: self.phase,
                to: next,
            });
        }
        self.phase = next;
        Ok(())
    }

    fn close_live(
        &mut self,
        reason: SessionCloseReason,
        next_phase: SessionSlotPhase,
    ) -> Result<SessionClosure, SessionSlotError> {
        let live = self.live.take().ok_or(SessionSlotError::NoLiveSession)?;
        live.state.transition(SessionState::Closed, 0)?;
        self.phase = next_phase;
        Ok(SessionClosure {
            session_id: live.id,
            reason,
            close_business_streams: true,
            close_target_connections: true,
        })
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SessionSlotError {
    #[error("Session slot is stopped")]
    Stopped,
    #[error("Session slot in {phase:?} phase is not connecting")]
    NotConnecting { phase: SessionSlotPhase },
    #[error("invalid Session manager transition from {from:?} to {to:?}")]
    InvalidManagerTransition {
        from: SessionSlotPhase,
        to: SessionSlotPhase,
    },
    #[error("Session slot already owns a live protocol Session")]
    AlreadyLive,
    #[error("Session slot has no live protocol Session")]
    NoLiveSession,
    #[error("live protocol Session has no ready Path to remove")]
    NoReadyPath,
    #[error("ready Path count overflowed")]
    ReadyPathCountOverflow,
    #[error("Session slot in {phase:?} phase does not admit a new Path")]
    PathAdmissionClosed { phase: SessionSlotPhase },
    #[error(transparent)]
    SessionId(#[from] SessionIdGenerationError),
    #[error(transparent)]
    ProtocolState(#[from] StateTransitionError),
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use pathchord_policy::TargetHost;

    use super::*;

    #[derive(Debug)]
    struct IncrementingIdSource {
        next: u128,
    }

    impl SessionIdSource for IncrementingIdSource {
        fn next_session_id(&mut self) -> Result<SessionId, SessionIdGenerationError> {
            let value = self.next;
            self.next = self
                .next
                .checked_add(1)
                .ok_or(SessionIdGenerationError::Exhausted)?;
            Ok(SessionId::new(value))
        }
    }

    fn connecting_slot(start: u128) -> SessionSlot<IncrementingIdSource> {
        let mut slot = SessionSlot::with_id_source(
            EgressId::new("jp-1"),
            IncrementingIdSource { next: start },
        );
        slot.begin_connecting().expect("begin connecting");
        slot
    }

    struct FakeListener {
        descriptor: ListenerDescriptor,
    }

    #[async_trait]
    impl IngressListener for FakeListener {
        fn descriptor(&self) -> &ListenerDescriptor {
            &self.descriptor
        }

        async fn accept(&self) -> Result<AcceptedConnection, ListenerError> {
            let (client, _server) = tokio::io::duplex(64);
            Ok(AcceptedConnection {
                io: Box::new(client),
                context: ConnectionContext {
                    listener_id: self.descriptor.id.clone(),
                    source: SocketAddr::from_str("127.0.0.1:12345").expect("socket address"),
                    authentication_identity: None,
                    process: None,
                    protocol: FlowProtocol::Tcp,
                    target: TargetAddress {
                        host: TargetHost::Hostname("example.net".into()),
                        port: 443,
                    },
                },
            })
        }
    }

    #[test]
    fn reconnecting_slot_owns_fresh_session_id_allocation() {
        let mut slot = connecting_slot(1);
        let first = slot.attach(1).expect("first Session");

        let closure = slot
            .lose_ready_path()
            .expect("remove last Path")
            .expect("close old Session");
        assert_eq!(closure.session_id, first);
        assert!(closure.close_business_streams);
        assert_eq!(slot.phase(), SessionSlotPhase::Connecting);
        assert_eq!(slot.current_session_id(), None);

        let replacement = slot.attach(1).expect("replacement Session");
        assert_eq!(first, SessionId::new(1));
        assert_eq!(replacement, SessionId::new(2));
        assert_eq!(slot.current_session_id(), Some(replacement));
    }

    #[test]
    fn live_session_requires_a_ready_path() {
        let mut slot = connecting_slot(1);
        assert!(matches!(
            slot.attach(0),
            Err(SessionSlotError::ProtocolState(
                StateTransitionError::SessionRequiresReadyPath { .. }
            ))
        ));
    }

    #[test]
    fn only_the_last_ready_path_closes_the_session() {
        let mut slot = connecting_slot(1);
        let session_id = slot.attach(2).expect("live Session");

        assert_eq!(slot.lose_ready_path().expect("first Path loss"), None);
        assert_eq!(slot.ready_path_count(), Some(1));
        assert_eq!(slot.current_session_id(), Some(session_id));

        let closure = slot
            .lose_ready_path()
            .expect("last Path loss")
            .expect("Session closure");
        assert_eq!(closure.session_id, session_id);
        assert_eq!(slot.ready_path_count(), None);
        assert_eq!(slot.phase(), SessionSlotPhase::Connecting);
    }

    #[test]
    fn draining_session_does_not_admit_a_new_path() {
        let mut slot = connecting_slot(1);
        slot.attach(1).expect("live Session");
        slot.begin_draining().expect("begin drain");

        assert_eq!(
            slot.add_ready_path(),
            Err(SessionSlotError::PathAdmissionClosed {
                phase: SessionSlotPhase::Draining
            })
        );

        let closure = slot
            .lose_ready_path()
            .expect("last draining Path")
            .expect("drained Session closes");
        assert_eq!(closure.reason, SessionCloseReason::DrainComplete);
        assert_eq!(slot.phase(), SessionSlotPhase::Configured);
    }

    #[test]
    fn repeated_reconnects_do_not_accumulate_session_history() {
        let mut slot = connecting_slot(1);
        for _ in 1_u128..=10_000 {
            slot.attach(1).expect("fresh Session");
            slot.lose_ready_path()
                .expect("Path loss")
                .expect("Session closure");
        }
        assert_eq!(slot.phase(), SessionSlotPhase::Connecting);
        assert_eq!(slot.current_session_id(), None);
    }

    #[test]
    fn hard_close_reasons_gate_reconnection_explicitly() {
        let cases = [
            (
                SessionCloseReason::EgressUnavailable,
                SessionSlotPhase::WaitingForEgress,
            ),
            (
                SessionCloseReason::AuthorizationDisabled,
                SessionSlotPhase::AuthorizationBlocked,
            ),
            (
                SessionCloseReason::AuthorizationRevoked,
                SessionSlotPhase::AuthorizationBlocked,
            ),
            (
                SessionCloseReason::EndpointRestart,
                SessionSlotPhase::Stopped,
            ),
        ];

        for (reason, expected_phase) in cases {
            let mut slot = connecting_slot(1);
            slot.attach(1).expect("live Session");
            slot.close_for(reason).expect("hard close");
            assert_eq!(slot.phase(), expected_phase);
            assert!(matches!(
                slot.attach(1),
                Err(SessionSlotError::NotConnecting { .. })
            ));
        }

        let mut offline = connecting_slot(1);
        offline.attach(1).expect("live Session");
        offline
            .close_for(SessionCloseReason::EgressUnavailable)
            .expect("offline close");
        offline.egress_online().expect("Egress recovered");
        assert_eq!(offline.phase(), SessionSlotPhase::Connecting);

        let mut revoked = connecting_slot(1);
        revoked.attach(1).expect("live Session");
        revoked
            .close_for(SessionCloseReason::AuthorizationRevoked)
            .expect("revocation close");
        revoked
            .authorization_enabled()
            .expect("authorization restored");
        assert_eq!(revoked.phase(), SessionSlotPhase::Connecting);

        let mut disabled = connecting_slot(1);
        disabled.attach(1).expect("live Session");
        disabled
            .close_for(SessionCloseReason::AuthorizationDisabled)
            .expect("disable close");
        disabled
            .authorization_enabled()
            .expect("authorization restored");
        assert_eq!(disabled.phase(), SessionSlotPhase::Connecting);
    }

    #[tokio::test]
    async fn fake_listener_populates_policy_context() {
        let listener = FakeListener {
            descriptor: ListenerDescriptor {
                id: ListenerId::new("local-http"),
                kind: ListenerKind::Http,
                bind: SocketAddr::from_str("127.0.0.1:8080").expect("socket address"),
                authentication_required: false,
            },
        };

        let accepted = listener.accept().await.expect("fake accept");
        assert_eq!(accepted.context.listener_id.as_str(), "local-http");
        assert_eq!(accepted.context.target.port, 443);
        assert_eq!(
            accepted.context.policy_context(Default::default()).protocol,
            FlowProtocol::Tcp
        );
        drop(accepted.io);
    }
}
