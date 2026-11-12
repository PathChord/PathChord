//! Egress target-dialing and authorization boundaries.
//!
//! Persistence is intentionally absent in Phase 0. A future Egress-owned store
//! will publish validated generations as immutable `AuthorizationSnapshot`s.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::IpAddr;

use async_trait::async_trait;
use pathchord_core::{RequestId, SessionId, StreamId};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite};

pub trait TargetConnection: AsyncRead + AsyncWrite + Send + Unpin {}

impl<T> TargetConnection for T where T: AsyncRead + AsyncWrite + Send + Unpin {}

pub type BoxedTargetConnection = Box<dyn TargetConnection>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetRequest {
    /// Original application hostname, retained so Egress can apply its DNS policy.
    pub original_hostname: Option<String>,
    /// Address candidates supplied by Ingress, without discarding the hostname.
    pub resolved_ip_candidates: Vec<IpAddr>,
    pub port: u16,
}

impl TargetRequest {
    fn validate(&self) -> Result<(), TargetConnectError> {
        if self.port == 0 {
            return Err(TargetConnectError::InvalidPort);
        }
        if self.original_hostname.as_deref() == Some("") {
            return Err(TargetConnectError::EmptyHostname);
        }
        if self.original_hostname.is_none() && self.resolved_ip_candidates.is_empty() {
            return Err(TargetConnectError::MissingDestination);
        }
        Ok(())
    }
}

/// One Session-scoped `STREAM_OPEN` operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamOpenRequest {
    pub session_id: SessionId,
    pub stream_id: StreamId,
    pub request_id: RequestId,
    pub target: TargetRequest,
}

#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum TargetConnectError {
    #[error("target request uses invalid port 0")]
    InvalidPort,
    #[error("target request uses an empty original hostname")]
    EmptyHostname,
    #[error("target request contains neither an original hostname nor an IP candidate")]
    MissingDestination,
    #[error("target connection failed: {0}")]
    Connection(String),
}

#[async_trait]
pub trait TargetConnector: Send + Sync {
    async fn connect(
        &self,
        request: TargetRequest,
    ) -> Result<BoxedTargetConnection, TargetConnectError>;
}

/// Semantic result cached for a Session-scoped RequestID.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StreamOpenResult {
    Opened,
    TargetFailure(TargetConnectError),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamOpenResponse {
    pub result: StreamOpenResult,
    /// True when this result was returned from the idempotency cache.
    pub replayed: bool,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum FakeEgressError {
    #[error("Session {session_id} is not active and cannot open new Streams")]
    SessionNotActive { session_id: SessionId },
    #[error("RequestID {request_id} was reused with conflicting data in Session {session_id}")]
    ConflictingRequestId {
        session_id: SessionId,
        request_id: RequestId,
    },
    #[error("Stream {stream_id} in Session {session_id} already belongs to another RequestID")]
    StreamAlreadyOpen {
        session_id: SessionId,
        stream_id: StreamId,
    },
    #[error("response for RequestID {request_id} in Session {session_id} was lost")]
    ResponseLost {
        session_id: SessionId,
        request_id: RequestId,
    },
}

#[derive(Debug, Clone)]
struct CachedOpen {
    request: StreamOpenRequest,
    result: StreamOpenResult,
}

/// Deterministic Phase-0 Egress fixture with Session-scoped open idempotency.
///
/// It owns every successfully dialed connection. A simulated response loss is
/// injected only after the connection and cached result have been committed,
/// matching an uncertain `STREAM_OPEN_OK` observed by Ingress.
pub struct FakeEgress<C> {
    connector: C,
    requests: HashMap<(SessionId, RequestId), CachedOpen>,
    stream_requests: HashMap<(SessionId, StreamId), RequestId>,
    connections: HashMap<(SessionId, StreamId), BoxedTargetConnection>,
    active_sessions: HashSet<SessionId>,
    lose_next_success_response: bool,
}

impl<C> FakeEgress<C>
where
    C: TargetConnector,
{
    pub fn new(connector: C) -> Self {
        Self {
            connector,
            requests: HashMap::new(),
            stream_requests: HashMap::new(),
            connections: HashMap::new(),
            active_sessions: HashSet::new(),
            lose_next_success_response: false,
        }
    }

    pub const fn connector(&self) -> &C {
        &self.connector
    }

    /// Registers a Session after a successful protocol attach.
    ///
    /// Registration is idempotent: repeated attach notifications for the same
    /// active Session do not change the registry or any open state.
    pub fn register_session(&mut self, session_id: SessionId) {
        self.active_sessions.insert(session_id);
    }

    pub fn active_session_count(&self) -> usize {
        self.active_sessions.len()
    }

    pub fn cached_request_count(&self) -> usize {
        self.requests.len()
    }

    pub fn active_connection_count(&self) -> usize {
        self.connections.len()
    }

    pub fn owns_connection(&self, session_id: SessionId, stream_id: StreamId) -> bool {
        self.connections.contains_key(&(session_id, stream_id))
    }

    /// Loses the next successful response after its target connection is owned.
    pub fn lose_next_success_response(&mut self) {
        self.lose_next_success_response = true;
    }

    /// Drops all target connections and idempotency state owned by one Session,
    /// then removes that Session from the active attach registry.
    pub fn close_session(&mut self, session_id: SessionId) -> usize {
        let connection_count = self.connections.len();
        self.connections
            .retain(|(owned_session, _), _| *owned_session != session_id);
        self.requests
            .retain(|(owned_session, _), _| *owned_session != session_id);
        self.stream_requests
            .retain(|(owned_session, _), _| *owned_session != session_id);
        self.active_sessions.remove(&session_id);
        connection_count - self.connections.len()
    }

    /// Drops one target socket but retains its idempotency tombstone.
    ///
    /// The cached `STREAM_OPEN` result remains until `close_session`, so a late
    /// duplicate cannot create a second target connection.
    pub fn close_stream(&mut self, session_id: SessionId, stream_id: StreamId) -> bool {
        self.connections.remove(&(session_id, stream_id)).is_some()
    }

    pub async fn open_stream(
        &mut self,
        request: StreamOpenRequest,
    ) -> Result<StreamOpenResponse, FakeEgressError> {
        if !self.active_sessions.contains(&request.session_id) {
            return Err(FakeEgressError::SessionNotActive {
                session_id: request.session_id,
            });
        }

        let request_key = (request.session_id, request.request_id);
        if let Some(cached) = self.requests.get(&request_key) {
            if cached.request != request {
                return Err(FakeEgressError::ConflictingRequestId {
                    session_id: request.session_id,
                    request_id: request.request_id,
                });
            }
            return Ok(StreamOpenResponse {
                result: cached.result.clone(),
                replayed: true,
            });
        }

        let connection_key = (request.session_id, request.stream_id);
        if self.stream_requests.contains_key(&connection_key) {
            return Err(FakeEgressError::StreamAlreadyOpen {
                session_id: request.session_id,
                stream_id: request.stream_id,
            });
        }
        let dial_result = match request.target.validate() {
            Ok(()) => self.connector.connect(request.target.clone()).await,
            Err(error) => Err(error),
        };

        // `connect` is the only cancellation point. Commit all fixture state
        // after it returns so dropping a pending future leaves no tombstone.
        self.stream_requests
            .insert(connection_key, request.request_id);
        let result = match dial_result {
            Ok(connection) => {
                self.connections.insert(connection_key, connection);
                StreamOpenResult::Opened
            }
            Err(error) => StreamOpenResult::TargetFailure(error),
        };
        self.requests.insert(
            request_key,
            CachedOpen {
                request: request.clone(),
                result: result.clone(),
            },
        );

        if result == StreamOpenResult::Opened && self.lose_next_success_response {
            self.lose_next_success_response = false;
            return Err(FakeEgressError::ResponseLost {
                session_id: request.session_id,
                request_id: request.request_id,
            });
        }

        Ok(StreamOpenResponse {
            result,
            replayed: false,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct IngressId(String);

impl IngressId {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EgressId(String);

impl EgressId {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthorizationState {
    Enabled,
    Disabled,
    Revoked,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationRecord {
    pub ingress_id: IngressId,
    pub ingress_public_key: [u8; 32],
    pub state: AuthorizationState,
    pub administrator_labels: BTreeMap<String, String>,
    pub record_generation: u64,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum AuthorizationSnapshotError {
    #[error("Egress id must not be empty")]
    EmptyEgressId,
    #[error("Ingress id must not be empty")]
    EmptyIngressId,
    #[error("duplicate Ingress identity: {0}")]
    DuplicateIngress(String),
    #[error(
        "record generation {record_generation} is newer than snapshot generation {snapshot_generation}"
    )]
    RecordGenerationAhead {
        record_generation: u64,
        snapshot_generation: u64,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DenialReason {
    NotEnrolled,
    KeyMismatch,
    Disabled,
    Revoked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthorizationDecision {
    Authorized { generation: u64 },
    Denied(DenialReason),
}

#[derive(Debug, Clone)]
pub struct AuthorizationSnapshot {
    generation: u64,
    egress_id: EgressId,
    egress_public_key: [u8; 32],
    records: HashMap<IngressId, AuthorizationRecord>,
}

impl AuthorizationSnapshot {
    pub fn try_new(
        generation: u64,
        egress_id: EgressId,
        egress_public_key: [u8; 32],
        records: impl IntoIterator<Item = AuthorizationRecord>,
    ) -> Result<Self, AuthorizationSnapshotError> {
        if egress_id.as_str().is_empty() {
            return Err(AuthorizationSnapshotError::EmptyEgressId);
        }

        let mut indexed = HashMap::new();
        for record in records {
            if record.ingress_id.as_str().is_empty() {
                return Err(AuthorizationSnapshotError::EmptyIngressId);
            }
            if record.record_generation > generation {
                return Err(AuthorizationSnapshotError::RecordGenerationAhead {
                    record_generation: record.record_generation,
                    snapshot_generation: generation,
                });
            }
            let id = record.ingress_id.clone();
            if indexed.insert(id.clone(), record).is_some() {
                return Err(AuthorizationSnapshotError::DuplicateIngress(
                    id.as_str().to_owned(),
                ));
            }
        }

        Ok(Self {
            generation,
            egress_id,
            egress_public_key,
            records: indexed,
        })
    }

    pub const fn generation(&self) -> u64 {
        self.generation
    }

    pub fn egress_id(&self) -> &EgressId {
        &self.egress_id
    }

    pub const fn egress_public_key(&self) -> &[u8; 32] {
        &self.egress_public_key
    }

    pub fn authorize(
        &self,
        ingress_id: &IngressId,
        presented_key: &[u8; 32],
    ) -> AuthorizationDecision {
        let Some(record) = self.records.get(ingress_id) else {
            return AuthorizationDecision::Denied(DenialReason::NotEnrolled);
        };
        if &record.ingress_public_key != presented_key {
            return AuthorizationDecision::Denied(DenialReason::KeyMismatch);
        }
        match record.state {
            AuthorizationState::Enabled => AuthorizationDecision::Authorized {
                generation: self.generation,
            },
            AuthorizationState::Disabled => AuthorizationDecision::Denied(DenialReason::Disabled),
            AuthorizationState::Revoked => AuthorizationDecision::Denied(DenialReason::Revoked),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::future::{Future, pending, poll_fn};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::task::Poll;

    use super::*;

    struct CountingConnector {
        calls: Arc<AtomicUsize>,
        seen_targets: Mutex<Vec<TargetRequest>>,
        peers: Mutex<Vec<tokio::io::DuplexStream>>,
        failure: Option<TargetConnectError>,
        pending_first: bool,
    }

    impl CountingConnector {
        fn successful() -> Self {
            Self {
                calls: Arc::new(AtomicUsize::new(0)),
                seen_targets: Mutex::new(Vec::new()),
                peers: Mutex::new(Vec::new()),
                failure: None,
                pending_first: false,
            }
        }

        fn failing(error: TargetConnectError) -> Self {
            Self {
                failure: Some(error),
                ..Self::successful()
            }
        }

        fn pending_once() -> Self {
            Self {
                pending_first: true,
                ..Self::successful()
            }
        }

        fn call_count(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }

        fn seen_targets(&self) -> Vec<TargetRequest> {
            self.seen_targets.lock().expect("target log lock").clone()
        }
    }

    #[async_trait]
    impl TargetConnector for CountingConnector {
        async fn connect(
            &self,
            request: TargetRequest,
        ) -> Result<BoxedTargetConnection, TargetConnectError> {
            let ordinal = self.calls.fetch_add(1, Ordering::SeqCst);
            self.seen_targets
                .lock()
                .expect("target log lock")
                .push(request);
            if self.pending_first && ordinal == 0 {
                return pending().await;
            }
            if let Some(error) = &self.failure {
                return Err(error.clone());
            }

            let (egress_side, target_side) = tokio::io::duplex(64);
            self.peers
                .lock()
                .expect("target peers lock")
                .push(target_side);
            Ok(Box::new(egress_side))
        }
    }

    fn open_request(session: u128, stream: u64, request: u128) -> StreamOpenRequest {
        StreamOpenRequest {
            session_id: SessionId::new(session),
            stream_id: StreamId::new(stream).expect("test StreamID"),
            request_id: RequestId::new(request),
            target: TargetRequest {
                original_hostname: Some("service.example".into()),
                resolved_ip_candidates: vec![
                    "192.0.2.10".parse().expect("IPv4 candidate"),
                    "2001:db8::10".parse().expect("IPv6 candidate"),
                ],
                port: 443,
            },
        }
    }

    fn register_request_session(
        egress: &mut FakeEgress<CountingConnector>,
        request: &StreamOpenRequest,
    ) {
        egress.register_session(request.session_id);
    }

    #[tokio::test]
    async fn retry_on_another_path_replays_success_without_a_second_dial() {
        let mut egress = FakeEgress::new(CountingConnector::successful());
        let request = open_request(1, 7, 99);
        register_request_session(&mut egress, &request);
        let expected_target = request.target.clone();
        egress.lose_next_success_response();

        // Path A reaches Egress and the dial succeeds, but its response is lost.
        assert_eq!(
            egress.open_stream(request.clone()).await,
            Err(FakeEgressError::ResponseLost {
                session_id: request.session_id,
                request_id: request.request_id,
            })
        );
        assert_eq!(egress.connector().call_count(), 1);
        assert_eq!(egress.active_connection_count(), 1);
        assert_eq!(egress.cached_request_count(), 1);
        assert!(egress.owns_connection(request.session_id, request.stream_id));

        // Path B carries the identical retry and receives the committed result.
        assert_eq!(
            egress.open_stream(request).await,
            Ok(StreamOpenResponse {
                result: StreamOpenResult::Opened,
                replayed: true,
            })
        );
        assert_eq!(egress.connector().call_count(), 1);
        assert_eq!(egress.active_connection_count(), 1);
        assert_eq!(egress.connector().seen_targets(), vec![expected_target]);
    }

    #[tokio::test]
    async fn cancelling_a_pending_dial_leaves_the_stream_retryable() {
        let mut egress = FakeEgress::new(CountingConnector::pending_once());
        let request = open_request(1, 7, 99);
        register_request_session(&mut egress, &request);

        let mut first_attempt = Box::pin(egress.open_stream(request.clone()));
        let observed_pending = poll_fn(|context| {
            Poll::Ready(matches!(
                first_attempt.as_mut().poll(context),
                Poll::Pending
            ))
        })
        .await;
        assert!(observed_pending);
        drop(first_attempt);

        assert_eq!(egress.connector().call_count(), 1);
        assert_eq!(egress.cached_request_count(), 0);
        assert_eq!(egress.active_connection_count(), 0);
        assert_eq!(
            egress.open_stream(request).await,
            Ok(StreamOpenResponse {
                result: StreamOpenResult::Opened,
                replayed: false,
            })
        );
        assert_eq!(egress.connector().call_count(), 2);
        assert_eq!(egress.cached_request_count(), 1);
        assert_eq!(egress.active_connection_count(), 1);
    }

    #[tokio::test]
    async fn session_registration_is_idempotent_and_unknown_opens_are_rejected() {
        let mut egress = FakeEgress::new(CountingConnector::successful());
        let request = open_request(1, 7, 99);

        assert_eq!(
            egress.open_stream(request.clone()).await,
            Err(FakeEgressError::SessionNotActive {
                session_id: request.session_id,
            })
        );
        assert_eq!(egress.connector().call_count(), 0);
        assert_eq!(egress.active_session_count(), 0);

        egress.register_session(request.session_id);
        egress.register_session(request.session_id);
        assert_eq!(egress.active_session_count(), 1);
        assert_eq!(
            egress.open_stream(request).await,
            Ok(StreamOpenResponse {
                result: StreamOpenResult::Opened,
                replayed: false,
            })
        );
        assert_eq!(egress.connector().call_count(), 1);
    }

    #[tokio::test]
    async fn conflicting_request_id_reuse_is_rejected_before_dialing() {
        let mut egress = FakeEgress::new(CountingConnector::successful());
        let request = open_request(1, 7, 99);
        register_request_session(&mut egress, &request);
        assert_eq!(
            egress.open_stream(request.clone()).await,
            Ok(StreamOpenResponse {
                result: StreamOpenResult::Opened,
                replayed: false,
            })
        );

        let mut conflicting = request.clone();
        conflicting.target.port = 8443;
        assert_eq!(
            egress.open_stream(conflicting).await,
            Err(FakeEgressError::ConflictingRequestId {
                session_id: request.session_id,
                request_id: request.request_id,
            })
        );
        assert_eq!(egress.connector().call_count(), 1);
        assert_eq!(egress.active_connection_count(), 1);
    }

    #[tokio::test]
    async fn a_stream_cannot_be_reopened_under_a_new_request_id() {
        let mut egress = FakeEgress::new(CountingConnector::successful());
        let request = open_request(1, 7, 99);
        register_request_session(&mut egress, &request);
        egress
            .open_stream(request.clone())
            .await
            .expect("first open");

        let mut duplicate_stream = request.clone();
        duplicate_stream.request_id = RequestId::new(100);
        assert_eq!(
            egress.open_stream(duplicate_stream).await,
            Err(FakeEgressError::StreamAlreadyOpen {
                session_id: request.session_id,
                stream_id: request.stream_id,
            })
        );
        assert_eq!(egress.connector().call_count(), 1);
    }

    #[tokio::test]
    async fn failed_open_still_reserves_the_stream_id() {
        let failure = TargetConnectError::Connection("refused".into());
        let mut egress = FakeEgress::new(CountingConnector::failing(failure));
        let request = open_request(1, 7, 99);
        register_request_session(&mut egress, &request);
        egress
            .open_stream(request.clone())
            .await
            .expect("target failure is a cached protocol result");

        let mut reused_stream = request.clone();
        reused_stream.request_id = RequestId::new(100);
        assert_eq!(
            egress.open_stream(reused_stream).await,
            Err(FakeEgressError::StreamAlreadyOpen {
                session_id: request.session_id,
                stream_id: request.stream_id,
            })
        );
        assert_eq!(egress.connector().call_count(), 1);
    }

    #[tokio::test]
    async fn target_failure_is_cached_for_identical_retries() {
        let failure = TargetConnectError::Connection("connection refused".into());
        let mut egress = FakeEgress::new(CountingConnector::failing(failure.clone()));
        let request = open_request(1, 7, 99);
        register_request_session(&mut egress, &request);

        assert_eq!(
            egress.open_stream(request.clone()).await,
            Ok(StreamOpenResponse {
                result: StreamOpenResult::TargetFailure(failure.clone()),
                replayed: false,
            })
        );
        assert_eq!(
            egress.open_stream(request).await,
            Ok(StreamOpenResponse {
                result: StreamOpenResult::TargetFailure(failure),
                replayed: true,
            })
        );
        assert_eq!(egress.connector().call_count(), 1);
        assert_eq!(egress.active_connection_count(), 0);
    }

    #[tokio::test]
    async fn request_id_cache_is_scoped_to_one_session() {
        let mut egress = FakeEgress::new(CountingConnector::successful());
        let first = open_request(1, 7, 99);
        let second = open_request(2, 7, 99);
        register_request_session(&mut egress, &first);
        register_request_session(&mut egress, &second);

        egress.open_stream(first).await.expect("first Session open");
        egress
            .open_stream(second)
            .await
            .expect("second Session open");

        assert_eq!(egress.connector().call_count(), 2);
        assert_eq!(egress.active_connection_count(), 2);
        assert_eq!(egress.cached_request_count(), 2);
    }

    #[tokio::test]
    async fn closing_a_session_drops_its_connections_and_cached_results() {
        let mut egress = FakeEgress::new(CountingConnector::successful());
        let first = open_request(1, 7, 99);
        let second = open_request(2, 7, 99);
        register_request_session(&mut egress, &first);
        register_request_session(&mut egress, &second);
        egress
            .open_stream(first.clone())
            .await
            .expect("first Session open");
        egress
            .open_stream(second.clone())
            .await
            .expect("second Session open");

        assert_eq!(egress.close_session(first.session_id), 1);
        assert!(!egress.owns_connection(first.session_id, first.stream_id));
        assert!(egress.owns_connection(second.session_id, second.stream_id));
        assert_eq!(egress.active_session_count(), 1);
        assert_eq!(egress.active_connection_count(), 1);
        assert_eq!(egress.cached_request_count(), 1);
    }

    #[tokio::test]
    async fn closed_session_rejects_a_delayed_open_without_redialing() {
        let mut egress = FakeEgress::new(CountingConnector::successful());
        let request = open_request(1, 7, 99);
        register_request_session(&mut egress, &request);
        egress
            .open_stream(request.clone())
            .await
            .expect("initial open");
        assert_eq!(egress.close_session(request.session_id), 1);

        assert_eq!(
            egress.open_stream(request.clone()).await,
            Err(FakeEgressError::SessionNotActive {
                session_id: request.session_id,
            })
        );
        assert_eq!(egress.connector().call_count(), 1);
        assert_eq!(egress.active_session_count(), 0);
        assert_eq!(egress.active_connection_count(), 0);
        assert_eq!(egress.cached_request_count(), 0);
    }

    #[tokio::test]
    async fn closing_a_stream_drops_its_socket_but_retains_idempotency() {
        let mut egress = FakeEgress::new(CountingConnector::successful());
        let request = open_request(1, 7, 99);
        register_request_session(&mut egress, &request);
        egress
            .open_stream(request.clone())
            .await
            .expect("initial open");

        assert!(egress.close_stream(request.session_id, request.stream_id));
        assert_eq!(egress.active_connection_count(), 0);
        assert_eq!(egress.cached_request_count(), 1);
        assert_eq!(
            egress.open_stream(request).await,
            Ok(StreamOpenResponse {
                result: StreamOpenResult::Opened,
                replayed: true,
            })
        );
        assert_eq!(egress.connector().call_count(), 1);
        assert_eq!(egress.active_connection_count(), 0);
    }

    #[tokio::test]
    async fn invalid_target_is_cached_without_calling_the_connector() {
        let mut egress = FakeEgress::new(CountingConnector::successful());
        let mut request = open_request(1, 7, 99);
        register_request_session(&mut egress, &request);
        request.target.original_hostname = None;
        request.target.resolved_ip_candidates.clear();

        assert_eq!(
            egress.open_stream(request.clone()).await,
            Ok(StreamOpenResponse {
                result: StreamOpenResult::TargetFailure(TargetConnectError::MissingDestination),
                replayed: false,
            })
        );
        assert_eq!(
            egress.open_stream(request).await,
            Ok(StreamOpenResponse {
                result: StreamOpenResult::TargetFailure(TargetConnectError::MissingDestination),
                replayed: true,
            })
        );
        assert_eq!(egress.connector().call_count(), 0);
    }

    fn record(state: AuthorizationState) -> AuthorizationRecord {
        AuthorizationRecord {
            ingress_id: IngressId::new("ingress-1"),
            ingress_public_key: [7; 32],
            state,
            administrator_labels: BTreeMap::new(),
            record_generation: 3,
        }
    }

    #[test]
    fn enabled_identity_requires_the_enrolled_key() {
        let snapshot = AuthorizationSnapshot::try_new(
            3,
            EgressId::new("egress-1"),
            [9; 32],
            [record(AuthorizationState::Enabled)],
        )
        .expect("valid snapshot");

        assert_eq!(
            snapshot.authorize(&IngressId::new("ingress-1"), &[7; 32]),
            AuthorizationDecision::Authorized { generation: 3 }
        );
        assert_eq!(
            snapshot.authorize(&IngressId::new("ingress-1"), &[8; 32]),
            AuthorizationDecision::Denied(DenialReason::KeyMismatch)
        );
    }

    #[test]
    fn disabled_and_revoked_are_hard_denials() {
        for (state, reason) in [
            (AuthorizationState::Disabled, DenialReason::Disabled),
            (AuthorizationState::Revoked, DenialReason::Revoked),
        ] {
            let snapshot = AuthorizationSnapshot::try_new(
                4,
                EgressId::new("egress-1"),
                [9; 32],
                [record(state)],
            )
            .expect("valid snapshot");
            assert_eq!(
                snapshot.authorize(&IngressId::new("ingress-1"), &[7; 32]),
                AuthorizationDecision::Denied(reason)
            );
        }
    }

    #[test]
    fn snapshot_rejects_duplicate_identity_records() {
        let duplicate = record(AuthorizationState::Enabled);
        assert!(matches!(
            AuthorizationSnapshot::try_new(
                3,
                EgressId::new("egress-1"),
                [9; 32],
                [duplicate.clone(), duplicate]
            ),
            Err(AuthorizationSnapshotError::DuplicateIngress(_))
        ));
    }
}
