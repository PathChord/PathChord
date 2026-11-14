//! Bounded UDP Association ownership with one stable target socket per identity.

use std::collections::{BTreeSet, HashMap, VecDeque};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use pathchord_core::{
    ErrorClass, MAX_VARINT, Message, ProtocolLimits, TargetEndpoint, UdpClose, UdpDatagram,
    UdpOpen, UdpOpenErr, UdpOpenOk,
};
use thiserror::Error;
use tokio::time::Instant;

const MAX_RECENT_DATAGRAM_SEQUENCES: usize = 256;
/// Time allowed for outstanding UDP exchanges when the peer closes an Association.
pub const DEFAULT_UDP_DRAIN_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_UDP_DRAIN_TIMEOUT: Duration = Duration::from_secs(60);

#[derive(Debug, Clone, Error, PartialEq, Eq)]
#[error("UDP target failed with {error:?}")]
pub struct UdpTargetError {
    pub error: ErrorClass,
    pub reason: Vec<u8>,
}

impl UdpTargetError {
    #[must_use]
    pub fn new(error: ErrorClass, reason: impl Into<Vec<u8>>) -> Self {
        Self {
            error,
            reason: reason.into(),
        }
    }
}

#[async_trait]
pub trait UdpTargetSocket: Send {
    fn target_visible_port(&self) -> u16;

    async fn send_datagram(&mut self, payload: &[u8]) -> Result<(), UdpTargetError>;

    async fn receive_datagram(&mut self, maximum: usize) -> Result<Vec<u8>, UdpTargetError>;
}

pub type BoxedUdpTargetSocket = Box<dyn UdpTargetSocket>;

#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum SessionUdpError {
    #[error("Session UDP route is unavailable")]
    Unavailable,
    #[error("Session UDP exchange failed")]
    Exchange,
    #[error("Session UDP response exceeds the configured bound")]
    ResponseTooLarge,
}

/// Ingress-side datagram interface implemented by a live Session UDP owner.
/// One call preserves exactly one request and one response datagram boundary.
#[async_trait]
pub trait SessionUdpHandle: Send + Sync {
    async fn exchange_datagram(
        &self,
        target: TargetEndpoint,
        request: Vec<u8>,
        maximum_response: usize,
    ) -> Result<Vec<u8>, SessionUdpError>;
}

#[async_trait]
pub trait UdpTargetFactory: Send + Sync {
    async fn open(&self, target: TargetEndpoint) -> Result<BoxedUdpTargetSocket, UdpTargetError>;
}

#[async_trait]
impl<T> UdpTargetFactory for Arc<T>
where
    T: UdpTargetFactory + ?Sized,
{
    async fn open(&self, target: TargetEndpoint) -> Result<BoxedUdpTargetSocket, UdpTargetError> {
        (**self).open(target).await
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct UdpAssociationSnapshot {
    pub active_associations: usize,
    pub draining_associations: usize,
    pub queued_datagrams: usize,
    pub queued_bytes: usize,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum UdpRuntimeError {
    #[error("UDP Association capacity is exhausted")]
    AssociationLimit,
    #[error("UDP target queue is full ({capacity} bytes)")]
    QueueFull { capacity: usize },
    #[error("UDP Association {0} conflicts with an existing target")]
    AssociationConflict(u64),
    #[error("UDP Association {0} is not open")]
    UnknownAssociation(u64),
    #[error("UDP frame is not handled by the Association runtime")]
    UnexpectedMessage,
    #[error("UDP payload exceeds the negotiated frame limit")]
    PayloadTooLarge,
    #[error("UDP sequence space is exhausted")]
    SequenceExhausted,
    #[error("UDP target returned an invalid visible port")]
    InvalidVisiblePort,
    #[error("UDP Association drain timeout is outside the allowed bounds")]
    InvalidDrainTimeout,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AssociationState {
    Open,
    Draining { deadline: Instant },
}

struct Association {
    target: TargetEndpoint,
    socket: BoxedUdpTargetSocket,
    state: AssociationState,
    recent_ingress_sequences: BTreeSet<u64>,
    next_egress_sequence: u64,
    queued: VecDeque<UdpDatagram>,
    queued_bytes: usize,
}

pub struct UdpAssociationRuntime<F> {
    factory: F,
    limits: ProtocolLimits,
    max_associations: usize,
    max_queued_bytes: usize,
    queued_bytes: usize,
    associations: HashMap<u64, Association>,
}

impl<F> std::fmt::Debug for UdpAssociationRuntime<F>
where
    F: UdpTargetFactory,
{
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("UdpAssociationRuntime")
            .field("limits", &self.limits)
            .field("max_associations", &self.max_associations)
            .field("max_queued_bytes", &self.max_queued_bytes)
            .field("snapshot", &self.snapshot())
            .finish_non_exhaustive()
    }
}

impl<F> UdpAssociationRuntime<F>
where
    F: UdpTargetFactory,
{
    pub fn new(
        factory: F,
        limits: ProtocolLimits,
        max_associations: usize,
        max_queued_bytes: usize,
    ) -> Result<Self, UdpRuntimeError> {
        if max_associations == 0 || max_queued_bytes == 0 {
            return Err(UdpRuntimeError::AssociationLimit);
        }
        Ok(Self {
            factory,
            limits,
            max_associations,
            max_queued_bytes,
            queued_bytes: 0,
            associations: HashMap::new(),
        })
    }

    #[must_use]
    pub fn snapshot(&self) -> UdpAssociationSnapshot {
        UdpAssociationSnapshot {
            active_associations: self.associations.len(),
            draining_associations: self
                .associations
                .values()
                .filter(|association| {
                    matches!(association.state, AssociationState::Draining { .. })
                })
                .count(),
            queued_datagrams: self
                .associations
                .values()
                .map(|association| association.queued.len())
                .sum(),
            queued_bytes: self.queued_bytes,
        }
    }

    #[must_use]
    pub fn target(&self, association_id: u64) -> Option<&TargetEndpoint> {
        self.associations
            .get(&association_id)
            .map(|association| &association.target)
    }

    #[must_use]
    pub fn association_ids(&self) -> Vec<u64> {
        let mut ids: Vec<_> = self.associations.keys().copied().collect();
        ids.sort_unstable();
        ids
    }

    #[must_use]
    pub fn is_draining(&self, association_id: u64) -> bool {
        self.associations
            .get(&association_id)
            .is_some_and(|association| {
                matches!(association.state, AssociationState::Draining { .. })
            })
    }

    /// Stops new datagrams while retaining already accepted exchanges until
    /// they complete or the bounded grace period expires. Repeated requests
    /// cannot extend a deadline. Closing an absent Association is idempotent.
    pub fn begin_drain(
        &mut self,
        association_id: u64,
        timeout: Duration,
    ) -> Result<(), UdpRuntimeError> {
        if timeout.is_zero() || timeout > MAX_UDP_DRAIN_TIMEOUT {
            return Err(UdpRuntimeError::InvalidDrainTimeout);
        }
        let deadline = Instant::now() + timeout;
        if let Some(association) = self.associations.get_mut(&association_id) {
            association.state = match association.state {
                AssociationState::Open => AssociationState::Draining { deadline },
                AssociationState::Draining { deadline: current } => AssociationState::Draining {
                    deadline: current.min(deadline),
                },
            };
        }
        Ok(())
    }

    /// Removes Associations whose accepted exchanges and queues are complete,
    /// or whose drain deadline has elapsed. The owner calls this after handing
    /// dequeued datagrams to its own sender; returned IDs may be used to retire
    /// related scheduling metadata.
    pub fn reap_draining(&mut self) -> Vec<u64> {
        let now = Instant::now();
        let mut closed = Vec::new();
        self.associations.retain(|id, association| {
            let finished = match association.state {
                AssociationState::Open => false,
                AssociationState::Draining { deadline } => {
                    now >= deadline || association.queued.is_empty()
                }
            };
            if finished {
                self.queued_bytes -= association.queued_bytes;
                closed.push(*id);
            }
            !finished
        });
        closed.sort_unstable();
        closed
    }

    pub async fn handle(&mut self, message: Message) -> Result<Vec<Message>, UdpRuntimeError> {
        match message {
            Message::UdpOpen(open) => self.open(open).await.map(|message| vec![message]),
            Message::UdpDatagram(datagram) => self.send(datagram).await,
            Message::UdpClose(close) => {
                self.begin_drain(close.association_id, DEFAULT_UDP_DRAIN_TIMEOUT)?;
                Ok(Vec::new())
            }
            _ => Err(UdpRuntimeError::UnexpectedMessage),
        }
    }

    pub async fn receive_from_target(
        &mut self,
        association_id: u64,
    ) -> Result<Vec<Message>, UdpRuntimeError> {
        let received = {
            let association = self
                .associations
                .get_mut(&association_id)
                .ok_or(UdpRuntimeError::UnknownAssociation(association_id))?;
            if matches!(association.state, AssociationState::Draining { .. }) {
                return Ok(Vec::new());
            }
            association
                .socket
                .receive_datagram(self.limits.max_frame_payload())
                .await
        };
        let payload = match received {
            Ok(payload) => payload,
            Err(mut error) => {
                error.reason.truncate(self.limits.max_control_payload());
                self.close(association_id)?;
                return Ok(vec![Message::UdpClose(UdpClose {
                    association_id,
                    error: error.error,
                    reason: error.reason,
                })]);
            }
        };
        if payload.len() > self.limits.max_frame_payload() {
            return Err(UdpRuntimeError::PayloadTooLarge);
        }
        if self.queued_bytes.saturating_add(payload.len()) > self.max_queued_bytes {
            return Err(UdpRuntimeError::QueueFull {
                capacity: self.max_queued_bytes,
            });
        }
        let association = self
            .associations
            .get_mut(&association_id)
            .ok_or(UdpRuntimeError::UnknownAssociation(association_id))?;
        let datagram_seq = association.next_egress_sequence;
        if datagram_seq > MAX_VARINT {
            return Err(UdpRuntimeError::SequenceExhausted);
        }
        association.next_egress_sequence = datagram_seq
            .checked_add(1)
            .ok_or(UdpRuntimeError::SequenceExhausted)?;
        association.queued_bytes += payload.len();
        self.queued_bytes += payload.len();
        association.queued.push_back(UdpDatagram {
            association_id,
            datagram_seq,
            payload,
        });
        Ok(Vec::new())
    }

    pub fn dequeue(&mut self, association_id: u64) -> Result<Option<Message>, UdpRuntimeError> {
        if self.associations.get(&association_id).is_some_and(|association| {
            matches!(association.state, AssociationState::Draining { deadline } if Instant::now() >= deadline)
        }) {
            // The owner's next reap returns the closed ID so it can retire
            // its corresponding scheduling state as well.
            return Ok(None);
        }
        let association = self
            .associations
            .get_mut(&association_id)
            .ok_or(UdpRuntimeError::UnknownAssociation(association_id))?;
        let Some(datagram) = association.queued.pop_front() else {
            return Ok(None);
        };
        association.queued_bytes -= datagram.payload.len();
        self.queued_bytes -= datagram.payload.len();
        Ok(Some(Message::UdpDatagram(datagram)))
    }

    pub fn close(&mut self, association_id: u64) -> Result<(), UdpRuntimeError> {
        if let Some(association) = self.associations.remove(&association_id) {
            self.queued_bytes -= association.queued_bytes;
        }
        Ok(())
    }

    pub fn close_all(&mut self) {
        self.associations.clear();
        self.queued_bytes = 0;
    }

    async fn open(&mut self, open: UdpOpen) -> Result<Message, UdpRuntimeError> {
        if open.association_id > MAX_VARINT {
            return Err(UdpRuntimeError::SequenceExhausted);
        }
        if let Some(existing) = self.associations.get(&open.association_id) {
            if matches!(existing.state, AssociationState::Draining { .. }) {
                return Ok(Message::UdpOpenErr(UdpOpenErr {
                    association_id: open.association_id,
                    error: ErrorClass::EgressFailure,
                    reason: b"UDP Association is draining".to_vec(),
                }));
            }
            if existing.target == open.target {
                return Ok(Message::UdpOpenOk(UdpOpenOk {
                    association_id: open.association_id,
                    target_visible_port: existing.socket.target_visible_port(),
                }));
            }
            return Ok(Message::UdpOpenErr(UdpOpenErr {
                association_id: open.association_id,
                error: ErrorClass::EgressFailure,
                reason: b"UDP Association target conflicts with an existing identity".to_vec(),
            }));
        }
        if self.associations.len() >= self.max_associations {
            return Ok(Message::UdpOpenErr(UdpOpenErr {
                association_id: open.association_id,
                error: ErrorClass::EgressFailure,
                reason: b"UDP Association capacity is exhausted".to_vec(),
            }));
        }
        let socket = match self.factory.open(open.target.clone()).await {
            Ok(socket) => socket,
            Err(mut error) => {
                error.reason.truncate(self.limits.max_control_payload());
                return Ok(Message::UdpOpenErr(UdpOpenErr {
                    association_id: open.association_id,
                    error: error.error,
                    reason: error.reason,
                }));
            }
        };
        let target_visible_port = socket.target_visible_port();
        if target_visible_port == 0 {
            return Err(UdpRuntimeError::InvalidVisiblePort);
        }
        self.associations.insert(
            open.association_id,
            Association {
                target: open.target,
                socket,
                state: AssociationState::Open,
                recent_ingress_sequences: BTreeSet::new(),
                next_egress_sequence: 0,
                queued: VecDeque::new(),
                queued_bytes: 0,
            },
        );
        Ok(Message::UdpOpenOk(UdpOpenOk {
            association_id: open.association_id,
            target_visible_port,
        }))
    }

    async fn send(&mut self, datagram: UdpDatagram) -> Result<Vec<Message>, UdpRuntimeError> {
        if datagram.datagram_seq > MAX_VARINT {
            return Err(UdpRuntimeError::SequenceExhausted);
        }
        if datagram.payload.len() > self.limits.max_frame_payload() {
            return Err(UdpRuntimeError::PayloadTooLarge);
        }
        let Some(association) = self.associations.get_mut(&datagram.association_id) else {
            return Ok(vec![Message::UdpClose(UdpClose {
                association_id: datagram.association_id,
                error: ErrorClass::PathFailure,
                reason: b"UDP Association is not open".to_vec(),
            })]);
        };
        if matches!(association.state, AssociationState::Draining { .. }) {
            // UDP traffic is not reliable; refusing a new datagram must not
            // terminate the surrounding Session while this Association drains.
            return Ok(Vec::new());
        }
        if association
            .recent_ingress_sequences
            .contains(&datagram.datagram_seq)
        {
            return Ok(Vec::new());
        }
        if let Err(mut error) = association.socket.send_datagram(&datagram.payload).await {
            error.reason.truncate(self.limits.max_control_payload());
            let close = Message::UdpClose(UdpClose {
                association_id: datagram.association_id,
                error: error.error,
                reason: error.reason,
            });
            self.close(datagram.association_id)?;
            return Ok(vec![close]);
        }
        association
            .recent_ingress_sequences
            .insert(datagram.datagram_seq);
        while association.recent_ingress_sequences.len() > MAX_RECENT_DATAGRAM_SEQUENCES {
            association.recent_ingress_sequences.pop_first();
        }
        Ok(Vec::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::{Arc, Mutex};

    #[derive(Default)]
    struct FakeSocketState {
        sent: Vec<Vec<u8>>,
        incoming: VecDeque<Vec<u8>>,
    }

    struct FakeSocket {
        state: Arc<Mutex<FakeSocketState>>,
    }

    #[async_trait]
    impl UdpTargetSocket for FakeSocket {
        fn target_visible_port(&self) -> u16 {
            53000
        }

        async fn send_datagram(&mut self, payload: &[u8]) -> Result<(), UdpTargetError> {
            self.state
                .lock()
                .expect("fake socket lock")
                .sent
                .push(payload.to_vec());
            Ok(())
        }

        async fn receive_datagram(&mut self, _maximum: usize) -> Result<Vec<u8>, UdpTargetError> {
            self.state
                .lock()
                .expect("fake socket lock")
                .incoming
                .pop_front()
                .ok_or_else(|| {
                    UdpTargetError::new(ErrorClass::TargetFailure, b"empty fake socket".to_vec())
                })
        }
    }

    #[derive(Clone)]
    struct FakeFactory {
        state: Arc<Mutex<FakeSocketState>>,
    }

    #[async_trait]
    impl UdpTargetFactory for FakeFactory {
        async fn open(
            &self,
            _target: TargetEndpoint,
        ) -> Result<BoxedUdpTargetSocket, UdpTargetError> {
            Ok(Box::new(FakeSocket {
                state: Arc::clone(&self.state),
            }))
        }
    }

    fn target() -> TargetEndpoint {
        TargetEndpoint {
            hostname: b"dns.test".to_vec(),
            port: 53,
            resolved_addresses: vec![IpAddr::V4(Ipv4Addr::LOCALHOST)],
        }
    }

    #[tokio::test]
    async fn association_preserves_datagram_boundaries_and_socket_identity() {
        let state = Arc::new(Mutex::new(FakeSocketState::default()));
        let factory = FakeFactory {
            state: Arc::clone(&state),
        };
        let mut runtime =
            UdpAssociationRuntime::new(factory, ProtocolLimits::default(), 4, 1024).unwrap();
        assert_eq!(
            runtime
                .handle(Message::UdpOpen(UdpOpen {
                    association_id: 7,
                    target_flags: 3,
                    target: target(),
                }))
                .await
                .unwrap(),
            vec![Message::UdpOpenOk(UdpOpenOk {
                association_id: 7,
                target_visible_port: 53000,
            })]
        );
        runtime
            .handle(Message::UdpDatagram(UdpDatagram {
                association_id: 7,
                datagram_seq: 2,
                payload: b"second".to_vec(),
            }))
            .await
            .unwrap();
        runtime
            .handle(Message::UdpDatagram(UdpDatagram {
                association_id: 7,
                datagram_seq: 1,
                payload: b"first".to_vec(),
            }))
            .await
            .unwrap();
        runtime
            .handle(Message::UdpDatagram(UdpDatagram {
                association_id: 7,
                datagram_seq: 1,
                payload: b"duplicate".to_vec(),
            }))
            .await
            .unwrap();
        assert_eq!(
            state.lock().unwrap().sent,
            vec![b"second".to_vec(), b"first".to_vec()]
        );
        state
            .lock()
            .unwrap()
            .incoming
            .extend([b"reply-one".to_vec(), b"reply-two".to_vec()]);
        runtime.receive_from_target(7).await.unwrap();
        runtime.receive_from_target(7).await.unwrap();
        assert_eq!(
            runtime.dequeue(7).unwrap(),
            Some(Message::UdpDatagram(UdpDatagram {
                association_id: 7,
                datagram_seq: 0,
                payload: b"reply-one".to_vec(),
            }))
        );
        assert_eq!(
            runtime.dequeue(7).unwrap(),
            Some(Message::UdpDatagram(UdpDatagram {
                association_id: 7,
                datagram_seq: 1,
                payload: b"reply-two".to_vec(),
            }))
        );
        runtime
            .handle(Message::UdpClose(UdpClose {
                association_id: 7,
                error: ErrorClass::PathFailure,
                reason: Vec::new(),
            }))
            .await
            .unwrap();
        assert!(runtime.is_draining(7));
        assert_eq!(runtime.reap_draining(), vec![7]);
        assert_eq!(runtime.snapshot().active_associations, 0);
    }

    #[tokio::test(start_paused = true)]
    async fn draining_rejects_new_requests_and_delivers_accepted_responses() {
        let state = Arc::new(Mutex::new(FakeSocketState::default()));
        let mut runtime = UdpAssociationRuntime::new(
            FakeFactory {
                state: Arc::clone(&state),
            },
            ProtocolLimits::default(),
            1,
            1024,
        )
        .unwrap();
        let open = UdpOpen {
            association_id: 7,
            target_flags: 3,
            target: target(),
        };
        runtime
            .handle(Message::UdpOpen(open.clone()))
            .await
            .unwrap();
        runtime
            .handle(Message::UdpDatagram(UdpDatagram {
                association_id: 7,
                datagram_seq: 1,
                payload: b"accepted".to_vec(),
            }))
            .await
            .unwrap();
        state.lock().unwrap().incoming.push_back(b"reply".to_vec());
        runtime.receive_from_target(7).await.unwrap();
        runtime.begin_drain(7, Duration::from_secs(3)).unwrap();
        assert_eq!(runtime.snapshot().draining_associations, 1);
        runtime
            .handle(Message::UdpDatagram(UdpDatagram {
                association_id: 7,
                datagram_seq: 2,
                payload: b"too late".to_vec(),
            }))
            .await
            .unwrap();
        assert_eq!(state.lock().unwrap().sent, vec![b"accepted".to_vec()]);
        assert!(matches!(
            runtime
                .handle(Message::UdpOpen(open))
                .await
                .unwrap()
                .as_slice(),
            [Message::UdpOpenErr(_)]
        ));
        assert!(runtime.reap_draining().is_empty());
        // New target datagrams are not admitted after draining begins.
        state
            .lock()
            .unwrap()
            .incoming
            .push_back(b"too late".to_vec());
        runtime.receive_from_target(7).await.unwrap();
        assert_eq!(state.lock().unwrap().incoming.len(), 1);
        assert!(
            runtime.reap_draining().is_empty(),
            "queued response must be sent first"
        );
        assert!(matches!(
            runtime.dequeue(7).unwrap(),
            Some(Message::UdpDatagram(_))
        ));
        assert_eq!(runtime.reap_draining(), vec![7]);
        assert_eq!(runtime.snapshot().queued_bytes, 0);
    }

    #[tokio::test(start_paused = true)]
    async fn drain_deadline_drops_remaining_work_and_cannot_be_extended() {
        let state = Arc::new(Mutex::new(FakeSocketState::default()));
        let mut runtime = UdpAssociationRuntime::new(
            FakeFactory {
                state: Arc::clone(&state),
            },
            ProtocolLimits::default(),
            1,
            1024,
        )
        .unwrap();
        runtime
            .handle(Message::UdpOpen(UdpOpen {
                association_id: 1,
                target_flags: 3,
                target: target(),
            }))
            .await
            .unwrap();
        runtime
            .handle(Message::UdpDatagram(UdpDatagram {
                association_id: 1,
                datagram_seq: 1,
                payload: b"request".to_vec(),
            }))
            .await
            .unwrap();
        state.lock().unwrap().incoming.push_back(b"queued".to_vec());
        runtime.receive_from_target(1).await.unwrap();
        assert_eq!(runtime.snapshot().queued_bytes, 6);
        runtime.begin_drain(1, Duration::from_secs(1)).unwrap();
        runtime.begin_drain(1, Duration::from_secs(5)).unwrap();
        assert_eq!(
            runtime.begin_drain(1, Duration::ZERO),
            Err(UdpRuntimeError::InvalidDrainTimeout)
        );
        tokio::time::advance(Duration::from_secs(1)).await;
        assert_eq!(runtime.reap_draining(), vec![1]);
        assert_eq!(runtime.snapshot().active_associations, 0);
        assert_eq!(runtime.snapshot().queued_bytes, 0);
    }

    #[tokio::test]
    async fn target_queue_is_bounded_without_merging_datagrams() {
        let state = Arc::new(Mutex::new(FakeSocketState::default()));
        state.lock().unwrap().incoming.push_back(b"12345".to_vec());
        let mut runtime = UdpAssociationRuntime::new(
            FakeFactory {
                state: Arc::clone(&state),
            },
            ProtocolLimits::default(),
            1,
            4,
        )
        .unwrap();
        runtime
            .handle(Message::UdpOpen(UdpOpen {
                association_id: 1,
                target_flags: 3,
                target: target(),
            }))
            .await
            .unwrap();
        assert_eq!(
            runtime.receive_from_target(1).await,
            Err(UdpRuntimeError::QueueFull { capacity: 4 })
        );
        assert_eq!(runtime.snapshot().queued_bytes, 0);
    }
}
