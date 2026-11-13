use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use async_trait::async_trait;
use pathchord_core::{
    ErrorClass, PathId, PathReady, ProtocolLimits, RequestId, SessionId, StreamId, StreamOpen,
    TargetEndpoint,
};
use pathchord_egress::{
    BoxedTargetConnection, FakeEgress, FakeEgressError, StreamOpenRequest, StreamOpenResult,
    TargetConnectError, TargetConnector, TargetRequest,
};
use pathchord_noise::{WIRE_PROFILE_V1_PROLOGUE_PREFIX, generate_static_keypair};
use pathchord_path::{
    AuthorizationState, PathAuthorization, SinglePathHandshakeConfig, SinglePathOutcome,
    StreamOpenDecision, StreamOpener, establish_single_path,
};

#[derive(Clone, Debug, Default)]
struct CountingConnector {
    calls: Arc<AtomicUsize>,
}

impl CountingConnector {
    fn calls(&self) -> usize {
        self.calls.load(Ordering::Relaxed)
    }
}

#[async_trait]
impl TargetConnector for CountingConnector {
    async fn connect(
        &self,
        _request: TargetRequest,
    ) -> Result<BoxedTargetConnection, TargetConnectError> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        let (stream, _peer) = tokio::io::duplex(128);
        Ok(Box::new(stream))
    }
}

struct FakeEgressOpener {
    egress: FakeEgress<CountingConnector>,
    session_id: SessionId,
}

#[async_trait]
impl StreamOpener for FakeEgressOpener {
    type Error = FakeEgressError;

    async fn open_stream(
        &mut self,
        request: StreamOpen,
    ) -> Result<StreamOpenDecision, Self::Error> {
        let target = TargetRequest {
            original_hostname: if request.target.hostname.is_empty() {
                None
            } else {
                Some(String::from_utf8(request.target.hostname).expect("UTF-8 hostname"))
            },
            resolved_ip_candidates: request.target.resolved_addresses,
            port: request.target.port,
        };
        let response = self
            .egress
            .open_stream(StreamOpenRequest {
                session_id: self.session_id,
                stream_id: request.stream_id,
                request_id: request.request_id,
                target,
            })
            .await?;
        Ok(match response.result {
            StreamOpenResult::Opened => StreamOpenDecision::Opened {
                metadata: b"fake-target-open".to_vec(),
            },
            StreamOpenResult::TargetFailure(error) => StreamOpenDecision::Rejected {
                error: ErrorClass::TargetFailure,
                reason: error.to_string().into_bytes(),
            },
        })
    }
}

fn handshake_config() -> SinglePathHandshakeConfig {
    let mut prologue = WIRE_PROFILE_V1_PROLOGUE_PREFIX.to_vec();
    prologue.extend_from_slice(b"egress-test");
    SinglePathHandshakeConfig {
        egress_identity: prologue,
        egress_id: b"egress-test".to_vec(),
        ingress_id: b"ingress-test".to_vec(),
        session_id: SessionId::new(41),
        path_id: PathId::new(42),
        offered_capabilities: 1,
        required_capabilities: 1,
        supported_capabilities: 1,
        local_limits: ProtocolLimits::default(),
        ready_limits: PathReady {
            max_frame_payload: 60 * 1024,
            max_control_payload: 4 * 1024,
            max_session_buffering: 16 * 1024 * 1024,
        },
    }
}

fn admitted_path() -> pathchord_path::SinglePathReady {
    let initiator = generate_static_keypair().expect("initiator key");
    let responder = generate_static_keypair().expect("responder key");
    let config = handshake_config();
    let authorization = PathAuthorization {
        ingress_id: config.ingress_id.clone(),
        public_key: *initiator.public(),
        state: AuthorizationState::Enabled,
        generation: 3,
    };
    let outcome = establish_single_path(
        initiator.private(),
        responder.private(),
        responder.public(),
        &config,
        &authorization,
    )
    .expect("single-Path admission");
    let SinglePathOutcome::Ready(ready) = outcome else {
        panic!("expected PATH_READY");
    };
    *ready
}

fn request() -> StreamOpen {
    StreamOpen {
        stream_id: StreamId::new(7).expect("stream id"),
        request_id: RequestId::new(8),
        target: TargetEndpoint {
            hostname: b"target.example".to_vec(),
            port: 443,
            resolved_addresses: Vec::new(),
        },
    }
}

#[tokio::test]
async fn routes_stream_open_to_fake_egress_and_replays_without_redial() {
    let mut path = admitted_path();
    let connector = CountingConnector::default();
    let mut opener = FakeEgressOpener {
        egress: FakeEgress::new(connector.clone()),
        session_id: SessionId::new(41),
    };
    opener.egress.register_session(SessionId::new(41));
    let open = request();

    let first = path
        .open_stream(&mut opener, open.clone())
        .await
        .expect("first stream open");
    assert_eq!(
        first,
        StreamOpenDecision::Opened {
            metadata: b"fake-target-open".to_vec(),
        }
    );
    assert_eq!(connector.calls(), 1);
    assert_eq!(opener.egress.active_connection_count(), 1);

    let replay = path
        .open_stream(&mut opener, open)
        .await
        .expect("replayed stream open");
    assert_eq!(
        replay,
        StreamOpenDecision::Opened {
            metadata: b"fake-target-open".to_vec(),
        }
    );
    assert_eq!(connector.calls(), 1);
    assert_eq!(opener.egress.active_connection_count(), 1);
}
