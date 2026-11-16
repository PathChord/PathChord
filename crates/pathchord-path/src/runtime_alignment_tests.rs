use super::tests::{
    EchoFactory, EchoUdpFactory, admitted_pair_for, authorization, egress_config, ingress_config,
    keys, target,
};
use super::*;
use crate::{CompleteFrameTransport, PathAdmissionOutcome, accept_path, dial_path};
use std::task::{Context, Poll};
use tokio::io::{DuplexStream, ReadBuf};

async fn pair_with_capabilities(
    capabilities: u64,
) -> (
    IngressAdmittedPath<DuplexStream>,
    EgressAdmittedPath<DuplexStream>,
) {
    let (ingress_key, egress_key) = keys();
    let mut local = ingress_config();
    local.offered_capabilities = capabilities;
    local.required_capabilities = capabilities;
    let mut remote = egress_config();
    remote.required_capabilities = capabilities;
    remote.supported_capabilities = capabilities;
    let authorization = authorization(&ingress_key);
    let (client, server) = duplex(512 * 1024);
    let (client, server) = tokio::join!(
        dial_path(client, ingress_key.private(), egress_key.public(), &local),
        accept_path(server, egress_key.private(), &remote, &authorization),
    );
    let PathAdmissionOutcome::Ready(client) = client.unwrap() else {
        panic!("client admission")
    };
    let PathAdmissionOutcome::Ready(server) = server.unwrap() else {
        panic!("server admission")
    };
    (client, server)
}

async fn receive_session_operation(peer: &mut NoiseRecordStream<DuplexStream>) -> SessionControl {
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let frame = peer.receive_frame().await.unwrap().unwrap();
            if let Message::SessionControl(control) = Message::decode(
                frame.header().frame_type(),
                frame.payload(),
                ProtocolLimits::default(),
            )
            .unwrap()
            {
                return control;
            }
        }
    })
    .await
    .unwrap()
}

#[tokio::test]
async fn ingress_rejects_unnegotiated_protocols_without_disrupting_negotiated_flows() {
    for capabilities in [CAPABILITY_TCP_STREAM, CAPABILITY_UDP_SESSION] {
        let (path, peer) = pair_with_capabilities(capabilities).await;
        let factory = EchoFactory::default();
        let egress =
            EgressSessionHandle::start_with_udp(peer, factory.clone(), EchoUdpFactory).unwrap();
        let ingress = IngressSessionHandle::start(path).unwrap();
        if capabilities == CAPABILITY_TCP_STREAM {
            let mut stream = ingress.open_tcp(target("allowed-tcp.test")).await.unwrap();
            assert_echo(&mut stream, b"before-denial").await;
            assert!(matches!(
                ingress.open_udp(target("denied-udp.test")).await,
                Err(OpenUdpError::Rejected {
                    error: ErrorClass::EgressFailure,
                    ..
                })
            ));
            assert_echo(&mut stream, b"after-denial").await;
            stream.shutdown().await.unwrap();
            stream.read_to_end(&mut Vec::new()).await.unwrap();
        } else {
            let mut udp = ingress.open_udp(target("allowed-udp.test")).await.unwrap();
            assert!(matches!(
                ingress.open_tcp(target("denied-tcp.test")).await,
                Err(OpenStreamError::Rejected {
                    error: ErrorClass::EgressFailure,
                    ..
                })
            ));
            udp.send(b"after-denial".to_vec()).await.unwrap();
            assert_eq!(
                tokio::time::timeout(Duration::from_secs(2), udp.receive())
                    .await
                    .unwrap(),
                Some(b"after-denial".to_vec())
            );
            udp.close().await.unwrap();
        }
        assert!(!ingress.snapshot().closed);
        ingress.shutdown().await.unwrap();
        egress.wait().await.unwrap();
        factory.join().await;
    }
}

#[tokio::test]
async fn egress_rejects_authenticated_opens_outside_the_negotiated_protocols() {
    for capabilities in [CAPABILITY_TCP_STREAM, CAPABILITY_UDP_SESSION] {
        let (path, peer) = pair_with_capabilities(capabilities).await;
        let factory = EchoFactory::default();
        let egress =
            EgressSessionHandle::start_with_udp(peer, factory.clone(), EchoUdpFactory).unwrap();
        let path_id = path.path_id();
        let mut peer = path.into_transport();
        let mut wire_sequence = 2;
        for operation in 0..2 {
            let tcp = (capabilities == CAPABILITY_UDP_SESSION) == (operation == 0);
            let request = if tcp {
                Message::StreamOpen(StreamOpen {
                    request_id: RequestId::new(77),
                    stream_id: StreamId::new(1).unwrap(),
                    target: target("gate.test"),
                })
            } else {
                Message::UdpOpen(UdpOpen {
                    association_id: 1,
                    target_flags: 1,
                    target: target("gate.test"),
                })
            };
            send_peer_message(
                &mut peer,
                path_id,
                &mut wire_sequence,
                Message::SessionControl(SessionControl {
                    sequence: operation,
                    depends_on: operation.checked_sub(1),
                    frame_type: request.frame_type(),
                    eligible_paths: Vec::new(),
                    payload: request.encode(ProtocolLimits::default()).unwrap(),
                }),
            )
            .await;
            let response = receive_session_operation(&mut peer).await;
            let message = Message::decode(
                response.frame_type,
                &response.payload,
                ProtocolLimits::default(),
            )
            .unwrap();
            if operation == 0 {
                assert!(matches!(
                    message,
                    Message::StreamOpenErr(StreamOpenErr {
                        error: ErrorClass::EgressFailure,
                        ..
                    }) | Message::UdpOpenErr(UdpOpenErr {
                        error: ErrorClass::EgressFailure,
                        ..
                    })
                ));
            } else {
                assert!(matches!(
                    message,
                    Message::StreamOpenOk(_) | Message::UdpOpenOk(_)
                ));
            }
            send_peer_message(
                &mut peer,
                path_id,
                &mut wire_sequence,
                Message::SessionControlAck(ControlAck {
                    highest_contiguous: response.sequence,
                    ranges: Vec::new(),
                }),
            )
            .await;
            assert!(!egress.controller().snapshot().closed);
        }
        drop(peer);
        assert!(matches!(
            egress.wait().await,
            Err(SessionRuntimeError::PathClosed)
        ));
        factory.join().await;
    }
}

async fn send_peer_message(
    peer: &mut NoiseRecordStream<DuplexStream>,
    path_id: PathId,
    sequence: &mut u64,
    message: Message,
) {
    let limits = ProtocolLimits::default();
    peer.send_frame(
        PathFrame::new(
            message.frame_type(),
            FrameFlags::empty(),
            ingress_config().session_id,
            path_id,
            *sequence,
            message.encode(limits).unwrap(),
            limits,
        )
        .unwrap(),
    )
    .await
    .unwrap();
    *sequence += 1;
}

async fn wait_for_retired_path(
    ingress: &IngressSessionHandle,
    path: PathId,
    terminal: pathchord_core::PathState,
) {
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let snapshot = ingress.snapshot();
            assert!(
                !snapshot.closed,
                "a second healthy Path must keep the Session live: {snapshot:?}"
            );
            if snapshot.path_states.get(&path) == Some(&terminal) {
                assert_eq!(snapshot.ready_paths, 1);
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
}

async fn assert_echo(stream: &mut BoxedSessionStream, payload: &[u8]) {
    stream.write_all(payload).await.unwrap();
    let mut received = vec![0; payload.len()];
    tokio::time::timeout(Duration::from_secs(2), stream.read_exact(&mut received))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(received, payload);
}

#[tokio::test]
async fn malformed_authenticated_payload_closes_only_its_path() {
    let (ingress_key, egress_key) = keys();
    let (ingress_primary, egress_primary) = admitted_pair_for(&ingress_key, &egress_key, 1).await;
    let factory = EchoFactory::default();
    let egress = EgressSessionHandle::start(egress_primary, factory.clone()).unwrap();
    let ingress = IngressSessionHandle::start(ingress_primary).unwrap();
    let mut stream = ingress
        .open_tcp(target("survives-malformed.test"))
        .await
        .unwrap();
    assert_echo(&mut stream, b"before").await;
    let (secondary, peer) = admitted_pair_for(&ingress_key, &egress_key, 2).await;
    ingress
        .add_path(secondary, MultipathPathObservation::default())
        .await
        .unwrap();
    let (mut io, mut noise) = peer.into_transport().into_parts();
    let frame = PathFrame::new(
        FrameType::Heartbeat,
        FrameFlags::empty(),
        ingress_config().session_id,
        PathId::new(2),
        noise.next_send_nonce().unwrap(),
        Vec::new(),
        ProtocolLimits::default(),
    )
    .unwrap();
    io.write_all(
        &noise
            .seal_frame(&frame, ProtocolLimits::default())
            .unwrap()
            .encode(),
    )
    .await
    .unwrap();
    wait_for_retired_path(&ingress, PathId::new(2), pathchord_core::PathState::Failed).await;
    assert_echo(&mut stream, b"after").await;
    assert!(!egress.controller().snapshot().closed);
    stream.shutdown().await.unwrap();
    stream.read_to_end(&mut Vec::new()).await.unwrap();
    ingress.shutdown().await.unwrap();
    egress.wait().await.unwrap();
    factory.join().await;
}

#[tokio::test]
async fn a_path_with_different_non_class_capabilities_cannot_join() {
    let (ingress_key, egress_key) = keys();
    let (primary, peer) = admitted_pair_for(&ingress_key, &egress_key, 1).await;
    let factory = EchoFactory::default();
    let egress = EgressSessionHandle::start(peer, factory.clone()).unwrap();
    let ingress = IngressSessionHandle::start(primary).unwrap();
    let mut stream = ingress
        .open_tcp(target("unchanged-capabilities.test"))
        .await
        .unwrap();

    let mut local = ingress_config();
    local.path_id = PathId::new(2);
    local.offered_capabilities = 1;
    let mut remote = egress_config();
    remote.supported_capabilities = 1;
    let authorization = authorization(&ingress_key);
    let (client, server) = duplex(512 * 1024);
    let (client, server) = tokio::join!(
        dial_path(client, ingress_key.private(), egress_key.public(), &local),
        accept_path(server, egress_key.private(), &remote, &authorization),
    );
    let PathAdmissionOutcome::Ready(client) = client.unwrap() else {
        panic!("client admission")
    };
    let PathAdmissionOutcome::Ready(server) = server.unwrap() else {
        panic!("server admission")
    };
    assert_eq!(client.negotiated_capabilities(), 1);
    assert_eq!(server.negotiated_capabilities(), 1);
    assert!(matches!(
        ingress
            .add_path(client, MultipathPathObservation::default())
            .await,
        Err(SessionRuntimeError::InvalidRuntimeLimit)
    ));
    assert!(matches!(
        egress
            .controller()
            .add_path(server, MultipathPathObservation::default())
            .await,
        Err(SessionRuntimeError::InvalidRuntimeLimit)
    ));
    assert_eq!(ingress.snapshot().ready_paths, 1);
    assert_echo(&mut stream, b"still-compatible").await;
    stream.shutdown().await.unwrap();
    stream.read_to_end(&mut Vec::new()).await.unwrap();
    ingress.shutdown().await.unwrap();
    egress.wait().await.unwrap();
    factory.join().await;
}

struct ResetTarget;

impl AsyncRead for ResetTarget {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        _context: &mut Context<'_>,
        _buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Poll::Ready(Err(std::io::Error::new(
            std::io::ErrorKind::ConnectionReset,
            "target reset",
        )))
    }
}

impl AsyncWrite for ResetTarget {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        _context: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Poll::Ready(Ok(bytes.len()))
    }
    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _context: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _context: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

struct ResetFactory;

#[async_trait]
impl EgressStreamFactory for ResetFactory {
    async fn open(
        &self,
        _target: TargetEndpoint,
    ) -> Result<BoxedSessionStream, EgressStreamOpenError> {
        Ok(Box::new(ResetTarget))
    }
}

#[tokio::test]
async fn target_io_reset_preserves_target_failure_on_the_peer() {
    let (ingress_key, egress_key) = keys();
    let (path, peer) = admitted_pair_for(&ingress_key, &egress_key, 1).await;
    let egress = EgressSessionHandle::start(peer, ResetFactory).unwrap();
    let ingress = IngressSessionHandle::start(path).unwrap();
    let mut stream = ingress.open_tcp(target("target-reset.test")).await.unwrap();
    stream.read_to_end(&mut Vec::new()).await.unwrap();
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if ingress
                .snapshot()
                .streams
                .values()
                .any(|stream| stream.close_reason.as_deref() == Some("target_failure"))
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert!(!ingress.snapshot().closed);
    assert_eq!(ingress.snapshot().ready_paths, 1);
    ingress.shutdown().await.unwrap();
    egress.wait().await.unwrap();
}

#[tokio::test]
async fn received_drain_deadline_closes_a_path_with_an_unacknowledged_open() {
    let (ingress_key, egress_key) = keys();
    let (primary, peer) = admitted_pair_for(&ingress_key, &egress_key, 1).await;
    let factory = EchoFactory::default();
    let egress = EgressSessionHandle::start(peer, factory.clone()).unwrap();
    let ingress = Arc::new(IngressSessionHandle::start(primary).unwrap());
    let mut healthy = ingress
        .open_tcp(target("survives-drain.test"))
        .await
        .unwrap();
    let (secondary, peer) = admitted_pair_for(&ingress_key, &egress_key, 2).await;
    ingress
        .add_path(secondary, MultipathPathObservation::default())
        .await
        .unwrap();
    let mut peer = peer.into_transport();
    let pending = {
        let ingress = Arc::clone(&ingress);
        tokio::spawn(async move {
            ingress
                .open_tcp_routed(
                    target("unacknowledged.test"),
                    BTreeMap::from([(PathId::new(2), 1)]),
                )
                .await
        })
    };
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let frame = peer.receive_frame().await.unwrap().unwrap();
            if let Message::SessionControl(control) = Message::decode(
                frame.header().frame_type(),
                frame.payload(),
                ProtocolLimits::default(),
            )
            .unwrap()
                && control.frame_type == FrameType::StreamOpen
            {
                break;
            }
        }
    })
    .await
    .unwrap();
    let mut sequence = 2;
    send_peer_message(
        &mut peer,
        PathId::new(2),
        &mut sequence,
        Message::PathDrain(PathDrain {
            drain_reason: 1,
            // Keep the Path draining across at least one health tick.
            deadline_ms: 300,
        }),
    )
    .await;
    wait_for_retired_path(&ingress, PathId::new(2), pathchord_core::PathState::Closed).await;
    assert!(pending.await.unwrap().is_err());
    assert_echo(&mut healthy, b"after-deadline").await;
    healthy.shutdown().await.unwrap();
    healthy.read_to_end(&mut Vec::new()).await.unwrap();
    Arc::try_unwrap(ingress).unwrap().shutdown().await.unwrap();
    egress.wait().await.unwrap();
    factory.join().await;
}

#[tokio::test]
async fn opens_use_random_request_ids_and_retries_preserve_them() {
    let (ingress_key, egress_key) = keys();
    let (path, peer) = admitted_pair_for(&ingress_key, &egress_key, 1).await;
    let ingress = Arc::new(IngressSessionHandle::start(path).unwrap());
    let mut peer = peer.into_transport();
    let mut sequence = 2;
    let mut identifiers = BTreeSet::new();
    for index in 0_u64..16 {
        let pending = {
            let ingress = Arc::clone(&ingress);
            tokio::spawn(async move { ingress.open_tcp(target("request-id.test")).await })
        };
        let control = loop {
            let frame = peer.receive_frame().await.unwrap().unwrap();
            if let Message::SessionControl(control) = Message::decode(
                frame.header().frame_type(),
                frame.payload(),
                ProtocolLimits::default(),
            )
            .unwrap()
                && control.frame_type == FrameType::StreamOpen
            {
                break control;
            }
        };
        let Message::StreamOpen(open) = Message::decode(
            control.frame_type,
            &control.payload,
            ProtocolLimits::default(),
        )
        .unwrap() else {
            panic!("Stream open")
        };
        assert!(identifiers.insert(open.request_id));
        assert_ne!(open.request_id.get(), u128::from(open.stream_id.get()));
        if index == 0 {
            let retry = tokio::time::timeout(Duration::from_secs(2), async {
                loop {
                    let frame = peer.receive_frame().await.unwrap().unwrap();
                    if let Message::SessionControl(retry) = Message::decode(
                        frame.header().frame_type(),
                        frame.payload(),
                        ProtocolLimits::default(),
                    )
                    .unwrap()
                        && retry.frame_type == FrameType::StreamOpen
                    {
                        break retry;
                    }
                }
            })
            .await
            .unwrap();
            assert_eq!(retry, control);
        }
        send_peer_message(
            &mut peer,
            PathId::new(1),
            &mut sequence,
            Message::SessionControlAck(ControlAck {
                highest_contiguous: control.sequence,
                ranges: Vec::new(),
            }),
        )
        .await;
        let response = Message::StreamOpenErr(StreamOpenErr {
            stream_id: open.stream_id,
            error: ErrorClass::TargetFailure,
            reason: b"test rejection".to_vec(),
        });
        send_peer_message(
            &mut peer,
            PathId::new(1),
            &mut sequence,
            Message::SessionControl(SessionControl {
                sequence: index,
                depends_on: index.checked_sub(1),
                frame_type: response.frame_type(),
                eligible_paths: Vec::new(),
                payload: response.encode(ProtocolLimits::default()).unwrap(),
            }),
        )
        .await;
        assert!(matches!(
            pending.await.unwrap(),
            Err(OpenStreamError::Rejected {
                error: ErrorClass::TargetFailure,
                ..
            })
        ));
    }
}
