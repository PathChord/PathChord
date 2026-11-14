use pathchord_core::{
    FrameFlags, FrameType, Message, PathFrame, PathId, PathReady, ProtocolLimits, SessionId,
};
use pathchord_noise::{WIRE_PROFILE_V1_PROLOGUE_PREFIX, generate_static_keypair};
use pathchord_path::{
    AuthorizationState, CompleteFrameTransport, NoiseRecordStream, PathAuthorization,
    SinglePathHandshakeConfig, SinglePathOutcome, establish_single_path,
};

fn admitted_transports() -> (
    pathchord_noise::NoiseTransport,
    pathchord_noise::NoiseTransport,
    ProtocolLimits,
) {
    let initiator = generate_static_keypair().expect("initiator key");
    let responder = generate_static_keypair().expect("responder key");
    let mut prologue = WIRE_PROFILE_V1_PROLOGUE_PREFIX.to_vec();
    prologue.extend_from_slice(b"record-test");
    let config = SinglePathHandshakeConfig {
        egress_identity: prologue,
        egress_id: b"record-test".to_vec(),
        ingress_id: b"record-ingress".to_vec(),
        session_id: SessionId::new(91),
        path_id: PathId::new(92),
        offered_capabilities: 1,
        required_capabilities: 1,
        supported_capabilities: 1,
        replication_budget_bytes_per_second: 8 * 1024 * 1024,
        local_limits: ProtocolLimits::default(),
        ready_limits: PathReady {
            max_frame_payload: 60 * 1024,
            max_control_payload: 4 * 1024,
            max_session_buffering: 16 * 1024 * 1024,
        },
    };
    let authorization = PathAuthorization {
        ingress_id: config.ingress_id.clone(),
        public_key: *initiator.public(),
        state: AuthorizationState::Enabled,
        generation: 1,
    };
    let outcome = establish_single_path(
        initiator.private(),
        responder.private(),
        responder.public(),
        &config,
        &authorization,
    )
    .expect("Path admission");
    let SinglePathOutcome::Ready(ready) = outcome else {
        panic!("expected ready Path");
    };
    let (initiator_transport, responder_transport) = ready.into_transports();
    (
        initiator_transport,
        responder_transport,
        config.local_limits,
    )
}

#[tokio::test]
async fn exchanges_complete_authenticated_records_over_a_byte_stream() {
    let (initiator_transport, responder_transport, limits) = admitted_transports();
    let (left, right) = tokio::io::duplex(16 * 1024);
    let mut sender = NoiseRecordStream::new(left, initiator_transport, limits);
    let mut receiver = NoiseRecordStream::new(right, responder_transport, limits);
    let payload = Message::Heartbeat(pathchord_core::Heartbeat { control_seq: 7 })
        .encode(limits)
        .expect("heartbeat payload");
    let frame = PathFrame::new(
        FrameType::Heartbeat,
        FrameFlags::empty(),
        SessionId::new(91),
        PathId::new(92),
        2,
        payload,
        limits,
    )
    .expect("frame");

    sender.send_frame(frame.clone()).await.expect("send record");
    assert_eq!(
        receiver.receive_frame().await.expect("receive record"),
        Some(frame)
    );
}
