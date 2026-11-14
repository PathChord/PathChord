use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use pathchord_core::{PathReady, ProtocolLimits};
use pathchord_egress::{
    AuthorizationMutation, AuthorizationMutationRequest, AuthorizationStore,
    EgressId as StoreEgressId, EgressNode, EgressNodeConfig, IngressId as StoreIngressId,
    TcpTargetConnector,
};
use pathchord_ingress::{
    HttpConnectListener, IngressDataPlane, IngressDataPlaneConfig, ListenerDescriptor, ListenerId,
    ListenerKind, ListenerRuntime,
};
use pathchord_noise::generate_static_keypair;
use pathchord_policy::{
    Capabilities, EgressConfig, EgressId, EgressRule, EgressSelection, EgressStatusRequirements,
    Endpoint, FallbackAction, FlowMatch, FlowProtocol, Generation, PolicyConfig,
    RetransmissionReplication, RuleId, Scheduler, Selector, TrafficPolicy, TrafficPolicyId,
    TransitProxyConfig, TransitProxyId, TransitRule, ValidatedPolicySnapshot,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;

#[tokio::test]
async fn http_connect_crosses_transit_noise_session_and_egress() {
    let ingress_key = generate_static_keypair().expect("Ingress identity");
    let egress_key = Arc::new(generate_static_keypair().expect("Egress identity"));
    let store = Arc::new(
        AuthorizationStore::open(
            ":memory:",
            StoreEgressId::new("egress-a"),
            *egress_key.public(),
        )
        .expect("authorization store"),
    );
    store
        .mutate(AuthorizationMutationRequest {
            actor_id: "test".into(),
            request_id: "enroll-ingress".into(),
            expected_generation: 0,
            ingress_id: StoreIngressId::new("ingress-a"),
            mutation: AuthorizationMutation::Enroll {
                public_key: *ingress_key.public(),
                administrator_labels: BTreeMap::new(),
            },
        })
        .expect("enroll Ingress");

    let egress = Arc::new(
        EgressNode::bind(
            EgressNodeConfig {
                bind: "127.0.0.1:0".parse().unwrap(),
                egress_id: "egress-a".into(),
                keypair: Arc::clone(&egress_key),
                authorizations: Arc::clone(&store),
                protocol_limits: ProtocolLimits::default(),
                ready_limits: PathReady {
                    max_frame_payload: 32 * 1024,
                    max_control_payload: 4 * 1024,
                    max_session_buffering: 4 * 1024 * 1024,
                },
                required_capabilities: 1,
                supported_capabilities: 1,
                max_concurrent_paths: 8,
                capacity_bps: 1_000_000_000,
                recommended_path_count: 1,
                max_streams_per_ingress: 128,
                remote_dns_only: false,
                quota_remaining: None,
                traffic_multiplier_basis_points: 10_000,
            },
            TcpTargetConnector::new(),
        )
        .await
        .expect("bind Egress"),
    );
    let egress_address = egress.local_addr();
    let (stop_egress, egress_shutdown) = oneshot::channel();
    let egress_owner = Arc::clone(&egress);
    let egress_task = tokio::spawn(async move {
        egress_owner
            .run_until_shutdown(async move {
                let _ = egress_shutdown.await;
            })
            .await
    });

    let policy = policy(egress_address, egress_key.public());
    let data_plane = Arc::new(
        IngressDataPlane::new(IngressDataPlaneConfig::new(
            "ingress-a",
            ingress_key,
            policy,
        ))
        .expect("Ingress data plane"),
    );
    data_plane.warmup().await;
    assert_eq!(data_plane.snapshot().await.ready_paths, 1);

    let target = TcpListener::bind("127.0.0.1:0").await.expect("echo target");
    let target_address = target.local_addr().expect("target address");
    let target_task = tokio::spawn(async move {
        let (mut stream, _) = target.accept().await.expect("target accept");
        let mut buffer = [0_u8; 4096];
        loop {
            let read = stream.read(&mut buffer).await.expect("target read");
            if read == 0 {
                break;
            }
            stream
                .write_all(&buffer[..read])
                .await
                .expect("target echo");
        }
    });

    let descriptor = ListenerDescriptor {
        id: ListenerId::new("http-e2e"),
        kind: ListenerKind::Http,
        bind: Some("127.0.0.1:0".parse().unwrap()),
        interface: None,
        address: None,
        mtu: None,
        flow_tags: std::collections::BTreeSet::new(),
        process_metadata: pathchord_policy::ProcessMetadataRequest::default(),
        allowed_sources: vec!["127.0.0.1/32".into()],
        authentication_required: false,
    };
    let listener = HttpConnectListener::bind(descriptor)
        .await
        .expect("HTTP listener");
    let proxy_address = listener.local_addr().expect("proxy address");
    let mut runtime = ListenerRuntime::new(Arc::clone(&data_plane));
    runtime.add_listener(listener).expect("add listener");
    let (stop_listener, listener_shutdown) = oneshot::channel();
    let listener_task = tokio::spawn(async move {
        runtime
            .run_until_shutdown(async move {
                let _ = listener_shutdown.await;
            })
            .await
    });

    let mut client = TcpStream::connect(proxy_address)
        .await
        .expect("proxy connect");
    client
        .write_all(
            format!("CONNECT {target_address} HTTP/1.1\r\nHost: {target_address}\r\n\r\n")
                .as_bytes(),
        )
        .await
        .expect("CONNECT request");
    let mut response = Vec::new();
    while !response.ends_with(b"\r\n\r\n") {
        assert!(response.len() < 4096, "bounded HTTP response");
        response.push(client.read_u8().await.expect("CONNECT response"));
    }
    assert!(response.starts_with(b"HTTP/1.1 200"));

    let payload = b"real-pathchord-data-plane";
    client.write_all(payload).await.expect("payload send");
    let mut echoed = vec![0_u8; payload.len()];
    client
        .read_exact(&mut echoed)
        .await
        .expect("payload receive");
    assert_eq!(echoed, payload);
    client.shutdown().await.expect("client half-close");
    drop(client);

    stop_listener.send(()).expect("listener shutdown");
    listener_task
        .await
        .expect("listener task")
        .expect("listener runtime");
    data_plane.shutdown().await.expect("data plane shutdown");
    stop_egress.send(()).expect("Egress shutdown");
    egress_task
        .await
        .expect("Egress task")
        .expect("Egress runtime");
    target_task.await.expect("target task");
    assert_eq!(
        egress.snapshot().expect("Egress snapshot").active_sessions,
        0
    );
}

fn policy(
    egress_address: std::net::SocketAddr,
    egress_public_key: &[u8; 32],
) -> ValidatedPolicySnapshot {
    let egress_id = EgressId::new("egress-a");
    let transit_id = TransitProxyId::new("direct-a");
    let traffic_policy_id = TrafficPolicyId::new("default");
    ValidatedPolicySnapshot::new(
        Generation::new(1),
        PolicyConfig {
            egresses: vec![EgressConfig {
                id: egress_id.clone(),
                endpoint: Endpoint {
                    host: egress_address.ip().to_string(),
                    port: egress_address.port(),
                },
                public_key: URL_SAFE_NO_PAD.encode(egress_public_key),
                labels: BTreeMap::new(),
                capabilities: Capabilities {
                    tcp: true,
                    udp: false,
                },
                status_requirements: EgressStatusRequirements {
                    min_usable_paths: 1,
                    capabilities: BTreeSet::from([FlowProtocol::Tcp]),
                },
            }],
            transit_proxies: vec![TransitProxyConfig {
                options: Default::default(),
                id: transit_id,
                source: None,
                protocol: "direct".into(),
                endpoint: Endpoint {
                    host: String::new(),
                    port: 1,
                },
                credentials_ref: None,
                labels: BTreeMap::new(),
                tags: BTreeSet::new(),
                weight: 100,
            }],
            egress_rules: vec![EgressRule {
                id: RuleId::new("all-to-egress"),
                matches: FlowMatch::default(),
                egress: EgressSelection::Id(egress_id.clone()),
                min_usable_paths: 1,
                required_capabilities: BTreeSet::from([FlowProtocol::Tcp]),
            }],
            transit_rules: vec![TransitRule {
                id: RuleId::new("egress-direct"),
                egress: egress_id,
                matches: FlowMatch::default(),
                require: Selector::default(),
                reject_tags: BTreeSet::new(),
                weight: 100,
                traffic_policy: traffic_policy_id.clone(),
                traffic_class: None,
            }],
            traffic_policies: vec![TrafficPolicy {
                id: traffic_policy_id,
                scheduler: Scheduler::EffectiveCapacityWeighted,
                session_replication_budget_bps: 0,
                class_replication_budget_bps: None,
                retransmission_replication: RetransmissionReplication::Disabled,
                classes: BTreeMap::new(),
            }],
            fallback: Some(FallbackAction::Reject),
            ..PolicyConfig::default()
        },
    )
    .expect("validated policy")
}
