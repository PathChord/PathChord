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
    http_connect_through_egress("default", "127.0.0.1:0").await;
}

#[tokio::test]
async fn namespaced_egress_keeps_its_canonical_noise_and_enrollment_identity() {
    http_connect_through_egress("tenant-a", "127.0.0.1:0").await;
}

#[tokio::test]
async fn direct_transit_establishes_an_ipv6_egress_session() {
    http_connect_through_egress("default", "[::1]:0").await;
}

#[tokio::test]
async fn retiring_a_replaced_transit_path_prevents_new_streams_from_using_it() {
    use pathchord_policy::{
        SubscriptionConfig, SubscriptionId, SubscriptionSource, SubscriptionSourceType,
    };
    use pathchord_transit::{
        AdapterRegistry, NoTransitCredentials, SubscriptionError, SubscriptionFetchRequest,
        SubscriptionFetcher, SubscriptionManager,
    };

    struct FixtureFetcher;
    #[async_trait::async_trait]
    impl SubscriptionFetcher for FixtureFetcher {
        async fn fetch(&self, _: SubscriptionFetchRequest) -> Result<Vec<u8>, SubscriptionError> {
            Ok(b"proxies: [{name: relay, type: direct}]".to_vec())
        }
    }
    tokio::time::timeout(std::time::Duration::from_secs(20), async {
        let ingress_key = generate_static_keypair().unwrap();
        let egress_key = Arc::new(generate_static_keypair().unwrap());
        let store = Arc::new(
            AuthorizationStore::open(
                ":memory:",
                StoreEgressId::new("egress-a"),
                *egress_key.public(),
            )
            .unwrap(),
        );
        store
            .mutate(AuthorizationMutationRequest {
                actor_id: "test".into(),
                request_id: "enroll".into(),
                expected_generation: 0,
                ingress_id: StoreIngressId::new("ingress-a"),
                mutation: AuthorizationMutation::Enroll {
                    public_key: *ingress_key.public(),
                    administrator_labels: BTreeMap::new(),
                },
            })
            .unwrap();
        let egress = Arc::new(
            EgressNode::bind(
                EgressNodeConfig {
                    bind: "127.0.0.1:0".parse().unwrap(),
                    egress_id: "egress-a".into(),
                    keypair: Arc::clone(&egress_key),
                    authorizations: store,
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
                    max_inbound_target_connections: 128,
                    remote_dns_only: false,
                    quota_remaining: None,
                    traffic_multiplier_basis_points: 10_000,
                },
                TcpTargetConnector::new(),
            )
            .await
            .unwrap(),
        );
        let (stop, shutdown) = oneshot::channel();
        let owner = Arc::clone(&egress);
        let task = tokio::spawn(async move {
            owner
                .run_until_shutdown(async {
                    let _ = shutdown.await;
                })
                .await
        });
        let old = policy("default", egress.local_addr(), egress_key.public());
        let mut config = old.config().clone();
        config.transit_proxies.clear();
        config.subscriptions.push(SubscriptionConfig {
            id: SubscriptionId::new("provider"),
            enabled: true,
            source: SubscriptionSource {
                source_type: SubscriptionSourceType::Clash,
                url: "https://example.test/sub".into(),
                credentials_ref: None,
                user_agent: None,
            },
            refresh: Default::default(),
            cache: None,
        });
        let subscription = config.subscriptions[0].clone();
        let plane = IngressDataPlane::new(IngressDataPlaneConfig::new(
            "ingress-a",
            ingress_key,
            ValidatedPolicySnapshot::new(Generation::new(1), config).unwrap(),
        ))
        .unwrap();
        let mut manager = SubscriptionManager::new(
            Arc::new(FixtureFetcher),
            std::env::temp_dir(),
            BTreeSet::from(["direct".into()]),
        );
        manager.refresh(&subscription).await;
        let registry = AdapterRegistry::for_configs(
            Arc::new(NoTransitCredentials),
            std::time::Duration::from_secs(2),
            manager.snapshot().nodes.values().map(|node| &node.config),
        )
        .unwrap();
        let prepared = manager.snapshot().prepare_adapters(&registry).await;
        manager.commit_prepared_adapters(prepared).unwrap();
        let snapshot = manager.snapshot().clone();
        let node = snapshot.selectable_nodes().next().unwrap();
        let admission = snapshot.validated_admission(&node.config.id).unwrap();
        let adapter = admission.adapter();
        assert_eq!(
            plane
                .register_verified_dynamic_transit_adapter(
                    node.config.clone(),
                    admission,
                    pathchord_policy::TransitProxyRuntimeStatus {
                        state: pathchord_policy::RuntimeNodeState::Ready,
                        capabilities: BTreeSet::from([FlowProtocol::Tcp]),
                        selection_score: 1,
                        ..Default::default()
                    }
                )
                .await,
            pathchord_ingress::DynamicTransitRegistration::Registered
        );
        plane.warmup().await;
        assert_eq!(plane.snapshot().await.ready_paths, 1);
        let old_path = plane.session_snapshots().await[0]
            .path_transit
            .keys()
            .next()
            .copied()
            .unwrap();
        let old_target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let old_address = old_target.local_addr().unwrap();
        let old_echo = tokio::spawn(async move {
            let (mut stream, _) = old_target.accept().await.unwrap();
            for _ in 0..2 {
                let mut bytes = [0; 4];
                stream.read_exact(&mut bytes).await.unwrap();
                stream.write_all(&bytes).await.unwrap();
            }
        });
        let old_context = pathchord_ingress::ConnectionContext {
            flow_tags: BTreeSet::new(),
            listener_id: ListenerId::new("test"),
            source: "127.0.0.1:1234".parse().unwrap(),
            authentication_identity: None,
            process: None,
            protocol: FlowProtocol::Tcp,
            target: pathchord_ingress::TargetAddress {
                host: pathchord_ingress::TargetHost::Ip(old_address.ip()),
                port: old_address.port(),
            },
        };
        let mut old_stream = plane.open_tcp(&old_context).await.unwrap();
        old_stream.write_all(b"old1").await.unwrap();
        let mut old_bytes = [0; 4];
        old_stream.read_exact(&mut old_bytes).await.unwrap();
        assert_eq!(&old_bytes, b"old1");
        plane
            .initialize_subscription_visibility("provider", false)
            .await;
        plane
            .retire_replaced_transit_paths(std::slice::from_ref(&node.config.id))
            .await;
        manager.suspend_source_admissions(&subscription.id);
        let prepared = manager.snapshot().prepare_adapters(&registry).await;
        manager.commit_prepared_adapters(prepared).unwrap();
        plane.allow_subscription_after_refresh("provider").await;
        let admission = manager
            .snapshot()
            .validated_admission(&node.config.id)
            .unwrap();
        assert!(!Arc::ptr_eq(&adapter, &admission.adapter()));
        assert_eq!(
            plane
                .register_verified_dynamic_transit_adapter(
                    node.config.clone(),
                    admission,
                    pathchord_policy::TransitProxyRuntimeStatus {
                        state: pathchord_policy::RuntimeNodeState::Ready,
                        capabilities: BTreeSet::from([FlowProtocol::Tcp]),
                        selection_score: 1,
                        ..Default::default()
                    }
                )
                .await,
            pathchord_ingress::DynamicTransitRegistration::Registered
        );
        plane.warmup().await;
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = target.local_addr().unwrap();
        let echo = tokio::spawn(async move {
            let (mut stream, _) = target.accept().await.unwrap();
            let mut b = [0; 4];
            stream.read_exact(&mut b).await.unwrap();
            stream.write_all(&b).await.unwrap();
        });
        let context = pathchord_ingress::ConnectionContext {
            flow_tags: BTreeSet::new(),
            listener_id: ListenerId::new("test"),
            source: "127.0.0.1:1234".parse().unwrap(),
            authentication_identity: None,
            process: None,
            protocol: FlowProtocol::Tcp,
            target: pathchord_ingress::TargetAddress {
                host: pathchord_ingress::TargetHost::Ip(address.ip()),
                port: address.port(),
            },
        };
        let mut stream = plane.open_tcp(&context).await.unwrap();
        stream.write_all(b"ping").await.unwrap();
        let mut b = [0; 4];
        stream.read_exact(&mut b).await.unwrap();
        assert_eq!(&b, b"ping");
        assert!(
            plane
                .session_snapshots()
                .await
                .iter()
                .flat_map(|s| s.path_transit.keys())
                .all(|id| *id != old_path)
        );
        old_stream.write_all(b"old2").await.unwrap();
        tokio::time::timeout(
            std::time::Duration::from_secs(2),
            old_stream.read_exact(&mut old_bytes),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(&old_bytes, b"old2");
        drop(old_stream);
        old_echo.await.unwrap();
        drop(stream);
        echo.await.unwrap();
        plane.shutdown().await.unwrap();
        let _ = stop.send(());
        task.await.unwrap().unwrap();
    })
    .await
    .unwrap();
}

async fn http_connect_through_egress(namespace: &str, egress_bind: &str) {
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
                bind: egress_bind.parse().unwrap(),
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
                max_inbound_target_connections: 128,
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

    let policy = policy(namespace, egress_address, egress_key.public());
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
        id: ListenerId::in_namespace(namespace, "http-e2e"),
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
    namespace: &str,
    egress_address: std::net::SocketAddr,
    egress_public_key: &[u8; 32],
) -> ValidatedPolicySnapshot {
    let egress_id = EgressId::in_namespace(namespace, "egress-a");
    let transit_id = TransitProxyId::in_namespace(namespace, "direct-a");
    let traffic_policy_id = TrafficPolicyId::in_namespace(namespace, "default");
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
                id: RuleId::in_namespace(namespace, "all-to-egress"),
                matches: FlowMatch::default(),
                egress: EgressSelection::Id(egress_id.clone()),
                min_usable_paths: 1,
                required_capabilities: BTreeSet::from([FlowProtocol::Tcp]),
            }],
            transit_rules: vec![TransitRule {
                id: RuleId::in_namespace(namespace, "egress-direct"),
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
