use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use pathchord_core::{PathReady, ProtocolLimits};
use pathchord_egress::{
    AuthorizationMutation, AuthorizationMutationRequest, AuthorizationStore,
    EgressId as StoreEgressId, EgressNode, EgressNodeConfig, IngressId as StoreIngressId,
    TcpTargetConnector,
};
use pathchord_ingress::{
    ConnectionContext, HttpConnectListener, IngressDataPlane, IngressDataPlaneConfig,
    ListenerDescriptor, ListenerId, ListenerKind, ListenerRuntime, TargetAddress,
};
use pathchord_noise::generate_static_keypair;
use pathchord_policy::{
    Capabilities, EgressAdmission, EgressConfig, EgressId, EgressPathPoolConfig, EgressRule,
    EgressSelection, Endpoint, FallbackAction, FlowMatch, FlowProtocol, Generation, PolicyConfig,
    RetransmissionReplication, RuleId, Scheduler, Selector, TargetHost, TrafficPolicy,
    TrafficPolicyId, TransitProxyConfig, TransitProxyId, TransitRule, ValidatedPolicySnapshot,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::oneshot;

struct StalledTransit {
    metadata: pathchord_transit::TransitMetadata,
}

#[async_trait::async_trait]
impl pathchord_transit::TransitAdapter for StalledTransit {
    fn metadata(&self) -> &pathchord_transit::TransitMetadata {
        &self.metadata
    }

    async fn connect(
        &self,
        _: pathchord_transit::ConnectRequest,
    ) -> Result<pathchord_transit::BoxedTransitConnection, pathchord_transit::TransitError> {
        std::future::pending().await
    }
}

struct ConcurrentTransit {
    inner: pathchord_transit::DirectTransitAdapter,
    egress_address: std::net::SocketAddr,
    successful_dials: AtomicUsize,
    refill_barrier: tokio::sync::Barrier,
}

#[async_trait::async_trait]
impl pathchord_transit::TransitAdapter for ConcurrentTransit {
    fn metadata(&self) -> &pathchord_transit::TransitMetadata {
        self.inner.metadata()
    }

    fn supports_udp(&self) -> bool {
        self.inner.supports_udp()
    }

    async fn connect(
        &self,
        request: pathchord_transit::ConnectRequest,
    ) -> Result<pathchord_transit::BoxedTransitConnection, pathchord_transit::TransitError> {
        if request.destination.port == self.egress_address.port()
            && self.successful_dials.fetch_add(1, Ordering::Relaxed) > 0
        {
            self.refill_barrier.wait().await;
        }
        self.inner.connect(request).await
    }
}

#[tokio::test]
async fn http_connect_crosses_transit_noise_session_and_egress() {
    http_connect_through_egress("default", "127.0.0.1:0", 4).await;
}

#[tokio::test]
async fn namespaced_egress_keeps_its_canonical_noise_and_enrollment_identity() {
    http_connect_through_egress("tenant-a", "127.0.0.1:0", 4).await;
}

#[tokio::test]
async fn direct_transit_establishes_an_ipv6_egress_session() {
    http_connect_through_egress("default", "[::1]:0", 4).await;
}

#[tokio::test]
async fn maintains_128_paths_and_forwards_traffic() {
    tokio::time::timeout(
        std::time::Duration::from_secs(75),
        http_connect_through_egress("default", "127.0.0.1:0", 128),
    )
    .await
    .expect("large Path pool");
}

#[tokio::test]
async fn revoked_session_does_not_fail_ingress_shutdown() {
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        let runtime_metrics = tokio::runtime::Handle::current().metrics();
        let tasks_before = runtime_metrics.num_alive_tasks();
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
                    binds: vec!["127.0.0.1:0".parse().unwrap()],
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
        let plane = IngressDataPlane::new(IngressDataPlaneConfig::new(
            "ingress-a",
            ingress_key,
            policy("default", egress.local_addr(), egress_key.public()),
        ))
        .unwrap();
        plane.warmup().await;
        assert_eq!(plane.snapshot().await.sessions, 1);
        store
            .mutate(AuthorizationMutationRequest {
                actor_id: "test".into(),
                request_id: "revoke".into(),
                expected_generation: 1,
                ingress_id: StoreIngressId::new("ingress-a"),
                mutation: AuthorizationMutation::Revoke,
            })
            .unwrap();
        egress
            .reconcile_authorizations_until(std::time::Duration::from_secs(2))
            .await
            .unwrap();
        while plane.snapshot().await.sessions != 0 {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        let result = plane.shutdown().await;
        let _ = stop.send(());
        task.await.unwrap().unwrap();
        let snapshot =
            result.expect("a revoked and already closed Session permits graceful shutdown");
        assert_eq!(snapshot.sessions, 0);
        assert_eq!(snapshot.streams, 0);
        assert_eq!(snapshot.retained_outbound_bytes, 0);
        for _ in 0..100 {
            if runtime_metrics.num_alive_tasks() <= tasks_before {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert_eq!(runtime_metrics.num_alive_tasks(), tasks_before);
    })
    .await
    .expect("bounded revoke then shutdown regression");
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
                    binds: vec!["127.0.0.1:0".parse().unwrap()],
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
        plane.warmup().await;
        assert_eq!(plane.snapshot().await.ready_paths, 3);
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

async fn http_connect_through_egress(namespace: &str, egress_bind: &str, target_paths: u32) {
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
                binds: vec![egress_bind.parse().unwrap()],
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
                supported_capabilities: 0b11,
                max_concurrent_paths: 256,
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

    let failed_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("failed endpoint");
    let failed_endpoint = failed_listener
        .local_addr()
        .expect("failed endpoint address");
    drop(failed_listener);
    let base_policy = policy_with_endpoints(
        namespace,
        &[failed_endpoint, egress_address],
        egress_key.public(),
    );
    let mut base_config = base_policy.config().clone();
    base_config.egresses[0].capabilities.udp = true;
    base_config.egresses[0].path_pool.min_usable_paths = 3;
    base_config.egresses[0].path_pool.target_usable_paths = Some(target_paths);
    base_config.egresses[0].endpoints.push(Endpoint {
        host: egress_address.ip().to_string(),
        port: egress_address.port(),
    });
    let base_policy = ValidatedPolicySnapshot::new(Generation::new(1), base_config).unwrap();
    let stalled_id = TransitProxyId::in_namespace(namespace, "aaa-stalled");
    let mut config = base_policy.config().clone();
    config.transit_proxies.push(TransitProxyConfig {
        id: stalled_id.clone(),
        source: None,
        protocol: "http".into(),
        endpoint: Endpoint {
            host: "127.0.0.1".into(),
            port: 1,
        },
        credentials_ref: None,
        labels: BTreeMap::new(),
        tags: BTreeSet::new(),
        weight: 100,
        options: Default::default(),
    });
    let policy = ValidatedPolicySnapshot::new(Generation::new(1), config).unwrap();
    let data_plane = Arc::new(
        IngressDataPlane::new(IngressDataPlaneConfig::new(
            "ingress-a",
            ingress_key,
            policy,
        ))
        .expect("Ingress data plane"),
    );
    if target_paths == 4 {
        let id = TransitProxyId::in_namespace(namespace, "direct-a");
        data_plane
            .register_transit_adapter(
                id.clone(),
                Arc::new(ConcurrentTransit {
                    inner: pathchord_transit::DirectTransitAdapter::new(
                        id.as_str(),
                        std::time::Duration::from_secs(2),
                    ),
                    egress_address,
                    successful_dials: AtomicUsize::new(0),
                    refill_barrier: tokio::sync::Barrier::new(target_paths as usize),
                }),
                pathchord_policy::TransitProxyRuntimeStatus {
                    state: pathchord_policy::RuntimeNodeState::Ready,
                    capabilities: BTreeSet::from([FlowProtocol::Tcp, FlowProtocol::Udp]),
                    selection_score: 1,
                    ..Default::default()
                },
            )
            .await
            .unwrap();
    }
    let expected_paths = target_paths as usize + 1;
    let result = tokio::time::timeout(std::time::Duration::from_secs(55), async {
        loop {
            data_plane.warmup().await;
            if data_plane.snapshot().await.ready_paths == expected_paths
                && egress.snapshot().unwrap().active_paths == expected_paths
            {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await;
    if result.is_err() {
        panic!(
            "Path target {target_paths}: Ingress {:?}, Egress {:?}",
            data_plane
                .session_snapshots()
                .await
                .iter()
                .map(|s| (s.session.ready_paths, s.target_shortfall_reason))
                .collect::<Vec<_>>(),
            egress.snapshot().unwrap()
        );
    }
    // New Paths can attach before the Egress actor's first status tick.
    // Business admission requires fresh status on the configured minimum.
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    if target_paths > 100 {
        // Observe several heartbeat periods before sending business traffic.
        tokio::time::sleep(std::time::Duration::from_secs(7)).await;
        assert_eq!(data_plane.snapshot().await.ready_paths, expected_paths);
        assert_eq!(egress.snapshot().unwrap().active_paths, expected_paths);
    }
    let session_snapshot = data_plane
        .session_snapshots()
        .await
        .into_iter()
        .next()
        .expect("Egress session snapshot");
    assert_eq!(session_snapshot.minimum_usable_paths, 3);
    assert_eq!(
        session_snapshot.requested_target_usable_paths,
        u64::from(target_paths)
    );
    assert_eq!(
        session_snapshot.effective_target_usable_paths,
        target_paths as usize
    );
    assert_eq!(session_snapshot.target_path_count, target_paths as usize);
    assert_eq!(session_snapshot.target_shortfall, 0);
    assert_eq!(session_snapshot.target_shortfall_reason, None);
    assert!(session_snapshot.endpoint_states[0].failures >= 1);
    assert_eq!(session_snapshot.endpoint_states[1].state, "available");
    assert!(
        session_snapshot
            .path_endpoint
            .values()
            .any(|index| *index == 1)
    );
    assert!(
        session_snapshot
            .path_endpoint
            .values()
            .any(|index| *index == 2)
    );
    data_plane
        .register_transit_adapter(
            stalled_id,
            Arc::new(StalledTransit {
                metadata: pathchord_transit::TransitMetadata {
                    adapter_id: "aaa-stalled".into(),
                    kind: pathchord_transit::AdapterKind::ExternalProxy {
                        protocol: "http".into(),
                    },
                    labels: BTreeMap::new(),
                },
            }),
            pathchord_policy::TransitProxyRuntimeStatus {
                state: pathchord_policy::RuntimeNodeState::Ready,
                capabilities: BTreeSet::from([FlowProtocol::Tcp]),
                selection_score: 1,
                ..Default::default()
            },
        )
        .await
        .unwrap();

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
    let connect_result = tokio::time::timeout(std::time::Duration::from_secs(3), async {
        while !response.ends_with(b"\r\n\r\n") {
            assert!(response.len() < 4096, "bounded HTTP response");
            response.push(client.read_u8().await.expect("CONNECT response"));
        }
    })
    .await;
    if connect_result.is_err() {
        let snap = data_plane.session_snapshots().await;
        panic!(
            "CONNECT stalled: Ingress {:?}, Egress {:?}, response {:?}",
            snap.iter()
                .map(|s| (
                    s.session.ready_paths,
                    s.session.pending_session_controls,
                    s.session.pending_stream_opens,
                    s.session.active_streams,
                    s.session.egress_status.as_ref().map(|r| (
                        r.fresh,
                        r.age_ms,
                        r.report.admission_allowed
                    ))
                ))
                .collect::<Vec<_>>(),
            egress.snapshot().unwrap(),
            response
        );
    }

    assert!(
        response.starts_with(b"HTTP/1.1 200"),
        "{}",
        String::from_utf8_lossy(&response)
    );

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

    let udp_target = UdpSocket::bind("127.0.0.1:0").await.expect("UDP target");
    let udp_target_address = udp_target.local_addr().expect("UDP target address");
    let udp_target_task = tokio::spawn(async move {
        let mut buffer = [0_u8; 128];
        let (length, peer) = udp_target
            .recv_from(&mut buffer)
            .await
            .expect("UDP receive");
        udp_target
            .send_to(&buffer[..length], peer)
            .await
            .expect("UDP echo");
    });
    let udp_context = ConnectionContext {
        flow_tags: BTreeSet::new(),
        listener_id: ListenerId::in_namespace(namespace, "udp-e2e"),
        source: "127.0.0.1:10001".parse().unwrap(),
        authentication_identity: None,
        process: None,
        protocol: FlowProtocol::Udp,
        target: TargetAddress {
            host: TargetHost::Ip(udp_target_address.ip()),
            port: udp_target_address.port(),
        },
    };
    let mut udp_flow = data_plane.open_udp(&udp_context).await.expect("UDP flow");
    udp_flow
        .send(b"real-pathchord-udp".to_vec())
        .await
        .expect("UDP send");
    assert_eq!(
        udp_flow.receive().await,
        Some(b"real-pathchord-udp".to_vec())
    );
    udp_flow.close().await.expect("UDP close");

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
    udp_target_task.await.expect("UDP target task");
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
    policy_with_endpoints(namespace, &[egress_address], egress_public_key)
}

fn policy_with_endpoints(
    namespace: &str,
    egress_endpoints: &[std::net::SocketAddr],
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
                endpoints: egress_endpoints
                    .iter()
                    .map(|endpoint| Endpoint {
                        host: endpoint.ip().to_string(),
                        port: endpoint.port(),
                    })
                    .collect(),
                public_key: URL_SAFE_NO_PAD.encode(egress_public_key),
                labels: BTreeMap::new(),
                capabilities: Capabilities {
                    tcp: true,
                    udp: false,
                },
                path_pool: EgressPathPoolConfig::default(),
                admission: EgressAdmission {
                    required_capabilities: BTreeSet::from([FlowProtocol::Tcp]),
                },
                transit: pathchord_policy::EgressTransitBinding::default(),
                traffic_policy: Some(traffic_policy_id.clone()),
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
