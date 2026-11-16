use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};

use async_trait::async_trait;
use pathchord_policy::{
    Capabilities, EgressConfig, EgressStatusRequirements, EgressTransitBinding, Endpoint,
    FallbackAction, FlowMatch, Generation, PolicyConfig, ProxyRule, ProxySelection,
    RetransmissionReplication, RuleId, Scheduler, TrafficPolicy, TrafficPolicyId,
};
use pathchord_transit::{
    AdapterKind, BoxedTransitConnection, BoxedTransitDatagram, NoTransitCredentials,
    TransitDatagram, TransitMetadata,
};
use tokio::net::TcpListener;
use tokio::sync::Notify;

use super::*;

fn proxy(id: &str, endpoint: std::net::SocketAddr) -> TransitProxyConfig {
    TransitProxyConfig {
        id: TransitProxyId::new(id),
        source: None,
        protocol: "http".to_owned(),
        endpoint: Endpoint {
            host: endpoint.ip().to_string(),
            port: endpoint.port(),
        },
        credentials_ref: None,
        labels: BTreeMap::new(),
        tags: BTreeSet::new(),
        weight: 100,
        options: pathchord_policy::TransitOptions::default(),
    }
}

fn policy(generation: u64, nodes: Vec<TransitProxyConfig>) -> ValidatedPolicySnapshot {
    ValidatedPolicySnapshot::new(
        Generation::new(generation),
        PolicyConfig {
            transit_proxies: nodes,
            proxy_rules: vec![ProxyRule {
                id: RuleId::new("ordinary"),
                matches: FlowMatch::default(),
                require: Selector::default(),
                select: ProxySelection::Any,
            }],
            fallback: Some(FallbackAction::Reject),
            ..PolicyConfig::default()
        },
    )
    .unwrap()
}

fn plane(snapshot: ValidatedPolicySnapshot) -> Arc<IngressDataPlane> {
    Arc::new(
        IngressDataPlane::new(IngressDataPlaneConfig::new(
            "reload-fixture",
            pathchord_noise::generate_static_keypair().unwrap(),
            snapshot,
        ))
        .unwrap(),
    )
}

fn egress_policy(generation: u64, budget_bps: u64) -> ValidatedPolicySnapshot {
    ValidatedPolicySnapshot::new(
        Generation::new(generation),
        PolicyConfig {
            egresses: vec![EgressConfig {
                id: EgressId::new("edge"),
                endpoints: vec![Endpoint {
                    host: "127.0.0.1".into(),
                    port: 7443,
                }],
                public_key: "test-key".into(),
                labels: BTreeMap::new(),
                capabilities: Capabilities {
                    tcp: true,
                    udp: true,
                },
                status_requirements: EgressStatusRequirements::default(),
                transit: EgressTransitBinding::default(),
                traffic_policy: Some(TrafficPolicyId::new("edge-policy")),
            }],
            traffic_policies: vec![TrafficPolicy {
                id: TrafficPolicyId::new("edge-policy"),
                scheduler: Scheduler::EffectiveCapacityWeighted,
                session_replication_budget_bps: budget_bps,
                class_replication_budget_bps: None,
                retransmission_replication: RetransmissionReplication::Allowed,
                classes: BTreeMap::new(),
            }],
            fallback: Some(FallbackAction::Reject),
            ..PolicyConfig::default()
        },
    )
    .unwrap()
}

fn registry(configs: &[TransitProxyConfig]) -> AdapterRegistry<NoTransitCredentials> {
    AdapterRegistry::for_configs(
        Arc::new(NoTransitCredentials),
        Duration::from_secs(1),
        configs,
    )
    .unwrap()
}

#[tokio::test]
async fn referenced_egress_policy_changes_require_restart() {
    let current = egress_policy(1, 8_000);
    let next = egress_policy(2, 16_000);
    let plane = plane(current.clone());
    let registry = registry(&[]);
    assert!(matches!(
        plane.prepare_static_snapshot(&next, &registry).await,
        Err(DataPlaneError::StaticReloadRequiresRestart)
    ));
}

#[tokio::test]
async fn egress_endpoint_topology_changes_require_restart() {
    let current = egress_policy(1, 8_000);
    let mut next_config = current.config().clone();
    next_config.egresses[0].endpoints.push(Endpoint {
        host: "2001:db8::10".into(),
        port: 8443,
    });
    let next = ValidatedPolicySnapshot::new(Generation::new(2), next_config).unwrap();
    let plane = plane(current);
    let registry = registry(&[]);
    assert!(matches!(
        plane.prepare_static_snapshot(&next, &registry).await,
        Err(DataPlaneError::StaticReloadRequiresRestart)
    ));
}

fn context() -> ConnectionContext {
    ConnectionContext {
        flow_tags: BTreeSet::new(),
        listener_id: crate::ListenerId::new("test"),
        source: "127.0.0.1:10000".parse().unwrap(),
        authentication_identity: None,
        process: None,
        protocol: FlowProtocol::Tcp,
        target: crate::TargetAddress {
            host: crate::TargetHost::Hostname("target.invalid".to_owned()),
            port: 80,
        },
    }
}

fn context_with_target(address: std::net::SocketAddr) -> ConnectionContext {
    let mut context = context();
    context.target = crate::TargetAddress {
        host: crate::TargetHost::Ip(address.ip()),
        port: address.port(),
    };
    context
}

async fn http_proxy(marker: u8) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let mut clients = JoinSet::new();
        loop {
            tokio::select! {
                accepted = listener.accept() => {
                    let (mut client, _) = accepted.unwrap();
                    clients.spawn(async move {
                        let mut header = Vec::new();
                        while !header.ends_with(b"\r\n\r\n") { header.push(client.read_u8().await.unwrap()); assert!(header.len() < 8192); }
                        client.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n").await.unwrap();
                        client.write_all(&[marker]).await.unwrap();
                        let mut bytes = [0; 256];
                        loop {
                            let count = client.read(&mut bytes).await.unwrap_or_default(); if count == 0 { break; }
                            if client.write_all(&bytes[..count]).await.is_err() { break; }
                        }
                    });
                }
                _ = clients.join_next(), if !clients.is_empty() => {}
            }
        }
    });
    (endpoint, task)
}

#[derive(Debug)]
struct FailoverDatagram {
    payload: Option<Vec<u8>>,
}

#[async_trait]
impl TransitDatagram for FailoverDatagram {
    async fn send(&mut self, payload: &[u8]) -> Result<(), TransitError> {
        self.payload = Some(payload.to_vec());
        Ok(())
    }

    async fn receive(&mut self) -> Result<Vec<u8>, TransitError> {
        self.payload
            .take()
            .ok_or_else(|| TransitError::Connection("no datagram is queued".to_owned()))
    }
}

#[derive(Debug)]
struct FailingSendDatagram;

#[async_trait]
impl TransitDatagram for FailingSendDatagram {
    async fn send(&mut self, _: &[u8]) -> Result<(), TransitError> {
        Err(TransitError::Connection("UDP send failed".to_owned()))
    }

    async fn receive(&mut self) -> Result<Vec<u8>, TransitError> {
        Err(TransitError::Connection("UDP receive failed".to_owned()))
    }
}

#[derive(Debug)]
struct FailoverAdapter {
    metadata: TransitMetadata,
    fail_tcp: bool,
    fail_udp: bool,
    fail_udp_send: bool,
    fail_tcp_write: bool,
    tcp_calls: Arc<AtomicUsize>,
    udp_calls: Arc<AtomicUsize>,
    tcp_release: Option<Arc<Notify>>,
}

#[async_trait]
impl TransitAdapter for FailoverAdapter {
    fn metadata(&self) -> &TransitMetadata {
        &self.metadata
    }

    fn supports_udp(&self) -> bool {
        true
    }

    async fn connect(&self, _: ConnectRequest) -> Result<BoxedTransitConnection, TransitError> {
        self.tcp_calls.fetch_add(1, Ordering::SeqCst);
        if let Some(release) = &self.tcp_release {
            release.notified().await;
        }
        if self.fail_tcp {
            return Err(TransitError::Connection(
                "synthetic first candidate failure".to_owned(),
            ));
        }
        if self.fail_tcp_write {
            let (local, remote) = tokio::io::duplex(1024);
            drop(remote);
            return Ok(Box::new(local));
        }
        let (local, remote) = tokio::io::duplex(1024);
        tokio::spawn(async move {
            let (mut read, mut write) = tokio::io::split(remote);
            let _ = tokio::io::copy(&mut read, &mut write).await;
        });
        Ok(Box::new(local))
    }

    async fn connect_udp(&self, _: ConnectRequest) -> Result<BoxedTransitDatagram, TransitError> {
        self.udp_calls.fetch_add(1, Ordering::SeqCst);
        if self.fail_udp {
            return Err(TransitError::Connection(
                "synthetic first UDP candidate failure".to_owned(),
            ));
        }
        if self.fail_udp_send {
            return Ok(Box::new(FailingSendDatagram));
        }
        Ok(Box::new(FailoverDatagram { payload: None }))
    }
}

fn failover_adapter(
    id: &str,
    fail_tcp: bool,
    fail_udp: bool,
) -> (Arc<FailoverAdapter>, Arc<AtomicUsize>, Arc<AtomicUsize>) {
    let tcp_calls = Arc::new(AtomicUsize::new(0));
    let udp_calls = Arc::new(AtomicUsize::new(0));
    let adapter = Arc::new(FailoverAdapter {
        metadata: TransitMetadata {
            adapter_id: id.to_owned(),
            kind: AdapterKind::ExternalProxy {
                protocol: "synthetic".to_owned(),
            },
            labels: BTreeMap::new(),
        },
        fail_tcp,
        fail_udp,
        fail_udp_send: false,
        fail_tcp_write: false,
        tcp_calls: Arc::clone(&tcp_calls),
        udp_calls: Arc::clone(&udp_calls),
        tcp_release: None,
    });
    (adapter, tcp_calls, udp_calls)
}

fn ready_tcp_udp() -> TransitProxyRuntimeStatus {
    TransitProxyRuntimeStatus {
        state: RuntimeNodeState::Ready,
        capabilities: BTreeSet::from([FlowProtocol::Tcp, FlowProtocol::Udp]),
        selection_score: 1,
        ..TransitProxyRuntimeStatus::default()
    }
}

async fn register_fixture_adapter(
    plane: &IngressDataPlane,
    config: &TransitProxyConfig,
    adapter: Arc<dyn TransitAdapter>,
) {
    plane
        .register_transit_adapter(config.id.clone(), adapter, ready_tcp_udp())
        .await
        .unwrap();
}

#[tokio::test]
async fn ordinary_proxy_retries_the_next_eligible_tcp_candidate_before_admission() {
    let first_config = proxy("first", "127.0.0.1:9".parse().unwrap());
    let second_config = proxy("second", "127.0.0.1:9".parse().unwrap());
    let plane = plane(policy(1, vec![first_config.clone(), second_config.clone()]));
    let (first, first_tcp, _) = failover_adapter("first", true, false);
    let (second, second_tcp, _) = failover_adapter("second", false, false);
    register_fixture_adapter(&plane, &first_config, first).await;
    register_fixture_adapter(&plane, &second_config, second).await;

    let mut stream = plane.open_tcp(&context()).await.unwrap();
    stream.write_all(b"failover").await.unwrap();
    let mut echoed = [0; 8];
    stream.read_exact(&mut echoed).await.unwrap();
    assert_eq!(&echoed, b"failover");
    assert_eq!(first_tcp.load(Ordering::SeqCst), 1);
    assert_eq!(second_tcp.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn ordinary_proxy_never_retries_after_an_admitted_tcp_flow_write_fails() {
    let first_config = proxy("first", "127.0.0.1:9".parse().unwrap());
    let second_config = proxy("second", "127.0.0.1:9".parse().unwrap());
    let plane = plane(policy(1, vec![first_config.clone(), second_config.clone()]));
    let (first, first_tcp, _) = failover_adapter("first", false, false);
    let mut first = Arc::try_unwrap(first).unwrap();
    first.fail_tcp_write = true;
    let (second, second_tcp, _) = failover_adapter("second", false, false);
    register_fixture_adapter(&plane, &first_config, Arc::new(first)).await;
    register_fixture_adapter(&plane, &second_config, second).await;

    let mut stream = plane.open_tcp(&context()).await.unwrap();
    assert!(stream.write_all(b"already-admitted").await.is_err());
    assert_eq!(first_tcp.load(Ordering::SeqCst), 1);
    assert_eq!(second_tcp.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn ordinary_proxy_retries_after_real_connect_rejection_without_sending_payload() {
    timeout(Duration::from_secs(5), async {
        let first = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let first_address = first.local_addr().unwrap();
        let first_task = tokio::spawn(async move {
            let (mut stream, _) = first.accept().await.unwrap();
            let mut header = Vec::new();
            while !header.ends_with(b"\r\n\r\n") {
                header.push(stream.read_u8().await.unwrap());
                assert!(header.len() < 8192);
            }
            assert!(header.starts_with(b"CONNECT target.invalid:80 HTTP/1.1\r\n"));
            stream
                .write_all(b"HTTP/1.1 503 Service Unavailable\r\n\r\n")
                .await
                .unwrap();
            let mut extra = [0; 1];
            assert_eq!(stream.read(&mut extra).await.unwrap(), 0);
        });
        let (second_address, second_task) = http_proxy(b'B').await;
        let configs = vec![
            proxy("first", first_address),
            proxy("second", second_address),
        ];
        let plane = plane(policy(1, configs.clone()));
        let registry = registry(&configs);
        for config in &configs {
            let adapter = registry.build(config).await.unwrap();
            register_fixture_adapter(&plane, config, adapter).await;
        }
        let mut stream = plane.open_tcp(&context()).await.unwrap();
        assert_eq!(stream.read_u8().await.unwrap(), b'B');
        stream.write_all(b"payload").await.unwrap();
        let mut echoed = [0; 7];
        stream.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"payload");
        first_task.await.unwrap();
        second_task.abort();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn ordinary_proxy_retries_the_next_eligible_udp_candidate_before_admission() {
    let first_config = proxy("first", "127.0.0.1:9".parse().unwrap());
    let second_config = proxy("second", "127.0.0.1:9".parse().unwrap());
    let plane = plane(policy(1, vec![first_config.clone(), second_config.clone()]));
    let (first, _, first_udp) = failover_adapter("first", false, true);
    let (second, _, second_udp) = failover_adapter("second", false, false);
    register_fixture_adapter(&plane, &first_config, first).await;
    register_fixture_adapter(&plane, &second_config, second).await;

    let mut handle = plane.open_udp(&context()).await.unwrap();
    handle.send(b"udp-failover".to_vec()).await.unwrap();
    assert_eq!(handle.receive().await, Some(b"udp-failover".to_vec()));
    assert_eq!(first_udp.load(Ordering::SeqCst), 1);
    assert_eq!(second_udp.load(Ordering::SeqCst), 1);
    handle.close().await.unwrap();
}

#[tokio::test]
async fn ordinary_proxy_never_retries_after_an_admitted_udp_flow_send_fails() {
    let first_config = proxy("first", "127.0.0.1:9".parse().unwrap());
    let second_config = proxy("second", "127.0.0.1:9".parse().unwrap());
    let plane = plane(policy(1, vec![first_config.clone(), second_config.clone()]));
    let (first, _, first_udp) = failover_adapter("first", false, false);
    let mut first = Arc::try_unwrap(first).unwrap();
    first.fail_udp_send = true;
    let (second, _, second_udp) = failover_adapter("second", false, false);
    register_fixture_adapter(&plane, &first_config, Arc::new(first)).await;
    register_fixture_adapter(&plane, &second_config, second).await;

    let mut handle = plane.open_udp(&context()).await.unwrap();
    assert!(handle.send(b"already-admitted".to_vec()).await.is_err());
    assert_eq!(first_udp.load(Ordering::SeqCst), 1);
    assert_eq!(second_udp.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn failed_ordinary_proxy_candidates_do_not_fall_back_to_direct() {
    let first_config = proxy("first", "127.0.0.1:9".parse().unwrap());
    let second_config = proxy("second", "127.0.0.1:9".parse().unwrap());
    let config = policy(1, vec![first_config.clone(), second_config.clone()])
        .config()
        .clone();
    let snapshot = ValidatedPolicySnapshot::new(
        Generation::new(1),
        PolicyConfig {
            fallback: Some(FallbackAction::Direct),
            ..config
        },
    )
    .unwrap();
    let plane = plane(snapshot);
    let (first, _, _) = failover_adapter("first", true, false);
    let (second, _, _) = failover_adapter("second", true, false);
    register_fixture_adapter(&plane, &first_config, first).await;
    register_fixture_adapter(&plane, &second_config, second).await;

    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target_address = target.local_addr().unwrap();
    let result = plane.open_tcp(&context_with_target(target_address)).await;
    assert!(matches!(result, Err(DataPlaneError::Transit(_))));
    assert!(
        timeout(Duration::from_millis(50), target.accept())
            .await
            .is_err()
    );
}

#[tokio::test]
async fn failed_ordinary_udp_candidates_do_not_fall_back_to_direct() {
    let first_config = proxy("first", "127.0.0.1:9".parse().unwrap());
    let second_config = proxy("second", "127.0.0.1:9".parse().unwrap());
    let config = policy(1, vec![first_config.clone(), second_config.clone()])
        .config()
        .clone();
    let snapshot = ValidatedPolicySnapshot::new(
        Generation::new(1),
        PolicyConfig {
            fallback: Some(FallbackAction::Direct),
            ..config
        },
    )
    .unwrap();
    let plane = plane(snapshot);
    let (first, _, first_udp) = failover_adapter("first", false, true);
    let (second, _, second_udp) = failover_adapter("second", false, true);
    register_fixture_adapter(&plane, &first_config, first).await;
    register_fixture_adapter(&plane, &second_config, second).await;

    let target = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let result = plane
        .open_udp(&context_with_target(target.local_addr().unwrap()))
        .await;
    assert!(matches!(result, Err(DataPlaneError::Transit(_))));
    assert_eq!(first_udp.load(Ordering::SeqCst), 1);
    assert_eq!(second_udp.load(Ordering::SeqCst), 1);
    let mut packet = [0; 16];
    assert!(
        timeout(Duration::from_millis(50), target.recv_from(&mut packet))
            .await
            .is_err()
    );
}

#[tokio::test]
async fn ordinary_proxy_attempts_only_a_bounded_number_of_eligible_nodes() {
    let configs: Vec<_> = (0..MAX_ORDINARY_PROXY_ATTEMPTS + 1)
        .map(|index| proxy(&format!("node-{index:02}"), "127.0.0.1:9".parse().unwrap()))
        .collect();
    let plane = plane(policy(1, configs.clone()));
    let mut calls = Vec::new();
    for (index, config) in configs.iter().enumerate() {
        let (adapter, tcp_calls, _) = failover_adapter(
            config.id.as_str(),
            index != MAX_ORDINARY_PROXY_ATTEMPTS,
            false,
        );
        register_fixture_adapter(&plane, config, adapter).await;
        calls.push(tcp_calls);
    }
    assert!(matches!(
        plane.open_tcp(&context()).await,
        Err(DataPlaneError::Transit(_))
    ));
    assert!(
        calls[..MAX_ORDINARY_PROXY_ATTEMPTS]
            .iter()
            .all(|calls| calls.load(Ordering::SeqCst) == 1)
    );
    assert_eq!(calls[MAX_ORDINARY_PROXY_ATTEMPTS].load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn ordinary_proxy_times_out_a_stalled_candidate_and_tries_the_next() {
    let first_config = proxy("first", "127.0.0.1:9".parse().unwrap());
    let second_config = proxy("second", "127.0.0.1:9".parse().unwrap());
    let mut config = IngressDataPlaneConfig::new(
        "timeout-fixture",
        pathchord_noise::generate_static_keypair().unwrap(),
        policy(1, vec![first_config.clone(), second_config.clone()]),
    );
    config.path_connect_timeout = Duration::from_millis(20);
    let plane = Arc::new(IngressDataPlane::new(config).unwrap());
    let (first, first_tcp, _) = failover_adapter("first", true, false);
    let mut first = Arc::try_unwrap(first).unwrap();
    first.tcp_release = Some(Arc::new(Notify::new()));
    let (second, second_tcp, _) = failover_adapter("second", false, false);
    register_fixture_adapter(&plane, &first_config, Arc::new(first)).await;
    register_fixture_adapter(&plane, &second_config, second).await;

    let mut stream = timeout(Duration::from_secs(1), plane.open_tcp(&context()))
        .await
        .unwrap()
        .unwrap();
    stream.write_all(b"echo").await.unwrap();
    let mut echoed = [0; 4];
    stream.read_exact(&mut echoed).await.unwrap();
    assert_eq!(&echoed, b"echo");
    assert_eq!(first_tcp.load(Ordering::SeqCst), 1);
    assert_eq!(second_tcp.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn cancelling_ordinary_proxy_dial_releases_the_publication_gate() {
    let node = proxy("node", "127.0.0.1:9".parse().unwrap());
    let plane = plane(policy(1, vec![node.clone()]));
    let (adapter, calls, _) = failover_adapter("node", true, false);
    let mut adapter = Arc::try_unwrap(adapter).unwrap();
    adapter.tcp_release = Some(Arc::new(Notify::new()));
    register_fixture_adapter(&plane, &node, Arc::new(adapter)).await;
    let opening = {
        let plane = Arc::clone(&plane);
        tokio::spawn(async move { plane.open_tcp(&context()).await })
    };
    timeout(Duration::from_secs(1), async {
        while calls.load(Ordering::SeqCst) == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let (replacement, _, _) = failover_adapter("replacement", false, false);
    let mut update = {
        let plane = Arc::clone(&plane);
        tokio::spawn(async move {
            plane
                .register_transit_adapter(node.id, replacement, ready_tcp_udp())
                .await
        })
    };
    assert!(
        timeout(Duration::from_millis(25), &mut update)
            .await
            .is_err()
    );
    opening.abort();
    assert!(matches!(opening.await, Err(error) if error.is_cancelled()));
    timeout(Duration::from_secs(1), update)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn stalled_ordinary_proxy_attempts_cannot_indefinitely_delay_subscription_disable() {
    let mut config = IngressDataPlaneConfig::new(
        "timeout-fixture",
        pathchord_noise::generate_static_keypair().unwrap(),
        policy(1, Vec::new()),
    );
    config.path_connect_timeout = Duration::from_millis(100);
    let plane = Arc::new(IngressDataPlane::new(config).unwrap());
    let mut calls = Vec::new();
    for id in ["first", "second"] {
        let mut node = proxy(id, "127.0.0.1:9".parse().unwrap());
        node.source = Some(pathchord_policy::TransitSource {
            source_type: "clash".to_owned(),
            subscription: "provider".to_owned(),
        });
        let (adapter, tcp_calls, _) = failover_adapter(id, true, false);
        let mut adapter = Arc::try_unwrap(adapter).unwrap();
        adapter.tcp_release = Some(Arc::new(Notify::new()));
        plane
            .register_dynamic_transit_adapter(node, Arc::new(adapter), ready_tcp_udp())
            .await;
        calls.push(tcp_calls);
    }
    let opening = {
        let plane = Arc::clone(&plane);
        tokio::spawn(async move { plane.open_tcp(&context()).await })
    };
    timeout(Duration::from_secs(1), async {
        while calls[0].load(Ordering::SeqCst) == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let disable = {
        let plane = Arc::clone(&plane);
        tokio::spawn(async move {
            plane
                .subscription_transaction("provider", || ((), Some(false)))
                .await;
        })
    };
    timeout(Duration::from_millis(500), disable)
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(
        opening.await.unwrap(),
        Err(DataPlaneError::Transit(_))
    ));
    assert_eq!(calls[0].load(Ordering::SeqCst), 1);
    assert_eq!(calls[1].load(Ordering::SeqCst), 1);
    assert!(matches!(
        plane.open_tcp(&context()).await,
        Err(DataPlaneError::PolicyRejected)
    ));
}

#[tokio::test]
async fn disabling_a_subscription_cancels_queued_node_probes_without_affecting_static_nodes() {
    let static_node = proxy("a-static", "127.0.0.1:9".parse().unwrap());
    let plane = plane(policy(1, vec![static_node.clone()]));
    let (blocker, static_calls, _) = failover_adapter("a-static", false, false);
    let mut blocker = Arc::try_unwrap(blocker).unwrap();
    let release = Arc::new(Notify::new());
    blocker.tcp_release = Some(Arc::clone(&release));
    register_fixture_adapter(&plane, &static_node, Arc::new(blocker)).await;

    let mut dynamic_node = proxy("z-provider", "127.0.0.1:9".parse().unwrap());
    dynamic_node.source = Some(pathchord_policy::TransitSource {
        source_type: "clash".into(),
        subscription: "provider".into(),
    });
    let (dynamic, dynamic_calls, _) = failover_adapter("z-provider", false, false);
    plane
        .register_dynamic_transit_adapter(dynamic_node, dynamic, ready_tcp_udp())
        .await;

    let mut config = crate::TransitProbeConfig::new(pathchord_transit::Endpoint {
        host: "target.invalid".into(),
        port: 80,
    });
    config.max_concurrency = 1;
    config.timeout = Duration::from_secs(2);
    plane.configure_node_probe(Some(config)).await.unwrap();
    let probe = {
        let plane = Arc::clone(&plane);
        tokio::spawn(async move { plane.probe_transits().await })
    };
    timeout(Duration::from_secs(1), async {
        while static_calls.load(Ordering::SeqCst) == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    plane
        .subscription_transaction("provider", || ((), Some(false)))
        .await;
    release.notify_one();
    timeout(Duration::from_secs(2), probe)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(static_calls.load(Ordering::SeqCst), 1);
    assert_eq!(dynamic_calls.load(Ordering::SeqCst), 0);
    let observations = plane.transit_observations().await;
    assert_eq!(
        observations[&static_node.id].state,
        crate::TransitProbeState::Up
    );
}

#[tokio::test]
async fn disabling_a_subscription_cancels_an_inflight_node_probe() {
    let static_node = proxy("z-static", "127.0.0.1:9".parse().unwrap());
    let plane = plane(policy(1, vec![static_node.clone()]));
    let (static_adapter, static_calls, _) = failover_adapter("z-static", false, false);
    register_fixture_adapter(&plane, &static_node, static_adapter).await;

    let mut dynamic_node = proxy("a-provider", "127.0.0.1:9".parse().unwrap());
    dynamic_node.source = Some(pathchord_policy::TransitSource {
        source_type: "clash".into(),
        subscription: "provider".into(),
    });
    let dynamic_id = dynamic_node.id.clone();
    let (dynamic, dynamic_calls, _) = failover_adapter("a-provider", false, false);
    let mut dynamic = Arc::try_unwrap(dynamic).unwrap();
    dynamic.tcp_release = Some(Arc::new(Notify::new()));
    plane
        .register_dynamic_transit_adapter(dynamic_node, Arc::new(dynamic), ready_tcp_udp())
        .await;
    let mut config = crate::TransitProbeConfig::new(pathchord_transit::Endpoint {
        host: "target.invalid".into(),
        port: 80,
    });
    config.max_concurrency = 1;
    config.timeout = Duration::from_secs(10);
    plane.configure_node_probe(Some(config)).await.unwrap();
    let probe = {
        let plane = Arc::clone(&plane);
        tokio::spawn(async move { plane.probe_transits().await })
    };
    timeout(Duration::from_secs(1), async {
        while dynamic_calls.load(Ordering::SeqCst) == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    plane
        .subscription_transaction("provider", || ((), Some(false)))
        .await;
    // The blocked dial must be dropped; waiting for its ten-second timeout
    // would also block the independent static probe.
    timeout(Duration::from_secs(1), probe)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(dynamic_calls.load(Ordering::SeqCst), 1);
    assert_eq!(static_calls.load(Ordering::SeqCst), 1);
    let observations = plane.transit_observations().await;
    assert_eq!(observations[&dynamic_id].attempts, 0);
    assert_eq!(
        observations[&static_node.id].state,
        crate::TransitProbeState::Up
    );
}

#[tokio::test]
async fn queued_probe_rechecks_the_subscription_admission_before_dialing() {
    struct FixtureFetcher(Vec<u8>);
    #[async_trait]
    impl pathchord_transit::SubscriptionFetcher for FixtureFetcher {
        async fn fetch(
            &self,
            _: pathchord_transit::SubscriptionFetchRequest,
        ) -> Result<Vec<u8>, pathchord_transit::SubscriptionError> {
            Ok(self.0.clone())
        }
    }

    let static_node = proxy("a-static", "127.0.0.1:9".parse().unwrap());
    let plane = plane(policy(1, vec![static_node.clone()]));
    let (blocker, static_calls, _) = failover_adapter("a-static", false, false);
    let mut blocker = Arc::try_unwrap(blocker).unwrap();
    let release = Arc::new(Notify::new());
    blocker.tcp_release = Some(Arc::clone(&release));
    register_fixture_adapter(&plane, &static_node, Arc::new(blocker)).await;

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let document =
        format!("proxies: [{{name: node, type: http, server: 127.0.0.1, port: {port}}}]");
    let source = pathchord_policy::SubscriptionConfig {
        id: pathchord_policy::SubscriptionId::new("provider"),
        enabled: true,
        source: pathchord_policy::SubscriptionSource {
            source_type: pathchord_policy::SubscriptionSourceType::Clash,
            url: "https://example.test/sub".into(),
            credentials_ref: None,
            user_agent: None,
        },
        refresh: Default::default(),
        cache: None,
    };
    let mut manager = pathchord_transit::SubscriptionManager::new(
        Arc::new(FixtureFetcher(document.into_bytes())),
        std::env::temp_dir(),
        BTreeSet::from(["http".into()]),
    );
    assert!(matches!(
        manager.refresh(&source).await,
        pathchord_transit::RefreshOutcome::Published { .. }
    ));
    let registry = AdapterRegistry::for_configs(
        Arc::new(NoTransitCredentials),
        Duration::from_secs(1),
        manager.snapshot().nodes.values().map(|node| &node.config),
    )
    .unwrap();
    let prepared = manager.snapshot().prepare_adapters(&registry).await;
    manager.commit_prepared_adapters(prepared).unwrap();
    let node = manager.snapshot().selectable_nodes().next().unwrap();
    let id = node.config.id.clone();
    assert!(static_node.id < id);
    let admission = manager.snapshot().validated_admission(&id).unwrap();
    assert_eq!(
        plane
            .register_verified_dynamic_transit_adapter(
                node.config.clone(),
                admission,
                ready_tcp_udp()
            )
            .await,
        DynamicTransitRegistration::Registered
    );

    let mut config = crate::TransitProbeConfig::new(pathchord_transit::Endpoint {
        host: "target.invalid".into(),
        port: 80,
    });
    config.max_concurrency = 1;
    config.timeout = Duration::from_secs(2);
    plane.configure_node_probe(Some(config)).await.unwrap();
    let probe = {
        let plane = Arc::clone(&plane);
        tokio::spawn(async move { plane.probe_transits().await })
    };
    timeout(Duration::from_secs(1), async {
        while static_calls.load(Ordering::SeqCst) == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    // Revoke through the subscription manager before any data-plane status
    // update, so only the admission token can fence this queued adapter.
    manager.reconcile(&[]);
    release.notify_one();
    timeout(Duration::from_secs(2), probe)
        .await
        .unwrap()
        .unwrap();
    assert!(
        timeout(Duration::from_millis(50), listener.accept())
            .await
            .is_err()
    );
    assert_eq!(plane.transit_observations().await[&id].attempts, 0);
}

#[tokio::test]
async fn ordinary_proxy_candidate_snapshot_is_held_until_a_flow_is_admitted() {
    let first_config = proxy("first", "127.0.0.1:9".parse().unwrap());
    let second_config = proxy("second", "127.0.0.1:9".parse().unwrap());
    let plane = plane(policy(1, vec![first_config.clone(), second_config.clone()]));
    let release = Arc::new(Notify::new());
    let first_tcp = Arc::new(AtomicUsize::new(0));
    let first = Arc::new(FailoverAdapter {
        metadata: TransitMetadata {
            adapter_id: "first".to_owned(),
            kind: AdapterKind::ExternalProxy {
                protocol: "synthetic".to_owned(),
            },
            labels: BTreeMap::new(),
        },
        fail_tcp: true,
        fail_udp: false,
        fail_udp_send: false,
        fail_tcp_write: false,
        tcp_calls: Arc::clone(&first_tcp),
        udp_calls: Arc::new(AtomicUsize::new(0)),
        tcp_release: Some(Arc::clone(&release)),
    });
    let (second, second_tcp, _) = failover_adapter("second", false, false);
    register_fixture_adapter(&plane, &first_config, first).await;
    register_fixture_adapter(
        &plane,
        &second_config,
        Arc::clone(&second) as Arc<dyn TransitAdapter>,
    )
    .await;

    let opening = {
        let plane = Arc::clone(&plane);
        tokio::spawn(async move { plane.open_tcp(&context()).await })
    };
    timeout(Duration::from_secs(1), async {
        while first_tcp.load(Ordering::SeqCst) == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();

    let replacement_calls = Arc::new(AtomicUsize::new(0));
    let replacement = Arc::new(FailoverAdapter {
        metadata: TransitMetadata {
            adapter_id: "second-replacement".to_owned(),
            kind: AdapterKind::ExternalProxy {
                protocol: "synthetic".to_owned(),
            },
            labels: BTreeMap::new(),
        },
        fail_tcp: false,
        fail_udp: false,
        fail_udp_send: false,
        fail_tcp_write: false,
        tcp_calls: Arc::clone(&replacement_calls),
        udp_calls: Arc::new(AtomicUsize::new(0)),
        tcp_release: None,
    });
    let mut register = {
        let plane = Arc::clone(&plane);
        let config = second_config.clone();
        tokio::spawn(async move {
            plane
                .register_transit_adapter(config.id, replacement, ready_tcp_udp())
                .await
        })
    };
    assert!(
        timeout(Duration::from_millis(50), &mut register)
            .await
            .is_err()
    );
    release.notify_one();
    let mut stream = timeout(Duration::from_secs(1), opening)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    stream.write_all(b"old").await.unwrap();
    let mut echoed = [0; 3];
    stream.read_exact(&mut echoed).await.unwrap();
    assert_eq!(&echoed, b"old");
    timeout(Duration::from_secs(1), register)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(second_tcp.load(Ordering::SeqCst), 1);
    assert_eq!(replacement_calls.load(Ordering::SeqCst), 0);
    let opening = {
        let plane = Arc::clone(&plane);
        tokio::spawn(async move { plane.open_tcp(&context()).await })
    };
    timeout(Duration::from_secs(1), async {
        while first_tcp.load(Ordering::SeqCst) < 2 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    release.notify_one();
    let _new_stream = timeout(Duration::from_secs(1), opening)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(replacement_calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn ordinary_proxy_retry_uses_the_original_static_configuration_generation() {
    timeout(Duration::from_secs(5), async {
        let first_config = proxy("first", "127.0.0.1:9".parse().unwrap());
        let (old_address, old_task) = http_proxy(b'O').await;
        let (new_address, new_task) = http_proxy(b'N').await;
        let old_second = proxy("second", old_address);
        let new_second = proxy("second", new_address);
        let plane = plane(policy(1, vec![first_config.clone(), old_second.clone()]));
        let (first, first_calls, _) = failover_adapter("first", true, false);
        let release = Arc::new(Notify::new());
        let mut first = Arc::try_unwrap(first).unwrap();
        first.tcp_release = Some(Arc::clone(&release));
        register_fixture_adapter(&plane, &first_config, Arc::new(first)).await;
        let registry = registry(&[first_config.clone(), old_second.clone()]);
        let old_adapter = registry.build(&old_second).await.unwrap();
        register_fixture_adapter(&plane, &old_second, old_adapter).await;

        let opening = {
            let plane = Arc::clone(&plane);
            tokio::spawn(async move { plane.open_tcp(&context()).await })
        };
        while first_calls.load(Ordering::SeqCst) == 0 {
            tokio::task::yield_now().await;
        }
        let next = policy(2, vec![first_config, new_second]);
        let prepared = plane
            .prepare_static_snapshot(&next, &registry)
            .await
            .unwrap();
        let mut reload = {
            let plane = Arc::clone(&plane);
            tokio::spawn(async move { plane.commit_static_snapshot(prepared, || Ok(())).await })
        };
        assert!(
            timeout(Duration::from_millis(50), &mut reload)
                .await
                .is_err()
        );
        release.notify_one();
        let mut old = opening.await.unwrap().unwrap();
        assert_eq!(old.read_u8().await.unwrap(), b'O');
        reload.await.unwrap().unwrap();
        assert_eq!(plane.policy_generation(), 2);

        let opening = {
            let plane = Arc::clone(&plane);
            tokio::spawn(async move { plane.open_tcp(&context()).await })
        };
        while first_calls.load(Ordering::SeqCst) < 2 {
            tokio::task::yield_now().await;
        }
        release.notify_one();
        let mut new = opening.await.unwrap().unwrap();
        assert_eq!(new.read_u8().await.unwrap(), b'N');
        old_task.abort();
        new_task.abort();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn static_reload_replaces_the_real_endpoint_and_keeps_admitted_tcp_flows() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let (first, first_task) = http_proxy(b'A').await;
        let (second, second_task) = http_proxy(b'B').await;
        let first_config = proxy("static-node", first);
        let second_config = proxy("static-node", second);
        let plane = plane(policy(1, vec![first_config.clone()]));
        let registry = registry(std::slice::from_ref(&first_config));
        let adapter = registry.build(&first_config).await.unwrap();
        plane
            .register_transit_adapter(
                first_config.id.clone(),
                adapter,
                TransitProxyRuntimeStatus {
                    state: RuntimeNodeState::Ready,
                    capabilities: BTreeSet::from([FlowProtocol::Tcp]),
                    selection_score: 1,
                    ..TransitProxyRuntimeStatus::default()
                },
            )
            .await
            .unwrap();
        let mut existing = plane.open_tcp(&context()).await.unwrap();
        assert_eq!(existing.read_u8().await.unwrap(), b'A');
        let outcome = plane
            .apply_static_snapshot(&policy(2, vec![second_config]), &registry)
            .await
            .unwrap();
        assert_eq!(outcome.changed, std::slice::from_ref(&first_config.id));
        assert_eq!(plane.policy_generation(), 2);
        let mut replacement = plane.open_tcp(&context()).await.unwrap();
        assert_eq!(replacement.read_u8().await.unwrap(), b'B');
        existing.write_all(b"old").await.unwrap();
        let mut bytes = [0; 3];
        existing.read_exact(&mut bytes).await.unwrap();
        assert_eq!(&bytes, b"old");
        replacement.shutdown().await.unwrap();
        existing.shutdown().await.unwrap();
        first_task.abort();
        second_task.abort();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn failed_static_adapter_build_keeps_generation_policy_and_all_old_adapters() {
    let endpoint = "127.0.0.1:12345".parse().unwrap();
    let original = proxy("static-node", endpoint);
    let plane = plane(policy(1, vec![original.clone()]));
    let registry = registry(std::slice::from_ref(&original));
    let adapter = registry.build(&original).await.unwrap();
    plane
        .register_transit_adapter(
            original.id.clone(),
            Arc::clone(&adapter),
            TransitProxyRuntimeStatus {
                state: RuntimeNodeState::Ready,
                ..TransitProxyRuntimeStatus::default()
            },
        )
        .await
        .unwrap();
    let mut invalid = proxy("new-node", endpoint);
    invalid.protocol = "ss".to_owned();
    let next = policy(2, vec![proxy("replacement", endpoint), invalid]);
    assert!(plane.apply_static_snapshot(&next, &registry).await.is_err());
    assert_eq!(plane.policy_generation(), 1);
    assert_eq!(plane.transit_configs.read().await[&original.id], original);
    assert_eq!(plane.transit_adapters.read().await.len(), 1);
    assert!(Arc::ptr_eq(
        &plane.transit_adapters.read().await[&original.id],
        &adapter
    ));
    assert!(
        plane
            .runtime
            .read()
            .await
            .transit_proxy(&TransitProxyId::new("replacement"))
            .is_none()
    );
}

#[tokio::test]
async fn static_reconciliation_reuses_unchanged_adapters_and_preserves_dynamic_nodes() {
    let endpoint = "127.0.0.1:12345".parse().unwrap();
    let original = proxy("static-node", endpoint);
    let plane = plane(policy(1, vec![original.clone()]));
    let registry = registry(std::slice::from_ref(&original));
    let adapter = registry.build(&original).await.unwrap();
    plane
        .register_transit_adapter(
            original.id.clone(),
            Arc::clone(&adapter),
            TransitProxyRuntimeStatus {
                state: RuntimeNodeState::Ready,
                ..TransitProxyRuntimeStatus::default()
            },
        )
        .await
        .unwrap();
    let dynamic = proxy("subscription-node", endpoint);
    let dynamic_adapter = registry.build(&dynamic).await.unwrap();
    plane
        .register_dynamic_transit_adapter(
            dynamic.clone(),
            Arc::clone(&dynamic_adapter),
            TransitProxyRuntimeStatus {
                state: RuntimeNodeState::Ready,
                ..TransitProxyRuntimeStatus::default()
            },
        )
        .await;
    let outcome = plane
        .apply_static_snapshot(&policy(2, vec![original.clone()]), &registry)
        .await
        .unwrap();
    assert!(outcome.changed.is_empty() && outcome.added.is_empty());
    assert!(Arc::ptr_eq(
        &plane.transit_adapters.read().await[&original.id],
        &adapter
    ));
    assert!(Arc::ptr_eq(
        &plane.transit_adapters.read().await[&dynamic.id],
        &dynamic_adapter
    ));
    assert!(matches!(
        plane
            .apply_static_snapshot(&policy(3, vec![dynamic.clone()]), &registry)
            .await,
        Err(DataPlaneError::StaticDynamicConflict)
    ));
    assert_eq!(plane.policy_generation(), 2);
    let outcome = plane
        .apply_static_snapshot(&policy(3, vec![]), &registry)
        .await
        .unwrap();
    assert_eq!(outcome.removed, std::slice::from_ref(&original.id));
    assert!(
        !plane
            .transit_adapters
            .read()
            .await
            .contains_key(&original.id)
    );
    assert!(
        plane
            .transit_adapters
            .read()
            .await
            .contains_key(&dynamic.id)
    );
    assert!(
        plane
            .runtime
            .read()
            .await
            .transit_proxy(&dynamic.id)
            .is_some()
    );
}

#[tokio::test]
async fn rejected_durable_commit_and_stale_preparation_leave_the_live_snapshot_untouched() {
    let endpoint = "127.0.0.1:12345".parse().unwrap();
    let original = proxy("static-node", endpoint);
    let plane = plane(policy(1, vec![original.clone()]));
    let registry = registry(std::slice::from_ref(&original));
    let adapter = registry.build(&original).await.unwrap();
    plane
        .register_transit_adapter(
            original.id.clone(),
            Arc::clone(&adapter),
            TransitProxyRuntimeStatus {
                state: RuntimeNodeState::Ready,
                ..TransitProxyRuntimeStatus::default()
            },
        )
        .await
        .unwrap();
    let prepared = plane
        .prepare_static_snapshot(&policy(2, vec![]), &registry)
        .await
        .unwrap();
    assert!(matches!(
        plane
            .commit_static_snapshot(prepared, || Err(DataPlaneError::ControlCommitRejected))
            .await,
        Err(DataPlaneError::ControlCommitRejected)
    ));
    assert_eq!(plane.policy_generation(), 1);
    assert!(Arc::ptr_eq(
        &plane.transit_adapters.read().await[&original.id],
        &adapter
    ));
    assert_eq!(plane.transit_configs.read().await[&original.id], original);
    let stale = plane
        .prepare_static_snapshot(&policy(2, vec![]), &registry)
        .await
        .unwrap();
    let current = plane
        .prepare_static_snapshot(&policy(3, vec![original.clone()]), &registry)
        .await
        .unwrap();
    plane
        .commit_static_snapshot(current, || Ok(()))
        .await
        .unwrap();
    let called = AtomicUsize::new(0);
    assert!(matches!(
        plane
            .commit_static_snapshot(stale, || {
                called.fetch_add(1, Ordering::SeqCst);
                Ok(())
            })
            .await,
        Err(DataPlaneError::StaticReloadConflict)
    ));
    assert_eq!(called.load(Ordering::SeqCst), 0);
    assert_eq!(plane.policy_generation(), 3);
}

struct ControlledProbe {
    metadata: TransitMetadata,
    behavior: Arc<AtomicU8>,
    active: Arc<AtomicUsize>,
    maximum: Arc<AtomicUsize>,
    targets: Arc<std::sync::Mutex<Vec<TransitEndpoint>>>,
    release: Arc<Notify>,
}

#[async_trait]
impl TransitAdapter for ControlledProbe {
    fn metadata(&self) -> &TransitMetadata {
        &self.metadata
    }
    async fn connect(
        &self,
        request: ConnectRequest,
    ) -> Result<BoxedTransitConnection, TransitError> {
        struct Active(Arc<AtomicUsize>);
        impl Drop for Active {
            fn drop(&mut self) {
                self.0.fetch_sub(1, Ordering::SeqCst);
            }
        }
        self.targets.lock().unwrap().push(request.destination);
        let current = self.active.fetch_add(1, Ordering::SeqCst) + 1;
        self.maximum.fetch_max(current, Ordering::SeqCst);
        let _active = Active(Arc::clone(&self.active));
        match self.behavior.load(Ordering::SeqCst) {
            1 => Err(TransitError::Connection("private-error-detail".to_owned())),
            2 => {
                self.release.notified().await;
                Err(TransitError::Connection("released".to_owned()))
            }
            _ => {
                tokio::time::sleep(Duration::from_millis(5)).await;
                Ok(Box::new(tokio::io::duplex(16).0))
            }
        }
    }
}

#[tokio::test]
async fn probes_require_an_explicit_target_are_bounded_and_recover_without_inventing_bandwidth() {
    let configs: Vec<_> = (0..5)
        .map(|index| proxy(&format!("node-{index}"), "127.0.0.1:1080".parse().unwrap()))
        .collect();
    let plane = plane(policy(1, configs.clone()));
    let behavior = Arc::new(AtomicU8::new(0));
    let active = Arc::new(AtomicUsize::new(0));
    let maximum = Arc::new(AtomicUsize::new(0));
    let targets = Arc::new(std::sync::Mutex::new(Vec::new()));
    for config in &configs {
        let adapter = Arc::new(ControlledProbe {
            metadata: TransitMetadata {
                adapter_id: config.id.as_str().to_owned(),
                kind: AdapterKind::ExternalProxy {
                    protocol: "fixture".to_owned(),
                },
                labels: BTreeMap::new(),
            },
            behavior: Arc::clone(&behavior),
            active: Arc::clone(&active),
            maximum: Arc::clone(&maximum),
            targets: Arc::clone(&targets),
            release: Arc::new(Notify::new()),
        });
        plane
            .register_transit_adapter(
                config.id.clone(),
                adapter,
                TransitProxyRuntimeStatus {
                    state: RuntimeNodeState::Ready,
                    capabilities: BTreeSet::from([FlowProtocol::Tcp]),
                    ..TransitProxyRuntimeStatus::default()
                },
            )
            .await
            .unwrap();
    }
    plane.probe_transits().await;
    assert!(targets.lock().unwrap().is_empty());
    assert!(
        plane
            .transit_observations()
            .await
            .values()
            .all(
                |observation| observation.state == crate::TransitProbeState::Unknown
                    && observation.rtt_ms.is_none()
            )
    );
    let target = TransitEndpoint {
        host: "explicit-probe.invalid".to_owned(),
        port: 8443,
    };
    let mut config = crate::TransitProbeConfig::new(target.clone());
    config.max_concurrency = 2;
    config.window_size = 2;
    config.timeout = Duration::from_millis(20);
    plane.configure_node_probe(Some(config)).await.unwrap();
    plane.probe_transits().await;
    assert_eq!(maximum.load(Ordering::SeqCst), 2);
    assert!(
        targets
            .lock()
            .unwrap()
            .iter()
            .all(|actual| actual == &target)
    );
    assert!(
        plane
            .transit_observations()
            .await
            .values()
            .all(
                |observation| observation.state == crate::TransitProbeState::Up
                    && observation.loss_ppm == Some(0)
                    && observation.throughput_bps.is_none()
                    && observation.effective_capacity_bps.is_none()
            )
    );
    behavior.store(2, Ordering::SeqCst);
    plane.probe_transits().await;
    assert_eq!(active.load(Ordering::SeqCst), 0);
    assert!(
        plane
            .transit_observations()
            .await
            .values()
            .all(
                |observation| observation.state == crate::TransitProbeState::Down
                    && observation.last_error == Some(crate::TransitProbeFailure::Timeout)
                    && observation.loss_ppm == Some(500_000)
            )
    );
    behavior.store(0, Ordering::SeqCst);
    plane.probe_transits().await;
    plane.probe_transits().await;
    assert!(
        plane
            .transit_observations()
            .await
            .values()
            .all(
                |observation| observation.state == crate::TransitProbeState::Up
                    && observation.loss_ppm == Some(0)
                    && observation.attempts == 4
                    && observation.successes == 3
            )
    );
}
