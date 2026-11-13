use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};

use async_trait::async_trait;
use pathchord_policy::{
    Endpoint, FallbackAction, FlowMatch, Generation, PolicyConfig, ProxyRule, ProxySelection,
    RuleId,
};
use pathchord_transit::{
    AdapterKind, BoxedTransitConnection, NoTransitCredentials, TransitMetadata,
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

fn registry(configs: &[TransitProxyConfig]) -> AdapterRegistry<NoTransitCredentials> {
    AdapterRegistry::for_configs(
        Arc::new(NoTransitCredentials),
        Duration::from_secs(1),
        configs,
    )
    .unwrap()
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
