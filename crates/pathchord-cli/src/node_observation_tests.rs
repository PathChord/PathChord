use super::*;

fn observation_test_plane() -> Arc<IngressDataPlane> {
    let policy = pathchord_policy::ValidatedPolicySnapshot::new(
        Generation::new(1),
        PolicyConfig {
            fallback: Some(FallbackAction::Reject),
            ..Default::default()
        },
    )
    .unwrap();
    Arc::new(
        IngressDataPlane::new(IngressDataPlaneConfig::new(
            "test-ingress",
            generate_static_keypair().unwrap(),
            policy,
        ))
        .unwrap(),
    )
}

fn observation_test_control() -> Arc<tokio::sync::Mutex<LocalControlDispatcher>> {
    Arc::new(tokio::sync::Mutex::new(
        LocalControlDispatcher::with_service(
            SystemProxyPlatform::current(),
            IngressControlService::new(),
        ),
    ))
}

fn test_usage() -> pathchord_transit::SubscriptionUsage {
    pathchord_transit::SubscriptionUsage {
        upload_bytes: Some(12),
        download_bytes: Some(34),
        total_bytes: Some(1_000),
        expires_at: None,
        traffic_multiplier_basis_points: Some(10_000),
    }
}

fn test_probe() -> pathchord_ingress::TransitProbeObservation {
    pathchord_ingress::TransitProbeObservation {
        adapter_ready: true,
        state: TransitProbeState::Up,
        rtt_ms: Some(12),
        jitter_ms: Some(3),
        loss_ppm: Some(100),
        ..Default::default()
    }
}

struct ObservationFetcher;

#[async_trait]
impl pathchord_transit::SubscriptionFetcher for ObservationFetcher {
    async fn fetch(
        &self,
        _: pathchord_transit::SubscriptionFetchRequest,
    ) -> Result<Vec<u8>, pathchord_transit::SubscriptionError> {
        Ok(b"proxies: [{name: node, type: http, server: 127.0.0.1, port: 8080}]".to_vec())
    }

    async fn fetch_document(
        &self,
        request: pathchord_transit::SubscriptionFetchRequest,
    ) -> Result<pathchord_transit::SubscriptionDocument, pathchord_transit::SubscriptionError> {
        Ok(pathchord_transit::SubscriptionDocument {
            body: self.fetch(request).await?,
            usage: Some(test_usage()),
        })
    }
}

async fn observation_test_subscription()
-> (pathchord_policy::SubscriptionConfig, DynamicTransitSnapshot) {
    let subscription = pathchord_policy::SubscriptionConfig {
        id: pathchord_policy::SubscriptionId::new("provider"),
        enabled: true,
        source: pathchord_policy::SubscriptionSource {
            source_type: SubscriptionSourceType::Clash,
            url: "https://example.invalid/subscription".into(),
            credentials_ref: None,
            user_agent: None,
        },
        refresh: Default::default(),
        cache: None,
    };
    let mut manager = SubscriptionManager::new(
        Arc::new(ObservationFetcher),
        std::env::temp_dir(),
        BTreeSet::from(["http".to_owned()]),
    );
    assert!(matches!(
        manager.refresh(&subscription).await,
        RefreshOutcome::Published { .. }
    ));
    (subscription, manager.snapshot().clone())
}

async fn declare_subscription(
    control: &Arc<tokio::sync::Mutex<LocalControlDispatcher>>,
    subscription: &pathchord_policy::SubscriptionConfig,
) -> u64 {
    let policy = PolicyConfig {
        subscriptions: vec![subscription.clone()],
        ..Default::default()
    };
    let (_, specs) = declarative_control_resources(&policy).unwrap();
    let mut dispatcher = control.lock().await;
    dispatcher
        .service_mut()
        .reconcile_declarative_resources(1, [], specs)
        .unwrap();
    dispatcher.service().snapshot().generation
}

#[tokio::test]
async fn probe_updates_skip_missing_nodes_at_capacity_and_keep_subscription_fields() {
    let control = observation_test_control();
    let plane = observation_test_plane();
    let dynamic = tokio::sync::RwLock::new(DynamicTransitSnapshot::default());
    let node = NodeId::new("node-0").unwrap();
    let diagnostic = pathchord_transit::NodeDiagnostic {
        code: pathchord_transit::NodeUnavailableReason::AdapterUnavailable,
        fields: Vec::new(),
        message: "test diagnostic".into(),
    };
    {
        let mut dispatcher = control.lock().await;
        let nodes = (0..pathchord_ingress::MAX_NODE_COUNT)
            .map(|index| NodeId::new(format!("node-{index}")).unwrap());
        dispatcher
            .service_mut()
            .reconcile_declarative_resources(1, nodes, [])
            .unwrap();
        dispatcher
            .service()
            .observation_handle()
            .set_node_metadata(
                node.clone(),
                Some("default".into()),
                Some("http".into()),
                Some("127.0.0.1:8080".into()),
                Some("provider".into()),
                BTreeMap::new(),
            )
            .unwrap();
        let mut previous = empty_node_observation();
        previous.diagnostic = Some(diagnostic.clone());
        previous.usage = Some(test_usage());
        dispatcher
            .service_mut()
            .set_node_observation(node.clone(), previous)
            .unwrap();
    }
    let fence = probe_observation_fence(&control, &plane, &dynamic).await;
    apply_probe_observations(
        &control,
        &plane,
        &dynamic,
        fence,
        BTreeMap::from([
            (
                pathchord_policy::TransitProxyId::new("node-0"),
                test_probe(),
            ),
            (
                pathchord_policy::TransitProxyId::new("missing"),
                test_probe(),
            ),
        ]),
    )
    .await
    .unwrap();
    let dispatcher = control.lock().await;
    assert_eq!(
        dispatcher.service().snapshot().nodes.len(),
        pathchord_ingress::MAX_NODE_COUNT
    );
    assert!(
        !dispatcher
            .service()
            .snapshot()
            .nodes
            .contains_key(&NodeId::new("missing").unwrap())
    );
    let observations = dispatcher.service().observation_snapshot();
    let observation = &observations.nodes[&node];
    assert_eq!(observation.rtt_ms, Some(12));
    assert_eq!(observation.diagnostic.as_ref(), Some(&diagnostic));
    assert_eq!(observation.usage, Some(test_usage()));
    assert_eq!(observation.state, NodeHealthState::Down);
}

#[tokio::test]
async fn subscription_sync_preserves_probes_and_probe_updates_preserve_diagnostic_and_usage() {
    let control = observation_test_control();
    let plane = observation_test_plane();
    let (subscription, snapshot) = observation_test_subscription().await;
    let generation = declare_subscription(&control, &subscription).await;
    let dynamic = tokio::sync::RwLock::new(snapshot.clone());
    let node = snapshot.nodes.values().next().unwrap();
    let id = NodeId::new(node.config.id.as_str()).unwrap();
    let policy = PolicyConfig::default();
    sync_control_nodes(
        &control,
        &plane,
        &policy,
        &snapshot,
        &BTreeMap::new(),
        std::slice::from_ref(&subscription),
        generation,
    )
    .await
    .unwrap();
    let fence = probe_observation_fence(&control, &plane, &dynamic).await;
    apply_probe_observations(
        &control,
        &plane,
        &dynamic,
        fence,
        BTreeMap::from([(node.config.id.clone(), test_probe())]),
    )
    .await
    .unwrap();
    let diagnostic = pathchord_transit::NodeDiagnostic {
        code: pathchord_transit::NodeUnavailableReason::AdapterUnavailable,
        fields: Vec::new(),
        message: "test diagnostic".into(),
    };
    sync_control_nodes(
        &control,
        &plane,
        &policy,
        &snapshot,
        &BTreeMap::from([(node.config.id.clone(), diagnostic.clone())]),
        std::slice::from_ref(&subscription),
        generation,
    )
    .await
    .unwrap();
    {
        let dispatcher = control.lock().await;
        let observations = dispatcher.service().observation_snapshot();
        let observation = &observations.nodes[&id];
        assert_eq!(observation.rtt_ms, Some(12));
        assert_eq!(observation.jitter_ms, Some(3));
        assert_eq!(observation.diagnostic.as_ref(), Some(&diagnostic));
        assert_eq!(observation.usage, Some(test_usage()));
    }
    let fence = probe_observation_fence(&control, &plane, &dynamic).await;
    apply_probe_observations(
        &control,
        &plane,
        &dynamic,
        fence,
        BTreeMap::from([(node.config.id.clone(), test_probe())]),
    )
    .await
    .unwrap();
    {
        let dispatcher = control.lock().await;
        let observations = dispatcher.service().observation_snapshot();
        let observation = &observations.nodes[&id];
        assert_eq!(observation.rtt_ms, Some(12));
        assert_eq!(observation.diagnostic.as_ref(), Some(&diagnostic));
        assert_eq!(observation.usage, Some(test_usage()));
        assert_eq!(observation.state, NodeHealthState::Down);
    }
    let mut replacement = snapshot.clone();
    replacement
        .nodes
        .get_mut(&node.config.id)
        .unwrap()
        .config
        .endpoint
        .port = 9090;
    sync_control_nodes(
        &control,
        &plane,
        &policy,
        &replacement,
        &BTreeMap::new(),
        std::slice::from_ref(&subscription),
        generation,
    )
    .await
    .unwrap();
    let dispatcher = control.lock().await;
    let observations = dispatcher.service().observation_snapshot();
    let observation = &observations.nodes[&id];
    assert_eq!(observation.rtt_ms, None);
    assert_eq!(observation.diagnostic, None);
    assert_eq!(observation.usage, Some(test_usage()));
}

#[tokio::test]
async fn stale_subscription_registration_cannot_follow_deletion() {
    let control = observation_test_control();
    let plane = observation_test_plane();
    let (subscription, snapshot) = observation_test_subscription().await;
    let generation = declare_subscription(&control, &subscription).await;
    let node_id = NodeId::new(snapshot.nodes.values().next().unwrap().config.id.as_str()).unwrap();
    let mut dispatcher = control.lock().await;
    let registration = tokio::spawn({
        let control = Arc::clone(&control);
        let plane = Arc::clone(&plane);
        let subscription = subscription.clone();
        let snapshot = snapshot.clone();
        async move {
            sync_control_nodes(
                &control,
                &plane,
                &PolicyConfig::default(),
                &snapshot,
                &BTreeMap::new(),
                &[subscription],
                generation,
            )
            .await
        }
    });
    tokio::task::yield_now().await;
    dispatcher
        .service_mut()
        .delete_subscription(
            "test",
            pathchord_core::RequestId::new(1),
            generation,
            &ControlSubscriptionId::new(subscription.id.as_str()).unwrap(),
        )
        .unwrap();
    let after_delete = dispatcher.service().snapshot().generation;
    drop(dispatcher);
    tokio::time::timeout(Duration::from_secs(2), registration)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    sync_control_nodes(
        &control,
        &plane,
        &PolicyConfig::default(),
        &snapshot,
        &BTreeMap::new(),
        std::slice::from_ref(&subscription),
        after_delete,
    )
    .await
    .unwrap();
    let mut replacement = subscription.clone();
    replacement.source.url = "https://example.invalid/replacement".into();
    let (_, mut specs) = declarative_control_resources(&PolicyConfig {
        subscriptions: vec![replacement],
        ..Default::default()
    })
    .unwrap();
    let replacement_generation = {
        let mut dispatcher = control.lock().await;
        dispatcher
            .service_mut()
            .add_subscription(
                "test",
                pathchord_core::RequestId::new(2),
                after_delete,
                specs.pop().unwrap(),
            )
            .unwrap();
        dispatcher.service().snapshot().generation
    };
    sync_control_nodes(
        &control,
        &plane,
        &PolicyConfig::default(),
        &snapshot,
        &BTreeMap::new(),
        std::slice::from_ref(&subscription),
        replacement_generation,
    )
    .await
    .unwrap();
    let dispatcher = control.lock().await;
    assert!(!dispatcher.service().snapshot().nodes.contains_key(&node_id));
    assert!(
        !dispatcher
            .service()
            .observation_snapshot()
            .node_metadata
            .contains_key(&node_id)
    );
}

#[tokio::test]
async fn unchanged_refresh_keeps_verified_siblings_selectable_before_republication() {
    struct UnchangedFetcher;
    #[async_trait]
    impl pathchord_transit::SubscriptionFetcher for UnchangedFetcher {
        async fn fetch(
            &self,
            _: pathchord_transit::SubscriptionFetchRequest,
        ) -> Result<Vec<u8>, pathchord_transit::SubscriptionError> {
            Ok(b"proxies: [{name: node, type: http, server: 127.0.0.1, port: 8080}, {name: unsupported, type: ssr, server: 127.0.0.1, port: 1}]".to_vec())
        }
    }
    let (subscription, _) = observation_test_subscription().await;
    let mut manager = SubscriptionManager::new(
        Arc::new(UnchangedFetcher),
        std::env::temp_dir(),
        BTreeSet::from(["http".into()]),
    );
    manager.refresh(&subscription).await;
    let registry = AdapterRegistry::for_configs(
        Arc::new(FileTransitCredentialProvider::new(std::env::temp_dir()).unwrap()),
        Duration::from_secs(1),
        manager.snapshot().nodes.values().map(|node| &node.config),
    )
    .unwrap();
    let prepared = manager.snapshot().prepare_adapters(&registry).await;
    manager.commit_prepared_adapters(prepared).unwrap();
    let plane = observation_test_plane();
    assert!(
        publish_dynamic_transit(&plane, &mut manager)
            .await
            .is_empty()
    );
    let prior = manager.snapshot().clone();
    let old = prior.selectable_nodes().next().unwrap();
    let old_admission = prior.validated_admission(&old.config.id).unwrap();
    let control = observation_test_control();
    let generation = declare_subscription(&control, &subscription).await;
    let candidate = manager.prepare_refresh(&subscription, generation).await;
    let mut dispatcher = control.lock().await;
    let outcome = commit_subscription_refresh(
        &mut manager,
        candidate,
        generation,
        &mut dispatcher,
        &ControlSubscriptionId::new("provider").unwrap(),
        &plane,
        &registry,
    )
    .await
    .unwrap();
    assert!(matches!(outcome, RefreshOutcome::Published { .. }));
    assert!(old_admission.matches_config(&old.config));
    assert_eq!(prior.selectable_nodes().count(), 1);
    assert_eq!(manager.snapshot().selectable_nodes().count(), 1);
    let retained = manager
        .snapshot()
        .validated_admission(&old.config.id)
        .unwrap();
    assert!(Arc::ptr_eq(&old_admission.adapter(), &retained.adapter()));
}

#[tokio::test]
async fn rejected_refresh_restores_the_previous_verified_adapter() {
    use std::collections::VecDeque;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    struct SequenceFetcher(std::sync::Mutex<VecDeque<Vec<u8>>>);
    #[async_trait]
    impl pathchord_transit::SubscriptionFetcher for SequenceFetcher {
        async fn fetch(
            &self,
            _: pathchord_transit::SubscriptionFetchRequest,
        ) -> Result<Vec<u8>, pathchord_transit::SubscriptionError> {
            Ok(self.0.lock().unwrap().pop_front().unwrap())
        }
    }
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let proxy = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut header = Vec::new();
        while !header.ends_with(b"\r\n\r\n") {
            header.push(stream.read_u8().await.unwrap());
        }
        let text = String::from_utf8(header).unwrap();
        let expected = base64::engine::general_purpose::STANDARD.encode("old:secret");
        assert!(text.contains(&format!("Proxy-Authorization: Basic {expected}\r\n")));
        stream
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await
            .unwrap();
        let mut payload = [0; 4];
        stream.read_exact(&mut payload).await.unwrap();
        stream.write_all(&payload).await.unwrap();
    });
    let document = |user: &str| {
        format!("proxies: [{{name: node, type: http, server: 127.0.0.1, port: {port}, username: {user}, password: secret}}]").into_bytes()
    };
    let subscription = pathchord_policy::SubscriptionConfig {
        id: pathchord_policy::SubscriptionId::new("provider"),
        enabled: true,
        source: pathchord_policy::SubscriptionSource {
            source_type: SubscriptionSourceType::Clash,
            url: "https://example.invalid/subscription".into(),
            credentials_ref: None,
            user_agent: None,
        },
        refresh: Default::default(),
        cache: None,
    };
    let mut manager = SubscriptionManager::new(
        Arc::new(SequenceFetcher(std::sync::Mutex::new(VecDeque::from([
            document("old"),
            document("other"),
            document("new"),
        ])))),
        std::env::temp_dir(),
        BTreeSet::from(["http".into()]),
    );
    assert!(matches!(
        manager.refresh(&subscription).await,
        RefreshOutcome::Published { .. }
    ));
    let registry = AdapterRegistry::for_configs(
        Arc::new(FileTransitCredentialProvider::new(std::env::temp_dir()).unwrap()),
        Duration::from_secs(1),
        manager.snapshot().nodes.values().map(|node| &node.config),
    )
    .unwrap();
    let prepared = manager.snapshot().prepare_adapters(&registry).await;
    manager.commit_prepared_adapters(prepared).unwrap();
    let prior = manager.snapshot().clone();
    let policy = pathchord_policy::ValidatedPolicySnapshot::new(
        Generation::new(1),
        PolicyConfig {
            proxy_rules: vec![pathchord_policy::ProxyRule {
                id: pathchord_policy::RuleId::new("proxy"),
                matches: Default::default(),
                require: Default::default(),
                select: pathchord_policy::ProxySelection::Any,
            }],
            fallback: Some(FallbackAction::Reject),
            ..Default::default()
        },
    )
    .unwrap();
    let plane = IngressDataPlane::new(IngressDataPlaneConfig::new(
        "test",
        generate_static_keypair().unwrap(),
        policy,
    ))
    .unwrap();
    assert!(
        publish_dynamic_transit(&plane, &mut manager)
            .await
            .is_empty()
    );
    let mut other = subscription.clone();
    other.id = pathchord_policy::SubscriptionId::new("other");
    other.source.url = "https://example.invalid/other".into();
    assert!(matches!(
        manager.refresh(&other).await,
        RefreshOutcome::Published { .. }
    ));
    plane
        .initialize_subscription_visibility("other", false)
        .await;
    let candidate = manager.prepare_refresh(&subscription, 0).await;
    let mut dispatcher = LocalControlDispatcher::with_service(
        SystemProxyPlatform::current(),
        IngressControlService::new(),
    );
    let result = commit_subscription_refresh(
        &mut manager,
        candidate,
        0,
        &mut dispatcher,
        &ControlSubscriptionId::new("provider").unwrap(),
        &plane,
        &registry,
    )
    .await;
    assert!(result.is_err());
    assert_eq!(prior.selectable_nodes().count(), 0);
    assert_eq!(manager.snapshot().selectable_nodes().count(), 1);
    let other_node = manager
        .snapshot()
        .nodes
        .values()
        .find(|node| node.source_subscription == other.id)
        .expect("the other subscription candidate remains present");
    assert_eq!(other_node.state, DynamicNodeState::Pending);
    let context = pathchord_ingress::ConnectionContext {
        flow_tags: BTreeSet::new(),
        listener_id: pathchord_ingress::ListenerId::new("test"),
        source: "127.0.0.1:1234".parse().unwrap(),
        authentication_identity: None,
        process: None,
        protocol: FlowProtocol::Tcp,
        target: TargetAddress {
            host: TargetHost::Hostname("target.test".into()),
            port: 443,
        },
    };
    let mut stream = plane.open_tcp(&context).await.unwrap();
    stream.write_all(b"ping").await.unwrap();
    let mut reply = [0; 4];
    stream.read_exact(&mut reply).await.unwrap();
    assert_eq!(&reply, b"ping");
    proxy.await.unwrap();
}

#[tokio::test]
async fn static_node_conflict_revokes_dynamic_admission_and_reports_safe_diagnostic() {
    let (subscription, _) = observation_test_subscription().await;
    let mut manager = SubscriptionManager::new(
        Arc::new(ObservationFetcher),
        std::env::temp_dir(),
        BTreeSet::from(["http".into()]),
    );
    manager.refresh(&subscription).await;
    let registry = AdapterRegistry::for_configs(
        Arc::new(FileTransitCredentialProvider::new(std::env::temp_dir()).unwrap()),
        Duration::from_secs(1),
        manager.snapshot().nodes.values().map(|node| &node.config),
    )
    .unwrap();
    let prepared = manager.snapshot().prepare_adapters(&registry).await;
    manager.commit_prepared_adapters(prepared).unwrap();
    let old = manager.snapshot().clone();
    let node = old.selectable_nodes().next().unwrap();
    let mut static_node = node.config.clone();
    static_node.source = None;
    let policy = pathchord_policy::ValidatedPolicySnapshot::new(
        Generation::new(1),
        PolicyConfig {
            transit_proxies: vec![static_node],
            fallback: Some(FallbackAction::Reject),
            ..Default::default()
        },
    )
    .unwrap();
    let plane = IngressDataPlane::new(IngressDataPlaneConfig::new(
        "test",
        generate_static_keypair().unwrap(),
        policy,
    ))
    .unwrap();
    let diagnostics = publish_dynamic_transit(&plane, &mut manager).await;
    assert_eq!(diagnostics.len(), 1);
    assert_eq!(manager.snapshot().selectable_nodes().count(), 0);
    assert_eq!(old.selectable_nodes().count(), 0);
    assert!(
        diagnostics
            .values()
            .all(|diagnostic| !diagnostic.message.contains("8080"))
    );
}

#[tokio::test]
async fn stale_probe_cannot_revive_removed_or_replaced_node() {
    let control = observation_test_control();
    let plane = observation_test_plane();
    let dynamic = tokio::sync::RwLock::new(DynamicTransitSnapshot::default());
    let node = NodeId::new("node").unwrap();
    {
        let mut dispatcher = control.lock().await;
        dispatcher.service_mut().add_node(node.clone()).unwrap();
        dispatcher
            .service()
            .observation_handle()
            .set_node_metadata(
                node.clone(),
                Some("default".into()),
                Some("http".into()),
                Some("old:8080".into()),
                Some("old-source".into()),
                BTreeMap::new(),
            )
            .unwrap();
    }
    let stale = probe_observation_fence(&control, &plane, &dynamic).await;
    {
        let mut dispatcher = control.lock().await;
        dispatcher.service_mut().remove_node(&node).unwrap();
    }
    apply_probe_observations(
        &control,
        &plane,
        &dynamic,
        stale,
        BTreeMap::from([(pathchord_policy::TransitProxyId::new("node"), test_probe())]),
    )
    .await
    .unwrap();
    {
        let dispatcher = control.lock().await;
        assert!(!dispatcher.service().snapshot().nodes.contains_key(&node));
        assert!(
            !dispatcher
                .service()
                .observation_snapshot()
                .nodes
                .contains_key(&node)
        );
    }
    {
        let mut dispatcher = control.lock().await;
        dispatcher.service_mut().add_node(node.clone()).unwrap();
    }
    let stale = probe_observation_fence(&control, &plane, &dynamic).await;
    {
        let dispatcher = control.lock().await;
        dispatcher
            .service()
            .observation_handle()
            .set_node_metadata(
                node.clone(),
                Some("default".into()),
                Some("http".into()),
                Some("new:8080".into()),
                Some("new-source".into()),
                BTreeMap::new(),
            )
            .unwrap();
    }
    apply_probe_observations(
        &control,
        &plane,
        &dynamic,
        stale,
        BTreeMap::from([(pathchord_policy::TransitProxyId::new("node"), test_probe())]),
    )
    .await
    .unwrap();
    assert!(
        !control
            .lock()
            .await
            .service()
            .observation_snapshot()
            .nodes
            .contains_key(&node)
    );
    // A refresh may replace credentials while leaving visible metadata the
    // same. Its dynamic generation must also fence the old probe result.
    let stale = probe_observation_fence(&control, &plane, &dynamic).await;
    dynamic.write().await.generation += 1;
    apply_probe_observations(
        &control,
        &plane,
        &dynamic,
        stale,
        BTreeMap::from([(pathchord_policy::TransitProxyId::new("node"), test_probe())]),
    )
    .await
    .unwrap();
    assert!(
        !control
            .lock()
            .await
            .service()
            .observation_snapshot()
            .nodes
            .contains_key(&node)
    );
}
