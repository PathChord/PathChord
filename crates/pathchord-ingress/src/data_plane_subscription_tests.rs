use super::*;
use crate::{
    Actor, GenerationExpectation, IngressControlService, IngressControlStore, LOCAL_API_VERSION,
    LocalControlDispatcher, RequestEnvelope, SubscriptionId, SubscriptionRefreshSpec,
    SubscriptionSpec, SystemProxyPlatform,
};
use pathchord_core::management::{ManagementDispatcher, ManagementSource};
use pathchord_policy::{
    FallbackAction, FlowMatch, Generation, PolicyConfig, ProxyRule, ProxySelection, RuleId,
    Selector, TransitSource,
};
use pathchord_transit::{
    BoxedTransitConnection, BoxedTransitDatagram, TransitDatagram, TransitMetadata,
};
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

struct EchoAdapter;

#[async_trait::async_trait]
impl TransitAdapter for EchoAdapter {
    fn metadata(&self) -> &TransitMetadata {
        panic!("metadata is not used by this test")
    }

    fn supports_udp(&self) -> bool {
        true
    }

    async fn connect(&self, _: ConnectRequest) -> Result<BoxedTransitConnection, TransitError> {
        let (local, remote) = tokio::io::duplex(1024);
        tokio::spawn(async move {
            let (mut read, mut write) = tokio::io::split(remote);
            let _ = tokio::io::copy(&mut read, &mut write).await;
        });
        Ok(Box::new(local))
    }

    async fn connect_udp(&self, _: ConnectRequest) -> Result<BoxedTransitDatagram, TransitError> {
        Ok(Box::new(EchoDatagram(None)))
    }
}

#[derive(Debug)]
struct EchoDatagram(Option<Vec<u8>>);

#[async_trait::async_trait]
impl TransitDatagram for EchoDatagram {
    async fn send(&mut self, payload: &[u8]) -> Result<(), TransitError> {
        self.0 = Some(payload.to_vec());
        Ok(())
    }
    async fn receive(&mut self) -> Result<Vec<u8>, TransitError> {
        Ok(self.0.take().unwrap())
    }
}

fn source_node() -> TransitProxyConfig {
    TransitProxyConfig {
        id: TransitProxyId::new("provider-node"),
        source: Some(TransitSource {
            source_type: "clash".into(),
            subscription: "provider".into(),
        }),
        protocol: "http".into(),
        endpoint: pathchord_policy::Endpoint {
            host: "127.0.0.1".into(),
            port: 1080,
        },
        credentials_ref: None,
        options: Default::default(),
        labels: Default::default(),
        tags: Default::default(),
        weight: 100,
    }
}

fn ready() -> TransitProxyRuntimeStatus {
    TransitProxyRuntimeStatus {
        state: RuntimeNodeState::Ready,
        capabilities: BTreeSet::from([FlowProtocol::Tcp, FlowProtocol::Udp]),
        selection_score: 1,
        ..Default::default()
    }
}

fn context() -> ConnectionContext {
    ConnectionContext {
        flow_tags: BTreeSet::new(),
        listener_id: crate::ListenerId::new("test"),
        source: "127.0.0.1:1234".parse().unwrap(),
        authentication_identity: None,
        process: None,
        protocol: FlowProtocol::Tcp,
        target: crate::TargetAddress {
            host: crate::TargetHost::Hostname("example.test".into()),
            port: 443,
        },
    }
}

async fn setup() -> (
    Arc<IngressDataPlane>,
    LocalControlDispatcher,
    Arc<IngressControlStore>,
) {
    let policy = ValidatedPolicySnapshot::new(
        Generation::new(1),
        PolicyConfig {
            proxy_rules: vec![ProxyRule {
                id: RuleId::new("proxy"),
                matches: FlowMatch::default(),
                require: Selector::default(),
                select: ProxySelection::Any,
            }],
            fallback: Some(FallbackAction::Reject),
            ..Default::default()
        },
    )
    .unwrap();
    let plane = Arc::new(
        IngressDataPlane::new(IngressDataPlaneConfig::new(
            "ingress",
            pathchord_noise::generate_static_keypair().unwrap(),
            policy,
        ))
        .unwrap(),
    );
    plane
        .register_dynamic_transit_adapter(source_node(), Arc::new(EchoAdapter), ready())
        .await;
    let store = Arc::new(IngressControlStore::open_in_memory().unwrap());
    let mut service = IngressControlService::open(Arc::clone(&store)).unwrap();
    service
        .reconcile_declarative_resources(
            1,
            [],
            [SubscriptionSpec {
                id: SubscriptionId::new("provider").unwrap(),
                source_type: "clash".into(),
                display_name: "provider".into(),
                enabled: true,
                url: "https://example.test/sub".into(),
                credentials_ref: None,
                user_agent: None,
                refresh: SubscriptionRefreshSpec::default(),
                cache: None,
            }],
        )
        .unwrap();
    let mut dispatcher = LocalControlDispatcher::with_service(SystemProxyPlatform::Linux, service);
    dispatcher.set_subscription_data_plane(Arc::clone(&plane));
    (plane, dispatcher, store)
}

fn request(operation: &str, id: &str, generation: u64) -> RequestEnvelope {
    RequestEnvelope {
        api_version: LOCAL_API_VERSION.into(),
        operation: operation.into(),
        request_id: id.into(),
        actor: Actor {
            id: "operator".into(),
            capabilities: vec!["subscriptions:write".into()],
        },
        expected_generation: Some(GenerationExpectation {
            scope: "configuration".into(),
            value: generation,
        }),
        body: json!({"id": "provider"}),
    }
}

async fn dispatch(
    dispatcher: &mut LocalControlDispatcher,
    request: RequestEnvelope,
) -> crate::ResponseEnvelope {
    ManagementDispatcher::dispatch_from(dispatcher, request, ManagementSource::Local).await
}

#[tokio::test]
async fn successful_disable_or_delete_fences_new_flows_even_after_stale_publication() {
    for operation in ["subscriptions.disable", "subscriptions.delete"] {
        let (plane, mut dispatcher, _) = setup().await;
        let mut existing = plane.open_tcp(&context()).await.unwrap();
        let mut datagram = plane.open_udp(&context()).await.unwrap();
        let generation = dispatcher.service().snapshot().generation;
        assert!(
            dispatch(&mut dispatcher, request(operation, "mutation", generation))
                .await
                .ok
        );
        assert!(plane.open_tcp(&context()).await.is_err());
        assert!(plane.open_udp(&context()).await.is_err());
        existing.write_all(b"open").await.unwrap();
        let mut reply = [0; 4];
        existing.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply, b"open");
        datagram.send(b"datagram".to_vec()).await.unwrap();
        assert_eq!(datagram.receive().await, Some(b"datagram".to_vec()));
        plane
            .register_dynamic_transit_adapter(source_node(), Arc::new(EchoAdapter), ready())
            .await;
        assert!(plane.open_tcp(&context()).await.is_err());
        assert!(plane.open_udp(&context()).await.is_err());
    }
}

#[tokio::test]
async fn subscription_disable_revokes_cloned_verified_snapshots_and_stale_registration() {
    struct FixtureFetcher;
    #[async_trait::async_trait]
    impl pathchord_transit::SubscriptionFetcher for FixtureFetcher {
        async fn fetch(
            &self,
            _: pathchord_transit::SubscriptionFetchRequest,
        ) -> Result<Vec<u8>, pathchord_transit::SubscriptionError> {
            Ok(b"proxies: [{name: node, type: http, server: proxy.test, port: 8080}]".to_vec())
        }
    }
    let (plane, mut dispatcher, _) = setup().await;
    let config = pathchord_policy::SubscriptionConfig {
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
        Arc::new(FixtureFetcher),
        std::env::temp_dir(),
        BTreeSet::from(["http".into()]),
    );
    assert!(matches!(
        manager.refresh(&config).await,
        pathchord_transit::RefreshOutcome::Published { .. }
    ));
    let registry = AdapterRegistry::for_configs(
        Arc::new(pathchord_transit::NoTransitCredentials),
        Duration::from_secs(1),
        manager.snapshot().nodes.values().map(|node| &node.config),
    )
    .unwrap();
    let prepared = manager.snapshot().prepare_adapters(&registry).await;
    manager.commit_prepared_adapters(prepared).unwrap();
    let old = manager.snapshot().clone();
    let node = old.selectable_nodes().next().unwrap();
    let id = node.config.id.clone();
    let admission = old.validated_admission(&id).unwrap();
    let adapter = admission.adapter();
    assert_eq!(
        plane
            .register_verified_dynamic_transit_adapter(
                node.config.clone(),
                admission.clone(),
                ready(),
            )
            .await,
        DynamicTransitRegistration::Registered
    );
    assert!(Arc::ptr_eq(
        &adapter,
        &plane.transit_adapters.read().await[&id]
    ));
    let mut changed = node.config.clone();
    changed.endpoint.port = 9999;
    assert_eq!(
        plane
            .register_verified_dynamic_transit_adapter(changed, admission.clone(), ready())
            .await,
        DynamicTransitRegistration::StaleAdmission
    );

    let generation = dispatcher.service().snapshot().generation;
    assert!(
        dispatch(
            &mut dispatcher,
            request("subscriptions.disable", "disable-proof", generation)
        )
        .await
        .ok
    );
    assert_eq!(old.selectable_nodes().count(), 0);
    assert!(old.validated_adapter(&id).is_none());
    assert!(plane.open_tcp(&context()).await.is_err());
    plane.allow_subscription_after_refresh("provider").await;
    assert_eq!(
        plane
            .register_verified_dynamic_transit_adapter(node.config.clone(), admission, ready(),)
            .await,
        DynamicTransitRegistration::StaleAdmission
    );
    plane
        .publish_dynamic_transit_status(node.config.clone(), ready())
        .await;
    assert!(plane.open_tcp(&context()).await.is_err());
}

#[tokio::test]
async fn failed_commit_keeps_node_selectable_and_old_disable_replay_respects_current_state() {
    let (plane, mut dispatcher, store) = setup().await;
    let generation = dispatcher.service().snapshot().generation;
    store.fail_next_commit();
    assert!(
        !dispatch(
            &mut dispatcher,
            request("subscriptions.disable", "failed", generation)
        )
        .await
        .ok
    );
    assert!(plane.open_tcp(&context()).await.is_ok());
    assert!(
        dispatcher
            .service()
            .snapshot()
            .subscriptions
            .values()
            .next()
            .unwrap()
            .spec
            .enabled
    );
    let disable = request("subscriptions.disable", "disable", generation);
    assert!(dispatch(&mut dispatcher, disable.clone()).await.ok);
    let generation = dispatcher.service().snapshot().generation;
    assert!(
        dispatch(
            &mut dispatcher,
            request("subscriptions.enable", "enable", generation)
        )
        .await
        .ok
    );
    plane.allow_subscription_after_refresh("provider").await;
    plane
        .register_dynamic_transit_adapter(source_node(), Arc::new(EchoAdapter), ready())
        .await;
    assert!(plane.open_tcp(&context()).await.is_ok());
    assert!(dispatch(&mut dispatcher, disable).await.ok);
    assert!(plane.open_tcp(&context()).await.is_ok());
}
