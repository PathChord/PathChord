use std::sync::Arc;
use tokio::sync::Mutex;

use pathchord_ingress::{
    FakePlatformProxyAdapter, ListenerDescriptor, ListenerId, ListenerKind, ListenerRuntimeEvent,
    LocalControlDispatcher, NodeId, RuntimeCounts, SystemProxyPlatform, WebGateway,
    WebGatewayConfig,
};

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut dispatcher = LocalControlDispatcher::with_platform_proxy(
        SystemProxyPlatform::Windows,
        Arc::new(FakePlatformProxyAdapter::new()),
    );
    dispatcher
        .service_mut()
        .add_node(NodeId::new("tokyo-edge")?)?;
    let listener_id = ListenerId::new("local-http");
    let bind = "127.0.0.1:8080".parse()?;
    dispatcher
        .service_mut()
        .register_listener(ListenerDescriptor {
            id: listener_id.clone(),
            kind: ListenerKind::Http,
            bind: Some(bind),
            interface: None,
            address: None,
            mtu: None,
            flow_tags: std::collections::BTreeSet::new(),
            process_metadata: pathchord_policy::ProcessMetadataRequest::default(),
            allowed_sources: vec!["127.0.0.1/32".into()],
            authentication_required: false,
        });
    let observations = dispatcher.service().observation_handle();
    observations.set_runtime_counts(RuntimeCounts {
        sessions: 1,
        ready_paths: 2,
        streams: 3,
        target_connections: 3,
    })?;
    observations.apply_listener_event(ListenerRuntimeEvent::ListenerStarted {
        listener_id,
        bind: Some(bind),
        interface: None,
        address: None,
        mtu: None,
    })?;

    let gateway = WebGateway::bind(
        WebGatewayConfig::default(),
        Arc::new(Mutex::new(dispatcher)),
    )
    .await?;
    println!("http://{}", gateway.local_addr()?);
    gateway.run().await?;
    Ok(())
}
