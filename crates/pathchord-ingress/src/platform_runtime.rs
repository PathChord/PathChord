//! All-or-nothing platform resource construction and supervision.

use std::collections::BTreeMap;
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use pathchord_policy::{
    AuthenticationMode, FlowProtocol, ListenerConfig, ListenerKind as PolicyListenerKind,
    PolicyConfig, TransparentBackend,
};
use thiserror::Error;
use tokio::sync::watch;
use tokio::task::JoinSet;

use crate::{
    ListenerCredentialVerifierFactory, ListenerDescriptor, ListenerKind, ListenerRuntime,
    ListenerRuntimeConfig, PacketDevice, ProcessMetadataProvider, ProtectedEndpointSet,
    RuntimeReport, Socks5Runtime, Socks5RuntimeConfig, Socks5RuntimeReport,
    SystemProcessMetadataProvider, TcpFlowOpener, TunDeviceConfig, TunFlowRuntime,
    TunFlowRuntimeConfig, TunFlowRuntimeReport, UdpFlowOpener,
    UnavailableListenerCredentialFactory,
};

#[cfg(target_os = "linux")]
use crate::{
    IpCommandRouteAdapter, LinuxEbpfInterception, LinuxRouteAdapter, LinuxRoutingEffect,
    LinuxTproxyUdpSocket, LinuxTransparentRouteConfig, LinuxTransparentRouteManager,
    TransparentUdpAdapter, TransparentUdpRuntimeConfig, TransparentUdpRuntimeReport,
    run_transparent_udp,
};

#[derive(Debug, Clone)]
pub struct IngressPlatformConfig {
    pub data_dir: PathBuf,
    pub dns: Option<Arc<crate::DnsRuntime>>,
    pub listener_runtime: ListenerRuntimeConfig,
    pub route_priority_base: u32,
    pub route_protocol: u8,
    pub maximum_udp_payload: usize,
    pub maximum_udp_associations: usize,
    pub udp_association_queue: usize,
    pub udp_idle_timeout: Duration,
    pub shutdown_timeout: Duration,
}

impl IngressPlatformConfig {
    #[must_use]
    pub fn new(data_dir: impl Into<PathBuf>) -> Self {
        Self {
            data_dir: data_dir.into(),
            dns: None,
            listener_runtime: ListenerRuntimeConfig::default(),
            route_priority_base: 30_000,
            route_protocol: 186,
            maximum_udp_payload: u16::MAX as usize,
            maximum_udp_associations: 1024,
            udp_association_queue: 64,
            udp_idle_timeout: Duration::from_secs(120),
            shutdown_timeout: Duration::from_secs(5),
        }
    }

    fn validate(&self) -> Result<(), IngressPlatformError> {
        if self.route_priority_base == 0
            || self.route_protocol == 0
            || self.maximum_udp_payload == 0
            || self.maximum_udp_payload > u16::MAX as usize
            || self.maximum_udp_associations == 0
            || self.udp_association_queue == 0
            || self.shutdown_timeout.is_zero()
        {
            return Err(IngressPlatformError::InvalidConfig(
                "platform runtime limits are invalid".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum IngressPlatformError {
    #[error("platform runtime configuration is invalid: {0}")]
    InvalidConfig(String),
    #[error("listener {listener_id} is unsupported on {platform}")]
    UnsupportedPlatform {
        listener_id: String,
        platform: String,
    },
    #[error("listener {listener_id} platform resource failed: {message}")]
    Adapter {
        listener_id: String,
        message: String,
    },
    #[error("listener runtime failed: {0}")]
    Listener(String),
    #[error("platform task failed: {0}")]
    Task(String),
    #[error("platform task stopped unexpectedly: {0}")]
    UnexpectedStop(String),
}

pub trait TunPacketDeviceFactory: std::fmt::Debug + Send + Sync {
    fn create(&self, config: &TunDeviceConfig) -> Result<Arc<dyn PacketDevice>, String>;
}

#[derive(Debug, Default)]
pub struct TunRsPacketDeviceFactory;

impl TunPacketDeviceFactory for TunRsPacketDeviceFactory {
    #[cfg(not(target_os = "freebsd"))]
    fn create(&self, config: &TunDeviceConfig) -> Result<Arc<dyn PacketDevice>, String> {
        crate::TunRsPacketDevice::create(config)
            .map(|device| Arc::new(device) as Arc<dyn PacketDevice>)
            .map_err(|error| error.to_string())
    }

    #[cfg(target_os = "freebsd")]
    fn create(&self, _config: &TunDeviceConfig) -> Result<Arc<dyn PacketDevice>, String> {
        Err("TUN listeners are unsupported on FreeBSD".to_owned())
    }
}

#[cfg(target_os = "linux")]
pub trait TransparentUdpFactory: std::fmt::Debug + Send + Sync {
    fn bind(
        &self,
        address: SocketAddr,
        protected: ProtectedEndpointSet,
        maximum_payload: usize,
    ) -> Result<Arc<dyn TransparentUdpAdapter>, String>;
}

#[cfg(target_os = "linux")]
#[derive(Debug, Default)]
pub struct LinuxTransparentUdpFactory;

#[cfg(target_os = "linux")]
impl TransparentUdpFactory for LinuxTransparentUdpFactory {
    fn bind(
        &self,
        address: SocketAddr,
        protected: ProtectedEndpointSet,
        maximum_payload: usize,
    ) -> Result<Arc<dyn TransparentUdpAdapter>, String> {
        LinuxTproxyUdpSocket::bind(address, protected, maximum_payload)
            .map(|socket| Arc::new(socket) as Arc<dyn TransparentUdpAdapter>)
            .map_err(|error| error.to_string())
    }
}

pub struct IngressPlatformFactories {
    pub tun: Arc<dyn TunPacketDeviceFactory>,
    pub listener_credentials: Arc<dyn ListenerCredentialVerifierFactory>,
    pub process_metadata: Arc<dyn ProcessMetadataProvider>,
    #[cfg(target_os = "linux")]
    pub route: Arc<dyn LinuxRouteAdapter>,
    #[cfg(target_os = "linux")]
    pub transparent_udp: Arc<dyn TransparentUdpFactory>,
}

impl std::fmt::Debug for IngressPlatformFactories {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("IngressPlatformFactories(..)")
    }
}

impl Default for IngressPlatformFactories {
    fn default() -> Self {
        Self {
            tun: Arc::new(TunRsPacketDeviceFactory),
            listener_credentials: Arc::new(UnavailableListenerCredentialFactory),
            process_metadata: Arc::new(SystemProcessMetadataProvider::default()),
            #[cfg(target_os = "linux")]
            route: Arc::new(IpCommandRouteAdapter::system()),
            #[cfg(target_os = "linux")]
            transparent_udp: Arc::new(LinuxTransparentUdpFactory),
        }
    }
}

#[derive(Clone)]
struct SharedTcpOpener(Arc<dyn TcpFlowOpener>);

impl std::fmt::Debug for SharedTcpOpener {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("SharedTcpOpener(..)")
    }
}

#[async_trait]
impl TcpFlowOpener for SharedTcpOpener {
    async fn connect(
        &self,
        context: crate::ConnectionContext,
    ) -> Result<crate::BoxedLocalConnection, crate::FlowBridgeError> {
        self.0.connect(context).await
    }
}

struct TunRuntimeEntry {
    listener_id: pathchord_policy::ListenerId,
    runtime: TunFlowRuntime,
    device: Arc<dyn PacketDevice>,
}

struct SocksRuntimeEntry {
    listener_id: pathchord_policy::ListenerId,
    runtime: Socks5Runtime,
}

#[cfg(target_os = "linux")]
struct UdpRuntimeEntry {
    listener_id: pathchord_policy::ListenerId,
    adapter: Arc<dyn TransparentUdpAdapter>,
    config: TransparentUdpRuntimeConfig,
    emit_lifecycle: bool,
}

pub struct IngressPlatformRuntime {
    config: IngressPlatformConfig,
    inventory: Vec<ListenerDescriptor>,
    event_sender: Option<crate::ListenerRuntimeEventSender>,
    listeners: Option<ListenerRuntime<SharedTcpOpener>>,
    socks: Vec<SocksRuntimeEntry>,
    #[cfg(target_os = "linux")]
    udp_opener: Arc<dyn UdpFlowOpener>,
    tun: Vec<TunRuntimeEntry>,
    #[cfg(target_os = "linux")]
    udp: Vec<UdpRuntimeEntry>,
    #[cfg(target_os = "linux")]
    routes: Vec<(
        pathchord_policy::ListenerId,
        Arc<LinuxTransparentRouteManager>,
    )>,
    #[cfg(target_os = "linux")]
    ebpf: Vec<(pathchord_policy::ListenerId, LinuxEbpfInterception)>,
}

impl std::fmt::Debug for IngressPlatformRuntime {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("IngressPlatformRuntime")
            .field(
                "tcp_listeners",
                &self.listeners.as_ref().map(ListenerRuntime::listener_count),
            )
            .field("socks_listeners", &self.socks.len())
            .field("tun_listeners", &self.tun.len())
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IngressPlatformReport {
    pub tcp: Option<RuntimeReport>,
    pub socks: BTreeMap<pathchord_policy::ListenerId, Socks5RuntimeReport>,
    pub tun: BTreeMap<pathchord_policy::ListenerId, TunFlowRuntimeReport>,
    #[cfg(target_os = "linux")]
    pub transparent_udp: BTreeMap<pathchord_policy::ListenerId, TransparentUdpRuntimeReport>,
    #[cfg(target_os = "linux")]
    pub restored_routes: BTreeMap<pathchord_policy::ListenerId, usize>,
}

impl IngressPlatformRuntime {
    pub fn set_listener_event_sender(&mut self, sender: crate::ListenerRuntimeEventSender) {
        if let Some(runtime) = self.listeners.as_mut() {
            runtime.set_event_sender(sender.clone());
        }
        for entry in &mut self.socks {
            entry.runtime.set_event_sender(sender.clone());
        }
        self.event_sender = Some(sender);
    }

    #[must_use]
    pub fn listener_inventory(&self) -> &[ListenerDescriptor] {
        &self.inventory
    }

    pub fn listener_addresses(
        &self,
    ) -> Result<BTreeMap<pathchord_policy::ListenerId, SocketAddr>, IngressPlatformError> {
        let mut addresses = self
            .listeners
            .as_ref()
            .map(ListenerRuntime::listener_addresses)
            .transpose()
            .map(|addresses| addresses.unwrap_or_default())
            .map_err(|error| IngressPlatformError::Listener(error.to_string()))?;
        for entry in &self.socks {
            addresses.insert(
                entry.listener_id.clone(),
                entry
                    .runtime
                    .local_addr()
                    .map_err(|error| IngressPlatformError::Listener(error.to_string()))?,
            );
        }
        Ok(addresses)
    }

    pub async fn bind(
        config: IngressPlatformConfig,
        policy: &PolicyConfig,
        tcp_opener: Arc<dyn TcpFlowOpener>,
        udp_opener: Arc<dyn UdpFlowOpener>,
        protected: ProtectedEndpointSet,
    ) -> Result<Self, IngressPlatformError> {
        Self::bind_with_factories(
            config,
            &policy.listeners,
            tcp_opener,
            udp_opener,
            protected,
            IngressPlatformFactories::default(),
        )
        .await
    }

    pub async fn bind_with_factories(
        config: IngressPlatformConfig,
        listeners: &[ListenerConfig],
        tcp_opener: Arc<dyn TcpFlowOpener>,
        udp_opener: Arc<dyn UdpFlowOpener>,
        protected: ProtectedEndpointSet,
        factories: IngressPlatformFactories,
    ) -> Result<Self, IngressPlatformError> {
        config.validate()?;
        validate_listener_platforms(listeners)?;
        preflight_listeners(&config, listeners)?;
        let inventory = listeners
            .iter()
            .map(listener_descriptor)
            .collect::<Result<Vec<_>, _>>()?;
        let mut listener_credentials = BTreeMap::new();
        for listener in listeners.iter().filter(|listener| {
            matches!(
                listener.kind,
                PolicyListenerKind::Http | PolicyListenerKind::Socks5 | PolicyListenerKind::Mixed
            )
        }) {
            let verifier = factories
                .listener_credentials
                .verifier_for(listener)
                .await
                .map_err(|error| adapter_error(listener, error))?;
            listener_credentials.insert(listener.id.clone(), verifier);
        }
        let udp_opener: Arc<dyn UdpFlowOpener> = match config.dns.as_ref() {
            Some(dns) => Arc::new(crate::DnsAwareUdpFlowOpener::new(
                Arc::clone(dns),
                udp_opener,
            )),
            None => udp_opener,
        };

        #[cfg(target_os = "linux")]
        let mut routes: Vec<(
            pathchord_policy::ListenerId,
            Arc<LinuxTransparentRouteManager>,
        )> = Vec::new();
        #[cfg(target_os = "linux")]
        let mut udp = Vec::new();
        let mut tun = Vec::new();
        let mut socks = Vec::new();
        let mut tcp_descriptors = Vec::new();

        #[cfg(target_os = "linux")]
        let mut route_index = 0_u32;
        #[cfg(target_os = "linux")]
        let mut ebpf = Vec::new();
        for listener in listeners {
            match listener.kind {
                PolicyListenerKind::Http | PolicyListenerKind::Redirect => {
                    tcp_descriptors.push(listener_descriptor(listener)?);
                }
                PolicyListenerKind::Socks5 | PolicyListenerKind::Mixed => {
                    let descriptor = listener_descriptor(listener)?;
                    let credential_verifier =
                        listener_credentials.remove(&listener.id).ok_or_else(|| {
                            invalid_listener(listener, "credential verifier is missing")
                        })?;
                    let runtime = match Socks5Runtime::bind(
                        descriptor,
                        Socks5RuntimeConfig {
                            tcp_enabled: listener.protocols.contains(&FlowProtocol::Tcp),
                            udp_enabled: listener.protocols.contains(&FlowProtocol::Udp),
                            max_clients: config.listener_runtime.max_connections,
                            max_targets_per_client: config.maximum_udp_associations,
                            target_queue: config.udp_association_queue,
                            idle_timeout: config.udp_idle_timeout,
                            shutdown_timeout: config.shutdown_timeout,
                        },
                        Arc::clone(&tcp_opener),
                        Arc::clone(&udp_opener),
                        credential_verifier,
                    )
                    .await
                    {
                        Ok(mut runtime) => {
                            runtime.set_process_metadata_provider(Arc::clone(
                                &factories.process_metadata,
                            ));
                            runtime
                        }
                        Err(error) => {
                            #[cfg(target_os = "linux")]
                            if let Some(rollback) = restore_routes(&routes) {
                                return Err(rollback);
                            }
                            return Err(adapter_error(listener, error));
                        }
                    };
                    socks.push(SocksRuntimeEntry {
                        listener_id: listener.id.clone(),
                        runtime,
                    });
                }
                PolicyListenerKind::Tproxy => {
                    #[cfg(target_os = "linux")]
                    {
                        let priority = config
                            .route_priority_base
                            .checked_add(route_index)
                            .ok_or_else(|| {
                                IngressPlatformError::InvalidConfig(
                                    "routing priority overflow".to_owned(),
                                )
                            })?;
                        route_index = route_index.checked_add(1).ok_or_else(|| {
                            IngressPlatformError::InvalidConfig(
                                "too many TPROXY listeners".to_owned(),
                            )
                        })?;
                        let route_config = LinuxTransparentRouteConfig::from_listener(
                            listener,
                            priority,
                            config.route_protocol,
                        )
                        .map_err(|error| adapter_error(listener, error))?;
                        let manager = Arc::new(LinuxTransparentRouteManager::new(
                            Arc::clone(&factories.route),
                            config
                                .data_dir
                                .join(format!("{}-routing.json", listener.id.as_str())),
                        ));
                        if let Err(error) = manager.apply(route_config) {
                            if let Some(rollback) = restore_routes(&routes) {
                                return Err(rollback);
                            }
                            return Err(adapter_error(listener, error));
                        }
                        routes.push((listener.id.clone(), manager));
                        if listener.backend == TransparentBackend::Ebpf {
                            let interface = listener.interface.as_deref().ok_or_else(|| {
                                invalid_listener(listener, "eBPF interface is missing")
                            })?;
                            let mark = listener.mark.ok_or_else(|| {
                                invalid_listener(listener, "eBPF mark is missing")
                            })?;
                            let backend = match LinuxEbpfInterception::attach(
                                &config.data_dir,
                                listener.id.as_str(),
                                interface,
                                mark,
                                priority,
                            ) {
                                Ok(backend) => backend,
                                Err(error) => {
                                    if let Some(rollback) = restore_routes(&routes) {
                                        return Err(rollback);
                                    }
                                    return Err(adapter_error(listener, error));
                                }
                            };
                            ebpf.push((listener.id.clone(), backend));
                        }
                        if listener.protocols.contains(&FlowProtocol::Tcp) {
                            tcp_descriptors.push(listener_descriptor(listener)?);
                        }
                        if listener.protocols.contains(&FlowProtocol::Udp) {
                            let bind = listener_socket_addr(listener)?;
                            let adapter = match factories.transparent_udp.bind(
                                bind,
                                protected.clone(),
                                config.maximum_udp_payload,
                            ) {
                                Ok(adapter) => adapter,
                                Err(message) => {
                                    if let Some(rollback) = restore_routes(&routes) {
                                        return Err(rollback);
                                    }
                                    return Err(IngressPlatformError::Adapter {
                                        listener_id: listener.id.as_str().to_owned(),
                                        message,
                                    });
                                }
                            };
                            udp.push(UdpRuntimeEntry {
                                listener_id: listener.id.clone(),
                                adapter,
                                config: TransparentUdpRuntimeConfig {
                                    listener_id: listener.id.clone(),
                                    flow_tags: listener.flow_tags.clone(),
                                    allowed_sources: listener.allowed_sources.clone(),
                                    process_metadata: listener.process_metadata,
                                    process_metadata_provider: Arc::clone(
                                        &factories.process_metadata,
                                    ),
                                    max_associations: config.maximum_udp_associations,
                                    association_queue: config.udp_association_queue,
                                    idle_timeout: config.udp_idle_timeout,
                                },
                                emit_lifecycle: !listener.protocols.contains(&FlowProtocol::Tcp),
                            });
                        }
                    }
                    #[cfg(not(target_os = "linux"))]
                    {
                        return Err(unsupported(listener));
                    }
                }
                PolicyListenerKind::Tun => {
                    let tun_config = TunDeviceConfig::parse(
                        listener.interface.clone().ok_or_else(|| {
                            invalid_listener(listener, "TUN interface is missing")
                        })?,
                        listener
                            .address
                            .as_deref()
                            .ok_or_else(|| invalid_listener(listener, "TUN address is missing"))?,
                        u16::try_from(listener.mtu.unwrap_or(1500))
                            .map_err(|_| invalid_listener(listener, "TUN MTU is outside u16"))?,
                    )
                    .map_err(|error| adapter_error(listener, error))?;
                    let device = match factories.tun.create(&tun_config) {
                        Ok(device) => device,
                        Err(message) => {
                            #[cfg(target_os = "linux")]
                            if let Some(rollback) = restore_routes(&routes) {
                                return Err(rollback);
                            }
                            return Err(IngressPlatformError::Adapter {
                                listener_id: listener.id.as_str().to_owned(),
                                message,
                            });
                        }
                    };
                    let mut runtime_config =
                        TunFlowRuntimeConfig::from_tun(listener.id.clone(), &tun_config);
                    runtime_config.flow_tags = listener.flow_tags.clone();
                    runtime_config.allowed_sources = listener.allowed_sources.clone();
                    runtime_config.process_metadata = listener.process_metadata;
                    runtime_config.process_metadata_provider =
                        Arc::clone(&factories.process_metadata);
                    runtime_config.tcp_enabled = listener.protocols.contains(&FlowProtocol::Tcp);
                    runtime_config.udp_enabled = listener.protocols.contains(&FlowProtocol::Udp);
                    runtime_config.max_tcp_flows = config.listener_runtime.max_connections;
                    runtime_config.max_udp_associations = config.maximum_udp_associations;
                    runtime_config.udp_packet_queue = config.udp_association_queue;
                    runtime_config.idle_timeout = config.udp_idle_timeout;
                    let runtime = match TunFlowRuntime::new(
                        runtime_config,
                        Arc::clone(&tcp_opener),
                        Arc::clone(&udp_opener),
                        protected.clone(),
                    ) {
                        Ok(runtime) => runtime,
                        Err(error) => {
                            #[cfg(target_os = "linux")]
                            if let Some(rollback) = restore_routes(&routes) {
                                return Err(rollback);
                            }
                            return Err(adapter_error(listener, error));
                        }
                    };
                    tun.push(TunRuntimeEntry {
                        listener_id: listener.id.clone(),
                        runtime,
                        device,
                    });
                }
            }
        }

        let listeners = if tcp_descriptors.is_empty() {
            None
        } else {
            match ListenerRuntime::bind_descriptors_with_credentials_and_protected(
                SharedTcpOpener(tcp_opener),
                config.listener_runtime,
                tcp_descriptors,
                listener_credentials,
                protected.clone(),
            )
            .await
            {
                Ok(mut runtime) => {
                    runtime.set_process_metadata_provider(Arc::clone(&factories.process_metadata));
                    Some(runtime)
                }
                Err(error) => {
                    #[cfg(target_os = "linux")]
                    if let Some(rollback) = restore_routes(&routes) {
                        return Err(rollback);
                    }
                    return Err(IngressPlatformError::Listener(error.to_string()));
                }
            }
        };
        if listeners.is_none() && socks.is_empty() && tun.is_empty() {
            #[cfg(target_os = "linux")]
            if udp.is_empty() {
                if let Some(rollback) = restore_routes(&routes) {
                    return Err(rollback);
                }
                return Err(IngressPlatformError::InvalidConfig(
                    "no runnable listeners are configured".to_owned(),
                ));
            }
            #[cfg(not(target_os = "linux"))]
            return Err(IngressPlatformError::InvalidConfig(
                "no runnable listeners are configured".to_owned(),
            ));
        }
        Ok(Self {
            config,
            inventory,
            event_sender: None,
            listeners,
            socks,
            #[cfg(target_os = "linux")]
            udp_opener,
            tun,
            #[cfg(target_os = "linux")]
            udp,
            #[cfg(target_os = "linux")]
            routes,
            #[cfg(target_os = "linux")]
            ebpf,
        })
    }

    pub async fn run_until_shutdown<F>(
        mut self,
        shutdown: F,
    ) -> Result<IngressPlatformReport, IngressPlatformError>
    where
        F: Future<Output = ()> + Send,
    {
        let (cancel, _) = watch::channel(false);
        let mut tasks = JoinSet::new();
        let mut standalone_listeners = Vec::new();
        if let Some(runtime) = self.listeners.take() {
            let receiver = cancel.subscribe();
            tasks.spawn(async move {
                PlatformTask::Tcp(runtime.run_until_shutdown(wait_for_cancel(receiver)).await)
            });
        }
        for entry in self.tun.drain(..) {
            emit_platform_started(
                &self.event_sender,
                self.inventory
                    .iter()
                    .find(|item| item.id == entry.listener_id),
                None,
            );
            standalone_listeners.push(entry.listener_id.clone());
            let receiver = cancel.subscribe();
            tasks.spawn(async move {
                PlatformTask::Tun {
                    listener_id: entry.listener_id,
                    result: entry
                        .runtime
                        .run(entry.device, wait_for_cancel(receiver))
                        .await,
                }
            });
        }
        for entry in self.socks.drain(..) {
            let address = entry.runtime.local_addr().ok();
            emit_platform_started(
                &self.event_sender,
                self.inventory
                    .iter()
                    .find(|item| item.id == entry.listener_id),
                address,
            );
            standalone_listeners.push(entry.listener_id.clone());
            let receiver = cancel.subscribe();
            tasks.spawn(async move {
                PlatformTask::Socks {
                    listener_id: entry.listener_id,
                    result: entry
                        .runtime
                        .run_until_shutdown(wait_for_cancel(receiver))
                        .await,
                }
            });
        }
        #[cfg(target_os = "linux")]
        for entry in self.udp.drain(..) {
            if entry.emit_lifecycle {
                let descriptor = self
                    .inventory
                    .iter()
                    .find(|item| item.id == entry.listener_id);
                emit_platform_started(
                    &self.event_sender,
                    descriptor,
                    descriptor.and_then(|item| item.bind),
                );
                standalone_listeners.push(entry.listener_id.clone());
            }
            let receiver = cancel.subscribe();
            let opener = Arc::clone(&self.udp_opener);
            tasks.spawn(async move {
                PlatformTask::Udp {
                    listener_id: entry.listener_id,
                    result: run_transparent_udp(
                        entry.adapter,
                        opener,
                        entry.config,
                        wait_for_cancel(receiver),
                    )
                    .await,
                }
            });
        }

        let mut report = IngressPlatformReport::default();
        let mut first_error = None;
        let mut shutdown = Box::pin(shutdown);
        tokio::select! {
            () = shutdown.as_mut() => {}
            joined = tasks.join_next(), if !tasks.is_empty() => {
                match joined {
                    Some(Ok(task)) => {
                        if let Err(error) = collect_task(task, &mut report) {
                            first_error = Some(error);
                        } else {
                            first_error = Some(IngressPlatformError::UnexpectedStop(
                                "platform runtime completed before shutdown".to_owned(),
                            ));
                        }
                    }
                    Some(Err(error)) => {
                        first_error = Some(IngressPlatformError::Task(error.to_string()));
                    }
                    None => {}
                }
            }
        }
        let _ = cancel.send(true);
        let drain = async {
            while let Some(joined) = tasks.join_next().await {
                match joined {
                    Ok(task) => {
                        if first_error.is_none() {
                            first_error = collect_task(task, &mut report).err();
                        }
                    }
                    Err(error) if first_error.is_none() => {
                        first_error = Some(IngressPlatformError::Task(error.to_string()));
                    }
                    Err(_) => {}
                }
            }
        };
        if tokio::time::timeout(self.config.shutdown_timeout, drain)
            .await
            .is_err()
        {
            tasks.abort_all();
            while tasks.join_next().await.is_some() {}
            first_error.get_or_insert_with(|| {
                IngressPlatformError::Task("platform shutdown timed out".to_owned())
            });
        }
        #[cfg(target_os = "linux")]
        for (listener_id, mut backend) in self.ebpf.drain(..) {
            if let Err(error) = backend.detach() {
                first_error.get_or_insert_with(|| IngressPlatformError::Adapter {
                    listener_id: listener_id.as_str().to_owned(),
                    message: error.to_string(),
                });
            }
        }
        #[cfg(target_os = "linux")]
        for (listener_id, route) in &self.routes {
            match route.restore() {
                Ok(LinuxRoutingEffect {
                    restored_objects, ..
                }) => {
                    report
                        .restored_routes
                        .insert(listener_id.clone(), restored_objects);
                }
                Err(error) if first_error.is_none() => {
                    first_error = Some(IngressPlatformError::Adapter {
                        listener_id: listener_id.as_str().to_owned(),
                        message: error.to_string(),
                    });
                }
                Err(_) => {}
            }
        }
        if let Some(sender) = &self.event_sender {
            for listener_id in standalone_listeners {
                let _ = sender.send(crate::ListenerRuntimeEvent::ListenerStopped { listener_id });
            }
        }
        first_error.map_or(Ok(report), Err)
    }
}

fn emit_platform_started(
    sender: &Option<crate::ListenerRuntimeEventSender>,
    descriptor: Option<&ListenerDescriptor>,
    bind: Option<SocketAddr>,
) {
    let (Some(sender), Some(descriptor)) = (sender, descriptor) else {
        return;
    };
    let _ = sender.send(crate::ListenerRuntimeEvent::ListenerStarted {
        listener_id: descriptor.id.clone(),
        bind,
        interface: descriptor.interface.clone(),
        address: descriptor.address.clone(),
        mtu: descriptor.mtu,
    });
}

enum PlatformTask {
    Tcp(Result<RuntimeReport, crate::RuntimeError>),
    Tun {
        listener_id: pathchord_policy::ListenerId,
        result: Result<TunFlowRuntimeReport, crate::TunFlowRuntimeError>,
    },
    Socks {
        listener_id: pathchord_policy::ListenerId,
        result: Result<Socks5RuntimeReport, crate::Socks5RuntimeError>,
    },
    #[cfg(target_os = "linux")]
    Udp {
        listener_id: pathchord_policy::ListenerId,
        result: Result<TransparentUdpRuntimeReport, crate::TransparentUdpRuntimeError>,
    },
}

fn collect_task(
    task: PlatformTask,
    report: &mut IngressPlatformReport,
) -> Result<(), IngressPlatformError> {
    match task {
        PlatformTask::Tcp(result) => {
            report.tcp =
                Some(result.map_err(|error| IngressPlatformError::Listener(error.to_string()))?);
        }
        PlatformTask::Tun {
            listener_id,
            result,
        } => {
            report.tun.insert(
                listener_id.clone(),
                result.map_err(|error| IngressPlatformError::Adapter {
                    listener_id: listener_id.as_str().to_owned(),
                    message: error.to_string(),
                })?,
            );
        }
        PlatformTask::Socks {
            listener_id,
            result,
        } => {
            report.socks.insert(
                listener_id.clone(),
                result.map_err(|error| IngressPlatformError::Adapter {
                    listener_id: listener_id.as_str().to_owned(),
                    message: error.to_string(),
                })?,
            );
        }
        #[cfg(target_os = "linux")]
        PlatformTask::Udp {
            listener_id,
            result,
        } => {
            report.transparent_udp.insert(
                listener_id.clone(),
                result.map_err(|error| IngressPlatformError::Adapter {
                    listener_id: listener_id.as_str().to_owned(),
                    message: error.to_string(),
                })?,
            );
        }
    }
    Ok(())
}

async fn wait_for_cancel(mut receiver: watch::Receiver<bool>) {
    if *receiver.borrow() {
        return;
    }
    while receiver.changed().await.is_ok() {
        if *receiver.borrow() {
            return;
        }
    }
}

fn validate_listener_platforms(listeners: &[ListenerConfig]) -> Result<(), IngressPlatformError> {
    for listener in listeners {
        if listener.platform != "any" && listener.platform != std::env::consts::OS {
            return Err(unsupported(listener));
        }
        #[cfg(not(target_os = "linux"))]
        if matches!(
            listener.kind,
            PolicyListenerKind::Tproxy | PolicyListenerKind::Redirect
        ) {
            return Err(unsupported(listener));
        }
        #[cfg(not(target_os = "linux"))]
        if listener.backend == TransparentBackend::Ebpf {
            return Err(unsupported(listener));
        }
        #[cfg(target_os = "freebsd")]
        if listener.kind == PolicyListenerKind::Tun {
            return Err(unsupported(listener));
        }
    }
    Ok(())
}

fn preflight_listeners(
    _config: &IngressPlatformConfig,
    listeners: &[ListenerConfig],
) -> Result<(), IngressPlatformError> {
    #[cfg(target_os = "linux")]
    let mut route_index = 0_u32;
    for listener in listeners {
        match listener.kind {
            PolicyListenerKind::Http
            | PolicyListenerKind::Socks5
            | PolicyListenerKind::Mixed
            | PolicyListenerKind::Redirect => {
                listener_descriptor(listener)?;
            }
            PolicyListenerKind::Tproxy => {
                listener_socket_addr(listener)?;
                #[cfg(target_os = "linux")]
                {
                    let priority = _config
                        .route_priority_base
                        .checked_add(route_index)
                        .ok_or_else(|| {
                            IngressPlatformError::InvalidConfig(
                                "routing priority overflow".to_owned(),
                            )
                        })?;
                    route_index = route_index.checked_add(1).ok_or_else(|| {
                        IngressPlatformError::InvalidConfig("too many TPROXY listeners".to_owned())
                    })?;
                    LinuxTransparentRouteConfig::from_listener(
                        listener,
                        priority,
                        _config.route_protocol,
                    )
                    .map_err(|error| adapter_error(listener, error))?;
                }
            }
            PolicyListenerKind::Tun => {
                TunDeviceConfig::parse(
                    listener
                        .interface
                        .clone()
                        .ok_or_else(|| invalid_listener(listener, "TUN interface is missing"))?,
                    listener
                        .address
                        .as_deref()
                        .ok_or_else(|| invalid_listener(listener, "TUN address is missing"))?,
                    u16::try_from(listener.mtu.unwrap_or(1500))
                        .map_err(|_| invalid_listener(listener, "TUN MTU is outside u16"))?,
                )
                .map_err(|error| adapter_error(listener, error))?;
            }
        }
    }
    Ok(())
}

fn listener_descriptor(
    listener: &ListenerConfig,
) -> Result<ListenerDescriptor, IngressPlatformError> {
    let kind = match listener.kind {
        PolicyListenerKind::Http => ListenerKind::Http,
        PolicyListenerKind::Socks5 => ListenerKind::Socks5,
        PolicyListenerKind::Mixed => ListenerKind::Mixed,
        PolicyListenerKind::Tproxy => ListenerKind::Tproxy,
        PolicyListenerKind::Redirect => ListenerKind::Redirect,
        PolicyListenerKind::Tun => ListenerKind::Tun,
    };
    let bind = listener
        .bind
        .as_ref()
        .map(|_| listener_socket_addr(listener))
        .transpose()?;
    let mut allowed_sources = listener.allowed_sources.clone();
    if let Some(bind) = bind
        && allowed_sources.is_empty()
        && bind.ip().is_loopback()
    {
        let prefix = if bind.is_ipv4() { 32 } else { 128 };
        allowed_sources.push(format!("{}/{}", bind.ip(), prefix));
    }
    Ok(ListenerDescriptor {
        id: listener.id.clone(),
        kind,
        bind,
        interface: listener.interface.clone(),
        address: listener.address.clone(),
        mtu: listener.mtu,
        flow_tags: listener.flow_tags.clone(),
        process_metadata: listener.process_metadata,
        allowed_sources,
        authentication_required: listener.authentication == AuthenticationMode::Required,
    })
}

fn listener_socket_addr(listener: &ListenerConfig) -> Result<SocketAddr, IngressPlatformError> {
    let bind = listener
        .bind
        .as_ref()
        .ok_or_else(|| invalid_listener(listener, "listener bind is missing"))?;
    let host = bind
        .host
        .parse::<IpAddr>()
        .map_err(|_| invalid_listener(listener, "listener bind host must be an IP literal"))?;
    Ok(SocketAddr::new(host, bind.port))
}

fn invalid_listener(listener: &ListenerConfig, message: &str) -> IngressPlatformError {
    IngressPlatformError::InvalidConfig(format!("listener {}: {message}", listener.id.as_str()))
}

fn unsupported(listener: &ListenerConfig) -> IngressPlatformError {
    IngressPlatformError::UnsupportedPlatform {
        listener_id: listener.id.as_str().to_owned(),
        platform: listener.platform.clone(),
    }
}

fn adapter_error(listener: &ListenerConfig, error: impl std::fmt::Display) -> IngressPlatformError {
    IngressPlatformError::Adapter {
        listener_id: listener.id.as_str().to_owned(),
        message: error.to_string(),
    }
}

#[cfg(target_os = "linux")]
fn restore_routes(
    routes: &[(
        pathchord_policy::ListenerId,
        Arc<LinuxTransparentRouteManager>,
    )],
) -> Option<IngressPlatformError> {
    for (listener_id, route) in routes.iter().rev() {
        if let Err(error) = route.restore() {
            return Some(IngressPlatformError::Adapter {
                listener_id: listener_id.as_str().to_owned(),
                message: format!("route rollback failed: {error}"),
            });
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(target_os = "linux")]
    use std::collections::BTreeMap;
    use std::collections::BTreeSet;
    #[cfg(target_os = "linux")]
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicU64, Ordering};

    use pathchord_policy::{Endpoint, ListenerKind as PolicyListenerKind};
    #[cfg(target_os = "linux")]
    use tokio::sync::oneshot;

    static NEXT_DATA_DIR: AtomicU64 = AtomicU64::new(0);

    #[cfg(target_os = "linux")]
    #[derive(Debug, Default)]
    struct FakeRouteState {
        objects: BTreeMap<(crate::IpFamily, bool), LinuxTransparentRouteConfig>,
    }

    #[cfg(target_os = "linux")]
    #[derive(Debug, Default)]
    struct FakeRouteAdapter {
        state: Mutex<FakeRouteState>,
    }

    #[cfg(target_os = "linux")]
    impl FakeRouteAdapter {
        fn count(&self) -> usize {
            self.state.lock().unwrap().objects.len()
        }

        fn inspect(
            &self,
            family: crate::IpFamily,
            route: bool,
            config: LinuxTransparentRouteConfig,
        ) -> crate::RouteObjectState {
            match self.state.lock().unwrap().objects.get(&(family, route)) {
                None => crate::RouteObjectState::Absent,
                Some(existing) if *existing == config => crate::RouteObjectState::Exact,
                Some(_) => crate::RouteObjectState::Conflict,
            }
        }

        fn add(&self, family: crate::IpFamily, route: bool, config: LinuxTransparentRouteConfig) {
            self.state
                .lock()
                .unwrap()
                .objects
                .insert((family, route), config);
        }

        fn delete(&self, family: crate::IpFamily, route: bool) {
            self.state.lock().unwrap().objects.remove(&(family, route));
        }
    }

    #[cfg(target_os = "linux")]
    impl LinuxRouteAdapter for FakeRouteAdapter {
        fn inspect_rule(
            &self,
            family: crate::IpFamily,
            config: LinuxTransparentRouteConfig,
        ) -> Result<crate::RouteObjectState, crate::LinuxRoutingError> {
            Ok(self.inspect(family, false, config))
        }

        fn inspect_route(
            &self,
            family: crate::IpFamily,
            config: LinuxTransparentRouteConfig,
        ) -> Result<crate::RouteObjectState, crate::LinuxRoutingError> {
            Ok(self.inspect(family, true, config))
        }

        fn add_rule(
            &self,
            family: crate::IpFamily,
            config: LinuxTransparentRouteConfig,
        ) -> Result<(), crate::LinuxRoutingError> {
            self.add(family, false, config);
            Ok(())
        }

        fn add_route(
            &self,
            family: crate::IpFamily,
            config: LinuxTransparentRouteConfig,
        ) -> Result<(), crate::LinuxRoutingError> {
            self.add(family, true, config);
            Ok(())
        }

        fn delete_rule(
            &self,
            family: crate::IpFamily,
            _config: LinuxTransparentRouteConfig,
        ) -> Result<(), crate::LinuxRoutingError> {
            self.delete(family, false);
            Ok(())
        }

        fn delete_route(
            &self,
            family: crate::IpFamily,
            _config: LinuxTransparentRouteConfig,
        ) -> Result<(), crate::LinuxRoutingError> {
            self.delete(family, true);
            Ok(())
        }
    }

    #[cfg(target_os = "linux")]
    #[derive(Debug)]
    struct FakeTunFactory {
        fail: bool,
    }

    #[cfg(target_os = "linux")]
    impl TunPacketDeviceFactory for FakeTunFactory {
        fn create(&self, config: &TunDeviceConfig) -> Result<Arc<dyn PacketDevice>, String> {
            if self.fail {
                Err("injected TUN failure".to_owned())
            } else {
                Ok(crate::FakePacketDevice::new(usize::from(config.mtu), 8))
            }
        }
    }

    #[cfg(target_os = "linux")]
    #[derive(Debug, Default)]
    struct FakeUdpFactory;

    #[cfg(target_os = "linux")]
    impl TransparentUdpFactory for FakeUdpFactory {
        fn bind(
            &self,
            _address: SocketAddr,
            _protected: ProtectedEndpointSet,
            _maximum_payload: usize,
        ) -> Result<Arc<dyn TransparentUdpAdapter>, String> {
            Ok(crate::FakeTransparentUdpAdapter::new(8))
        }
    }

    #[derive(Debug)]
    struct RejectUdpOpener;

    #[async_trait]
    impl UdpFlowOpener for RejectUdpOpener {
        async fn open_udp(
            &self,
            _context: &crate::ConnectionContext,
        ) -> Result<crate::BoxedUdpFlowHandle, crate::UdpFlowError> {
            Err(crate::UdpFlowError::Open("unused".to_owned()))
        }
    }

    #[cfg(target_os = "linux")]
    #[derive(Debug, Default)]
    struct RecordingSocksVerifier {
        calls: AtomicU64,
    }

    #[cfg(target_os = "linux")]
    #[async_trait]
    impl crate::ListenerCredentialVerifier for RecordingSocksVerifier {
        async fn verify(&self, username: &str, password: &[u8]) -> bool {
            self.calls.fetch_add(1, Ordering::SeqCst);
            username == "alice" && password == b"secret"
        }
    }

    #[cfg(target_os = "linux")]
    #[derive(Debug)]
    struct RecordingCredentialFactory {
        verifier: Arc<RecordingSocksVerifier>,
    }

    #[cfg(target_os = "linux")]
    #[async_trait]
    impl crate::ListenerCredentialVerifierFactory for RecordingCredentialFactory {
        async fn verifier_for(
            &self,
            _listener: &ListenerConfig,
        ) -> Result<Arc<dyn crate::ListenerCredentialVerifier>, crate::ListenerCredentialError>
        {
            Ok(self.verifier.clone())
        }
    }

    fn listener(id: &str, kind: PolicyListenerKind) -> ListenerConfig {
        ListenerConfig {
            id: pathchord_policy::ListenerId::new(id),
            kind,
            platform: "any".to_owned(),
            bind: (!matches!(kind, PolicyListenerKind::Tun)).then(|| Endpoint {
                host: "127.0.0.1".to_owned(),
                port: 0,
            }),
            allowed_sources: Vec::new(),
            authentication: AuthenticationMode::Disabled,
            backend: Default::default(),
            credentials_ref: None,
            flow_tags: BTreeSet::new(),
            process_metadata: pathchord_policy::ProcessMetadataRequest::default(),
            mark: (kind == PolicyListenerKind::Tproxy).then_some(1),
            route_table: (kind == PolicyListenerKind::Tproxy).then_some(100),
            protocols: match kind {
                PolicyListenerKind::Tproxy | PolicyListenerKind::Tun => {
                    BTreeSet::from([FlowProtocol::Tcp, FlowProtocol::Udp])
                }
                _ => BTreeSet::from([FlowProtocol::Tcp]),
            },
            interface: (kind == PolicyListenerKind::Tun).then(|| "PathChord".to_owned()),
            address: (kind == PolicyListenerKind::Tun).then(|| "198.18.0.1/30".to_owned()),
            mtu: (kind == PolicyListenerKind::Tun).then_some(1500),
            bypass: Vec::new(),
            proxy_ref: None,
        }
    }

    fn data_dir() -> PathBuf {
        let id = NEXT_DATA_DIR.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!("pathchord-platform-{}-{id}", std::process::id()))
    }

    fn tcp_opener() -> Arc<dyn TcpFlowOpener> {
        Arc::new(crate::FixedTargetDialer::new(|_| {
            Err::<tokio::io::DuplexStream, _>(crate::FlowBridgeError::Dial("unused".to_owned()))
        }))
    }

    #[cfg(target_os = "linux")]
    fn factories(routes: Arc<FakeRouteAdapter>, tun_failure: bool) -> IngressPlatformFactories {
        IngressPlatformFactories {
            tun: Arc::new(FakeTunFactory { fail: tun_failure }),
            listener_credentials: Arc::new(crate::UnavailableListenerCredentialFactory),
            process_metadata: Arc::new(crate::NoopProcessMetadataProvider),
            route: routes,
            transparent_udp: Arc::new(FakeUdpFactory),
        }
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn mixed_platform_config_starts_stops_and_restores_routes() {
        let routes = Arc::new(FakeRouteAdapter::default());
        let mut tproxy = listener("tproxy", PolicyListenerKind::Tproxy);
        tproxy.protocols = BTreeSet::from([FlowProtocol::Udp]);
        let mut socks = listener("socks", PolicyListenerKind::Socks5);
        socks.protocols = BTreeSet::from([FlowProtocol::Tcp, FlowProtocol::Udp]);
        socks.authentication = AuthenticationMode::Required;
        socks.credentials_ref = Some("listener-users".to_owned());
        let listeners = vec![
            listener("http", PolicyListenerKind::Http),
            socks,
            tproxy,
            listener("tun", PolicyListenerKind::Tun),
        ];
        let root = data_dir();
        let verifier = Arc::new(RecordingSocksVerifier::default());
        let mut platform_factories = factories(routes.clone(), false);
        platform_factories.listener_credentials = Arc::new(RecordingCredentialFactory {
            verifier: verifier.clone(),
        });
        let mut runtime = IngressPlatformRuntime::bind_with_factories(
            IngressPlatformConfig::new(&root),
            &listeners,
            tcp_opener(),
            Arc::new(RejectUdpOpener),
            ProtectedEndpointSet::default(),
            platform_factories,
        )
        .await
        .unwrap();
        assert_eq!(routes.count(), 4);
        assert_eq!(runtime.listener_inventory().len(), 4);
        let addresses = runtime.listener_addresses().unwrap();
        assert_eq!(addresses.len(), 2);
        let socks_address = addresses[&pathchord_policy::ListenerId::new("socks")];
        let (events_tx, mut events_rx) = tokio::sync::mpsc::unbounded_channel();
        runtime.set_listener_event_sender(events_tx);
        let (shutdown, signal) = oneshot::channel();
        let task = tokio::spawn(runtime.run_until_shutdown(async move {
            let _ = signal.await;
        }));

        let mut control = tokio::net::TcpStream::connect(socks_address).await.unwrap();
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        control.write_all(&[5, 1, 2]).await.unwrap();
        let mut method = [0_u8; 2];
        control.read_exact(&mut method).await.unwrap();
        assert_eq!(method, [5, 2]);
        control
            .write_all(&[
                1, 5, b'a', b'l', b'i', b'c', b'e', 6, b's', b'e', b'c', b'r', b'e', b't',
            ])
            .await
            .unwrap();
        let mut auth = [0_u8; 2];
        control.read_exact(&mut auth).await.unwrap();
        assert_eq!(auth, [1, 0]);
        control
            .write_all(&[
                5,
                crate::socks5::UDP_ASSOCIATE,
                0,
                crate::socks5::IPV4,
                0,
                0,
                0,
                0,
                0,
                0,
            ])
            .await
            .unwrap();
        let mut relay = [0_u8; 10];
        control.read_exact(&mut relay).await.unwrap();
        assert_eq!(relay[..4], [5, 0, 0, crate::socks5::IPV4]);

        shutdown.send(()).unwrap();
        let report = task.await.unwrap().unwrap();
        assert_eq!(report.tcp.unwrap().listener_count, 1);
        assert_eq!(
            report.socks[&pathchord_policy::ListenerId::new("socks")].udp_associations,
            1
        );
        assert!(
            report
                .transparent_udp
                .contains_key(&pathchord_policy::ListenerId::new("tproxy"))
        );
        assert!(
            report
                .tun
                .contains_key(&pathchord_policy::ListenerId::new("tun"))
        );
        assert_eq!(
            report.restored_routes[&pathchord_policy::ListenerId::new("tproxy")],
            4
        );
        assert_eq!(routes.count(), 0);
        assert_eq!(verifier.calls.load(Ordering::SeqCst), 1);

        let mut lifecycle = BTreeMap::<pathchord_policy::ListenerId, (usize, usize)>::new();
        while let Ok(event) = events_rx.try_recv() {
            match event {
                crate::ListenerRuntimeEvent::ListenerStarted { listener_id, .. } => {
                    lifecycle.entry(listener_id).or_default().0 += 1;
                }
                crate::ListenerRuntimeEvent::ListenerStopped { listener_id } => {
                    lifecycle.entry(listener_id).or_default().1 += 1;
                }
                _ => {}
            }
        }
        for listener_id in ["http", "socks", "tproxy", "tun"] {
            assert_eq!(
                lifecycle[&pathchord_policy::ListenerId::new(listener_id)],
                (1, 1),
                "listener {listener_id} lifecycle must be emitted exactly once"
            );
        }
        let _ = std::fs::remove_dir(root);
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn startup_failure_rolls_back_previously_applied_routes() {
        let routes = Arc::new(FakeRouteAdapter::default());
        let mut tproxy = listener("tproxy", PolicyListenerKind::Tproxy);
        tproxy.protocols = BTreeSet::from([FlowProtocol::Udp]);
        let root = data_dir();
        let result = IngressPlatformRuntime::bind_with_factories(
            IngressPlatformConfig::new(&root),
            &[tproxy, listener("tun", PolicyListenerKind::Tun)],
            tcp_opener(),
            Arc::new(RejectUdpOpener),
            ProtectedEndpointSet::default(),
            factories(routes.clone(), true),
        )
        .await;
        assert!(matches!(result, Err(IngressPlatformError::Adapter { .. })));
        assert_eq!(routes.count(), 0);
        let _ = std::fs::remove_dir(root);
    }

    #[tokio::test]
    async fn rejects_listener_for_another_platform_before_resource_creation() {
        let mut foreign = listener("foreign", PolicyListenerKind::Http);
        foreign.platform = if cfg!(windows) {
            "linux".to_owned()
        } else {
            "windows".to_owned()
        };
        let result = IngressPlatformRuntime::bind_with_factories(
            IngressPlatformConfig::new(data_dir()),
            &[foreign],
            tcp_opener(),
            Arc::new(RejectUdpOpener),
            ProtectedEndpointSet::default(),
            IngressPlatformFactories::default(),
        )
        .await;
        assert!(matches!(
            result,
            Err(IngressPlatformError::UnsupportedPlatform { .. })
        ));
    }

    #[cfg(target_os = "freebsd")]
    #[tokio::test]
    async fn rejects_transparent_and_tun_listeners_before_resource_creation() {
        for kind in [
            PolicyListenerKind::Tproxy,
            PolicyListenerKind::Redirect,
            PolicyListenerKind::Tun,
        ] {
            let path = data_dir();
            let result = IngressPlatformRuntime::bind_with_factories(
                IngressPlatformConfig::new(&path),
                &[listener("unsupported", kind)],
                tcp_opener(),
                Arc::new(RejectUdpOpener),
                ProtectedEndpointSet::default(),
                IngressPlatformFactories::default(),
            )
            .await;
            assert!(matches!(
                result,
                Err(IngressPlatformError::UnsupportedPlatform { .. })
            ));
            assert!(
                !path.exists(),
                "rejection must not create platform resources"
            );
        }
    }
}
