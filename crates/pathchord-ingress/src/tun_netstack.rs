//! Direct smoltcp reactor for turning TUN packets into PathChord TCP/UDP flows.

use std::collections::{BTreeMap, VecDeque};
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, Wake, Waker};
use std::time::{Duration, Instant as StdInstant};

use smoltcp::iface::{Config as InterfaceConfig, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::udp::UdpMetadata;
use smoltcp::socket::{tcp, udp};
use smoltcp::time::{Duration as SmolDuration, Instant as SmolInstant};
use smoltcp::wire::{
    HardwareAddress, IpCidr, IpEndpoint, IpProtocol, IpVersion, Ipv4Packet, Ipv6Packet, TcpPacket,
    UdpPacket,
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{Notify, mpsc};
use tokio::task::JoinSet;

use crate::{
    AcceptedConnection, ConnectionContext, ConnectionResponse, FlowProtocol, ListenerId,
    PacketDevice, PacketDeviceError, ProcessMetadataProvider, ProcessSocketTuple,
    ProtectedEndpointSet, TargetAddress, TargetHost, TcpFlowOpener, UdpFlowOpener,
};

#[derive(Debug, Clone)]
pub struct TunFlowRuntimeConfig {
    pub listener_id: ListenerId,
    pub flow_tags: std::collections::BTreeSet<String>,
    pub allowed_sources: Vec<String>,
    pub process_metadata: pathchord_policy::ProcessMetadataRequest,
    pub process_metadata_provider: Arc<dyn ProcessMetadataProvider>,
    pub addresses: Vec<(IpAddr, u8)>,
    pub mtu: usize,
    pub tcp_enabled: bool,
    pub udp_enabled: bool,
    pub max_tcp_flows: usize,
    pub max_udp_associations: usize,
    pub socket_buffer_bytes: usize,
    pub per_flow_buffer_bytes: usize,
    pub packet_queue: usize,
    pub udp_packet_queue: usize,
    pub idle_timeout: Duration,
    pub maximum_poll_interval: Duration,
}

impl TunFlowRuntimeConfig {
    pub fn from_tun(listener_id: ListenerId, config: &crate::TunDeviceConfig) -> Self {
        Self {
            listener_id,
            flow_tags: std::collections::BTreeSet::new(),
            allowed_sources: Vec::new(),
            process_metadata: pathchord_policy::ProcessMetadataRequest::default(),
            process_metadata_provider: Arc::new(crate::NoopProcessMetadataProvider),
            addresses: vec![(config.address, config.prefix)],
            mtu: usize::from(config.mtu),
            tcp_enabled: true,
            udp_enabled: true,
            max_tcp_flows: 1024,
            max_udp_associations: 1024,
            socket_buffer_bytes: 256 * 1024,
            per_flow_buffer_bytes: 64 * 1024,
            packet_queue: 1024,
            udp_packet_queue: 256,
            idle_timeout: Duration::from_secs(300),
            maximum_poll_interval: Duration::from_millis(25),
        }
    }

    fn validate(&self) -> Result<(), TunFlowRuntimeError> {
        let addresses_valid = !self.addresses.is_empty()
            && self.addresses.iter().all(|(address, prefix)| {
                (*prefix <= 32 && address.is_ipv4()) || (*prefix <= 128 && address.is_ipv6())
            });
        if self.listener_id.as_str().is_empty()
            || !addresses_valid
            || self.mtu < 576
            || (!self.tcp_enabled && !self.udp_enabled)
            || self.max_tcp_flows == 0
            || self.max_udp_associations == 0
            || self.socket_buffer_bytes == 0
            || self.per_flow_buffer_bytes == 0
            || self.packet_queue == 0
            || self.udp_packet_queue == 0
            || self.maximum_poll_interval.is_zero()
        {
            return Err(TunFlowRuntimeError::InvalidConfig);
        }
        Ok(())
    }
}

#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum TunFlowRuntimeError {
    #[error("TUN flow runtime configuration is invalid")]
    InvalidConfig,
    #[error("TUN packet device failed: {0}")]
    Device(String),
    #[error("smoltcp interface failed: {0}")]
    Smoltcp(String),
    #[error("TUN flow task failed: {0}")]
    Task(String),
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TunFlowRuntimeReport {
    pub packets_received: u64,
    pub packets_sent: u64,
    pub packets_rejected: u64,
    pub tcp_flows_opened: u64,
    pub tcp_flows_reset: u64,
    pub udp_associations_opened: u64,
    pub udp_datagrams_received: u64,
    pub udp_datagrams_sent: u64,
}

pub struct TunFlowRuntime {
    config: TunFlowRuntimeConfig,
    tcp_opener: Arc<dyn TcpFlowOpener>,
    udp_opener: Arc<dyn UdpFlowOpener>,
    protected: ProtectedEndpointSet,
}

impl std::fmt::Debug for TunFlowRuntime {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TunFlowRuntime")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl TunFlowRuntime {
    pub fn new(
        config: TunFlowRuntimeConfig,
        tcp_opener: Arc<dyn TcpFlowOpener>,
        udp_opener: Arc<dyn UdpFlowOpener>,
        protected: ProtectedEndpointSet,
    ) -> Result<Self, TunFlowRuntimeError> {
        config.validate()?;
        Ok(Self {
            config,
            tcp_opener,
            udp_opener,
            protected,
        })
    }

    pub async fn run<F>(
        self,
        packet_device: Arc<dyn PacketDevice>,
        shutdown: F,
    ) -> Result<TunFlowRuntimeReport, TunFlowRuntimeError>
    where
        F: Future<Output = ()> + Send,
    {
        let mut reactor = Reactor::new(
            self.config,
            self.tcp_opener,
            self.udp_opener,
            self.protected,
        )?;
        let mut tcp_tasks = JoinSet::new();
        let mut udp_tasks = JoinSet::new();
        let mut shutdown = Box::pin(shutdown);

        reactor.tick(&mut tcp_tasks, &mut udp_tasks).await?;
        reactor.flush_packets(packet_device.as_ref()).await?;
        loop {
            let delay = reactor.poll_delay();
            let sleep = tokio::time::sleep(delay);
            tokio::pin!(sleep);
            tokio::select! {
                () = shutdown.as_mut() => break,
                packet = packet_device.receive_packet() => {
                    match packet {
                        Ok(packet) => reactor.receive_packet(packet),
                        Err(PacketDeviceError::Closed) => break,
                        Err(error) => return Err(TunFlowRuntimeError::Device(error.to_string())),
                    }
                }
                command = reactor.commands.recv() => {
                    if let Some(command) = command {
                        reactor.handle_command(command);
                    }
                }
                joined = tcp_tasks.join_next(), if !tcp_tasks.is_empty() => {
                    reactor.handle_tcp_task(joined)?;
                }
                joined = udp_tasks.join_next(), if !udp_tasks.is_empty() => {
                    reactor.handle_udp_task(joined)?;
                }
                () = reactor.notify.notified() => {}
                () = &mut sleep => {}
            }
            reactor.tick(&mut tcp_tasks, &mut udp_tasks).await?;
            reactor.flush_packets(packet_device.as_ref()).await?;
        }

        reactor.tcp_flows.clear();
        reactor.udp_associations.clear();
        let graceful = async {
            while tcp_tasks.join_next().await.is_some() {}
            while udp_tasks.join_next().await.is_some() {}
        };
        if tokio::time::timeout(Duration::from_secs(1), graceful)
            .await
            .is_err()
        {
            tcp_tasks.abort_all();
            udp_tasks.abort_all();
            while tcp_tasks.join_next().await.is_some() {}
            while udp_tasks.join_next().await.is_some() {}
        }
        Ok(reactor.report)
    }
}

#[derive(Debug)]
struct QueueDevice {
    inbound: VecDeque<Vec<u8>>,
    outbound: VecDeque<Vec<u8>>,
    capabilities: DeviceCapabilities,
    queue_limit: usize,
}

impl QueueDevice {
    fn new(queue_limit: usize) -> Self {
        let mut capabilities = DeviceCapabilities::default();
        capabilities.medium = Medium::Ip;
        capabilities.max_transmission_unit = crate::tun_fragmentation::MAX_PACKET_BYTES;
        Self {
            inbound: VecDeque::new(),
            outbound: VecDeque::new(),
            capabilities,
            queue_limit,
        }
    }
}

struct QueueRxToken(Vec<u8>);

impl RxToken for QueueRxToken {
    fn consume<R, F>(self, function: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        function(&self.0)
    }
}

struct QueueTxToken<'a> {
    outbound: &'a mut VecDeque<Vec<u8>>,
    queue_limit: usize,
}

impl TxToken for QueueTxToken<'_> {
    fn consume<R, F>(self, length: usize, function: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut packet = vec![0_u8; length];
        let result = function(&mut packet);
        if self.outbound.len() < self.queue_limit {
            self.outbound.push_back(packet);
        }
        result
    }
}

impl Device for QueueDevice {
    type RxToken<'a> = QueueRxToken;
    type TxToken<'a> = QueueTxToken<'a>;

    fn receive(
        &mut self,
        _timestamp: SmolInstant,
    ) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let packet = self.inbound.pop_front()?;
        Some((
            QueueRxToken(packet),
            QueueTxToken {
                outbound: &mut self.outbound,
                queue_limit: self.queue_limit,
            },
        ))
    }

    fn transmit(&mut self, _timestamp: SmolInstant) -> Option<Self::TxToken<'_>> {
        Some(QueueTxToken {
            outbound: &mut self.outbound,
            queue_limit: self.queue_limit,
        })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        self.capabilities.clone()
    }
}

#[derive(Debug)]
struct ReactorWake(Arc<Notify>);

impl Wake for ReactorWake {
    fn wake(self: Arc<Self>) {
        self.0.notify_one();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.0.notify_one();
    }
}

struct TcpFlowState {
    socket: SocketHandle,
    io: tokio::io::DuplexStream,
    local_eof: bool,
    remote_eof: bool,
    last_activity: StdInstant,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct UdpKey {
    source: SocketAddr,
    target: SocketAddr,
}

enum ReactorCommand {
    UdpResponse { key: UdpKey, payload: Vec<u8> },
}

type TcpTaskResult = (u64, Result<crate::FlowBridgeStats, crate::FlowBridgeError>);
type UdpTaskResult = (UdpKey, Result<(), TunFlowRuntimeError>);

struct Reactor {
    config: TunFlowRuntimeConfig,
    tcp_opener: Arc<dyn TcpFlowOpener>,
    udp_opener: Arc<dyn UdpFlowOpener>,
    protected: ProtectedEndpointSet,
    interface: Interface,
    device: QueueDevice,
    sockets: SocketSet<'static>,
    tcp_listeners: BTreeMap<u16, SocketHandle>,
    tcp_flows: BTreeMap<u64, TcpFlowState>,
    udp_sockets: BTreeMap<u16, SocketHandle>,
    udp_associations: BTreeMap<UdpKey, mpsc::Sender<Vec<u8>>>,
    pending_udp_responses: VecDeque<(UdpKey, Vec<u8>)>,
    command_sender: mpsc::Sender<ReactorCommand>,
    commands: mpsc::Receiver<ReactorCommand>,
    notify: Arc<Notify>,
    waker: Waker,
    started: StdInstant,
    next_flow_id: u64,
    report: TunFlowRuntimeReport,
    reassembler: crate::tun_fragmentation::Reassembler,
    next_fragment_id: u32,
}

impl Reactor {
    fn new(
        config: TunFlowRuntimeConfig,
        tcp_opener: Arc<dyn TcpFlowOpener>,
        udp_opener: Arc<dyn UdpFlowOpener>,
        protected: ProtectedEndpointSet,
    ) -> Result<Self, TunFlowRuntimeError> {
        let started = StdInstant::now();
        let mut device = QueueDevice::new(config.packet_queue);
        let interface_config = InterfaceConfig::new(HardwareAddress::Ip);
        let mut interface =
            Interface::new(interface_config, &mut device, SmolInstant::from_millis(0));
        interface.update_ip_addrs(|addresses| {
            for (address, prefix) in &config.addresses {
                let _ = addresses.push(IpCidr::new((*address).into(), *prefix));
            }
        });
        interface.set_any_ip(true);
        let (command_sender, commands) = mpsc::channel(config.packet_queue);
        let notify = Arc::new(Notify::new());
        let waker = Waker::from(Arc::new(ReactorWake(Arc::clone(&notify))));
        let reassembler = crate::tun_fragmentation::Reassembler::new(config.packet_queue.min(16));
        Ok(Self {
            config,
            tcp_opener,
            udp_opener,
            protected,
            interface,
            device,
            sockets: SocketSet::new(Vec::new()),
            tcp_listeners: BTreeMap::new(),
            tcp_flows: BTreeMap::new(),
            udp_sockets: BTreeMap::new(),
            udp_associations: BTreeMap::new(),
            pending_udp_responses: VecDeque::new(),
            command_sender,
            commands,
            notify,
            waker,
            started,
            next_flow_id: 0,
            report: TunFlowRuntimeReport::default(),
            reassembler,
            next_fragment_id: 1,
        })
    }

    fn now(&self) -> SmolInstant {
        let millis = self.started.elapsed().as_millis().min(i64::MAX as u128) as i64;
        SmolInstant::from_millis(millis)
    }

    fn poll_delay(&mut self) -> Duration {
        self.interface
            .poll_delay(self.now(), &self.sockets)
            .map(|delay| Duration::from_millis(delay.total_millis()))
            .unwrap_or(self.config.maximum_poll_interval)
            .min(self.config.maximum_poll_interval)
    }

    fn receive_packet(&mut self, packet: Vec<u8>) {
        self.report.packets_received = self.report.packets_received.saturating_add(1);
        if crate::tun_fragmentation::source(&packet)
            .is_none_or(|source| !crate::source_allowed(&self.config.allowed_sources, source))
        {
            self.report.packets_rejected = self.report.packets_rejected.saturating_add(1);
            return;
        }
        let packet = match self.reassembler.receive(packet, StdInstant::now()) {
            Ok(Some(packet)) => packet,
            Ok(None) => return,
            Err(()) => {
                self.report.packets_rejected = self.report.packets_rejected.saturating_add(1);
                return;
            }
        };
        let Some(tuple) = packet_tuple(&packet) else {
            self.report.packets_rejected = self.report.packets_rejected.saturating_add(1);
            return;
        };
        if self.protected.contains(&tuple.target) {
            self.report.packets_rejected = self.report.packets_rejected.saturating_add(1);
            return;
        }
        if !crate::source_allowed(&self.config.allowed_sources, tuple.source.ip()) {
            self.report.packets_rejected = self.report.packets_rejected.saturating_add(1);
            return;
        }
        let admitted = match tuple.protocol {
            FlowProtocol::Tcp if self.config.tcp_enabled => {
                self.ensure_tcp_listener(tuple.target.port())
            }
            FlowProtocol::Udp if self.config.udp_enabled => {
                self.ensure_udp_socket(tuple.target.port())
            }
            _ => false,
        };
        if admitted {
            if self.device.inbound.len() < self.config.packet_queue {
                self.device.inbound.push_back(packet);
            } else {
                self.report.packets_rejected = self.report.packets_rejected.saturating_add(1);
            }
        } else {
            self.report.packets_rejected = self.report.packets_rejected.saturating_add(1);
        }
    }

    fn ensure_tcp_listener(&mut self, port: u16) -> bool {
        if self.tcp_listeners.contains_key(&port) {
            return true;
        }
        if self.tcp_flows.len() + self.tcp_listeners.len() >= self.config.max_tcp_flows {
            return false;
        }
        let rx = tcp::SocketBuffer::new(vec![0; self.config.socket_buffer_bytes]);
        let tx = tcp::SocketBuffer::new(vec![0; self.config.socket_buffer_bytes]);
        let mut socket = tcp::Socket::new(rx, tx);
        socket.set_timeout(Some(SmolDuration::from_millis(
            self.config.idle_timeout.as_millis().min(u64::MAX as u128) as u64,
        )));
        if socket.listen(port).is_err() {
            return false;
        }
        let handle = self.sockets.add(socket);
        self.tcp_listeners.insert(port, handle);
        true
    }

    fn ensure_udp_socket(&mut self, port: u16) -> bool {
        if self.udp_sockets.contains_key(&port) {
            return true;
        }
        if self.udp_sockets.len() >= self.config.max_udp_associations {
            return false;
        }
        let rx = udp::PacketBuffer::new(
            vec![udp::PacketMetadata::EMPTY; self.config.udp_packet_queue],
            vec![0; self.config.socket_buffer_bytes],
        );
        let tx = udp::PacketBuffer::new(
            vec![udp::PacketMetadata::EMPTY; self.config.udp_packet_queue],
            vec![0; self.config.socket_buffer_bytes],
        );
        let mut socket = udp::Socket::new(rx, tx);
        if socket.bind(port).is_err() {
            return false;
        }
        let handle = self.sockets.add(socket);
        self.udp_sockets.insert(port, handle);
        true
    }

    async fn tick(
        &mut self,
        tcp_tasks: &mut JoinSet<TcpTaskResult>,
        udp_tasks: &mut JoinSet<UdpTaskResult>,
    ) -> Result<(), TunFlowRuntimeError> {
        self.interface
            .poll(self.now(), &mut self.device, &mut self.sockets);
        self.accept_tcp_flows(tcp_tasks).await?;
        self.pump_tcp_flows();
        self.receive_udp_datagrams(udp_tasks);
        self.flush_udp_responses();
        self.interface
            .poll(self.now(), &mut self.device, &mut self.sockets);
        self.cleanup_tcp_flows();
        Ok(())
    }

    async fn accept_tcp_flows(
        &mut self,
        tasks: &mut JoinSet<TcpTaskResult>,
    ) -> Result<(), TunFlowRuntimeError> {
        let listeners: Vec<_> = self
            .tcp_listeners
            .iter()
            .map(|(port, handle)| (*port, *handle))
            .collect();
        for (port, handle) in listeners {
            let state = self.sockets.get::<tcp::Socket>(handle).state();
            if state == tcp::State::Listen || state == tcp::State::SynReceived {
                continue;
            }
            self.tcp_listeners.remove(&port);
            if !matches!(state, tcp::State::Established | tcp::State::CloseWait) {
                self.sockets.remove(handle);
                self.ensure_tcp_listener(port);
                continue;
            }
            let socket = self.sockets.get::<tcp::Socket>(handle);
            let Some(local) = socket.local_endpoint().map(endpoint_to_socket) else {
                self.sockets.remove(handle);
                self.ensure_tcp_listener(port);
                continue;
            };
            let Some(remote) = socket.remote_endpoint().map(endpoint_to_socket) else {
                self.sockets.remove(handle);
                self.ensure_tcp_listener(port);
                continue;
            };
            self.ensure_tcp_listener(port);
            if self.protected.contains(&local) || self.tcp_flows.len() >= self.config.max_tcp_flows
            {
                self.sockets.get_mut::<tcp::Socket>(handle).abort();
                self.report.tcp_flows_reset = self.report.tcp_flows_reset.saturating_add(1);
                continue;
            }
            let flow_id = self.next_flow_id;
            self.next_flow_id = self.next_flow_id.saturating_add(1);
            let (engine_io, application_io) = tokio::io::duplex(self.config.per_flow_buffer_bytes);
            let context = ConnectionContext {
                flow_tags: self.config.flow_tags.clone(),
                listener_id: self.config.listener_id.clone(),
                source: remote,
                authentication_identity: None,
                process: None,
                protocol: FlowProtocol::Tcp,
                target: TargetAddress {
                    host: TargetHost::Ip(local.ip()),
                    port: local.port(),
                },
            };
            let opener = Arc::clone(&self.tcp_opener);
            let process_metadata = self.config.process_metadata;
            let process_metadata_provider = Arc::clone(&self.config.process_metadata_provider);
            tasks.spawn(async move {
                let mut context = context;
                if !process_metadata.is_empty() {
                    context.process = process_metadata_provider
                        .lookup(
                            ProcessSocketTuple {
                                source: remote,
                                local,
                            },
                            process_metadata,
                        )
                        .await;
                }
                let accepted = AcceptedConnection {
                    io: Box::new(application_io),
                    context,
                    response: ConnectionResponse::None,
                };
                (
                    flow_id,
                    crate::bridge_connection(accepted, opener.as_ref()).await,
                )
            });
            self.tcp_flows.insert(
                flow_id,
                TcpFlowState {
                    socket: handle,
                    io: engine_io,
                    local_eof: false,
                    remote_eof: false,
                    last_activity: StdInstant::now(),
                },
            );
            self.report.tcp_flows_opened = self.report.tcp_flows_opened.saturating_add(1);
        }
        Ok(())
    }

    fn pump_tcp_flows(&mut self) {
        let ids: Vec<_> = self.tcp_flows.keys().copied().collect();
        for id in ids {
            let Some(flow) = self.tcp_flows.get_mut(&id) else {
                continue;
            };
            let socket = self.sockets.get_mut::<tcp::Socket>(flow.socket);
            if socket.state() == tcp::State::Closed && !flow.local_eof && !flow.remote_eof {
                flow.local_eof = true;
                flow.remote_eof = true;
                self.report.tcp_flows_reset = self.report.tcp_flows_reset.saturating_add(1);
                continue;
            }
            let mut context = Context::from_waker(&self.waker);
            if socket.can_recv() {
                let mut buffer =
                    vec![0_u8; self.config.per_flow_buffer_bytes.min(socket.recv_queue())];
                if let Ok(length) = socket.peek_slice(&mut buffer)
                    && length > 0
                {
                    match Pin::new(&mut flow.io).poll_write(&mut context, &buffer[..length]) {
                        Poll::Ready(Ok(written)) if written > 0 => {
                            let _ = socket.recv(|data| (written.min(data.len()), ()));
                            flow.last_activity = StdInstant::now();
                        }
                        Poll::Ready(Err(_)) => socket.abort(),
                        _ => {}
                    }
                }
            }
            if socket.can_send() && !flow.local_eof {
                let available = socket.send_capacity().saturating_sub(socket.send_queue());
                if available > 0 {
                    let mut buffer = vec![0_u8; available.min(self.config.per_flow_buffer_bytes)];
                    let mut read = ReadBuf::new(&mut buffer);
                    match Pin::new(&mut flow.io).poll_read(&mut context, &mut read) {
                        Poll::Ready(Ok(())) if read.filled().is_empty() => {
                            flow.local_eof = true;
                            socket.close();
                        }
                        Poll::Ready(Ok(())) => {
                            if socket.send_slice(read.filled()).is_ok() {
                                flow.last_activity = StdInstant::now();
                            }
                        }
                        Poll::Ready(Err(_)) => socket.abort(),
                        Poll::Pending => {}
                    }
                }
            }
            if !socket.may_recv() && socket.recv_queue() == 0 && !flow.remote_eof {
                flow.remote_eof = true;
                let _ = Pin::new(&mut flow.io).poll_shutdown(&mut context);
            }
            if tcp_flow_timed_out(flow.last_activity, self.config.idle_timeout) {
                socket.abort();
                flow.local_eof = true;
                flow.remote_eof = true;
                self.report.tcp_flows_reset = self.report.tcp_flows_reset.saturating_add(1);
            }
        }
    }

    fn cleanup_tcp_flows(&mut self) {
        let closed: Vec<_> = self
            .tcp_flows
            .iter()
            .filter_map(|(id, flow)| {
                let socket = self.sockets.get::<tcp::Socket>(flow.socket);
                (socket.state() == tcp::State::Closed).then_some((*id, flow.socket))
            })
            .collect();
        for (id, handle) in closed {
            if let Some(flow) = self.tcp_flows.remove(&id)
                && !flow.local_eof
                && !flow.remote_eof
            {
                self.report.tcp_flows_reset = self.report.tcp_flows_reset.saturating_add(1);
            }
            self.sockets.remove(handle);
        }
    }

    fn receive_udp_datagrams(&mut self, tasks: &mut JoinSet<UdpTaskResult>) {
        let sockets: Vec<_> = self.udp_sockets.values().copied().collect();
        let mut datagrams = Vec::new();
        for handle in sockets {
            let socket = self.sockets.get_mut::<udp::Socket>(handle);
            let local_port = socket.endpoint().port;
            while socket.can_recv() {
                let Ok((payload, metadata)) = socket.recv() else {
                    break;
                };
                let Some(local_address) = metadata.local_address else {
                    continue;
                };
                let source = endpoint_to_socket(metadata.endpoint);
                let target = SocketAddr::new(local_address.into(), local_port);
                datagrams.push((source, target, payload.to_vec()));
            }
        }
        for (source, target, payload) in datagrams {
            self.report.udp_datagrams_received =
                self.report.udp_datagrams_received.saturating_add(1);
            let key = UdpKey { source, target };
            if let Some(sender) = self.udp_associations.get(&key) {
                let _ = sender.try_send(payload);
                continue;
            }
            if self.udp_associations.len() >= self.config.max_udp_associations {
                self.report.packets_rejected = self.report.packets_rejected.saturating_add(1);
                continue;
            }
            let (sender, receiver) = mpsc::channel(self.config.udp_packet_queue);
            if sender.try_send(payload).is_err() {
                continue;
            }
            self.udp_associations.insert(key.clone(), sender);
            let opener = Arc::clone(&self.udp_opener);
            let commands = self.command_sender.clone();
            let listener_id = self.config.listener_id.clone();
            let flow_tags = self.config.flow_tags.clone();
            let process_metadata = self.config.process_metadata;
            let process_metadata_provider = Arc::clone(&self.config.process_metadata_provider);
            let idle_timeout = self.config.idle_timeout;
            tasks.spawn(async move {
                let result = run_udp_association(UdpAssociationArgs {
                    key: key.clone(),
                    listener_id,
                    flow_tags,
                    process_metadata,
                    process_metadata_provider,
                    opener,
                    requests: receiver,
                    commands,
                    idle_timeout,
                })
                .await;
                (key, result)
            });
            self.report.udp_associations_opened =
                self.report.udp_associations_opened.saturating_add(1);
        }
    }

    fn handle_command(&mut self, command: ReactorCommand) {
        match command {
            ReactorCommand::UdpResponse { key, payload } => {
                if self.pending_udp_responses.len() < self.config.udp_packet_queue {
                    self.pending_udp_responses.push_back((key, payload));
                } else {
                    self.report.packets_rejected = self.report.packets_rejected.saturating_add(1);
                }
            }
        }
    }

    fn flush_udp_responses(&mut self) {
        let mut remaining = VecDeque::new();
        while let Some((key, payload)) = self.pending_udp_responses.pop_front() {
            let Some(handle) = self.udp_sockets.get(&key.target.port()).copied() else {
                continue;
            };
            let socket = self.sockets.get_mut::<udp::Socket>(handle);
            let metadata = UdpMetadata {
                endpoint: socket_to_endpoint(key.source),
                local_address: Some(key.target.ip().into()),
                meta: Default::default(),
            };
            if socket.send_slice(&payload, metadata).is_ok() {
                self.report.udp_datagrams_sent = self.report.udp_datagrams_sent.saturating_add(1);
            } else if remaining.len() < self.config.udp_packet_queue {
                remaining.push_back((key, payload));
            }
        }
        self.pending_udp_responses = remaining;
    }

    fn handle_tcp_task(
        &mut self,
        joined: Option<Result<TcpTaskResult, tokio::task::JoinError>>,
    ) -> Result<(), TunFlowRuntimeError> {
        match joined {
            // Successful completion can leave response bytes in the duplex
            // buffer. pump_tcp_flows drains them before observing EOF and
            // sending FIN; closing here would discard that accepted response.
            Some(Ok((_, Ok(_)))) => {}
            Some(Ok((id, Err(_)))) => {
                if let Some(flow) = self.tcp_flows.get_mut(&id) {
                    self.sockets.get_mut::<tcp::Socket>(flow.socket).abort();
                    flow.local_eof = true;
                    flow.remote_eof = true;
                    self.report.tcp_flows_reset = self.report.tcp_flows_reset.saturating_add(1);
                }
            }
            Some(Err(error)) => return Err(TunFlowRuntimeError::Task(error.to_string())),
            None => {}
        }
        Ok(())
    }

    fn handle_udp_task(
        &mut self,
        joined: Option<Result<UdpTaskResult, tokio::task::JoinError>>,
    ) -> Result<(), TunFlowRuntimeError> {
        match joined {
            Some(Ok((key, result))) => {
                self.udp_associations.remove(&key);
                if result.is_err() {
                    self.report.packets_rejected = self.report.packets_rejected.saturating_add(1);
                }
            }
            Some(Err(error)) => return Err(TunFlowRuntimeError::Task(error.to_string())),
            None => {}
        }
        Ok(())
    }

    async fn flush_packets(
        &mut self,
        packet_device: &dyn PacketDevice,
    ) -> Result<(), TunFlowRuntimeError> {
        while let Some(packet) = self.device.outbound.pop_front() {
            let fragments =
                crate::tun_fragmentation::split(&packet, self.config.mtu, self.next_fragment_id)
                    .map_err(|()| {
                        TunFlowRuntimeError::Device("cannot fragment outgoing IP packet".to_owned())
                    })?;
            self.next_fragment_id = self.next_fragment_id.wrapping_add(1);
            for fragment in fragments {
                packet_device
                    .send_packet(&fragment)
                    .await
                    .map_err(|error| TunFlowRuntimeError::Device(error.to_string()))?;
                self.report.packets_sent = self.report.packets_sent.saturating_add(1);
            }
        }
        Ok(())
    }
}

struct UdpAssociationArgs {
    key: UdpKey,
    listener_id: ListenerId,
    flow_tags: std::collections::BTreeSet<String>,
    process_metadata: pathchord_policy::ProcessMetadataRequest,
    process_metadata_provider: Arc<dyn ProcessMetadataProvider>,
    opener: Arc<dyn UdpFlowOpener>,
    requests: mpsc::Receiver<Vec<u8>>,
    commands: mpsc::Sender<ReactorCommand>,
    idle_timeout: Duration,
}

async fn run_udp_association(args: UdpAssociationArgs) -> Result<(), TunFlowRuntimeError> {
    let UdpAssociationArgs {
        key,
        listener_id,
        flow_tags,
        process_metadata,
        process_metadata_provider,
        opener,
        mut requests,
        commands,
        idle_timeout,
    } = args;
    let context = ConnectionContext {
        flow_tags,
        listener_id,
        source: key.source,
        authentication_identity: None,
        process: None,
        protocol: FlowProtocol::Udp,
        target: TargetAddress {
            host: TargetHost::Ip(key.target.ip()),
            port: key.target.port(),
        },
    };
    let mut context = context;
    if !process_metadata.is_empty() {
        context.process = process_metadata_provider
            .lookup(
                ProcessSocketTuple {
                    source: key.source,
                    local: key.target,
                },
                process_metadata,
            )
            .await;
    }
    let mut handle = opener
        .open_udp(&context)
        .await
        .map_err(|error| TunFlowRuntimeError::Task(error.to_string()))?;
    loop {
        let idle = tokio::time::sleep(idle_timeout);
        tokio::pin!(idle);
        tokio::select! {
            () = &mut idle => {
                handle.close().await.map_err(|error| TunFlowRuntimeError::Task(error.to_string()))?;
                return Ok(());
            }
            request = requests.recv() => {
                let Some(request) = request else {
                    handle.close().await.map_err(|error| TunFlowRuntimeError::Task(error.to_string()))?;
                    return Ok(());
                };
                handle.send(request).await.map_err(|error| TunFlowRuntimeError::Task(error.to_string()))?;
            }
            response = handle.receive() => {
                let Some(payload) = response else {
                    return Ok(());
                };
                commands.send(ReactorCommand::UdpResponse {
                    key: key.clone(),
                    payload,
                }).await.map_err(|_| TunFlowRuntimeError::Task("reactor command queue closed".to_owned()))?;
            }
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct PacketTuple {
    protocol: FlowProtocol,
    source: SocketAddr,
    target: SocketAddr,
}

fn packet_tuple(packet: &[u8]) -> Option<PacketTuple> {
    if packet.is_empty() {
        return None;
    }
    let (protocol, source, destination, payload) = match IpVersion::of_packet(packet).ok()? {
        IpVersion::Ipv4 => {
            let packet = Ipv4Packet::new_checked(packet).ok()?;
            (
                packet.next_header(),
                IpAddr::V4(packet.src_addr()),
                IpAddr::V4(packet.dst_addr()),
                packet.payload(),
            )
        }
        IpVersion::Ipv6 => {
            let packet = Ipv6Packet::new_checked(packet).ok()?;
            (
                packet.next_header(),
                IpAddr::V6(packet.src_addr()),
                IpAddr::V6(packet.dst_addr()),
                packet.payload(),
            )
        }
    };
    let (protocol, source_port, target_port) = match protocol {
        IpProtocol::Tcp => {
            let packet = TcpPacket::new_checked(payload).ok()?;
            (FlowProtocol::Tcp, packet.src_port(), packet.dst_port())
        }
        IpProtocol::Udp => {
            let packet = UdpPacket::new_checked(payload).ok()?;
            (FlowProtocol::Udp, packet.src_port(), packet.dst_port())
        }
        _ => return None,
    };
    Some(PacketTuple {
        protocol,
        source: SocketAddr::new(source, source_port),
        target: SocketAddr::new(destination, target_port),
    })
}

fn endpoint_to_socket(endpoint: IpEndpoint) -> SocketAddr {
    SocketAddr::new(endpoint.addr.into(), endpoint.port)
}

fn socket_to_endpoint(endpoint: SocketAddr) -> IpEndpoint {
    IpEndpoint::new(endpoint.ip().into(), endpoint.port())
}

fn tcp_flow_timed_out(last_activity: StdInstant, idle_timeout: Duration) -> bool {
    last_activity.elapsed() > idle_timeout
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    use async_trait::async_trait;
    use smoltcp::phy::ChecksumCapabilities;
    use smoltcp::wire::{Ipv4Address, Ipv4Repr, Ipv6Address, Ipv6Repr, TcpSeqNumber, UdpRepr};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::sync::oneshot;

    #[derive(Debug, Default)]
    struct FakeUdpOpener {
        contexts: Mutex<Vec<ConnectionContext>>,
    }

    #[derive(Debug)]
    struct EchoUdpHandle {
        responses: mpsc::Receiver<Vec<u8>>,
        response_tx: mpsc::Sender<Vec<u8>>,
    }

    #[async_trait]
    impl crate::UdpFlowHandle for EchoUdpHandle {
        async fn send(&mut self, mut payload: Vec<u8>) -> Result<(), crate::UdpFlowError> {
            payload.reverse();
            self.response_tx
                .send(payload)
                .await
                .map_err(|_| crate::UdpFlowError::Task("closed".to_owned()))
        }

        async fn receive(&mut self) -> Option<Vec<u8>> {
            self.responses.recv().await
        }

        async fn close(self: Box<Self>) -> Result<(), crate::UdpFlowError> {
            Ok(())
        }
    }

    #[async_trait]
    impl UdpFlowOpener for FakeUdpOpener {
        async fn open_udp(
            &self,
            context: &ConnectionContext,
        ) -> Result<crate::BoxedUdpFlowHandle, crate::UdpFlowError> {
            self.contexts.lock().unwrap().push(context.clone());
            let (response_tx, responses) = mpsc::channel(4);
            Ok(Box::new(EchoUdpHandle {
                responses,
                response_tx,
            }))
        }
    }

    fn config() -> TunFlowRuntimeConfig {
        TunFlowRuntimeConfig {
            listener_id: ListenerId::new("tun"),
            flow_tags: std::collections::BTreeSet::new(),
            allowed_sources: Vec::new(),
            process_metadata: pathchord_policy::ProcessMetadataRequest::default(),
            process_metadata_provider: Arc::new(crate::NoopProcessMetadataProvider),
            addresses: vec![
                ("10.0.0.1".parse().unwrap(), 24),
                ("fd00::1".parse().unwrap(), 64),
            ],
            mtu: 1500,
            tcp_enabled: true,
            udp_enabled: true,
            max_tcp_flows: 16,
            max_udp_associations: 16,
            socket_buffer_bytes: 16 * 1024,
            per_flow_buffer_bytes: 4096,
            packet_queue: 64,
            udp_packet_queue: 16,
            idle_timeout: Duration::from_secs(30),
            maximum_poll_interval: Duration::from_millis(1),
        }
    }

    fn build_udp_v4(
        source: (Ipv4Address, u16),
        target: (Ipv4Address, u16),
        payload: &[u8],
    ) -> Vec<u8> {
        let udp = UdpRepr {
            src_port: source.1,
            dst_port: target.1,
        };
        let ip = Ipv4Repr {
            src_addr: source.0,
            dst_addr: target.0,
            next_header: IpProtocol::Udp,
            payload_len: udp.header_len() + payload.len(),
            hop_limit: 64,
        };
        let mut bytes = vec![0_u8; ip.buffer_len() + udp.header_len() + payload.len()];
        ip.emit(
            &mut Ipv4Packet::new_unchecked(&mut bytes),
            &ChecksumCapabilities::default(),
        );
        udp.emit(
            &mut UdpPacket::new_unchecked(&mut bytes[ip.buffer_len()..]),
            &source.0.into(),
            &target.0.into(),
            payload.len(),
            |buffer| buffer.copy_from_slice(payload),
            &ChecksumCapabilities::default(),
        );
        bytes
    }

    fn build_udp_v6(
        source: (Ipv6Address, u16),
        target: (Ipv6Address, u16),
        payload: &[u8],
    ) -> Vec<u8> {
        let udp = UdpRepr {
            src_port: source.1,
            dst_port: target.1,
        };
        let ip = Ipv6Repr {
            src_addr: source.0,
            dst_addr: target.0,
            next_header: IpProtocol::Udp,
            payload_len: udp.header_len() + payload.len(),
            hop_limit: 64,
        };
        let mut bytes = vec![0_u8; ip.buffer_len() + udp.header_len() + payload.len()];
        ip.emit(&mut Ipv6Packet::new_unchecked(&mut bytes));
        udp.emit(
            &mut UdpPacket::new_unchecked(&mut bytes[ip.buffer_len()..]),
            &source.0.into(),
            &target.0.into(),
            payload.len(),
            |buffer| buffer.copy_from_slice(payload),
            &ChecksumCapabilities::default(),
        );
        bytes
    }

    struct TestTcpSegment<'a> {
        sequence: TcpSeqNumber,
        acknowledgement: Option<TcpSeqNumber>,
        syn: bool,
        fin: bool,
        rst: bool,
        payload: &'a [u8],
    }

    impl<'a> TestTcpSegment<'a> {
        fn syn(sequence: TcpSeqNumber) -> Self {
            Self {
                sequence,
                acknowledgement: None,
                syn: true,
                fin: false,
                rst: false,
                payload: &[],
            }
        }

        fn ack(sequence: TcpSeqNumber, acknowledgement: TcpSeqNumber) -> Self {
            Self {
                sequence,
                acknowledgement: Some(acknowledgement),
                syn: false,
                fin: false,
                rst: false,
                payload: &[],
            }
        }

        fn data(sequence: TcpSeqNumber, acknowledgement: TcpSeqNumber, payload: &'a [u8]) -> Self {
            Self {
                sequence,
                acknowledgement: Some(acknowledgement),
                syn: false,
                fin: false,
                rst: false,
                payload,
            }
        }

        fn fin(sequence: TcpSeqNumber, acknowledgement: TcpSeqNumber) -> Self {
            Self {
                sequence,
                acknowledgement: Some(acknowledgement),
                syn: false,
                fin: true,
                rst: false,
                payload: &[],
            }
        }

        fn rst(sequence: TcpSeqNumber, acknowledgement: TcpSeqNumber) -> Self {
            Self {
                sequence,
                acknowledgement: Some(acknowledgement),
                syn: false,
                fin: false,
                rst: true,
                payload: &[],
            }
        }
    }

    fn build_tcp_v4(
        source: (Ipv4Address, u16),
        target: (Ipv4Address, u16),
        segment: TestTcpSegment<'_>,
    ) -> Vec<u8> {
        let ip = Ipv4Repr {
            src_addr: source.0,
            dst_addr: target.0,
            next_header: IpProtocol::Tcp,
            payload_len: 20 + segment.payload.len(),
            hop_limit: 64,
        };
        let mut bytes = vec![0_u8; ip.buffer_len() + 20 + segment.payload.len()];
        ip.emit(
            &mut Ipv4Packet::new_unchecked(&mut bytes),
            &ChecksumCapabilities::default(),
        );
        let mut tcp = TcpPacket::new_unchecked(&mut bytes[ip.buffer_len()..]);
        tcp.set_src_port(source.1);
        tcp.set_dst_port(target.1);
        tcp.set_seq_number(segment.sequence);
        tcp.set_ack_number(segment.acknowledgement.unwrap_or(TcpSeqNumber(0)));
        tcp.set_ack(segment.acknowledgement.is_some());
        tcp.set_syn(segment.syn);
        tcp.set_fin(segment.fin);
        tcp.set_rst(segment.rst);
        tcp.set_psh(!segment.payload.is_empty());
        tcp.set_header_len(20);
        tcp.set_window_len(32_768);
        tcp.payload_mut().copy_from_slice(segment.payload);
        tcp.fill_checksum(&source.0.into(), &target.0.into());
        bytes
    }

    fn tcp_packet(packet: &[u8]) -> Option<TcpPacket<&[u8]>> {
        let ip = Ipv4Packet::new_checked(packet).ok()?;
        TcpPacket::new_checked(ip.payload()).ok()
    }

    fn udp_payload(packet: &[u8]) -> Option<Vec<u8>> {
        match IpVersion::of_packet(packet).ok()? {
            IpVersion::Ipv4 => {
                let ip = Ipv4Packet::new_checked(packet).ok()?;
                Some(
                    UdpPacket::new_checked(ip.payload())
                        .ok()?
                        .payload()
                        .to_vec(),
                )
            }
            IpVersion::Ipv6 => {
                let ip = Ipv6Packet::new_checked(packet).ok()?;
                Some(
                    UdpPacket::new_checked(ip.payload())
                        .ok()?
                        .payload()
                        .to_vec(),
                )
            }
        }
    }

    async fn wait_for_packet(
        device: &crate::FakePacketDevice,
        predicate: impl Fn(&[u8]) -> bool,
    ) -> Vec<u8> {
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                for packet in device.take_outbound() {
                    if predicate(&packet) {
                        return packet;
                    }
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("packet timeout")
    }

    async fn complete_tcp_handshake(
        device: &crate::FakePacketDevice,
        source: (Ipv4Address, u16),
        target: (Ipv4Address, u16),
        client_seq: TcpSeqNumber,
    ) -> TcpSeqNumber {
        device
            .inject(build_tcp_v4(
                source,
                target,
                TestTcpSegment::syn(client_seq),
            ))
            .await
            .unwrap();
        let syn_ack = wait_for_packet(device, |packet| {
            tcp_packet(packet).is_some_and(|tcp| tcp.syn() && tcp.ack())
        })
        .await;
        let server_seq = tcp_packet(&syn_ack).unwrap().seq_number();
        device
            .inject(build_tcp_v4(
                source,
                target,
                TestTcpSegment::ack(client_seq + 1, server_seq + 1),
            ))
            .await
            .unwrap();
        server_seq
    }

    #[tokio::test]
    async fn udp_v4_v6_preserve_boundaries_and_shutdown() {
        let device = crate::FakePacketDevice::new(1500, 32);
        let udp = Arc::new(FakeUdpOpener::default());
        let tcp = Arc::new(crate::FixedTargetDialer::new(|_| {
            Err::<tokio::io::DuplexStream, _>(crate::FlowBridgeError::Dial("unused".to_owned()))
        }));
        let runtime =
            TunFlowRuntime::new(config(), tcp, udp.clone(), ProtectedEndpointSet::default())
                .unwrap();
        let (shutdown, signal) = oneshot::channel();
        let task = tokio::spawn(runtime.run(device.clone(), async move {
            let _ = signal.await;
        }));

        device
            .inject(build_udp_v4(
                (Ipv4Address::new(10, 0, 0, 2), 40_000),
                (Ipv4Address::new(198, 51, 100, 20), 53),
                &[1, 2, 3],
            ))
            .await
            .unwrap();
        let response =
            wait_for_packet(&device, |packet| udp_payload(packet) == Some(vec![3, 2, 1])).await;
        assert_eq!(udp_payload(&response), Some(vec![3, 2, 1]));

        device
            .inject(build_udp_v6(
                ("fd00::2".parse().unwrap(), 40_001),
                ("2001:db8::20".parse().unwrap(), 53),
                &[4, 5, 6],
            ))
            .await
            .unwrap();
        let response =
            wait_for_packet(&device, |packet| udp_payload(packet) == Some(vec![6, 5, 4])).await;
        assert_eq!(udp_payload(&response), Some(vec![6, 5, 4]));
        assert_eq!(udp.contexts.lock().unwrap().len(), 2);

        shutdown.send(()).unwrap();
        let report = task.await.unwrap().unwrap();
        assert_eq!(report.udp_associations_opened, 2);
        assert_eq!(report.udp_datagrams_sent, 2);
    }

    #[tokio::test]
    async fn protected_endpoint_is_rejected_before_socket_creation() {
        let device = crate::FakePacketDevice::new(1500, 4);
        let protected = ProtectedEndpointSet::default();
        protected.replace(["198.51.100.20:53".parse().unwrap()]);
        let runtime = TunFlowRuntime::new(
            config(),
            Arc::new(crate::FixedTargetDialer::new(|_| {
                Err::<tokio::io::DuplexStream, _>(crate::FlowBridgeError::Dial("unused".to_owned()))
            })),
            Arc::new(FakeUdpOpener::default()),
            protected,
        )
        .unwrap();
        let (shutdown, signal) = oneshot::channel();
        let task = tokio::spawn(runtime.run(device.clone(), async move {
            let _ = signal.await;
        }));
        device
            .inject(build_udp_v4(
                (Ipv4Address::new(10, 0, 0, 2), 40_000),
                (Ipv4Address::new(198, 51, 100, 20), 53),
                &[1],
            ))
            .await
            .unwrap();
        tokio::task::yield_now().await;
        shutdown.send(()).unwrap();
        let report = task.await.unwrap().unwrap();
        assert_eq!(report.packets_rejected, 1);
        assert!(device.outbound().is_empty());
    }

    #[tokio::test]
    async fn source_restrictions_reject_tun_packets_before_socket_creation() {
        let device = crate::FakePacketDevice::new(1500, 4);
        let mut runtime_config = config();
        runtime_config.allowed_sources = vec!["192.0.2.0/24".to_owned()];
        let runtime = TunFlowRuntime::new(
            runtime_config,
            Arc::new(crate::FixedTargetDialer::new(|_| {
                Err::<tokio::io::DuplexStream, _>(crate::FlowBridgeError::Dial("unused".to_owned()))
            })),
            Arc::new(FakeUdpOpener::default()),
            ProtectedEndpointSet::default(),
        )
        .unwrap();
        let (shutdown, signal) = oneshot::channel();
        let task = tokio::spawn(runtime.run(device.clone(), async move {
            let _ = signal.await;
        }));
        device
            .inject(build_udp_v4(
                (Ipv4Address::new(10, 0, 0, 2), 40_000),
                (Ipv4Address::new(198, 51, 100, 20), 53),
                &[1],
            ))
            .await
            .unwrap();
        tokio::task::yield_now().await;
        shutdown.send(()).unwrap();
        let report = task.await.unwrap().unwrap();
        assert_eq!(report.packets_rejected, 1);
        assert!(device.outbound().is_empty());
    }

    #[tokio::test]
    async fn tcp_handshake_backpressure_and_half_close_use_smoltcp_state_machine() {
        let device = crate::FakePacketDevice::new(1500, 64);
        let target_slot = Arc::new(Mutex::new(None));
        let target_slot_for_opener = target_slot.clone();
        let seen_context = Arc::new(Mutex::new(None));
        let seen_context_for_opener = seen_context.clone();
        let (mut target_peer, target_stream) = tokio::io::duplex(4096);
        *target_slot.lock().unwrap() = Some(target_stream);
        let tcp = Arc::new(crate::FixedTargetDialer::new(move |context| {
            *seen_context_for_opener.lock().unwrap() = Some(context);
            target_slot_for_opener
                .lock()
                .unwrap()
                .take()
                .ok_or_else(|| crate::FlowBridgeError::Dial("target already used".to_owned()))
        }));
        let mut runtime_config = config();
        runtime_config.per_flow_buffer_bytes = 8;
        let runtime = TunFlowRuntime::new(
            runtime_config,
            tcp,
            Arc::new(FakeUdpOpener::default()),
            ProtectedEndpointSet::default(),
        )
        .unwrap();
        let (shutdown, signal) = oneshot::channel();
        let task = tokio::spawn(runtime.run(device.clone(), async move {
            let _ = signal.await;
        }));

        let source = (Ipv4Address::new(10, 0, 0, 2), 40_000);
        let target = (Ipv4Address::new(198, 51, 100, 20), 443);
        let client_seq = TcpSeqNumber(1_000);
        let payload: Vec<_> = (0_u8..128).collect();
        device
            .inject(build_tcp_v4(
                source,
                target,
                TestTcpSegment::syn(client_seq),
            ))
            .await
            .unwrap();
        let syn_ack = wait_for_packet(&device, |packet| {
            tcp_packet(packet).is_some_and(|tcp| tcp.syn() && tcp.ack())
        })
        .await;
        let server_seq = tcp_packet(&syn_ack).unwrap().seq_number();
        device
            .inject(build_tcp_v4(
                source,
                target,
                TestTcpSegment::ack(client_seq + 1, server_seq + 1),
            ))
            .await
            .unwrap();
        device
            .inject(build_tcp_v4(
                source,
                target,
                TestTcpSegment::data(client_seq + 1, server_seq + 1, &payload),
            ))
            .await
            .unwrap();
        device
            .inject(build_tcp_v4(
                source,
                target,
                TestTcpSegment::fin(client_seq + 1 + payload.len(), server_seq + 1),
            ))
            .await
            .unwrap();
        let mut inbound = Vec::new();
        tokio::time::timeout(
            Duration::from_secs(2),
            target_peer.read_to_end(&mut inbound),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(inbound, payload);

        target_peer.write_all(b"pong").await.unwrap();
        let data = wait_for_packet(&device, |packet| {
            tcp_packet(packet).is_some_and(|tcp| tcp.payload() == b"pong")
        })
        .await;
        assert_eq!(tcp_packet(&data).unwrap().payload(), b"pong");
        target_peer.shutdown().await.unwrap();

        shutdown.send(()).unwrap();
        let report = task.await.unwrap().unwrap();
        assert_eq!(report.tcp_flows_opened, 1);
        assert_eq!(report.tcp_flows_reset, 0);
        let seen = seen_context.lock().unwrap();
        let context = seen.as_ref().unwrap();
        assert_eq!(context.source, "10.0.0.2:40000".parse().unwrap());
        assert_eq!(context.target.port, 443);
    }

    #[tokio::test]
    async fn tcp_reset_aborts_the_opened_flow() {
        let device = crate::FakePacketDevice::new(1500, 64);
        let target_slot = Arc::new(Mutex::new(None));
        let target_slot_for_opener = target_slot.clone();
        let (mut target_peer, target_stream) = tokio::io::duplex(1024);
        *target_slot.lock().unwrap() = Some(target_stream);
        let runtime = TunFlowRuntime::new(
            config(),
            Arc::new(crate::FixedTargetDialer::new(move |_| {
                target_slot_for_opener
                    .lock()
                    .unwrap()
                    .take()
                    .ok_or_else(|| crate::FlowBridgeError::Dial("target already used".to_owned()))
            })),
            Arc::new(FakeUdpOpener::default()),
            ProtectedEndpointSet::default(),
        )
        .unwrap();
        let (shutdown, signal) = oneshot::channel();
        let task = tokio::spawn(runtime.run(device.clone(), async move {
            let _ = signal.await;
        }));
        let source = (Ipv4Address::new(10, 0, 0, 2), 40_002);
        let target = (Ipv4Address::new(198, 51, 100, 21), 443);
        let client_seq = TcpSeqNumber(2_000);
        let server_seq = complete_tcp_handshake(&device, source, target, client_seq).await;
        device
            .inject(build_tcp_v4(
                source,
                target,
                TestTcpSegment::data(client_seq + 1, server_seq + 1, b"x"),
            ))
            .await
            .unwrap();
        let mut byte = [0_u8; 1];
        tokio::time::timeout(Duration::from_secs(2), target_peer.read_exact(&mut byte))
            .await
            .unwrap()
            .unwrap();
        device
            .inject(build_tcp_v4(
                source,
                target,
                TestTcpSegment::rst(client_seq + 2, server_seq + 1),
            ))
            .await
            .unwrap();
        let mut eof = Vec::new();
        tokio::time::timeout(Duration::from_secs(2), target_peer.read_to_end(&mut eof))
            .await
            .unwrap()
            .unwrap();
        shutdown.send(()).unwrap();
        let report = task.await.unwrap().unwrap();
        assert_eq!(report.tcp_flows_opened, 1);
        assert!(report.tcp_flows_reset >= 1);
    }

    #[test]
    fn packet_tuple_parses_tcp_udp_and_ipv6() {
        let udp4 = build_udp_v4(
            (Ipv4Address::new(10, 0, 0, 2), 1000),
            (Ipv4Address::new(198, 51, 100, 20), 53),
            &[1],
        );
        assert_eq!(packet_tuple(&udp4).unwrap().protocol, FlowProtocol::Udp);
        let udp6 = build_udp_v6(
            ("fd00::2".parse().unwrap(), 1000),
            ("2001:db8::20".parse().unwrap(), 53),
            &[1],
        );
        assert_eq!(packet_tuple(&udp6).unwrap().target.port(), 53);
        assert!(tcp_flow_timed_out(
            StdInstant::now() - Duration::from_secs(2),
            Duration::from_secs(1)
        ));
    }
}
