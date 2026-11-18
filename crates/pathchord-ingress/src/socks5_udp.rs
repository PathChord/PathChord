//! Supervised SOCKS and mixed HTTP/SOCKS listener runtime.

use std::collections::BTreeMap;
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{Semaphore, mpsc, watch};
use tokio::task::JoinSet;

use crate::socks5::{DOMAIN, IPV4, IPV6, SocksCommand, accept_handshake, send_reply_address};
use crate::{
    AcceptedConnection, BoxedUdpFlowHandle, ConnectionContext, FlowProtocol, HttpConnectListener,
    ListenerDescriptor, ListenerError, ListenerKind, NoopProcessMetadataProvider, ProcessMetadata,
    ProcessMetadataProvider, ProcessSocketTuple, SocksCredentialVerifier, TargetAddress,
    TargetHost, TcpFlowOpener, UdpFlowError, UdpFlowOpener,
};

#[derive(Debug, Clone)]
pub struct Socks5RuntimeConfig {
    pub tcp_enabled: bool,
    pub udp_enabled: bool,
    pub max_clients: usize,
    pub max_targets_per_client: usize,
    pub target_queue: usize,
    pub idle_timeout: Duration,
    pub shutdown_timeout: Duration,
}

impl Socks5RuntimeConfig {
    fn validate(&self) -> Result<(), Socks5RuntimeError> {
        if (!self.tcp_enabled && !self.udp_enabled)
            || self.max_clients == 0
            || self.max_targets_per_client == 0
            || self.target_queue == 0
            || self.shutdown_timeout.is_zero()
        {
            Err(Socks5RuntimeError::InvalidConfig)
        } else {
            Ok(())
        }
    }
}

#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum Socks5RuntimeError {
    #[error("SOCKS5 runtime configuration is invalid")]
    InvalidConfig,
    #[error("SOCKS5 listener failed: {0}")]
    Listener(String),
    #[error("SOCKS5 local policy rejected the client: {0}")]
    Policy(String),
    #[error("SOCKS5 protocol failed: {0}")]
    Protocol(String),
    #[error("SOCKS5 client flow failed: {0}")]
    Flow(String),
    #[error("SOCKS5 task failed: {0}")]
    Task(String),
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Socks5RuntimeReport {
    pub accepted_clients: u64,
    pub tcp_connections: u64,
    pub udp_associations: u64,
    pub udp_datagrams_received: u64,
    pub udp_datagrams_sent: u64,
    pub udp_bytes_received: u64,
    pub udp_bytes_sent: u64,
    pub rejected_requests: u64,
    pub fragmented_datagrams_rejected: u64,
}

pub struct Socks5Runtime {
    listener: TcpListener,
    descriptor: ListenerDescriptor,
    config: Socks5RuntimeConfig,
    tcp_opener: Arc<dyn TcpFlowOpener>,
    udp_opener: Arc<dyn UdpFlowOpener>,
    credential_verifier: Arc<dyn SocksCredentialVerifier>,
    process_metadata: Arc<dyn ProcessMetadataProvider>,
    events: Option<crate::ListenerRuntimeEventSender>,
    connection_admission: Option<Arc<Semaphore>>,
}

impl std::fmt::Debug for Socks5Runtime {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Socks5Runtime")
            .field("descriptor", &self.descriptor)
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl Socks5Runtime {
    pub async fn bind(
        descriptor: ListenerDescriptor,
        config: Socks5RuntimeConfig,
        tcp_opener: Arc<dyn TcpFlowOpener>,
        udp_opener: Arc<dyn UdpFlowOpener>,
        credential_verifier: Arc<dyn SocksCredentialVerifier>,
    ) -> Result<Self, Socks5RuntimeError> {
        config.validate()?;
        if !matches!(descriptor.kind, ListenerKind::Socks5 | ListenerKind::Mixed)
            || (descriptor.kind == ListenerKind::Mixed && !config.tcp_enabled)
        {
            return Err(Socks5RuntimeError::InvalidConfig);
        }
        let listener = TcpListener::bind(
            descriptor
                .required_bind()
                .map_err(|_| Socks5RuntimeError::InvalidConfig)?,
        )
        .await
        .map_err(|error| Socks5RuntimeError::Listener(error.to_string()))?;
        Ok(Self {
            listener,
            descriptor,
            config,
            tcp_opener,
            udp_opener,
            credential_verifier,
            process_metadata: Arc::new(NoopProcessMetadataProvider),
            events: None,
            connection_admission: None,
        })
    }

    pub fn set_event_sender(&mut self, sender: crate::ListenerRuntimeEventSender) {
        self.events = Some(sender);
    }

    pub(crate) fn set_connection_admission(&mut self, admission: Arc<Semaphore>) {
        self.connection_admission = Some(admission);
    }

    pub fn set_process_metadata_provider(&mut self, provider: Arc<dyn ProcessMetadataProvider>) {
        self.process_metadata = provider;
    }

    pub fn local_addr(&self) -> Result<SocketAddr, Socks5RuntimeError> {
        self.listener
            .local_addr()
            .map_err(|error| Socks5RuntimeError::Listener(error.to_string()))
    }

    pub async fn run_until_shutdown<F>(
        self,
        shutdown: F,
    ) -> Result<Socks5RuntimeReport, Socks5RuntimeError>
    where
        F: Future<Output = ()> + Send,
    {
        let permits = Arc::new(Semaphore::new(self.config.max_clients));
        let (cancel, _) = watch::channel(false);
        let mut tasks = JoinSet::new();
        let mut shutdown = Box::pin(shutdown);
        let mut report = Socks5RuntimeReport::default();
        let mut next_connection_id = 0_u64;
        let listener_id = self.descriptor.id.clone();
        loop {
            tokio::select! {
                () = shutdown.as_mut() => break,
                joined = tasks.join_next(), if !tasks.is_empty() => {
                    collect_client(joined, &mut report, &listener_id, &self.events)?;
                }
                permit = Arc::clone(&permits).acquire_owned() => {
                    let permit = permit.map_err(|error| Socks5RuntimeError::Task(error.to_string()))?;
                    let accepted = tokio::select! {
                        () = shutdown.as_mut() => {
                            drop(permit);
                            break;
                        }
                        accepted = self.listener.accept() => accepted,
                    };
                    let (stream, source) = accepted
                        .map_err(|error| Socks5RuntimeError::Listener(error.to_string()))?;
                    let admission = match self.connection_admission.as_ref() {
                        Some(shared) => Some(tokio::select! {
                            () = shutdown.as_mut() => break,
                            result = Arc::clone(shared).acquire_owned() => result
                                .map_err(|error| Socks5RuntimeError::Task(error.to_string()))?,
                        }),
                        None => None,
                    };
                    report.accepted_clients = report.accepted_clients.saturating_add(1);
                    let descriptor = self.descriptor.clone();
                    let config = self.config.clone();
                    let tcp_opener = Arc::clone(&self.tcp_opener);
                    let udp_opener = Arc::clone(&self.udp_opener);
                    let verifier = Arc::clone(&self.credential_verifier);
                    let process_metadata = Arc::clone(&self.process_metadata);
                    let events = self.events.clone();
                    let connection_id = format!("{}-{next_connection_id}", listener_id.as_str());
                    next_connection_id = next_connection_id.saturating_add(1);
                    let receiver = cancel.subscribe();
                    tasks.spawn(async move {
                        let _permit = permit;
                        let _admission = admission;
                        handle_client(
                            stream,
                            source,
                            descriptor,
                            config,
                            tcp_opener,
                            udp_opener,
                            verifier,
                            process_metadata,
                            connection_id,
                            events,
                            receiver,
                        ).await
                    });
                }
            }
        }
        let _ = cancel.send(true);
        let drain = async {
            while let Some(joined) = tasks.join_next().await {
                collect_client(Some(joined), &mut report, &listener_id, &self.events)?;
            }
            Ok::<(), Socks5RuntimeError>(())
        };
        if tokio::time::timeout(self.config.shutdown_timeout, drain)
            .await
            .is_err()
        {
            tasks.abort_all();
            while tasks.join_next().await.is_some() {}
        }
        Ok(report)
    }
}

fn collect_client(
    joined: Option<Result<Result<Socks5RuntimeReport, Socks5RuntimeError>, tokio::task::JoinError>>,
    report: &mut Socks5RuntimeReport,
    listener_id: &crate::ListenerId,
    events: &Option<crate::ListenerRuntimeEventSender>,
) -> Result<(), Socks5RuntimeError> {
    match joined {
        Some(Ok(Ok(client))) => {
            report.tcp_connections = report
                .tcp_connections
                .saturating_add(client.tcp_connections);
            report.udp_associations = report
                .udp_associations
                .saturating_add(client.udp_associations);
            report.udp_datagrams_received = report
                .udp_datagrams_received
                .saturating_add(client.udp_datagrams_received);
            report.udp_datagrams_sent = report
                .udp_datagrams_sent
                .saturating_add(client.udp_datagrams_sent);
            report.udp_bytes_received = report
                .udp_bytes_received
                .saturating_add(client.udp_bytes_received);
            report.udp_bytes_sent = report.udp_bytes_sent.saturating_add(client.udp_bytes_sent);
            report.rejected_requests = report
                .rejected_requests
                .saturating_add(client.rejected_requests);
            report.fragmented_datagrams_rejected = report
                .fragmented_datagrams_rejected
                .saturating_add(client.fragmented_datagrams_rejected);
        }
        Some(Ok(Err(error))) => {
            report.rejected_requests = report.rejected_requests.saturating_add(1);
            match error {
                Socks5RuntimeError::Policy(reason) => emit(
                    events,
                    crate::ListenerRuntimeEvent::PolicyRejected {
                        listener_id: listener_id.clone(),
                        reason,
                    },
                ),
                Socks5RuntimeError::Protocol(reason) => emit(
                    events,
                    crate::ListenerRuntimeEvent::ProtocolRejected {
                        listener_id: listener_id.clone(),
                        reason,
                    },
                ),
                _ => {}
            }
        }
        Some(Err(error)) => return Err(Socks5RuntimeError::Task(error.to_string())),
        None => {}
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn handle_client(
    mut stream: TcpStream,
    source: SocketAddr,
    descriptor: ListenerDescriptor,
    config: Socks5RuntimeConfig,
    tcp_opener: Arc<dyn TcpFlowOpener>,
    udp_opener: Arc<dyn UdpFlowOpener>,
    credential_verifier: Arc<dyn SocksCredentialVerifier>,
    process_metadata: Arc<dyn ProcessMetadataProvider>,
    connection_id: String,
    events: Option<crate::ListenerRuntimeEventSender>,
    cancel: watch::Receiver<bool>,
) -> Result<Socks5RuntimeReport, Socks5RuntimeError> {
    if !descriptor.allows_source(source.ip()) {
        return Err(Socks5RuntimeError::Policy(
            "source address is not allowed".to_owned(),
        ));
    }
    let detected = if descriptor.kind == ListenerKind::Mixed {
        let Some(detected) = until_cancelled(&cancel, crate::mixed::detect_protocol(&stream)).await
        else {
            return Ok(Socks5RuntimeReport::default());
        };
        Some(detected.map_err(listener_error)?)
    } else {
        None
    };
    if detected == Some(crate::mixed::ProxyProtocol::Http) {
        let local = stream
            .local_addr()
            .map_err(|error| Socks5RuntimeError::Protocol(error.to_string()))?;
        let mut http_descriptor = descriptor;
        http_descriptor.kind = ListenerKind::Http;
        let accepted = until_cancelled(
            &cancel,
            HttpConnectListener::accept_stream_with_verifier(
                &http_descriptor,
                stream,
                source,
                credential_verifier,
            ),
        )
        .await;
        let Some(accepted) = accepted else {
            return Ok(Socks5RuntimeReport::default());
        };
        let mut accepted = accepted.map_err(listener_error)?;
        if !http_descriptor.process_metadata.is_empty() {
            accepted.context.process = process_metadata
                .lookup(
                    ProcessSocketTuple { source, local },
                    http_descriptor.process_metadata,
                )
                .await;
        }
        return bridge_tcp_client(
            accepted,
            tcp_opener.as_ref(),
            connection_id,
            &events,
            &cancel,
        )
        .await;
    }
    let handshake = until_cancelled(
        &cancel,
        accept_handshake(
            &mut stream,
            descriptor.authentication_required,
            credential_verifier.as_ref(),
        ),
    )
    .await;
    let Some(handshake) = handshake else {
        return Ok(Socks5RuntimeReport::default());
    };
    let handshake = match handshake {
        Ok(handshake) => handshake,
        Err(error) => {
            crate::listener_rejection::finish(&mut stream).await;
            return Err(listener_error(error));
        }
    };
    let identity = handshake.authentication_identity;
    let request = handshake.request;
    let process = if descriptor.process_metadata.is_empty() {
        None
    } else {
        let local = stream
            .local_addr()
            .map_err(|error| Socks5RuntimeError::Protocol(error.to_string()))?;
        process_metadata
            .lookup(
                ProcessSocketTuple { source, local },
                descriptor.process_metadata,
            )
            .await
    };
    match request.command {
        SocksCommand::Connect if config.tcp_enabled => {
            let accepted = AcceptedConnection {
                io: Box::new(stream),
                context: ConnectionContext {
                    flow_tags: descriptor.flow_tags,
                    listener_id: descriptor.id.clone(),
                    source,
                    authentication_identity: identity,
                    process,
                    protocol: FlowProtocol::Tcp,
                    target: request.target,
                },
                response: handshake.version.connection_response(),
            };
            bridge_tcp_client(
                accepted,
                tcp_opener.as_ref(),
                connection_id,
                &events,
                &cancel,
            )
            .await
        }
        SocksCommand::UdpAssociate if config.udp_enabled => {
            let requested_source = associate_source(&request.target, source)?;
            emit_connection_accepted(&events, &descriptor.id, &connection_id, &request.target);
            match run_udp_association(
                stream,
                source,
                descriptor.id.clone(),
                descriptor.flow_tags,
                identity,
                process,
                requested_source,
                config,
                udp_opener,
                cancel,
            )
            .await
            {
                Ok(report) => {
                    emit(
                        &events,
                        crate::ListenerRuntimeEvent::ConnectionCompleted {
                            listener_id: descriptor.id,
                            connection_id,
                            stats: crate::FlowBridgeStats {
                                local_to_target_bytes: report.udp_bytes_received,
                                target_to_local_bytes: report.udp_bytes_sent,
                            },
                        },
                    );
                    Ok(report)
                }
                Err(error) => {
                    emit_connection_failed(&events, descriptor.id, connection_id, &error);
                    Err(Socks5RuntimeError::Flow(error.to_string()))
                }
            }
        }
        _ => {
            handshake
                .version
                .reject_command(&mut stream)
                .await
                .map_err(listener_error)?;
            crate::listener_rejection::finish(&mut stream).await;
            Err(Socks5RuntimeError::Protocol(
                "SOCKS command is disabled".to_owned(),
            ))
        }
    }
}

async fn bridge_tcp_client(
    accepted: AcceptedConnection,
    tcp_opener: &dyn TcpFlowOpener,
    connection_id: String,
    events: &Option<crate::ListenerRuntimeEventSender>,
    cancel: &watch::Receiver<bool>,
) -> Result<Socks5RuntimeReport, Socks5RuntimeError> {
    let listener_id = accepted.context.listener_id.clone();
    emit_connection_accepted(
        events,
        &listener_id,
        &connection_id,
        &accepted.context.target,
    );
    let result = until_cancelled(cancel, crate::bridge_connection(accepted, tcp_opener)).await;
    let Some(result) = result else {
        emit_connection_failed(
            events,
            listener_id,
            connection_id,
            &crate::FlowBridgeError::ShuttingDown,
        );
        return Ok(Socks5RuntimeReport::default());
    };
    match result {
        Ok(stats) => {
            emit(
                events,
                crate::ListenerRuntimeEvent::ConnectionCompleted {
                    listener_id,
                    connection_id,
                    stats,
                },
            );
            Ok(Socks5RuntimeReport {
                tcp_connections: 1,
                ..Socks5RuntimeReport::default()
            })
        }
        Err(error) => {
            emit_connection_failed(events, listener_id, connection_id, &error);
            Err(Socks5RuntimeError::Flow(error.to_string()))
        }
    }
}

async fn until_cancelled<T>(
    cancel: &watch::Receiver<bool>,
    work: impl Future<Output = T>,
) -> Option<T> {
    let mut cancel = cancel.clone();
    let shutdown = async move {
        if *cancel.borrow() {
            return;
        }
        loop {
            if cancel.changed().await.is_err() || *cancel.borrow() {
                return;
            }
        }
    };
    tokio::select! { value = work => Some(value), () = shutdown => None }
}

fn emit(events: &Option<crate::ListenerRuntimeEventSender>, event: crate::ListenerRuntimeEvent) {
    if let Some(events) = events {
        let _ = events.send(event);
    }
}

fn emit_connection_accepted(
    events: &Option<crate::ListenerRuntimeEventSender>,
    listener_id: &crate::ListenerId,
    connection_id: &str,
    target: &TargetAddress,
) {
    emit(
        events,
        crate::ListenerRuntimeEvent::ConnectionAccepted {
            listener_id: listener_id.clone(),
            connection_id: connection_id.to_owned(),
            target_display: display_target(target),
        },
    );
}

fn emit_connection_failed(
    events: &Option<crate::ListenerRuntimeEventSender>,
    listener_id: crate::ListenerId,
    connection_id: String,
    error: &impl std::fmt::Display,
) {
    emit(
        events,
        crate::ListenerRuntimeEvent::ConnectionFailed {
            listener_id,
            connection_id: Some(connection_id),
            error: error.to_string(),
        },
    );
}

fn display_target(target: &TargetAddress) -> String {
    match &target.host {
        TargetHost::Hostname(host) => format!("{host}:{}", target.port),
        TargetHost::Ip(IpAddr::V4(address)) => format!("{address}:{}", target.port),
        TargetHost::Ip(IpAddr::V6(address)) => format!("[{address}]:{}", target.port),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TargetKey(TargetAddress);

impl PartialOrd for TargetKey {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for TargetKey {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        target_sort_key(&self.0).cmp(&target_sort_key(&other.0))
    }
}

fn target_sort_key(target: &TargetAddress) -> (u8, String, u16) {
    match &target.host {
        TargetHost::Ip(address) => (0, address.to_string(), target.port),
        TargetHost::Hostname(host) => (1, host.clone(), target.port),
    }
}

struct TargetResponse {
    target: TargetAddress,
    payload: Vec<u8>,
}

#[allow(clippy::too_many_arguments)]
async fn run_udp_association(
    mut control: TcpStream,
    control_peer: SocketAddr,
    listener_id: crate::ListenerId,
    flow_tags: std::collections::BTreeSet<String>,
    identity: Option<String>,
    process: Option<ProcessMetadata>,
    requested_source: Option<SocketAddr>,
    config: Socks5RuntimeConfig,
    opener: Arc<dyn UdpFlowOpener>,
    mut cancel: watch::Receiver<bool>,
) -> Result<Socks5RuntimeReport, Socks5RuntimeError> {
    let local_ip = control
        .local_addr()
        .map_err(|error| Socks5RuntimeError::Listener(error.to_string()))?
        .ip();
    let bind = SocketAddr::new(local_ip, 0);
    let relay = UdpSocket::bind(bind)
        .await
        .map_err(|error| Socks5RuntimeError::Listener(error.to_string()))?;
    let relay_address = relay
        .local_addr()
        .map_err(|error| Socks5RuntimeError::Listener(error.to_string()))?;
    send_reply_address(&mut control, 0, relay_address)
        .await
        .map_err(listener_error)?;

    let mut pinned_source = requested_source;
    let (responses_tx, mut responses) = mpsc::channel(config.target_queue);
    let mut targets = BTreeMap::<TargetKey, mpsc::Sender<Vec<u8>>>::new();
    let mut tasks = JoinSet::new();
    let mut buffer = vec![0_u8; u16::MAX as usize];
    let mut control_byte = [0_u8; 1];
    let mut report = Socks5RuntimeReport {
        udp_associations: 1,
        ..Socks5RuntimeReport::default()
    };

    loop {
        let idle = tokio::time::sleep(config.idle_timeout);
        tokio::pin!(idle);
        tokio::select! {
            () = wait_for_cancel(&mut cancel) => break,
            () = &mut idle => break,
            read = control.read(&mut control_byte) => {
                match read {
                    Ok(0) => break,
                    Ok(_) => {}
                    Err(error) => return Err(Socks5RuntimeError::Protocol(error.to_string())),
                }
            }
            received = relay.recv_from(&mut buffer) => {
                let (length, source) = received
                    .map_err(|error| Socks5RuntimeError::Protocol(error.to_string()))?;
                if source.ip() != control_peer.ip()
                    || pinned_source.is_some_and(|expected| source != expected)
                {
                    report.rejected_requests = report.rejected_requests.saturating_add(1);
                    continue;
                }
                if pinned_source.is_none() {
                    pinned_source = Some(source);
                }
                let datagram = match decode_udp_datagram(&buffer[..length]) {
                    Ok(datagram) => datagram,
                    Err(SocksUdpHeaderError::Fragmented) => {
                        report.fragmented_datagrams_rejected =
                            report.fragmented_datagrams_rejected.saturating_add(1);
                        continue;
                    }
                    Err(_) => {
                        report.rejected_requests = report.rejected_requests.saturating_add(1);
                        continue;
                    }
                };
                report.udp_datagrams_received = report.udp_datagrams_received.saturating_add(1);
                report.udp_bytes_received = report
                    .udp_bytes_received
                    .saturating_add(u64::try_from(datagram.payload.len()).unwrap_or(u64::MAX));
                let key = TargetKey(datagram.target.clone());
                if let Some(sender) = targets.get(&key) {
                    if sender.try_send(datagram.payload).is_err() {
                        report.rejected_requests = report.rejected_requests.saturating_add(1);
                    }
                    continue;
                }
                if targets.len() >= config.max_targets_per_client {
                    report.rejected_requests = report.rejected_requests.saturating_add(1);
                    continue;
                }
                let context = ConnectionContext {
                    flow_tags: flow_tags.clone(),
                    listener_id: listener_id.clone(),
                    source,
                    authentication_identity: identity.clone(),
                    process: process.clone(),
                    protocol: FlowProtocol::Udp,
                    target: datagram.target.clone(),
                };
                let handle = match opener.open_udp(&context).await {
                    Ok(handle) => handle,
                    Err(_) => {
                        report.rejected_requests = report.rejected_requests.saturating_add(1);
                        continue;
                    }
                };
                let (requests_tx, requests_rx) = mpsc::channel(config.target_queue);
                requests_tx.try_send(datagram.payload).map_err(|_| {
                    Socks5RuntimeError::Task("new SOCKS UDP target queue closed".to_owned())
                })?;
                targets.insert(key.clone(), requests_tx);
                let responses = responses_tx.clone();
                let timeout = config.idle_timeout;
                let task_key = key.clone();
                tasks.spawn(async move {
                    let result = run_target(key, handle, requests_rx, responses, timeout).await;
                    (task_key, result)
                });
            }
            response = responses.recv() => {
                let Some(response) = response else { break; };
                let Some(destination) = pinned_source else { continue; };
                let encoded = encode_udp_datagram(&response.target, &response.payload)?;
                relay.send_to(&encoded, destination).await
                    .map_err(|error| Socks5RuntimeError::Protocol(error.to_string()))?;
                report.udp_datagrams_sent = report.udp_datagrams_sent.saturating_add(1);
                report.udp_bytes_sent = report
                    .udp_bytes_sent
                    .saturating_add(u64::try_from(response.payload.len()).unwrap_or(u64::MAX));
            }
            joined = tasks.join_next(), if !tasks.is_empty() => {
                match joined {
                    Some(Ok((key, Ok(())))) => { targets.remove(&key); }
                    Some(Ok((key, Err(_)))) => {
                        targets.remove(&key);
                        report.rejected_requests = report.rejected_requests.saturating_add(1);
                    }
                    Some(Err(error)) => return Err(Socks5RuntimeError::Task(error.to_string())),
                    None => {}
                }
            }
        }
    }
    targets.clear();
    let graceful = async { while tasks.join_next().await.is_some() {} };
    if tokio::time::timeout(config.shutdown_timeout, graceful)
        .await
        .is_err()
    {
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
    }
    Ok(report)
}

async fn run_target(
    key: TargetKey,
    mut handle: BoxedUdpFlowHandle,
    mut requests: mpsc::Receiver<Vec<u8>>,
    responses: mpsc::Sender<TargetResponse>,
    idle_timeout: Duration,
) -> Result<(), UdpFlowError> {
    loop {
        let idle = tokio::time::sleep(idle_timeout);
        tokio::pin!(idle);
        tokio::select! {
            () = &mut idle => {
                handle.close().await?;
                return Ok(());
            }
            request = requests.recv() => {
                let Some(request) = request else {
                    handle.close().await?;
                    return Ok(());
                };
                handle.send(request).await?;
            }
            response = handle.receive() => {
                let Some(payload) = response else { return Ok(()); };
                responses.send(TargetResponse {
                    target: key.0.clone(),
                    payload,
                }).await.map_err(|_| UdpFlowError::Task("SOCKS response queue closed".to_owned()))?;
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SocksUdpDatagram {
    target: TargetAddress,
    payload: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SocksUdpHeaderError {
    Malformed,
    Fragmented,
}

fn decode_udp_datagram(input: &[u8]) -> Result<SocksUdpDatagram, SocksUdpHeaderError> {
    if input.len() < 4 || input[0] != 0 || input[1] != 0 {
        return Err(SocksUdpHeaderError::Malformed);
    }
    if input[2] != 0 {
        return Err(SocksUdpHeaderError::Fragmented);
    }
    let (host, offset) = match input[3] {
        IPV4 if input.len() >= 10 => (
            TargetHost::Ip(IpAddr::V4(Ipv4Addr::new(
                input[4], input[5], input[6], input[7],
            ))),
            8,
        ),
        IPV6 if input.len() >= 22 => {
            let bytes: [u8; 16] = input[4..20]
                .try_into()
                .map_err(|_| SocksUdpHeaderError::Malformed)?;
            (TargetHost::Ip(IpAddr::V6(Ipv6Addr::from(bytes))), 20)
        }
        DOMAIN if input.len() >= 7 => {
            let length = usize::from(input[4]);
            let end = 5_usize
                .checked_add(length)
                .ok_or(SocksUdpHeaderError::Malformed)?;
            if length == 0
                || end
                    .checked_add(2)
                    .is_none_or(|minimum| input.len() < minimum)
            {
                return Err(SocksUdpHeaderError::Malformed);
            }
            let domain = std::str::from_utf8(&input[5..end])
                .map_err(|_| SocksUdpHeaderError::Malformed)?
                .to_owned();
            (TargetHost::Hostname(domain), end)
        }
        _ => return Err(SocksUdpHeaderError::Malformed),
    };
    let port = u16::from_be_bytes([input[offset], input[offset + 1]]);
    if port == 0 {
        return Err(SocksUdpHeaderError::Malformed);
    }
    Ok(SocksUdpDatagram {
        target: TargetAddress { host, port },
        payload: input[offset + 2..].to_vec(),
    })
}

fn encode_udp_datagram(
    target: &TargetAddress,
    payload: &[u8],
) -> Result<Vec<u8>, Socks5RuntimeError> {
    let mut output = vec![0, 0, 0];
    match &target.host {
        TargetHost::Ip(IpAddr::V4(address)) => {
            output.push(IPV4);
            output.extend_from_slice(&address.octets());
        }
        TargetHost::Ip(IpAddr::V6(address)) => {
            output.push(IPV6);
            output.extend_from_slice(&address.octets());
        }
        TargetHost::Hostname(host) => {
            let length = u8::try_from(host.len())
                .map_err(|_| Socks5RuntimeError::Protocol("SOCKS domain is too long".to_owned()))?;
            if length == 0 {
                return Err(Socks5RuntimeError::Protocol(
                    "SOCKS domain is empty".to_owned(),
                ));
            }
            output.push(DOMAIN);
            output.push(length);
            output.extend_from_slice(host.as_bytes());
        }
    }
    output.extend_from_slice(&target.port.to_be_bytes());
    output.extend_from_slice(payload);
    Ok(output)
}

fn associate_source(
    target: &TargetAddress,
    control_peer: SocketAddr,
) -> Result<Option<SocketAddr>, Socks5RuntimeError> {
    match &target.host {
        TargetHost::Ip(address) if address.is_unspecified() && target.port == 0 => Ok(None),
        TargetHost::Ip(address) if address.is_unspecified() => {
            Ok(Some(SocketAddr::new(control_peer.ip(), target.port)))
        }
        TargetHost::Ip(address) if *address == control_peer.ip() && target.port != 0 => {
            Ok(Some(SocketAddr::new(*address, target.port)))
        }
        _ => Err(Socks5RuntimeError::Protocol(
            "UDP ASSOCIATE source does not match control client".to_owned(),
        )),
    }
}

async fn wait_for_cancel(receiver: &mut watch::Receiver<bool>) {
    if *receiver.borrow() {
        return;
    }
    while receiver.changed().await.is_ok() {
        if *receiver.borrow() {
            return;
        }
    }
}

fn listener_error(error: ListenerError) -> Socks5RuntimeError {
    match error {
        ListenerError::Policy(reason) => Socks5RuntimeError::Policy(reason),
        ListenerError::Protocol(reason) => Socks5RuntimeError::Protocol(reason),
        error => Socks5RuntimeError::Protocol(error.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::socks5::UDP_ASSOCIATE;
    use async_trait::async_trait;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::sync::oneshot;

    #[derive(Debug)]
    struct DirectUdpOpener;

    #[derive(Debug)]
    struct DirectUdpHandle {
        socket: UdpSocket,
    }

    #[async_trait]
    impl crate::UdpFlowHandle for DirectUdpHandle {
        async fn send(&mut self, payload: Vec<u8>) -> Result<(), UdpFlowError> {
            self.socket
                .send(&payload)
                .await
                .map(|_| ())
                .map_err(|error| UdpFlowError::Task(error.to_string()))
        }

        async fn receive(&mut self) -> Option<Vec<u8>> {
            let mut payload = vec![0_u8; 65_535];
            let length = self.socket.recv(&mut payload).await.ok()?;
            payload.truncate(length);
            Some(payload)
        }

        async fn close(self: Box<Self>) -> Result<(), UdpFlowError> {
            Ok(())
        }
    }

    #[async_trait]
    impl UdpFlowOpener for DirectUdpOpener {
        async fn open_udp(
            &self,
            context: &ConnectionContext,
        ) -> Result<BoxedUdpFlowHandle, UdpFlowError> {
            let TargetHost::Ip(address) = context.target.host else {
                return Err(UdpFlowError::Open("test target must be an IP".to_owned()));
            };
            let bind = if address.is_ipv4() {
                "0.0.0.0:0"
            } else {
                "[::]:0"
            };
            let socket = UdpSocket::bind(bind)
                .await
                .map_err(|error| UdpFlowError::Open(error.to_string()))?;
            socket
                .connect(SocketAddr::new(address, context.target.port))
                .await
                .map_err(|error| UdpFlowError::Open(error.to_string()))?;
            Ok(Box::new(DirectUdpHandle { socket }))
        }
    }

    #[derive(Debug, Default)]
    struct RetryUdpOpener {
        calls: AtomicUsize,
    }

    #[derive(Debug)]
    struct RetryUdpHandle {
        fail_send: bool,
        responses_tx: mpsc::Sender<Vec<u8>>,
        responses: mpsc::Receiver<Vec<u8>>,
    }

    #[async_trait]
    impl crate::UdpFlowHandle for RetryUdpHandle {
        async fn send(&mut self, payload: Vec<u8>) -> Result<(), UdpFlowError> {
            if self.fail_send {
                return Err(UdpFlowError::Task("injected target failure".to_owned()));
            }
            self.responses_tx
                .send(payload)
                .await
                .map_err(|_| UdpFlowError::Task("test response queue closed".to_owned()))
        }

        async fn receive(&mut self) -> Option<Vec<u8>> {
            self.responses.recv().await
        }

        async fn close(self: Box<Self>) -> Result<(), UdpFlowError> {
            Ok(())
        }
    }

    #[async_trait]
    impl UdpFlowOpener for RetryUdpOpener {
        async fn open_udp(
            &self,
            _context: &ConnectionContext,
        ) -> Result<BoxedUdpFlowHandle, UdpFlowError> {
            let call = self.calls.fetch_add(1, Ordering::SeqCst);
            let (responses_tx, responses) = mpsc::channel(1);
            Ok(Box::new(RetryUdpHandle {
                fail_send: call == 0,
                responses_tx,
                responses,
            }))
        }
    }

    fn descriptor() -> ListenerDescriptor {
        ListenerDescriptor {
            id: crate::ListenerId::new("socks"),
            kind: ListenerKind::Socks5,
            bind: Some("127.0.0.1:0".parse().unwrap()),
            interface: None,
            address: None,
            mtu: None,
            flow_tags: std::collections::BTreeSet::new(),
            process_metadata: crate::ProcessMetadataRequest::default(),
            allowed_sources: Vec::new(),
            authentication_required: false,
        }
    }

    async fn read_reply(stream: &mut TcpStream) -> SocketAddr {
        let mut header = [0_u8; 4];
        stream.read_exact(&mut header).await.unwrap();
        assert_eq!(header[..3], [5, 0, 0]);
        match header[3] {
            IPV4 => {
                let mut body = [0_u8; 6];
                stream.read_exact(&mut body).await.unwrap();
                SocketAddr::new(
                    IpAddr::V4(Ipv4Addr::new(body[0], body[1], body[2], body[3])),
                    u16::from_be_bytes([body[4], body[5]]),
                )
            }
            IPV6 => {
                let mut body = [0_u8; 18];
                stream.read_exact(&mut body).await.unwrap();
                let address: [u8; 16] = body[..16].try_into().unwrap();
                SocketAddr::new(
                    IpAddr::V6(Ipv6Addr::from(address)),
                    u16::from_be_bytes([body[16], body[17]]),
                )
            }
            other => panic!("unexpected address type {other}"),
        }
    }

    #[tokio::test]
    async fn loopback_udp_associate_reaches_a_real_target() {
        let target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let target_address = target.local_addr().unwrap();
        let echo = tokio::spawn(async move {
            let mut payload = [0_u8; 32];
            let (length, peer) = target.recv_from(&mut payload).await.unwrap();
            target.send_to(&payload[..length], peer).await.unwrap();
        });

        let runtime = Socks5Runtime::bind(
            descriptor(),
            Socks5RuntimeConfig {
                tcp_enabled: true,
                udp_enabled: true,
                max_clients: 8,
                max_targets_per_client: 4,
                target_queue: 4,
                idle_timeout: Duration::from_secs(30),
                shutdown_timeout: Duration::from_secs(1),
            },
            Arc::new(crate::FixedTargetDialer::new(|_| {
                Err::<tokio::io::DuplexStream, _>(crate::FlowBridgeError::Dial("unused".to_owned()))
            })),
            Arc::new(DirectUdpOpener),
            Arc::new(crate::RejectSocksCredentials),
        )
        .await
        .unwrap();
        let control_address = runtime.local_addr().unwrap();
        let (shutdown, signal) = oneshot::channel();
        let task = tokio::spawn(runtime.run_until_shutdown(async move {
            let _ = signal.await;
        }));

        let mut control = TcpStream::connect(control_address).await.unwrap();
        control.write_all(&[5, 1, 0]).await.unwrap();
        let mut method = [0_u8; 2];
        control.read_exact(&mut method).await.unwrap();
        assert_eq!(method, [5, 0]);
        control
            .write_all(&[5, UDP_ASSOCIATE, 0, IPV4, 0, 0, 0, 0, 0, 0])
            .await
            .unwrap();
        let relay = read_reply(&mut control).await;
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let request = encode_udp_datagram(
            &TargetAddress {
                host: TargetHost::Ip(target_address.ip()),
                port: target_address.port(),
            },
            b"socks-udp",
        )
        .unwrap();
        client.send_to(&request, relay).await.unwrap();
        let mut response = vec![0_u8; 128];
        let (length, _) =
            tokio::time::timeout(Duration::from_secs(2), client.recv_from(&mut response))
                .await
                .unwrap()
                .unwrap();
        let response = decode_udp_datagram(&response[..length]).unwrap();
        assert_eq!(response.payload, b"socks-udp");
        assert_eq!(response.target.port, target_address.port());

        let mut fragmented = request.clone();
        fragmented[2] = 1;
        client.send_to(&fragmented, relay).await.unwrap();
        drop(control);
        shutdown.send(()).unwrap();
        let report = task.await.unwrap().unwrap();
        assert_eq!(report.udp_associations, 1);
        assert_eq!(report.udp_datagrams_received, 1);
        assert_eq!(report.udp_datagrams_sent, 1);
        echo.await.unwrap();
    }

    #[tokio::test]
    async fn failed_target_handle_can_reopen_the_same_target() {
        let opener = Arc::new(RetryUdpOpener::default());
        let runtime = Socks5Runtime::bind(
            descriptor(),
            Socks5RuntimeConfig {
                tcp_enabled: false,
                udp_enabled: true,
                max_clients: 2,
                max_targets_per_client: 2,
                target_queue: 2,
                idle_timeout: Duration::from_secs(30),
                shutdown_timeout: Duration::from_secs(1),
            },
            Arc::new(crate::FixedTargetDialer::new(|_| {
                Err::<tokio::io::DuplexStream, _>(crate::FlowBridgeError::Dial("unused".to_owned()))
            })),
            opener.clone(),
            Arc::new(crate::RejectSocksCredentials),
        )
        .await
        .unwrap();
        let control_address = runtime.local_addr().unwrap();
        let (shutdown, signal) = oneshot::channel();
        let task = tokio::spawn(runtime.run_until_shutdown(async move {
            let _ = signal.await;
        }));

        let mut control = TcpStream::connect(control_address).await.unwrap();
        control.write_all(&[5, 1, 0]).await.unwrap();
        let mut method = [0_u8; 2];
        control.read_exact(&mut method).await.unwrap();
        assert_eq!(method, [5, 0]);
        control
            .write_all(&[5, UDP_ASSOCIATE, 0, IPV4, 0, 0, 0, 0, 0, 0])
            .await
            .unwrap();
        let relay = read_reply(&mut control).await;
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let request = encode_udp_datagram(
            &TargetAddress {
                host: TargetHost::Ip("192.0.2.1".parse().unwrap()),
                port: 5353,
            },
            b"retry-target",
        )
        .unwrap();

        let response = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                client.send_to(&request, relay).await.unwrap();
                let mut response = vec![0_u8; 128];
                if let Ok(Ok((length, _))) =
                    tokio::time::timeout(Duration::from_millis(20), client.recv_from(&mut response))
                        .await
                {
                    break decode_udp_datagram(&response[..length]).unwrap();
                }
            }
        })
        .await
        .expect("the failed target must be removed and reopened");
        assert_eq!(response.payload, b"retry-target");
        assert!(opener.calls.load(Ordering::SeqCst) >= 2);

        drop(control);
        shutdown.send(()).unwrap();
        let report = task.await.unwrap().unwrap();
        assert!(report.rejected_requests >= 1);
    }

    #[tokio::test]
    async fn idle_runtime_shutdown_completes_without_abort_or_hang() {
        let runtime = Socks5Runtime::bind(
            descriptor(),
            Socks5RuntimeConfig {
                tcp_enabled: true,
                udp_enabled: true,
                max_clients: 2,
                max_targets_per_client: 2,
                target_queue: 2,
                idle_timeout: Duration::from_secs(30),
                shutdown_timeout: Duration::from_secs(1),
            },
            Arc::new(crate::FixedTargetDialer::new(|_| {
                Err::<tokio::io::DuplexStream, _>(crate::FlowBridgeError::Dial("unused".to_owned()))
            })),
            Arc::new(DirectUdpOpener),
            Arc::new(crate::RejectSocksCredentials),
        )
        .await
        .unwrap();
        let (shutdown, signal) = oneshot::channel();
        let task = tokio::spawn(runtime.run_until_shutdown(async move {
            let _ = signal.await;
        }));
        shutdown.send(()).unwrap();

        let report = tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .expect("idle runtime shutdown timed out")
            .unwrap()
            .unwrap();
        assert_eq!(report, Socks5RuntimeReport::default());
    }

    #[test]
    fn udp_header_round_trips_domain_ipv4_ipv6_and_rejects_fragments() {
        for target in [
            TargetAddress {
                host: TargetHost::Hostname("example.test".to_owned()),
                port: 53,
            },
            TargetAddress {
                host: TargetHost::Ip("192.0.2.1".parse().unwrap()),
                port: 443,
            },
            TargetAddress {
                host: TargetHost::Ip("2001:db8::1".parse().unwrap()),
                port: 5353,
            },
        ] {
            let encoded = encode_udp_datagram(&target, b"payload").unwrap();
            let decoded = decode_udp_datagram(&encoded).unwrap();
            assert_eq!(decoded.target, target);
            assert_eq!(decoded.payload, b"payload");
        }
        let mut fragmented = encode_udp_datagram(
            &TargetAddress {
                host: TargetHost::Ip("192.0.2.1".parse().unwrap()),
                port: 53,
            },
            b"x",
        )
        .unwrap();
        fragmented[2] = 1;
        assert_eq!(
            decode_udp_datagram(&fragmented),
            Err(SocksUdpHeaderError::Fragmented)
        );
    }

    #[tokio::test]
    async fn verifier_rejects_non_matching_userpass() {
        #[derive(Debug)]
        struct Deny;
        #[async_trait]
        impl SocksCredentialVerifier for Deny {
            async fn verify(&self, _username: &str, _password: &[u8]) -> bool {
                false
            }
        }

        let (mut client, mut server) = tokio::io::duplex(128);
        let task = tokio::spawn(async move { accept_handshake(&mut server, true, &Deny).await });
        client.write_all(&[5, 1, 2]).await.unwrap();
        let mut method = [0_u8; 2];
        client.read_exact(&mut method).await.unwrap();
        assert_eq!(method, [5, 2]);
        client
            .write_all(&[1, 5, b'a', b'l', b'i', b'c', b'e', 3, b'b', b'a', b'd'])
            .await
            .unwrap();
        let mut auth = [0_u8; 2];
        client.read_exact(&mut auth).await.unwrap();
        assert_eq!(auth, [1, 1]);
        assert!(task.await.unwrap().is_err());
    }
}
