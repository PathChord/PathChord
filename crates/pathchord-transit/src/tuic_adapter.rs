//! Narrow native TUIC v5 TCP adapter over Quinn.
//!
//! This owns TUIC TLS-exporter authentication, TCP CONNECT, UDP relaying and
//! heartbeats. No external proxy process is involved.

use std::collections::{BTreeMap, VecDeque};
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use async_trait::async_trait;
use futures_util::{StreamExt, stream::FuturesUnordered};
use quinn::crypto::rustls::QuicClientConfig;
use quinn::{ClientConfig, Endpoint, RecvStream, SendStream, TransportConfig};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::time::timeout;

use crate::tuic_codec::{
    TuicAddress, TuicCredentials, TuicEndpoint, TuicPacket, decode_packet,
    encode_authenticate_token, encode_connect, encode_dissociate, encode_packet,
};
use crate::{
    AdapterKind, BoxedTransitConnection, BoxedTransitDatagram, ConnectRequest,
    Endpoint as TransitEndpoint, TransitAdapter, TransitCredential, TransitDatagram, TransitError,
    TransitMetadata,
};

pub(crate) struct TuicAdapter {
    metadata: TransitMetadata,
    endpoint: TransitEndpoint,
    credentials: TuicCredentials,
    tls: Arc<rustls::ClientConfig>,
    server_name: String,
    udp_enabled: bool,
    udp_relay: UdpRelay,
    udp_over_stream: bool,
    congestion: Congestion,
    heartbeat: Duration,
    timeout: Duration,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum UdpRelay {
    Native,
    Quic,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Congestion {
    Cubic,
    NewReno,
    Bbr,
}

impl std::fmt::Debug for TuicAdapter {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TuicAdapter")
            .field("metadata", &self.metadata)
            .finish_non_exhaustive()
    }
}

impl TuicAdapter {
    pub fn from_config(
        config: &pathchord_policy::TransitProxyConfig,
        credential: &TransitCredential,
        timeout: Duration,
        base_tls: Arc<rustls::ClientConfig>,
    ) -> Result<Self, TransitError> {
        if config.protocol != "tuic" {
            return Err(unsupported("TUIC adapter requires protocol tuic"));
        }
        crate::adapter_registry::validate_native_options(config, true, false, true)?;
        let mut allowed = vec![
            "uuid",
            "password",
            "congestion_control",
            "udp_relay_mode",
            "heartbeat",
            "zero_rtt_handshake",
            "udp_over_stream",
        ];
        if let Some(field) = config
            .options
            .tls
            .as_ref()
            .and_then(|tls| tls.client_key_field.as_deref())
        {
            allowed.push(field);
        }
        crate::adapter_registry::validate_credentials(Some(credential), &allowed)?;
        let uuid = credential
            .field("uuid")
            .ok_or_else(|| unsupported("TUIC UUID is missing"))?;
        let password = credential
            .field("password")
            .ok_or_else(|| unsupported("TUIC password is missing"))?;
        let credentials = TuicCredentials::parse(uuid, password)
            .map_err(|error| unsupported(error.to_string()))?;
        let congestion = match credential
            .field("congestion_control")
            .filter(|value| !value.is_empty())
        {
            None | Some("cubic") => Congestion::Cubic,
            Some("new_reno") => Congestion::NewReno,
            Some("bbr") => Congestion::Bbr,
            Some(_) => return Err(unsupported("TUIC congestion control is unsupported")),
        };
        let udp_relay_mode = credential
            .field("udp_relay_mode")
            .filter(|value| !value.is_empty());
        let udp_over_stream = parse_optional_bool(credential.field("udp_over_stream"))?;
        if udp_over_stream && udp_relay_mode.is_some() {
            return Err(unsupported(
                "TUIC udp_over_stream conflicts with udp_relay_mode",
            ));
        }
        let udp_relay = match udp_relay_mode {
            None | Some("native") => UdpRelay::Native,
            Some("quic") => UdpRelay::Quic,
            Some(_) => return Err(unsupported("TUIC UDP relay mode is unsupported")),
        };
        let zero_rtt = parse_optional_bool(credential.field("zero_rtt_handshake"))?;
        if zero_rtt {
            return Err(unsupported("TUIC 0-RTT handshake is not supported"));
        }
        let heartbeat = credential
            .field("heartbeat")
            .map(parse_duration)
            .transpose()?
            .unwrap_or(Duration::from_secs(10));
        let tls_options = config
            .options
            .tls
            .clone()
            .unwrap_or(pathchord_policy::TransitTls {
                enabled: true,
                alpn: vec!["h3".into()],
                ..Default::default()
            });
        if !tls_options.enabled {
            return Err(unsupported("TUIC requires TLS"));
        }
        if tls_options.fingerprint.is_some() {
            return Err(unsupported("TUIC QUIC TLS fingerprint is unsupported"));
        }
        crate::tls::server_name(&config.endpoint.host, Some(&tls_options))?;
        let tls = crate::tls::configure(base_tls, Some(&tls_options), Some(credential))?;
        let server_name = tls_options
            .server_name
            .clone()
            .unwrap_or_else(|| config.endpoint.host.clone());
        Ok(Self {
            metadata: TransitMetadata {
                adapter_id: config.id.as_str().to_owned(),
                kind: AdapterKind::ExternalProxy {
                    protocol: "tuic".into(),
                },
                labels: config.labels.clone(),
            },
            endpoint: TransitEndpoint {
                host: config.endpoint.host.clone(),
                port: config.endpoint.port,
            },
            credentials,
            tls,
            server_name,
            udp_enabled: config.options.udp != Some(false),
            udp_relay,
            udp_over_stream,
            congestion,
            heartbeat,
            timeout,
        })
    }

    async fn connect_session(&self) -> Result<TuicSession, TransitError> {
        let address = timeout(
            self.timeout,
            tokio::net::lookup_host((self.endpoint.host.as_str(), self.endpoint.port)),
        )
        .await
        .map_err(|_| TransitError::Connection("TUIC endpoint resolution timed out".into()))?
        .map_err(|_| TransitError::Connection("TUIC endpoint resolution failed".into()))?
        .next()
        .ok_or_else(|| TransitError::Connection("TUIC endpoint did not resolve".into()))?;
        let mut quic = ClientConfig::new(Arc::new(
            QuicClientConfig::try_from((*self.tls).clone())
                .map_err(|_| unsupported("TUIC TLS config is invalid"))?,
        ));
        let mut transport = TransportConfig::default();
        let controller: Arc<dyn quinn::congestion::ControllerFactory + Send + Sync> =
            match self.congestion {
                Congestion::Cubic => Arc::new(quinn::congestion::CubicConfig::default()),
                Congestion::NewReno => Arc::new(quinn::congestion::NewRenoConfig::default()),
                Congestion::Bbr => Arc::new(quinn::congestion::BbrConfig::default()),
            };
        transport.congestion_controller_factory(controller);
        transport.datagram_receive_buffer_size(Some(512 * 1024));
        transport.datagram_send_buffer_size(512 * 1024);
        quic.transport_config(Arc::new(transport));
        let bind = if address.is_ipv6() {
            "[::]:0"
        } else {
            "0.0.0.0:0"
        };
        let mut endpoint = Endpoint::client(
            bind.parse()
                .map_err(|_| TransitError::Connection("TUIC local bind failed".into()))?,
        )
        .map_err(|_| TransitError::Connection("TUIC QUIC endpoint failed".into()))?;
        endpoint.set_default_client_config(quic);
        let connecting = endpoint
            .connect(address, &self.server_name)
            .map_err(|_| TransitError::Connection("TUIC QUIC connect failed".into()))?;
        let connection = timeout(self.timeout, connecting)
            .await
            .map_err(|_| TransitError::Connection("TUIC handshake timed out".into()))?
            .map_err(|error| TransitError::Connection(format!("TUIC handshake failed: {error}")))?;
        let heartbeat = connection.clone();
        let interval = self.heartbeat;
        let heartbeat_task = tokio::spawn(async move {
            loop {
                tokio::time::sleep(interval).await;
                if heartbeat
                    .send_datagram(crate::tuic_codec::encode_heartbeat())
                    .is_err()
                {
                    break;
                }
            }
        });
        Ok(TuicSession {
            connection,
            _endpoint: endpoint,
            heartbeat: heartbeat_task,
        })
    }

    async fn connect_tunnel(
        &self,
        destination: &TransitEndpoint,
    ) -> Result<BoxedTransitConnection, TransitError> {
        timeout(self.timeout, async {
            let session = self.connect_session().await?;
            let connection = &session.connection;
            let mut token = [0_u8; 32];
            connection
                .export_keying_material(
                    &mut token,
                    &self.credentials.uuid,
                    self.credentials.password.as_bytes(),
                )
                .map_err(|_| TransitError::Protocol("TUIC TLS exporter failed".into()))?;
            let mut auth = connection
                .open_uni()
                .await
                .map_err(|_| TransitError::Connection("TUIC auth stream failed".into()))?;
            auth.write_all(&encode_authenticate_token(&self.credentials.uuid, &token))
                .await
                .map_err(|_| TransitError::Connection("TUIC auth write failed".into()))?;
            auth.finish()
                .map_err(|_| TransitError::Connection("TUIC auth finish failed".into()))?;
            let endpoint = TuicEndpoint {
                address: tuic_address(destination)?,
                port: destination.port,
            };
            let command =
                encode_connect(&endpoint).map_err(|error| unsupported(error.to_string()))?;
            let (mut send, recv) = connection
                .open_bi()
                .await
                .map_err(|_| TransitError::Connection("TUIC connect stream failed".into()))?;
            send.write_all(&command)
                .await
                .map_err(|_| TransitError::Connection("TUIC connect command failed".into()))?;
            Ok(Box::new(TuicStream {
                send,
                recv,
                _session: session,
                shutdown: None,
                shutdown_result: None,
                shutdown_timeout: self.timeout.min(Duration::from_secs(2)),
            }) as BoxedTransitConnection)
        })
        .await
        .map_err(|_| TransitError::Connection("TUIC connection setup timed out".into()))?
    }
}

#[async_trait]
impl TransitAdapter for TuicAdapter {
    fn metadata(&self) -> &TransitMetadata {
        &self.metadata
    }
    fn supports_udp(&self) -> bool {
        self.udp_enabled
    }

    async fn connect(
        &self,
        request: ConnectRequest,
    ) -> Result<BoxedTransitConnection, TransitError> {
        crate::validate_destination(&request.destination)?;
        self.connect_tunnel(&request.destination).await
    }

    async fn connect_udp(
        &self,
        request: ConnectRequest,
    ) -> Result<BoxedTransitDatagram, TransitError> {
        if !self.udp_enabled {
            return Err(unsupported("TUIC UDP is disabled"));
        }
        crate::validate_destination(&request.destination)?;
        if self.udp_over_stream {
            let destination = TransitEndpoint {
                host: crate::uot::request_host(2).to_owned(),
                port: 0,
            };
            let inner = timeout(self.timeout, async {
                let stream = self.connect_tunnel(&destination).await?;
                crate::uot::UotDatagram::connect(stream, request.destination, 2).await
            })
            .await
            .map_err(|_| TransitError::Connection("TUIC UDP stream setup timed out".into()))??;
            return Ok(Box::new(TuicStreamDatagram {
                inner: Some(inner),
                io_timeout: self.timeout,
                close_timeout: self.timeout.min(Duration::from_secs(2)),
            }));
        }
        timeout(self.timeout, async {
            let session = self.connect_session().await?;
            let connection = &session.connection;
            let mut token = [0_u8; 32];
            connection
                .export_keying_material(
                    &mut token,
                    &self.credentials.uuid,
                    self.credentials.password.as_bytes(),
                )
                .map_err(|_| TransitError::Protocol("TUIC TLS exporter failed".into()))?;
            let mut auth = connection
                .open_uni()
                .await
                .map_err(|_| TransitError::Connection("TUIC auth stream failed".into()))?;
            auth.write_all(&encode_authenticate_token(&self.credentials.uuid, &token))
                .await
                .map_err(|_| TransitError::Connection("TUIC auth write failed".into()))?;
            auth.finish()
                .map_err(|_| TransitError::Connection("TUIC auth finish failed".into()))?;
            let endpoint = TuicEndpoint {
                address: tuic_address(&request.destination)?,
                port: request.destination.port,
            };
            let mut association = [0_u8; 2];
            getrandom::fill(&mut association).map_err(|_| {
                TransitError::Connection("TUIC association ID generation failed".into())
            })?;
            let association_id = u16::from_be_bytes(association).max(1);
            let (incoming_packets, incoming_task) = if self.udp_relay == UdpRelay::Quic {
                let (receiver, task) = spawn_packet_reader(session.connection.clone());
                (Some(receiver), Some(task))
            } else {
                (None, None)
            };
            Ok(Box::new(TuicDatagram {
                session,
                endpoint,
                association_id,
                packet_id: 0,
                relay: self.udp_relay,
                fragments: FragmentReassembler::default(),
                incoming_packets,
                incoming_task,
                pending_send: None,
                close_timeout: self.timeout.min(Duration::from_secs(2)),
                io_timeout: self.timeout,
            }) as BoxedTransitDatagram)
        })
        .await
        .map_err(|_| TransitError::Connection("TUIC UDP setup timed out".into()))?
    }
}

struct TuicStreamDatagram {
    inner: Option<BoxedTransitDatagram>,
    io_timeout: Duration,
    close_timeout: Duration,
}

impl std::fmt::Debug for TuicStreamDatagram {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("TuicStreamDatagram(..)")
    }
}

#[async_trait]
impl TransitDatagram for TuicStreamDatagram {
    async fn send(&mut self, payload: &[u8]) -> Result<(), TransitError> {
        let inner = self
            .inner
            .as_mut()
            .ok_or_else(|| TransitError::Connection("TUIC UDP stream is closed".into()))?;
        match timeout(self.io_timeout, inner.send(payload)).await {
            Ok(result) => result,
            Err(_) => {
                self.inner.take();
                Err(TransitError::Connection("TUIC UDP send timed out".into()))
            }
        }
    }

    async fn receive(&mut self) -> Result<Vec<u8>, TransitError> {
        self.inner
            .as_mut()
            .ok_or_else(|| TransitError::Connection("TUIC UDP stream is closed".into()))?
            .receive()
            .await
    }

    async fn close(mut self: Box<Self>) -> Result<(), TransitError> {
        let inner = self
            .inner
            .take()
            .ok_or_else(|| TransitError::Connection("TUIC UDP stream is closed".into()))?;
        timeout(self.close_timeout, inner.close())
            .await
            .map_err(|_| TransitError::Connection("TUIC UDP stream close timed out".into()))?
    }
}

fn tuic_address(endpoint: &TransitEndpoint) -> Result<TuicAddress, TransitError> {
    if let Ok(ip) = endpoint.host.parse::<std::net::IpAddr>() {
        Ok(match ip {
            std::net::IpAddr::V4(value) => TuicAddress::Ipv4(value.octets()),
            std::net::IpAddr::V6(value) => TuicAddress::Ipv6(value.octets()),
        })
    } else if endpoint.host.is_empty() || endpoint.host.len() > 255 {
        Err(unsupported("TUIC destination hostname is invalid"))
    } else {
        Ok(TuicAddress::Domain(endpoint.host.clone()))
    }
}

fn valid_reply_source(expected: &TuicEndpoint, source: &TuicEndpoint) -> bool {
    if source.port != expected.port {
        return false;
    }
    match (&expected.address, &source.address) {
        (TuicAddress::Domain(expected), TuicAddress::Domain(actual)) => {
            expected.eq_ignore_ascii_case(actual)
        }
        (TuicAddress::Domain(_), TuicAddress::Ipv4(_) | TuicAddress::Ipv6(_)) => true,
        (TuicAddress::Ipv4(expected), TuicAddress::Ipv4(actual)) => expected == actual,
        (TuicAddress::Ipv6(expected), TuicAddress::Ipv6(actual)) => expected == actual,
        _ => false,
    }
}

struct TuicStream {
    send: SendStream,
    recv: RecvStream,
    _session: TuicSession,
    shutdown: Option<Pin<Box<dyn Future<Output = io::Result<()>> + Send>>>,
    shutdown_result: Option<Result<(), (io::ErrorKind, String)>>,
    shutdown_timeout: Duration,
}

#[derive(Debug)]
struct TuicSession {
    connection: quinn::Connection,
    _endpoint: quinn::Endpoint,
    heartbeat: tokio::task::JoinHandle<()>,
}

impl Drop for TuicSession {
    fn drop(&mut self) {
        self.heartbeat.abort();
        self.connection.close(0_u32.into(), b"closed");
    }
}

#[derive(Debug)]
struct TuicDatagram {
    session: TuicSession,
    endpoint: TuicEndpoint,
    association_id: u16,
    packet_id: u16,
    relay: UdpRelay,
    fragments: FragmentReassembler,
    incoming_packets: Option<tokio::sync::mpsc::Receiver<QueuedPacket>>,
    incoming_task: Option<tokio::task::JoinHandle<()>>,
    pending_send: Option<tokio::task::JoinHandle<Result<(), TransitError>>>,
    close_timeout: Duration,
    io_timeout: Duration,
}

#[derive(Debug)]
struct QueuedPacket {
    bytes: bytes::Bytes,
    _permit: tokio::sync::OwnedSemaphorePermit,
}

impl TuicDatagram {
    async fn read_stream_packet(&mut self) -> Result<bytes::Bytes, TransitError> {
        self.incoming_packets
            .as_mut()
            .expect("QUIC relay has a packet reader")
            .recv()
            .await
            .map(|packet| packet.bytes)
            .ok_or_else(|| TransitError::Connection("TUIC UDP stream receive failed".into()))
    }

    async fn flush_pending_send(&mut self) -> Result<(), TransitError> {
        if let Some(task) = &mut self.pending_send {
            let result = task
                .await
                .map_err(|_| TransitError::Connection("TUIC UDP sender stopped".into()))?;
            self.pending_send = None;
            result?;
        }
        Ok(())
    }
}

impl Drop for TuicDatagram {
    fn drop(&mut self) {
        if let Some(task) = self.incoming_task.take() {
            task.abort();
        }
        if let Some(task) = self.pending_send.take() {
            task.abort();
        }
    }
}

fn spawn_packet_reader(
    connection: quinn::Connection,
) -> (
    tokio::sync::mpsc::Receiver<QueuedPacket>,
    tokio::task::JoinHandle<()>,
) {
    const MAX_STREAM_PACKET: usize = u16::MAX as usize + 270;
    const MAX_PENDING_STREAMS: usize = 8;
    const MAX_QUEUED_BYTES: usize = 256 * 1024;
    let (sender, receiver) = tokio::sync::mpsc::channel(64);
    let task = tokio::spawn(async move {
        let budget = Arc::new(tokio::sync::Semaphore::new(MAX_QUEUED_BYTES));
        let mut streams = FuturesUnordered::new();
        loop {
            tokio::select! {
                accepted = connection.accept_uni(), if streams.len() < MAX_PENDING_STREAMS => {
                    let Ok(mut stream) = accepted else { break; };
                    streams.push(async move {
                        timeout(Duration::from_secs(5), stream.read_to_end(MAX_STREAM_PACKET)).await
                    });
                }
                Some(result) = streams.next(), if !streams.is_empty() => {
                    if let Ok(Ok(packet)) = result {
                        // A full bounded queue drops UDP packets rather than
                        // blocking all other stream readers indefinitely.
                        if let Ok(permit) = Arc::clone(&budget).try_acquire_many_owned(packet.len() as u32) {
                            let _ = sender.try_send(QueuedPacket { bytes: bytes::Bytes::from(packet), _permit: permit });
                        }
                    }
                }
            }
        }
    });
    (receiver, task)
}

#[derive(Debug, Default)]
struct FragmentReassembler {
    packets: BTreeMap<u16, FragmentAssembly>,
    order: VecDeque<u16>,
    latest: Option<u16>,
    last_seen: Option<std::time::Instant>,
}

#[derive(Debug)]
struct FragmentAssembly {
    parts: Vec<Option<bytes::Bytes>>,
    bytes: usize,
    received: usize,
    created: std::time::Instant,
    source: Option<TuicEndpoint>,
}

impl FragmentReassembler {
    fn push(&mut self, packet: TuicPacket) -> Result<Option<Vec<u8>>, TransitError> {
        self.push_at(packet, std::time::Instant::now())
    }

    fn push_at(
        &mut self,
        packet: TuicPacket,
        now: std::time::Instant,
    ) -> Result<Option<Vec<u8>>, TransitError> {
        const MAX_AGE: Duration = Duration::from_secs(10);
        const MAX_DISTANCE: u16 = 1024;
        if self
            .last_seen
            .is_some_and(|last| now.saturating_duration_since(last) >= MAX_AGE)
        {
            self.latest = None;
            self.packets.clear();
            self.order.clear();
        }
        if let Some(latest) = self.latest {
            let delta = packet.packet_id.wrapping_sub(latest);
            if delta == 1 << 15 {
                self.packets.clear();
                self.order.clear();
                self.latest = Some(packet.packet_id);
            } else if delta > 1 << 15 && latest.wrapping_sub(packet.packet_id) > MAX_DISTANCE {
                return Ok(None);
            } else if delta != 0 && delta < 1 << 15 {
                self.latest = Some(packet.packet_id);
            }
        } else {
            self.latest = Some(packet.packet_id);
        }
        self.last_seen = Some(now);
        let latest = self.latest.expect("latest packet is known");
        self.packets.retain(|id, assembly| {
            let behind = latest.wrapping_sub(*id);
            now.saturating_duration_since(assembly.created) < MAX_AGE
                && (behind <= MAX_DISTANCE || behind > i16::MAX as u16)
        });
        self.order.retain(|id| self.packets.contains_key(id));
        if packet.fragment_total == 1 {
            self.packets.remove(&packet.packet_id);
            self.order.retain(|id| *id != packet.packet_id);
            return Ok(Some(packet.payload.to_vec()));
        }
        let id = packet.packet_id;
        if !self.packets.contains_key(&id) {
            const MAX_INCOMPLETE: usize = 16;
            if self.packets.len() >= MAX_INCOMPLETE
                && let Some(oldest) = self.order.pop_front()
            {
                self.packets.remove(&oldest);
            }
            self.order.push_back(id);
            self.packets.insert(
                id,
                FragmentAssembly {
                    parts: vec![None; usize::from(packet.fragment_total)],
                    bytes: 0,
                    received: 0,
                    created: now,
                    source: None,
                },
            );
        }
        let assembly = self.packets.get_mut(&id).expect("fragment assembly exists");
        if assembly.parts.len() != usize::from(packet.fragment_total) {
            return Err(TransitError::Protocol("TUIC fragment count changed".into()));
        }
        if !matches!(packet.endpoint.address, TuicAddress::None) {
            if assembly
                .source
                .as_ref()
                .is_some_and(|source| source != &packet.endpoint)
            {
                return Err(TransitError::Protocol(
                    "conflicting TUIC fragment sources".into(),
                ));
            }
            assembly.source = Some(packet.endpoint.clone());
        }
        let slot = &mut assembly.parts[usize::from(packet.fragment_id)];
        if let Some(existing) = slot {
            return if *existing == packet.payload {
                Ok(None)
            } else {
                Err(TransitError::Protocol("conflicting TUIC fragments".into()))
            };
        }
        assembly.bytes += packet.payload.len();
        if assembly.bytes > usize::from(u16::MAX) {
            return Err(TransitError::Protocol(
                "TUIC reassembled packet is too large".into(),
            ));
        }
        *slot = Some(packet.payload);
        assembly.received += 1;
        if assembly.received != assembly.parts.len() {
            return Ok(None);
        }
        let assembly = self.packets.remove(&id).expect("fragment assembly exists");
        self.order.retain(|item| *item != id);
        let mut payload = Vec::with_capacity(assembly.bytes);
        for part in assembly.parts {
            payload.extend_from_slice(&part.expect("all fragments received"));
        }
        Ok(Some(payload))
    }
}

#[async_trait]
impl TransitDatagram for TuicDatagram {
    async fn send(&mut self, payload: &[u8]) -> Result<(), TransitError> {
        let io_timeout = self.io_timeout;
        let result = timeout(io_timeout, async {
            if self.relay == UdpRelay::Quic {
                self.flush_pending_send().await?;
            }
            if payload.len() > usize::from(u16::MAX) {
                return Err(unsupported("TUIC UDP packet exceeds the protocol limit"));
            }
            let template = TuicPacket {
                association_id: self.association_id,
                packet_id: self.packet_id,
                fragment_total: 1,
                fragment_id: 0,
                endpoint: self.endpoint.clone(),
                payload: bytes::Bytes::new(),
            };
            self.packet_id = self.packet_id.wrapping_add(1);
            match self.relay {
                UdpRelay::Native => {
                    let max_size =
                        self.session.connection.max_datagram_size().ok_or_else(|| {
                            unsupported("TUIC peer does not accept QUIC datagrams")
                        })?;
                    let header_size = encode_packet(&template)
                        .map_err(|error| unsupported(error.to_string()))?
                        .len();
                    let chunk_size = max_size
                        .checked_sub(header_size)
                        .filter(|size| *size > 0)
                        .ok_or_else(|| unsupported("TUIC datagram size is too small"))?;
                    let total = payload.len().max(1).div_ceil(chunk_size);
                    let total = u8::try_from(total)
                        .map_err(|_| unsupported("TUIC UDP packet needs too many fragments"))?;
                    for index in 0..total {
                        let start = usize::from(index) * chunk_size;
                        let end = (start + chunk_size).min(payload.len());
                        let mut fragment = template.clone();
                        fragment.fragment_total = total;
                        fragment.fragment_id = index;
                        if index > 0 {
                            fragment.endpoint = TuicEndpoint {
                                address: TuicAddress::None,
                                port: 0,
                            };
                        }
                        fragment.payload = bytes::Bytes::copy_from_slice(&payload[start..end]);
                        let encoded = encode_packet(&fragment)
                            .map_err(|error| unsupported(error.to_string()))?;
                        self.session
                            .connection
                            .send_datagram(encoded)
                            .map_err(|_| {
                                TransitError::Connection("TUIC UDP datagram send failed".into())
                            })?;
                    }
                    Ok(())
                }
                UdpRelay::Quic => {
                    let mut packet = template;
                    packet.payload = bytes::Bytes::copy_from_slice(payload);
                    let packet =
                        encode_packet(&packet).map_err(|error| unsupported(error.to_string()))?;
                    let mut stream = self.session.connection.open_uni().await.map_err(|_| {
                        TransitError::Connection("TUIC UDP stream open failed".into())
                    })?;
                    let connection = self.session.connection.clone();
                    self.pending_send = Some(tokio::spawn(async move {
                        let operation = async {
                            stream.write_all(&packet).await.map_err(|_| {
                                TransitError::Connection("TUIC UDP stream write failed".into())
                            })?;
                            stream.finish().map_err(|_| {
                                TransitError::Connection("TUIC UDP stream finish failed".into())
                            })
                        };
                        match timeout(io_timeout, operation).await {
                            Ok(result) => result,
                            Err(_) => {
                                connection.close(0_u32.into(), b"UDP send timeout");
                                Err(TransitError::Connection("TUIC UDP send timed out".into()))
                            }
                        }
                    }));
                    self.flush_pending_send().await
                }
            }
        })
        .await;
        match result {
            Ok(result) => result,
            Err(_) => {
                if let Some(task) = self.pending_send.take() {
                    task.abort();
                }
                self.session
                    .connection
                    .close(0_u32.into(), b"UDP send timeout");
                Err(TransitError::Connection("TUIC UDP send timed out".into()))
            }
        }
    }

    async fn receive(&mut self) -> Result<Vec<u8>, TransitError> {
        loop {
            let packet = match self.relay {
                UdpRelay::Native => {
                    self.session.connection.read_datagram().await.map_err(|_| {
                        TransitError::Connection("TUIC UDP datagram receive failed".into())
                    })?
                }
                UdpRelay::Quic => self.read_stream_packet().await?,
            };
            if packet == crate::tuic_codec::encode_heartbeat() {
                continue;
            }
            let packet = decode_packet(&packet).map_err(|error| unsupported(error.to_string()))?;
            if packet.association_id != self.association_id {
                return Err(TransitError::Protocol(
                    "TUIC UDP association ID mismatch".into(),
                ));
            }
            if !matches!(packet.endpoint.address, TuicAddress::None)
                && !valid_reply_source(&self.endpoint, &packet.endpoint)
            {
                return Err(TransitError::Protocol(
                    "TUIC UDP reply source mismatch".into(),
                ));
            }
            if let Some(payload) = self.fragments.push(packet)? {
                return Ok(payload);
            }
        }
    }

    async fn close(mut self: Box<Self>) -> Result<(), TransitError> {
        let close_timeout = self.close_timeout;
        timeout(close_timeout, async {
            self.flush_pending_send().await?;
            let mut command =
                self.session.connection.open_uni().await.map_err(|_| {
                    TransitError::Connection("TUIC dissociate stream failed".into())
                })?;
            command
                .write_all(&encode_dissociate(self.association_id))
                .await
                .map_err(|_| TransitError::Connection("TUIC dissociate write failed".into()))?;
            command
                .finish()
                .map_err(|_| TransitError::Connection("TUIC dissociate finish failed".into()))?;
            if command
                .stopped()
                .await
                .map_err(|_| {
                    TransitError::Connection("TUIC dissociate acknowledgement failed".into())
                })?
                .is_some()
            {
                return Err(TransitError::Connection(
                    "TUIC dissociate was stopped by peer".into(),
                ));
            }
            Ok(())
        })
        .await
        .map_err(|_| TransitError::Connection("TUIC dissociate timed out".into()))?
    }
}
impl AsyncRead for TuicStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.recv).poll_read(cx, buffer)
    }
}
impl AsyncWrite for TuicStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.send)
            .poll_write(cx, bytes)
            .map_err(io::Error::other)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.send).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Some(result) = &self.shutdown_result {
            return Poll::Ready(match result {
                Ok(()) => Ok(()),
                Err((kind, message)) => Err(io::Error::new(*kind, message.clone())),
            });
        }
        if self.shutdown.is_none() {
            if let Err(error) = std::task::ready!(Pin::new(&mut self.send).poll_shutdown(cx)) {
                self.shutdown_result = Some(Err((error.kind(), error.to_string())));
                return Poll::Ready(Err(error));
            }
            let stopped = self.send.stopped();
            let duration = self.shutdown_timeout;
            self.shutdown = Some(Box::pin(async move {
                match timeout(duration, stopped).await {
                    Ok(Ok(None)) => Ok(()),
                    Ok(Ok(Some(_))) => Err(io::Error::other("TUIC stream was stopped by peer")),
                    Ok(Err(_)) => Err(io::Error::other("TUIC stream acknowledgement failed")),
                    Err(_) => Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "TUIC stream shutdown timed out",
                    )),
                }
            }));
        }
        let result = self
            .shutdown
            .as_mut()
            .expect("shutdown future was created")
            .as_mut()
            .poll(cx);
        if let Poll::Ready(outcome) = &result {
            self.shutdown_result = Some(match outcome {
                Ok(()) => Ok(()),
                Err(error) => Err((error.kind(), error.to_string())),
            });
            self.shutdown = None;
        }
        result
    }
}

fn unsupported(message: impl Into<String>) -> TransitError {
    TransitError::Unsupported(message.into())
}

fn parse_optional_bool(value: Option<&str>) -> Result<bool, TransitError> {
    match value.map(str::to_ascii_lowercase).as_deref() {
        None | Some("false" | "0" | "no") => Ok(false),
        Some("true" | "1" | "yes") => Ok(true),
        Some(_) => Err(unsupported("TUIC boolean option is invalid")),
    }
}

fn parse_duration(value: &str) -> Result<Duration, TransitError> {
    let value = value.trim();
    let (number, multiplier) = if let Some(value) = value.strip_suffix("ms") {
        (value, 1_u64)
    } else if let Some(value) = value.strip_suffix('s') {
        (value, 1_000_u64)
    } else if let Some(value) = value.strip_suffix('m') {
        (value, 60_000_u64)
    } else {
        (value, 1_000_u64)
    };
    let millis = number
        .parse::<u64>()
        .ok()
        .and_then(|number| number.checked_mul(multiplier))
        .filter(|millis| (1..=86_400_000).contains(millis))
        .ok_or_else(|| unsupported("TUIC heartbeat duration is invalid"))?;
    Ok(Duration::from_millis(millis))
}

#[cfg(test)]
mod tests {
    use super::*;
    use pathchord_policy::{
        Endpoint as PolicyEndpoint, TransitOptions, TransitProxyId, TransitTls,
    };
    use serde_json::json;
    use std::collections::{BTreeMap, BTreeSet};
    use std::path::PathBuf;
    use std::process::Stdio;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::UdpSocket;
    use tokio::process::Command;

    #[test]
    fn rejects_invalid_boolean_options_instead_of_disabling_them() {
        assert!(parse_optional_bool(Some("perhaps")).is_err());
        assert!(parse_optional_bool(Some("")).is_err());
        assert!(parse_optional_bool(Some("TRUE")).unwrap());
        assert!(!parse_optional_bool(Some("false")).unwrap());
    }

    #[test]
    fn checks_server_name_and_defaults_heartbeat_during_preparation() {
        let mut node = pathchord_policy::TransitProxyConfig {
            id: TransitProxyId::new("tuic-options"),
            source: None,
            protocol: "tuic".into(),
            endpoint: PolicyEndpoint {
                host: "127.0.0.1".into(),
                port: 443,
            },
            credentials_ref: None,
            labels: BTreeMap::new(),
            tags: BTreeSet::new(),
            weight: 100,
            options: TransitOptions::default(),
        };
        let credential = TransitCredential::new(BTreeMap::from([
            ("uuid".into(), "6cbf3f72-3417-4922-bde6-67820d041f25".into()),
            ("password".into(), "fixture-password".into()),
        ]));
        let build = |node: &_| {
            TuicAdapter::from_config(
                node,
                &credential,
                Duration::from_secs(1),
                crate::adapter_registry::native_tls_roots(),
            )
        };
        assert_eq!(build(&node).unwrap().heartbeat, Duration::from_secs(10));
        node.options.tls = Some(TransitTls {
            enabled: true,
            server_name: Some("invalid server name".into()),
            ..Default::default()
        });
        assert!(matches!(build(&node), Err(TransitError::Unsupported(_))));
    }

    #[test]
    fn udp_over_stream_conflicts_with_every_explicit_relay_mode() {
        let node = pathchord_policy::TransitProxyConfig {
            id: TransitProxyId::new("tuic-options"),
            source: None,
            protocol: "tuic".into(),
            endpoint: PolicyEndpoint {
                host: "127.0.0.1".into(),
                port: 443,
            },
            credentials_ref: None,
            labels: BTreeMap::new(),
            tags: BTreeSet::new(),
            weight: 100,
            options: TransitOptions::default(),
        };
        let credentials = |stream: &str, relay: Option<&str>| {
            let mut fields = BTreeMap::from([
                ("uuid".into(), "6cbf3f72-3417-4922-bde6-67820d041f25".into()),
                ("password".into(), "fixture-password".into()),
                ("udp_over_stream".into(), stream.into()),
            ]);
            if let Some(relay) = relay {
                fields.insert("udp_relay_mode".into(), relay.into());
            }
            TransitCredential::new(fields)
        };
        let build = |credential: &TransitCredential| {
            TuicAdapter::from_config(
                &node,
                credential,
                Duration::from_secs(1),
                crate::adapter_registry::native_tls_roots(),
            )
        };
        for relay in ["native", "quic", "unrecognized"] {
            assert!(build(&credentials("true", Some(relay))).is_err());
        }
        assert!(build(&credentials("true", None)).unwrap().udp_over_stream);
        assert!(
            build(&credentials("true", Some("")))
                .unwrap()
                .udp_over_stream
        );
        for relay in ["native", "quic"] {
            assert!(
                !build(&credentials("false", Some(relay)))
                    .unwrap()
                    .udp_over_stream
            );
        }
        assert!(build(&credentials("perhaps", None)).is_err());
    }

    #[test]
    fn reassembles_reordered_duplicate_fragments_with_bounded_state() {
        let fragment = |packet_id, fragment_id, bytes: &'static [u8]| TuicPacket {
            association_id: 1,
            packet_id,
            fragment_total: 3,
            fragment_id,
            endpoint: TuicEndpoint {
                address: if fragment_id == 0 {
                    TuicAddress::Ipv4([127, 0, 0, 1])
                } else {
                    TuicAddress::None
                },
                port: if fragment_id == 0 { 53 } else { 0 },
            },
            payload: bytes::Bytes::from_static(bytes),
        };
        let mut reassembler = FragmentReassembler::default();
        assert_eq!(reassembler.push(fragment(9, 2, b"c")).unwrap(), None);
        assert_eq!(reassembler.push(fragment(9, 0, b"a")).unwrap(), None);
        assert_eq!(reassembler.push(fragment(9, 2, b"c")).unwrap(), None);
        assert_eq!(
            reassembler.push(fragment(9, 1, b"b")).unwrap(),
            Some(b"abc".to_vec())
        );
        for id in 0..20 {
            reassembler.push(fragment(id, 0, b"a")).unwrap();
        }
        assert_eq!(reassembler.packets.len(), 16);
        assert!(!reassembler.packets.contains_key(&0));
        assert!(reassembler.push(fragment(19, 0, b"different")).is_err());
        let now = std::time::Instant::now();
        let mut expired = FragmentReassembler::default();
        assert!(
            expired
                .push_at(fragment(42, 0, b"old"), now)
                .unwrap()
                .is_none()
        );
        let later = now + Duration::from_secs(11);
        assert!(
            expired
                .push_at(fragment(42, 1, b"new-b"), later)
                .unwrap()
                .is_none()
        );
        assert!(
            expired
                .push_at(fragment(42, 2, b"new-c"), later)
                .unwrap()
                .is_none()
        );
        assert_eq!(
            expired.push_at(fragment(42, 0, b"new-a"), later).unwrap(),
            Some(b"new-anew-bnew-c".to_vec())
        );
        assert!(expired.push(fragment(65_535, 0, b"old")).unwrap().is_none());
        expired
            .push(TuicPacket {
                fragment_total: 1,
                fragment_id: 0,
                ..fragment(0, 0, b"single")
            })
            .unwrap();
        expired
            .push(TuicPacket {
                fragment_total: 1,
                fragment_id: 0,
                ..fragment(1024, 0, b"single")
            })
            .unwrap();
        assert!(!expired.packets.contains_key(&65_535));
        let expected = TuicEndpoint {
            address: TuicAddress::Ipv4([127, 0, 0, 1]),
            port: 53,
        };
        assert!(!valid_reply_source(
            &expected,
            &TuicEndpoint {
                address: TuicAddress::Ipv4([127, 0, 0, 2]),
                port: 53
            }
        ));
        let expected_domain = TuicEndpoint {
            address: TuicAddress::Domain("dns.example".into()),
            port: 53,
        };
        assert!(valid_reply_source(
            &expected_domain,
            &TuicEndpoint {
                address: TuicAddress::Domain("DNS.EXAMPLE".into()),
                port: 53
            }
        ));
        assert!(!valid_reply_source(
            &expected_domain,
            &TuicEndpoint {
                address: TuicAddress::Domain("other.example".into()),
                port: 53
            }
        ));
        assert!(valid_reply_source(
            &expected_domain,
            &TuicEndpoint {
                address: TuicAddress::Ipv4([192, 0, 2, 53]),
                port: 53
            }
        ));
        assert!(!valid_reply_source(
            &expected,
            &TuicEndpoint {
                address: expected.address.clone(),
                port: 54
            }
        ));
        let mut half_ring = FragmentReassembler::default();
        let two = |id, index, data| TuicPacket {
            fragment_total: 2,
            ..fragment(id, index, data)
        };
        assert_eq!(half_ring.push(two(0, 0, b"old")).unwrap(), None);
        assert_eq!(
            half_ring
                .push(TuicPacket {
                    fragment_total: 1,
                    ..fragment(32_768, 0, b"single")
                })
                .unwrap(),
            Some(b"single".to_vec())
        );
        assert_eq!(half_ring.push(two(0, 1, b"new")).unwrap(), None);
    }

    #[tokio::test]
    #[ignore = "requires PATHCHORD_TEST_SING_BOX pointing to sing-box 1.14.4"]
    async fn native_tuic_tcp_interoperates_with_sing_box() {
        let binary =
            PathBuf::from(std::env::var_os("PATHCHORD_TEST_SING_BOX").expect("reference peer"));
        let uuid = "6cbf3f72-3417-4922-bde6-67820d041f25";
        let password = "pathchord-tuic-password";
        let cert =
            rcgen::generate_simple_self_signed(vec!["tuic.test".into()]).expect("certificate");
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let config = json!({
            "log": {"level": "debug"},
            "inbounds": [{
                "type": "tuic", "listen": "127.0.0.1", "listen_port": port,
                "users": [{"uuid": uuid, "password": password}],
                "tls": {"enabled": true, "alpn": ["h3"], "certificate": cert.cert.pem(), "key": cert.signing_key.serialize_pem()}
            }],
            "outbounds": [{"type": "direct", "tag": "direct"}], "route": {"final": "direct"}
        });
        let mut peer = Command::new(binary)
            .arg("run")
            .arg("-c")
            .arg("stdin")
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .expect("start reference peer");
        peer.stdin
            .take()
            .expect("peer stdin")
            .write_all(&serde_json::to_vec(&config).unwrap())
            .await
            .unwrap();
        let target = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_addr = target.local_addr().unwrap();
        let target_task = tokio::spawn(async move {
            let (mut stream, _) = target.accept().await.unwrap();
            let mut payload = [0_u8; 6];
            stream.read_exact(&mut payload).await.unwrap();
            stream.write_all(&payload).await.unwrap();
        });
        let node = pathchord_policy::TransitProxyConfig {
            id: TransitProxyId::new("tuic-test"),
            source: None,
            protocol: "tuic".into(),
            endpoint: PolicyEndpoint {
                host: "127.0.0.1".into(),
                port,
            },
            credentials_ref: None,
            labels: BTreeMap::new(),
            tags: BTreeSet::new(),
            weight: 100,
            options: TransitOptions {
                tls: Some(TransitTls {
                    enabled: true,
                    insecure: true,
                    server_name: Some("tuic.test".into()),
                    alpn: vec!["h3".into()],
                    ..Default::default()
                }),
                ..Default::default()
            },
        };
        let credentials = TransitCredential::new(BTreeMap::from([
            ("uuid".into(), uuid.into()),
            ("password".into(), password.into()),
        ]));
        let adapter = TuicAdapter::from_config(
            &node,
            &credentials,
            Duration::from_secs(5),
            crate::adapter_registry::native_tls_roots(),
        )
        .unwrap();
        assert_eq!(adapter.tls.alpn_protocols, vec![b"h3".to_vec()]);
        let mut stream = adapter
            .connect(ConnectRequest {
                destination: TransitEndpoint {
                    host: "127.0.0.1".into(),
                    port: target_addr.port(),
                },
            })
            .await
            .unwrap();
        stream.write_all(b"tuic!!").await.unwrap();
        stream.flush().await.unwrap();
        let mut echoed = [0_u8; 6];
        stream.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"tuic!!");
        target_task.await.unwrap();
        let udp_target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let udp_address = udp_target.local_addr().unwrap();
        let udp_task = tokio::spawn(async move {
            let mut packet = [0_u8; 8192];
            for _ in 0..13 {
                let (length, peer) = udp_target.recv_from(&mut packet).await.unwrap();
                udp_target.send_to(&packet[..length], peer).await.unwrap();
            }
        });
        let mut datagram = adapter
            .connect_udp(ConnectRequest {
                destination: TransitEndpoint {
                    host: "127.0.0.1".into(),
                    port: udp_address.port(),
                },
            })
            .await
            .unwrap();
        datagram.send(b"udp-tuic").await.unwrap();
        let received = timeout(Duration::from_secs(5), datagram.receive())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(received, b"udp-tuic");
        datagram.close().await.unwrap();
        for relay in ["native", "quic"] {
            for congestion in ["cubic", "new_reno", "bbr"] {
                let credentials = TransitCredential::new(BTreeMap::from([
                    ("uuid".into(), uuid.into()),
                    ("password".into(), password.into()),
                    ("udp_relay_mode".into(), relay.into()),
                    ("congestion_control".into(), congestion.into()),
                ]));
                let adapter = TuicAdapter::from_config(
                    &node,
                    &credentials,
                    Duration::from_secs(5),
                    crate::adapter_registry::native_tls_roots(),
                )
                .unwrap();
                let mut datagram = adapter
                    .connect_udp(ConnectRequest {
                        destination: TransitEndpoint {
                            host: "127.0.0.1".into(),
                            port: udp_address.port(),
                        },
                    })
                    .await
                    .unwrap();
                datagram.send(b"udp-tuic").await.unwrap();
                let received = timeout(Duration::from_secs(5), datagram.receive())
                    .await
                    .unwrap()
                    .unwrap();
                assert_eq!(
                    received, b"udp-tuic",
                    "relay {relay}, congestion {congestion}"
                );
                let large = vec![0x5a; 4096];
                datagram.send(&large).await.unwrap();
                let received = timeout(Duration::from_secs(5), datagram.receive())
                    .await
                    .unwrap()
                    .unwrap();
                assert_eq!(
                    received, large,
                    "fragmented relay {relay}, congestion {congestion}"
                );
                datagram.close().await.unwrap();
            }
        }
        udp_task.await.unwrap();
        peer.kill().await.unwrap();
        peer.wait().await.unwrap();
    }
}
