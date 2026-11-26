//! Native AnyTLS single-stream adapter.
//!
//! AnyTLS sessions are multiplexed by the protocol, but a Transit adapter owns
//! one bounded stream at a time. The session handshake and frame relay are kept
//! here so the codec remains transport-neutral and can be tested independently.

use std::net::IpAddr;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};
use std::time::Duration;
#[cfg(test)]
use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};

use async_trait::async_trait;
use bytes::BytesMut;
#[cfg(test)]
use tokio::io::{AsyncRead, AsyncWrite, DuplexStream, ReadBuf};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{Mutex as AsyncMutex, mpsc, oneshot};
use tokio::time::timeout;
use zeroize::Zeroizing;

use crate::anytls_codec::{
    AnyTlsAddress, AnyTlsCommand, AnyTlsFrame, AnyTlsPaddingScheme, AnyTlsSettings,
    MAX_FRAME_PAYLOAD, authentication_record,
};
use crate::native_transport::NativeTransport;
use crate::{
    AdapterKind, BoxedTransitConnection, ConnectRequest, Endpoint, TransitAdapter,
    TransitCredential, TransitError, TransitMetadata,
};

const STREAM_ID: u32 = 1;
const MAX_IDLE_SESSIONS: usize = 8;
const IDLE_SESSION_TIMEOUT: Duration = Duration::from_secs(60);
#[cfg(test)]
const MAX_HANDSHAKE_BYTES: usize = 128 * 1024;

pub(crate) struct AnyTlsAdapter {
    metadata: TransitMetadata,
    password: Zeroizing<String>,
    transport: NativeTransport,
    udp_enabled: bool,
    timeout: Duration,
    sessions: Arc<AsyncMutex<Vec<SessionHandle>>>,
    padding: Arc<Mutex<AnyTlsPaddingScheme>>,
}

impl std::fmt::Debug for AnyTlsAdapter {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AnyTlsAdapter")
            .field("metadata", &self.metadata)
            .field("timeout", &self.timeout)
            .finish_non_exhaustive()
    }
}

impl AnyTlsAdapter {
    pub fn from_config(
        config: &pathchord_policy::TransitProxyConfig,
        credential: &TransitCredential,
        timeout: Duration,
        tls: Arc<rustls::ClientConfig>,
    ) -> Result<Self, TransitError> {
        let mut config = config.clone();
        if config.protocol != "anytls" {
            return Err(unsupported("AnyTLS adapter requires protocol anytls"));
        }
        let tls_options = config
            .options
            .tls
            .clone()
            .unwrap_or(pathchord_policy::TransitTls {
                enabled: true,
                ..Default::default()
            });
        if !tls_options.enabled {
            return Err(unsupported("native AnyTLS requires TLS"));
        }
        config.options.tls = Some(tls_options);
        let mut allowed = vec!["password"];
        if let Some(field) = config
            .options
            .tls
            .as_ref()
            .and_then(|tls| tls.client_key_field.as_deref())
        {
            allowed.push(field);
        }
        crate::adapter_registry::validate_credentials(Some(credential), &allowed)?;
        let password = credential
            .field("password")
            .filter(|value| !value.is_empty())
            .ok_or_else(|| unsupported("AnyTLS password is missing"))?;
        let transport = NativeTransport::new(&config, credential, tls, timeout)?;
        Ok(Self {
            metadata: TransitMetadata {
                adapter_id: config.id.as_str().to_owned(),
                kind: AdapterKind::ExternalProxy {
                    protocol: "anytls".to_owned(),
                },
                labels: config.labels.clone(),
            },
            password: Zeroizing::new(password.to_owned()),
            transport,
            udp_enabled: config.options.udp != Some(false),
            timeout,
            sessions: Arc::new(AsyncMutex::new(Vec::new())),
            padding: Arc::new(Mutex::new(AnyTlsPaddingScheme::default_scheme())),
        })
    }

    async fn open(
        &self,
        destination: &Endpoint,
        eager_payload: Option<bytes::Bytes>,
    ) -> Result<BoxedTransitConnection, TransitError> {
        let destination = anytls_address(destination)?;
        timeout(self.timeout, async {
            let session = self.acquire_session().await?;
            let (reply, result) = oneshot::channel();
            session
                .sender
                .send(SessionCommand::Open {
                    destination,
                    eager_payload,
                    reply,
                })
                .await
                .map_err(|_| TransitError::Connection("AnyTLS Session is closed".into()))?;
            result
                .await
                .map_err(|_| TransitError::Connection("AnyTLS Session open cancelled".into()))?
        })
        .await
        .map_err(|_| TransitError::Connection("AnyTLS session timed out".to_owned()))?
    }

    async fn acquire_session(&self) -> Result<SessionHandle, TransitError> {
        let now = std::time::Instant::now();
        let mut sessions = self.sessions.lock().await;
        sessions.retain(|session| {
            session.healthy.load(Ordering::Acquire)
                && !(session.idle.load(Ordering::Acquire)
                    && now.duration_since(*session.last_idle.lock().expect("AnyTLS idle"))
                        >= IDLE_SESSION_TIMEOUT)
        });
        if let Some(session) = sessions
            .iter()
            .find(|session| session.idle.load(Ordering::Acquire))
            .cloned()
        {
            session.idle.store(false, Ordering::Release);
            return Ok(session);
        }
        drop(sessions);
        let mut stream = self.transport.connect().await?;
        let scheme = self.padding.lock().expect("AnyTLS padding state").clone();
        let padding_size = scheme
            .rules(0)
            .iter()
            .find_map(|rule| AnyTlsPaddingScheme::sample_size(*rule).ok().flatten())
            .unwrap_or(0);
        let mut padding = vec![0u8; padding_size];
        if !padding.is_empty() {
            getrandom::fill(&mut padding)
                .map_err(|_| protocol("AnyTLS padding randomness failed"))?;
        }
        let auth = authentication_record(&self.password, &padding).map_err(protocol)?;
        stream.write_all(&auth).await.map_err(io_failure)?;
        let (sender, receiver) = mpsc::channel(2);
        let session = SessionHandle {
            sender,
            idle: Arc::new(AtomicBool::new(false)),
            healthy: Arc::new(AtomicBool::new(true)),
            last_idle: Arc::new(Mutex::new(std::time::Instant::now())),
            scheme: Arc::new(Mutex::new(scheme)),
            pool: Arc::downgrade(&self.sessions),
            node_padding: Arc::clone(&self.padding),
        };
        let mut sessions = self.sessions.lock().await;
        sessions.push(session.clone());
        let mut idle: Vec<_> = sessions
            .iter()
            .filter(|candidate| candidate.idle.load(Ordering::Acquire))
            .cloned()
            .collect();
        idle.sort_by_key(|candidate| *candidate.last_idle.lock().expect("AnyTLS idle"));
        while idle.len() > MAX_IDLE_SESSIONS {
            let evicted = idle.remove(0);
            evicted.healthy.store(false, Ordering::Release);
            sessions.retain(|candidate| !Arc::ptr_eq(&candidate.healthy, &evicted.healthy));
        }
        drop(sessions);
        let worker_session = session.clone();
        tokio::spawn(async move {
            run_session(stream, receiver, worker_session).await;
        });
        Ok(session)
    }
}

#[derive(Clone)]
struct SessionHandle {
    sender: mpsc::Sender<SessionCommand>,
    idle: Arc<AtomicBool>,
    healthy: Arc<AtomicBool>,
    last_idle: Arc<Mutex<std::time::Instant>>,
    scheme: Arc<Mutex<AnyTlsPaddingScheme>>,
    pool: std::sync::Weak<AsyncMutex<Vec<SessionHandle>>>,
    node_padding: Arc<Mutex<AnyTlsPaddingScheme>>,
}

enum SessionCommand {
    Open {
        destination: AnyTlsAddress,
        eager_payload: Option<bytes::Bytes>,
        reply: oneshot::Sender<Result<BoxedTransitConnection, TransitError>>,
    },
}

async fn run_session(
    mut upstream: BoxedTransitConnection,
    mut commands: mpsc::Receiver<SessionCommand>,
    session: SessionHandle,
) {
    let mut packet_count = 0_u32;
    loop {
        let command = if session.idle.load(Ordering::Acquire) {
            match timeout(IDLE_SESSION_TIMEOUT, commands.recv()).await {
                Ok(command) => command,
                Err(_) => {
                    session.healthy.store(false, Ordering::Release);
                    break;
                }
            }
        } else {
            commands.recv().await
        };
        let Some(SessionCommand::Open {
            destination,
            eager_payload,
            reply,
        }) = command
        else {
            break;
        };
        let (client, server) = tokio::io::duplex(MAX_FRAME_PAYLOAD * 2);
        let (mut client_read, mut client_write) = tokio::io::split(server);
        let mut initial = BytesMut::new();
        let mut address = BytesMut::new();
        if packet_count == 0 {
            let settings = AnyTlsSettings::official_client(
                &session.scheme.lock().expect("AnyTLS padding scheme"),
            );
            if (AnyTlsFrame {
                command: AnyTlsCommand::Settings,
                stream_id: 0,
                payload: match settings.encode() {
                    Ok(value) => value,
                    Err(error) => {
                        session.healthy.store(false, Ordering::Release);
                        let _ = reply.send(Err(protocol(error)));
                        break;
                    }
                },
            })
            .encode(&mut initial)
            .is_err()
            {
                session.healthy.store(false, Ordering::Release);
                let _ = reply.send(Err(protocol("AnyTLS settings encoding failed")));
                break;
            }
        }
        if destination.encode(&mut address).is_err()
            || (AnyTlsFrame {
                command: AnyTlsCommand::Syn,
                stream_id: STREAM_ID,
                payload: bytes::Bytes::new(),
            })
            .encode(&mut initial)
            .is_err()
            || (AnyTlsFrame {
                command: AnyTlsCommand::Push,
                stream_id: STREAM_ID,
                payload: address.freeze(),
            })
            .encode(&mut initial)
            .is_err()
        {
            session.healthy.store(false, Ordering::Release);
            let _ = reply.send(Err(protocol("AnyTLS Stream request encoding failed")));
            break;
        }
        if let Some(payload) = eager_payload
            && (AnyTlsFrame {
                command: AnyTlsCommand::Push,
                stream_id: STREAM_ID,
                payload,
            })
            .encode(&mut initial)
            .is_err()
        {
            session.healthy.store(false, Ordering::Release);
            let _ = reply.send(Err(protocol("AnyTLS Stream payload encoding failed")));
            break;
        }
        packet_count = packet_count.saturating_add(1);
        if write_session_packet(&mut upstream, &initial, &session.scheme, packet_count)
            .await
            .is_err()
        {
            session.healthy.store(false, Ordering::Release);
            let _ = reply.send(Err(protocol("AnyTLS Stream request write failed")));
            break;
        }
        let mut input = BytesMut::new();
        let mut up_buf = [0u8; 8192];
        let mut down_buf = [0u8; 8192];
        let mut opened = false;
        while !opened {
            let size = match upstream.read(&mut down_buf).await {
                Ok(0) | Err(_) => {
                    session.healthy.store(false, Ordering::Release);
                    let _ = reply.send(Err(protocol("AnyTLS peer closed before SYNACK")));
                    return;
                }
                Ok(n) => n,
            };
            input.extend_from_slice(&down_buf[..size]);
            'frames: loop {
                let frame = match AnyTlsFrame::decode(&mut input) {
                    Ok(Some(frame)) => frame,
                    Ok(None) => break 'frames,
                    Err(_) => {
                        session.healthy.store(false, Ordering::Release);
                        let _ = reply.send(Err(protocol("AnyTLS invalid frame")));
                        return;
                    }
                };
                match frame.command {
                    AnyTlsCommand::SynAck if frame.stream_id == STREAM_ID => {
                        if !frame.payload.is_empty() {
                            session.healthy.store(false, Ordering::Release);
                            let _ = reply.send(Err(protocol("AnyTLS peer rejected the stream")));
                            return;
                        }
                        opened = true;
                        break;
                    }
                    AnyTlsCommand::HeartRequest => {
                        if let Ok(response) = heartbeat_response(frame.stream_id) {
                            let _ = upstream.write_all(&response).await;
                        }
                    }
                    AnyTlsCommand::UpdatePaddingScheme => {
                        match AnyTlsPaddingScheme::parse(&frame.payload) {
                            Ok(scheme) => {
                                *session
                                    .node_padding
                                    .lock()
                                    .expect("AnyTLS node padding state") = scheme;
                            }
                            Err(_) => {
                                session.healthy.store(false, Ordering::Release);
                                let _ =
                                    reply.send(Err(protocol("AnyTLS padding update is invalid")));
                                return;
                            }
                        }
                    }
                    AnyTlsCommand::ServerSettings => {
                        let settings = match AnyTlsSettings::decode(&frame.payload) {
                            Ok(settings) => settings,
                            Err(_) => {
                                session.healthy.store(false, Ordering::Release);
                                let _ =
                                    reply.send(Err(protocol("AnyTLS server settings are invalid")));
                                return;
                            }
                        };
                        if settings
                            .protocol_version()
                            .ok()
                            .is_some_and(|version| version < 2)
                        {
                            session.healthy.store(false, Ordering::Release);
                            let _ = reply.send(Err(protocol(
                                "AnyTLS server protocol version is unsupported",
                            )));
                            return;
                        }
                    }
                    AnyTlsCommand::Alert => {
                        session.healthy.store(false, Ordering::Release);
                        let _ = reply.send(Err(protocol("AnyTLS peer sent ALERT")));
                        return;
                    }
                    AnyTlsCommand::Waste => {}
                    _ => {}
                }
            }
        }
        let _ = reply.send(Ok(Box::new(client)));
        loop {
            tokio::select! {
                result = client_read.read(&mut up_buf) => {
                    let Ok(size) = result else { break; }; if size == 0 { let mut fin=BytesMut::new(); let _=(AnyTlsFrame{command:AnyTlsCommand::Fin,stream_id:STREAM_ID,payload:bytes::Bytes::new()}).encode(&mut fin); let _=upstream.write_all(&fin).await; let _=upstream.flush().await; break; }
                    let mut frame=BytesMut::new(); if (AnyTlsFrame{command:AnyTlsCommand::Push,stream_id:STREAM_ID,payload:bytes::Bytes::copy_from_slice(&up_buf[..size])}).encode(&mut frame).is_err() { break; } packet_count = packet_count.saturating_add(1); if write_session_packet(&mut upstream, &frame, &session.scheme, packet_count).await.is_err() { session.healthy.store(false, Ordering::Release); break; }
                }
                result = upstream.read(&mut down_buf) => {
                    let Ok(size)=result else { session.healthy.store(false, Ordering::Release); break; }; if size==0 { session.healthy.store(false, Ordering::Release); break; } input.extend_from_slice(&down_buf[..size]);
                    loop {
                        let frame = match AnyTlsFrame::decode(&mut input) {
                            Ok(Some(frame)) => frame,
                            Ok(None) => break,
                            Err(_) => {
                                session.healthy.store(false, Ordering::Release);
                                break;
                            }
                        };
                        match frame.command {
                            AnyTlsCommand::Push if frame.stream_id == STREAM_ID => {
                                if client_write.write_all(&frame.payload).await.is_err() {
                                    break;
                                }
                            }
                            AnyTlsCommand::Fin if frame.stream_id == STREAM_ID => {
                                let _ = client_write.shutdown().await;
                                break;
                            }
                            AnyTlsCommand::HeartRequest => {
                                if let Ok(resp) = heartbeat_response(frame.stream_id) {
                                    let _ = upstream.write_all(&resp).await;
                                }
                            }
                            AnyTlsCommand::UpdatePaddingScheme => {
                                match AnyTlsPaddingScheme::parse(&frame.payload) {
                                    Ok(scheme) => {
                                        *session.node_padding.lock().expect("AnyTLS node padding state") = scheme;
                                    }
                                    Err(_) => session.healthy.store(false, Ordering::Release),
                                }
                            }
                            AnyTlsCommand::ServerSettings => {
                                if AnyTlsSettings::decode(&frame.payload)
                                    .ok()
                                    .and_then(|settings| settings.protocol_version().ok())
                                    .is_none_or(|version| version < 2)
                                {
                                    session.healthy.store(false, Ordering::Release);
                                }
                            }
                            AnyTlsCommand::Alert => {
                                session.healthy.store(false, Ordering::Release);
                                let _ = client_write.shutdown().await;
                                break;
                            }
                            _ => {}
                        }
                    }
                }
            }
        }
        if session.healthy.load(Ordering::Acquire) {
            session.idle.store(true, Ordering::Release);
            *session.last_idle.lock().expect("AnyTLS idle") = std::time::Instant::now();
            if let Some(pool) = session.pool.upgrade() {
                let mut sessions = pool.lock().await;
                let mut idle = sessions
                    .iter()
                    .filter(|candidate| candidate.idle.load(Ordering::Acquire))
                    .cloned()
                    .collect::<Vec<_>>();
                idle.sort_by_key(|candidate| *candidate.last_idle.lock().expect("AnyTLS idle"));
                while idle.len() > MAX_IDLE_SESSIONS {
                    let evicted = idle.remove(0);
                    evicted.healthy.store(false, Ordering::Release);
                    sessions.retain(|candidate| !Arc::ptr_eq(&candidate.healthy, &evicted.healthy));
                }
            }
        }
        continue;
    }
    session.healthy.store(false, Ordering::Release);
}

async fn write_session_packet(
    upstream: &mut BoxedTransitConnection,
    data: &[u8],
    scheme: &Arc<Mutex<AnyTlsPaddingScheme>>,
    packet: u32,
) -> Result<(), TransitError> {
    let scheme = scheme.lock().expect("AnyTLS padding scheme").clone();
    let target = scheme
        .rules(packet)
        .iter()
        .find_map(|rule| AnyTlsPaddingScheme::sample_size(*rule).ok().flatten())
        .unwrap_or(0);
    let mut output = BytesMut::from(data);
    let mut remaining = target.saturating_sub(output.len());
    while remaining >= 7 {
        let size = remaining.saturating_sub(7).min(MAX_FRAME_PAYLOAD);
        let mut waste = BytesMut::new();
        AnyTlsFrame {
            command: AnyTlsCommand::Waste,
            stream_id: 0,
            payload: bytes::Bytes::from(vec![0; size]),
        }
        .encode(&mut waste)
        .map_err(protocol)?;
        output.extend_from_slice(&waste);
        remaining = target.saturating_sub(output.len());
    }
    upstream.write_all(&output).await.map_err(io_failure)?;
    upstream.flush().await.map_err(io_failure)
}

#[async_trait]
impl TransitAdapter for AnyTlsAdapter {
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
        self.open(&request.destination, None).await
    }

    async fn connect_udp(
        &self,
        request: ConnectRequest,
    ) -> Result<crate::BoxedTransitDatagram, TransitError> {
        if !self.udp_enabled {
            return Err(unsupported("AnyTLS UDP is disabled"));
        }
        // The peer can require the UoT connect request before sending SYNACK.
        let request_payload = crate::uot::encode_v2_connect_request(&request.destination)?;
        let stream = self
            .open(
                &Endpoint {
                    host: crate::uot::request_host(2).into(),
                    port: 0,
                },
                Some(request_payload.into()),
            )
            .await?;
        Ok(crate::uot::UotDatagram::from_v2_stream(
            stream,
            request.destination,
        ))
    }
}

fn anytls_address(endpoint: &Endpoint) -> Result<AnyTlsAddress, TransitError> {
    if endpoint.host.is_empty()
        || (endpoint.port == 0 && endpoint.host != crate::uot::request_host(2))
    {
        return Err(unsupported("AnyTLS destination is invalid"));
    }
    if let Ok(address) = endpoint.host.parse::<IpAddr>() {
        return Ok(match address {
            IpAddr::V4(value) => AnyTlsAddress::Ipv4(value.octets(), endpoint.port),
            IpAddr::V6(value) => AnyTlsAddress::Ipv6(value.octets(), endpoint.port),
        });
    }
    Ok(AnyTlsAddress::Domain(endpoint.host.clone(), endpoint.port))
}

#[cfg(test)]
#[cfg(test)]
async fn open_stream_relay(
    mut stream: BoxedTransitConnection,
) -> Result<BoxedTransitConnection, TransitError> {
    let mut input = BytesMut::new();
    let mut buffer = [0_u8; 8192];
    loop {
        if input.len() > MAX_HANDSHAKE_BYTES {
            return Err(protocol("AnyTLS handshake exceeded the size bound"));
        }
        if let Some(frame) = AnyTlsFrame::decode(&mut input).map_err(protocol)? {
            match frame.command {
                AnyTlsCommand::SynAck if frame.stream_id == STREAM_ID => {
                    if !frame.payload.is_empty() {
                        return Err(protocol("AnyTLS peer rejected the stream"));
                    }
                    return Ok(spawn_stream_relay(stream, input));
                }
                AnyTlsCommand::Alert => return Err(protocol("AnyTLS peer rejected the stream")),
                AnyTlsCommand::HeartRequest => {
                    let response = heartbeat_response(frame.stream_id).map_err(protocol)?;
                    stream.write_all(&response).await.map_err(io_failure)?;
                    stream.flush().await.map_err(io_failure)?;
                }
                AnyTlsCommand::Fin if frame.stream_id == STREAM_ID => {
                    return Err(protocol("AnyTLS peer closed before SYNACK"));
                }
                _ => {}
            }
            continue;
        }
        let read = stream.read(&mut buffer).await.map_err(io_failure)?;
        if read == 0 {
            return Err(protocol("AnyTLS peer closed before SYNACK"));
        }
        input.extend_from_slice(&buffer[..read]);
    }
}

fn heartbeat_response(stream_id: u32) -> Result<BytesMut, &'static str> {
    let mut response = BytesMut::new();
    AnyTlsFrame {
        command: AnyTlsCommand::HeartResponse,
        stream_id,
        payload: bytes::Bytes::new(),
    }
    .encode(&mut response)?;
    Ok(response)
}

#[cfg(test)]
#[derive(Clone, Copy)]
#[cfg(test)]
enum RelayEnd {
    Closed,
    Alert,
}

#[cfg(test)]
#[cfg(test)]
struct RelayStream {
    client: DuplexStream,
    end: Arc<Mutex<Option<RelayEnd>>>,
}

#[cfg(test)]
#[cfg(test)]
impl AsyncRead for RelayStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if output.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        let before = output.filled().len();
        std::task::ready!(Pin::new(&mut self.client).poll_read(cx, output))?;
        if output.filled().len() == before
            && matches!(
                *self.end.lock().expect("relay state"),
                Some(RelayEnd::Alert)
            )
        {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "AnyTLS peer closed the session with ALERT",
            )));
        }
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
#[cfg(test)]
impl AsyncWrite for RelayStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.end.lock().expect("relay state").is_some() {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        Pin::new(&mut self.client).poll_write(cx, bytes)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.client).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.client).poll_shutdown(cx)
    }
}

#[cfg(test)]
#[cfg(test)]
fn spawn_stream_relay(
    stream: BoxedTransitConnection,
    mut input: BytesMut,
) -> BoxedTransitConnection {
    let (client, server) = tokio::io::duplex(MAX_FRAME_PAYLOAD * 2);
    let (mut client_read, mut client_write) = tokio::io::split(server);
    let (mut upstream_read, mut upstream_write) = tokio::io::split(stream);
    let (control_tx, mut control_rx) = mpsc::channel::<BytesMut>(8);
    let writer = tokio::spawn(async move {
        let mut data = vec![0_u8; MAX_FRAME_PAYLOAD];
        let mut control_open = true;
        loop {
            tokio::select! {
                result = client_read.read(&mut data) => {
                    let Ok(size) = result else { break; };
                    if size == 0 { break; }
                    let mut frame = BytesMut::new();
                    if (AnyTlsFrame { command: AnyTlsCommand::Push, stream_id: STREAM_ID, payload: bytes::Bytes::copy_from_slice(&data[..size]) }).encode(&mut frame).is_err() { break; }
                    if upstream_write.write_all(&frame).await.is_err()
                        || upstream_write.flush().await.is_err() { break; }
                }
                control = control_rx.recv(), if control_open => {
                    let Some(control) = control else {
                        control_open = false;
                        continue;
                    };
                    if upstream_write.write_all(&control).await.is_err()
                        || upstream_write.flush().await.is_err() { break; }
                }
            }
        }
        let mut fin = BytesMut::new();
        let _ = (AnyTlsFrame {
            command: AnyTlsCommand::Fin,
            stream_id: STREAM_ID,
            payload: bytes::Bytes::new(),
        })
        .encode(&mut fin);
        let _ = upstream_write.write_all(&fin).await;
        let _ = upstream_write.shutdown().await;
    });
    let end = Arc::new(Mutex::new(None));
    let peer_end = Arc::clone(&end);
    tokio::spawn(async move {
        let mut buffer = [0_u8; 8192];
        let reason = 'relay: loop {
            while let Ok(Some(frame)) = AnyTlsFrame::decode(&mut input) {
                match frame.command {
                    AnyTlsCommand::Push if frame.stream_id == STREAM_ID => {
                        if client_write.write_all(&frame.payload).await.is_err() {
                            // The caller dropped the stream. The writer still
                            // owns any pending upload and its local FIN.
                            return;
                        }
                    }
                    AnyTlsCommand::HeartRequest => {
                        if let Ok(response) = heartbeat_response(frame.stream_id) {
                            let _ = control_tx.send(response).await;
                        }
                    }
                    AnyTlsCommand::Fin if frame.stream_id == STREAM_ID => {
                        break 'relay RelayEnd::Closed;
                    }
                    AnyTlsCommand::Alert => {
                        break 'relay RelayEnd::Alert;
                    }
                    _ => {}
                }
            }
            let Ok(read) = upstream_read.read(&mut buffer).await else {
                break RelayEnd::Closed;
            };
            if read == 0 {
                break RelayEnd::Closed;
            }
            input.extend_from_slice(&buffer[..read]);
        };
        *peer_end.lock().expect("relay state") = Some(reason);
        writer.abort();
        let _ = client_write.shutdown().await;
    });
    Box::new(RelayStream { client, end })
}

fn unsupported(message: &str) -> TransitError {
    TransitError::Unsupported(message.to_owned())
}
fn protocol(message: &str) -> TransitError {
    TransitError::Protocol(message.to_owned())
}
fn io_failure(error: std::io::Error) -> TransitError {
    TransitError::Connection(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use pathchord_policy::{Endpoint as PolicyEndpoint, TransitOptions, TransitProxyId};
    use serde_json::json;
    use std::collections::{BTreeMap, BTreeSet};
    use std::path::PathBuf;
    use std::process::Stdio;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::process::Command;

    #[tokio::test]
    #[ignore = "requires PATHCHORD_TEST_SING_BOX pointing to sing-box 1.14.4"]
    async fn native_anytls_tcp_and_udp_interoperate_with_sing_box() {
        let binary =
            PathBuf::from(std::env::var_os("PATHCHORD_TEST_SING_BOX").expect("reference peer"));
        let password = "pathchord-anytls-password";
        let rcgen::CertifiedKey { cert, signing_key } =
            rcgen::generate_simple_self_signed(vec!["anytls.test".into()])
                .expect("test certificate");
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let document = json!({
            "log": {"disabled": true},
            "inbounds": [{
                "type": "anytls",
                "listen": "127.0.0.1",
                "listen_port": port,
                "users": [{"name": "pathchord", "password": password}],
                "udp_timeout": "5m",
                "tls": {"enabled": true, "certificate": cert.pem(), "key": signing_key.serialize_pem()}
            }],
            "outbounds": [{"type": "direct", "tag": "direct"}],
            "route": {"final": "direct"}
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
            .expect("start sing-box peer");
        peer.stdin
            .take()
            .expect("peer stdin")
            .write_all(serde_json::to_vec(&document).unwrap().as_slice())
            .await
            .unwrap();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .is_err()
        {
            assert!(
                tokio::time::Instant::now() < deadline,
                "AnyTLS peer readiness"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let target = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_address = target.local_addr().unwrap();
        let target_task = tokio::spawn(async move {
            let (mut stream, _) = target.accept().await.unwrap();
            let mut payload = [0_u8; 8192];
            loop {
                let length = stream.read(&mut payload).await.unwrap();
                if length == 0 {
                    break;
                }
                stream.write_all(&payload[..length]).await.unwrap();
            }
        });
        let config = pathchord_policy::TransitProxyConfig {
            id: TransitProxyId::new("anytls-test"),
            source: None,
            protocol: "anytls".into(),
            endpoint: PolicyEndpoint {
                host: "127.0.0.1".into(),
                port,
            },
            credentials_ref: None,
            labels: BTreeMap::new(),
            tags: BTreeSet::new(),
            weight: 100,
            options: TransitOptions {
                tls: Some(pathchord_policy::TransitTls {
                    enabled: true,
                    insecure: true,
                    server_name: Some("anytls.test".into()),
                    ..Default::default()
                }),
                ..Default::default()
            },
        };
        let credentials =
            TransitCredential::new(BTreeMap::from([("password".into(), password.into())]));
        let adapter = AnyTlsAdapter::from_config(
            &config,
            &credentials,
            Duration::from_secs(5),
            crate::adapter_registry::native_tls_roots(),
        )
        .unwrap();
        let mut stream = adapter
            .connect(ConnectRequest {
                destination: Endpoint {
                    host: "127.0.0.1".into(),
                    port: target_address.port(),
                },
            })
            .await
            .unwrap();
        for length in [7, 65_535, 65_536, 131_070, 131_071, 262_145] {
            let payload: Vec<_> = (0..length).map(|index| (index % 251) as u8).collect();
            let mut echoed = vec![0; length];
            let (mut read, mut write) = tokio::io::split(&mut stream);
            timeout(Duration::from_secs(5), async {
                tokio::try_join!(
                    async {
                        write.write_all(&payload).await?;
                        write.flush().await
                    },
                    read.read_exact(&mut echoed)
                )
            })
            .await
            .unwrap_or_else(|_| panic!("AnyTLS TCP echo timed out at {length} bytes"))
            .unwrap();
            assert_eq!(echoed, payload);
        }
        stream.shutdown().await.unwrap();
        timeout(Duration::from_secs(5), target_task)
            .await
            .unwrap()
            .unwrap();
        let udp_target = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let udp_address = udp_target.local_addr().unwrap();
        let udp_task = tokio::spawn(async move {
            let mut payload = [0_u8; 256];
            let (length, peer) = udp_target.recv_from(&mut payload).await.unwrap();
            udp_target.send_to(&payload[..length], peer).await.unwrap();
        });
        let mut datagram = adapter
            .connect_udp(ConnectRequest {
                destination: Endpoint {
                    host: "127.0.0.1".into(),
                    port: udp_address.port(),
                },
            })
            .await
            .unwrap();
        datagram.send(b"anytls-udp").await.unwrap();
        assert_eq!(datagram.receive().await.unwrap(), b"anytls-udp");
        datagram.close().await.unwrap();
        udp_task.await.unwrap();
        peer.kill().await.unwrap();
        peer.wait().await.unwrap();
    }

    #[tokio::test]
    async fn nonempty_synack_is_a_redacted_open_error() {
        let (upstream, mut peer) = tokio::io::duplex(256);
        let mut response = BytesMut::new();
        append_frame(&mut response, AnyTlsCommand::SynAck, b"private peer error");
        peer.write_all(&response).await.unwrap();

        let result = open_stream_relay(Box::new(upstream)).await;
        assert!(matches!(
            result,
            Err(TransitError::Protocol(reason)) if reason == "AnyTLS peer rejected the stream"
        ));
    }

    #[tokio::test]
    async fn heartbeat_reply_preserves_stream_id_before_and_after_synack() {
        let (upstream, mut peer) = tokio::io::duplex(256);
        let mut frames = BytesMut::new();
        append_frame(&mut frames, AnyTlsCommand::HeartRequest, b"ignored");
        append_frame(&mut frames, AnyTlsCommand::SynAck, b"");
        append_frame(&mut frames, AnyTlsCommand::HeartRequest, b"also ignored");
        peer.write_all(&frames).await.unwrap();
        let _relay = open_stream_relay(Box::new(upstream)).await.unwrap();

        let mut responses = [0; 14];
        timeout(Duration::from_secs(1), peer.read_exact(&mut responses))
            .await
            .unwrap()
            .unwrap();
        let mut responses = BytesMut::from(responses.as_slice());
        for _ in 0..2 {
            let response = AnyTlsFrame::decode(&mut responses).unwrap().unwrap();
            assert_eq!(response.command, AnyTlsCommand::HeartResponse);
            assert_eq!(response.stream_id, STREAM_ID);
            assert!(response.payload.is_empty());
        }
    }

    #[tokio::test]
    async fn peer_fin_and_alert_stop_writes_without_sending_fin_back() {
        for (command, payload) in [
            (AnyTlsCommand::Fin, b"".as_slice()),
            (AnyTlsCommand::Alert, b"private alert".as_slice()),
        ] {
            let (upstream, mut peer) = tokio::io::duplex(256);
            let mut frames = BytesMut::new();
            append_frame(&mut frames, AnyTlsCommand::SynAck, b"");
            append_frame(&mut frames, AnyTlsCommand::Push, b"reply");
            append_frame(&mut frames, command, payload);
            peer.write_all(&frames).await.unwrap();
            let mut relay = open_stream_relay(Box::new(upstream)).await.unwrap();

            let mut data = Vec::new();
            let result = timeout(Duration::from_secs(1), relay.read_to_end(&mut data))
                .await
                .unwrap();
            assert_eq!(data, b"reply");
            if command == AnyTlsCommand::Alert {
                let error = result.unwrap_err();
                assert_eq!(error.kind(), io::ErrorKind::ConnectionAborted);
                assert!(!error.to_string().contains("private alert"));
            } else {
                result.unwrap();
            }
            assert_eq!(
                relay.write_all(b"after close").await.unwrap_err().kind(),
                io::ErrorKind::BrokenPipe
            );
            let mut reply = Vec::new();
            timeout(Duration::from_secs(1), peer.read_to_end(&mut reply))
                .await
                .unwrap()
                .unwrap();
            assert!(reply.is_empty());
        }
    }

    #[tokio::test]
    async fn relay_preserves_complete_and_partial_frames_read_with_synack() {
        let (upstream, mut peer) = tokio::io::duplex(256);
        let mut response = BytesMut::new();
        append_frame(&mut response, AnyTlsCommand::SynAck, b"");
        append_frame(&mut response, AnyTlsCommand::Push, b"first");
        let split = response.len() + 3;
        append_frame(&mut response, AnyTlsCommand::Push, b"second");
        append_frame(&mut response, AnyTlsCommand::Fin, b"");
        let remainder = response.split_off(split);
        peer.write_all(&response).await.unwrap();

        let mut relay = open_stream_relay(Box::new(upstream)).await.unwrap();
        let mut first = [0; 5];
        timeout(Duration::from_secs(1), relay.read_exact(&mut first))
            .await
            .expect("the complete buffered frame needs no further socket reads")
            .unwrap();
        assert_eq!(&first, b"first");
        peer.write_all(&remainder).await.unwrap();
        let mut rest = Vec::new();
        timeout(Duration::from_secs(1), relay.read_to_end(&mut rest))
            .await
            .expect("the partial buffered frame should resume")
            .unwrap();
        assert_eq!(rest, b"second");
    }

    fn append_frame(output: &mut BytesMut, command: AnyTlsCommand, payload: &'static [u8]) {
        AnyTlsFrame {
            command,
            stream_id: STREAM_ID,
            payload: bytes::Bytes::from_static(payload),
        }
        .encode(output)
        .unwrap();
    }

    #[tokio::test]
    async fn buffered_relay_flushes_the_tail_after_two_maximum_frames() {
        let (upstream, mut peer) = tokio::io::duplex(16 * 1024);
        let buffered = tokio::io::BufWriter::with_capacity(16 * 1024, upstream);
        let stream = spawn_stream_relay(Box::new(buffered), BytesMut::new());
        let peer_task = tokio::spawn(async move {
            let mut input = BytesMut::new();
            let mut buffer = [0_u8; 8192];
            loop {
                while let Some(frame) = AnyTlsFrame::decode(&mut input).unwrap() {
                    if frame.command == AnyTlsCommand::Fin {
                        return;
                    }
                    assert_eq!(frame.command, AnyTlsCommand::Push);
                    let mut response = BytesMut::new();
                    frame.encode(&mut response).unwrap();
                    peer.write_all(&response).await.unwrap();
                }
                let count = peer.read(&mut buffer).await.unwrap();
                if count == 0 {
                    return;
                }
                input.extend_from_slice(&buffer[..count]);
            }
        });
        let payload: Vec<_> = (0..MAX_FRAME_PAYLOAD * 2 + 1)
            .map(|index| (index % 251) as u8)
            .collect();
        let mut echoed = vec![0; payload.len()];
        let (mut read, mut write) = tokio::io::split(stream);
        let result = timeout(Duration::from_secs(2), async {
            tokio::try_join!(
                async {
                    write.write_all(&payload).await?;
                    write.flush().await
                },
                read.read_exact(&mut echoed)
            )
        })
        .await;
        drop(read);
        drop(write);
        peer_task.abort();
        let _ = peer_task.await;
        result
            .expect("the final one-byte PUSH must reach a buffered peer without client shutdown")
            .unwrap();
        assert_eq!(echoed, payload);
    }

    #[tokio::test]
    async fn anytls_udp_over_tcp_uses_bounded_length_frames() {
        let (client, mut peer) = tokio::io::duplex(1024);
        let mut datagram = crate::uot::UotDatagram::from_v2_stream(
            Box::new(client),
            Endpoint {
                host: "127.0.0.1".into(),
                port: 53,
            },
        );
        datagram.send(b"request").await.unwrap();
        let mut header = [0_u8; 2];
        peer.read_exact(&mut header).await.unwrap();
        assert_eq!(u16::from_be_bytes(header), 7);
        let mut request = [0_u8; 7];
        peer.read_exact(&mut request).await.unwrap();
        assert_eq!(&request, b"request");
        // Ingress cancels a pending receive when another send is ready.
        for partial in [b"\x00".as_slice(), b"\x05re".as_slice()] {
            peer.write_all(partial).await.unwrap();
            tokio::select! {
                biased;
                result = datagram.receive() => panic!("incomplete UDP frame returned {result:?}"),
                () = std::future::ready(()) => {}
            }
        }
        peer.write_all(b"ply\x00\x04next").await.unwrap();
        assert_eq!(
            timeout(Duration::from_secs(1), datagram.receive())
                .await
                .unwrap()
                .unwrap(),
            b"reply"
        );
        assert_eq!(
            timeout(Duration::from_secs(1), datagram.receive())
                .await
                .unwrap()
                .unwrap(),
            b"next"
        );
        assert!(
            datagram
                .send(&vec![0_u8; u16::MAX as usize + 1])
                .await
                .is_err()
        );
    }
}
