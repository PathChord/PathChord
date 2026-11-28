//! Native AnyTLS single-stream adapter.
//!
//! Each Session serves one Stream at a time, then remains available to the
//! same node for either a TCP Stream or a UDP-over-TCP association.

use std::{
    io,
    net::IpAddr,
    pin::Pin,
    sync::{Arc, Mutex, Weak},
    task::{Context, Poll},
    time::Duration,
};

use async_trait::async_trait;
use bytes::{Bytes, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf};
use tokio::sync::{Mutex as AsyncMutex, oneshot};
use tokio::time::{Instant, timeout};
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

const FIRST_STREAM_ID: u32 = 1;
const MAX_IDLE_SESSIONS: usize = 8;
const IDLE_SESSION_TIMEOUT: Duration = Duration::from_secs(60);

pub(crate) struct AnyTlsAdapter {
    metadata: TransitMetadata,
    password: Zeroizing<String>,
    transport: NativeTransport,
    udp_enabled: bool,
    timeout: Duration,
    sessions: Arc<SessionPool>,
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
            sessions: Arc::new(SessionPool::default()),
            padding: Arc::new(Mutex::new(AnyTlsPaddingScheme::default_scheme())),
        })
    }

    async fn open(
        &self,
        destination: &Endpoint,
        eager_payload: Option<Bytes>,
    ) -> Result<BoxedTransitConnection, TransitError> {
        let destination = anytls_address(destination)?;
        timeout(self.timeout, async {
            let (reply, result) = oneshot::channel();
            let request = OpenRequest {
                destination,
                eager_payload,
                reply,
            };
            if let Err(request) = self.sessions.lease(request) {
                let mut stream = self.transport.connect().await?;
                let scheme = self.padding.lock().expect("AnyTLS padding state").clone();
                let mut padding = vec![0; packet_padding_target(&scheme, 0)?];
                getrandom::fill(&mut padding)
                    .map_err(|_| protocol("AnyTLS padding randomness failed"))?;
                let auth = authentication_record(&self.password, &padding).map_err(protocol)?;
                stream.write_all(&auth).await.map_err(io_failure)?;
                let session = Session::new(stream, scheme, Arc::clone(&self.padding));
                tokio::spawn(session.run(request, Arc::downgrade(&self.sessions)));
            }
            result
                .await
                .map_err(|_| protocol("AnyTLS Session open cancelled"))?
        })
        .await
        .map_err(|_| TransitError::Connection("AnyTLS session timed out".into()))?
    }
}

struct OpenRequest {
    destination: AnyTlsAddress,
    eager_payload: Option<Bytes>,
    reply: oneshot::Sender<Result<BoxedTransitConnection, TransitError>>,
}

#[derive(Default)]
struct SessionPool {
    idle: Mutex<Vec<(Instant, oneshot::Sender<OpenRequest>)>>,
}

impl SessionPool {
    fn lease(&self, mut request: OpenRequest) -> Result<(), OpenRequest> {
        let mut idle = self.idle.lock().expect("AnyTLS idle pool");
        while let Some((deadline, sender)) = idle.pop() {
            if Instant::now() < deadline {
                match sender.send(request) {
                    Ok(()) => return Ok(()),
                    Err(unsent) => request = unsent,
                }
            }
        }
        Err(request)
    }

    fn release(&self, deadline: Instant) -> oneshot::Receiver<OpenRequest> {
        let (sender, receiver) = oneshot::channel();
        let mut idle = self.idle.lock().expect("AnyTLS idle pool");
        idle.retain(|(_, sender)| !sender.is_closed());
        if idle.len() == MAX_IDLE_SESSIONS {
            idle.remove(0);
        }
        idle.push((deadline, sender));
        receiver
    }
}

struct FrameReader {
    upstream: tokio::io::ReadHalf<BoxedTransitConnection>,
    input: BytesMut,
}

impl FrameReader {
    async fn next(&mut self) -> Result<AnyTlsFrame, TransitError> {
        loop {
            if let Some(frame) = AnyTlsFrame::decode(&mut self.input).map_err(protocol)? {
                // Peers may attach opaque heartbeat data. The response is always empty.
                if frame.command != AnyTlsCommand::HeartRequest {
                    frame.validate().map_err(protocol)?;
                }
                return Ok(frame);
            }
            let mut chunk = [0; 8192];
            let size = self.upstream.read(&mut chunk).await.map_err(io_failure)?;
            if size == 0 {
                return Err(protocol("AnyTLS Session closed by peer"));
            }
            self.input.extend_from_slice(&chunk[..size]);
        }
    }
}

struct SessionWriter {
    upstream: tokio::io::WriteHalf<BoxedTransitConnection>,
    scheme: AnyTlsPaddingScheme,
    packet: u32,
    // A cancelled partial write leaves the transport unsuitable for reuse.
    writing: bool,
}

impl SessionWriter {
    async fn write(&mut self, mut data: BytesMut) -> Result<(), TransitError> {
        self.packet = self.packet.saturating_add(1);
        let target = packet_padding_target(&self.scheme, self.packet)?;
        while target.saturating_sub(data.len()) >= crate::anytls_codec::FRAME_HEADER_LEN {
            let length = (target - data.len() - crate::anytls_codec::FRAME_HEADER_LEN)
                .min(MAX_FRAME_PAYLOAD);
            encode_frame(
                &mut data,
                AnyTlsCommand::Waste,
                0,
                Bytes::from(vec![0; length]),
            )?;
        }
        self.write_bytes(&data).await
    }

    async fn write_bytes(&mut self, data: &[u8]) -> Result<(), TransitError> {
        self.writing = true;
        self.upstream.write_all(data).await.map_err(io_failure)?;
        self.upstream.flush().await.map_err(io_failure)?;
        self.writing = false;
        Ok(())
    }

    async fn frame(
        &mut self,
        command: AnyTlsCommand,
        id: u32,
        payload: Bytes,
    ) -> Result<(), TransitError> {
        let mut data = BytesMut::new();
        encode_frame(&mut data, command, id, payload)?;
        if command == AnyTlsCommand::Push {
            self.write(data).await
        } else {
            self.write_bytes(&data).await
        }
    }
}

fn packet_padding_target(scheme: &AnyTlsPaddingScheme, packet: u32) -> Result<usize, TransitError> {
    for rule in scheme.rules(packet) {
        if let Some(size) = AnyTlsPaddingScheme::sample_size(*rule).map_err(protocol)? {
            return Ok(size);
        }
    }
    Ok(0)
}

fn encode_frame(
    data: &mut BytesMut,
    command: AnyTlsCommand,
    stream_id: u32,
    payload: Bytes,
) -> Result<(), TransitError> {
    AnyTlsFrame {
        command,
        stream_id,
        payload,
    }
    .encode(data)
    .map_err(protocol)
}

struct Session {
    reader: FrameReader,
    writer: AsyncMutex<SessionWriter>,
    node_padding: Arc<Mutex<AnyTlsPaddingScheme>>,
}

impl Session {
    fn new(
        stream: BoxedTransitConnection,
        scheme: AnyTlsPaddingScheme,
        node_padding: Arc<Mutex<AnyTlsPaddingScheme>>,
    ) -> Self {
        let (read, write) = tokio::io::split(stream);
        Self {
            reader: FrameReader {
                upstream: read,
                input: BytesMut::new(),
            },
            writer: AsyncMutex::new(SessionWriter {
                upstream: write,
                scheme,
                packet: 0,
                writing: false,
            }),
            node_padding,
        }
    }

    async fn run(mut self, mut request: OpenRequest, pool: Weak<SessionPool>) {
        let mut stream_id = FIRST_STREAM_ID;
        loop {
            let OpenRequest {
                destination,
                eager_payload,
                mut reply,
            } = request;
            let handshake = tokio::select! {
                result = self.handshake(stream_id, destination, eager_payload) => result,
                () = reply.closed() => return,
            };
            if let Err(error) = handshake {
                let _ = reply.send(Err(error));
                return;
            }
            let (client, server) = tokio::io::duplex(MAX_FRAME_PAYLOAD * 2);
            let end = Arc::new(Mutex::new(None));
            if reply
                .send(Ok(Box::new(RelayStream {
                    client,
                    end: Arc::clone(&end),
                })))
                .is_err()
            {
                return;
            }
            let healthy = self.relay(stream_id, server, &end).await;
            if !healthy || self.writer.get_mut().writing {
                return;
            }
            let Some(next_id) = stream_id.checked_add(1) else {
                return;
            };
            let Some(next) = self.wait_for_lease(&pool).await else {
                return;
            };
            stream_id = next_id;
            request = next;
        }
    }

    async fn handshake(
        &mut self,
        stream_id: u32,
        destination: AnyTlsAddress,
        eager_payload: Option<Bytes>,
    ) -> Result<(), TransitError> {
        let writer = self.writer.get_mut();
        let mut initial = BytesMut::new();
        if writer.packet == 0 {
            let settings = AnyTlsSettings::official_client(&writer.scheme)
                .encode()
                .map_err(protocol)?;
            encode_frame(&mut initial, AnyTlsCommand::Settings, 0, settings)?;
        }
        let mut address = BytesMut::new();
        destination.encode(&mut address).map_err(protocol)?;
        encode_frame(&mut initial, AnyTlsCommand::Syn, stream_id, Bytes::new())?;
        encode_frame(
            &mut initial,
            AnyTlsCommand::Push,
            stream_id,
            address.freeze(),
        )?;
        if let Some(payload) = eager_payload {
            encode_frame(&mut initial, AnyTlsCommand::Push, stream_id, payload)?;
        }
        writer.write(initial).await?;
        loop {
            let frame = self.reader.next().await?;
            match frame.command {
                AnyTlsCommand::SynAck if frame.stream_id == stream_id => {
                    return if frame.payload.is_empty() {
                        Ok(())
                    } else {
                        Err(protocol("AnyTLS peer rejected the stream"))
                    };
                }
                AnyTlsCommand::Fin if frame.stream_id == stream_id => {
                    return Err(protocol("AnyTLS peer closed before SYNACK"));
                }
                _ => handle_control(&self.writer, &self.node_padding, frame).await?,
            }
        }
    }

    async fn relay(
        &mut self,
        stream_id: u32,
        mut server: DuplexStream,
        end: &Mutex<Option<RelayEnd>>,
    ) -> bool {
        let (mut upload, mut download) = tokio::io::split(&mut server);
        let receive = async {
            loop {
                let frame = self.reader.next().await?;
                match frame.command {
                    AnyTlsCommand::Push if frame.stream_id == stream_id => {
                        // If the caller dropped the stream, its buffered upload still owns its FIN.
                        let _ = download.write_all(&frame.payload).await;
                    }
                    AnyTlsCommand::Fin if frame.stream_id == stream_id => return Ok(()),
                    _ => handle_control(&self.writer, &self.node_padding, frame).await?,
                }
            }
        };
        let send = async {
            let mut buffer = [0; 8192];
            loop {
                let size = upload.read(&mut buffer).await.map_err(io_failure)?;
                let mut writer = self.writer.lock().await;
                if size == 0 {
                    return writer
                        .frame(AnyTlsCommand::Fin, stream_id, Bytes::new())
                        .await;
                }
                writer
                    .frame(
                        AnyTlsCommand::Push,
                        stream_id,
                        Bytes::copy_from_slice(&buffer[..size]),
                    )
                    .await?;
            }
        };
        let result = tokio::select! {
            biased;
            result = receive => result,
            result = send => result,
        };
        *end.lock().expect("AnyTLS relay state") = Some(if result.is_ok() {
            RelayEnd::Closed
        } else {
            RelayEnd::Failed
        });
        result.is_ok()
    }

    async fn wait_for_lease(&mut self, pool: &Weak<SessionPool>) -> Option<OpenRequest> {
        let deadline = Instant::now() + IDLE_SESSION_TIMEOUT;
        let mut lease = pool.upgrade()?.release(deadline);
        let request = tokio::time::timeout_at(deadline, &mut lease)
            .await
            .ok()
            .and_then(Result::ok);
        drop(lease);
        if let Some(pool) = pool.upgrade() {
            pool.idle
                .lock()
                .expect("AnyTLS idle pool")
                .retain(|(_, sender)| !sender.is_closed());
        }
        request
    }
}

async fn handle_control(
    writer: &AsyncMutex<SessionWriter>,
    node_padding: &Mutex<AnyTlsPaddingScheme>,
    frame: AnyTlsFrame,
) -> Result<(), TransitError> {
    match frame.command {
        AnyTlsCommand::HeartRequest => {
            writer
                .lock()
                .await
                .frame(AnyTlsCommand::HeartResponse, frame.stream_id, Bytes::new())
                .await?
        }
        AnyTlsCommand::UpdatePaddingScheme => {
            let scheme = AnyTlsPaddingScheme::parse(&frame.payload).map_err(protocol)?;
            *node_padding.lock().expect("AnyTLS padding state") = scheme;
        }
        AnyTlsCommand::ServerSettings => {
            let settings = AnyTlsSettings::decode(&frame.payload).map_err(protocol)?;
            if settings.protocol_version().map_err(protocol)? < 2 {
                return Err(protocol("AnyTLS server protocol version is unsupported"));
            }
        }
        AnyTlsCommand::Alert => return Err(protocol("AnyTLS peer sent ALERT")),
        _ => {}
    }
    Ok(())
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

#[derive(Clone, Copy)]
enum RelayEnd {
    Closed,
    Failed,
}

struct RelayStream {
    client: DuplexStream,
    end: Arc<Mutex<Option<RelayEnd>>>,
}

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
                Some(RelayEnd::Failed)
            )
        {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "AnyTLS Session failed",
            )));
        }
        Poll::Ready(Ok(()))
    }
}

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

    fn test_request() -> (
        OpenRequest,
        oneshot::Receiver<Result<BoxedTransitConnection, TransitError>>,
    ) {
        let (reply, result) = oneshot::channel();
        (
            OpenRequest {
                destination: AnyTlsAddress::Ipv4([127, 0, 0, 1], 80),
                eager_payload: None,
                reply,
            },
            result,
        )
    }

    fn start_session(
        upstream: BoxedTransitConnection,
    ) -> (
        Arc<SessionPool>,
        oneshot::Receiver<Result<BoxedTransitConnection, TransitError>>,
    ) {
        let pool = Arc::new(SessionPool::default());
        let scheme = AnyTlsPaddingScheme::parse(b"stop=1\n0=1-1").unwrap();
        let session = Session::new(upstream, scheme.clone(), Arc::new(Mutex::new(scheme)));
        let (request, result) = test_request();
        tokio::spawn(session.run(request, Arc::downgrade(&pool)));
        (pool, result)
    }

    async fn read_peer_frame(peer: &mut DuplexStream) -> AnyTlsFrame {
        timeout(Duration::from_secs(2), async {
            let mut header = [0; 7];
            peer.read_exact(&mut header).await.unwrap();
            let length = u16::from_be_bytes([header[5], header[6]]) as usize;
            let mut input = BytesMut::from(header.as_slice());
            input.resize(7 + length, 0);
            peer.read_exact(&mut input[7..]).await.unwrap();
            AnyTlsFrame::decode(&mut input).unwrap().unwrap()
        })
        .await
        .expect("worker writes a complete frame")
    }

    async fn read_open(peer: &mut DuplexStream, id: u32) {
        if id == FIRST_STREAM_ID {
            assert_eq!(read_peer_frame(peer).await.command, AnyTlsCommand::Settings);
        }
        for expected in [AnyTlsCommand::Syn, AnyTlsCommand::Push] {
            let frame = read_peer_frame(peer).await;
            assert_eq!((frame.command, frame.stream_id), (expected, id));
        }
    }

    #[tokio::test]
    async fn pool_evicts_oldest_leases_newest_and_skips_expired_sessions() {
        let pool = SessionPool::default();
        let mut oldest = pool.release(Instant::now() + IDLE_SESSION_TIMEOUT);
        let mut retained = (0..MAX_IDLE_SESSIONS)
            .map(|_| pool.release(Instant::now() + IDLE_SESSION_TIMEOUT))
            .collect::<Vec<_>>();
        assert!(matches!(
            oldest.try_recv(),
            Err(oneshot::error::TryRecvError::Closed)
        ));
        let newest = retained.pop().unwrap();
        assert!(pool.lease(test_request().0).is_ok());
        assert!(newest.await.is_ok());
        drop(retained);
        let expired = pool.release(Instant::now());
        assert!(pool.lease(test_request().0).is_err());
        assert!(expired.await.is_err());
    }

    #[tokio::test]
    async fn cancelled_open_retires_the_session_while_waiting_for_synack() {
        let (upstream, mut peer) = tokio::io::duplex(1024);
        let (pool, result) = start_session(Box::new(upstream));
        read_open(&mut peer, 1).await;
        drop(result);
        let mut tail = Vec::new();
        timeout(Duration::from_secs(1), peer.read_to_end(&mut tail))
            .await
            .unwrap()
            .unwrap();
        assert!(tail.is_empty());
        assert!(pool.lease(test_request().0).is_err());
    }

    #[tokio::test]
    async fn nonempty_synack_is_a_redacted_open_error() {
        let (upstream, mut peer) = tokio::io::duplex(256);
        let mut response = BytesMut::new();
        append_frame(&mut response, AnyTlsCommand::SynAck, b"private peer error");
        peer.write_all(&response).await.unwrap();

        let (_pool, result) = start_session(Box::new(upstream));
        let result = result.await.unwrap();
        assert!(matches!(
            result,
            Err(TransitError::Protocol(reason)) if reason == "AnyTLS peer rejected the stream"
        ));
    }

    #[tokio::test]
    async fn heartbeat_reply_preserves_stream_id_before_and_after_synack() {
        let (upstream, mut peer) = tokio::io::duplex(256);
        let mut frames = BytesMut::new();
        append_frame(&mut frames, AnyTlsCommand::HeartRequest, b"opaque");
        append_frame(&mut frames, AnyTlsCommand::SynAck, b"");
        append_frame(&mut frames, AnyTlsCommand::HeartRequest, b"opaque");
        peer.write_all(&frames).await.unwrap();
        let (_pool, result) = start_session(Box::new(upstream));
        read_open(&mut peer, FIRST_STREAM_ID).await;
        let _relay = result.await.unwrap().unwrap();

        let mut responses = [0; 14];
        timeout(Duration::from_secs(1), peer.read_exact(&mut responses))
            .await
            .unwrap()
            .unwrap();
        let mut responses = BytesMut::from(responses.as_slice());
        for _ in 0..2 {
            let response = AnyTlsFrame::decode(&mut responses).unwrap().unwrap();
            assert_eq!(response.command, AnyTlsCommand::HeartResponse);
            assert_eq!(response.stream_id, FIRST_STREAM_ID);
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
            let (pool, result) = start_session(Box::new(upstream));
            read_open(&mut peer, FIRST_STREAM_ID).await;
            let mut relay = result.await.unwrap().unwrap();

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
            drop(pool);
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

        let (_pool, result) = start_session(Box::new(upstream));
        let mut relay = result.await.unwrap().unwrap();
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
            stream_id: FIRST_STREAM_ID,
            payload: bytes::Bytes::from_static(payload),
        }
        .encode(output)
        .unwrap();
    }

    #[tokio::test]
    async fn buffered_relay_flushes_the_tail_after_two_maximum_frames() {
        let (upstream, mut peer) = tokio::io::duplex(16 * 1024);
        let buffered = tokio::io::BufWriter::with_capacity(16 * 1024, upstream);
        let (_pool, result) = start_session(Box::new(buffered));
        let peer_task = tokio::spawn(async move {
            read_open(&mut peer, FIRST_STREAM_ID).await;
            let mut ack = BytesMut::new();
            append_frame(&mut ack, AnyTlsCommand::SynAck, b"");
            peer.write_all(&ack).await.unwrap();
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
        let stream = result.await.unwrap().unwrap();
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
