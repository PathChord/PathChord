//! Narrow native Hysteria2 TCP adapter built directly on Quinn and h3.
//!
//! This owns one QUIC connection per opened TCP stream and intentionally leaves
//! Hysteria2 UDP relay, port hopping, and obfuscation to the codec layer until
//! independent peer fixtures cover those lifecycles.

use std::sync::Arc;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use std::{
    io,
    io::IoSliceMut,
    pin::Pin,
    task::{Context, Poll},
};

use async_trait::async_trait;
use bytes::Bytes;
use http::Request;
use quinn::crypto::rustls::QuicClientConfig;
use quinn::udp::{RecvMeta, Transmit};
use quinn::{
    AsyncUdpSocket, ClientConfig, Endpoint, EndpointConfig, RecvStream, Runtime, SendStream,
    TokioRuntime, TransportConfig, UdpPoller,
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::time::timeout;

use crate::hysteria2_codec::AuthHeaders;
use crate::{
    AdapterKind, BoxedTransitConnection, ConnectRequest, Endpoint as TransitEndpoint,
    TransitAdapter, TransitCredential, TransitError, TransitMetadata,
};

pub(crate) struct Hysteria2Adapter {
    metadata: TransitMetadata,
    endpoint: TransitEndpoint,
    password: String,
    obfs_password: Option<String>,
    hop_ports: Option<Vec<u16>>,
    hop_interval: Option<Duration>,
    tls: Arc<rustls::ClientConfig>,
    connect_timeout: Duration,
    udp_enabled: bool,
}

impl std::fmt::Debug for Hysteria2Adapter {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Hysteria2Adapter")
            .field("metadata", &self.metadata)
            .finish_non_exhaustive()
    }
}

#[derive(Debug)]
struct SalamanderSocket {
    inner: Arc<dyn AsyncUdpSocket>,
    password: Option<Vec<u8>>,
    canonical: std::net::SocketAddr,
    hop_ports: Vec<u16>,
    hop_interval: Option<Duration>,
    hop_state: Mutex<(usize, Instant)>,
}

fn parse_hop_ports(value: &str) -> Result<Vec<u16>, TransitError> {
    let mut ports = Vec::new();
    for part in value
        .split(',')
        .map(str::trim)
        .filter(|part| !part.is_empty())
    {
        if let Some((start, end)) = part.split_once('-') {
            let start = start.parse::<u16>().map_err(|_| {
                TransitError::Unsupported("Hysteria2 server_ports is invalid".into())
            })?;
            let end = end.parse::<u16>().map_err(|_| {
                TransitError::Unsupported("Hysteria2 server_ports is invalid".into())
            })?;
            if start == 0 || end == 0 || start > end || usize::from(end - start) > 256 {
                return Err(TransitError::Unsupported(
                    "Hysteria2 server_ports is invalid".into(),
                ));
            }
            ports.extend(start..=end);
        } else {
            let port = part.parse::<u16>().map_err(|_| {
                TransitError::Unsupported("Hysteria2 server_ports is invalid".into())
            })?;
            if port == 0 {
                return Err(TransitError::Unsupported(
                    "Hysteria2 server_ports is invalid".into(),
                ));
            }
            ports.push(port);
        }
    }
    ports.sort_unstable();
    ports.dedup();
    if ports.is_empty() || ports.len() > 256 {
        return Err(TransitError::Unsupported(
            "Hysteria2 server_ports is invalid".into(),
        ));
    }
    Ok(ports)
}

fn parse_hop_interval(value: &str) -> Result<Duration, TransitError> {
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
        .ok_or_else(|| TransitError::Unsupported("Hysteria2 hop_interval is invalid".into()))?;
    Ok(Duration::from_millis(millis))
}

impl SalamanderSocket {
    fn new(
        inner: Arc<dyn AsyncUdpSocket>,
        password: Option<&str>,
        canonical: std::net::SocketAddr,
        hop_ports: Vec<u16>,
        hop_interval: Option<Duration>,
    ) -> Self {
        Self {
            inner,
            password: password.map(|value| value.as_bytes().to_vec()),
            canonical,
            hop_ports,
            hop_interval,
            hop_state: Mutex::new((0, Instant::now())),
        }
    }

    fn destination(&self, original: std::net::SocketAddr) -> std::net::SocketAddr {
        if self.hop_ports.is_empty() {
            return original;
        }
        let Ok(mut state) = self.hop_state.lock() else {
            return original;
        };
        if self
            .hop_interval
            .is_some_and(|interval| state.1.elapsed() < interval)
        {
            return std::net::SocketAddr::new(original.ip(), self.hop_ports[state.0]);
        }
        let index = state.0 % self.hop_ports.len();
        state.0 = (index + 1) % self.hop_ports.len();
        state.1 = Instant::now();
        std::net::SocketAddr::new(original.ip(), self.hop_ports[index])
    }
}

impl AsyncUdpSocket for SalamanderSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        self.inner.clone().create_io_poller()
    }

    fn try_send(&self, transmit: &Transmit<'_>) -> io::Result<()> {
        if transmit.segment_size.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Hysteria2 Salamander does not support UDP segmentation",
            ));
        }
        let mut salt = [0_u8; 8];
        getrandom::fill(&mut salt)
            .map_err(|_| io::Error::other("Hysteria2 Salamander salt generation failed"))?;
        let encrypted = match &self.password {
            Some(password) => {
                crate::hysteria2_codec::salamander_encode(password, transmit.contents, salt)
            }
            None => transmit.contents.to_vec(),
        };
        let transformed = Transmit {
            destination: self.destination(transmit.destination),
            ecn: transmit.ecn,
            contents: &encrypted,
            segment_size: None,
            src_ip: transmit.src_ip,
        };
        self.inner.try_send(&transformed)
    }

    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        const MAX_DATAGRAM: usize = 64 * 1024;
        let count = bufs.len().min(meta.len());
        let mut storage = vec![0_u8; count * MAX_DATAGRAM];
        let mut scratch = storage
            .chunks_mut(MAX_DATAGRAM)
            .map(IoSliceMut::new)
            .collect::<Vec<_>>();
        let mut scratch_meta = vec![RecvMeta::default(); count];
        let received = match self.inner.poll_recv(cx, &mut scratch, &mut scratch_meta) {
            Poll::Ready(Ok(value)) => value,
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Pending => return Poll::Pending,
        };
        drop(scratch);
        let mut output = 0;
        for (index, metadata) in scratch_meta.iter().enumerate().take(received) {
            let raw_start = index * MAX_DATAGRAM;
            let raw_end = raw_start.saturating_add(metadata.len).min(storage.len());
            let plain = match &self.password {
                Some(password) => {
                    let Some(value) = crate::hysteria2_codec::salamander_decode(
                        password,
                        &storage[raw_start..raw_end],
                    ) else {
                        continue;
                    };
                    value
                }
                None => storage[raw_start..raw_end].to_vec(),
            };
            if plain.len() > bufs[output].len() {
                continue;
            }
            bufs[output][..plain.len()].copy_from_slice(&plain);
            meta[output] = RecvMeta {
                addr: if self.hop_ports.is_empty() {
                    metadata.addr
                } else {
                    self.canonical
                },
                len: plain.len(),
                stride: plain.len(),
                ecn: metadata.ecn,
                dst_ip: metadata.dst_ip,
            };
            output += 1;
        }
        Poll::Ready(Ok(output))
    }

    fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
        self.inner.local_addr()
    }

    fn max_transmit_segments(&self) -> usize {
        1
    }

    fn max_receive_segments(&self) -> usize {
        1
    }

    fn may_fragment(&self) -> bool {
        false
    }
}

impl Hysteria2Adapter {
    pub fn from_config(
        config: &pathchord_policy::TransitProxyConfig,
        credential: &TransitCredential,
        timeout: Duration,
        base_tls: Arc<rustls::ClientConfig>,
    ) -> Result<Self, TransitError> {
        if config.protocol != "hysteria2" {
            return Err(TransitError::Unsupported(
                "Hysteria2 adapter requires protocol hysteria2".into(),
            ));
        }
        let mut allowed = vec![
            "password",
            "auth",
            "obfs",
            "obfs_password",
            "server_ports",
            "hop_interval",
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
        crate::adapter_registry::validate_native_options(config, true, false, true)?;
        if let (Some(password), Some(auth)) =
            (credential.field("password"), credential.field("auth"))
            && password != auth
        {
            return Err(TransitError::Unsupported(
                "Hysteria2 authentication aliases conflict".into(),
            ));
        }
        let password = credential
            .field("password")
            .or_else(|| credential.field("auth"))
            .ok_or_else(|| TransitError::Unsupported("Hysteria2 password is missing".into()))?;
        if password.is_empty() || password.len() > 1024 {
            return Err(TransitError::Unsupported(
                "Hysteria2 password is invalid".into(),
            ));
        }
        let obfs_password = credential.field("obfs_password").map(str::to_owned);
        if let Some(obfs) = credential.field("obfs")
            && obfs != "salamander"
        {
            return Err(TransitError::Unsupported(
                "Hysteria2 only supports Salamander obfuscation".into(),
            ));
        }
        if obfs_password
            .as_deref()
            .is_some_and(|value| value.len() < 4)
        {
            return Err(TransitError::Unsupported(
                "Hysteria2 Salamander password is too short".into(),
            ));
        }
        let hop_ports = credential
            .field("server_ports")
            .map(parse_hop_ports)
            .transpose()?;
        let hop_interval = credential
            .field("hop_interval")
            .map(parse_hop_interval)
            .transpose()?
            .or_else(|| hop_ports.as_ref().map(|_| Duration::from_secs(30)));
        if hop_interval.is_some() && hop_ports.is_none() {
            return Err(TransitError::Unsupported(
                "Hysteria2 hop_interval requires server_ports".into(),
            ));
        }
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
            return Err(TransitError::Unsupported("Hysteria2 requires TLS".into()));
        }
        let tls = crate::tls::configure(base_tls, Some(&tls_options), Some(credential))?;
        Ok(Self {
            metadata: TransitMetadata {
                adapter_id: config.id.as_str().to_owned(),
                kind: AdapterKind::ExternalProxy {
                    protocol: "hysteria2".into(),
                },
                labels: config.labels.clone(),
            },
            endpoint: crate::Endpoint {
                host: config.endpoint.host.clone(),
                port: config.endpoint.port,
            },
            password: password.to_owned(),
            obfs_password,
            hop_ports,
            hop_interval,
            tls,
            connect_timeout: timeout,
            udp_enabled: config.options.udp != Some(false),
        })
    }

    async fn connect_session(&self) -> Result<quinn::Connection, TransitError> {
        let address = timeout(
            self.connect_timeout,
            tokio::net::lookup_host((self.endpoint.host.as_str(), self.endpoint.port)),
        )
        .await
        .map_err(|_| TransitError::Connection("Hysteria2 endpoint resolution timed out".into()))?
        .map_err(|_| TransitError::Connection("Hysteria2 endpoint resolution failed".into()))?
        .collect::<Vec<_>>();
        let address = address
            .into_iter()
            .next()
            .ok_or_else(|| TransitError::Connection("Hysteria2 endpoint did not resolve".into()))?;
        let server_name = self.endpoint.host.clone();
        let mut config = ClientConfig::new(Arc::new(
            QuicClientConfig::try_from((*self.tls).clone())
                .map_err(|_| TransitError::Unsupported("Hysteria2 TLS config is invalid".into()))?,
        ));
        let mut transport = TransportConfig::default();
        transport.datagram_receive_buffer_size(Some(4 * 1024 * 1024));
        transport.datagram_send_buffer_size(4 * 1024 * 1024);
        config.transport_config(Arc::new(transport));
        let bind = if address.is_ipv6() {
            "[::]:0"
        } else {
            "0.0.0.0:0"
        };
        let runtime: Arc<dyn Runtime> = Arc::new(TokioRuntime);
        let std_socket =
            std::net::UdpSocket::bind(bind.parse::<std::net::SocketAddr>().map_err(|_| {
                TransitError::Connection("Hysteria2 local QUIC bind failed".into())
            })?)
            .map_err(|_| TransitError::Connection("Hysteria2 QUIC socket failed".into()))?;
        let inner = runtime
            .wrap_udp_socket(std_socket)
            .map_err(|_| TransitError::Connection("Hysteria2 QUIC socket failed".into()))?;
        let socket: Arc<dyn AsyncUdpSocket> = match (&self.obfs_password, &self.hop_ports) {
            (Some(password), Some(ports)) => Arc::new(SalamanderSocket::new(
                inner,
                Some(password),
                address,
                ports.clone(),
                self.hop_interval,
            )),
            (Some(password), None) => Arc::new(SalamanderSocket::new(
                inner,
                Some(password),
                address,
                Vec::new(),
                None,
            )),
            (None, Some(ports)) => Arc::new(SalamanderSocket::new(
                inner,
                None,
                address,
                ports.clone(),
                self.hop_interval,
            )),
            (None, None) => inner,
        };
        let mut endpoint =
            Endpoint::new_with_abstract_socket(EndpointConfig::default(), None, socket, runtime)
                .map_err(|_| TransitError::Connection("Hysteria2 QUIC endpoint failed".into()))?;
        endpoint.set_default_client_config(config);
        let connection = timeout(
            self.connect_timeout,
            endpoint
                .connect(address, &server_name)
                .map_err(|_| TransitError::Connection("Hysteria2 QUIC connect failed".into()))?,
        )
        .await
        .map_err(|_| TransitError::Connection("Hysteria2 QUIC handshake timed out".into()))?
        .map_err(|_| TransitError::Connection("Hysteria2 QUIC handshake failed".into()))?;
        // Keep the endpoint alive until the QUIC connection closes without
        // leaking it for the lifetime of the process.
        let keepalive = connection.clone();
        tokio::spawn(async move {
            keepalive.closed().await;
            drop(endpoint);
        });
        Ok(connection)
    }

    async fn authenticate(&self, connection: &quinn::Connection) -> Result<bool, TransitError> {
        let h3_connection = h3_quinn::Connection::new(connection.clone());
        let (_driver, mut sender) = h3::client::new(h3_connection)
            .await
            .map_err(|_| TransitError::Protocol("Hysteria2 HTTP/3 setup failed".into()))?;
        let auth = AuthHeaders {
            password: self.password.clone(),
            receive_bps: 0,
            padding: "a".repeat(crate::hysteria2_codec::AUTH_PADDING_MIN),
        };
        let fields = auth
            .fields()
            .map_err(|message| TransitError::Unsupported(message.into()))?;
        let http_request = Request::builder()
            .method("POST")
            .uri("https://hysteria/auth")
            .header("hysteria-auth", fields[0].1.as_str())
            .header("hysteria-cc-rx", fields[1].1.as_str())
            .header("hysteria-padding", fields[2].1.as_str())
            .body(())
            .map_err(|_| TransitError::Protocol("Hysteria2 auth request invalid".into()))?;
        let mut auth_stream = sender
            .send_request(http_request)
            .await
            .map_err(|_| TransitError::Protocol("Hysteria2 auth request failed".into()))?;
        auth_stream
            .finish()
            .await
            .map_err(|_| TransitError::Protocol("Hysteria2 auth request finish failed".into()))?;
        let response = auth_stream
            .recv_response()
            .await
            .map_err(|_| TransitError::Protocol("Hysteria2 auth response failed".into()))?;
        if response.status().as_u16() != 233 {
            return Err(TransitError::Protocol(
                "Hysteria2 authentication rejected".into(),
            ));
        }
        Ok(response
            .headers()
            .get("hysteria-udp")
            .and_then(|value| value.to_str().ok())
            == Some("true"))
    }
}

#[async_trait]
impl TransitAdapter for Hysteria2Adapter {
    fn metadata(&self) -> &TransitMetadata {
        &self.metadata
    }

    async fn connect(
        &self,
        request: ConnectRequest,
    ) -> Result<BoxedTransitConnection, TransitError> {
        crate::validate_destination(&request.destination)?;
        let connection = self.connect_session().await?;
        self.authenticate(&connection).await?;
        let destination = format!("{}:{}", request.destination.host, request.destination.port);
        let (mut send, recv) = connection
            .open_bi()
            .await
            .map_err(|_| TransitError::Connection("Hysteria2 TCP stream open failed".into()))?;
        send.write_all(
            &crate::hysteria2_codec::encode_tcp_request(&destination, &[])
                .map_err(|message| TransitError::Unsupported(message.into()))?,
        )
        .await
        .map_err(|_| TransitError::Connection("Hysteria2 TCP request failed".into()))?;
        Ok(Box::new(Hysteria2Stream {
            send,
            recv,
            response_done: false,
            response_buffer: Vec::new(),
            leftover: Vec::new(),
            leftover_pos: 0,
        }))
    }

    fn supports_udp(&self) -> bool {
        self.udp_enabled
    }

    async fn connect_udp(
        &self,
        request: ConnectRequest,
    ) -> Result<crate::BoxedTransitDatagram, TransitError> {
        if !self.udp_enabled {
            return Err(TransitError::Unsupported(
                "Hysteria2 UDP is disabled".into(),
            ));
        }
        crate::validate_destination(&request.destination)?;
        let connection = self.connect_session().await?;
        if !self.authenticate(&connection).await? {
            return Err(TransitError::Unsupported(
                "Hysteria2 server did not advertise UDP relay".into(),
            ));
        }
        let mut id_bytes = [0_u8; 4];
        getrandom::fill(&mut id_bytes).map_err(|_| {
            TransitError::Connection("Hysteria2 session id generation failed".into())
        })?;
        Ok(Box::new(Hysteria2Datagram {
            connection,
            session_id: u32::from_be_bytes(id_bytes),
            packet_id: 0,
            destination: format!("{}:{}", request.destination.host, request.destination.port),
        }))
    }
}

struct Hysteria2Stream {
    send: SendStream,
    recv: RecvStream,
    response_done: bool,
    response_buffer: Vec<u8>,
    leftover: Vec<u8>,
    leftover_pos: usize,
}

struct Hysteria2Datagram {
    connection: quinn::Connection,
    session_id: u32,
    packet_id: u16,
    destination: String,
}

impl std::fmt::Debug for Hysteria2Datagram {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Hysteria2Datagram")
            .field("session_id", &self.session_id)
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl crate::TransitDatagram for Hysteria2Datagram {
    async fn send(&mut self, payload: &[u8]) -> Result<(), TransitError> {
        let packet = crate::hysteria2_codec::UdpMessage {
            session_id: self.session_id,
            packet_id: self.packet_id,
            fragment_id: 0,
            fragment_count: 1,
            address: self.destination.clone(),
            payload: payload.to_vec(),
        };
        self.packet_id = self.packet_id.wrapping_add(1);
        let encoded = crate::hysteria2_codec::encode_udp_message(&packet)
            .map_err(|message| TransitError::Unsupported(message.into()))?;
        self.connection
            .send_datagram(Bytes::from(encoded))
            .map_err(|_| TransitError::Connection("Hysteria2 UDP datagram send failed".into()))
    }

    async fn receive(&mut self) -> Result<Vec<u8>, TransitError> {
        let encoded = self.connection.read_datagram().await.map_err(|_| {
            TransitError::Connection("Hysteria2 UDP datagram receive failed".into())
        })?;
        let packet = crate::hysteria2_codec::decode_udp_message(&encoded)
            .map_err(|message| TransitError::Protocol(message.into()))?;
        if packet.session_id != self.session_id
            || packet.fragment_count != 1
            || packet.fragment_id != 0
        {
            return Err(TransitError::Protocol(
                "Hysteria2 UDP fragment is unsupported".into(),
            ));
        }
        Ok(packet.payload)
    }

    async fn close(self: Box<Self>) -> Result<(), TransitError> {
        self.connection.close(0u32.into(), b"closed");
        Ok(())
    }
}

impl AsyncRead for Hysteria2Stream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        while !self.response_done {
            match crate::hysteria2_codec::parse_tcp_response(&self.response_buffer) {
                Ok(Some(consumed)) => {
                    self.leftover = self.response_buffer.split_off(consumed);
                    self.response_buffer.clear();
                    self.response_done = true;
                }
                Ok(None) => {
                    let mut bytes = [0_u8; 1024];
                    let mut read_buffer = ReadBuf::new(&mut bytes);
                    match Pin::new(&mut self.recv).poll_read(cx, &mut read_buffer) {
                        Poll::Ready(Ok(())) if read_buffer.filled().is_empty() => {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                "Hysteria2 stream closed before TCP response",
                            )));
                        }
                        Poll::Ready(Ok(())) => {
                            self.response_buffer.extend_from_slice(read_buffer.filled());
                        }
                        Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                        Poll::Pending => return Poll::Pending,
                    }
                }
                Err(error) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::ConnectionRefused,
                        error,
                    )));
                }
            }
        }
        if self.leftover_pos < self.leftover.len() {
            let available = &self.leftover[self.leftover_pos..];
            let length = available.len().min(buffer.remaining());
            buffer.put_slice(&available[..length]);
            self.leftover_pos += length;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.recv).poll_read(cx, buffer)
    }
}

impl AsyncWrite for Hysteria2Stream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        bytes: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.send)
            .poll_write(cx, bytes)
            .map_err(std::io::Error::other)
    }
    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.send).poll_flush(cx)
    }
    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.send).poll_shutdown(cx)
    }
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
    use tokio::net::UdpSocket;
    use tokio::process::Command;

    #[test]
    fn server_port_ranges_are_bounded_and_normalized() {
        assert_eq!(parse_hop_ports("443,8443,8443").unwrap(), vec![443, 8443]);
        assert_eq!(
            parse_hop_ports("1000-1002").unwrap(),
            vec![1000, 1001, 1002]
        );
        assert!(parse_hop_ports("0").is_err());
        assert!(parse_hop_ports("1002-1000").is_err());
        assert_eq!(parse_hop_interval("2s").unwrap(), Duration::from_secs(2));
        assert_eq!(
            parse_hop_interval("500ms").unwrap(),
            Duration::from_millis(500)
        );
        assert!(parse_hop_interval("0s").is_err());
    }

    #[test]
    fn rejects_unimplemented_bandwidth_fields_before_connecting() {
        let config = pathchord_policy::TransitProxyConfig {
            id: TransitProxyId::new("hy2"),
            source: None,
            protocol: "hysteria2".into(),
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
        for field in ["up_mbps", "down_mbps"] {
            let credentials = TransitCredential::new(BTreeMap::from([
                ("password".into(), "secret".into()),
                (field.into(), "10".into()),
            ]));
            assert!(matches!(
                Hysteria2Adapter::from_config(
                    &config,
                    &credentials,
                    Duration::from_secs(1),
                    crate::adapter_registry::native_tls_roots()
                ),
                Err(TransitError::Unsupported(_))
            ));
        }
    }

    #[tokio::test]
    #[ignore = "requires PATHCHORD_TEST_SING_BOX pointing to sing-box 1.14.4"]
    async fn native_hysteria2_tcp_interoperates_with_sing_box() {
        let binary =
            PathBuf::from(std::env::var_os("PATHCHORD_TEST_SING_BOX").expect("reference peer"));
        let cert =
            rcgen::generate_simple_self_signed(vec!["hysteria.test".into()]).expect("certificate");
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let config = serde_json::to_vec(&json!({
            "log": {"disabled": true},
            "inbounds": [{
                "type": "hysteria2",
                "listen": "127.0.0.1",
                "listen_port": port,
                "users": [{"password": "pathchord-hysteria-password"}],
                "obfs": {"type": "salamander", "password": "pathchord-salamander"},
                "tls": {
                    "enabled": true,
                    "server_name": "hysteria.test",
                    "certificate": cert.cert.pem(),
                    "key": cert.signing_key.serialize_pem()
                }
            }],
            "outbounds": [{"type": "direct", "tag": "direct"}],
            "route": {"final": "direct"}
        }))
        .unwrap();
        let mut server = Command::new(binary)
            .arg("run")
            .arg("-c")
            .arg("stdin")
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        server
            .stdin
            .take()
            .unwrap()
            .write_all(&config)
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
        let target = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_addr = target.local_addr().unwrap();
        let target_task = tokio::spawn(async move {
            let (mut stream, _) = target.accept().await.unwrap();
            let mut payload = [0_u8; 7];
            stream.read_exact(&mut payload).await.unwrap();
            stream.write_all(&payload).await.unwrap();
        });
        let mut config = pathchord_policy::TransitProxyConfig {
            id: TransitProxyId::new("hysteria2-test"),
            source: None,
            protocol: "hysteria2".into(),
            endpoint: PolicyEndpoint {
                host: "127.0.0.1".into(),
                port,
            },
            credentials_ref: None,
            labels: BTreeMap::new(),
            tags: BTreeSet::new(),
            weight: 100,
            options: TransitOptions::default(),
        };
        config.options.tls = Some(pathchord_policy::TransitTls {
            enabled: true,
            server_name: Some("hysteria.test".into()),
            alpn: vec!["h3".into()],
            insecure: true,
            ..Default::default()
        });
        let credentials = TransitCredential::new(BTreeMap::from([
            ("password".into(), "pathchord-hysteria-password".into()),
            ("obfs".into(), "salamander".into()),
            ("obfs_password".into(), "pathchord-salamander".into()),
        ]));
        let adapter = Hysteria2Adapter::from_config(
            &config,
            &credentials,
            Duration::from_secs(5),
            crate::adapter_registry::native_tls_roots(),
        )
        .unwrap();
        let mut stream = adapter
            .connect(ConnectRequest {
                destination: crate::Endpoint {
                    host: "127.0.0.1".into(),
                    port: target_addr.port(),
                },
            })
            .await
            .unwrap();
        stream.write_all(b"hy2test").await.unwrap();
        stream.flush().await.unwrap();
        let mut echoed = [0_u8; 7];
        stream.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"hy2test");
        target_task.await.unwrap();
        let udp_target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let udp_address = udp_target.local_addr().unwrap();
        let udp_task = tokio::spawn(async move {
            let mut payload = [0_u8; 32];
            let (length, peer) = udp_target.recv_from(&mut payload).await.unwrap();
            udp_target.send_to(&payload[..length], peer).await.unwrap();
        });
        let mut datagram = adapter
            .connect_udp(ConnectRequest {
                destination: crate::Endpoint {
                    host: udp_address.ip().to_string(),
                    port: udp_address.port(),
                },
            })
            .await
            .unwrap();
        datagram.send(b"hy2-udp").await.unwrap();
        assert_eq!(datagram.receive().await.unwrap(), b"hy2-udp");
        datagram.close().await.unwrap();
        udp_task.await.unwrap();
        server.kill().await.unwrap();
        server.wait().await.unwrap();
    }
}
