//! Narrow native Hysteria2 TCP adapter built directly on Quinn and h3.
//!
//! Implements TCP and UDP relay, port hopping, and UDP obfuscation.

#[path = "hysteria2_brutal.rs"]
mod brutal;
#[path = "hysteria2_gecko.rs"]
mod gecko;

use std::collections::{BTreeMap, VecDeque};
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

use crate::hysteria2_codec::{AuthHeaders, AuthResponse, ServerReceiveRate};
use crate::{
    AdapterKind, BoxedTransitConnection, ConnectRequest, Endpoint as TransitEndpoint,
    TransitAdapter, TransitCredential, TransitError, TransitMetadata,
};

pub(crate) struct Hysteria2Adapter {
    metadata: TransitMetadata,
    endpoint: TransitEndpoint,
    server_name: String,
    password: String,
    send_bps: u64,
    receive_bps: u64,
    obfuscation: Obfuscation,
    hop_ports: Option<PortRanges>,
    hop_interval: Option<Duration>,
    tls: Arc<rustls::ClientConfig>,
    connect_timeout: Duration,
    udp_enabled: bool,
}

enum Obfuscation {
    None,
    Salamander(String),
    Gecko(String, gecko::GeckoConfig),
}

impl std::fmt::Debug for Hysteria2Adapter {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Hysteria2Adapter")
            .field("metadata", &self.metadata)
            .finish_non_exhaustive()
    }
}

fn parse_mbps(value: &str, name: &str) -> Result<u64, TransitError> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(TransitError::Unsupported(format!(
            "Hysteria2 {name} is invalid"
        )));
    }
    value
        .parse::<u64>()
        .ok()
        .and_then(|mbps| mbps.checked_mul(125_000))
        .ok_or_else(|| {
            TransitError::Unsupported(format!("Hysteria2 {name} is invalid or too large"))
        })
}

#[derive(Debug)]
struct SalamanderSocket {
    inner: Arc<dyn AsyncUdpSocket>,
    password: Option<Vec<u8>>,
    canonical: std::net::SocketAddr,
    hop_ports: Option<PortRanges>,
    hop_interval: Option<Duration>,
    hop_state: Mutex<(usize, Instant)>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct PortRanges {
    ranges: Vec<(u16, u16)>,
    total: u32,
}

impl PortRanges {
    fn select(&self, mut index: u32) -> u16 {
        for &(start, end) in &self.ranges {
            let count = u32::from(end) - u32::from(start) + 1;
            if index < count {
                return (u32::from(start) + index) as u16;
            }
            index -= count;
        }
        unreachable!("port index is within the normalized ranges")
    }

    fn random(&self) -> io::Result<u16> {
        Ok(self.select(gecko::random_below(self.total)?))
    }
}

fn parse_hop_ports(value: &str) -> Result<PortRanges, TransitError> {
    let mut ranges = Vec::new();
    if value.is_empty() || value.len() > 4096 {
        return Err(TransitError::Unsupported(
            "Hysteria2 server_ports is invalid".into(),
        ));
    }
    for part in value.split(',').map(str::trim) {
        if part.is_empty() || ranges.len() >= 512 {
            return Err(TransitError::Unsupported(
                "Hysteria2 server_ports is invalid".into(),
            ));
        }
        if let Some((start, end)) = part.split_once('-') {
            let start = start.parse::<u16>().map_err(|_| {
                TransitError::Unsupported("Hysteria2 server_ports is invalid".into())
            })?;
            let end = end.parse::<u16>().map_err(|_| {
                TransitError::Unsupported("Hysteria2 server_ports is invalid".into())
            })?;
            if start == 0 || end == 0 || start > end {
                return Err(TransitError::Unsupported(
                    "Hysteria2 server_ports is invalid".into(),
                ));
            }
            ranges.push((start, end));
        } else {
            let port = part.parse::<u16>().map_err(|_| {
                TransitError::Unsupported("Hysteria2 server_ports is invalid".into())
            })?;
            if port == 0 {
                return Err(TransitError::Unsupported(
                    "Hysteria2 server_ports is invalid".into(),
                ));
            }
            ranges.push((port, port));
        }
    }
    ranges.sort_unstable();
    let mut normalized: Vec<(u16, u16)> = Vec::new();
    for (start, end) in ranges {
        if let Some(last) = normalized.last_mut()
            && u32::from(start) <= u32::from(last.1) + 1
        {
            last.1 = last.1.max(end);
        } else {
            normalized.push((start, end));
        }
    }
    let total = normalized
        .iter()
        .map(|(start, end)| u32::from(*end) - u32::from(*start) + 1)
        .sum();
    Ok(PortRanges {
        ranges: normalized,
        total,
    })
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
        hop_ports: Option<PortRanges>,
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

    fn destination(&self, original: std::net::SocketAddr) -> io::Result<std::net::SocketAddr> {
        let Some(ports) = &self.hop_ports else {
            return Ok(original);
        };
        let mut state = self
            .hop_state
            .lock()
            .map_err(|_| io::Error::other("Hysteria2 hop state is unavailable"))?;
        if state.0 == 0
            || self
                .hop_interval
                .is_some_and(|interval| state.1.elapsed() >= interval)
        {
            state.0 = usize::from(ports.random()?);
            state.1 = Instant::now();
        }
        Ok(std::net::SocketAddr::new(original.ip(), state.0 as u16))
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
            destination: self.destination(transmit.destination)?,
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
                addr: if self.hop_ports.is_none() {
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
            "gecko_min_packet_size",
            "gecko_max_packet_size",
            "server_ports",
            "hop_interval",
            "up_mbps",
            "down_mbps",
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
        let send_bps = credential
            .field("up_mbps")
            .map(|value| parse_mbps(value, "up_mbps"))
            .transpose()?
            .unwrap_or(0);
        let receive_bps = credential
            .field("down_mbps")
            .map(|value| parse_mbps(value, "down_mbps"))
            .transpose()?
            .unwrap_or(0);
        let gecko_min = credential.field("gecko_min_packet_size");
        let gecko_max = credential.field("gecko_max_packet_size");
        if (gecko_min.is_some() || gecko_max.is_some()) && credential.field("obfs") != Some("gecko")
        {
            return Err(TransitError::Unsupported(
                "Hysteria2 Gecko packet sizes require Gecko obfuscation".into(),
            ));
        }
        let obfuscation = match (credential.field("obfs"), credential.field("obfs_password")) {
            (None, None) => Obfuscation::None,
            (Some("salamander"), Some(password)) if password.len() >= 4 => {
                Obfuscation::Salamander(password.to_owned())
            }
            (Some("gecko"), Some(password)) if !password.is_empty() => {
                let settings = gecko::GeckoConfig::parse(gecko_min, gecko_max).map_err(|_| {
                    TransitError::Unsupported("Hysteria2 Gecko packet size range is invalid".into())
                })?;
                Obfuscation::Gecko(password.to_owned(), settings)
            }
            (Some("salamander" | "gecko"), _) => {
                return Err(TransitError::Unsupported(
                    "Hysteria2 obfuscation password is missing or invalid".into(),
                ));
            }
            (None, Some(_)) => {
                return Err(TransitError::Unsupported(
                    "Hysteria2 obfuscation type is missing".into(),
                ));
            }
            (Some(_), _) => {
                return Err(TransitError::Unsupported(
                    "Hysteria2 obfuscation type is unsupported".into(),
                ));
            }
        };
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
        let mut tls_options = config
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
        if tls_options.fingerprint.is_some() {
            return Err(TransitError::Unsupported(
                "Hysteria2 QUIC TLS fingerprint is unsupported".into(),
            ));
        }
        if tls_options.alpn.is_empty() {
            tls_options.alpn.push("h3".into());
        } else if tls_options.alpn.iter().any(|value| value != "h3") {
            return Err(TransitError::Unsupported(
                "Hysteria2 HTTP/3 requires h3 ALPN".into(),
            ));
        }
        let server_name = tls_options
            .server_name
            .as_deref()
            .unwrap_or(&config.endpoint.host)
            .to_owned();
        crate::tls::server_name(&config.endpoint.host, Some(&tls_options))?;
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
            server_name,
            password: password.to_owned(),
            send_bps,
            receive_bps,
            obfuscation,
            hop_ports,
            hop_interval,
            tls,
            connect_timeout: timeout,
            udp_enabled: config.options.udp != Some(false),
        })
    }

    async fn connect_session(&self) -> Result<Hysteria2Session, TransitError> {
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
        let server_name = self.server_name.clone();
        let mut config = ClientConfig::new(Arc::new(
            QuicClientConfig::try_from((*self.tls).clone())
                .map_err(|_| TransitError::Unsupported("Hysteria2 TLS config is invalid".into()))?,
        ));
        let mut transport = TransportConfig::default();
        transport.congestion_controller_factory(Arc::new(brutal::BrutalFactory::new()));
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
        let password = match &self.obfuscation {
            Obfuscation::None => None,
            Obfuscation::Salamander(password) | Obfuscation::Gecko(password, _) => {
                Some(password.as_str())
            }
        };
        let socket: Arc<dyn AsyncUdpSocket> = if password.is_some() || self.hop_ports.is_some() {
            Arc::new(SalamanderSocket::new(
                inner,
                password,
                address,
                self.hop_ports.clone(),
                self.hop_interval,
            ))
        } else {
            inner
        };
        let socket: Arc<dyn AsyncUdpSocket> = match self.obfuscation {
            Obfuscation::Gecko(_, settings) => Arc::new(gecko::GeckoSocket::new(socket, settings)),
            _ => socket,
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
        Ok(Hysteria2Session {
            connection,
            _endpoint: endpoint,
            http3: None,
        })
    }

    async fn authenticate(&self, session: &mut Hysteria2Session) -> Result<bool, TransitError> {
        let result = timeout(self.connect_timeout, self.authenticate_inner(session))
            .await
            .map_err(|_| TransitError::Connection("Hysteria2 authentication timed out".into()))
            .and_then(|result| result);
        if result.is_err() {
            session.connection.close(0_u32.into(), b"");
        }
        result
    }

    async fn authenticate_inner(
        &self,
        session: &mut Hysteria2Session,
    ) -> Result<bool, TransitError> {
        let h3_connection = h3_quinn::Connection::new(session.connection.clone());
        let (mut driver, mut sender) = h3::client::new(h3_connection)
            .await
            .map_err(|_| TransitError::Protocol("Hysteria2 HTTP/3 setup failed".into()))?;
        // The HTTP/3 driver owns the critical streams. Keep a request sender
        // with it because dropping the last sender closes the H3 connection.
        let keep_sender = sender.clone();
        session.http3 = Some(tokio::spawn(async move {
            let _sender = keep_sender;
            driver.wait_idle().await;
        }));
        let auth = AuthHeaders {
            password: self.password.clone(),
            receive_bps: self.receive_bps,
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
        let auth = AuthResponse::parse(response.headers())
            .map_err(|message| TransitError::Protocol(message.into()))?;
        let send_bps = match auth.receive_rate {
            ServerReceiveRate::Auto => 0,
            ServerReceiveRate::BytesPerSecond(rate) if rate == 0 || rate > self.send_bps => {
                self.send_bps
            }
            ServerReceiveRate::BytesPerSecond(rate) => rate,
        };
        if send_bps != 0 {
            let controller = session
                .connection
                .congestion_state()
                .into_any()
                .downcast::<brutal::BrutalController>()
                .map_err(|_| {
                    TransitError::Protocol("Hysteria2 congestion controller missing".into())
                })?;
            controller.enable(send_bps);
        }
        Ok(auth.udp_enabled)
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
        let mut session = self.connect_session().await?;
        self.authenticate(&mut session).await?;
        let destination = format_destination(&request.destination);
        let (mut send, recv) = session
            .connection
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
            session: Some(session),
            drain_timeout: self.connect_timeout.min(Duration::from_secs(2)),
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
        let mut session = self.connect_session().await?;
        if !self.authenticate(&mut session).await? {
            return Err(TransitError::Unsupported(
                "Hysteria2 server did not advertise UDP relay".into(),
            ));
        }
        let mut id_bytes = [0_u8; 4];
        getrandom::fill(&mut id_bytes).map_err(|_| {
            TransitError::Connection("Hysteria2 session id generation failed".into())
        })?;
        Ok(Box::new(Hysteria2Datagram {
            session,
            session_id: u32::from_be_bytes(id_bytes),
            packet_id: 0,
            destination: format_destination(&request.destination),
            fragments: Hysteria2Fragments::default(),
            timeout: self.connect_timeout,
        }))
    }
}

fn format_destination(endpoint: &TransitEndpoint) -> String {
    if endpoint.host.parse::<std::net::Ipv6Addr>().is_ok() {
        format!("[{}]:{}", endpoint.host, endpoint.port)
    } else {
        format!("{}:{}", endpoint.host, endpoint.port)
    }
}

struct Hysteria2Session {
    connection: quinn::Connection,
    _endpoint: Endpoint,
    http3: Option<tokio::task::JoinHandle<()>>,
}

impl Drop for Hysteria2Session {
    fn drop(&mut self) {
        self.connection.close(0_u32.into(), b"closed");
        if let Some(driver) = &self.http3 {
            driver.abort();
        }
    }
}

struct Hysteria2Stream {
    send: SendStream,
    recv: RecvStream,
    session: Option<Hysteria2Session>,
    drain_timeout: Duration,
    response_done: bool,
    response_buffer: Vec<u8>,
    leftover: Vec<u8>,
    leftover_pos: usize,
}

impl Drop for Hysteria2Stream {
    fn drop(&mut self) {
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            return;
        };
        // Quinn queues FIN without waiting for acknowledgement. Keep the
        // session alive briefly so a connection close cannot discard that FIN
        // or the data queued ahead of it.
        let _ = self.send.finish();
        let acknowledgement = self.send.stopped();
        let session = self.session.take();
        let drain_timeout = self.drain_timeout;
        runtime.spawn(async move {
            let _ = timeout(drain_timeout, acknowledgement).await;
            drop(session);
        });
    }
}

struct Hysteria2Datagram {
    session: Hysteria2Session,
    session_id: u32,
    packet_id: u16,
    destination: String,
    fragments: Hysteria2Fragments,
    timeout: Duration,
}

#[derive(Debug, Default)]
struct Hysteria2Fragments {
    packets: BTreeMap<u16, Hysteria2Assembly>,
    order: VecDeque<u16>,
}

#[derive(Debug)]
struct Hysteria2Assembly {
    address: String,
    parts: Vec<Option<Vec<u8>>>,
    size: usize,
    received: usize,
    created: Instant,
}

impl Hysteria2Fragments {
    fn push(
        &mut self,
        packet: crate::hysteria2_codec::UdpMessage,
        now: Instant,
    ) -> Result<Option<Vec<u8>>, TransitError> {
        const MAX_INCOMPLETE: usize = 16;
        const MAX_AGE: Duration = Duration::from_secs(10);
        if packet.fragment_count == 0 {
            return Err(TransitError::Protocol(
                "Hysteria2 UDP fragment index is invalid".into(),
            ));
        }
        self.packets
            .retain(|_, assembly| now.saturating_duration_since(assembly.created) < MAX_AGE);
        self.order.retain(|id| self.packets.contains_key(id));
        if packet.fragment_count == 1 {
            return Ok(Some(packet.payload));
        }
        if packet.fragment_id >= packet.fragment_count {
            return Err(TransitError::Protocol(
                "Hysteria2 UDP fragment index is invalid".into(),
            ));
        }
        let id = packet.packet_id;
        if !self.packets.contains_key(&id) {
            if self.packets.len() >= MAX_INCOMPLETE
                && let Some(oldest) = self.order.pop_front()
            {
                self.packets.remove(&oldest);
            }
            self.order.push_back(id);
            self.packets.insert(
                id,
                Hysteria2Assembly {
                    address: packet.address.clone(),
                    parts: vec![None; usize::from(packet.fragment_count)],
                    size: 0,
                    received: 0,
                    created: now,
                },
            );
        }
        let assembly = self.packets.get_mut(&id).expect("fragment assembly exists");
        if assembly.address != packet.address
            || assembly.parts.len() != usize::from(packet.fragment_count)
        {
            self.packets.remove(&id);
            self.order.retain(|item| *item != id);
            return Err(TransitError::Protocol(
                "Hysteria2 UDP fragment metadata changed".into(),
            ));
        }
        let part = &mut assembly.parts[usize::from(packet.fragment_id)];
        if let Some(previous) = part {
            if previous == &packet.payload {
                return Ok(None);
            }
            self.packets.remove(&id);
            self.order.retain(|item| *item != id);
            return Err(TransitError::Protocol(
                "Hysteria2 UDP fragment content changed".into(),
            ));
        }
        assembly.size += packet.payload.len();
        if assembly.size > crate::hysteria2_codec::MAX_UDP_PAYLOAD {
            self.packets.remove(&id);
            self.order.retain(|item| *item != id);
            return Err(TransitError::Protocol(
                "Hysteria2 UDP reassembled packet is too large".into(),
            ));
        }
        *part = Some(packet.payload);
        assembly.received += 1;
        if assembly.received != assembly.parts.len() {
            return Ok(None);
        }
        let assembly = self.packets.remove(&id).expect("fragment assembly exists");
        self.order.retain(|item| *item != id);
        let mut payload = Vec::with_capacity(assembly.size);
        for part in assembly.parts {
            payload.extend(part.expect("all fragments are present"));
        }
        Ok(Some(payload))
    }
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
        if payload.len() > crate::hysteria2_codec::MAX_UDP_PAYLOAD {
            return Err(TransitError::Unsupported(
                "Hysteria2 UDP payload is too large".into(),
            ));
        }
        let mut packet = crate::hysteria2_codec::UdpMessage {
            session_id: self.session_id,
            packet_id: self.packet_id,
            fragment_id: 0,
            fragment_count: 1,
            address: self.destination.clone(),
            payload: Vec::new(),
        };
        self.packet_id = self.packet_id.wrapping_add(1);
        let header = crate::hysteria2_codec::encode_udp_message(&packet)
            .map_err(|message| TransitError::Unsupported(message.into()))?;
        let max = self.session.connection.max_datagram_size().ok_or_else(|| {
            TransitError::Unsupported("Hysteria2 peer does not accept QUIC datagrams".into())
        })?;
        let part_size = max
            .checked_sub(header.len())
            .filter(|size| *size > 0)
            .ok_or_else(|| {
                TransitError::Unsupported("Hysteria2 UDP datagram size is too small".into())
            })?;
        let count = payload.len().max(1).div_ceil(part_size);
        packet.fragment_count = u8::try_from(count).map_err(|_| {
            TransitError::Unsupported("Hysteria2 UDP packet needs too many fragments".into())
        })?;
        timeout(self.timeout, async {
            for index in 0..count {
                let start = index * part_size;
                let end = (start + part_size).min(payload.len());
                packet.fragment_id = index as u8;
                packet.payload = payload[start..end].to_vec();
                let encoded = crate::hysteria2_codec::encode_udp_message(&packet)
                    .map_err(|message| TransitError::Unsupported(message.into()))?;
                self.session
                    .connection
                    .send_datagram_wait(Bytes::from(encoded))
                    .await
                    .map_err(|_| {
                        TransitError::Connection("Hysteria2 UDP datagram send failed".into())
                    })?;
            }
            Ok(())
        })
        .await
        .map_err(|_| TransitError::Connection("Hysteria2 UDP datagram send timed out".into()))?
    }

    async fn receive(&mut self) -> Result<Vec<u8>, TransitError> {
        loop {
            let encoded = self.session.connection.read_datagram().await.map_err(|_| {
                TransitError::Connection("Hysteria2 UDP datagram receive failed".into())
            })?;
            let packet = crate::hysteria2_codec::decode_udp_message(&encoded)
                .map_err(|message| TransitError::Protocol(message.into()))?;
            if packet.session_id != self.session_id {
                return Err(TransitError::Protocol(
                    "Hysteria2 UDP session id does not match".into(),
                ));
            }
            if let Some(payload) = self.fragments.push(packet, Instant::now())? {
                return Ok(payload);
            }
        }
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
    use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
    use tokio::net::UdpSocket;
    use tokio::process::{Child, Command};

    struct FixturePeer {
        child: Child,
        ready: tokio::sync::oneshot::Receiver<std::net::SocketAddr>,
        logs: Arc<Mutex<VecDeque<&'static str>>>,
    }

    impl FixturePeer {
        fn new(mut child: Child) -> Self {
            let mut stderr = child.stderr.take().expect("test peer stderr is piped");
            let logs = Arc::new(Mutex::new(VecDeque::new()));
            let captured = Arc::clone(&logs);
            let (ready, ready_rx) = tokio::sync::oneshot::channel();
            tokio::spawn(async move {
                let mut ready = Some(ready);
                let mut line = Vec::with_capacity(4096);
                let mut oversized = false;
                let mut chunk = [0_u8; 1024];
                while let Ok(count) = stderr.read(&mut chunk).await {
                    if count == 0 {
                        break;
                    }
                    for &byte in &chunk[..count] {
                        if byte != b'\n' {
                            if line.len() < 4096 {
                                line.push(byte);
                            } else {
                                oversized = true;
                            }
                            continue;
                        }
                        let text = String::from_utf8_lossy(&line);
                        let address = (!oversized)
                            .then(|| text.split_once("udp server started at "))
                            .flatten()
                            .and_then(|(_, address)| address.split_whitespace().next())
                            .and_then(|address| address.parse::<std::net::SocketAddr>().ok())
                            .filter(|address| address.ip().is_loopback() && address.port() != 0);
                        let event = if oversized {
                            "oversized peer log suppressed"
                        } else if address.is_some() {
                            "peer reported UDP listener started"
                        } else if text.contains("FATAL") || text.contains("ERROR") {
                            "peer reported an error (details suppressed)"
                        } else {
                            "peer diagnostic suppressed"
                        };
                        {
                            let mut logs = captured.lock().unwrap();
                            if logs.len() == 32 {
                                logs.pop_front();
                            }
                            logs.push_back(event);
                        }
                        if let Some(address) = address
                            && let Some(ready) = ready.take()
                        {
                            let _ = ready.send(address);
                        }
                        line.clear();
                        oversized = false;
                    }
                }
            });
            Self {
                child,
                ready: ready_rx,
                logs,
            }
        }

        fn diagnostic(&mut self) -> String {
            let status = match self.child.try_wait() {
                Ok(Some(status)) => format!("exited with {status}"),
                Ok(None) => "running".to_owned(),
                Err(error) => format!("status unavailable ({:?})", error.kind()),
            };
            let logs = self
                .logs
                .lock()
                .unwrap()
                .iter()
                .copied()
                .collect::<Vec<_>>()
                .join(" | ");
            format!("peer status: {status}; peer log: {logs}")
        }

        async fn wait_for_udp(&mut self, limit: Duration) -> Result<std::net::SocketAddr, String> {
            let result = timeout(limit, async {
                tokio::select! {
                    ready = &mut self.ready => ready.map_err(|_| "peer log closed before UDP readiness".to_owned()),
                    status = self.child.wait() => Err(match status {
                        Ok(status) => format!("peer exited before UDP readiness: {status}"),
                        Err(error) => format!("peer wait failed before UDP readiness: {:?}", error.kind()),
                    }),
                }
            }).await;
            match result {
                Ok(Ok(address)) => match self.child.try_wait() {
                    Ok(None) => Ok(address),
                    _ => Err(format!(
                        "peer exited after UDP readiness; {}",
                        self.diagnostic()
                    )),
                },
                Ok(Err(error)) => Err(format!("{error}; {}", self.diagnostic())),
                Err(_) => Err(format!(
                    "peer UDP readiness timed out; {}",
                    self.diagnostic()
                )),
            }
        }
    }

    #[test]
    fn fixture_delayed_udp_peer_child() {
        let Some(mode) = std::env::var_os("PATHCHORD_HYSTERIA_FIXTURE_CHILD") else {
            return;
        };
        if mode == "exit" {
            eprintln!("fixture startup failed: fixture-credential /private/fixture-path");
            std::thread::sleep(Duration::from_millis(100));
            return;
        }
        std::thread::sleep(Duration::from_millis(300));
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        eprintln!(
            "fixture diagnostic credential: fixture-credential /private/fixture-path unknown-secret"
        );
        eprintln!("oversized {} unknown-secret", "x".repeat(16_384));
        eprintln!("udp server started at {}", socket.local_addr().unwrap());
        std::thread::sleep(Duration::from_secs(10));
    }

    #[tokio::test]
    async fn fixture_waits_for_its_own_delayed_udp_listener() {
        let occupied = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        // A free TCP port does not imply the same UDP port is available.
        let tcp = std::net::TcpListener::bind(occupied.local_addr().unwrap()).unwrap();
        drop(tcp);
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .arg("--exact")
            .arg("hysteria2_adapter::tests::fixture_delayed_udp_peer_child")
            .arg("--nocapture")
            .env("PATHCHORD_HYSTERIA_FIXTURE_CHILD", "1")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        let started = Instant::now();
        let mut peer = FixturePeer::new(command.spawn().unwrap());
        let address = peer.wait_for_udp(Duration::from_secs(3)).await.unwrap();
        assert!(started.elapsed() >= Duration::from_millis(250));
        assert_ne!(address, occupied.local_addr().unwrap());
        assert!(
            matches!(std::net::UdpSocket::bind(address), Err(error) if error.kind() == io::ErrorKind::AddrInUse)
        );
        let diagnostic = peer.diagnostic();
        assert!(diagnostic.contains("oversized peer log suppressed"));
        assert!(!diagnostic.contains("fixture-credential"));
        assert!(!diagnostic.contains("unknown-secret"));
        assert!(!diagnostic.contains("/private/fixture-path"));
        assert!(peer.logs.lock().unwrap().len() <= 32);
        peer.child.kill().await.unwrap();
        peer.child.wait().await.unwrap();
    }

    #[tokio::test]
    async fn fixture_reports_peer_exit_without_exposing_credentials() {
        let child = Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg("hysteria2_adapter::tests::fixture_delayed_udp_peer_child")
            .arg("--nocapture")
            .env("PATHCHORD_HYSTERIA_FIXTURE_CHILD", "exit")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let mut peer = FixturePeer::new(child);
        let error = peer.wait_for_udp(Duration::from_secs(2)).await.unwrap_err();
        assert!(error.contains("before UDP readiness"));
        assert!(error.contains("peer diagnostic suppressed"));
        assert!(!error.contains("fixture-credential"));
        assert!(!error.contains("/private/fixture-path"));
    }

    #[test]
    fn udp_fragments_are_reordered_bounded_and_expired() {
        use crate::hysteria2_codec::{MAX_UDP_PAYLOAD, UdpMessage};

        let fragment = |packet_id, fragment_id, fragment_count, payload: &[u8]| UdpMessage {
            session_id: 1,
            packet_id,
            fragment_id,
            fragment_count,
            address: "example.test:53".into(),
            payload: payload.into(),
        };
        let now = Instant::now();
        let mut fragments = Hysteria2Fragments::default();
        assert_eq!(fragments.push(fragment(1, 2, 3, b"c"), now).unwrap(), None);
        assert_eq!(fragments.push(fragment(1, 0, 3, b"a"), now).unwrap(), None);
        assert_eq!(fragments.push(fragment(1, 0, 3, b"a"), now).unwrap(), None);
        assert_eq!(
            fragments.push(fragment(1, 7, 1, b"single"), now).unwrap(),
            Some(b"single".to_vec())
        );
        assert_eq!(
            fragments.push(fragment(1, 1, 3, b"b"), now).unwrap(),
            Some(b"abc".to_vec())
        );
        assert!(fragments.push(fragment(2, 2, 2, b"x"), now).is_err());
        fragments.push(fragment(3, 0, 2, b"x"), now).unwrap();
        assert!(fragments.push(fragment(3, 0, 2, b"y"), now).is_err());
        fragments.push(fragment(3, 0, 2, b"x"), now).unwrap();
        let mut changed = fragment(3, 1, 2, b"y");
        changed.address = "other.test:53".into();
        assert!(fragments.push(changed, now).is_err());
        fragments
            .push(fragment(4, 0, 2, &vec![0; MAX_UDP_PAYLOAD]), now)
            .unwrap();
        assert!(fragments.push(fragment(4, 1, 2, b"x"), now).is_err());
        for id in 10..30 {
            fragments.push(fragment(id, 0, 2, b"x"), now).unwrap();
        }
        assert_eq!(fragments.packets.len(), 16);
        fragments
            .push(fragment(99, 0, 2, b"x"), now + Duration::from_secs(10))
            .unwrap();
        assert_eq!(fragments.packets.len(), 1);
        assert!(fragments.packets.contains_key(&99));
    }

    #[test]
    fn destinations_format_ipv6_with_brackets() {
        for (host, expected) in [
            ("2001:db8::1", "[2001:db8::1]:443"),
            ("192.0.2.1", "192.0.2.1:443"),
            ("example.test", "example.test:443"),
        ] {
            assert_eq!(
                format_destination(&TransitEndpoint {
                    host: host.into(),
                    port: 443,
                }),
                expected
            );
        }
    }

    #[test]
    fn server_port_ranges_are_bounded_and_normalized() {
        assert_eq!(
            parse_hop_ports("443,8443,8443").unwrap().ranges,
            vec![(443, 443), (8443, 8443)]
        );
        assert_eq!(
            parse_hop_ports("1000-1002").unwrap().ranges,
            vec![(1000, 1002)]
        );
        let all = parse_hop_ports("1-65535").unwrap();
        assert_eq!(all.ranges, vec![(1, 65535)]);
        assert_eq!(all.total, 65535);
        assert_eq!(all.select(0), 1);
        assert_eq!(all.select(65534), 65535);
        let ranges = parse_hop_ports("4090-8192,4096-10000,12000").unwrap();
        assert_eq!(ranges.ranges, vec![(4090, 10000), (12000, 12000)]);
        let samples: BTreeSet<_> = (0..100).map(|_| ranges.random().unwrap()).collect();
        assert!(samples.len() > 1);
        assert!(
            samples
                .iter()
                .all(|port| (4090..=10000).contains(port) || *port == 12000)
        );
        assert!(parse_hop_ports("0").is_err());
        assert!(parse_hop_ports("1002-1000").is_err());
        assert!(parse_hop_ports("1,,2").is_err());
        assert_eq!(parse_hop_interval("2s").unwrap(), Duration::from_secs(2));
        assert_eq!(
            parse_hop_interval("500ms").unwrap(),
            Duration::from_millis(500)
        );
        assert!(parse_hop_interval("0s").is_err());
    }

    #[test]
    fn accepts_bounded_bandwidth_values() {
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
        for (value, expected) in [("0", 0), ("1", 125_000), ("100", 12_500_000)] {
            let credentials = TransitCredential::new(BTreeMap::from([
                ("password".into(), "secret".into()),
                ("down_mbps".into(), value.into()),
                ("up_mbps".into(), value.into()),
            ]));
            let adapter = Hysteria2Adapter::from_config(
                &config,
                &credentials,
                Duration::from_secs(1),
                crate::adapter_registry::native_tls_roots(),
            )
            .unwrap();
            assert_eq!(adapter.receive_bps, expected);
            assert_eq!(adapter.send_bps, expected);
        }
        for value in [
            "",
            "-1",
            "1.5",
            "1 Mbps",
            "147573952589677",
            "999999999999999999999999",
        ] {
            let credentials = TransitCredential::new(BTreeMap::from([
                ("password".into(), "secret".into()),
                ("down_mbps".into(), value.into()),
            ]));
            assert!(
                Hysteria2Adapter::from_config(
                    &config,
                    &credentials,
                    Duration::from_secs(1),
                    crate::adapter_registry::native_tls_roots()
                )
                .is_err()
            );
        }
    }

    #[test]
    fn validates_http3_alpn_during_preparation() {
        let mut config = pathchord_policy::TransitProxyConfig {
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
        let credential =
            TransitCredential::new(BTreeMap::from([("password".into(), "secret".into())]));
        for (alpn, valid) in [
            (vec![], true),
            (vec!["h3"], true),
            (vec!["h2"], false),
            (vec!["h2", "h3"], false),
        ] {
            config.options.tls = Some(pathchord_policy::TransitTls {
                enabled: true,
                alpn: alpn.into_iter().map(str::to_owned).collect(),
                ..Default::default()
            });
            let result = Hysteria2Adapter::from_config(
                &config,
                &credential,
                Duration::from_secs(1),
                crate::adapter_registry::native_tls_roots(),
            );
            assert_eq!(result.is_ok(), valid);
        }
    }

    #[test]
    fn rejects_invalid_upload_bandwidth_before_connecting() {
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
        for value in ["", "-1", "1.5", "1 Mbps", "147573952589677"] {
            let credentials = TransitCredential::new(BTreeMap::from([
                ("password".into(), "secret".into()),
                ("up_mbps".into(), value.into()),
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

    async fn mock_h3_auth(
        response_rate: Option<&'static str>,
        udp: Option<&'static str>,
        status: u16,
        delay: Duration,
    ) -> (
        Hysteria2Adapter,
        tokio::sync::oneshot::Receiver<(String, String)>,
        tokio::sync::oneshot::Receiver<()>,
        tokio::task::JoinHandle<()>,
    ) {
        let rcgen::CertifiedKey { cert, signing_key } =
            rcgen::generate_simple_self_signed(vec!["hysteria.test".into()]).unwrap();
        let mut tls = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.der().clone()],
            rustls::pki_types::PrivatePkcs8KeyDer::from(signing_key.serialize_der()).into(),
        )
        .unwrap();
        tls.alpn_protocols = vec![b"h3".to_vec()];
        let server_config = quinn::ServerConfig::with_crypto(Arc::new(
            quinn::crypto::rustls::QuicServerConfig::try_from(tls).unwrap(),
        ));
        let endpoint =
            quinn::Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap()).unwrap();
        let port = endpoint.local_addr().unwrap().port();
        let (tx, rx) = tokio::sync::oneshot::channel();
        let (closed_tx, closed_rx) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            let incoming = endpoint.accept().await.unwrap().await.unwrap();
            let watch = incoming.clone();
            tokio::spawn(async move {
                watch.closed().await;
                let _ = closed_tx.send(());
            });
            let mut http3 = h3::server::builder()
                .build::<_, Bytes>(h3_quinn::Connection::new(incoming))
                .await
                .unwrap();
            let resolver = http3.accept().await.unwrap().unwrap();
            let (request, mut stream) = resolver.resolve_request().await.unwrap();
            assert_eq!(request.method(), http::Method::POST);
            assert_eq!(request.uri().path(), "/auth");
            let password = request.headers()["hysteria-auth"]
                .to_str()
                .unwrap()
                .to_owned();
            let receive_rate = request.headers()["hysteria-cc-rx"]
                .to_str()
                .unwrap()
                .to_owned();
            tx.send((password, receive_rate)).unwrap();
            tokio::spawn(async move {
                tokio::time::sleep(delay).await;
                let mut builder = http::Response::builder().status(status);
                if let Some(rate) = response_rate {
                    builder = builder.header("hysteria-cc-rx", rate);
                }
                if let Some(udp) = udp {
                    builder = builder.header("hysteria-udp", udp);
                }
                if let Ok(response) = builder.body(())
                    && stream.send_response(response).await.is_ok()
                {
                    let _ = stream.finish().await;
                }
            });
            let _ = http3.accept().await;
        });
        let config = pathchord_policy::TransitProxyConfig {
            id: TransitProxyId::new("hy2-auth-fixture"),
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
            options: TransitOptions {
                tls: Some(pathchord_policy::TransitTls {
                    enabled: true,
                    server_name: Some("hysteria.test".into()),
                    certificate: vec![cert.pem()],
                    ..Default::default()
                }),
                ..Default::default()
            },
        };
        let credentials = TransitCredential::new(BTreeMap::from([
            ("password".into(), "fixture-password".into()),
            ("down_mbps".into(), "7".into()),
        ]));
        let adapter = Hysteria2Adapter::from_config(
            &config,
            &credentials,
            Duration::from_secs(2),
            crate::adapter_registry::native_tls_roots(),
        )
        .unwrap();
        (adapter, rx, closed_rx, task)
    }

    #[tokio::test]
    async fn h3_auth_transmits_download_rate_and_honors_server_negotiation() {
        timeout(Duration::from_secs(20), async {
            for (rate, client_rate, expected_rate, udp, status, succeeds) in [
                (Some("0"), 0, 0, Some("true"), 233, true),
                (Some("auto"), 875_000, 0, Some("false"), 233, true),
                (Some("125000"), 0, 0, Some("true"), 233, true),
                (Some("0"), 875_000, 875_000, Some("true"), 233, true),
                (Some("125000"), 875_000, 125_000, Some("true"), 233, true),
                (Some("1000000"), 875_000, 875_000, Some("true"), 233, true),
                (Some("bad"), 875_000, 0, Some("true"), 233, false),
                (None, 875_000, 0, Some("true"), 233, false),
                (Some("0"), 875_000, 0, Some("true"), 403, false),
            ] {
                let (mut adapter, request, _closed, task) =
                    mock_h3_auth(rate, udp, status, Duration::ZERO).await;
                adapter.send_bps = client_rate;
                let mut session = adapter.connect_session().await.unwrap();
                let target = |conn: &quinn::Connection| {
                    conn.congestion_state()
                        .into_any()
                        .downcast::<brutal::BrutalController>()
                        .unwrap()
                        .target()
                };
                assert_eq!(target(&session.connection), 0);
                let result = adapter.authenticate(&mut session).await;
                assert_eq!(
                    request.await.unwrap(),
                    ("fixture-password".into(), "875000".into())
                );
                if succeeds {
                    assert_eq!(result.unwrap(), udp == Some("true"));
                    assert_eq!(target(&session.connection), expected_rate);
                } else {
                    assert!(result.is_err(), "rate {rate:?}, status {status}");
                    assert!(session.connection.close_reason().is_some());
                }
                task.abort();
            }
        })
        .await
        .expect("Hysteria2 HTTP/3 authentication matrix timed out");
    }

    #[tokio::test]
    async fn stalled_h3_authentication_times_out_and_closes_connection() {
        let (mut adapter, request, _closed, task) =
            mock_h3_auth(Some("0"), Some("true"), 233, Duration::from_secs(5)).await;
        let mut session = adapter.connect_session().await.unwrap();
        adapter.connect_timeout = Duration::from_millis(150);
        assert!(matches!(
            adapter.authenticate(&mut session).await,
            Err(TransitError::Connection(_))
        ));
        assert_eq!(request.await.unwrap().1, "875000");
        assert!(session.connection.close_reason().is_some());
        task.abort();
    }

    #[tokio::test]
    async fn cancelled_h3_authentication_closes_the_quic_session() {
        let (adapter, request, closed, task) =
            mock_h3_auth(Some("0"), Some("true"), 233, Duration::from_secs(5)).await;
        let connection = tokio::spawn(async move {
            adapter
                .connect(ConnectRequest {
                    destination: TransitEndpoint {
                        host: "127.0.0.1".into(),
                        port: 1234,
                    },
                })
                .await
        });
        assert_eq!(request.await.unwrap().1, "875000");
        connection.abort();
        assert!(matches!(connection.await, Err(error) if error.is_cancelled()));
        timeout(Duration::from_secs(1), closed)
            .await
            .expect("cancelled authentication leaked its QUIC session")
            .unwrap();
        task.abort();
    }

    #[tokio::test]
    #[ignore = "requires PATHCHORD_TEST_SING_BOX pointing to sing-box 1.14.4"]
    async fn native_hysteria2_tcp_interoperates_with_sing_box() {
        for obfs in ["salamander", "gecko"] {
            tokio::time::timeout(
                Duration::from_secs(20),
                sing_box_roundtrip(Some(obfs), None, false, None, None, None, false),
            )
            .await
            .expect("bounded Hysteria2 round trip");
        }
    }

    #[tokio::test]
    #[ignore = "requires PATHCHORD_TEST_SING_BOX pointing to sing-box 1.14.4"]
    async fn native_hysteria2_custom_gecko_sizes_interoperate_with_sing_box() {
        for sizes in [(700, 700), (800, 1400), (1452, 1452)] {
            timeout(
                Duration::from_secs(20),
                sing_box_roundtrip(Some("gecko"), None, false, None, None, Some(sizes), false),
            )
            .await
            .expect("bounded custom Gecko TCP/UDP round trip");
        }
    }

    #[tokio::test]
    #[ignore = "requires PATHCHORD_TEST_SING_BOX and PATHCHORD_TEST_GECKO_RELAY"]
    async fn large_gecko_packets_interoperate_with_independent_go_relay() {
        timeout(
            Duration::from_secs(25),
            sing_box_roundtrip(
                Some("gecko"),
                None,
                false,
                None,
                None,
                Some((2048, 2048)),
                true,
            ),
        )
        .await
        .expect("large Gecko packets through independent Go relay");
    }

    #[tokio::test]
    #[ignore = "requires PATHCHORD_TEST_SING_BOX pointing to sing-box 1.14.4"]
    async fn native_hysteria2_receive_rate_hint_interoperates_with_sing_box() {
        for ignore_client_bandwidth in [false, true] {
            tokio::time::timeout(
                Duration::from_secs(20),
                sing_box_roundtrip(
                    None,
                    Some("2"),
                    ignore_client_bandwidth,
                    None,
                    None,
                    None,
                    false,
                ),
            )
            .await
            .expect("bounded Hysteria2 receive-rate round trip");
        }
    }

    #[tokio::test]
    #[ignore = "requires PATHCHORD_TEST_SING_BOX pointing to sing-box 1.14.4"]
    async fn native_hysteria2_brutal_tcp_udp_and_obfuscation_interoperate_with_sing_box() {
        for obfs in ["salamander", "gecko"] {
            timeout(
                Duration::from_secs(20),
                sing_box_roundtrip(
                    Some(obfs),
                    Some("2"),
                    false,
                    Some("2"),
                    Some(1),
                    None,
                    false,
                ),
            )
            .await
            .expect("bounded Hysteria2 Brutal TCP/UDP round trip");
        }
    }

    #[tokio::test]
    #[ignore = "requires PATHCHORD_TEST_SING_BOX pointing to sing-box 1.14.4"]
    async fn native_hysteria2_sing_box_upload_negotiation_matrix() {
        timeout(Duration::from_secs(30), async {
            for (server_mbps, auto, client_mbps, expected_bps) in [
                (1, false, "0", 0),
                (1, false, "2", 125_000),
                (3, false, "1", 125_000),
                (0, false, "2", 250_000),
                (0, false, "0", 0),
                (0, true, "2", 0),
            ] {
                let binary = PathBuf::from(std::env::var_os("PATHCHORD_TEST_SING_BOX").unwrap());
                let cert = rcgen::generate_simple_self_signed(vec!["hysteria.test".into()]).unwrap();
                let reserved = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
                let address = reserved.local_addr().unwrap();
                drop(reserved);
                let inbound = json!({
                    "type": "hysteria2", "listen": "127.0.0.1", "listen_port": address.port(),
                    "users": [{"password": "test-password"}], "down_mbps": server_mbps,
                    "ignore_client_bandwidth": auto,
                    "tls": {"enabled": true, "certificate": cert.cert.pem(), "key": cert.signing_key.serialize_pem()}
                });
                let document = json!({"log": {"disabled": true}, "inbounds": [inbound], "outbounds": [{"type": "direct"}]});
                let mut server = Command::new(binary).args(["run", "-c", "stdin"])
                    .stdin(Stdio::piped()).stdout(Stdio::null()).stderr(Stdio::null())
                    .kill_on_drop(true).spawn().unwrap();
                server.stdin.take().unwrap().write_all(&serde_json::to_vec(&document).unwrap()).await.unwrap();
                timeout(Duration::from_secs(5), async {
                    loop {
                        assert!(server.try_wait().unwrap().is_none(), "sing-box exited before startup");
                        match std::net::UdpSocket::bind(address) {
                            Err(error) if error.kind() == io::ErrorKind::AddrInUse => break,
                            Ok(socket) => drop(socket),
                            Err(error) => panic!("sing-box UDP readiness failed: {error}"),
                        }
                        tokio::time::sleep(Duration::from_millis(20)).await;
                    }
                }).await.unwrap();
                let config = pathchord_policy::TransitProxyConfig {
                    id: TransitProxyId::new("hy2-rate-matrix"), source: None, protocol: "hysteria2".into(),
                    endpoint: PolicyEndpoint { host: address.ip().to_string(), port: address.port() },
                    credentials_ref: None, labels: BTreeMap::new(), tags: BTreeSet::new(), weight: 100,
                    options: TransitOptions { tls: Some(pathchord_policy::TransitTls {
                        enabled: true, server_name: Some("hysteria.test".into()),
                        certificate: vec![cert.cert.pem()], ..Default::default()
                    }), ..Default::default() },
                };
                let credentials = TransitCredential::new(BTreeMap::from([
                    ("password".into(), "test-password".into()),
                    ("up_mbps".into(), client_mbps.into()),
                    ("down_mbps".into(), "2".into()),
                ]));
                let adapter = Hysteria2Adapter::from_config(
                    &config, &credentials, Duration::from_secs(3), crate::adapter_registry::native_tls_roots()
                ).unwrap();
                let mut session = adapter.connect_session().await.unwrap();
                adapter.authenticate(&mut session).await.unwrap();
                let controller = session.connection.congestion_state().into_any()
                    .downcast::<brutal::BrutalController>().unwrap();
                assert_eq!(controller.target(), expected_bps,
                    "server_mbps={server_mbps}, auto={auto}, client_mbps={client_mbps}");
                drop(session);
                server.kill().await.unwrap();
                server.wait().await.unwrap();
            }
        }).await.expect("bounded Hysteria2 sing-box negotiation matrix");
    }

    #[tokio::test]
    #[ignore = "requires PATHCHORD_TEST_SING_BOX pointing to sing-box 1.14.4"]
    async fn native_hysteria2_brutal_paces_and_retransmits_with_sing_box() {
        use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

        timeout(Duration::from_secs(45), async {
            let binary = PathBuf::from(std::env::var_os("PATHCHORD_TEST_SING_BOX").unwrap());
            let cert = rcgen::generate_simple_self_signed(vec!["hysteria.test".into()]).unwrap();
            let reserved = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
            let server_addr = reserved.local_addr().unwrap();
            drop(reserved);
            let document = json!({
                "log": {"disabled": true},
                "inbounds": [{
                    "type": "hysteria2", "listen": "127.0.0.1", "listen_port": server_addr.port(),
                    "users": [{"password": "correct-password"}], "down_mbps": 1,
                    "tls": {"enabled": true, "certificate": cert.cert.pem(), "key": cert.signing_key.serialize_pem()}
                }],
                "outbounds": [{"type": "direct"}]
            });
            let mut server = Command::new(binary).args(["run", "-c", "stdin"])
                .stdin(Stdio::piped()).stdout(Stdio::null()).stderr(Stdio::null())
                .kill_on_drop(true).spawn().unwrap();
            server.stdin.take().unwrap().write_all(&serde_json::to_vec(&document).unwrap()).await.unwrap();
            timeout(Duration::from_secs(5), async {
                loop {
                    assert!(server.try_wait().unwrap().is_none(), "sing-box exited before startup");
                    match std::net::UdpSocket::bind(server_addr) {
                        Err(error) if error.kind() == io::ErrorKind::AddrInUse => break,
                        Ok(socket) => drop(socket),
                        Err(error) => panic!("sing-box UDP readiness failed: {error}"),
                    }
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
            }).await.unwrap();

            for induce_loss in [false, true] {
                let relay = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
                let relay_addr = relay.local_addr().unwrap();
                let dropping = Arc::new(AtomicBool::new(false));
                let dropped = Arc::new(AtomicU64::new(0));
                let reordered = Arc::new(AtomicU64::new(0));
                let highest_forwarded = Arc::new(AtomicU64::new(0));
                let relay_dropping = dropping.clone();
                let relay_dropped = dropped.clone();
                let relay_reordered = reordered.clone();
                let relay_highest = highest_forwarded.clone();
                let relay_task = tokio::spawn(async move {
                    let mut client = None;
                    let mut counter = 0_u64;
                    let mut data = vec![0_u8; 65_536];
                    loop {
                        let (length, from) = relay.recv_from(&mut data).await.unwrap();
                        let mut sequence = None;
                        let destination = if from == server_addr {
                            client
                        } else {
                            client = Some(from);
                            if relay_dropping.load(Ordering::Relaxed) {
                                counter += 1;
                                sequence = Some(counter);
                                if counter.is_multiple_of(17) {
                                    relay_dropped.fetch_add(1, Ordering::Relaxed);
                                    continue;
                                }
                            }
                            Some(server_addr)
                        };
                        if let Some(destination) = destination {
                            let packet = data[..length].to_vec();
                            let sender = relay.clone();
                            let reordered = relay_reordered.clone();
                            let highest = relay_highest.clone();
                            tokio::spawn(async move {
                                let delay = if sequence.is_some_and(|value| value.is_multiple_of(23)) { 35 } else { 10 };
                                tokio::time::sleep(Duration::from_millis(delay)).await;
                                if let Some(sequence) = sequence
                                    && highest.fetch_max(sequence, Ordering::Relaxed) > sequence
                                {
                                    reordered.fetch_add(1, Ordering::Relaxed);
                                }
                                let _ = sender.send_to(&packet, destination).await;
                            });
                        }
                    }
                });
                let target = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                let destination = target.local_addr().unwrap();
                let target_task = tokio::spawn(async move {
                    let (mut stream, _) = target.accept().await.unwrap();
                    let mut payload = vec![0_u8; 512 * 1024];
                    stream.read_exact(&mut payload).await.unwrap();
                    assert!(payload.iter().all(|byte| *byte == 0x6d));
                    stream.write_all(b"ok").await.unwrap();
                });
                let config = pathchord_policy::TransitProxyConfig {
                    id: TransitProxyId::new("hy2-brutal"), source: None, protocol: "hysteria2".into(),
                    endpoint: PolicyEndpoint { host: relay_addr.ip().to_string(), port: relay_addr.port() },
                    credentials_ref: None, labels: BTreeMap::new(), tags: BTreeSet::new(), weight: 100,
                    options: TransitOptions { tls: Some(pathchord_policy::TransitTls {
                        enabled: true, server_name: Some("hysteria.test".into()),
                        certificate: vec![cert.cert.pem()], ..Default::default()
                    }), ..Default::default() },
                };
                let credentials = TransitCredential::new(BTreeMap::from([
                    ("password".into(), "correct-password".into()),
                    ("up_mbps".into(), "2".into()),
                    ("down_mbps".into(), "2".into()),
                ]));
                let adapter = Hysteria2Adapter::from_config(
                    &config, &credentials, Duration::from_secs(5), crate::adapter_registry::native_tls_roots()
                ).unwrap();
                let mut session = adapter.connect_session().await.unwrap();
                adapter.authenticate(&mut session).await.unwrap();
                let connection = session.connection.clone();
                let controller = connection.congestion_state().into_any()
                    .downcast::<brutal::BrutalController>().unwrap();
                assert_eq!(controller.target(), 125_000);
                let (mut send, recv) = connection.open_bi().await.unwrap();
                send.write_all(&crate::hysteria2_codec::encode_tcp_request(&destination.to_string(), &[]).unwrap()).await.unwrap();
                let mut stream = Hysteria2Stream {
                    send, recv, session: Some(session), drain_timeout: Duration::from_secs(2),
                    response_done: false, response_buffer: Vec::new(),
                    leftover: Vec::new(), leftover_pos: 0,
                };
                dropping.store(induce_loss, Ordering::Relaxed);
                let started = Instant::now();
                stream.write_all(&vec![0x6d; 512 * 1024]).await.unwrap();
                let mut ack = [0_u8; 2];
                stream.read_exact(&mut ack).await.unwrap();
                let elapsed = started.elapsed();
                assert_eq!(&ack, b"ok");
                eprintln!(
                    "Hysteria2 512 KiB upload: {elapsed:?}, induced loss: {induce_loss}, lost packets: {}, RTT: {:?}",
                    connection.stats().path.lost_packets, connection.rtt()
                );
                assert!(elapsed >= Duration::from_millis(2_500), "upload ran too quickly: {elapsed:?}");
                assert!(elapsed < Duration::from_secs(18), "upload stalled: {elapsed:?}");
                let controller = connection.congestion_state().into_any()
                    .downcast::<brutal::BrutalController>().unwrap();
                let (acked, total) = controller.sample_ratio();
                assert!(total >= 50, "insufficient packet samples: {total}");
                if induce_loss {
                    assert!(dropped.load(Ordering::Relaxed) > 0);
                    assert!(reordered.load(Ordering::Relaxed) > 0);
                    assert!(connection.stats().path.lost_packets > 0);
                    assert!(acked < total, "lost packets did not reach Brutal");
                } else {
                    assert_eq!(acked, total);
                }
                target_task.await.unwrap();
                connection.close(0_u32.into(), b"done");
                relay_task.abort();
            }
            server.kill().await.unwrap();
            server.wait().await.unwrap();
        }).await.expect("bounded Hysteria2 Brutal transfer and loss test");
    }

    #[tokio::test]
    #[ignore = "requires PATHCHORD_TEST_SING_BOX pointing to sing-box 1.14.4"]
    async fn native_hysteria2_rejects_invalid_sing_box_auth() {
        timeout(Duration::from_secs(20), async {
            {
                let binary = PathBuf::from(std::env::var_os("PATHCHORD_TEST_SING_BOX").expect("reference peer"));
                let cert = rcgen::generate_simple_self_signed(vec!["hysteria.test".into()]).unwrap();
                let reserved = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
                let port = reserved.local_addr().unwrap().port();
                drop(reserved);
                let inbound = json!({
                    "type": "hysteria2", "listen": "127.0.0.1", "listen_port": port,
                    "users": [{"password": "correct-password"}],
                    "tls": {"enabled": true, "certificate": cert.cert.pem(), "key": cert.signing_key.serialize_pem()}
                });
                let document = json!({"log": {"disabled": true}, "inbounds": [inbound], "outbounds": [{"type":"direct"}]});
                let mut server = Command::new(binary).args(["run", "-c", "stdin"])
                    .stdin(Stdio::piped()).stdout(Stdio::null()).stderr(Stdio::null()).kill_on_drop(true).spawn().unwrap();
                server.stdin.take().unwrap().write_all(&serde_json::to_vec(&document).unwrap()).await.unwrap();
                timeout(Duration::from_secs(5), async {
                    loop {
                        assert!(server.try_wait().unwrap().is_none(), "sing-box exited before startup");
                        match std::net::UdpSocket::bind(("127.0.0.1", port)) {
                            Err(error) if error.kind() == io::ErrorKind::AddrInUse => break,
                            Ok(socket) => drop(socket),
                            Err(error) => panic!("sing-box UDP readiness failed: {error}"),
                        }
                        tokio::time::sleep(Duration::from_millis(20)).await;
                    }
                }).await.expect("sing-box Hysteria2 startup timed out");
                let config = pathchord_policy::TransitProxyConfig {
                    id: TransitProxyId::new("hy2-negative"), source: None, protocol: "hysteria2".into(),
                    endpoint: PolicyEndpoint {host: "127.0.0.1".into(), port}, credentials_ref: None,
                    labels: BTreeMap::new(), tags: BTreeSet::new(), weight: 100,
                    options: TransitOptions { tls: Some(pathchord_policy::TransitTls {
                        enabled: true, server_name: Some("hysteria.test".into()),
                        certificate: vec![cert.cert.pem()], ..Default::default()
                    }), ..Default::default() },
                };
                let credentials = TransitCredential::new(BTreeMap::from([
                    ("password".into(), "wrong-password".into()),
                    ("down_mbps".into(), "2".into()),
                ]));
                let adapter = Hysteria2Adapter::from_config(&config, &credentials, Duration::from_secs(3), crate::adapter_registry::native_tls_roots()).unwrap();
                let target = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                let request = ConnectRequest { destination: TransitEndpoint { host: "127.0.0.1".into(), port: target.local_addr().unwrap().port() } };
                let result = adapter.connect(request.clone()).await;
                assert!(matches!(result, Err(TransitError::Protocol(_))));
                assert!(timeout(Duration::from_millis(100), target.accept()).await.is_err());
                server.kill().await.unwrap();
                server.wait().await.unwrap();
            }
        }).await.expect("Hysteria2 independent negotiation rejection timed out");
    }

    async fn sing_box_roundtrip(
        obfs: Option<&str>,
        down_mbps: Option<&str>,
        ignore_client_bandwidth: bool,
        up_mbps: Option<&str>,
        server_down_mbps: Option<u64>,
        gecko_sizes: Option<(usize, usize)>,
        relay_gecko: bool,
    ) {
        let binary =
            PathBuf::from(std::env::var_os("PATHCHORD_TEST_SING_BOX").expect("reference peer"));
        let cert =
            rcgen::generate_simple_self_signed(vec!["hysteria.test".into()]).expect("certificate");
        let server_key = cert.signing_key.serialize_pem();
        let mut document = json!({
            "log": {"level": "info"},
            "inbounds": [{
                "type": "hysteria2",
                "listen": "127.0.0.1",
                "listen_port": 0,
                "users": [{"password": "pathchord-hysteria-password"}],
                "tls": {
                    "enabled": true,
                    "server_name": "hysteria.test",
                    "certificate": cert.cert.pem(),
                    "key": server_key
                }
            }],
            "outbounds": [{"type": "direct", "tag": "direct"}],
            "route": {"final": "direct"}
        });
        if let Some(obfs) = obfs.filter(|_| !relay_gecko) {
            document["inbounds"][0]["obfs"] =
                json!({"type": obfs, "password": "pathchord-obfuscation"});
        }
        if let Some((minimum, maximum)) = gecko_sizes.filter(|_| !relay_gecko) {
            document["inbounds"][0]["obfs"]["min_packet_size"] = json!(minimum);
            document["inbounds"][0]["obfs"]["max_packet_size"] = json!(maximum);
        }
        if let Some(rate) = server_down_mbps {
            document["inbounds"][0]["down_mbps"] = json!(rate);
        }
        if ignore_client_bandwidth {
            document["inbounds"][0]["ignore_client_bandwidth"] = json!(true);
        } else if down_mbps.is_some() {
            document["inbounds"][0]["up_mbps"] = json!(1);
        }
        let config = serde_json::to_vec(&document).unwrap();
        let mut server = Command::new(binary)
            .arg("run")
            .arg("-c")
            .arg("stdin")
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
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
        let mut server = FixturePeer::new(server);
        let mut server_address = server
            .wait_for_udp(Duration::from_secs(10))
            .await
            .unwrap_or_else(|error| panic!("Hysteria2 {obfs:?} server startup: {error}"));
        let mut relay = if relay_gecko {
            let (minimum, maximum) = gecko_sizes.expect("relay requires Gecko sizes");
            let binary = std::env::var_os("PATHCHORD_TEST_GECKO_RELAY")
                .expect("PATHCHORD_TEST_GECKO_RELAY must name the independent Go fixture");
            let mut process = Command::new(binary)
                .arg(server_address.to_string())
                .arg(minimum.to_string())
                .arg(maximum.to_string())
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .kill_on_drop(true)
                .spawn()
                .unwrap();
            let stdout = process.stdout.take().unwrap();
            let mut line = String::new();
            timeout(
                Duration::from_secs(5),
                BufReader::new(stdout).read_line(&mut line),
            )
            .await
            .unwrap()
            .unwrap();
            server_address = line
                .trim()
                .parse()
                .expect("independent Gecko relay address");
            Some(process)
        } else {
            None
        };
        let target = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_addr = target.local_addr().unwrap();
        let target_task = tokio::spawn(async move {
            let (mut stream, _) = target.accept().await.unwrap();
            let mut payload = vec![0_u8; 64 * 1024];
            stream.read_exact(&mut payload).await.unwrap();
            stream.write_all(&payload).await.unwrap();
            let mut tail = Vec::new();
            stream.read_to_end(&mut tail).await.unwrap();
            assert_eq!(tail, b"upload before shutdown");
        });
        let mut config = pathchord_policy::TransitProxyConfig {
            id: TransitProxyId::new("hysteria2-test"),
            source: None,
            protocol: "hysteria2".into(),
            endpoint: PolicyEndpoint {
                host: server_address.ip().to_string(),
                port: server_address.port(),
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
            certificate: vec![cert.cert.pem()],
            ..Default::default()
        });
        let mut fields =
            BTreeMap::from([("password".into(), "pathchord-hysteria-password".into())]);
        if let Some(obfs) = obfs {
            fields.insert("obfs".into(), obfs.into());
            fields.insert("obfs_password".into(), "pathchord-obfuscation".into());
        }
        if let Some((minimum, maximum)) = gecko_sizes {
            fields.insert("gecko_min_packet_size".into(), minimum.to_string());
            fields.insert("gecko_max_packet_size".into(), maximum.to_string());
        }
        if let Some(rate) = down_mbps {
            fields.insert("down_mbps".into(), rate.into());
        }
        if let Some(rate) = up_mbps {
            fields.insert("up_mbps".into(), rate.into());
        }
        let credentials = TransitCredential::new(fields);
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
            .unwrap_or_else(|error| {
                panic!(
                    "Hysteria2 {obfs:?} TCP connection failed: {error}; {}",
                    server.diagnostic()
                )
            });
        let upload: Vec<u8> = (0..64 * 1024).map(|value| (value % 251) as u8).collect();
        stream.write_all(&upload).await.unwrap();
        stream.flush().await.unwrap();
        let mut echoed = vec![0_u8; upload.len()];
        stream.read_exact(&mut echoed).await.unwrap();
        assert_eq!(echoed, upload);
        stream.write_all(b"upload before shutdown").await.unwrap();
        stream.shutdown().await.unwrap();
        drop(stream);
        target_task.await.unwrap();
        let udp_target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let udp_address = udp_target.local_addr().unwrap();
        let udp_task = tokio::spawn(async move {
            let mut payload = [0_u8; 4096];
            for _ in 0..6 {
                let (length, peer) = udp_target.recv_from(&mut payload).await.unwrap();
                udp_target.send_to(&payload[..length], peer).await.unwrap();
            }
        });
        let mut datagram = adapter
            .connect_udp(ConnectRequest {
                destination: crate::Endpoint {
                    host: udp_address.ip().to_string(),
                    port: udp_address.port(),
                },
            })
            .await
            .unwrap_or_else(|error| {
                panic!(
                    "Hysteria2 {obfs:?} UDP connection failed: {error}; {}",
                    server.diagnostic()
                )
            });
        for length in [1, 31, 511, 1000, 2048, 4096] {
            let packet = vec![0x5a; length];
            datagram.send(&packet).await.unwrap();
            assert_eq!(datagram.receive().await.unwrap(), packet);
        }
        datagram.close().await.unwrap();
        udp_task.await.unwrap();

        if let Ok(target) = tokio::net::TcpListener::bind("[::1]:0").await {
            let address = target.local_addr().unwrap();
            let task = tokio::spawn(async move {
                let (mut stream, _) = target.accept().await.unwrap();
                let mut payload = [0_u8; 4];
                stream.read_exact(&mut payload).await.unwrap();
                stream.write_all(&payload).await.unwrap();
            });
            let mut stream = adapter
                .connect(ConnectRequest {
                    destination: crate::Endpoint {
                        host: address.ip().to_string(),
                        port: address.port(),
                    },
                })
                .await
                .unwrap();
            stream.write_all(b"ipv6").await.unwrap();
            let mut response = [0_u8; 4];
            stream.read_exact(&mut response).await.unwrap();
            assert_eq!(&response, b"ipv6");
            task.await.unwrap();

            let target = UdpSocket::bind("[::1]:0").await.unwrap();
            let address = target.local_addr().unwrap();
            let task = tokio::spawn(async move {
                let mut payload = [0_u8; 32];
                let (length, peer) = target.recv_from(&mut payload).await.unwrap();
                target.send_to(&payload[..length], peer).await.unwrap();
            });
            let mut datagram = adapter
                .connect_udp(ConnectRequest {
                    destination: crate::Endpoint {
                        host: address.ip().to_string(),
                        port: address.port(),
                    },
                })
                .await
                .unwrap();
            datagram.send(b"ipv6-udp").await.unwrap();
            assert_eq!(datagram.receive().await.unwrap(), b"ipv6-udp");
            datagram.close().await.unwrap();
            task.await.unwrap();
        }
        server.child.kill().await.unwrap();
        server.child.wait().await.unwrap();
        if let Some(relay) = &mut relay {
            relay.kill().await.unwrap();
            relay.wait().await.unwrap();
        }
    }
}
