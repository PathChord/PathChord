//! Native byte transports used by protocol clients, with bounded WebSocket I/O.

use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use futures_util::{Sink, Stream};
use pathchord_policy::{TransitProxyConfig, TransitTls};
use rustls::ClientConfig;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::time::timeout;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::{HeaderName, HeaderValue};
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;

use crate::{
    BoxedTransitConnection, Endpoint, TransitCredential, TransitError, connect_tcp_endpoint,
};

pub(crate) struct NativeTransport {
    endpoint: Endpoint,
    tls: Option<(Arc<ClientConfig>, rustls::pki_types::ServerName<'static>)>,
    websocket: Option<crate::websocket_early::WebSocketEarlyConfig>,
    http_upgrade: Option<crate::http_upgrade::HttpUpgrade>,
    grpc: Option<crate::grpc_transport::GrpcConfig>,
    http: Option<crate::http_transport::HttpTransport>,
    quic: Option<crate::v2ray_quic::QuicTransport>,
    meek: Option<crate::meek_transport::MeekTransport>,
    require_tls13: bool,
    timeout: Duration,
}

impl NativeTransport {
    pub fn new(
        config: &TransitProxyConfig,
        credential: &TransitCredential,
        base: Arc<ClientConfig>,
        duration: Duration,
    ) -> Result<Self, TransitError> {
        config
            .options
            .validate()
            .map_err(|_| unsupported("invalid native transport options"))?;
        let options = &config.options;
        if !options.headers.is_empty()
            || options.udp_over_tcp.is_some()
            || (options.vmess.is_some() && config.protocol != "vmess")
            || options.tcp_fast_open == Some(true)
            || options.bind_interface.is_some()
            || options.routing_mark.is_some()
            || options.packet_encoding.is_some()
            || options
                .multiplex
                .as_ref()
                .is_some_and(|value| value != &pathchord_policy::TransitMultiplex::default())
        {
            return Err(unsupported(
                "node dialer, packet, or multiplex options require a different backend",
            ));
        }
        let tls_options = match options.tls.as_ref() {
            Some(value) if value.enabled => Some(value.clone()),
            Some(value) if value != &TransitTls::default() => {
                return Err(unsupported("TLS settings require enabled TLS"));
            }
            _ if config.protocol == "trojan" => Some(TransitTls {
                enabled: true,
                ..Default::default()
            }),
            _ => None,
        };
        if config.protocol == "trojan" && options.tls.as_ref().is_some_and(|value| !value.enabled) {
            return Err(unsupported("native Trojan requires TLS"));
        }
        let mut tls = match tls_options.as_ref() {
            Some(options) => Some((
                if base.reality_callback.is_some() {
                    Arc::clone(&base)
                } else {
                    crate::tls::configure(base, Some(options), Some(credential))?
                },
                crate::tls::server_name(&config.endpoint.host, Some(options))?,
            )),
            None => None,
        };
        let mut websocket = None;
        let mut http_upgrade = None;
        let mut grpc = None;
        let mut http = None;
        let mut quic = None;
        let mut meek = None;
        if credential.field("meek_url").is_some()
            && options
                .transport
                .as_ref()
                .is_none_or(|transport| transport.kind != "meek")
        {
            return Err(unsupported("Meek URL requires Meek transport"));
        }
        if let Some(transport) = &options.transport {
            match transport.kind.as_str() {
                "tcp"
                    if transport.path.is_none()
                        && transport.host.is_empty()
                        && transport.headers.is_empty()
                        && transport.service_name.is_none()
                        && transport.max_early_data.is_none()
                        && transport.early_data_header_name.is_none() => {}
                "ws" => {
                    if transport.service_name.is_some() || transport.host.len() > 1 {
                        return Err(unsupported(
                            "native WebSocket transport parameters are unsupported",
                        ));
                    }
                    if tls_options
                        .as_ref()
                        .is_some_and(|tls| tls.alpn.iter().any(|value| value != "http/1.1"))
                    {
                        return Err(unsupported("native WebSocket TLS requires HTTP/1.1 ALPN"));
                    }
                    if let Some((client, _)) = &mut tls
                        && client.alpn_protocols.is_empty()
                    {
                        Arc::make_mut(client).alpn_protocols = vec![b"http/1.1".to_vec()];
                    }
                    let host = if config.endpoint.host.contains(':') {
                        format!("[{}]", config.endpoint.host)
                    } else {
                        config.endpoint.host.clone()
                    };
                    let path = transport.path.as_deref().unwrap_or("/");
                    if !path.starts_with('/')
                        || path.contains('#')
                        || path
                            .bytes()
                            .any(|value| value.is_ascii_control() || value == b' ')
                    {
                        return Err(unsupported("WebSocket path is invalid"));
                    }
                    let uri = format!(
                        "{}://{host}:{}{path}",
                        if tls.is_some() { "wss" } else { "ws" },
                        config.endpoint.port
                    );
                    let mut request = uri
                        .into_client_request()
                        .map_err(|_| unsupported("WebSocket request is invalid"))?;
                    for (name, value) in &transport.headers {
                        if name.eq_ignore_ascii_case("connection")
                            || name.eq_ignore_ascii_case("upgrade")
                            || name.to_ascii_lowercase().starts_with("sec-websocket-")
                        {
                            return Err(unsupported(
                                "WebSocket headers conflict with protocol handshake fields",
                            ));
                        }
                        let name = HeaderName::from_bytes(name.as_bytes())
                            .map_err(|_| unsupported("WebSocket header name is invalid"))?;
                        let value = HeaderValue::from_str(value)
                            .map_err(|_| unsupported("WebSocket header value is invalid"))?;
                        if name == tokio_tungstenite::tungstenite::http::header::HOST {
                            let host = value
                                .to_str()
                                .map_err(|_| unsupported("WebSocket Host is invalid"))?;
                            if host.contains('@') || host.parse::<http::uri::Authority>().is_err() {
                                return Err(unsupported("WebSocket Host is invalid"));
                            }
                        }
                        request.headers_mut().insert(name, value);
                    }
                    if let Some(host) = transport.host.first() {
                        if host.contains('@') || host.parse::<http::uri::Authority>().is_err() {
                            return Err(unsupported("WebSocket Host is invalid"));
                        }
                        if transport
                            .headers
                            .iter()
                            .any(|(name, value)| name.eq_ignore_ascii_case("host") && value != host)
                        {
                            return Err(unsupported("WebSocket Host options conflict"));
                        }
                        request.headers_mut().insert(
                            "Host",
                            HeaderValue::from_str(host)
                                .map_err(|_| unsupported("WebSocket Host is invalid"))?,
                        );
                    }
                    websocket = Some(crate::websocket_early::WebSocketEarlyConfig::new(
                        request,
                        transport.max_early_data,
                        transport.early_data_header_name.as_deref(),
                    )?);
                }
                "httpupgrade" => {
                    http_upgrade = Some(crate::http_upgrade::HttpUpgrade::new(config, transport)?);
                    if let Some((client, _)) = &mut tls
                        && client.alpn_protocols.is_empty()
                    {
                        Arc::make_mut(client).alpn_protocols = vec![b"http/1.1".to_vec()];
                    }
                }
                "grpc" => {
                    if tls_options
                        .as_ref()
                        .is_some_and(|tls| tls.alpn.iter().any(|value| value != "h2"))
                    {
                        return Err(unsupported("gRPC TLS requires h2 ALPN"));
                    }
                    grpc = Some(crate::grpc_transport::GrpcConfig::new(
                        config,
                        transport,
                        tls.is_some(),
                    )?);
                    if let Some((client, _)) = &mut tls {
                        let mut configured = (**client).clone();
                        if configured.alpn_protocols.is_empty() {
                            configured.alpn_protocols = vec![b"h2".to_vec()];
                        }
                        *client = Arc::new(configured);
                    }
                }
                "http" => {
                    if tls_options.as_ref().is_some_and(|tls| {
                        tls.enabled && tls.alpn.iter().any(|value| value != "h2")
                    }) {
                        return Err(unsupported("HTTP transport TLS requires h2 ALPN"));
                    }
                    http = Some(crate::http_transport::HttpTransport::new(
                        config,
                        transport,
                        tls.is_some(),
                    )?);
                    if let Some((client, _)) = &mut tls
                        && client.alpn_protocols.is_empty()
                    {
                        Arc::make_mut(client).alpn_protocols = vec![b"h2".to_vec()];
                    }
                }
                "quic" => {
                    if !matches!(config.protocol.as_str(), "vless" | "vmess" | "trojan") {
                        return Err(unsupported("V2Ray QUIC is unsupported for this protocol"));
                    }
                    if transport.path.is_some()
                        || !transport.host.is_empty()
                        || !transport.headers.is_empty()
                        || transport.service_name.is_some()
                        || transport.max_early_data.is_some()
                        || transport.early_data_header_name.is_some()
                    {
                        return Err(unsupported(
                            "V2Ray QUIC transport parameters are unsupported",
                        ));
                    }
                    if tls_options
                        .as_ref()
                        .is_some_and(|value| value.reality.is_some() || value.fingerprint.is_some())
                    {
                        return Err(unsupported(
                            "V2Ray QUIC does not support REALITY or TLS fingerprints",
                        ));
                    }
                    let (client, _) = tls
                        .as_ref()
                        .ok_or_else(|| unsupported("V2Ray QUIC requires TLS"))?;
                    let server_name = tls_options
                        .as_ref()
                        .and_then(|options| options.server_name.clone())
                        .unwrap_or_else(|| config.endpoint.host.clone());
                    quic = Some(crate::v2ray_quic::QuicTransport::new(
                        Endpoint {
                            host: config.endpoint.host.clone(),
                            port: config.endpoint.port,
                        },
                        server_name,
                        Arc::clone(client),
                        duration,
                    )?);
                }
                "meek" => {
                    if !matches!(config.protocol.as_str(), "vless" | "vmess") {
                        return Err(unsupported("Meek is unsupported for this protocol"));
                    }
                    if transport.path.is_some()
                        || !transport.host.is_empty()
                        || !transport.headers.is_empty()
                        || transport.service_name.is_some()
                        || transport.max_early_data.is_some()
                        || transport.early_data_header_name.is_some()
                    {
                        return Err(unsupported(
                            "Meek URL and headers must not use public transport options",
                        ));
                    }
                    if tls_options
                        .as_ref()
                        .is_some_and(|value| value.reality.is_some())
                    {
                        return Err(unsupported("Meek does not support REALITY"));
                    }
                    let (client, name) = tls
                        .as_ref()
                        .ok_or_else(|| unsupported("Meek requires TLS"))?;
                    let private_url = credential
                        .field("meek_url")
                        .ok_or_else(|| unsupported("Meek URL is missing"))?;
                    meek = Some(crate::meek_transport::MeekTransport::new(
                        private_url,
                        Arc::clone(client),
                        name.clone(),
                        duration,
                    )?);
                }
                _ => {
                    return Err(unsupported(
                        "native protocol transport is not supported by this backend",
                    ));
                }
            }
        }
        Ok(Self {
            endpoint: Endpoint {
                host: config.endpoint.host.clone(),
                port: config.endpoint.port,
            },
            tls,
            websocket,
            http_upgrade,
            grpc,
            http,
            quic,
            meek,
            require_tls13: false,
            timeout: duration,
        })
    }

    pub(crate) fn require_tls13(mut self) -> Self {
        self.require_tls13 = true;
        self
    }

    pub async fn connect(&self) -> Result<BoxedTransitConnection, TransitError> {
        self.connect_inner(None, None, None).await
    }

    pub(crate) async fn connect_vision(
        &self,
    ) -> Result<
        (
            BoxedTransitConnection,
            Arc<crate::vision_transport::VisionSwitch>,
        ),
        TransitError,
    > {
        let direct = Arc::new(crate::vision_transport::VisionSwitch::default());
        let stream = self
            .connect_inner(Some(Arc::clone(&direct)), None, None)
            .await?;
        Ok((stream, direct))
    }

    pub(crate) async fn connect_reality(
        &self,
        tls: Arc<ClientConfig>,
        vision: bool,
        authenticate: &(dyn Fn() -> Result<(), TransitError> + Send + Sync),
    ) -> Result<
        (
            BoxedTransitConnection,
            Option<Arc<crate::vision_transport::VisionSwitch>>,
        ),
        TransitError,
    > {
        let direct = vision.then(|| Arc::new(crate::vision_transport::VisionSwitch::default()));
        let stream = self
            .connect_inner(direct.clone(), Some(tls), Some(authenticate))
            .await?;
        Ok((stream, direct))
    }

    async fn connect_inner(
        &self,
        direct: Option<Arc<crate::vision_transport::VisionSwitch>>,
        tls_override: Option<Arc<ClientConfig>>,
        authenticate: Option<&(dyn Fn() -> Result<(), TransitError> + Send + Sync)>,
    ) -> Result<BoxedTransitConnection, TransitError> {
        if let Some(meek) = &self.meek {
            if direct.is_some() || tls_override.is_some() || authenticate.is_some() {
                return Err(unsupported("Meek does not support Vision or REALITY"));
            }
            return meek.connect();
        }
        if let Some(quic) = &self.quic {
            if direct.is_some() || tls_override.is_some() || authenticate.is_some() {
                return Err(unsupported("V2Ray QUIC does not support Vision or REALITY"));
            }
            return quic.connect().await;
        }
        timeout(self.timeout, async {
            let stream = connect_tcp_endpoint(&self.endpoint, self.timeout).await?;
            let mut stream: BoxedTransitConnection = Box::new(stream);
            if let Some((tls, name)) = &self.tls {
                let mut tls = tls_override.unwrap_or_else(|| Arc::clone(tls));
                if (self.grpc.is_some() || self.http.is_some()) && tls.alpn_protocols.is_empty() {
                    let mut configured = (*tls).clone();
                    configured.alpn_protocols = vec![b"h2".to_vec()];
                    tls = Arc::new(configured);
                }
                let connector = tokio_rustls::TlsConnector::from(tls);
                if let Some(direct) = direct {
                    let guarded = crate::vision_transport::RecordLimitedIo::new(stream);
                    let tls_stream =
                        connector
                            .connect(name.clone(), guarded)
                            .await
                            .map_err(|error| {
                                TransitError::Connection(format!(
                                    "native proxy TLS handshake failed: {error}"
                                ))
                            })?;
                    if tls_stream.get_ref().1.protocol_version()
                        != Some(rustls::ProtocolVersion::TLSv1_3)
                    {
                        return Err(unsupported("VLESS Vision requires TLS 1.3"));
                    }
                    stream = Box::new(crate::vision_transport::VisionTlsIo::new(
                        tls_stream, direct,
                    ));
                } else {
                    let tls_stream =
                        connector
                            .connect(name.clone(), stream)
                            .await
                            .map_err(|error| {
                                TransitError::Connection(format!(
                                    "native proxy TLS handshake failed: {error}"
                                ))
                            })?;
                    if self.grpc.is_some() || self.http.is_some() {
                        let negotiated = tls_stream.get_ref().1.alpn_protocol();
                        // REALITY authenticates the tunneled peer separately.
                        // It can omit ALPN while still carrying HTTP/2; an
                        // explicit conflicting protocol is never accepted.
                        if negotiated != Some(b"h2")
                            && !(authenticate.is_some() && negotiated.is_none())
                        {
                            return Err(unsupported("HTTP/2 TLS peer did not negotiate h2"));
                        }
                    }
                    if self.require_tls13
                        && tls_stream.get_ref().1.protocol_version()
                            != Some(rustls::ProtocolVersion::TLSv1_3)
                    {
                        return Err(unsupported("VLESS Vision requires TLS 1.3"));
                    }
                    stream = Box::new(tls_stream);
                }
            } else if direct.is_some() {
                return Err(unsupported("VLESS Vision requires enabled TLS"));
            }
            if let Some(authenticate) = authenticate {
                authenticate()?;
            }
            if let Some(websocket) = &self.websocket {
                if websocket.enabled() {
                    return Ok(websocket.wrap(stream, self.timeout));
                }
                let config = WebSocketConfig::default()
                    .read_buffer_size(16 * 1024)
                    .write_buffer_size(0)
                    .max_write_buffer_size(128 * 1024)
                    .max_message_size(Some(1024 * 1024))
                    .max_frame_size(Some(1024 * 1024));
                let (websocket, _) = tokio_tungstenite::client_async_with_config(
                    websocket.request().clone(),
                    stream,
                    Some(config),
                )
                .await
                .map_err(|_| {
                    TransitError::Protocol("native proxy WebSocket handshake failed".into())
                })?;
                stream = Box::new(WebSocketIo {
                    websocket,
                    pending: Default::default(),
                });
            } else if let Some(upgrade) = &self.http_upgrade {
                upgrade.handshake(&mut stream).await?;
            } else if let Some(grpc) = &self.grpc {
                stream = grpc.connect(stream).await?;
            } else if let Some(http) = &self.http {
                stream = http.connect(stream).await?;
            }
            Ok(stream)
        })
        .await
        .map_err(|_| TransitError::Connection("native proxy transport timed out".into()))?
    }
}

fn unsupported(message: &str) -> TransitError {
    TransitError::Unsupported(message.to_owned())
}
fn io_error() -> std::io::Error {
    std::io::Error::other("proxy WebSocket transport failed")
}

struct WebSocketIo {
    websocket: tokio_tungstenite::WebSocketStream<BoxedTransitConnection>,
    pending: tokio_tungstenite::tungstenite::Bytes,
}

pub(crate) fn websocket_byte_stream(
    websocket: tokio_tungstenite::WebSocketStream<BoxedTransitConnection>,
) -> BoxedTransitConnection {
    Box::new(WebSocketIo {
        websocket,
        pending: Default::default(),
    })
}

impl AsyncRead for WebSocketIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if buffer.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        for _ in 0..16 {
            if !self.pending.is_empty() {
                let length = self.pending.len().min(buffer.remaining());
                buffer.put_slice(&self.pending.split_to(length));
                return Poll::Ready(Ok(()));
            }
            match Pin::new(&mut self.websocket).poll_next(cx) {
                Poll::Ready(Some(Ok(Message::Binary(bytes)))) => self.pending = bytes,
                Poll::Ready(Some(Ok(Message::Ping(_) | Message::Pong(_)))) => {}
                Poll::Ready(Some(Ok(Message::Close(_)))) | Poll::Ready(None) => {
                    return Poll::Ready(Ok(()));
                }
                Poll::Ready(Some(_)) => return Poll::Ready(Err(io_error())),
                Poll::Pending => return Poll::Pending,
            }
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }
}

impl AsyncWrite for WebSocketIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        if bytes.is_empty() {
            return Poll::Ready(Ok(0));
        }
        match Pin::new(&mut self.websocket).poll_ready(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(_)) => Poll::Ready(Err(io_error())),
            Poll::Ready(Ok(())) => {
                let length = bytes.len().min(16 * 1024);
                match Pin::new(&mut self.websocket)
                    .start_send(Message::binary(bytes[..length].to_vec()))
                {
                    Ok(()) => Poll::Ready(Ok(length)),
                    Err(_) => Poll::Ready(Err(io_error())),
                }
            }
        }
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.websocket)
            .poll_flush(cx)
            .map_err(|_| io_error())
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.websocket)
            .poll_close(cx)
            .map_err(|_| io_error())
    }
}
