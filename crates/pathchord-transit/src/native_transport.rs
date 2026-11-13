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
    websocket: Option<tokio_tungstenite::tungstenite::http::Request<()>>,
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
        let tls = match tls_options.as_ref() {
            Some(options) => Some((
                crate::tls::configure(base, Some(options), Some(credential))?,
                crate::tls::server_name(&config.endpoint.host, Some(options))?,
            )),
            None => None,
        };
        let mut websocket = None;
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
                    if transport.service_name.is_some()
                        || transport.host.len() > 1
                        || transport.max_early_data.unwrap_or(0) != 0
                        || transport.early_data_header_name.is_some()
                    {
                        return Err(unsupported(
                            "native WebSocket early data or transport parameters are unsupported",
                        ));
                    }
                    if tls_options
                        .as_ref()
                        .is_some_and(|tls| tls.alpn.iter().any(|value| value != "http/1.1"))
                    {
                        return Err(unsupported("native WebSocket TLS requires HTTP/1.1 ALPN"));
                    }
                    let host = if config.endpoint.host.contains(':') {
                        format!("[{}]", config.endpoint.host)
                    } else {
                        config.endpoint.host.clone()
                    };
                    let path = transport.path.as_deref().unwrap_or("/");
                    if !path.starts_with('/')
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
                        request.headers_mut().insert(name, value);
                    }
                    if let Some(host) = transport.host.first() {
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
                    websocket = Some(request);
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
            timeout: duration,
        })
    }

    pub async fn connect(&self) -> Result<BoxedTransitConnection, TransitError> {
        timeout(self.timeout, async {
            let stream = connect_tcp_endpoint(&self.endpoint, self.timeout).await?;
            let mut stream: BoxedTransitConnection = Box::new(stream);
            if let Some((tls, name)) = &self.tls {
                stream = Box::new(
                    tokio_rustls::TlsConnector::from(Arc::clone(tls))
                        .connect(name.clone(), stream)
                        .await
                        .map_err(|_| {
                            TransitError::Connection("native proxy TLS handshake failed".into())
                        })?,
                );
            }
            if let Some(request) = &self.websocket {
                let config = WebSocketConfig::default()
                    .read_buffer_size(16 * 1024)
                    .write_buffer_size(0)
                    .max_write_buffer_size(128 * 1024)
                    .max_message_size(Some(1024 * 1024))
                    .max_frame_size(Some(1024 * 1024));
                let (websocket, _) = tokio_tungstenite::client_async_with_config(
                    request.clone(),
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
