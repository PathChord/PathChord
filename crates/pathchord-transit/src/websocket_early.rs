//! Lazy WebSocket upgrade with bounded V2Ray-compatible early data.

use std::future::Future;
use std::io::{self, ErrorKind};
use std::pin::Pin;
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use futures_util::{Sink, Stream};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::{
    Message,
    handshake::{client::generate_key, derive_accept_key},
    http::{HeaderMap, HeaderName, HeaderValue, Request, Uri},
    protocol::{Role, WebSocketConfig},
};
use zeroize::Zeroizing;

use crate::{BoxedTransitConnection, TransitError};

const MAX_EARLY_DATA: usize = 65_536;
const MAX_RESPONSE_HEADERS: usize = 32 * 1024;
const MAX_RESPONSE_HEADER_COUNT: usize = 128;
const MAX_FRAME_PAYLOAD: usize = 16 * 1024;

/// Construct once from the already validated WebSocket request and transport options.
#[derive(Clone)]
pub(crate) struct WebSocketEarlyConfig {
    request: Request<()>,
    maximum: usize,
    header: Option<HeaderName>,
}

impl WebSocketEarlyConfig {
    pub(crate) fn new(
        mut request: Request<()>,
        maximum: Option<u32>,
        header_name: Option<&str>,
    ) -> Result<Self, TransitError> {
        let path_query = request
            .uri()
            .path_and_query()
            .ok_or_else(|| unsupported("WebSocket URI has no path"))?
            .as_str();
        let query_present = path_query.contains('?');
        let (path, query) = path_query.split_once('?').unwrap_or((path_query, ""));
        let mut query_early = None;
        let mut query_header = None;
        let mut duplicate_query_header = false;
        let mut remaining = Vec::new();
        if !query.is_empty() {
            for part in query.split('&') {
                let (decoded, value) = url::form_urlencoded::parse(part.as_bytes())
                    .next()
                    .map(|(key, value)| (key.into_owned(), value.into_owned()))
                    .unwrap_or_default();
                if decoded == "ed" {
                    if query_early.is_some()
                        || value.is_empty()
                        || !value.bytes().all(|b| b.is_ascii_digit())
                    {
                        return Err(unsupported("invalid WebSocket early data query"));
                    }
                    query_early = Some(
                        value
                            .parse::<u32>()
                            .map_err(|_| unsupported("invalid WebSocket early data query"))?,
                    );
                } else {
                    if decoded == "eh" {
                        duplicate_query_header |= query_header.is_some();
                        query_header = Some(value);
                    }
                    remaining.push(part);
                }
            }
        }
        let query_header = query_header.as_deref().filter(|value| !value.is_empty());
        if let Some(query_maximum) = query_early {
            if duplicate_query_header {
                return Err(unsupported("duplicate WebSocket early data header query"));
            }
            if maximum.is_some_and(|value| value != query_maximum) {
                return Err(unsupported("conflicting WebSocket early data limits"));
            }
            let effective_header = query_header.unwrap_or("Sec-WebSocket-Protocol");
            if header_name.is_some_and(|value| {
                !value.is_empty() && !value.eq_ignore_ascii_case(effective_header)
            }) {
                return Err(unsupported("conflicting WebSocket early data header"));
            }
        }
        let maximum = maximum.or(query_early).unwrap_or(0) as usize;
        if maximum > MAX_EARLY_DATA {
            return Err(unsupported("WebSocket early data limit is too large"));
        }
        let requested_header = if query_early.is_some() && maximum > 0 {
            Some(query_header.unwrap_or("Sec-WebSocket-Protocol"))
        } else {
            header_name.filter(|value| !value.is_empty())
        };
        if maximum == 0 && requested_header.is_some() {
            return Err(unsupported(
                "WebSocket early data header requires a positive limit",
            ));
        }
        let header = requested_header
            .map(|name| {
                if name.len() > 128 {
                    return Err(unsupported("WebSocket early data header is too long"));
                }
                HeaderName::from_bytes(name.as_bytes())
                    .map_err(|_| unsupported("invalid WebSocket early data header"))
            })
            .transpose()?;
        if let Some(header) = &header {
            if matches!(
                header.as_str(),
                "host"
                    | "connection"
                    | "upgrade"
                    | "content-length"
                    | "transfer-encoding"
                    | "sec-websocket-key"
                    | "sec-websocket-version"
                    | "sec-websocket-extensions"
            ) {
                return Err(unsupported("WebSocket early data header is reserved"));
            }
            if request.headers().contains_key(header) {
                return Err(unsupported(
                    "WebSocket early data header conflicts with configured headers",
                ));
            }
        }
        if maximum > 0
            && header.is_none()
            && (query_present && query_early.is_none() || !remaining.is_empty())
        {
            return Err(unsupported(
                "WebSocket path early data cannot be combined with a query",
            ));
        }
        if query_early.is_some() {
            let path_query = if remaining.is_empty() {
                path.to_owned()
            } else {
                format!("{path}?{}", remaining.join("&"))
            };
            let mut parts = request.uri().clone().into_parts();
            parts.path_and_query = Some(
                path_query
                    .parse()
                    .map_err(|_| unsupported("invalid WebSocket path"))?,
            );
            *request.uri_mut() =
                Uri::from_parts(parts).map_err(|_| unsupported("invalid WebSocket URI"))?;
        }
        if request.method() != tokio_tungstenite::tungstenite::http::Method::GET
            || request.version() != tokio_tungstenite::tungstenite::http::Version::HTTP_11
            || !matches!(request.uri().scheme_str(), Some("ws" | "wss"))
            || request.uri().authority().is_none()
        {
            return Err(unsupported("invalid WebSocket request"));
        }
        if request.headers().contains_key("content-length")
            || request.headers().contains_key("transfer-encoding")
            || request.headers().contains_key("sec-websocket-extensions")
        {
            return Err(unsupported("unsupported WebSocket request header"));
        }
        Ok(Self {
            request,
            maximum,
            header,
        })
    }

    pub(crate) fn enabled(&self) -> bool {
        self.maximum > 0
    }

    /// The normalized request (notably, with an `ed` query parameter removed).
    pub(crate) fn request(&self) -> &Request<()> {
        &self.request
    }

    pub(crate) fn wrap(
        &self,
        stream: BoxedTransitConnection,
        timeout: Duration,
    ) -> BoxedTransitConnection {
        Box::new(EarlyWebSocket {
            state: State::Fresh {
                stream: Some(stream),
                config: self.clone(),
                timeout,
            },
            first_write: None,
            pending: Default::default(),
            read_waker: None,
            write_waker: None,
            write_closed: false,
        })
    }
}

fn unsupported(message: &'static str) -> TransitError {
    TransitError::Unsupported(message.to_owned())
}

fn failure(message: &'static str) -> io::Error {
    io::Error::new(ErrorKind::InvalidData, message)
}

type Ws = WebSocketStream<BoxedTransitConnection>;
type Handshake = Pin<Box<dyn Future<Output = io::Result<Ws>> + Send>>;

enum State {
    Fresh {
        stream: Option<BoxedTransitConnection>,
        config: WebSocketEarlyConfig,
        timeout: Duration,
    },
    Connecting(Handshake),
    Connected(Ws),
    Failed(ErrorKind, &'static str),
    Closed,
}

struct EarlyWebSocket {
    state: State,
    // A cancelled first write may be retried, but never replaced with different bytes.
    first_write: Option<Zeroizing<Vec<u8>>>,
    pending: tokio_tungstenite::tungstenite::Bytes,
    read_waker: Option<Waker>,
    write_waker: Option<Waker>,
    write_closed: bool,
}

impl EarlyWebSocket {
    fn start(&mut self, bytes: Option<&[u8]>) -> io::Result<()> {
        let State::Fresh {
            stream,
            config,
            timeout,
        } = &mut self.state
        else {
            return Ok(());
        };
        let mut request = config.request.clone();
        let early = bytes
            .map(|bytes| &bytes[..bytes.len().min(config.maximum)])
            .unwrap_or_default();
        if bytes.is_some() && !early.is_empty() {
            self.first_write = Some(Zeroizing::new(early.to_vec()));
        }
        if !early.is_empty() {
            let encoded = Zeroizing::new(URL_SAFE_NO_PAD.encode(early));
            if let Some(header) = &config.header {
                request.headers_mut().insert(
                    header.clone(),
                    HeaderValue::from_str(&encoded)
                        .map_err(|_| failure("invalid WebSocket early data"))?,
                );
            } else {
                let path = request.uri().path();
                let mut parts = request.uri().clone().into_parts();
                parts.path_and_query = Some(
                    format!("{path}{}", encoded.as_str())
                        .parse()
                        .map_err(|_| failure("invalid WebSocket early data path"))?,
                );
                *request.uri_mut() = Uri::from_parts(parts)
                    .map_err(|_| failure("invalid WebSocket early data URI"))?;
            }
        }
        let stream = stream.take().expect("fresh stream is present");
        let duration = *timeout;
        let protocol_is_early_data = config
            .header
            .as_ref()
            .is_some_and(|name| name.as_str() == "sec-websocket-protocol");
        self.state = State::Connecting(Box::pin(async move {
            tokio::time::timeout(duration, handshake(stream, request, protocol_is_early_data))
                .await
                .map_err(|_| io::Error::new(ErrorKind::TimedOut, "WebSocket handshake timed out"))?
        }));
        Ok(())
    }

    fn poll_connect(&mut self, cx: &mut Context<'_>, reading: bool) -> Poll<io::Result<()>> {
        if let State::Connecting(future) = &mut self.state {
            match future.as_mut().poll(cx) {
                Poll::Pending => {
                    if reading {
                        self.read_waker = Some(cx.waker().clone());
                    } else {
                        self.write_waker = Some(cx.waker().clone());
                    }
                    return Poll::Pending;
                }
                Poll::Ready(Ok(ws)) => self.state = State::Connected(ws),
                Poll::Ready(Err(error)) => {
                    let kind = error.kind();
                    self.state = State::Failed(kind, "WebSocket handshake failed");
                    self.wake_waiters();
                    return Poll::Ready(Err(error));
                }
            }
            self.wake_waiters();
        }
        match &self.state {
            State::Connected(_) => Poll::Ready(Ok(())),
            State::Failed(kind, message) => Poll::Ready(Err(io::Error::new(*kind, *message))),
            State::Closed => Poll::Ready(Err(io::Error::new(
                ErrorKind::BrokenPipe,
                "WebSocket is closed",
            ))),
            State::Fresh { .. } | State::Connecting(_) => unreachable!(),
        }
    }

    fn wake_waiters(&mut self) {
        if let Some(waker) = self.read_waker.take() {
            waker.wake();
        }
        if let Some(waker) = self.write_waker.take() {
            waker.wake();
        }
    }
}

impl AsyncRead for EarlyWebSocket {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if out.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        if matches!(self.state, State::Closed) {
            return Poll::Ready(Ok(()));
        }
        self.start(None)?;
        std::task::ready!(self.poll_connect(cx, true))?;
        for _ in 0..16 {
            if !self.pending.is_empty() {
                let length = self.pending.len().min(out.remaining());
                out.put_slice(&self.pending.split_to(length));
                return Poll::Ready(Ok(()));
            }
            let State::Connected(ws) = &mut self.state else {
                unreachable!()
            };
            match Pin::new(ws).poll_next(cx) {
                Poll::Ready(Some(Ok(Message::Binary(bytes)))) => self.pending = bytes,
                Poll::Ready(Some(Ok(Message::Ping(_) | Message::Pong(_)))) => {}
                Poll::Ready(Some(Ok(Message::Close(_)))) | Poll::Ready(None) => {
                    self.state = State::Closed;
                    return Poll::Ready(Ok(()));
                }
                Poll::Ready(Some(_)) => {
                    return Poll::Ready(Err(failure("invalid WebSocket message")));
                }
                Poll::Pending => return Poll::Pending,
            }
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }
}

impl AsyncWrite for EarlyWebSocket {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.write_closed {
            return Poll::Ready(Err(io::Error::new(
                ErrorKind::BrokenPipe,
                "WebSocket write side is closed",
            )));
        }
        if bytes.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if let Err(error) = self.start(Some(bytes)) {
            self.first_write.take();
            self.state = State::Failed(error.kind(), "WebSocket early data setup failed");
            self.wake_waiters();
            return Poll::Ready(Err(error));
        }
        if let Some(first) = &self.first_write {
            if !bytes.starts_with(first.as_slice()) {
                self.state = State::Failed(
                    ErrorKind::InvalidInput,
                    "cancelled WebSocket first write changed",
                );
                self.wake_waiters();
                return Poll::Ready(Err(io::Error::new(
                    ErrorKind::InvalidInput,
                    "cancelled WebSocket first write changed",
                )));
            }
            std::task::ready!(self.poll_connect(cx, false))?;
            let length = self.first_write.take().expect("first write pending").len();
            return Poll::Ready(Ok(length));
        }
        std::task::ready!(self.poll_connect(cx, false))?;
        let State::Connected(ws) = &mut self.state else {
            unreachable!()
        };
        std::task::ready!(Pin::new(&mut *ws).poll_ready(cx))
            .map_err(|_| failure("WebSocket write failed"))?;
        let length = bytes.len().min(MAX_FRAME_PAYLOAD);
        Pin::new(ws)
            .start_send(Message::binary(bytes[..length].to_vec()))
            .map_err(|_| failure("WebSocket write failed"))?;
        Poll::Ready(Ok(length))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.write_closed {
            return Poll::Ready(Ok(()));
        }
        self.start(None)?;
        std::task::ready!(self.poll_connect(cx, false))?;
        let State::Connected(ws) = &mut self.state else {
            unreachable!()
        };
        Pin::new(ws)
            .poll_flush(cx)
            .map_err(|_| failure("WebSocket flush failed"))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.write_closed || matches!(self.state, State::Closed) {
            return Poll::Ready(Ok(()));
        }
        self.start(None)?;
        std::task::ready!(self.poll_connect(cx, false))?;
        let State::Connected(ws) = &mut self.state else {
            unreachable!()
        };
        std::task::ready!(Pin::new(ws).poll_close(cx))
            .map_err(|_| failure("WebSocket shutdown failed"))?;
        self.write_closed = true;
        Poll::Ready(Ok(()))
    }
}

struct PrefixedIo {
    prefix: std::io::Cursor<Vec<u8>>,
    inner: BoxedTransitConnection,
}

impl AsyncRead for PrefixedIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let position = self.prefix.position() as usize;
        let bytes = &self.prefix.get_ref()[position..];
        if !bytes.is_empty() {
            let count = bytes.len().min(out.remaining());
            out.put_slice(&bytes[..count]);
            self.prefix.set_position((position + count) as u64);
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, out)
    }
}

impl AsyncWrite for PrefixedIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, bytes)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

async fn handshake(
    mut stream: BoxedTransitConnection,
    mut request: Request<()>,
    protocol_is_early_data: bool,
) -> io::Result<Ws> {
    let key = generate_key();
    request.headers_mut().insert(
        "Sec-WebSocket-Key",
        HeaderValue::from_str(&key).map_err(|_| failure("invalid WebSocket key"))?,
    );
    let expected_protocol = request.headers().get("Sec-WebSocket-Protocol").cloned();
    let mut outbound = Zeroizing::new(Vec::new());
    let target = request
        .uri()
        .path_and_query()
        .ok_or_else(|| failure("missing WebSocket path"))?
        .as_str();
    outbound.extend_from_slice(b"GET ");
    outbound.extend_from_slice(target.as_bytes());
    outbound.extend_from_slice(b" HTTP/1.1\r\n");
    for (name, value) in request.headers() {
        outbound.extend_from_slice(name.as_str().as_bytes());
        outbound.extend_from_slice(b": ");
        outbound.extend_from_slice(value.as_bytes());
        outbound.extend_from_slice(b"\r\n");
    }
    outbound.extend_from_slice(b"\r\n");
    stream.write_all(&outbound).await?;
    stream.flush().await?;
    let mut response = Vec::new();
    let header_end = loop {
        if let Some(position) = response.windows(4).position(|window| window == b"\r\n\r\n") {
            if position + 4 > MAX_RESPONSE_HEADERS {
                return Err(failure("WebSocket response headers too large"));
            }
            break position + 4;
        }
        if response.len() >= MAX_RESPONSE_HEADERS {
            return Err(failure("WebSocket response headers too large"));
        }
        let mut chunk = [0_u8; 4096];
        let count = stream.read(&mut chunk).await?;
        if count == 0 {
            return Err(io::Error::new(
                ErrorKind::UnexpectedEof,
                "truncated WebSocket response",
            ));
        }
        response.extend_from_slice(&chunk[..count]);
    };
    validate_response(
        &response[..header_end],
        &key,
        expected_protocol.as_ref(),
        protocol_is_early_data,
    )?;
    let prefixed: BoxedTransitConnection = Box::new(PrefixedIo {
        prefix: std::io::Cursor::new(response.split_off(header_end)),
        inner: stream,
    });
    let config = WebSocketConfig::default()
        .read_buffer_size(16 * 1024)
        .write_buffer_size(0)
        .max_write_buffer_size(128 * 1024)
        .max_message_size(Some(1024 * 1024))
        .max_frame_size(Some(1024 * 1024));
    Ok(WebSocketStream::from_raw_socket(prefixed, Role::Client, Some(config)).await)
}

fn validate_response(
    bytes: &[u8],
    key: &str,
    expected_protocol: Option<&HeaderValue>,
    protocol_is_early_data: bool,
) -> io::Result<()> {
    let text = std::str::from_utf8(bytes).map_err(|_| failure("invalid WebSocket response"))?;
    let mut lines = text.split("\r\n");
    let mut status = lines
        .next()
        .ok_or_else(|| failure("missing WebSocket response"))?
        .split_whitespace();
    if status.next() != Some("HTTP/1.1") || status.next() != Some("101") {
        return Err(failure("WebSocket upgrade rejected"));
    }
    let mut headers = HeaderMap::new();
    let mut count = 0;
    for line in lines {
        if line.is_empty() {
            break;
        }
        count += 1;
        if count > MAX_RESPONSE_HEADER_COUNT {
            return Err(failure("too many WebSocket response headers"));
        }
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| failure("invalid WebSocket response header"))?;
        let name = HeaderName::from_bytes(name.as_bytes())
            .map_err(|_| failure("invalid WebSocket response header"))?;
        let value = HeaderValue::from_str(value.trim())
            .map_err(|_| failure("invalid WebSocket response header"))?;
        headers.append(name, value);
    }
    let has_token = |name: &str, token: &str| {
        headers
            .get_all(name)
            .iter()
            .filter_map(|value| value.to_str().ok())
            .flat_map(|value| value.split(','))
            .any(|value| value.trim().eq_ignore_ascii_case(token))
    };
    if !has_token("upgrade", "websocket") || !has_token("connection", "upgrade") {
        return Err(failure("invalid WebSocket upgrade response"));
    }
    let mut accepts = headers.get_all("sec-websocket-accept").iter();
    let expected = derive_accept_key(key.as_bytes());
    if accepts
        .next()
        .is_none_or(|value| value.as_bytes() != expected.as_bytes())
        || accepts.next().is_some()
    {
        return Err(failure("invalid WebSocket accept key"));
    }
    if headers.contains_key("sec-websocket-extensions") {
        return Err(failure("unsupported WebSocket extension"));
    }
    let mut protocols = headers.get_all("sec-websocket-protocol").iter();
    if let Some(protocol) = protocols.next() {
        if expected_protocol != Some(protocol) || protocols.next().is_some() {
            return Err(failure("unexpected WebSocket subprotocol"));
        }
    } else if expected_protocol.is_some() && !protocol_is_early_data {
        return Err(failure("missing WebSocket subprotocol"));
    }
    Ok(())
}
