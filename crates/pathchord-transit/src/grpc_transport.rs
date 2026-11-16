//! HTTP/2 gRPC byte stream transport for V2Ray-compatible Hunk messages.

use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

use bytes::{Buf, BufMut, Bytes, BytesMut};
use pathchord_policy::{TransitProxyConfig, TransitTransport};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::{BoxedTransitConnection, TransitError};

const MAX_MESSAGE: usize = 4 * 1024 * 1024;
const MAX_WRITE: usize = 16 * 1024;

pub(crate) struct GrpcConfig {
    uri: http::Uri,
}

impl GrpcConfig {
    pub(crate) fn new(
        config: &TransitProxyConfig,
        transport: &TransitTransport,
        tls: bool,
    ) -> Result<Self, TransitError> {
        if !matches!(config.protocol.as_str(), "vless" | "vmess" | "trojan") {
            return Err(unsupported("gRPC is unavailable for this protocol"));
        }
        if transport.path.is_some()
            || !transport.host.is_empty()
            || !transport.headers.is_empty()
            || transport.max_early_data.is_some()
            || transport.early_data_header_name.is_some()
        {
            return Err(unsupported("unsupported gRPC transport parameters"));
        }
        let service = transport.service_name.as_deref().unwrap_or_default();
        let path = if let Some(custom) = service.strip_prefix('/') {
            // Xray accepts an absolute custom service/method path. The part
            // after `|` is the multi-mode server method, which we do not use.
            let (service, method) = custom.rsplit_once('/').unwrap_or(("", custom));
            let service = service
                .split('/')
                .map(escape_segment)
                .collect::<Vec<_>>()
                .join("/");
            let method = method.split('|').next().unwrap_or_default();
            format!("/{service}/{}", escape_segment(method))
        } else {
            format!("/{}/Tun", escape_segment(service))
        };
        let host = config
            .options
            .tls
            .as_ref()
            .and_then(|tls| tls.server_name.as_deref())
            .unwrap_or(&config.endpoint.host);
        let host = if host.contains(':') {
            format!("[{host}]")
        } else {
            host.to_owned()
        };
        let uri = format!(
            "{}://{host}:{}{path}",
            if tls { "https" } else { "http" },
            config.endpoint.port
        )
        .parse()
        .map_err(|_| unsupported("gRPC authority or service name is invalid"))?;
        Ok(Self { uri })
    }

    pub(crate) async fn connect(
        &self,
        stream: BoxedTransitConnection,
    ) -> Result<BoxedTransitConnection, TransitError> {
        let (mut client, connection) = h2::client::handshake(stream)
            .await
            .map_err(|_| protocol("gRPC HTTP/2 handshake failed"))?;
        let request = http::Request::builder()
            .method(http::Method::POST)
            .uri(self.uri.clone())
            .header(http::header::CONTENT_TYPE, "application/grpc")
            .header(http::header::TE, "trailers")
            .body(())
            .map_err(|_| unsupported("gRPC request is invalid"))?;
        let (response, send) = client
            .send_request(request, false)
            .map_err(|_| protocol("gRPC request failed"))?;
        let driver = tokio::spawn(async move {
            let _ = connection.await;
        });
        Ok(Box::new(GrpcIo {
            response: Some(response),
            recv: None,
            send,
            driver,
            incoming: BytesMut::new(),
            decoded: Bytes::new(),
            outgoing: Bytes::new(),
            write_closed: false,
            read_closed: false,
            grpc_status: None,
            read_error: None,
        }))
    }
}

fn escape_segment(value: &str) -> String {
    use std::fmt::Write as _;

    // Match Go's url.PathEscape used by the upstream gRPC implementations.
    // URL path builders may normalize dot segments or leave ',' and ';'
    // unescaped, which changes Xray's registered service and method names.
    let mut escaped = String::new();
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric()
            || matches!(
                byte,
                b'-' | b'_' | b'.' | b'~' | b'$' | b'&' | b'+' | b':' | b'=' | b'@'
            )
        {
            escaped.push(char::from(byte));
        } else {
            write!(escaped, "%{byte:02X}").expect("writing to a String cannot fail");
        }
    }
    escaped
}

fn unsupported(message: &str) -> TransitError {
    TransitError::Unsupported(message.to_owned())
}

fn protocol(message: &str) -> TransitError {
    TransitError::Protocol(message.to_owned())
}

fn invalid_data(message: &'static str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, message)
}

fn connection_error() -> std::io::Error {
    std::io::Error::other("gRPC HTTP/2 stream failed")
}

struct GrpcIo {
    response: Option<h2::client::ResponseFuture>,
    recv: Option<h2::RecvStream>,
    send: h2::SendStream<Bytes>,
    driver: tokio::task::JoinHandle<()>,
    incoming: BytesMut,
    decoded: Bytes,
    outgoing: Bytes,
    write_closed: bool,
    read_closed: bool,
    grpc_status: Option<bool>,
    read_error: Option<(std::io::ErrorKind, String)>,
}

impl Drop for GrpcIo {
    fn drop(&mut self) {
        self.send.send_reset(h2::Reason::CANCEL);
        self.driver.abort();
    }
}

impl GrpcIo {
    fn poll_outgoing(&mut self, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        while !self.outgoing.is_empty() {
            self.send.reserve_capacity(self.outgoing.len());
            let capacity = if self.send.capacity() == 0 {
                match self.send.poll_capacity(cx) {
                    Poll::Ready(Some(Ok(capacity))) => capacity,
                    Poll::Ready(_) => return Poll::Ready(Err(connection_error())),
                    Poll::Pending => return Poll::Pending,
                }
            } else {
                self.send.capacity()
            };
            let data = self.outgoing.split_to(capacity.min(self.outgoing.len()));
            self.send
                .send_data(data, false)
                .map_err(|_| connection_error())?;
        }
        Poll::Ready(Ok(()))
    }

    fn decode(&mut self) -> std::io::Result<bool> {
        if self.incoming.len() < 5 {
            return Ok(false);
        }
        if self.incoming[0] != 0 {
            return Err(invalid_data("compressed gRPC messages are unsupported"));
        }
        let size = u32::from_be_bytes(self.incoming[1..5].try_into().unwrap()) as usize;
        if size > MAX_MESSAGE {
            return Err(invalid_data("gRPC message exceeds the limit"));
        }
        if self.incoming.len() < size + 5 {
            return Ok(false);
        }
        self.incoming.advance(5);
        let mut message = self.incoming.split_to(size).freeze();
        if message.is_empty() {
            return Ok(true);
        }
        if message.get_u8() != 0x0a {
            return Err(invalid_data("gRPC Hunk contains an unknown field"));
        }
        let mut length = 0_usize;
        let mut shift = 0;
        loop {
            if !message.has_remaining() || shift >= 35 {
                return Err(invalid_data("gRPC Hunk length is invalid"));
            }
            let byte = message.get_u8();
            length |= usize::from(byte & 0x7f) << shift;
            if byte & 0x80 == 0 {
                break;
            }
            shift += 7;
        }
        if length != message.len() {
            return Err(invalid_data("gRPC Hunk length does not match its message"));
        }
        self.decoded = message;
        Ok(true)
    }
}

impl GrpcIo {
    fn poll_read_inner(
        &mut self,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if buf.remaining() == 0 || self.read_closed {
            return Poll::Ready(Ok(()));
        }
        // A preceding write may have accepted a partial HTTP/2 frame. Drive
        // it while reading as well, so request/response protocols do not
        // deadlock when the caller writes once and immediately waits for data.
        if let Poll::Ready(Err(error)) = self.poll_outgoing(cx) {
            return Poll::Ready(Err(error));
        }
        if let Some(response) = &mut self.response {
            let response = match Pin::new(response).poll(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Ok(response)) => response,
                Poll::Ready(Err(_)) => return Poll::Ready(Err(connection_error())),
            };
            if response.status() != http::StatusCode::OK
                || !response
                    .headers()
                    .get(http::header::CONTENT_TYPE)
                    .and_then(|value| value.to_str().ok())
                    .is_some_and(|value| {
                        let content_type = value.split(';').next().unwrap_or_default().trim();
                        content_type == "application/grpc"
                            || content_type
                                .strip_prefix("application/grpc+")
                                .is_some_and(|suffix| !suffix.is_empty())
                    })
            {
                return Poll::Ready(Err(invalid_data("gRPC response headers are invalid")));
            }
            self.grpc_status = response
                .headers()
                .get("grpc-status")
                .map(|value| value == "0");
            if self.grpc_status == Some(false) {
                return Poll::Ready(Err(invalid_data("gRPC response reported an error")));
            }
            self.recv = Some(response.into_body());
            self.response = None;
        }
        for _ in 0..32 {
            if !self.decoded.is_empty() {
                let count = self.decoded.len().min(buf.remaining());
                buf.put_slice(&self.decoded.split_to(count));
                return Poll::Ready(Ok(()));
            }
            if self.decode()? {
                continue;
            }
            let recv = self.recv.as_mut().expect("response established");
            match recv.poll_data(cx) {
                Poll::Ready(Some(Ok(data))) => {
                    recv.flow_control()
                        .release_capacity(data.len())
                        .map_err(|_| connection_error())?;
                    self.incoming.extend_from_slice(&data);
                    if self.incoming.len() > MAX_MESSAGE + 65_536 {
                        return Poll::Ready(Err(invalid_data("gRPC receive buffer exceeds limit")));
                    }
                }
                Poll::Ready(Some(Err(_))) => return Poll::Ready(Err(connection_error())),
                Poll::Pending => return Poll::Pending,
                Poll::Ready(None) => {
                    if !self.incoming.is_empty() {
                        return Poll::Ready(Err(invalid_data("truncated gRPC message")));
                    }
                    let recv = self.recv.as_mut().expect("response established");
                    let trailers = match recv.poll_trailers(cx) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Ok(trailers)) => trailers,
                        Poll::Ready(Err(_)) => return Poll::Ready(Err(connection_error())),
                    };
                    let status = trailers
                        .as_ref()
                        .and_then(|trailers| trailers.get("grpc-status"))
                        .map(|value| value == "0")
                        .or(self.grpc_status);
                    // sing-box's lite server ends the HTTP/2 body without a
                    // grpc-status trailer; when present the status is binding.
                    if status == Some(false) {
                        return Poll::Ready(Err(invalid_data("gRPC stream ended with an error")));
                    }
                    self.read_closed = true;
                    return Poll::Ready(Ok(()));
                }
            }
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }
}

impl AsyncRead for GrpcIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if let Some((kind, message)) = &self.read_error {
            return Poll::Ready(Err(std::io::Error::new(*kind, message.clone())));
        }
        let result = self.poll_read_inner(cx, buf);
        if let Poll::Ready(Err(error)) = &result {
            self.read_error = Some((error.kind(), error.to_string()));
        }
        result
    }
}

impl AsyncWrite for GrpcIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        if self.write_closed {
            return Poll::Ready(Err(std::io::ErrorKind::BrokenPipe.into()));
        }
        if self.read_error.is_some() {
            return Poll::Ready(Err(std::io::ErrorKind::BrokenPipe.into()));
        }
        if data.is_empty() {
            return Poll::Ready(Ok(0));
        }
        match self.poll_outgoing(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Pending => return Poll::Pending,
        }
        let count = data.len().min(MAX_WRITE);
        let mut protobuf = BytesMut::with_capacity(count + 4);
        protobuf.put_u8(0x0a);
        let mut length = count;
        while length >= 0x80 {
            protobuf.put_u8((length as u8 & 0x7f) | 0x80);
            length >>= 7;
        }
        protobuf.put_u8(length as u8);
        protobuf.extend_from_slice(&data[..count]);
        let mut frame = BytesMut::with_capacity(5 + protobuf.len());
        frame.put_u8(0);
        frame.put_u32(protobuf.len() as u32);
        frame.extend_from_slice(&protobuf);
        self.outgoing = frame.freeze();
        match self.poll_outgoing(cx) {
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Ready(Ok(())) | Poll::Pending => Poll::Ready(Ok(count)),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.poll_outgoing(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        if self.write_closed {
            return Poll::Ready(Ok(()));
        }
        match self.poll_outgoing(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Ready(Ok(())) => {
                self.send
                    .send_data(Bytes::new(), true)
                    .map_err(|_| connection_error())?;
                self.write_closed = true;
                Poll::Ready(Ok(()))
            }
        }
    }
}
