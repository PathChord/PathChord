//! V2Ray HTTP/1 and HTTP/2 byte-stream transports.

use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

use bytes::Bytes;
use http::header::{HeaderName, HeaderValue};
use pathchord_policy::{TransitProxyConfig, TransitTransport};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

use crate::{BoxedTransitConnection, TransitError};

const MAX_HEADER: usize = 16 * 1024;
const MAX_WRITE: usize = 16 * 1024;

pub(crate) struct HttpTransport {
    tls: bool,
    uri: http::Uri,
    headers: http::HeaderMap,
    request: Vec<u8>,
}

impl HttpTransport {
    pub(crate) fn new(
        node: &TransitProxyConfig,
        options: &TransitTransport,
        tls: bool,
    ) -> Result<Self, TransitError> {
        if options.service_name.is_some()
            || options.host.len() > 1
            || options.max_early_data.is_some()
            || options.early_data_header_name.is_some()
        {
            return Err(unsupported("HTTP transport parameters are unsupported"));
        }
        let path = options.path.as_deref().unwrap_or("/");
        if !path.starts_with('/')
            || path.contains('#')
            || path.parse::<http::uri::PathAndQuery>().is_err()
        {
            return Err(unsupported("HTTP transport path is invalid"));
        }
        let mut headers = http::HeaderMap::new();
        for (name, value) in &options.headers {
            let name = HeaderName::from_bytes(name.as_bytes())
                .map_err(|_| unsupported("HTTP transport header name is invalid"))?;
            let value = HeaderValue::from_str(value)
                .map_err(|_| unsupported("HTTP transport header value is invalid"))?;
            if headers.contains_key(&name) {
                return Err(unsupported("HTTP transport has duplicate headers"));
            }
            if matches!(
                name,
                http::header::CONNECTION
                    | http::header::UPGRADE
                    | http::header::CONTENT_LENGTH
                    | http::header::TRANSFER_ENCODING
            ) {
                return Err(unsupported("HTTP transport header conflicts with framing"));
            }
            headers.insert(name, value);
        }
        let header_host = headers
            .get(http::header::HOST)
            .and_then(|value| value.to_str().ok());
        if let (Some(configured), Some(header)) = (options.host.first(), header_host)
            && configured != header
        {
            return Err(unsupported("HTTP transport Host options conflict"));
        }
        let default_host = if tls {
            "www.example.com".to_owned()
        } else if node.endpoint.host.contains(':') {
            format!("[{}]", node.endpoint.host)
        } else {
            node.endpoint.host.clone()
        };
        let host = options
            .host
            .first()
            .map(String::as_str)
            .or(header_host)
            .unwrap_or(&default_host);
        if host.contains('@') || host.parse::<http::uri::Authority>().is_err() {
            return Err(unsupported("HTTP transport Host is invalid"));
        }
        let uri = format!("{}://{host}{path}", if tls { "https" } else { "http" })
            .parse()
            .map_err(|_| unsupported("HTTP transport URI is invalid"))?;
        let mut request = format!("PUT {path} HTTP/1.1\r\nHost: {host}\r\n").into_bytes();
        for (name, value) in &headers {
            if name == http::header::HOST {
                continue;
            }
            request.extend_from_slice(name.as_str().as_bytes());
            request.extend_from_slice(b": ");
            request.extend_from_slice(value.as_bytes());
            request.extend_from_slice(b"\r\n");
        }
        request.extend_from_slice(b"\r\n");
        if request.len() > MAX_HEADER {
            return Err(unsupported(
                "HTTP transport request exceeds the header limit",
            ));
        }
        headers.remove(http::header::HOST);
        Ok(Self {
            tls,
            uri,
            headers,
            request,
        })
    }

    pub(crate) async fn connect(
        &self,
        mut stream: BoxedTransitConnection,
    ) -> Result<BoxedTransitConnection, TransitError> {
        if !self.tls {
            stream
                .write_all(&self.request)
                .await
                .map_err(|_| protocol())?;
            stream.flush().await.map_err(|_| protocol())?;
            let mut response = Vec::with_capacity(512);
            while response.len() < MAX_HEADER && !response.ends_with(b"\r\n\r\n") {
                response.push(stream.read_u8().await.map_err(|_| protocol())?);
            }
            if !response.ends_with(b"\r\n\r\n") {
                return Err(protocol());
            }
            let text = std::str::from_utf8(&response).map_err(|_| protocol())?;
            let mut lines = text.split("\r\n");
            let mut status = lines.next().ok_or_else(protocol)?.split_whitespace();
            if !matches!(status.next(), Some("HTTP/1.0" | "HTTP/1.1"))
                || status.next() != Some("200")
            {
                return Err(protocol());
            }
            for line in lines.take_while(|line| !line.is_empty()) {
                let (name, value) = line.split_once(':').ok_or_else(protocol)?;
                HeaderName::from_bytes(name.as_bytes()).map_err(|_| protocol())?;
                HeaderValue::from_str(value.trim()).map_err(|_| protocol())?;
            }
            return Ok(stream);
        }
        let (mut client, connection) = h2::client::handshake(stream)
            .await
            .map_err(|_| protocol())?;
        let mut request = http::Request::builder()
            .method(http::Method::PUT)
            .uri(self.uri.clone());
        *request.headers_mut().ok_or_else(protocol)? = self.headers.clone();
        let (response, send) = client
            .send_request(request.body(()).map_err(|_| protocol())?, false)
            .map_err(|_| protocol())?;
        let driver = tokio::spawn(async move {
            let _ = connection.await;
        });
        Ok(Box::new(Http2Io {
            response: Some(response),
            recv: None,
            send,
            driver,
            incoming: Bytes::new(),
            outgoing: Bytes::new(),
            read_closed: false,
            write_closed: false,
            read_error: None,
        }))
    }
}

fn unsupported(message: &str) -> TransitError {
    TransitError::Unsupported(message.to_owned())
}
fn protocol() -> TransitError {
    TransitError::Protocol("HTTP transport handshake failed".to_owned())
}
fn io_error() -> std::io::Error {
    std::io::Error::other("HTTP/2 transport failed")
}

struct Http2Io {
    response: Option<h2::client::ResponseFuture>,
    recv: Option<h2::RecvStream>,
    send: h2::SendStream<Bytes>,
    driver: tokio::task::JoinHandle<()>,
    incoming: Bytes,
    outgoing: Bytes,
    read_closed: bool,
    write_closed: bool,
    read_error: Option<(std::io::ErrorKind, String)>,
}

impl Drop for Http2Io {
    fn drop(&mut self) {
        self.send.send_reset(h2::Reason::CANCEL);
        self.driver.abort();
    }
}

impl Http2Io {
    fn poll_outgoing(&mut self, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        while !self.outgoing.is_empty() {
            self.send.reserve_capacity(self.outgoing.len());
            let capacity = if self.send.capacity() == 0 {
                match self.send.poll_capacity(cx) {
                    Poll::Ready(Some(Ok(capacity))) => capacity,
                    Poll::Ready(_) => return Poll::Ready(Err(io_error())),
                    Poll::Pending => return Poll::Pending,
                }
            } else {
                self.send.capacity()
            };
            let bytes = self.outgoing.split_to(capacity.min(self.outgoing.len()));
            self.send.send_data(bytes, false).map_err(|_| io_error())?;
        }
        Poll::Ready(Ok(()))
    }

    fn poll_read_inner(
        &mut self,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if buf.remaining() == 0 || self.read_closed {
            return Poll::Ready(Ok(()));
        }
        if let Poll::Ready(Err(error)) = self.poll_outgoing(cx) {
            return Poll::Ready(Err(error));
        }
        if let Some(response) = &mut self.response {
            let response = match Pin::new(response).poll(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Ok(response)) => response,
                Poll::Ready(Err(_)) => return Poll::Ready(Err(io_error())),
            };
            if response.status() != http::StatusCode::OK {
                return Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "HTTP transport rejected",
                )));
            }
            self.recv = Some(response.into_body());
            self.response = None;
        }
        for _ in 0..32 {
            if !self.incoming.is_empty() {
                let count = self.incoming.len().min(buf.remaining());
                buf.put_slice(&self.incoming.split_to(count));
                return Poll::Ready(Ok(()));
            }
            let recv = self.recv.as_mut().expect("response established");
            match recv.poll_data(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Some(Err(_))) => return Poll::Ready(Err(io_error())),
                Poll::Ready(Some(Ok(data))) => {
                    recv.flow_control()
                        .release_capacity(data.len())
                        .map_err(|_| io_error())?;
                    self.incoming = data;
                }
                Poll::Ready(None) => {
                    self.read_closed = true;
                    return Poll::Ready(Ok(()));
                }
            }
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }
}

impl AsyncRead for Http2Io {
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

impl AsyncWrite for Http2Io {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        if self.write_closed || self.read_error.is_some() {
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
        self.outgoing = Bytes::copy_from_slice(&data[..count]);
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
                    .map_err(|_| io_error())?;
                self.write_closed = true;
                Poll::Ready(Ok(()))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pathchord_policy::{Endpoint, TransitOptions, TransitProxyId};

    fn config() -> (TransitProxyConfig, TransitTransport) {
        let node = TransitProxyConfig {
            id: TransitProxyId::new("http-test"),
            source: None,
            protocol: "vless".into(),
            endpoint: Endpoint {
                host: "proxy.test".into(),
                port: 443,
            },
            credentials_ref: None,
            labels: Default::default(),
            tags: Default::default(),
            weight: 1,
            options: TransitOptions::default(),
        };
        let transport = TransitTransport {
            kind: "http".into(),
            path: Some("/tunnel?x=1".into()),
            host: vec!["front.test".into()],
            headers: std::collections::BTreeMap::from([("x-custom".into(), "value".into())]),
            ..Default::default()
        };
        (node, transport)
    }

    #[tokio::test]
    async fn http1_forwards_parameters_and_preserves_coalesced_bytes() {
        let (node, options) = config();
        let transport = HttpTransport::new(&node, &options, false).unwrap();
        let (client, mut server) = tokio::io::duplex(8192);
        let peer = tokio::spawn(async move {
            let mut header = Vec::new();
            while !header.ends_with(b"\r\n\r\n") {
                header.push(server.read_u8().await.unwrap());
            }
            let header = String::from_utf8(header).unwrap();
            assert!(header.starts_with("PUT /tunnel?x=1 HTTP/1.1\r\n"));
            assert!(header.contains("Host: front.test\r\n"));
            assert!(header.contains("x-custom: value\r\n"));
            server
                .write_all(b"HTTP/1.1 200 OK\r\n\r\nreply")
                .await
                .unwrap();
            let mut request = [0; 7];
            server.read_exact(&mut request).await.unwrap();
            assert_eq!(&request, b"request");
        });
        let mut stream = transport.connect(Box::new(client)).await.unwrap();
        let mut reply = [0; 5];
        stream.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply, b"reply");
        stream.write_all(b"request").await.unwrap();
        peer.await.unwrap();
    }

    #[tokio::test]
    async fn http2_forwards_parameters_and_propagates_rejection() {
        let (node, options) = config();
        let transport = HttpTransport::new(&node, &options, true).unwrap();
        let (client, server) = tokio::io::duplex(8192);
        let peer = tokio::spawn(async move {
            let mut connection = h2::server::handshake(server).await.unwrap();
            let (request, mut respond) = connection.accept().await.unwrap().unwrap();
            assert_eq!(request.method(), http::Method::PUT);
            assert_eq!(request.uri().authority().unwrap().as_str(), "front.test");
            assert_eq!(
                request.uri().path_and_query().unwrap().as_str(),
                "/tunnel?x=1"
            );
            assert_eq!(request.headers()["x-custom"], "value");
            respond
                .send_response(
                    http::Response::builder().status(403).body(()).unwrap(),
                    true,
                )
                .unwrap();
            while connection.accept().await.is_some() {}
        });
        let mut stream = transport.connect(Box::new(client)).await.unwrap();
        let mut byte = [0];
        assert!(stream.read(&mut byte).await.is_err());
        assert!(stream.read(&mut byte).await.is_err());
        drop(stream);
        peer.await.unwrap();
    }

    #[test]
    fn http_transport_rejects_conflicts_and_unhandled_options() {
        let (node, mut options) = config();
        options.headers.insert("Host".into(), "other.test".into());
        assert!(HttpTransport::new(&node, &options, false).is_err());
        options.headers.remove("Host");
        options.headers.insert("Content-Length".into(), "4".into());
        assert!(HttpTransport::new(&node, &options, false).is_err());
        options.headers.clear();
        options.service_name = Some("not-consumed".into());
        assert!(HttpTransport::new(&node, &options, true).is_err());
        options.service_name = None;
        options.path = Some("/tunnel#fragment".into());
        assert!(HttpTransport::new(&node, &options, true).is_err());
        options.path = None;
        options.host = vec!["user@front.test".into()];
        assert!(HttpTransport::new(&node, &options, true).is_err());
    }

    #[test]
    fn websocket_rejects_fragments_and_host_userinfo_before_dialing() {
        let (mut node, mut options) = config();
        options.kind = "ws".into();
        options.path = Some("/tunnel#fragment".into());
        node.options.transport = Some(options.clone());
        let build = |node: &TransitProxyConfig| {
            crate::native_transport::NativeTransport::new(
                node,
                &crate::TransitCredential::default(),
                crate::adapter_registry::native_tls_roots(),
                std::time::Duration::from_secs(1),
            )
        };
        assert!(build(&node).is_err());
        options.path = None;
        options.host = vec!["user@front.test".into()];
        node.options.transport = Some(options);
        assert!(build(&node).is_err());
    }
}
