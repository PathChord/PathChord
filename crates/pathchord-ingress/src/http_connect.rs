//! Bounded HTTP CONNECT inbound adapter.
//!
//! The adapter terminates only the local HTTP proxy handshake. Target dialing
//! and Stream creation remain owned by the policy/Session layers.

use std::net::{IpAddr, SocketAddr};

use async_trait::async_trait;
use pathchord_policy::{TargetEndpoint, TargetHost};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;

use crate::{
    AcceptedConnection, BoxedLocalConnection, ConnectionContext, IngressListener,
    ListenerDescriptor, ListenerError, ListenerKind,
};

pub const MAX_HEADER_BYTES: usize = 16 * 1024;
const CONNECTED_RESPONSE: &[u8] = b"HTTP/1.1 200 Connection Established\r\n\r\n";
const BAD_REQUEST_RESPONSE: &[u8] = b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n";

/// A local HTTP CONNECT listener.
pub struct HttpConnectListener {
    descriptor: ListenerDescriptor,
    listener: TcpListener,
    authentication_identity: Option<String>,
}

impl std::fmt::Debug for HttpConnectListener {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("HttpConnectListener")
            .field("descriptor", &self.descriptor)
            .finish_non_exhaustive()
    }
}

impl HttpConnectListener {
    /// Binds an HTTP listener at the descriptor's configured address.
    pub async fn bind(descriptor: ListenerDescriptor) -> Result<Self, ListenerError> {
        if descriptor.kind != ListenerKind::Http {
            return Err(ListenerError::Accept(
                "HTTP CONNECT adapter requires an HTTP ListenerDescriptor".to_owned(),
            ));
        }
        let listener = TcpListener::bind(descriptor.bind)
            .await
            .map_err(|error| ListenerError::Accept(error.to_string()))?;
        Ok(Self {
            descriptor,
            listener,
            authentication_identity: None,
        })
    }

    /// Associates a pre-authenticated local identity with accepted requests.
    /// HTTP authentication parsing is intentionally outside this adapter.
    #[must_use]
    pub fn with_authentication_identity(mut self, identity: impl Into<String>) -> Self {
        self.authentication_identity = Some(identity.into());
        self
    }

    #[must_use]
    pub fn descriptor(&self) -> &ListenerDescriptor {
        &self.descriptor
    }

    /// Parses one HTTP CONNECT request from a generic stream. This is useful for
    /// deterministic adapter tests and for platform wrappers that already own
    /// an accepted stream.
    pub async fn accept_stream<S>(
        descriptor: &ListenerDescriptor,
        stream: S,
        source: SocketAddr,
        authentication_identity: Option<String>,
    ) -> Result<AcceptedConnection, ListenerError>
    where
        S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
        if descriptor.kind != ListenerKind::Http {
            return Err(ListenerError::Accept(
                "HTTP CONNECT adapter requires an HTTP ListenerDescriptor".to_owned(),
            ));
        }
        if descriptor.authentication_required && authentication_identity.is_none() {
            return Err(reject(stream, "HTTP listener authentication is required").await);
        }

        let mut reader = BufReader::new(stream);
        let mut first_line = Vec::new();
        if reader.read_until(b'\n', &mut first_line).await.is_err()
            || first_line.len() > MAX_HEADER_BYTES
        {
            return Err(reject(reader, "malformed HTTP request line").await);
        }
        let first_line = trim_line(&first_line);
        let mut fields = first_line.split_ascii_whitespace();
        let method = fields.next();
        let authority = fields.next();
        let version = fields.next();
        if method != Some("CONNECT") || authority.is_none() || version != Some("HTTP/1.1") {
            return Err(reject(reader, "HTTP CONNECT is required").await);
        }
        let authority = authority.expect("checked above");
        let target = match parse_authority(authority) {
            Ok(target) => target,
            Err(reason) => return Err(reject(reader, &reason).await),
        };

        let mut consumed = first_line.len() + 1;
        loop {
            let mut line = Vec::new();
            if reader.read_until(b'\n', &mut line).await.is_err() {
                return Err(reject(reader, "truncated HTTP headers").await);
            }
            consumed = consumed.saturating_add(line.len());
            if consumed > MAX_HEADER_BYTES {
                return Err(reject(reader, "HTTP headers exceed the configured limit").await);
            }
            let line = trim_line(&line);
            if line.is_empty() {
                break;
            }
            if !line.contains(':') {
                return Err(reject(reader, "malformed HTTP header").await);
            }
        }

        reader
            .write_all(CONNECTED_RESPONSE)
            .await
            .map_err(|error| ListenerError::Accept(error.to_string()))?;
        reader
            .flush()
            .await
            .map_err(|error| ListenerError::Accept(error.to_string()))?;

        Ok(AcceptedConnection {
            io: Box::new(reader) as BoxedLocalConnection,
            context: ConnectionContext {
                listener_id: descriptor.id.clone(),
                source,
                authentication_identity,
                process: None,
                protocol: crate::FlowProtocol::Tcp,
                target,
            },
        })
    }
}

#[async_trait]
impl IngressListener for HttpConnectListener {
    fn descriptor(&self) -> &ListenerDescriptor {
        &self.descriptor
    }

    async fn accept(&self) -> Result<AcceptedConnection, ListenerError> {
        let (stream, source) = self
            .listener
            .accept()
            .await
            .map_err(|error| ListenerError::Accept(error.to_string()))?;
        Self::accept_stream(
            &self.descriptor,
            stream,
            source,
            self.authentication_identity.clone(),
        )
        .await
    }
}

fn trim_line(line: &[u8]) -> &str {
    let line = line.strip_suffix(b"\n").unwrap_or(line);
    let line = line.strip_suffix(b"\r").unwrap_or(line);
    std::str::from_utf8(line).unwrap_or("")
}

fn parse_authority(authority: &str) -> Result<TargetEndpoint, String> {
    let (host, port) = if let Some(rest) = authority.strip_prefix('[') {
        let (host, port) = rest
            .split_once("]:")
            .ok_or_else(|| "bracketed IPv6 authority must include a port".to_owned())?;
        (host, port)
    } else {
        authority
            .rsplit_once(':')
            .ok_or_else(|| "CONNECT authority must include a port".to_owned())?
    };
    if host.is_empty() {
        return Err("CONNECT authority host is empty".to_owned());
    }
    let port = port
        .parse::<u16>()
        .map_err(|_| "CONNECT authority port is invalid".to_owned())?;
    if port == 0 {
        return Err("CONNECT authority port must be non-zero".to_owned());
    }
    let host = if let Ok(address) = host.parse::<IpAddr>() {
        TargetHost::Ip(address)
    } else {
        TargetHost::Hostname(host.to_owned())
    };
    Ok(TargetEndpoint { host, port })
}

async fn reject<S>(mut stream: S, reason: &str) -> ListenerError
where
    S: AsyncWrite + Unpin,
{
    let _ = stream.write_all(BAD_REQUEST_RESPONSE).await;
    let _ = stream.flush().await;
    ListenerError::Accept(reason.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn descriptor(authenticated: bool) -> ListenerDescriptor {
        ListenerDescriptor {
            id: crate::ListenerId::new("local-http"),
            kind: ListenerKind::Http,
            bind: "127.0.0.1:8080".parse().expect("bind"),
            authentication_required: authenticated,
        }
    }

    #[tokio::test]
    async fn parses_connect_and_returns_context() {
        let (mut client, server) = tokio::io::duplex(4096);
        let descriptor_method = descriptor(false);
        let task = tokio::spawn(async move {
            HttpConnectListener::accept_stream(
                &descriptor_method,
                server,
                "127.0.0.1:12345".parse().unwrap(),
                None,
            )
            .await
            .expect("accepted")
        });
        client
            .write_all(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com\r\n\r\n")
            .await
            .unwrap();
        let mut response = [0_u8; 39];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"HTTP/1.1 200 Connection Established\r\n\r\n");
        let accepted = task.await.unwrap();
        assert_eq!(accepted.context.protocol, crate::FlowProtocol::Tcp);
        assert_eq!(accepted.context.target.port, 443);
        assert_eq!(
            accepted.context.target.host,
            TargetHost::Hostname("example.com".into())
        );
    }

    #[tokio::test]
    async fn parses_bracketed_ipv6_authority() {
        let target = parse_authority("[2001:db8::1]:8443").unwrap();
        assert_eq!(target.port, 8443);
        assert_eq!(target.host, TargetHost::Ip("2001:db8::1".parse().unwrap()));
    }

    #[tokio::test]
    async fn rejects_method_auth_and_oversized_headers() {
        let descriptor_oversized = descriptor(false);
        let (mut client, server) = tokio::io::duplex(4096);
        let task = tokio::spawn(async move {
            HttpConnectListener::accept_stream(
                &descriptor_oversized,
                server,
                "127.0.0.1:12345".parse().unwrap(),
                None,
            )
            .await
        });
        client.write_all(b"GET / HTTP/1.1\r\n\r\n").await.unwrap();
        assert!(task.await.unwrap().is_err());

        let descriptor_required = descriptor(true);
        let (mut client, server) = tokio::io::duplex(4096);
        let task = tokio::spawn(async move {
            HttpConnectListener::accept_stream(
                &descriptor_required,
                server,
                "127.0.0.1:12345".parse().unwrap(),
                None,
            )
            .await
        });
        client
            .write_all(b"CONNECT example.com:443 HTTP/1.1\r\n\r\n")
            .await
            .unwrap();
        assert!(task.await.unwrap().is_err());

        let descriptor = descriptor(false);
        let (mut client, server) = tokio::io::duplex(MAX_HEADER_BYTES + 64);
        let task = tokio::spawn(async move {
            HttpConnectListener::accept_stream(
                &descriptor,
                server,
                "127.0.0.1:12345".parse().unwrap(),
                None,
            )
            .await
        });
        let mut request = b"CONNECT example.com:443 HTTP/1.1\r\nX-Large: ".to_vec();
        request.extend(std::iter::repeat_n(b'x', MAX_HEADER_BYTES));
        request.extend_from_slice(b"\r\n\r\n");
        client.write_all(&request).await.unwrap();
        assert!(task.await.unwrap().is_err());
    }

    #[test]
    fn rejects_invalid_authority() {
        assert!(parse_authority("example.com").is_err());
        assert!(parse_authority("example.com:0").is_err());
        assert!(parse_authority("[2001:db8::1]").is_err());
        assert!(SocketAddr::from_str("127.0.0.1:1").is_ok());
    }
}
