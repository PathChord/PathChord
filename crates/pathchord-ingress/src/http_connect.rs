//! Bounded HTTP proxy inbound adapter.
//!
//! The adapter terminates only the local HTTP proxy handshake. Target dialing
//! and Stream creation remain owned by the policy/Session layers.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use async_trait::async_trait;
use base64::prelude::{BASE64_STANDARD, Engine as _};
use pathchord_policy::{TargetEndpoint, TargetHost};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use zeroize::{Zeroize, Zeroizing};

use crate::{
    AcceptedConnection, BoxedLocalConnection, ConnectionContext, IngressListener,
    ListenerCredentialVerifier, ListenerDescriptor, ListenerError, ListenerKind,
    RejectListenerCredentials,
};

pub const MAX_HEADER_BYTES: usize = 16 * 1024;
const BAD_REQUEST_RESPONSE: &[u8] = b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n";
const PROXY_AUTHENTICATION_REQUIRED_RESPONSE: &[u8] = b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"PathChord\"\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";

/// A local HTTP forward proxy and CONNECT listener.
pub struct HttpConnectListener {
    descriptor: ListenerDescriptor,
    listener: TcpListener,
    credential_verifier: Arc<dyn ListenerCredentialVerifier>,
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
            return Err(ListenerError::InvalidDescriptor(
                "HTTP proxy adapter requires an HTTP ListenerDescriptor".to_owned(),
            ));
        }
        let listener = TcpListener::bind(descriptor.required_bind()?)
            .await
            .map_err(|error| ListenerError::Bind(error.to_string()))?;
        Ok(Self {
            descriptor,
            listener,
            credential_verifier: Arc::new(RejectListenerCredentials),
        })
    }

    #[must_use]
    pub fn with_credential_verifier(
        mut self,
        credential_verifier: Arc<dyn ListenerCredentialVerifier>,
    ) -> Self {
        self.credential_verifier = credential_verifier;
        self
    }

    #[must_use]
    pub fn descriptor(&self) -> &ListenerDescriptor {
        &self.descriptor
    }

    pub fn local_addr(&self) -> Result<SocketAddr, ListenerError> {
        self.listener
            .local_addr()
            .map_err(|error| ListenerError::Accept(error.to_string()))
    }

    /// Parses the first HTTP proxy request from a generic stream. This is useful for
    /// deterministic adapter tests and for platform wrappers that already own
    /// an accepted stream.
    pub async fn accept_stream<S>(
        descriptor: &ListenerDescriptor,
        stream: S,
        source: SocketAddr,
    ) -> Result<AcceptedConnection, ListenerError>
    where
        S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
        Self::accept_stream_with_verifier(
            descriptor,
            stream,
            source,
            Arc::new(RejectListenerCredentials),
        )
        .await
    }

    pub async fn accept_stream_with_verifier<S>(
        descriptor: &ListenerDescriptor,
        stream: S,
        source: SocketAddr,
        credential_verifier: Arc<dyn ListenerCredentialVerifier>,
    ) -> Result<AcceptedConnection, ListenerError>
    where
        S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
        if descriptor.kind != ListenerKind::Http {
            return Err(ListenerError::InvalidDescriptor(
                "HTTP proxy adapter requires an HTTP ListenerDescriptor".to_owned(),
            ));
        }
        if !descriptor.allows_source(source.ip()) {
            return Err(reject_policy(stream, "source address is not allowed").await);
        }

        let mut reader = BufReader::new(stream);
        let mut remaining = MAX_HEADER_BYTES;
        let first_line = read_header_line(&mut reader, &mut remaining)
            .await
            .map_err(|reason| ListenerError::Protocol(reason.to_owned()));
        let first_line_bytes = match first_line {
            Ok(line) => line,
            Err(error) => return Err(reject(reader, &error.to_string()).await),
        };
        let first_line = match trim_line(&first_line_bytes) {
            Some(line) => line,
            None => return Err(reject(reader, "HTTP request line is not UTF-8").await),
        };
        let mut fields = first_line.split_ascii_whitespace();
        let method = fields.next();
        let authority = fields.next();
        let version = fields.next();
        if method.is_none()
            || authority.is_none()
            || !matches!(version, Some("HTTP/1.0" | "HTTP/1.1"))
            || fields.next().is_some()
        {
            return Err(reject(reader, "malformed HTTP proxy request line").await);
        }
        let authority = authority.expect("checked above");
        let is_connect = method == Some("CONNECT");
        let target = match if is_connect {
            parse_authority(authority)
        } else {
            authority
                .parse::<hyper::Uri>()
                .map_err(|_| "invalid HTTP proxy URI".to_owned())
                .and_then(|uri| crate::http_forward::forward_target(&uri))
        } {
            Ok(target) => target,
            Err(reason) => return Err(reject(reader, &reason).await),
        };
        let mut prefix = if is_connect {
            Vec::new()
        } else {
            first_line_bytes
        };

        let mut proxy_authorization: Option<Zeroizing<String>> = None;
        loop {
            let mut line = match read_header_line(&mut reader, &mut remaining).await {
                Ok(line) => line,
                Err(reason) => return Err(reject(reader, reason).await),
            };
            let Some(header) = trim_line(&line) else {
                line.zeroize();
                return Err(reject(reader, "HTTP header is not UTF-8").await);
            };
            if header.is_empty() {
                if !is_connect {
                    prefix.extend_from_slice(&line);
                }
                line.zeroize();
                break;
            }
            let Some((name, value)) = header.split_once(':') else {
                line.zeroize();
                return Err(reject(reader, "malformed HTTP header").await);
            };
            let authorization = name
                .eq_ignore_ascii_case("Proxy-Authorization")
                .then(|| value.trim().to_owned());
            if !is_connect && authorization.is_none() {
                prefix.extend_from_slice(&line);
            }
            line.zeroize();
            if let Some(authorization) = authorization {
                if proxy_authorization.is_some() {
                    return Err(reject_authentication(reader).await);
                }
                proxy_authorization = Some(Zeroizing::new(authorization));
            }
        }

        let authentication_identity = if descriptor.authentication_required {
            match authenticate_basic(
                proxy_authorization.as_deref().map(String::as_str),
                credential_verifier.as_ref(),
            )
            .await
            {
                Some(identity) => Some(identity),
                None => return Err(reject_authentication(reader).await),
            }
        } else {
            None
        };

        let (io, response): (BoxedLocalConnection, _) = if is_connect {
            (Box::new(reader), crate::ConnectionResponse::HttpConnect)
        } else {
            let (read, write) = tokio::io::split(reader);
            let io = tokio::io::join(std::io::Cursor::new(prefix).chain(read), write);
            (
                Box::new(io),
                crate::ConnectionResponse::HttpForward(crate::http_forward::HttpForwardConfig {
                    authentication_required: descriptor.authentication_required,
                    credential_verifier,
                }),
            )
        };
        Ok(AcceptedConnection {
            io,
            context: ConnectionContext {
                flow_tags: descriptor.flow_tags.clone(),
                listener_id: descriptor.id.clone(),
                source,
                authentication_identity,
                process: None,
                protocol: crate::FlowProtocol::Tcp,
                target,
            },
            response,
        })
    }
}

#[async_trait]
impl IngressListener for HttpConnectListener {
    fn descriptor(&self) -> &ListenerDescriptor {
        &self.descriptor
    }

    fn local_addr(&self) -> Result<SocketAddr, ListenerError> {
        Self::local_addr(self)
    }

    async fn accept(&self) -> Result<AcceptedConnection, ListenerError> {
        let (stream, source) = self
            .listener
            .accept()
            .await
            .map_err(|error| ListenerError::Accept(error.to_string()))?;
        Self::accept_stream_with_verifier(
            &self.descriptor,
            stream,
            source,
            Arc::clone(&self.credential_verifier),
        )
        .await
    }
}

pub(crate) async fn authenticate_basic(
    authorization: Option<&str>,
    credential_verifier: &dyn ListenerCredentialVerifier,
) -> Option<String> {
    let mut fields = authorization?.split_ascii_whitespace();
    let scheme = fields.next()?;
    let encoded = fields.next()?;
    if !scheme.eq_ignore_ascii_case("Basic") || fields.next().is_some() {
        return None;
    }
    let decoded = Zeroizing::new(BASE64_STANDARD.decode(encoded).ok()?);
    let separator = decoded.iter().position(|byte| *byte == b':')?;
    let username = std::str::from_utf8(&decoded[..separator]).ok()?;
    let password = &decoded[separator + 1..];
    if username.is_empty()
        || password.is_empty()
        || !credential_verifier.verify(username, password).await
    {
        return None;
    }
    Some(username.to_owned())
}

async fn read_header_line<R>(
    reader: &mut BufReader<R>,
    remaining: &mut usize,
) -> Result<Vec<u8>, &'static str>
where
    R: AsyncRead + Unpin,
{
    let mut line = Vec::new();
    loop {
        if *remaining == 0 {
            return Err("HTTP headers exceed the configured limit");
        }
        let available = reader
            .fill_buf()
            .await
            .map_err(|_| "HTTP header read failed")?;
        if available.is_empty() {
            return Err("truncated HTTP headers");
        }
        let newline = available.iter().position(|byte| *byte == b'\n');
        let take = newline.map_or(available.len(), |offset| offset + 1);
        if take > *remaining {
            return Err("HTTP headers exceed the configured limit");
        }
        line.extend_from_slice(&available[..take]);
        reader.consume(take);
        *remaining -= take;
        if newline.is_some() {
            return Ok(line);
        }
    }
}

async fn reject_authentication<S>(mut stream: S) -> ListenerError
where
    S: AsyncWrite + Unpin,
{
    let _ = stream
        .write_all(PROXY_AUTHENTICATION_REQUIRED_RESPONSE)
        .await;
    let _ = stream.flush().await;
    ListenerError::Policy("HTTP proxy authentication failed".to_owned())
}

fn trim_line(line: &[u8]) -> Option<&str> {
    let line = line.strip_suffix(b"\n").unwrap_or(line);
    let line = line.strip_suffix(b"\r").unwrap_or(line);
    std::str::from_utf8(line).ok()
}

pub(crate) fn parse_authority(authority: &str) -> Result<TargetEndpoint, String> {
    let bracketed = authority.starts_with('[');
    let (host, port) = if let Some(rest) = authority.strip_prefix('[') {
        let (host, port) = rest
            .split_once("]:")
            .ok_or_else(|| "bracketed IPv6 authority must include a port".to_owned())?;
        if host.parse::<std::net::Ipv6Addr>().is_err() {
            return Err("bracketed authority host is not IPv6".to_owned());
        }
        (host, port)
    } else {
        authority
            .rsplit_once(':')
            .ok_or_else(|| "CONNECT authority must include a port".to_owned())?
    };
    if host.is_empty() {
        return Err("CONNECT authority host is empty".to_owned());
    }
    if !bracketed && host.contains(':') {
        return Err("IPv6 CONNECT authority must use brackets".to_owned());
    }
    if host.len() > 255 {
        return Err("CONNECT authority host is too long".to_owned());
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
    ListenerError::Protocol(reason.to_owned())
}

async fn reject_policy<S>(mut stream: S, reason: &str) -> ListenerError
where
    S: AsyncWrite + Unpin,
{
    let _ = stream.write_all(BAD_REQUEST_RESPONSE).await;
    let _ = stream.flush().await;
    ListenerError::Policy(reason.to_owned())
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
            bind: Some("127.0.0.1:8080".parse().expect("bind")),
            interface: None,
            address: None,
            mtu: None,
            flow_tags: std::collections::BTreeSet::new(),
            process_metadata: crate::ProcessMetadataRequest::default(),
            allowed_sources: Vec::new(),
            authentication_required: authenticated,
        }
    }

    #[tokio::test]
    async fn parses_connect_and_returns_context() {
        let (mut client, server) = tokio::io::duplex(4096);
        let descriptor_method = descriptor(false);
        let task = tokio::spawn(async move {
            let mut accepted = HttpConnectListener::accept_stream(
                &descriptor_method,
                server,
                "127.0.0.1:12345".parse().unwrap(),
            )
            .await
            .expect("accepted");
            accepted.confirm_success().await.expect("CONNECT success");
            accepted
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

    #[test]
    fn rejects_unbracketed_or_non_ipv6_bracketed_authorities() {
        assert!(parse_authority("2001:db8::1:8443").is_err());
        assert!(parse_authority("[example.com]:443").is_err());
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
            )
            .await
        });
        client.write_all(b"GET / HTTP/1.1\r\n\r\n").await.unwrap();
        assert!(matches!(
            task.await.unwrap(),
            Err(ListenerError::Protocol(_))
        ));

        let descriptor_required = descriptor(true);
        let (mut client, server) = tokio::io::duplex(4096);
        let task = tokio::spawn(async move {
            HttpConnectListener::accept_stream(
                &descriptor_required,
                server,
                "127.0.0.1:12345".parse().unwrap(),
            )
            .await
        });
        client
            .write_all(b"CONNECT example.com:443 HTTP/1.1\r\n\r\n")
            .await
            .unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();
        assert!(response.starts_with(b"HTTP/1.1 407"));
        assert!(
            response
                .windows(b"Proxy-Authenticate: Basic".len())
                .any(|window| window == b"Proxy-Authenticate: Basic")
        );
        assert!(matches!(task.await.unwrap(), Err(ListenerError::Policy(_))));

        let descriptor = descriptor(false);
        let (mut client, server) = tokio::io::duplex(MAX_HEADER_BYTES + 64);
        let task = tokio::spawn(async move {
            HttpConnectListener::accept_stream(
                &descriptor,
                server,
                "127.0.0.1:12345".parse().unwrap(),
            )
            .await
        });
        let mut request = b"CONNECT example.com:443 HTTP/1.1\r\nX-Large: ".to_vec();
        request.extend(std::iter::repeat_n(b'x', MAX_HEADER_BYTES));
        request.extend_from_slice(b"\r\n\r\n");
        client.write_all(&request).await.unwrap();
        assert!(task.await.unwrap().is_err());
    }

    #[tokio::test]
    async fn rejects_disallowed_source_before_connect_response() {
        let mut descriptor = descriptor(false);
        descriptor.allowed_sources = vec!["192.0.2.0/24".to_owned()];
        let (mut client, server) = tokio::io::duplex(4096);
        let task = tokio::spawn(async move {
            HttpConnectListener::accept_stream(
                &descriptor,
                server,
                "127.0.0.1:12345".parse().unwrap(),
            )
            .await
        });
        client
            .write_all(b"CONNECT example.com:443 HTTP/1.1\r\n\r\n")
            .await
            .unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();
        assert!(response.starts_with(b"HTTP/1.1 400"));
        assert!(matches!(task.await.unwrap(), Err(ListenerError::Policy(_))));
    }

    #[tokio::test]
    async fn rejects_eof_before_request_headers_are_complete() {
        let descriptor = descriptor(false);
        let (mut client, server) = tokio::io::duplex(4096);
        let task = tokio::spawn(async move {
            HttpConnectListener::accept_stream(
                &descriptor,
                server,
                "127.0.0.1:12345".parse().unwrap(),
            )
            .await
        });
        client
            .write_all(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com")
            .await
            .unwrap();
        client.shutdown().await.unwrap();
        assert!(task.await.unwrap().is_err());
    }

    #[tokio::test]
    async fn rejects_request_line_without_a_line_ending() {
        let descriptor = descriptor(false);
        let (mut client, server) = tokio::io::duplex(4096);
        let task = tokio::spawn(async move {
            HttpConnectListener::accept_stream(
                &descriptor,
                server,
                "127.0.0.1:12345".parse().unwrap(),
            )
            .await
        });
        client
            .write_all(b"CONNECT example.com:443 HTTP/1.1")
            .await
            .unwrap();
        client.shutdown().await.unwrap();
        assert!(task.await.unwrap().is_err());
    }

    #[tokio::test]
    async fn rejects_non_utf8_headers_instead_of_treating_them_as_empty() {
        let descriptor = descriptor(false);
        let (mut client, server) = tokio::io::duplex(4096);
        let task = tokio::spawn(async move {
            HttpConnectListener::accept_stream(
                &descriptor,
                server,
                "127.0.0.1:12345".parse().unwrap(),
            )
            .await
        });
        client
            .write_all(b"CONNECT example.com:443 HTTP/1.1\r\n\xff\r\n\r\n")
            .await
            .unwrap();
        assert!(task.await.unwrap().is_err());
    }

    #[tokio::test]
    async fn rejects_extra_request_line_tokens() {
        let descriptor = descriptor(false);
        let (mut client, server) = tokio::io::duplex(4096);
        let task = tokio::spawn(async move {
            HttpConnectListener::accept_stream(
                &descriptor,
                server,
                "127.0.0.1:12345".parse().unwrap(),
            )
            .await
        });
        client
            .write_all(b"CONNECT example.com:443 HTTP/1.1 extra\r\n\r\n")
            .await
            .unwrap();
        assert!(task.await.unwrap().is_err());
    }

    #[tokio::test]
    async fn required_basic_authentication_sets_the_verified_identity() {
        let descriptor = descriptor(true);
        let (mut client, server) = tokio::io::duplex(4096);
        let task = tokio::spawn(async move {
            let mut accepted = HttpConnectListener::accept_stream_with_verifier(
                &descriptor,
                server,
                "127.0.0.1:12345".parse().unwrap(),
                Arc::new(crate::StaticListenerCredentialVerifier::new(
                    "alice", b"secret",
                )),
            )
            .await
            .expect("authenticated CONNECT");
            accepted.confirm_success().await.unwrap();
            accepted.context.authentication_identity
        });
        client
            .write_all(
                b"CONNECT example.com:443 HTTP/1.1\r\nproxy-authorization: Basic YWxpY2U6c2VjcmV0\r\n\r\n",
            )
            .await
            .unwrap();
        let mut response = [0_u8; 39];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"HTTP/1.1 200 Connection Established\r\n\r\n");
        assert_eq!(task.await.unwrap().as_deref(), Some("alice"));
    }

    #[tokio::test]
    async fn duplicate_or_invalid_proxy_authorization_is_rejected_with_407() {
        for headers in [
            "Proxy-Authorization: Bearer token\r\n",
            "Proxy-Authorization: Basic YWxpY2U6d3Jvbmc=\r\n",
            "Proxy-Authorization: Basic YWxpY2U6c2VjcmV0\r\nProxy-Authorization: Basic YWxpY2U6c2VjcmV0\r\n",
        ] {
            let descriptor = descriptor(true);
            let (mut client, server) = tokio::io::duplex(4096);
            let task = tokio::spawn(async move {
                HttpConnectListener::accept_stream_with_verifier(
                    &descriptor,
                    server,
                    "127.0.0.1:12345".parse().unwrap(),
                    Arc::new(crate::StaticListenerCredentialVerifier::new(
                        "alice", b"secret",
                    )),
                )
                .await
            });
            client
                .write_all(format!("CONNECT example.com:443 HTTP/1.1\r\n{headers}\r\n").as_bytes())
                .await
                .unwrap();
            let mut response = Vec::new();
            client.read_to_end(&mut response).await.unwrap();
            assert!(response.starts_with(b"HTTP/1.1 407"));
            assert!(matches!(task.await.unwrap(), Err(ListenerError::Policy(_))));
        }
    }

    #[test]
    fn rejects_invalid_authority() {
        assert!(parse_authority("example.com").is_err());
        assert!(parse_authority("example.com:0").is_err());
        assert!(parse_authority("[2001:db8::1]").is_err());
        assert!(SocketAddr::from_str("127.0.0.1:1").is_ok());
    }
}
