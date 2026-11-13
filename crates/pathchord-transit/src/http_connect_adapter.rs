use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use base64::prelude::{BASE64_STANDARD, Engine as _};
use pathchord_policy::TransitProxyConfig;
use rustls::ClientConfig;
use rustls::pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::timeout;
use tokio_rustls::TlsConnector;

use crate::{
    AdapterKind, BoxedTransitConnection, ConnectRequest, Endpoint, TransitAdapter,
    TransitCredential, TransitError, TransitMetadata, connect_tcp_endpoint, validate_destination,
};

const MAX_CONNECT_RESPONSE_BYTES: usize = 16 * 1024;
const MAX_PROXY_CREDENTIAL_BYTES: usize = 1024;

#[derive(Clone)]
pub struct HttpConnectTransitAdapter {
    metadata: TransitMetadata,
    proxy: Endpoint,
    authorization: Option<String>,
    connect_timeout: Duration,
}

impl std::fmt::Debug for HttpConnectTransitAdapter {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("HttpConnectTransitAdapter")
            .field("metadata", &self.metadata)
            .field("proxy", &self.proxy)
            .field("authenticated", &self.authorization.is_some())
            .field("connect_timeout", &self.connect_timeout)
            .finish()
    }
}

impl HttpConnectTransitAdapter {
    pub fn from_config(
        config: &TransitProxyConfig,
        credential: Option<&TransitCredential>,
        connect_timeout: Duration,
    ) -> Result<Self, TransitError> {
        if config.protocol != "http" {
            return Err(TransitError::Unsupported(
                "HTTP CONNECT adapter requires protocol http".to_owned(),
            ));
        }
        Ok(Self {
            metadata: metadata(config, "http"),
            proxy: Endpoint {
                host: config.endpoint.host.clone(),
                port: config.endpoint.port,
            },
            authorization: proxy_authorization(credential)?,
            connect_timeout,
        })
    }
}

#[async_trait]
impl TransitAdapter for HttpConnectTransitAdapter {
    fn metadata(&self) -> &TransitMetadata {
        &self.metadata
    }

    async fn connect(
        &self,
        request: ConnectRequest,
    ) -> Result<BoxedTransitConnection, TransitError> {
        validate_destination(&request.destination)?;
        let mut stream = connect_tcp_endpoint(&self.proxy, self.connect_timeout).await?;
        timeout(
            self.connect_timeout,
            establish_connect_tunnel(
                &mut stream,
                &request.destination,
                self.authorization.as_deref(),
            ),
        )
        .await
        .map_err(|_| TransitError::Connection("HTTP CONNECT handshake timed out".to_owned()))??;
        Ok(Box::new(stream))
    }
}

#[derive(Clone)]
pub struct HttpsConnectTransitAdapter {
    metadata: TransitMetadata,
    proxy: Endpoint,
    authorization: Option<String>,
    connect_timeout: Duration,
    tls: Arc<ClientConfig>,
}

impl std::fmt::Debug for HttpsConnectTransitAdapter {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("HttpsConnectTransitAdapter")
            .field("metadata", &self.metadata)
            .field("proxy", &self.proxy)
            .field("authenticated", &self.authorization.is_some())
            .field("connect_timeout", &self.connect_timeout)
            .finish_non_exhaustive()
    }
}

impl HttpsConnectTransitAdapter {
    pub fn from_config(
        config: &TransitProxyConfig,
        credential: Option<&TransitCredential>,
        connect_timeout: Duration,
        tls: Arc<ClientConfig>,
    ) -> Result<Self, TransitError> {
        if config.protocol != "https" {
            return Err(TransitError::Unsupported(
                "HTTPS CONNECT adapter requires protocol https".to_owned(),
            ));
        }
        Ok(Self {
            metadata: metadata(config, "https"),
            proxy: Endpoint {
                host: config.endpoint.host.clone(),
                port: config.endpoint.port,
            },
            authorization: proxy_authorization(credential)?,
            connect_timeout,
            tls,
        })
    }
}

#[async_trait]
impl TransitAdapter for HttpsConnectTransitAdapter {
    fn metadata(&self) -> &TransitMetadata {
        &self.metadata
    }

    async fn connect(
        &self,
        request: ConnectRequest,
    ) -> Result<BoxedTransitConnection, TransitError> {
        validate_destination(&request.destination)?;
        let stream = connect_tcp_endpoint(&self.proxy, self.connect_timeout).await?;
        let server_name = ServerName::try_from(self.proxy.host.clone()).map_err(|_| {
            TransitError::Unsupported("HTTPS proxy TLS server name is invalid".to_owned())
        })?;
        let mut stream = timeout(
            self.connect_timeout,
            TlsConnector::from(Arc::clone(&self.tls)).connect(server_name, stream),
        )
        .await
        .map_err(|_| TransitError::Connection("HTTPS proxy TLS handshake timed out".to_owned()))?
        .map_err(|_| TransitError::Connection("HTTPS proxy TLS handshake failed".to_owned()))?;
        timeout(
            self.connect_timeout,
            establish_connect_tunnel(
                &mut stream,
                &request.destination,
                self.authorization.as_deref(),
            ),
        )
        .await
        .map_err(|_| TransitError::Connection("HTTPS CONNECT handshake timed out".to_owned()))??;
        Ok(Box::new(stream))
    }
}

fn metadata(config: &TransitProxyConfig, protocol: &str) -> TransitMetadata {
    TransitMetadata {
        adapter_id: config.id.as_str().to_owned(),
        kind: AdapterKind::ExternalProxy {
            protocol: protocol.to_owned(),
        },
        labels: config.labels.clone(),
    }
}

fn proxy_authorization(
    credential: Option<&TransitCredential>,
) -> Result<Option<String>, TransitError> {
    let username = credential.and_then(|value| value.field("username"));
    let password = credential.and_then(|value| value.field("password"));
    match (username, password) {
        (None, None) => Ok(None),
        (Some(username), Some(password))
            if username.len().saturating_add(password.len()) <= MAX_PROXY_CREDENTIAL_BYTES
                && !username.bytes().any(|byte| byte.is_ascii_control())
                && !password.bytes().any(|byte| byte.is_ascii_control()) =>
        {
            Ok(Some(
                BASE64_STANDARD.encode(format!("{username}:{password}")),
            ))
        }
        _ => Err(TransitError::Unsupported(
            "proxy username/password credentials are incomplete or invalid".to_owned(),
        )),
    }
}

async fn establish_connect_tunnel<S>(
    stream: &mut S,
    destination: &Endpoint,
    authorization: Option<&str>,
) -> Result<(), TransitError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let authority = authority(destination);
    let mut request = format!(
        "CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\nProxy-Connection: Keep-Alive\r\n"
    );
    if let Some(authorization) = authorization {
        request.push_str("Proxy-Authorization: Basic ");
        request.push_str(authorization);
        request.push_str("\r\n");
    }
    request.push_str("\r\n");
    stream
        .write_all(request.as_bytes())
        .await
        .map_err(|_| TransitError::Connection("CONNECT request write failed".to_owned()))?;
    stream
        .flush()
        .await
        .map_err(|_| TransitError::Connection("CONNECT request flush failed".to_owned()))?;

    let mut response = Vec::new();
    while response.len() < MAX_CONNECT_RESPONSE_BYTES {
        let mut byte = [0_u8; 1];
        stream
            .read_exact(&mut byte)
            .await
            .map_err(|_| TransitError::Protocol("CONNECT response is truncated".to_owned()))?;
        response.push(byte[0]);
        if response.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    if !response.ends_with(b"\r\n\r\n") {
        return Err(TransitError::Protocol(
            "CONNECT response headers exceed the bound".to_owned(),
        ));
    }
    let first_line_end = response
        .windows(2)
        .position(|window| window == b"\r\n")
        .ok_or_else(|| TransitError::Protocol("CONNECT status line is missing".to_owned()))?;
    let first_line = std::str::from_utf8(&response[..first_line_end])
        .map_err(|_| TransitError::Protocol("CONNECT status line is not UTF-8".to_owned()))?;
    let mut fields = first_line.split_ascii_whitespace();
    let version = fields.next().unwrap_or_default();
    let status = fields.next().unwrap_or_default();
    if !version.starts_with("HTTP/1.") || status != "200" {
        return Err(TransitError::Protocol(
            "CONNECT proxy rejected the tunnel".to_owned(),
        ));
    }
    Ok(())
}

fn authority(endpoint: &Endpoint) -> String {
    if endpoint
        .host
        .parse::<IpAddr>()
        .is_ok_and(|address| address.is_ipv6())
    {
        format!("[{}]:{}", endpoint.host, endpoint.port)
    } else {
        format!("{}:{}", endpoint.host, endpoint.port)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pathchord_policy::{Endpoint as PolicyEndpoint, TransitProxyId};
    use rcgen::{CertifiedKey, generate_simple_self_signed};
    use rustls::RootCertStore;
    use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
    use std::collections::{BTreeMap, BTreeSet};
    use tokio::io::{AsyncReadExt, AsyncWriteExt, copy_bidirectional};
    use tokio::net::{TcpListener, TcpStream};
    use tokio_rustls::TlsAcceptor;

    fn config(protocol: &str, proxy: std::net::SocketAddr) -> TransitProxyConfig {
        TransitProxyConfig {
            id: TransitProxyId::new(format!("{protocol}-proxy")),
            source: None,
            protocol: protocol.to_owned(),
            endpoint: PolicyEndpoint {
                host: if protocol == "https" {
                    "localhost".to_owned()
                } else {
                    proxy.ip().to_string()
                },
                port: proxy.port(),
            },
            credentials_ref: Some("proxy-auth".to_owned()),
            labels: BTreeMap::new(),
            tags: BTreeSet::new(),
            weight: 100,
        }
    }

    fn credential() -> TransitCredential {
        TransitCredential::new(BTreeMap::from([
            ("username".to_owned(), "proxy-user".to_owned()),
            ("password".to_owned(), "proxy-secret".to_owned()),
        ]))
    }

    async fn echo_target() -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut payload = [0_u8; 5];
            stream.read_exact(&mut payload).await.unwrap();
            stream.write_all(&payload).await.unwrap();
        });
        (address, task)
    }

    async fn serve_connect<S>(mut proxy: S, target: std::net::SocketAddr)
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let mut request = Vec::new();
        while request.len() < MAX_CONNECT_RESPONSE_BYTES {
            let mut byte = [0_u8; 1];
            proxy.read_exact(&mut byte).await.unwrap();
            request.push(byte[0]);
            if request.ends_with(b"\r\n\r\n") {
                break;
            }
        }
        let request = String::from_utf8(request).unwrap();
        assert!(request.starts_with("CONNECT "));
        assert!(request.contains("Proxy-Authorization: Basic "));
        let mut target = TcpStream::connect(target).await.unwrap();
        proxy
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await
            .unwrap();
        if let Err(error) = copy_bidirectional(&mut proxy, &mut target).await {
            assert_eq!(error.kind(), std::io::ErrorKind::UnexpectedEof);
        }
    }

    async fn assert_tunnel(adapter: &dyn TransitAdapter, target: std::net::SocketAddr) {
        let mut stream = adapter
            .connect(ConnectRequest {
                destination: Endpoint {
                    host: target.ip().to_string(),
                    port: target.port(),
                },
            })
            .await
            .unwrap();
        stream.write_all(b"hello").await.unwrap();
        let mut echoed = [0_u8; 5];
        stream.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"hello");
    }

    #[tokio::test]
    async fn http_connect_carries_raw_tunnel_bytes() {
        let (target, target_task) = echo_target().await;
        let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_address = proxy.local_addr().unwrap();
        let proxy_task = tokio::spawn(async move {
            let (stream, _) = proxy.accept().await.unwrap();
            serve_connect(stream, target).await;
        });
        let adapter = HttpConnectTransitAdapter::from_config(
            &config("http", proxy_address),
            Some(&credential()),
            Duration::from_secs(2),
        )
        .unwrap();
        assert!(!format!("{adapter:?}").contains("proxy-secret"));
        assert_tunnel(&adapter, target).await;
        target_task.await.unwrap();
        proxy_task.await.unwrap();
    }

    #[tokio::test]
    async fn https_connect_carries_raw_tunnel_bytes_after_tls() {
        let (target, target_task) = echo_target().await;
        let CertifiedKey { cert, signing_key } =
            generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
        let server = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![cert.der().clone()],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(signing_key.serialize_der())),
            )
            .unwrap();
        let mut roots = RootCertStore::empty();
        roots.add(cert.der().clone()).unwrap();
        let client = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_address = proxy.local_addr().unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(server));
        let proxy_task = tokio::spawn(async move {
            let (stream, _) = proxy.accept().await.unwrap();
            let stream = acceptor.accept(stream).await.unwrap();
            serve_connect(stream, target).await;
        });
        let adapter = HttpsConnectTransitAdapter::from_config(
            &config("https", proxy_address),
            Some(&credential()),
            Duration::from_secs(2),
            Arc::new(client),
        )
        .unwrap();
        assert_tunnel(&adapter, target).await;
        target_task.await.unwrap();
        proxy_task.await.unwrap();
    }

    #[tokio::test]
    async fn connect_response_headers_are_bounded() {
        let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_address = proxy.local_addr().unwrap();
        let proxy_task = tokio::spawn(async move {
            let (mut stream, _) = proxy.accept().await.unwrap();
            let mut request = [0_u8; 256];
            let _ = stream.read(&mut request).await.unwrap();
            stream
                .write_all(&vec![b'x'; MAX_CONNECT_RESPONSE_BYTES + 1])
                .await
                .unwrap();
        });
        let adapter = HttpConnectTransitAdapter::from_config(
            &config("http", proxy_address),
            None,
            Duration::from_secs(2),
        )
        .unwrap();
        assert!(matches!(
            adapter
                .connect(ConnectRequest {
                    destination: Endpoint {
                        host: "127.0.0.1".to_owned(),
                        port: 80,
                    },
                })
                .await,
            Err(TransitError::Protocol(_))
        ));
        proxy_task.await.unwrap();
    }
}
