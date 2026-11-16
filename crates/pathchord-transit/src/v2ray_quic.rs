//! sing-box V2Ray QUIC transport: one TLS 1.3 connection carries byte streams.

use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use futures_util::{StreamExt, stream::FuturesUnordered};
use quinn::crypto::rustls::{HandshakeData, QuicClientConfig};
use quinn::{ClientConfig, Connection, RecvStream, SendStream};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::Mutex;
use tokio::time::timeout;

use crate::{BoxedTransitConnection, Endpoint, TransitError};

pub(crate) struct QuicTransport {
    remote: Endpoint,
    server_name: String,
    client: ClientConfig,
    alpn: Vec<Vec<u8>>,
    session: Mutex<Option<Arc<Session>>>,
    timeout: Duration,
}

struct Session {
    connection: Connection,
    _endpoint: quinn::Endpoint,
}

impl QuicTransport {
    pub(crate) fn new(
        remote: Endpoint,
        server_name: String,
        tls: Arc<rustls::ClientConfig>,
        duration: Duration,
    ) -> Result<Self, TransitError> {
        let mut tls = (*tls).clone();
        if tls.alpn_protocols.is_empty() {
            tls.alpn_protocols.push(b"h3".to_vec());
        }
        let alpn = tls.alpn_protocols.clone();
        let client =
            ClientConfig::new(Arc::new(QuicClientConfig::try_from(tls).map_err(|_| {
                TransitError::Unsupported("V2Ray QUIC TLS configuration is invalid".into())
            })?));
        Ok(Self {
            remote,
            server_name,
            client,
            alpn,
            session: Mutex::new(None),
            timeout: duration,
        })
    }

    async fn session(&self) -> Result<Arc<Session>, TransitError> {
        let mut cached = self.session.lock().await;
        if let Some(session) = cached.as_ref()
            && session.connection.close_reason().is_none()
        {
            return Ok(Arc::clone(session));
        }
        *cached = None;
        let addresses = tokio::net::lookup_host((self.remote.host.as_str(), self.remote.port))
            .await
            .map_err(|_| connection_error("V2Ray QUIC endpoint resolution failed"))?;
        let session = Arc::new(self.dial_addresses(addresses).await?);
        *cached = Some(Arc::clone(&session));
        Ok(session)
    }

    async fn dial_addresses(
        &self,
        addresses: impl IntoIterator<Item = SocketAddr>,
    ) -> Result<Session, TransitError> {
        let mut pending = FuturesUnordered::new();
        for address in addresses.into_iter().take(16) {
            pending.push(self.dial_one(address));
        }
        let mut error = connection_error("V2Ray QUIC endpoint returned no addresses");
        while let Some(result) = pending.next().await {
            match result {
                Ok(session) => return Ok(session),
                Err(failure) => error = failure,
            }
        }
        Err(error)
    }

    async fn dial_one(&self, address: SocketAddr) -> Result<Session, TransitError> {
        let bind = if address.is_ipv6() {
            "[::]:0"
        } else {
            "0.0.0.0:0"
        };
        let mut endpoint = quinn::Endpoint::client(bind.parse().expect("fixed local bind"))
            .map_err(|_| connection_error("V2Ray QUIC local bind failed"))?;
        endpoint.set_default_client_config(self.client.clone());
        let connection = endpoint
            .connect(address, &self.server_name)
            .map_err(|_| connection_error("V2Ray QUIC connection failed"))?
            .await
            .map_err(|_| connection_error("V2Ray QUIC handshake failed"))?;
        let negotiated = connection
            .handshake_data()
            .and_then(|value| value.downcast::<HandshakeData>().ok())
            .and_then(|data| data.protocol);
        if !negotiated
            .as_ref()
            .is_some_and(|value| self.alpn.contains(value))
        {
            connection.close(0_u32.into(), b"ALPN mismatch");
            return Err(connection_error(
                "V2Ray QUIC peer did not negotiate configured ALPN",
            ));
        }
        Ok(Session {
            connection,
            _endpoint: endpoint,
        })
    }

    pub(crate) async fn connect(&self) -> Result<BoxedTransitConnection, TransitError> {
        timeout(self.timeout, async {
            for attempt in 0..2 {
                let session = self.session().await?;
                match session.connection.open_bi().await {
                    Ok((send, recv)) => {
                        return Ok(Box::new(QuicStream {
                            send,
                            recv,
                            _session: session,
                            shutdown: None,
                            shutdown_result: None,
                            shutdown_timeout: self.timeout.min(Duration::from_secs(2)),
                        }) as BoxedTransitConnection);
                    }
                    Err(_) if attempt == 0 && session.connection.close_reason().is_some() => {
                        let mut cached = self.session.lock().await;
                        if cached
                            .as_ref()
                            .is_some_and(|value| Arc::ptr_eq(value, &session))
                        {
                            *cached = None;
                        }
                    }
                    Err(_) => return Err(connection_error("V2Ray QUIC stream open failed")),
                }
            }
            Err(connection_error("V2Ray QUIC stream open failed"))
        })
        .await
        .map_err(|_| connection_error("V2Ray QUIC connection timed out"))?
    }
}

fn connection_error(message: &str) -> TransitError {
    TransitError::Connection(message.to_owned())
}

struct QuicStream {
    send: SendStream,
    recv: RecvStream,
    _session: Arc<Session>,
    shutdown: Option<Pin<Box<dyn Future<Output = io::Result<()>> + Send>>>,
    shutdown_result: Option<Result<(), (io::ErrorKind, String)>>,
    shutdown_timeout: Duration,
}

impl AsyncRead for QuicStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.recv).poll_read(cx, out)
    }
}

impl AsyncWrite for QuicStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.send)
            .poll_write(cx, data)
            .map_err(io::Error::other)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.send).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Some(result) = &self.shutdown_result {
            return Poll::Ready(match result {
                Ok(()) => Ok(()),
                Err((kind, message)) => Err(io::Error::new(*kind, message.clone())),
            });
        }
        if self.shutdown.is_none() {
            if let Err(error) = std::task::ready!(Pin::new(&mut self.send).poll_shutdown(cx)) {
                self.shutdown_result = Some(Err((error.kind(), error.to_string())));
                return Poll::Ready(Err(error));
            }
            let stopped = self.send.stopped();
            let duration = self.shutdown_timeout;
            self.shutdown = Some(Box::pin(async move {
                match timeout(duration, stopped).await {
                    Ok(Ok(None)) => Ok(()),
                    Ok(Ok(Some(_))) => Err(io::Error::other("V2Ray QUIC stream stopped by peer")),
                    Ok(Err(_)) => Err(io::Error::other("V2Ray QUIC stream acknowledgement failed")),
                    Err(_) => Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "V2Ray QUIC stream shutdown timed out",
                    )),
                }
            }));
        }
        let result = self
            .shutdown
            .as_mut()
            .expect("shutdown future exists")
            .as_mut()
            .poll(cx);
        if let Poll::Ready(outcome) = &result {
            self.shutdown_result = Some(match outcome {
                Ok(()) => Ok(()),
                Err(error) => Err((error.kind(), error.to_string())),
            });
            self.shutdown = None;
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quinn::crypto::rustls::QuicServerConfig;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn tls() -> (quinn::ServerConfig, Arc<rustls::ClientConfig>) {
        let rcgen::CertifiedKey { cert, signing_key } =
            rcgen::generate_simple_self_signed(vec!["quic.test".into()]).unwrap();
        let certificate = cert.der().clone();
        let mut server = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![certificate.clone()],
            rustls::pki_types::PrivatePkcs8KeyDer::from(signing_key.serialize_der()).into(),
        )
        .unwrap();
        server.alpn_protocols = vec![b"h3".to_vec()];
        let server =
            quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(server).unwrap()));
        let mut roots = rustls::RootCertStore::empty();
        roots.add(certificate).unwrap();
        let client = crate::tls::client_builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        (server, Arc::new(client))
    }

    async fn echo_one(connection: &Connection, expected: &[u8]) {
        let (mut send, mut recv) = connection.accept_bi().await.unwrap();
        assert_eq!(recv.read_to_end(1024).await.unwrap(), expected);
        send.write_all(expected).await.unwrap();
        send.finish().unwrap();
        assert!(send.stopped().await.unwrap().is_none());
    }

    async fn exchange_stream(mut stream: BoxedTransitConnection, message: &[u8]) {
        stream.write_all(message).await.unwrap();
        stream.shutdown().await.unwrap();
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await.unwrap();
        assert_eq!(response, message);
    }

    async fn exchange(transport: &QuicTransport, message: &[u8]) {
        exchange_stream(transport.connect().await.unwrap(), message).await;
    }

    #[tokio::test]
    async fn reuses_connection_preserves_half_close_and_reconnects_after_close() {
        timeout(Duration::from_secs(10), async {
            let (server_config, client_tls) = tls();
            let endpoint =
                quinn::Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap()).unwrap();
            let address = endpoint.local_addr().unwrap();
            let peer = tokio::spawn(async move {
                let first = endpoint.accept().await.unwrap().await.unwrap();
                echo_one(&first, b"first").await;
                echo_one(&first, b"second").await;
                first.close(0_u32.into(), b"rotate");
                let second = endpoint.accept().await.unwrap().await.unwrap();
                echo_one(&second, b"third").await;
            });
            let transport = QuicTransport::new(
                Endpoint {
                    host: address.ip().to_string(),
                    port: address.port(),
                },
                "quic.test".into(),
                client_tls,
                Duration::from_secs(3),
            )
            .unwrap();
            let first_stream = transport.connect().await.unwrap();
            let second_stream = transport.connect().await.unwrap();
            let first = transport.session.lock().await.as_ref().unwrap().clone();
            exchange_stream(first_stream, b"first").await;
            exchange_stream(second_stream, b"second").await;
            first.connection.closed().await;
            exchange(&transport, b"third").await;
            peer.await.unwrap();
        })
        .await
        .expect("QUIC reuse or reconnect timed out");
    }

    #[tokio::test]
    async fn cancelled_handshake_releases_cached_state_for_a_later_connection() {
        timeout(Duration::from_secs(10), async {
            let (server_config, client_tls) = tls();
            let blackhole = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
            let address = blackhole.local_addr().unwrap();
            let transport = QuicTransport::new(
                Endpoint {
                    host: address.ip().to_string(),
                    port: address.port(),
                },
                "quic.test".into(),
                client_tls,
                Duration::from_secs(3),
            )
            .unwrap();
            for _ in 0..2 {
                assert!(
                    timeout(Duration::from_millis(80), transport.connect())
                        .await
                        .is_err()
                );
                assert!(transport.session.lock().await.is_none());
            }
            drop(blackhole);
            let endpoint = quinn::Endpoint::server(server_config, address).unwrap();
            let peer = tokio::spawn(async move {
                loop {
                    let incoming = endpoint.accept().await.unwrap();
                    let Ok(conn) = incoming.await else { continue };
                    let Ok(Ok((mut send, mut recv))) =
                        timeout(Duration::from_secs(1), conn.accept_bi()).await
                    else {
                        continue;
                    };
                    assert_eq!(recv.read_to_end(1024).await.unwrap(), b"after-cancellation");
                    send.write_all(b"after-cancellation").await.unwrap();
                    send.finish().unwrap();
                    assert!(send.stopped().await.unwrap().is_none());
                    break;
                }
            });
            exchange(&transport, b"after-cancellation").await;
            peer.await.unwrap();
        })
        .await
        .expect("QUIC cancellation recovery timed out");
    }

    #[tokio::test]
    async fn connects_to_an_ipv6_quic_endpoint() {
        timeout(Duration::from_secs(5), async {
            let (server_config, client_tls) = tls();
            let endpoint = match quinn::Endpoint::server(server_config, "[::1]:0".parse().unwrap())
            {
                Ok(endpoint) => endpoint,
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::AddrNotAvailable | io::ErrorKind::Unsupported
                    ) =>
                {
                    return;
                }
                Err(error) => panic!("IPv6 QUIC test bind failed: {error}"),
            };
            let address = endpoint.local_addr().unwrap();
            let peer = tokio::spawn(async move {
                let conn = endpoint.accept().await.unwrap().await.unwrap();
                echo_one(&conn, b"ipv6").await;
            });
            let transport = QuicTransport::new(
                Endpoint {
                    host: address.ip().to_string(),
                    port: address.port(),
                },
                "quic.test".into(),
                client_tls,
                Duration::from_secs(3),
            )
            .unwrap();
            exchange(&transport, b"ipv6").await;
            peer.await.unwrap();
        })
        .await
        .expect("IPv6 QUIC exchange timed out");
    }

    #[tokio::test]
    async fn active_stream_outlives_its_transport_owner() {
        timeout(Duration::from_secs(5), async {
            let (server_config, client_tls) = tls();
            let endpoint =
                quinn::Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap()).unwrap();
            let address = endpoint.local_addr().unwrap();
            let peer = tokio::spawn(async move {
                let conn = endpoint.accept().await.unwrap().await.unwrap();
                echo_one(&conn, b"still-open").await;
            });
            let transport = QuicTransport::new(
                Endpoint {
                    host: address.ip().to_string(),
                    port: address.port(),
                },
                "quic.test".into(),
                client_tls,
                Duration::from_secs(3),
            )
            .unwrap();
            let stream = transport.connect().await.unwrap();
            drop(transport);
            exchange_stream(stream, b"still-open").await;
            peer.await.unwrap();
        })
        .await
        .expect("QUIC ownership test timed out");
    }

    #[tokio::test]
    async fn unreachable_first_address_does_not_block_a_reachable_peer() {
        timeout(Duration::from_secs(5), async {
            let (server_config, client_tls) = tls();
            let endpoint =
                quinn::Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap()).unwrap();
            let address = endpoint.local_addr().unwrap();
            let blackhole = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
            let first = blackhole.local_addr().unwrap();
            let peer = tokio::spawn(async move {
                let conn = endpoint.accept().await.unwrap().await.unwrap();
                echo_one(&conn, b"fallback").await;
            });
            let transport = QuicTransport::new(
                Endpoint {
                    host: address.ip().to_string(),
                    port: address.port(),
                },
                "quic.test".into(),
                client_tls,
                Duration::from_secs(3),
            )
            .unwrap();
            let session = timeout(
                Duration::from_millis(750),
                transport.dial_addresses([first, address]),
            )
            .await
            .expect("the responsive address must not wait for the blackhole")
            .unwrap();
            *transport.session.lock().await = Some(Arc::new(session));
            exchange(&transport, b"fallback").await;
            peer.await.unwrap();
        })
        .await
        .expect("QUIC address fallback test timed out");
    }

    #[tokio::test]
    async fn peer_stream_reset_is_reported_instead_of_becoming_eof() {
        timeout(Duration::from_secs(5), async {
            let (server_config, client_tls) = tls();
            let endpoint =
                quinn::Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap()).unwrap();
            let address = endpoint.local_addr().unwrap();
            let (done_tx, done_rx) = tokio::sync::oneshot::channel();
            let peer = tokio::spawn(async move {
                let conn = endpoint.accept().await.unwrap().await.unwrap();
                let (mut send, mut recv) = conn.accept_bi().await.unwrap();
                let mut byte = [0];
                recv.read_exact(&mut byte).await.unwrap();
                assert_eq!(&byte, b"x");
                send.reset(42_u32.into()).unwrap();
                let _ = done_rx.await;
            });
            let transport = QuicTransport::new(
                Endpoint {
                    host: address.ip().to_string(),
                    port: address.port(),
                },
                "quic.test".into(),
                client_tls,
                Duration::from_secs(3),
            )
            .unwrap();
            let mut stream = transport.connect().await.unwrap();
            stream.write_all(b"x").await.unwrap();
            let mut byte = [0];
            assert!(stream.read(&mut byte).await.is_err());
            done_tx.send(()).unwrap();
            peer.await.unwrap();
        })
        .await
        .expect("QUIC reset test timed out");
    }
}
