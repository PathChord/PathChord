//! Bounded dae/V2Fly Meek HTTPS polling byte transport.

use std::collections::VecDeque;
use std::io::{self, ErrorKind};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use bytes::Bytes;
use http::{HeaderValue, Method, Request, StatusCode, Uri, header};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper_util::rt::{TokioExecutor, TokioIo};
use rustls::pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::Notify;
use tokio::task::JoinHandle;
use tokio::time::{sleep, timeout};

use crate::{BoxedTransitConnection, Endpoint, TransitError};

const MAX_URL: usize = 8192;
const MAX_WRITE: usize = 65_536;
const MAX_RESPONSE: usize = 1 << 20;
const MAX_HTTP_HEADER: usize = 32 * 1024;

pub(crate) struct MeekTransport {
    uri: zeroize::Zeroizing<String>,
    authority: HeaderValue,
    remote: Endpoint,
    tls: Arc<rustls::ClientConfig>,
    server_name: ServerName<'static>,
    require_alpn: bool,
    timeout: Duration,
}

impl MeekTransport {
    pub(crate) fn new(
        private_url: &str,
        tls: Arc<rustls::ClientConfig>,
        server_name: ServerName<'static>,
        timeout: Duration,
    ) -> Result<Self, TransitError> {
        if private_url.is_empty() || private_url.len() > MAX_URL {
            return Err(unsupported("Meek URL is missing or too large"));
        }
        let parsed =
            url::Url::parse(private_url).map_err(|_| unsupported("Meek URL is invalid"))?;
        let uri = private_url
            .parse::<Uri>()
            .map_err(|_| unsupported("Meek URL is invalid"))?;
        let authority = uri
            .authority()
            .ok_or_else(|| unsupported("Meek URL has no authority"))?;
        if parsed.scheme() != "https"
            || parsed.host_str().is_none()
            || !parsed.username().is_empty()
            || parsed.password().is_some()
            || parsed.fragment().is_some()
            || authority.as_str().contains('@')
        {
            return Err(unsupported(
                "Meek requires a credential-free HTTPS URL without fragment",
            ));
        }
        let remote = Endpoint {
            host: match parsed.host().expect("validated URL host") {
                url::Host::Domain(host) => host.to_owned(),
                url::Host::Ipv4(address) => address.to_string(),
                url::Host::Ipv6(address) => address.to_string(),
            },
            port: parsed
                .port_or_known_default()
                .ok_or_else(|| unsupported("Meek URL port is invalid"))?,
        };
        let authority = HeaderValue::from_str(authority.as_str())
            .map_err(|_| unsupported("Meek URL authority is invalid"))?;
        let mut tls = (*tls).clone();
        let require_alpn = !tls.alpn_protocols.is_empty();
        if require_alpn
            && tls
                .alpn_protocols
                .iter()
                .any(|value| value != b"h2" && value != b"http/1.1")
        {
            return Err(unsupported("Meek supports only HTTP/2 or HTTP/1.1 ALPN"));
        }
        if !require_alpn {
            tls.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        }
        Ok(Self {
            uri: zeroize::Zeroizing::new(private_url.to_owned()),
            authority,
            remote,
            tls: Arc::new(tls),
            server_name,
            require_alpn,
            timeout,
        })
    }

    pub(crate) fn connect(&self) -> Result<BoxedTransitConnection, TransitError> {
        let mut id = [0; 16];
        getrandom::fill(&mut id).map_err(|_| connection("Meek session ID generation failed"))?;
        let session = HeaderValue::from_str(&URL_SAFE_NO_PAD.encode(id))
            .map_err(|_| connection("Meek session ID is invalid"))?;
        let shared = Arc::new(Mutex::new(Shared::default()));
        let notify = Arc::new(Notify::new());
        let worker = Worker {
            uri: self.uri.clone(),
            authority: self.authority.clone(),
            remote: self.remote.clone(),
            tls: Arc::clone(&self.tls),
            server_name: self.server_name.clone(),
            require_alpn: self.require_alpn,
            timeout: self.timeout,
            session,
            shared: Arc::clone(&shared),
            notify: Arc::clone(&notify),
        };
        let task = tokio::spawn(worker.run());
        Ok(Box::new(MeekStream {
            shared,
            notify,
            task,
            write_closed: false,
        }))
    }
}

impl std::fmt::Debug for MeekTransport {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("MeekTransport")
            .field("url", &"<redacted>")
            .finish_non_exhaustive()
    }
}

fn unsupported(message: &'static str) -> TransitError {
    TransitError::Unsupported(message.into())
}

fn connection(message: &'static str) -> TransitError {
    TransitError::Connection(message.into())
}

#[derive(Default)]
struct Shared {
    outgoing: VecDeque<u8>,
    incoming: VecDeque<u8>,
    accepted: u64,
    delivered: u64,
    closed: bool,
    error: Option<(ErrorKind, &'static str)>,
    reader: Option<Waker>,
    writer: Option<Waker>,
    flusher: Option<Waker>,
}

impl Shared {
    fn error(&self) -> Option<io::Error> {
        self.error
            .map(|(kind, message)| io::Error::new(kind, message))
    }

    fn take_wakers(&mut self) -> Vec<Waker> {
        [self.reader.take(), self.writer.take(), self.flusher.take()]
            .into_iter()
            .flatten()
            .collect()
    }
}

fn wake(wakers: Vec<Waker>) {
    for waker in wakers {
        waker.wake();
    }
}

struct MeekStream {
    shared: Arc<Mutex<Shared>>,
    notify: Arc<Notify>,
    task: JoinHandle<()>,
    write_closed: bool,
}

impl Drop for MeekStream {
    fn drop(&mut self) {
        self.task.abort();
        let wakers = {
            let mut shared = self
                .shared
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            shared.closed = true;
            shared.take_wakers()
        };
        wake(wakers);
    }
}

impl AsyncRead for MeekStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if out.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        let this = self.get_mut();
        let mut shared = this
            .shared
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if !shared.incoming.is_empty() {
            let amount = out.remaining().min(shared.incoming.len());
            let (first, second) = shared.incoming.as_slices();
            let first_len = amount.min(first.len());
            out.put_slice(&first[..first_len]);
            out.put_slice(&second[..amount - first_len]);
            drop(shared.incoming.drain(..amount));
            drop(shared);
            this.notify.notify_one();
            return Poll::Ready(Ok(()));
        }
        if let Some(error) = shared.error() {
            return Poll::Ready(Err(error));
        }
        if shared.closed {
            return Poll::Ready(Ok(()));
        }
        shared.reader = Some(cx.waker().clone());
        Poll::Pending
    }
}

impl AsyncWrite for MeekStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        if data.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let this = self.get_mut();
        if this.write_closed {
            return Poll::Ready(Err(io::Error::new(
                ErrorKind::BrokenPipe,
                "Meek write side is closed",
            )));
        }
        let mut shared = this
            .shared
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if let Some(error) = shared.error() {
            return Poll::Ready(Err(error));
        }
        if shared.closed {
            return Poll::Ready(Err(io::Error::new(
                ErrorKind::BrokenPipe,
                "Meek session is closed",
            )));
        }
        let available = MAX_WRITE - shared.outgoing.len();
        if available == 0 {
            shared.writer = Some(cx.waker().clone());
            return Poll::Pending;
        }
        let size = available.min(data.len());
        shared.accepted = shared
            .accepted
            .checked_add(size as u64)
            .ok_or_else(|| io::Error::other("Meek byte count exhausted"))?;
        shared.outgoing.extend(&data[..size]);
        drop(shared);
        this.notify.notify_one();
        Poll::Ready(Ok(size))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let mut shared = this
            .shared
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if let Some(error) = shared.error() {
            return Poll::Ready(Err(error));
        }
        if shared.accepted == shared.delivered {
            return Poll::Ready(Ok(()));
        }
        if shared.closed {
            return Poll::Ready(Err(io::Error::new(
                ErrorKind::BrokenPipe,
                "Meek session is closed",
            )));
        }
        shared.flusher = Some(cx.waker().clone());
        drop(shared);
        this.notify.notify_one();
        Poll::Pending
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.write_closed {
            return Poll::Ready(Ok(()));
        }
        std::task::ready!(self.as_mut().poll_flush(cx))?;
        self.write_closed = true;
        // Meek has no wire message for a directional FIN. A successful
        // shutdown here only closes the local write side; reads remain live.
        Poll::Ready(Ok(()))
    }
}

struct Worker {
    uri: zeroize::Zeroizing<String>,
    authority: HeaderValue,
    remote: Endpoint,
    tls: Arc<rustls::ClientConfig>,
    server_name: ServerName<'static>,
    require_alpn: bool,
    timeout: Duration,
    session: HeaderValue,
    shared: Arc<Mutex<Shared>>,
    notify: Arc<Notify>,
}

impl Worker {
    async fn run(self) {
        let mut delay = Duration::from_millis(100);
        loop {
            let notified = self.notify.notified();
            let work = {
                let mut shared = self
                    .shared
                    .lock()
                    .unwrap_or_else(|error| error.into_inner());
                if shared.closed {
                    return;
                }
                if !shared.incoming.is_empty() {
                    None
                } else if shared.outgoing.is_empty() {
                    Some(Vec::new())
                } else {
                    let size = shared.outgoing.len().min(MAX_WRITE);
                    let data: Vec<u8> = shared.outgoing.drain(..size).collect();
                    let writer = shared.writer.take();
                    drop(shared);
                    if let Some(writer) = writer {
                        writer.wake();
                    }
                    Some(data)
                }
            };
            let data = match work {
                None => {
                    notified.await;
                    continue;
                }
                Some(data) if data.is_empty() => {
                    tokio::select! {
                        _ = notified => continue,
                        _ = sleep(delay) => data,
                    }
                }
                Some(data) => data,
            };
            let sent_len = data.len();
            let result = timeout(self.timeout, self.round_trip(data)).await;
            let (response, error) = match result {
                Ok(Ok(response)) => (response, None),
                Ok(Err(error)) => (Vec::new(), Some((error.kind(), static_error(&error)))),
                Err(_) => (
                    Vec::new(),
                    Some((ErrorKind::TimedOut, "Meek request timed out")),
                ),
            };
            let active = sent_len != 0 || !response.is_empty();
            let wakers = {
                let mut shared = self
                    .shared
                    .lock()
                    .unwrap_or_else(|error| error.into_inner());
                if shared.closed {
                    return;
                }
                if let Some(error) = error {
                    shared.error = Some(error);
                } else {
                    shared.delivered += sent_len as u64;
                    shared.incoming.extend(response);
                }
                shared.take_wakers()
            };
            wake(wakers);
            if error.is_some() {
                return;
            }
            delay = if active {
                Duration::from_millis(10)
            } else {
                delay.mul_f32(1.5).min(Duration::from_secs(1))
            };
        }
    }

    async fn round_trip(&self, data: Vec<u8>) -> io::Result<Vec<u8>> {
        let raw = crate::connect_tcp_endpoint(&self.remote, self.timeout)
            .await
            .map_err(|_| io::Error::other("Meek connection failed"))?;
        let stream = tokio_rustls::TlsConnector::from(Arc::clone(&self.tls))
            .connect(self.server_name.clone(), raw)
            .await
            .map_err(|_| io::Error::other("Meek TLS handshake failed"))?;
        let negotiated = stream.get_ref().1.alpn_protocol();
        if negotiated.is_none() && self.require_alpn {
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                "Meek TLS ALPN was not negotiated",
            ));
        }
        let use_h2 = match negotiated {
            Some(b"h2") => true,
            Some(b"http/1.1") | None => false,
            _ => {
                return Err(io::Error::new(
                    ErrorKind::InvalidData,
                    "Meek TLS ALPN is unsupported",
                ));
            }
        };
        let uri = self
            .uri
            .parse::<Uri>()
            .map_err(|_| io::Error::other("Meek request URI is invalid"))?;
        let request_uri = if use_h2 {
            uri
        } else {
            uri.path_and_query()
                .map(|path| path.as_str())
                .unwrap_or("/")
                .parse::<Uri>()
                .map_err(|_| io::Error::other("Meek request URI is invalid"))?
        };
        let request = Request::builder()
            .method(Method::POST)
            .uri(request_uri)
            .header(header::HOST, self.authority.clone())
            .header("X-Session-ID", self.session.clone())
            .body(Full::new(Bytes::from(data)))
            .map_err(|_| io::Error::other("Meek request is invalid"))?;
        let response = if use_h2 {
            let mut builder = hyper::client::conn::http2::Builder::new(TokioExecutor::new());
            builder.max_header_list_size(MAX_HTTP_HEADER as u32);
            let (mut sender, driver) = builder
                .handshake(TokioIo::new(stream))
                .await
                .map_err(|_| io::Error::other("Meek HTTP/2 handshake failed"))?;
            let guard = Driver(tokio::spawn(async move {
                let _ = driver.await;
            }));
            let response = sender
                .send_request(request)
                .await
                .map_err(|_| io::Error::other("Meek HTTP request failed"))?;
            let body = response_body(response).await;
            drop(guard);
            body
        } else {
            let mut builder = hyper::client::conn::http1::Builder::new();
            builder.max_buf_size(MAX_HTTP_HEADER);
            builder.max_headers(128);
            let (mut sender, driver) = builder
                .handshake(TokioIo::new(stream))
                .await
                .map_err(|_| io::Error::other("Meek HTTP/1.1 handshake failed"))?;
            let guard = Driver(tokio::spawn(async move {
                let _ = driver.await;
            }));
            let response = sender
                .send_request(request)
                .await
                .map_err(|_| io::Error::other("Meek HTTP request failed"))?;
            let body = response_body(response).await;
            drop(guard);
            body
        }?;
        Ok(response)
    }
}

fn static_error(error: &io::Error) -> &'static str {
    match error.to_string().as_str() {
        "Meek response exceeds size limit" => "Meek response exceeds size limit",
        "Meek HTTP status is not 200" => "Meek HTTP status is not 200",
        "Meek TLS ALPN was not negotiated" => "Meek TLS ALPN was not negotiated",
        "Meek TLS ALPN is unsupported" => "Meek TLS ALPN is unsupported",
        "Meek TLS handshake failed" => "Meek TLS handshake failed",
        "Meek connection failed" => "Meek connection failed",
        _ => "Meek request failed",
    }
}

struct Driver(JoinHandle<()>);

impl Drop for Driver {
    fn drop(&mut self) {
        self.0.abort();
    }
}

async fn response_body(response: http::Response<Incoming>) -> io::Result<Vec<u8>> {
    if response.status() != StatusCode::OK {
        return Err(io::Error::new(
            ErrorKind::InvalidData,
            "Meek HTTP status is not 200",
        ));
    }
    let mut body = response.into_body();
    let mut result = Vec::new();
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|_| io::Error::other("Meek HTTP body failed"))?;
        if let Ok(data) = frame.into_data() {
            if result.len().saturating_add(data.len()) > MAX_RESPONSE {
                return Err(io::Error::new(
                    ErrorKind::InvalidData,
                    "Meek response exceeds size limit",
                ));
            }
            result.extend_from_slice(&data);
        }
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::service::service_fn;
    use std::convert::Infallible;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    fn tls(alpn: &[&[u8]]) -> (Arc<rustls::ClientConfig>, tokio_rustls::TlsAcceptor) {
        let rcgen::CertifiedKey { cert, signing_key } =
            rcgen::generate_simple_self_signed(vec!["sni.test".into()]).unwrap();
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
        server.alpn_protocols = alpn.iter().map(|value| value.to_vec()).collect();
        let mut roots = rustls::RootCertStore::empty();
        roots.add(certificate).unwrap();
        let client = crate::tls::client_builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        (
            Arc::new(client),
            tokio_rustls::TlsAcceptor::from(Arc::new(server)),
        )
    }

    async fn fake_server(
        acceptor: tokio_rustls::TlsAcceptor,
        status: StatusCode,
        oversized: bool,
    ) -> (
        std::net::SocketAddr,
        Arc<Mutex<Vec<(String, String, String, usize)>>>,
        Arc<AtomicUsize>,
        JoinHandle<()>,
    ) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let count = Arc::new(AtomicUsize::new(0));
        let task_requests = Arc::clone(&requests);
        let task_count = Arc::clone(&count);
        let task = tokio::spawn(async move {
            loop {
                let (stream, _) = listener.accept().await.unwrap();
                let acceptor = acceptor.clone();
                let requests = Arc::clone(&task_requests);
                let count = Arc::clone(&task_count);
                tokio::spawn(async move {
                    let Ok(stream) = acceptor.accept(stream).await else {
                        return;
                    };
                    let use_h2 = stream.get_ref().1.alpn_protocol() == Some(b"h2");
                    let service = service_fn(move |request: Request<Incoming>| {
                        let requests = Arc::clone(&requests);
                        let count = Arc::clone(&count);
                        async move {
                            count.fetch_add(1, Ordering::SeqCst);
                            let session = request
                                .headers()
                                .get("x-session-id")
                                .unwrap()
                                .to_str()
                                .unwrap()
                                .to_owned();
                            assert_eq!(URL_SAFE_NO_PAD.decode(&session).unwrap().len(), 16);
                            let host = request
                                .headers()
                                .get(header::HOST)
                                .unwrap()
                                .to_str()
                                .unwrap()
                                .to_owned();
                            let target =
                                request.uri().path_and_query().unwrap().as_str().to_owned();
                            assert!(!request.headers().contains_key(header::AUTHORIZATION));
                            let data = request.into_body().collect().await.unwrap().to_bytes();
                            requests
                                .lock()
                                .unwrap()
                                .push((session, host, target, data.len()));
                            let response = if oversized {
                                Bytes::from(vec![0x42; MAX_RESPONSE + 1])
                            } else {
                                data
                            };
                            Ok::<_, Infallible>(
                                http::Response::builder()
                                    .status(status)
                                    .body(Full::new(response))
                                    .unwrap(),
                            )
                        }
                    });
                    if use_h2 {
                        let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                            .serve_connection(TokioIo::new(stream), service)
                            .await;
                    } else {
                        let _ = hyper::server::conn::http1::Builder::new()
                            .serve_connection(TokioIo::new(stream), service)
                            .await;
                    }
                });
            }
        });
        (address, requests, count, task)
    }

    fn transport(address: std::net::SocketAddr, tls: Arc<rustls::ClientConfig>) -> MeekTransport {
        MeekTransport::new(
            &format!(
                "https://127.0.0.1:{}/tunnel?token=private-sentinel",
                address.port()
            ),
            tls,
            ServerName::try_from("sni.test").unwrap().to_owned(),
            Duration::from_secs(2),
        )
        .unwrap()
    }

    #[test]
    fn rejects_plaintext_userinfo_fragments_invalid_alpn_and_oversized_url() {
        let (tls, _) = tls(&[b"http/1.1"]);
        let name = ServerName::try_from("sni.test").unwrap().to_owned();
        let oversized = "https://example.test/".repeat(1000);
        for url in [
            "http://example.test/x",
            "https://user:pass@example.test/x",
            "https://@example.test/x",
            "https://example.test/x#private",
            oversized.as_str(),
        ] {
            assert!(
                MeekTransport::new(url, Arc::clone(&tls), name.clone(), Duration::from_secs(1))
                    .is_err()
            );
        }
        let mut invalid = (*tls).clone();
        invalid.alpn_protocols = vec![b"h3".to_vec()];
        assert!(
            MeekTransport::new(
                "https://example.test/",
                Arc::new(invalid),
                name,
                Duration::from_secs(1)
            )
            .is_err()
        );
        let private = MeekTransport::new(
            "https://example.test/private-path?token=private-sentinel",
            tls,
            ServerName::try_from("sni.test").unwrap().to_owned(),
            Duration::from_secs(1),
        )
        .unwrap();
        let debug = format!("{private:?}");
        assert!(!debug.contains("private-path"));
        assert!(!debug.contains("private-sentinel"));
    }

    #[tokio::test]
    async fn preserves_private_url_host_sni_and_session_identity() {
        timeout(Duration::from_secs(10), async {
            for alpn in [b"http/1.1".as_slice(), b"h2".as_slice()] {
                let (tls, acceptor) = tls(&[alpn]);
                let (address, requests, _, task) =
                    fake_server(acceptor, StatusCode::OK, false).await;
                let transport = transport(address, tls);
                let mut first = transport.connect().unwrap();
                let mut second = transport.connect().unwrap();
                async fn exchange(stream: &mut BoxedTransitConnection, message: &[u8]) {
                    stream.write_all(message).await.unwrap();
                    stream.flush().await.unwrap();
                    let mut response = vec![0; message.len()];
                    stream.read_exact(&mut response).await.unwrap();
                    assert_eq!(response, message);
                }
                exchange(&mut first, b"first").await;
                exchange(&mut first, b"again").await;
                exchange(&mut second, b"second").await;
                drop(first);
                drop(second);
                let records = requests.lock().unwrap();
                let sessions: std::collections::BTreeSet<_> =
                    records.iter().map(|entry| &entry.0).collect();
                assert_eq!(sessions.len(), 2);
                assert!(
                    records
                        .iter()
                        .all(|entry| entry.1 == format!("127.0.0.1:{}", address.port())
                            && entry.2 == "/tunnel?token=private-sentinel")
                );
                drop(records);
                task.abort();
            }
        })
        .await
        .expect("Meek session exchange timed out");
    }

    #[tokio::test]
    async fn large_bidirectional_payloads_use_bounded_requests() {
        timeout(Duration::from_secs(10), async {
            let (tls, acceptor) = tls(&[b"h2"]);
            let (address, requests, _, task) = fake_server(acceptor, StatusCode::OK, false).await;
            let mut stream = transport(address, tls).connect().unwrap();
            let payload: Vec<_> = (0..200_003).map(|index| (index % 251) as u8).collect();
            let (mut reader, mut writer) = tokio::io::split(&mut stream);
            let (sent, received) = tokio::join!(
                async {
                    writer.write_all(&payload).await?;
                    writer.flush().await
                },
                async {
                    let mut result = vec![0; payload.len()];
                    reader.read_exact(&mut result).await?;
                    Ok::<_, io::Error>(result)
                }
            );
            sent.unwrap();
            assert_eq!(received.unwrap(), payload);
            drop(reader);
            drop(writer);
            drop(stream);
            let records = requests.lock().unwrap();
            assert!(records.len() >= 4);
            assert!(records.iter().all(|entry| entry.3 <= MAX_WRITE));
            task.abort();
        })
        .await
        .expect("bounded Meek exchange timed out");
    }

    #[tokio::test]
    async fn write_shutdown_keeps_reading_without_claiming_remote_eof() {
        timeout(Duration::from_secs(5), async {
            let (tls, acceptor) = tls(&[b"http/1.1"]);
            let (address, _, _, task) = fake_server(acceptor, StatusCode::OK, false).await;
            let mut stream = transport(address, tls).connect().unwrap();
            stream.write_all(b"still-readable").await.unwrap();
            stream.shutdown().await.unwrap();
            assert_eq!(
                stream.write(b"no-more").await.unwrap_err().kind(),
                ErrorKind::BrokenPipe
            );
            let mut response = [0; 14];
            stream.read_exact(&mut response).await.unwrap();
            assert_eq!(&response, b"still-readable");
            task.abort();
        })
        .await
        .expect("Meek half-close behavior timed out");
    }

    #[tokio::test]
    async fn rejects_http_error_and_oversized_body_without_retry_or_secret_leak() {
        for (status, oversized) in [(StatusCode::FORBIDDEN, false), (StatusCode::OK, true)] {
            timeout(Duration::from_secs(5), async {
                let (tls, acceptor) = tls(&[b"http/1.1"]);
                let (address, _, count, task) = fake_server(acceptor, status, oversized).await;
                let mut stream = transport(address, tls).connect().unwrap();
                stream.write_all(b"not-replayed").await.unwrap();
                let error = stream.flush().await.unwrap_err();
                assert!(!error.to_string().contains("private-sentinel"));
                assert!(stream.read(&mut [0; 4]).await.is_err());
                sleep(Duration::from_millis(50)).await;
                assert_eq!(count.load(Ordering::SeqCst), 1);
                task.abort();
            })
            .await
            .expect("Meek failure test timed out");
        }
    }

    #[tokio::test]
    async fn response_loss_after_submission_never_replays_the_request_body() {
        timeout(Duration::from_secs(5), async {
            let (tls, acceptor) = tls(&[b"http/1.1"]);
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let peer = tokio::spawn(async move {
                let (stream, _) = listener.accept().await.unwrap();
                let mut stream = acceptor.accept(stream).await.unwrap();
                let mut headers = Vec::new();
                while !headers.ends_with(b"\r\n\r\n") {
                    headers.push(stream.read_u8().await.unwrap());
                }
                let text = std::str::from_utf8(&headers).unwrap();
                let length: usize = text
                    .lines()
                    .find_map(|line| {
                        line.split_once(':').and_then(|(name, value)| {
                            name.eq_ignore_ascii_case("content-length")
                                .then(|| value.trim().parse().unwrap())
                        })
                    })
                    .unwrap();
                let mut body = vec![0; length];
                stream.read_exact(&mut body).await.unwrap();
                assert_eq!(body, b"accepted-once");
                drop(stream);
                assert!(
                    timeout(Duration::from_millis(300), listener.accept())
                        .await
                        .is_err()
                );
            });
            let mut stream = transport(address, tls).connect().unwrap();
            stream.write_all(b"accepted-once").await.unwrap();
            assert!(stream.flush().await.is_err());
            assert!(stream.read(&mut [0; 1]).await.is_err());
            peer.await.unwrap();
        })
        .await
        .expect("Meek response-loss test timed out");
    }

    #[tokio::test]
    async fn dropping_a_pending_request_closes_its_tls_socket() {
        timeout(Duration::from_secs(5), async {
            let (tls, acceptor) = tls(&[b"http/1.1"]);
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let (started_tx, started_rx) = tokio::sync::oneshot::channel();
            let peer = tokio::spawn(async move {
                let (stream, _) = listener.accept().await.unwrap();
                let mut stream = acceptor.accept(stream).await.unwrap();
                let mut headers = Vec::new();
                while !headers.ends_with(b"\r\n\r\n") {
                    headers.push(stream.read_u8().await.unwrap());
                }
                let text = std::str::from_utf8(&headers).unwrap();
                let length: usize = text
                    .lines()
                    .find_map(|line| {
                        line.split_once(':').and_then(|(name, value)| {
                            name.eq_ignore_ascii_case("content-length")
                                .then(|| value.trim().parse().unwrap())
                        })
                    })
                    .unwrap();
                let mut body = vec![0; length];
                stream.read_exact(&mut body).await.unwrap();
                started_tx.send(()).unwrap();
                let result = timeout(Duration::from_secs(2), stream.read(&mut [0; 1])).await.unwrap();
                assert!(matches!(result, Ok(0))
                    || matches!(result, Err(error) if matches!(error.kind(), ErrorKind::UnexpectedEof | ErrorKind::ConnectionReset)));
            });
            let mut stream = transport(address, tls).connect().unwrap();
            stream.write_all(b"cancel").await.unwrap();
            let task = tokio::spawn(async move { stream.flush().await });
            started_rx.await.unwrap();
            task.abort();
            assert!(matches!(task.await, Err(error) if error.is_cancelled()));
            peer.await.unwrap();
        })
        .await
        .expect("Meek cancellation test timed out");
    }
}
