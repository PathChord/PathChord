use std::collections::BTreeSet;
use std::convert::Infallible;
use std::future::Future;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::header::{HeaderMap, HeaderValue};
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode, Uri};
use hyper_util::rt::TokioIo;
use pathchord_ingress::{
    BoxedLocalConnection, ConnectionContext, FlowBridgeError, HttpConnectListener,
    ListenerDescriptor, ListenerId, ListenerKind, ListenerRuntime, RuntimeError, RuntimeReport,
    StaticListenerCredentialVerifier, TargetHost, TcpFlowOpener,
};
use pathchord_policy::ProcessMetadataRequest;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, oneshot};
use tokio::task::{JoinHandle, JoinSet};

const AUTHORIZATION: &str = "Basic YWxpY2U6c2VjcmV0";

struct Task<T>(Option<JoinHandle<T>>);

impl<T> Drop for Task<T> {
    fn drop(&mut self) {
        if let Some(task) = self.0.take() {
            task.abort();
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum Route {
    Direct,
    Denied,
    Unavailable,
    Failed,
}

#[derive(Debug, Clone)]
struct Opener {
    route: Route,
    calls: Arc<Mutex<Vec<ConnectionContext>>>,
}

#[async_trait]
impl TcpFlowOpener for Opener {
    async fn connect(
        &self,
        context: ConnectionContext,
    ) -> Result<BoxedLocalConnection, FlowBridgeError> {
        self.calls.lock().unwrap().push(context.clone());
        match self.route {
            Route::Denied => return Err(FlowBridgeError::PolicyRejected),
            Route::Unavailable => return Err(FlowBridgeError::NoUsableRoute),
            Route::Failed => return Err(FlowBridgeError::Dial("private-upstream-detail".into())),
            Route::Direct => {}
        }
        // Test hostnames remain visible to policy; all target sockets stay local.
        let address = match context.target.host {
            TargetHost::Ip(address) => address,
            TargetHost::Hostname(_) => "127.0.0.1".parse().unwrap(),
        };
        TcpStream::connect(SocketAddr::new(address, context.target.port))
            .await
            .map(|stream| Box::new(stream) as BoxedLocalConnection)
            .map_err(|error| FlowBridgeError::Dial(error.to_string()))
    }
}

struct Proxy {
    address: SocketAddr,
    opener: Opener,
    shutdown: Option<oneshot::Sender<()>>,
    task: Task<Result<RuntimeReport, RuntimeError>>,
}

impl Proxy {
    async fn start(authentication_required: bool, route: Route) -> Self {
        let descriptor = ListenerDescriptor {
            id: ListenerId::new("http-forward"),
            kind: ListenerKind::Http,
            bind: Some("127.0.0.1:0".parse().unwrap()),
            interface: None,
            address: None,
            mtu: None,
            flow_tags: BTreeSet::new(),
            process_metadata: ProcessMetadataRequest::default(),
            allowed_sources: vec!["127.0.0.1/32".into()],
            authentication_required,
        };
        let listener = HttpConnectListener::bind(descriptor)
            .await
            .unwrap()
            .with_credential_verifier(Arc::new(StaticListenerCredentialVerifier::new(
                "alice", "secret",
            )));
        let address = listener.local_addr().unwrap();
        let opener = Opener {
            route,
            calls: Arc::new(Mutex::new(Vec::new())),
        };
        let mut runtime = ListenerRuntime::new(opener.clone());
        runtime.add_listener(listener).unwrap();
        let (shutdown, signal) = oneshot::channel();
        let task = tokio::spawn(runtime.run_until_shutdown(async move {
            let _ = signal.await;
        }));
        Self {
            address,
            opener,
            shutdown: Some(shutdown),
            task: Task(Some(task)),
        }
    }

    async fn stop(mut self) {
        self.shutdown.take().unwrap().send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(3), self.task.0.take().unwrap())
            .await
            .expect("bounded proxy shutdown")
            .expect("proxy task")
            .expect("proxy runtime");
    }
}

#[derive(Debug)]
struct CapturedRequest {
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
}

struct Origin {
    address: SocketAddr,
    requests: mpsc::UnboundedReceiver<CapturedRequest>,
    chunks: mpsc::UnboundedReceiver<Bytes>,
    _task: Task<()>,
}

impl Origin {
    async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (requests_tx, requests) = mpsc::unbounded_channel();
        let (chunks_tx, chunks) = mpsc::unbounded_channel();
        let task = tokio::spawn(async move {
            let mut connections = JoinSet::new();
            loop {
                tokio::select! {
                    accepted = listener.accept() => {
                        let (stream, _) = accepted.unwrap();
                        let requests = requests_tx.clone();
                        let chunks = chunks_tx.clone();
                        connections.spawn(async move {
                            let service = service_fn(move |request: Request<Incoming>| {
                                let requests = requests.clone();
                                let chunks = chunks.clone();
                                async move {
                                    let (parts, mut body) = request.into_parts();
                                    let mut bytes = Vec::new();
                                    while let Some(frame) = body.frame().await {
                                        if let Ok(data) = frame.unwrap().into_data() {
                                            let _ = chunks.send(data.clone());
                                            bytes.extend_from_slice(&data);
                                        }
                                    }
                                    requests.send(CapturedRequest {
                                        method: parts.method,
                                        uri: parts.uri,
                                        headers: parts.headers,
                                        body: Bytes::from(bytes),
                                    }).unwrap();
                                    let mut response = Response::new(Full::new(Bytes::from_static(b"origin-response")));
                                    response.headers_mut().insert("connection", HeaderValue::from_static("x-response-hop"));
                                    response.headers_mut().insert("x-response-hop", HeaderValue::from_static("remove-me"));
                                    response.headers_mut().insert("proxy-connection", HeaderValue::from_static("keep-alive"));
                                    Ok::<_, Infallible>(response)
                                }
                            });
                            let _ = hyper::server::conn::http1::Builder::new()
                                .serve_connection(TokioIo::new(stream), service)
                                .await;
                        });
                    }
                    joined = connections.join_next(), if !connections.is_empty() => {
                        joined.unwrap().unwrap();
                    }
                }
            }
        });
        Self {
            address,
            requests,
            chunks,
            _task: Task(Some(task)),
        }
    }

    fn url(&self, path: &str) -> String {
        format!("http://origin.test:{}{path}", self.address.port())
    }
}

struct Client {
    sender: hyper::client::conn::http1::SendRequest<Full<Bytes>>,
    _task: Task<Result<(), hyper::Error>>,
}

impl Client {
    async fn connect(proxy: SocketAddr) -> Self {
        let socket = TcpStream::connect(proxy).await.unwrap();
        let (sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(socket))
            .await
            .unwrap();
        Self {
            sender,
            _task: Task(Some(tokio::spawn(connection))),
        }
    }

    async fn request(
        &mut self,
        method: Method,
        url: &str,
        headers: &[(&str, &str)],
        body: &'static [u8],
    ) -> (StatusCode, HeaderMap, Bytes) {
        let mut request = Request::builder()
            .method(method)
            .uri(url)
            .header("host", "wrong-host.invalid")
            .body(Full::new(Bytes::from_static(body)))
            .unwrap();
        for (name, value) in headers {
            request.headers_mut().insert(
                hyper::header::HeaderName::from_bytes(name.as_bytes()).unwrap(),
                HeaderValue::from_str(value).unwrap(),
            );
        }
        let response = self.sender.send_request(request).await.unwrap();
        let (parts, body) = response.into_parts();
        let body = body.collect().await.unwrap().to_bytes();
        (parts.status, parts.headers, body)
    }
}

async fn bounded(future: impl Future<Output = ()>) {
    tokio::time::timeout(Duration::from_secs(15), future)
        .await
        .expect("bounded HTTP proxy test");
}

async fn raw_origin<F, Fut>(handler: F) -> (SocketAddr, Task<()>)
where
    F: FnOnce(BufReader<TcpStream>) -> Fut + Send + 'static,
    Fut: Future<Output = ()> + Send,
{
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        handler(BufReader::new(stream)).await;
    });
    (address, Task(Some(task)))
}

async fn read_head(stream: &mut BufReader<TcpStream>) -> String {
    let mut head = String::new();
    loop {
        let mut line = String::new();
        let length = stream.read_line(&mut line).await.unwrap();
        assert_ne!(length, 0, "complete HTTP header block: {head:?}");
        assert!(head.len() + length < 64 * 1024, "bounded response headers");
        head.push_str(&line);
        if line == "\r\n" {
            return head;
        }
    }
}

async fn read_response(stream: &mut BufReader<TcpStream>) -> (String, Vec<u8>) {
    let head = read_head(stream).await;
    let content_length = head.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.eq_ignore_ascii_case("content-length")
            .then(|| value.trim().parse::<usize>().unwrap())
    });
    let mut body = Vec::new();
    if let Some(length) = content_length {
        assert!(length < 64 * 1024, "bounded test response body");
        body.resize(length, 0);
        stream.read_exact(&mut body).await.unwrap();
    } else {
        assert!(
            head.to_ascii_lowercase()
                .contains("transfer-encoding: chunked")
        );
        (body, _) = read_chunked(stream).await;
    }
    (head, body)
}

async fn read_chunked(stream: &mut BufReader<TcpStream>) -> (Vec<u8>, HeaderMap) {
    let mut body = Vec::new();
    loop {
        let mut line = String::new();
        stream.read_line(&mut line).await.unwrap();
        let length = usize::from_str_radix(line.trim().split(';').next().unwrap(), 16).unwrap();
        if length == 0 {
            let mut trailers = HeaderMap::new();
            let mut trailer_bytes = 0;
            loop {
                line.clear();
                let length = stream.read_line(&mut line).await.unwrap();
                assert!(length > 0, "complete trailer block");
                trailer_bytes += length;
                assert!(trailer_bytes < 16 * 1024, "bounded test trailer block");
                if line == "\r\n" {
                    return (body, trailers);
                }
                let (name, value) = line.trim_end().split_once(':').unwrap();
                trailers.append(
                    hyper::header::HeaderName::from_bytes(name.as_bytes()).unwrap(),
                    HeaderValue::from_str(value.trim()).unwrap(),
                );
            }
        }
        assert!(body.len() + length < 64 * 1024, "bounded test body");
        let start = body.len();
        body.resize(start + length, 0);
        stream.read_exact(&mut body[start..]).await.unwrap();
        let mut terminator = [0; 2];
        stream.read_exact(&mut terminator).await.unwrap();
        assert_eq!(terminator, *b"\r\n");
    }
}

fn declared_trailers(head: &str) -> BTreeSet<String> {
    head.lines()
        .filter_map(|line| line.split_once(':'))
        .filter(|(name, _)| name.eq_ignore_ascii_case("trailer"))
        .flat_map(|(_, value)| value.split(','))
        .map(|name| name.trim().to_ascii_lowercase())
        .collect()
}

#[tokio::test]
async fn rewrites_absolute_requests_and_strips_proxy_and_hop_headers() {
    bounded(async {
        let mut origin = Origin::start().await;
        let proxy = Proxy::start(false, Route::Direct).await;
        let mut client = Client::connect(proxy.address).await;
        let (status, headers, body) = client
            .request(
                Method::GET,
                &origin.url("/resource?value=1"),
                &[
                    ("proxy-authorization", AUTHORIZATION),
                    ("proxy-connection", "keep-alive"),
                    ("connection", "x-request-hop, keep-alive"),
                    ("x-request-hop", "remove-me"),
                    ("authorization", "Bearer origin-token"),
                    ("x-forwarded-for", "203.0.113.1"),
                ],
                b"",
            )
            .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, "origin-response");
        assert!(!headers.contains_key("x-response-hop"));
        assert!(!headers.contains_key("proxy-connection"));
        let request = origin.requests.recv().await.unwrap();
        assert_eq!(request.method, Method::GET);
        assert_eq!(request.uri.to_string(), "/resource?value=1");
        assert_eq!(
            request.headers["host"],
            format!("origin.test:{}", origin.address.port())
        );
        assert!(!request.headers.contains_key("proxy-authorization"));
        assert!(!request.headers.contains_key("proxy-connection"));
        assert!(!request.headers.contains_key("x-request-hop"));
        assert_eq!(request.headers["authorization"], "Bearer origin-token");
        {
            let calls = proxy.opener.calls.lock().unwrap();
            assert_eq!(calls.len(), 1);
            assert_eq!(
                calls[0].target.host,
                TargetHost::Hostname("origin.test".into())
            );
            assert_eq!(
                calls[0].source.ip(),
                "127.0.0.1".parse::<std::net::IpAddr>().unwrap()
            );
        }
        drop(client);
        proxy.stop().await;
    })
    .await;
}

#[tokio::test]
async fn forwards_post_bodies_without_buffering_the_complete_chunked_upload() {
    bounded(async {
        let mut origin = Origin::start().await;
        let proxy = Proxy::start(false, Route::Direct).await;
        let mut client = BufReader::new(TcpStream::connect(proxy.address).await.unwrap());
        client
            .get_mut()
            .write_all(
                format!(
                    "POST {} HTTP/1.1\r\nHost: wrong-host.invalid\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n5\r\nfirst\r\n",
                    origin.url("/upload")
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        // The origin must receive data before the client finishes its body.
        assert_eq!(origin.chunks.recv().await.unwrap(), "first");
        client
            .get_mut()
            .write_all(b"6\r\nsecond\r\n0\r\n\r\n")
            .await
            .unwrap();
        let response = read_head(&mut client).await;
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
        let request = origin.requests.recv().await.unwrap();
        assert_eq!(request.method, Method::POST);
        assert_eq!(request.uri.to_string(), "/upload");
        assert_eq!(request.body, "firstsecond");
        drop(client);
        proxy.stop().await;
    })
    .await;
}

#[tokio::test]
async fn reroutes_and_authenticates_every_request_on_a_persistent_connection() {
    bounded(async {
        let mut first = Origin::start().await;
        let mut second = Origin::start().await;
        let proxy = Proxy::start(true, Route::Direct).await;
        let mut client = Client::connect(proxy.address).await;
        for origin in [&mut first, &mut second] {
            let (status, _, _) = client
                .request(
                    Method::GET,
                    &origin.url("/keep-alive"),
                    &[
                        ("proxy-authorization", AUTHORIZATION),
                        ("proxy-connection", "keep-alive"),
                    ],
                    b"",
                )
                .await;
            assert_eq!(status, StatusCode::OK);
            assert!(
                !origin
                    .requests
                    .recv()
                    .await
                    .unwrap()
                    .headers
                    .contains_key("proxy-authorization")
            );
        }
        let (status, headers, _) = client
            .request(Method::GET, &second.url("/missing-credentials"), &[], b"")
            .await;
        assert_eq!(status, StatusCode::PROXY_AUTHENTICATION_REQUIRED);
        assert!(headers.contains_key("proxy-authenticate"));
        {
            let calls = proxy.opener.calls.lock().unwrap();
            assert_eq!(
                calls.len(),
                2,
                "unauthenticated requests must not open a route"
            );
            assert_eq!(calls[0].target.port, first.address.port());
            assert_eq!(calls[1].target.port, second.address.port());
            assert!(
                calls
                    .iter()
                    .all(|context| context.authentication_identity.as_deref() == Some("alice"))
            );
        }
        drop(client);
        proxy.stop().await;
    })
    .await;
}

#[tokio::test]
async fn rejects_malformed_targets_framing_and_oversized_headers_before_dialing() {
    bounded(async {
        let proxy = Proxy::start(false, Route::Direct).await;
        let requests = [
            "GET /origin-form HTTP/1.1\r\nHost: origin.test\r\n\r\n".to_owned(),
            "GET https://origin.test/ HTTP/1.1\r\nHost: origin.test\r\n\r\n".to_owned(),
            "GET http://user:password@origin.test/ HTTP/1.1\r\nHost: origin.test\r\n\r\n".to_owned(),
            "POST http://origin.test/ HTTP/1.1\r\nHost: origin.test\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\nxx".to_owned(),
            format!("GET http://origin.test/ HTTP/1.1\r\nHost: origin.test\r\nX-Large: {}\r\n\r\n", "x".repeat(17 * 1024)),
        ];
        for request in requests {
            let mut client = BufReader::new(TcpStream::connect(proxy.address).await.unwrap());
            client.get_mut().write_all(request.as_bytes()).await.unwrap();
            let response = read_head(&mut client).await;
            assert!(
                response.starts_with("HTTP/1.1 400") || response.starts_with("HTTP/1.1 431"),
                "{response}"
            );
        }
        assert!(proxy.opener.calls.lock().unwrap().is_empty());
        proxy.stop().await;
    })
    .await;
}

#[tokio::test]
async fn normalized_then_closes_ambiguous_framing() {
    bounded(async {
        let mut first = Origin::start().await;
        let mut second = Origin::start().await;
        let proxy = Proxy::start(false, Route::Direct).await;
        let mut client = BufReader::new(TcpStream::connect(proxy.address).await.unwrap());
        client.get_mut().write_all(format!(
            "POST {} HTTP/1.1\r\nHost: origin.test\r\nContent-Length: 999\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nfirst\r\n0\r\n\r\nGET {} HTTP/1.1\r\nHost: origin.test\r\nConnection: close\r\n\r\n",
            first.url("/chunked"), second.url("/next-target")
        ).as_bytes()).await.unwrap();
        let (head, body) = read_response(&mut client).await;
        assert!(head.starts_with("HTTP/1.1 200"), "{head}");
        assert_eq!(body, b"origin-response");
        let mut remaining = Vec::new();
        client.read_to_end(&mut remaining).await.unwrap();
        assert!(remaining.is_empty(), "ambiguous framing must close the connection");
        let request = first.requests.recv().await.unwrap();
        assert_eq!(request.uri.to_string(), "/chunked");
        assert_eq!(request.body, "first");
        assert!(!(request.headers.contains_key("content-length")
            && request.headers.contains_key("transfer-encoding")));
        if let Some(length) = request.headers.get("content-length") {
            assert_eq!(length, "5");
        }
        assert!(matches!(second.requests.try_recv(), Err(mpsc::error::TryRecvError::Empty)));
        {
            let calls = proxy.opener.calls.lock().unwrap();
            assert_eq!(calls.len(), 1, "no later request may open a route after ambiguous framing");
            assert_eq!(calls[0].target.port, first.address.port());
        }
        drop(client);
        proxy.stop().await;
    })
    .await;
}

#[tokio::test]
async fn maps_route_failures_to_http_errors_without_exposing_private_details() {
    bounded(async {
        for (route, expected) in [
            (Route::Denied, StatusCode::FORBIDDEN),
            (Route::Unavailable, StatusCode::SERVICE_UNAVAILABLE),
            (Route::Failed, StatusCode::BAD_GATEWAY),
        ] {
            let proxy = Proxy::start(false, route).await;
            let mut client = Client::connect(proxy.address).await;
            let (status, _, body) = client
                .request(Method::GET, "http://origin.test/unavailable", &[], b"")
                .await;
            assert_eq!(status, expected);
            assert!(!String::from_utf8_lossy(&body).contains("private-upstream-detail"));
            assert_eq!(proxy.opener.calls.lock().unwrap().len(), 1);
            drop(client);
            proxy.stop().await;
        }
    })
    .await;
}

#[tokio::test]
async fn returns_redirects_without_following_them() {
    bounded(async {
        let mut destination = Origin::start().await;
        let location = destination.url("/must-not-follow");
        let response = format!(
            "HTTP/1.1 302 Found\r\nLocation: {location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        );
        let (address, mut origin) = raw_origin(move |mut stream| async move {
            assert!(read_head(&mut stream).await.starts_with("GET /redirect HTTP/1.1\r\n"));
            stream.get_mut().write_all(response.as_bytes()).await.unwrap();
            stream.get_mut().shutdown().await.unwrap();
        }).await;
        let proxy = Proxy::start(false, Route::Direct).await;
        let mut client = Client::connect(proxy.address).await;
        let (status, headers, body) = client.request(
            Method::GET, &format!("http://origin.test:{}/redirect", address.port()), &[], b""
        ).await;
        assert_eq!(status, StatusCode::FOUND);
        assert_eq!(headers["location"], location);
        assert!(body.is_empty());
        assert!(matches!(destination.requests.try_recv(), Err(mpsc::error::TryRecvError::Empty)));
        assert_eq!(proxy.opener.calls.lock().unwrap().len(), 1);
        drop(client);
        origin.0.take().unwrap().await.unwrap();
        proxy.stop().await;
    }).await;
}

#[tokio::test]
async fn early_responses_never_treat_unread_upload_bytes_as_another_request() {
    bounded(async {
        let mut trap = Origin::start().await;
        let mut next = Origin::start().await;
        let body = format!(
            "GET {} HTTP/1.1\r\nHost: origin.test\r\n\r\n", trap.url("/body-is-not-a-request")
        );
        let (address, mut origin) = raw_origin(|mut stream| async move {
            assert!(read_head(&mut stream).await.starts_with("POST /upload HTTP/1.1\r\n"));
            stream.get_mut().write_all(b"HTTP/1.1 413 Content Too Large\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await.unwrap();
            stream.get_mut().shutdown().await.unwrap();
        }).await;
        let proxy = Proxy::start(false, Route::Direct).await;
        let mut client = BufReader::new(TcpStream::connect(proxy.address).await.unwrap());
        client.get_mut().write_all(format!(
            "POST http://origin.test:{}/upload HTTP/1.1\r\nHost: origin.test\r\nContent-Length: {}\r\n\r\nstart", address.port(), body.len() + 5
        ).as_bytes()).await.unwrap();
        // A response before the rest of the upload proves that the body is streaming.
        let (head, response_body) = read_response(&mut client).await;
        assert!(head.starts_with("HTTP/1.1 413"), "{head}");
        assert!(response_body.is_empty());
        let rest = format!(
            "{body}GET {} HTTP/1.1\r\nHost: origin.test\r\nConnection: close\r\n\r\n", next.url("/after-upload")
        );
        let continued = match client.get_mut().write_all(rest.as_bytes()).await {
            Ok(()) => match client.fill_buf().await {
                Ok(bytes) => !bytes.is_empty(),
                Err(error) => {
                    assert!(matches!(error.kind(), std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::ConnectionAborted));
                    false
                }
            },
            Err(error) => {
                assert!(matches!(error.kind(), std::io::ErrorKind::BrokenPipe | std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::ConnectionAborted));
                false
            }
        };
        if continued {
            let (head, _) = read_response(&mut client).await;
            assert!(head.starts_with("HTTP/1.1 200"), "{head}");
            let request = next.requests.recv().await.unwrap();
            assert_eq!(request.uri.to_string(), "/after-upload");
            assert!(request.body.is_empty());
        }
        assert!(matches!(trap.requests.try_recv(), Err(mpsc::error::TryRecvError::Empty)));
        {
            let calls = proxy.opener.calls.lock().unwrap();
            assert_eq!(calls.len(), if continued { 2 } else { 1 });
            assert!(calls.iter().all(|context| context.target.port != trap.address.port()));
        }
        drop(client);
        origin.0.take().unwrap().await.unwrap();
        proxy.stop().await;
    }).await;
}

#[tokio::test]
async fn shutdown_closes_an_upstream_with_an_unfinished_streaming_response() {
    bounded(async {
        let (closed_tx, closed_rx) = oneshot::channel();
        let (address, mut origin) = raw_origin(move |mut stream| async move {
            read_head(&mut stream).await;
            stream
                .get_mut()
                .write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n")
                .await
                .unwrap();
            let mut byte = [0; 1];
            closed_tx
                .send(stream.read(&mut byte).await.unwrap() == 0)
                .unwrap();
        })
        .await;
        let proxy = Proxy::start(false, Route::Direct).await;
        let mut client = BufReader::new(TcpStream::connect(proxy.address).await.unwrap());
        client
            .get_mut()
            .write_all(
                format!(
                    "GET http://origin.test:{}/stream HTTP/1.1\r\nHost: origin.test\r\n\r\n",
                    address.port()
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        let head = read_head(&mut client).await;
        assert!(head.starts_with("HTTP/1.1 200"), "{head}");
        let mut body = Vec::new();
        while body.len() < 5 {
            let mut size = String::new();
            client.read_line(&mut size).await.unwrap();
            let length = usize::from_str_radix(size.trim(), 16).unwrap();
            assert!(length > 0 && body.len() + length <= 5);
            let start = body.len();
            body.resize(start + length, 0);
            client.read_exact(&mut body[start..]).await.unwrap();
            let mut terminator = [0; 2];
            client.read_exact(&mut terminator).await.unwrap();
            assert_eq!(terminator, *b"\r\n");
        }
        assert_eq!(body, b"hello");
        // Keep the client and incomplete response alive while stopping the owner.
        proxy.stop().await;
        assert!(
            tokio::time::timeout(Duration::from_secs(2), closed_rx)
                .await
                .expect("upstream closed after shutdown")
                .unwrap()
        );
        origin.0.take().unwrap().await.unwrap();
        drop(client);
    })
    .await;
}

#[tokio::test]
async fn preserves_safe_trailers_and_filters_proxy_metadata_in_both_directions() {
    bounded(async {
        let (captured_tx, captured_rx) = oneshot::channel();
        let (address, mut origin) = raw_origin(move |mut stream| async move {
            let head = read_head(&mut stream).await;
            let (body, trailers) = read_chunked(&mut stream).await;
            captured_tx.send((head, body, trailers)).unwrap();
            stream.get_mut().write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: x-response-private\r\nTrailer: Digest, X-Checksum, Proxy-Authorization, Proxy-Authenticate, X-Response-Private\r\n\r\n4\r\ndone\r\n0\r\nDigest: sha-256=response-digest\r\nX-Checksum: response-checksum\r\nProxy-Authorization: Basic response-proxy-secret\r\nProxy-Authenticate: Basic realm=private\r\nX-Response-Private: remove-me\r\n\r\n").await.unwrap();
            stream.get_mut().shutdown().await.unwrap();
        }).await;
        let proxy = Proxy::start(true, Route::Direct).await;
        let mut client = BufReader::new(TcpStream::connect(proxy.address).await.unwrap());
        client.get_mut().write_all(format!(
            "POST http://origin.test:{}/trailers HTTP/1.1\r\nHost: origin.test\r\nProxy-Authorization: {AUTHORIZATION}\r\nTransfer-Encoding: chunked\r\nConnection: te, x-request-private\r\nTE: trailers\r\nTrailer: Digest, X-Checksum, Proxy-Authorization, X-Request-Private\r\n\r\n4\r\ndata\r\n0\r\nDigest: sha-256=request-digest\r\nX-Checksum: request-checksum\r\nProxy-Authorization: Basic request-proxy-secret\r\nX-Request-Private: remove-me\r\n\r\n", address.port()
        ).as_bytes()).await.unwrap();
        let head = read_head(&mut client).await;
        assert!(head.starts_with("HTTP/1.1 200"), "{head}");
        let (body, trailers) = read_chunked(&mut client).await;
        assert_eq!(body, b"done");
        assert_eq!(trailers["digest"], "sha-256=response-digest");
        assert_eq!(trailers["x-checksum"], "response-checksum");
        assert!(!trailers.contains_key("proxy-authorization"));
        assert!(!trailers.contains_key("proxy-authenticate"));
        assert!(!trailers.contains_key("x-response-private"));
        let allowed = BTreeSet::from(["digest".to_owned(), "x-checksum".to_owned()]);
        assert_eq!(declared_trailers(&head), allowed);
        let (head, body, trailers) = captured_rx.await.unwrap();
        assert!(head.starts_with("POST /trailers HTTP/1.1\r\n"), "{head}");
        assert_eq!(body, b"data");
        assert_eq!(trailers["digest"], "sha-256=request-digest");
        assert_eq!(trailers["x-checksum"], "request-checksum");
        assert!(!trailers.contains_key("proxy-authorization"));
        assert!(!trailers.contains_key("x-request-private"));
        assert_eq!(declared_trailers(&head), allowed);
        assert!(!head.to_ascii_lowercase().contains("proxy-authorization"));
        drop(client);
        origin.0.take().unwrap().await.unwrap();
        proxy.stop().await;
    }).await;
}

#[tokio::test]
async fn upgrades_after_the_origin_response_without_forwarding_proxy_credentials() {
    bounded(async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (captured_tx, captured_rx) = oneshot::channel();
        let (upgrade_tx, upgrade_rx) = oneshot::channel();
        let mut origin = Task(Some(tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut stream = BufReader::new(stream);
            let head = read_head(&mut stream).await;
            captured_tx.send(head).unwrap();
            upgrade_rx.await.unwrap();
            stream.get_mut().write_all(b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\nserver-data").await.unwrap();
            let mut payload = [0; 11];
            stream.read_exact(&mut payload).await.unwrap();
            assert_eq!(&payload, b"client-data");
            stream.get_mut().write_all(&payload).await.unwrap();
        })));
        let proxy = Proxy::start(true, Route::Direct).await;
        let mut client = BufReader::new(TcpStream::connect(proxy.address).await.unwrap());
        client.get_mut().write_all(format!(
            "GET http://origin.test:{}/socket HTTP/1.1\r\nHost: wrong-host.invalid\r\nProxy-Authorization: {AUTHORIZATION}\r\nConnection: Upgrade, x-private-hop\r\nUpgrade: websocket, h2c\r\nX-Private-Hop: remove-me\r\n\r\n", address.port()
        ).as_bytes()).await.unwrap();
        let head = captured_rx.await.unwrap().to_ascii_lowercase();
        assert!(head.starts_with("get /socket http/1.1\r\n"));
        let offered = head.lines().find_map(|line| line.strip_prefix("upgrade:")).unwrap();
        assert_eq!(offered.split(',').map(str::trim).collect::<Vec<_>>(), ["websocket", "h2c"]);
        assert!(!head.contains("proxy-authorization"));
        assert!(!head.contains("x-private-hop"));
        assert!(tokio::time::timeout(Duration::from_millis(50), client.read_u8()).await.is_err(), "the proxy must wait for the origin's switching response");
        upgrade_tx.send(()).unwrap();
        let response = read_head(&mut client).await;
        assert!(response.starts_with("HTTP/1.1 101"), "{response}");
        let mut server_data = [0; 11];
        client.read_exact(&mut server_data).await.unwrap();
        assert_eq!(&server_data, b"server-data");
        client.get_mut().write_all(b"client-data").await.unwrap();
        client.read_exact(&mut server_data).await.unwrap();
        assert_eq!(&server_data, b"client-data");
        drop(client);
        origin.0.take().unwrap().await.unwrap();
        proxy.stop().await;
    })
    .await;
}
