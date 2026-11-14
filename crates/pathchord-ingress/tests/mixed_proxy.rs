use std::collections::BTreeSet;
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use pathchord_ingress::{
    BoxedLocalConnection, BoxedUdpFlowHandle, ConnectionContext, FlowBridgeError,
    IngressPlatformConfig, IngressPlatformError, IngressPlatformFactories, IngressPlatformReport,
    IngressPlatformRuntime, ListenerCredentialError, ListenerCredentialVerifier,
    ListenerCredentialVerifierFactory, ProtectedEndpointSet, StaticListenerCredentialVerifier,
    TargetHost, TcpFlowOpener, UdpFlowError, UdpFlowHandle, UdpFlowOpener,
};
use pathchord_policy::{
    AuthenticationMode, Endpoint, FlowProtocol, ListenerConfig, ListenerId, ListenerKind,
    ProcessMetadataRequest,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::oneshot;
use tokio::task::{JoinHandle, JoinSet};

const BASIC_CREDENTIALS: &str = "Basic YWxpY2U6c2VjcmV0";

struct Task<T>(Option<JoinHandle<T>>);

impl<T> Drop for Task<T> {
    fn drop(&mut self) {
        if let Some(task) = self.0.take() {
            task.abort();
        }
    }
}

async fn bounded(task: impl Future<Output = ()>) {
    tokio::time::timeout(Duration::from_secs(10), task)
        .await
        .expect("bounded mixed listener test");
}

#[derive(Debug, Default)]
struct DirectOpener {
    calls: Mutex<Vec<ConnectionContext>>,
}

fn target_address(context: &ConnectionContext) -> SocketAddr {
    let address = match &context.target.host {
        TargetHost::Ip(address) => *address,
        TargetHost::Hostname(host) => {
            assert_eq!(
                host, "example.test",
                "only local test hostnames are resolved"
            );
            IpAddr::V4(Ipv4Addr::LOCALHOST)
        }
    };
    SocketAddr::new(address, context.target.port)
}

#[async_trait]
impl TcpFlowOpener for DirectOpener {
    async fn connect(
        &self,
        context: ConnectionContext,
    ) -> Result<BoxedLocalConnection, FlowBridgeError> {
        let target = target_address(&context);
        self.calls.lock().unwrap().push(context);
        TcpStream::connect(target)
            .await
            .map(|stream| Box::new(stream) as BoxedLocalConnection)
            .map_err(|error| FlowBridgeError::Dial(error.to_string()))
    }
}

#[derive(Debug)]
struct DirectUdp(UdpSocket);

#[async_trait]
impl UdpFlowHandle for DirectUdp {
    async fn send(&mut self, payload: Vec<u8>) -> Result<(), UdpFlowError> {
        self.0
            .send(&payload)
            .await
            .map(|_| ())
            .map_err(|error| UdpFlowError::Task(error.to_string()))
    }

    async fn receive(&mut self) -> Option<Vec<u8>> {
        let mut payload = vec![0; 65_535];
        let length = self.0.recv(&mut payload).await.ok()?;
        payload.truncate(length);
        Some(payload)
    }

    async fn close(self: Box<Self>) -> Result<(), UdpFlowError> {
        Ok(())
    }
}

#[async_trait]
impl UdpFlowOpener for DirectOpener {
    async fn open_udp(
        &self,
        context: &ConnectionContext,
    ) -> Result<BoxedUdpFlowHandle, UdpFlowError> {
        self.calls.lock().unwrap().push(context.clone());
        let socket = UdpSocket::bind("127.0.0.1:0")
            .await
            .map_err(|error| UdpFlowError::Open(error.to_string()))?;
        socket
            .connect(target_address(context))
            .await
            .map_err(|error| UdpFlowError::Open(error.to_string()))?;
        Ok(Box::new(DirectUdp(socket)))
    }
}

#[derive(Debug)]
struct Credentials;

#[async_trait]
impl ListenerCredentialVerifierFactory for Credentials {
    async fn verifier_for(
        &self,
        _listener: &ListenerConfig,
    ) -> Result<Arc<dyn ListenerCredentialVerifier>, ListenerCredentialError> {
        Ok(Arc::new(StaticListenerCredentialVerifier::new(
            "alice", "secret",
        )))
    }
}

struct Proxy {
    address: SocketAddr,
    opener: Arc<DirectOpener>,
    stop: Option<oneshot::Sender<()>>,
    task: Task<Result<IngressPlatformReport, IngressPlatformError>>,
}

impl Proxy {
    async fn start(authentication_required: bool, allowed_sources: &[&str]) -> Self {
        let listener = ListenerConfig {
            id: ListenerId::new("mixed"),
            kind: ListenerKind::Mixed,
            platform: std::env::consts::OS.to_owned(),
            bind: Some(Endpoint {
                host: "127.0.0.1".to_owned(),
                port: 0,
            }),
            allowed_sources: allowed_sources
                .iter()
                .map(|value| (*value).to_owned())
                .collect(),
            authentication: if authentication_required {
                AuthenticationMode::Required
            } else {
                AuthenticationMode::Disabled
            },
            backend: Default::default(),
            credentials_ref: authentication_required.then(|| "mixed-users".to_owned()),
            mark: None,
            route_table: None,
            protocols: BTreeSet::from([FlowProtocol::Tcp, FlowProtocol::Udp]),
            interface: None,
            address: None,
            mtu: None,
            bypass: Vec::new(),
            proxy_ref: None,
            flow_tags: BTreeSet::from(["mixed-flow".to_owned()]),
            process_metadata: ProcessMetadataRequest::default(),
        };
        let opener = Arc::new(DirectOpener::default());
        let mut config = IngressPlatformConfig::new(std::env::temp_dir());
        config.listener_runtime.max_connections = 16;
        config.shutdown_timeout = Duration::from_secs(1);
        let runtime = IngressPlatformRuntime::bind_with_factories(
            config,
            &[listener],
            opener.clone(),
            opener.clone(),
            ProtectedEndpointSet::default(),
            IngressPlatformFactories {
                listener_credentials: Arc::new(Credentials),
                ..IngressPlatformFactories::default()
            },
        )
        .await
        .expect("bind one mixed listener");
        assert_eq!(runtime.listener_inventory().len(), 1);
        assert_eq!(
            runtime.listener_inventory()[0].kind,
            pathchord_ingress::ListenerKind::Mixed
        );
        let addresses = runtime.listener_addresses().unwrap();
        assert_eq!(addresses.len(), 1, "all protocols share one TCP listener");
        let address = addresses[&ListenerId::new("mixed")];
        let (stop, signal) = oneshot::channel();
        let task = tokio::spawn(runtime.run_until_shutdown(async move {
            let _ = signal.await;
        }));
        Self {
            address,
            opener,
            stop: Some(stop),
            task: Task(Some(task)),
        }
    }

    async fn stop(mut self) -> IngressPlatformReport {
        self.stop.take().unwrap().send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(3), self.task.0.take().unwrap())
            .await
            .expect("bounded mixed shutdown")
            .expect("mixed owner task")
            .expect("mixed runtime shutdown")
    }
}

async fn echo_target() -> (SocketAddr, Task<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let mut connections = JoinSet::new();
        loop {
            tokio::select! {
                accepted = listener.accept() => {
                    let (mut stream, _) = accepted.unwrap();
                    connections.spawn(async move {
                        let (mut input, mut output) = stream.split();
                        let _ = tokio::io::copy(&mut input, &mut output).await;
                    });
                }
                _ = connections.join_next(), if !connections.is_empty() => {}
            }
        }
    });
    (address, Task(Some(task)))
}

fn ipv4_target(target: SocketAddr) -> [u8; 6] {
    let SocketAddr::V4(target) = target else {
        panic!("IPv4 test target");
    };
    let [a, b, c, d] = target.ip().octets();
    let [high, low] = target.port().to_be_bytes();
    [a, b, c, d, high, low]
}

async fn read_head(stream: &mut TcpStream) -> Vec<u8> {
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        assert!(head.len() < 16 * 1024, "bounded HTTP response header");
        head.push(
            stream
                .read_u8()
                .await
                .expect("complete HTTP response header"),
        );
    }
    head
}

async fn expect_echo(mut client: TcpStream, payload: &[u8]) {
    client.shutdown().await.unwrap();
    let mut response = Vec::new();
    client.read_to_end(&mut response).await.unwrap();
    assert_eq!(response, payload);
}

async fn http_connect(proxy: SocketAddr, target: SocketAddr, authenticated: bool) -> TcpStream {
    let mut client = TcpStream::connect(proxy).await.unwrap();
    let authentication = if authenticated {
        format!("Proxy-Authorization: {BASIC_CREDENTIALS}\r\n")
    } else {
        String::new()
    };
    client
        .write_all(
            format!(
                "CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n{authentication}\r\nconnect-payload"
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    assert!(read_head(&mut client).await.starts_with(b"HTTP/1.1 200"));
    client
}

async fn socks5_command(
    proxy: SocketAddr,
    target: SocketAddr,
    command: u8,
    authenticated: bool,
    payload: &[u8],
) -> (TcpStream, SocketAddr) {
    let mut client = TcpStream::connect(proxy).await.unwrap();
    if authenticated {
        client.write_all(&[5, 2, 0, 2]).await.unwrap();
        let mut method = [0; 2];
        client.read_exact(&mut method).await.unwrap();
        assert_eq!(method, [5, 2]);
        client.write_all(b"\x01\x05alice\x06secret").await.unwrap();
        let mut auth = [0; 2];
        client.read_exact(&mut auth).await.unwrap();
        assert_eq!(auth, [1, 0]);
    }
    let mut request = if authenticated {
        Vec::new()
    } else {
        vec![5, 1, 0]
    };
    request.extend_from_slice(&[5, command, 0, 1]);
    request.extend_from_slice(&ipv4_target(target));
    request.extend_from_slice(payload);
    client.write_all(&request).await.unwrap();
    if !authenticated {
        let mut method = [0; 2];
        client.read_exact(&mut method).await.unwrap();
        assert_eq!(method, [5, 0]);
    }
    let mut response = [0; 10];
    client.read_exact(&mut response).await.unwrap();
    assert_eq!(&response[..4], &[5, 0, 0, 1]);
    let bound = SocketAddr::from((
        [response[4], response[5], response[6], response[7]],
        u16::from_be_bytes([response[8], response[9]]),
    ));
    (client, bound)
}

fn socks4_request(target: SocketAddr, hostname: bool) -> Vec<u8> {
    let mut request = vec![4, 1];
    request.extend_from_slice(&target.port().to_be_bytes());
    request.extend_from_slice(if hostname {
        &[0, 0, 0, 1]
    } else {
        &[127, 0, 0, 1]
    });
    request.extend_from_slice(b"unverified-user\0");
    if hostname {
        request.extend_from_slice(b"example.test\0");
    }
    request
}

#[tokio::test]
async fn one_mixed_port_forwards_http_connect_and_all_socks_versions() {
    bounded(async {
        let proxy = Proxy::start(false, &["127.0.0.1/32"]).await;
        let (target, _echo) = echo_target().await;
        let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin_address = origin.local_addr().unwrap();
        let origin_task = tokio::spawn(async move {
            let (mut stream, _) = origin.accept().await.unwrap();
            let head = read_head(&mut stream).await;
            assert!(head.starts_with(b"GET /ordinary?q=1 HTTP/1.1\r\n"));
            stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 13\r\nConnection: close\r\n\r\nordinary-http").await.unwrap();
        });
        let _origin = Task(Some(origin_task));
        let mut http = TcpStream::connect(proxy.address).await.unwrap();
        http.write_all(format!("GET http://{origin_address}/ordinary?q=1 HTTP/1.1\r\nHost: {origin_address}\r\nConnection: close\r\n\r\n").as_bytes()).await.unwrap();
        let mut response = Vec::new();
        http.read_to_end(&mut response).await.unwrap();
        assert!(response.starts_with(b"HTTP/1.1 200"));
        assert!(response.ends_with(b"ordinary-http"));

        expect_echo(http_connect(proxy.address, target, false).await, b"connect-payload").await;
        for hostname in [false, true] {
            let mut client = TcpStream::connect(proxy.address).await.unwrap();
            let mut request = socks4_request(target, hostname);
            request.extend_from_slice(b"socks4-payload");
            client.write_all(&request).await.unwrap();
            let mut response = [0; 8];
            client.read_exact(&mut response).await.unwrap();
            assert_eq!(response, [0, 90, 0, 0, 0, 0, 0, 0]);
            expect_echo(client, b"socks4-payload").await;
        }
        let (client, _) = socks5_command(proxy.address, target, 1, false, b"socks5-payload").await;
        expect_echo(client, b"socks5-payload").await;
        let calls = proxy.opener.calls.lock().unwrap().clone();
        assert_eq!(calls.len(), 5);
        assert!(calls.iter().all(|context| context.listener_id.as_str() == "mixed"
            && context.flow_tags.contains("mixed-flow") && context.authentication_identity.is_none()));
        assert!(calls.iter().any(|context| context.target.host == TargetHost::Hostname("example.test".to_owned())));
        proxy.stop().await;
    }).await;
}

#[tokio::test]
async fn mixed_udp_and_shutdown_work_while_idle_clients_remain_open() {
    bounded(async {
        let proxy = Proxy::start(false, &["127.0.0.1/32"]).await;
        let mut idle = TcpStream::connect(proxy.address).await.unwrap();
        let mut unknown = TcpStream::connect(proxy.address).await.unwrap();
        unknown.write_all(b"\x16\x03").await.unwrap();
        let target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let target_address = target.local_addr().unwrap();
        let _echo = Task(Some(tokio::spawn(async move {
            let mut payload = [0; 128];
            let (length, peer) = target.recv_from(&mut payload).await.unwrap();
            target.send_to(&payload[..length], peer).await.unwrap();
        })));
        let (mut control, relay) = tokio::time::timeout(
            Duration::from_secs(2),
            socks5_command(proxy.address, "0.0.0.0:0".parse().unwrap(), 3, false, &[]),
        )
        .await
        .expect("idle clients must not block protocol detection");
        let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut datagram = vec![0, 0, 0, 1];
        datagram.extend_from_slice(&ipv4_target(target_address));
        datagram.extend_from_slice(b"mixed-udp");
        udp.send_to(&datagram, relay).await.unwrap();
        let mut response = [0; 128];
        let (length, source) = udp.recv_from(&mut response).await.unwrap();
        assert_eq!(source, relay);
        assert_eq!(&response[..length], datagram);
        let report = proxy.stop().await;
        let report = &report.socks[&ListenerId::new("mixed")];
        assert_eq!(report.udp_associations, 1);
        assert_eq!(report.udp_datagrams_sent, 1);
        let mut byte = [0];
        assert_eq!(idle.read(&mut byte).await.unwrap(), 0);
        assert_eq!(control.read(&mut byte).await.unwrap(), 0);
    })
    .await;
}

#[tokio::test]
async fn mixed_authentication_is_shared_without_a_socks4_downgrade() {
    bounded(async {
        let proxy = Proxy::start(true, &["127.0.0.1/32"]).await;
        let (target, _echo) = echo_target().await;
        let mut http = TcpStream::connect(proxy.address).await.unwrap();
        http.write_all(format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n").as_bytes())
            .await
            .unwrap();
        assert!(read_head(&mut http).await.starts_with(b"HTTP/1.1 407"));
        let mut old = TcpStream::connect(proxy.address).await.unwrap();
        old.write_all(&socks4_request(target, false)).await.unwrap();
        let mut response = [0; 8];
        old.read_exact(&mut response).await.unwrap();
        assert_eq!(response, [0, 91, 0, 0, 0, 0, 0, 0]);
        let mut no_auth = TcpStream::connect(proxy.address).await.unwrap();
        no_auth.write_all(&[5, 1, 0]).await.unwrap();
        let mut method = [0; 2];
        no_auth.read_exact(&mut method).await.unwrap();
        assert_eq!(method, [5, 255]);
        assert!(proxy.opener.calls.lock().unwrap().is_empty());
        expect_echo(
            http_connect(proxy.address, target, true).await,
            b"connect-payload",
        )
        .await;
        let (client, _) =
            socks5_command(proxy.address, target, 1, true, b"authenticated-socks").await;
        expect_echo(client, b"authenticated-socks").await;
        let calls = proxy.opener.calls.lock().unwrap().clone();
        assert_eq!(calls.len(), 2);
        assert!(
            calls
                .iter()
                .all(|context| context.authentication_identity.as_deref() == Some("alice"))
        );
        proxy.stop().await;
    })
    .await;
}

#[tokio::test]
async fn mixed_source_and_protocol_rejections_never_open_targets() {
    bounded(async {
        let proxy = Proxy::start(false, &["192.0.2.0/24"]).await;
        for request in [
            &b"GET http://example.test/ HTTP/1.1\r\nHost: example.test\r\n\r\n"[..],
            &[5, 1, 0][..],
        ] {
            let mut client = TcpStream::connect(proxy.address).await.unwrap();
            let _ = client.write_all(request).await;
            let mut response = Vec::new();
            let _ = client.read_to_end(&mut response).await;
        }
        assert!(proxy.opener.calls.lock().unwrap().is_empty());
        proxy.stop().await;

        let proxy = Proxy::start(false, &["127.0.0.1/32"]).await;
        let mut http = TcpStream::connect(proxy.address).await.unwrap();
        http.write_all(b"GET /not-absolute HTTP/1.1\r\nHost: example.test\r\n\r\n")
            .await
            .unwrap();
        assert!(read_head(&mut http).await.starts_with(b"HTTP/1.1 400"));
        let mut socks = TcpStream::connect(proxy.address).await.unwrap();
        socks
            .write_all(&[5, 1, 0, 5, 2, 0, 1, 127, 0, 0, 1, 0, 80])
            .await
            .unwrap();
        let mut method = [0; 2];
        socks.read_exact(&mut method).await.unwrap();
        assert_eq!(method, [5, 0]);
        let mut response = [0; 10];
        socks.read_exact(&mut response).await.unwrap();
        assert_eq!(response[1], 7);
        assert!(proxy.opener.calls.lock().unwrap().is_empty());
        proxy.stop().await;
    })
    .await;
}
