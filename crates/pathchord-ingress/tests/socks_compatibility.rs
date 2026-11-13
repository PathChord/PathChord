use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use pathchord_ingress::{
    BoxedLocalConnection, BoxedUdpFlowHandle, ConnectionContext, FlowBridgeError,
    ListenerDescriptor, ListenerError, ListenerId, ListenerKind, RejectListenerCredentials,
    Socks5Listener, Socks5Runtime, Socks5RuntimeConfig, Socks5RuntimeError, Socks5RuntimeReport,
    TargetHost, TcpFlowOpener, UdpFlowError, UdpFlowOpener,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Notify, Semaphore, oneshot};

#[derive(Debug)]
struct RecordingOpener {
    target: SocketAddr,
    contexts: Mutex<Vec<ConnectionContext>>,
    entered: Notify,
    gate: Semaphore,
}

impl RecordingOpener {
    fn new(target: SocketAddr) -> Self {
        Self {
            target,
            contexts: Mutex::new(Vec::new()),
            entered: Notify::new(),
            gate: Semaphore::new(0),
        }
    }
}

#[async_trait]
impl TcpFlowOpener for RecordingOpener {
    async fn connect(
        &self,
        context: ConnectionContext,
    ) -> Result<BoxedLocalConnection, FlowBridgeError> {
        self.contexts.lock().unwrap().push(context);
        self.entered.notify_one();
        self.gate.acquire().await.unwrap().forget();
        TcpStream::connect(self.target)
            .await
            .map(|stream| Box::new(stream) as BoxedLocalConnection)
            .map_err(|error| FlowBridgeError::Dial(error.to_string()))
    }
}

#[derive(Debug)]
struct RejectUdp;

#[async_trait]
impl UdpFlowOpener for RejectUdp {
    async fn open_udp(
        &self,
        _context: &ConnectionContext,
    ) -> Result<BoxedUdpFlowHandle, UdpFlowError> {
        panic!("SOCKS4 must not open a UDP flow");
    }
}

fn descriptor(authentication_required: bool) -> ListenerDescriptor {
    ListenerDescriptor {
        id: ListenerId::new("socks-compatibility"),
        kind: ListenerKind::Socks5,
        bind: Some("127.0.0.1:0".parse().unwrap()),
        interface: None,
        address: None,
        mtu: None,
        flow_tags: Default::default(),
        process_metadata: Default::default(),
        allowed_sources: vec!["127.0.0.1/32".to_owned()],
        authentication_required,
    }
}

struct Proxy {
    address: SocketAddr,
    shutdown: oneshot::Sender<()>,
    task: tokio::task::JoinHandle<Result<Socks5RuntimeReport, Socks5RuntimeError>>,
}

impl Proxy {
    async fn start(authentication_required: bool, opener: Arc<RecordingOpener>) -> Self {
        let runtime = Socks5Runtime::bind(
            descriptor(authentication_required),
            Socks5RuntimeConfig {
                tcp_enabled: true,
                udp_enabled: true,
                max_clients: 4,
                max_targets_per_client: 4,
                target_queue: 2,
                idle_timeout: Duration::from_secs(2),
                shutdown_timeout: Duration::from_secs(1),
            },
            opener,
            Arc::new(RejectUdp),
            Arc::new(RejectListenerCredentials),
        )
        .await
        .unwrap();
        let address = runtime.local_addr().unwrap();
        let (shutdown, signal) = oneshot::channel();
        let task = tokio::spawn(runtime.run_until_shutdown(async move {
            let _ = signal.await;
        }));
        Self {
            address,
            shutdown,
            task,
        }
    }

    async fn stop(self) -> Socks5RuntimeReport {
        self.shutdown.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(2), self.task)
            .await
            .expect("bounded SOCKS shutdown")
            .unwrap()
            .unwrap()
    }
}

fn request_v4(command: u8, port: u16, address: [u8; 4], user: &[u8]) -> Vec<u8> {
    let mut packet = vec![4, command];
    packet.extend_from_slice(&port.to_be_bytes());
    packet.extend_from_slice(&address);
    packet.extend_from_slice(user);
    packet.push(0);
    packet
}

#[tokio::test]
async fn socks4_and_4a_wait_for_target_open_and_preserve_buffered_payload() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_address = target.local_addr().unwrap();
        let echo = tokio::spawn(async move {
            for _ in 0..2 {
                let (mut stream, _) = target.accept().await.unwrap();
                let (mut input, mut output) = stream.split();
                tokio::io::copy(&mut input, &mut output).await.unwrap();
            }
        });
        let opener = Arc::new(RecordingOpener::new(target_address));
        let proxy = Proxy::start(false, Arc::clone(&opener)).await;
        for (address, domain) in [([127, 0, 0, 1], None), ([0, 0, 0, 1], Some("example.test"))] {
            // A maximal unverified UserID must not become a policy identity.
            let mut request = request_v4(1, target_address.port(), address, &[b'a'; 255]);
            if let Some(domain) = domain {
                request.extend_from_slice(domain.as_bytes());
                request.push(0);
            }
            request.extend_from_slice(b"pipelined-payload");
            let mut client = TcpStream::connect(proxy.address).await.unwrap();
            client.write_all(&request).await.unwrap();
            opener.entered.notified().await;
            let mut reply = [0; 8];
            assert!(matches!(
                client.try_read(&mut reply),
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock
            ));
            opener.gate.add_permits(1);
            client.read_exact(&mut reply).await.unwrap();
            assert_eq!(reply, [0, 90, 0, 0, 0, 0, 0, 0]);
            client.shutdown().await.unwrap();
            let mut response = Vec::new();
            client.read_to_end(&mut response).await.unwrap();
            assert_eq!(response, b"pipelined-payload");
        }
        let report = proxy.stop().await;
        assert_eq!(report.tcp_connections, 2);
        echo.await.unwrap();
        let contexts = opener.contexts.lock().unwrap();
        assert_eq!(contexts.len(), 2);
        assert_eq!(
            contexts[0].target.host,
            TargetHost::Ip("127.0.0.1".parse().unwrap())
        );
        assert_eq!(
            contexts[1].target.host,
            TargetHost::Hostname("example.test".to_owned())
        );
        assert!(
            contexts
                .iter()
                .all(|context| context.authentication_identity.is_none())
        );
    })
    .await
    .expect("bounded SOCKS4 forwarding test");
}

#[tokio::test]
async fn socks4_cannot_bypass_required_password_authentication() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let opener = Arc::new(RecordingOpener::new("127.0.0.1:1".parse().unwrap()));
        let proxy = Proxy::start(true, Arc::clone(&opener)).await;
        let mut client = TcpStream::connect(proxy.address).await.unwrap();
        client
            .write_all(&request_v4(1, 443, [192, 0, 2, 1], b"administrator"))
            .await
            .unwrap();
        let mut reply = [0; 8];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply, [0, 91, 0, 0, 0, 0, 0, 0]);
        assert!(opener.contexts.lock().unwrap().is_empty());
        assert_eq!(proxy.stop().await.tcp_connections, 0);
    })
    .await
    .expect("bounded SOCKS4 authentication test");
}

#[tokio::test]
async fn socks4_rejects_unsupported_commands_and_bounded_malformed_fields() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let mut empty_domain = request_v4(1, 80, [0, 0, 0, 1], b"");
        empty_domain.push(0);
        let mut long_domain = request_v4(1, 80, [0, 0, 0, 1], b"");
        long_domain.extend_from_slice(&[b'a'; 256]);
        long_domain.push(0);
        let mut invalid_domain = request_v4(1, 80, [0, 0, 0, 1], b"");
        invalid_domain.extend_from_slice(&[0xff, 0]);
        let mut truncated_user = request_v4(1, 80, [192, 0, 2, 1], b"user");
        truncated_user.pop();
        for request in [
            request_v4(2, 80, [192, 0, 2, 1], b""),
            request_v4(3, 80, [192, 0, 2, 1], b""),
            request_v4(1, 0, [192, 0, 2, 1], b""),
            request_v4(1, 80, [192, 0, 2, 1], &[b'a'; 256]),
            empty_domain,
            long_domain,
            invalid_domain,
            truncated_user,
        ] {
            let (mut client, server) = tokio::io::duplex(1024);
            let task = tokio::spawn(async move {
                Socks5Listener::accept_stream(
                    server,
                    "127.0.0.1:1234".parse().unwrap(),
                    &descriptor(false),
                )
                .await
            });
            client.write_all(&request).await.unwrap();
            client.shutdown().await.unwrap();
            let mut reply = [0; 8];
            client.read_exact(&mut reply).await.unwrap();
            assert_eq!(reply, [0, 91, 0, 0, 0, 0, 0, 0]);
            assert!(matches!(
                task.await.unwrap(),
                Err(ListenerError::Protocol(_))
            ));
        }
    })
    .await
    .expect("bounded malformed SOCKS4 test");
}
