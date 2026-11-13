use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use pathchord_ingress::{
    BoxedLocalConnection, BoxedUdpFlowHandle, ConnectionContext, FlowBridgeError,
    IngressPlatformConfig, IngressPlatformRuntime, ProtectedEndpointSet, TargetHost, TcpFlowOpener,
    UdpFlowError, UdpFlowHandle, UdpFlowOpener,
};
use pathchord_policy::{
    AuthenticationMode, Endpoint, FlowProtocol, ListenerConfig, ListenerId, ListenerKind,
    PolicyConfig, ProcessMetadataRequest,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::oneshot;

#[derive(Debug)]
struct DirectOpener;

fn target_address(context: &ConnectionContext) -> SocketAddr {
    let TargetHost::Ip(ip) = context.target.host else {
        panic!("test targets must be IP literals");
    };
    SocketAddr::new(ip, context.target.port)
}

#[async_trait]
impl TcpFlowOpener for DirectOpener {
    async fn connect(
        &self,
        context: ConnectionContext,
    ) -> Result<BoxedLocalConnection, FlowBridgeError> {
        TcpStream::connect(target_address(&context))
            .await
            .map(|stream| Box::new(stream) as BoxedLocalConnection)
            .map_err(|error| FlowBridgeError::Dial(error.to_string()))
    }
}

#[derive(Debug)]
struct DirectUdpHandle(UdpSocket);

#[async_trait]
impl UdpFlowHandle for DirectUdpHandle {
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
        let socket = UdpSocket::bind("127.0.0.1:0")
            .await
            .map_err(|error| UdpFlowError::Open(error.to_string()))?;
        socket
            .connect(target_address(context))
            .await
            .map_err(|error| UdpFlowError::Open(error.to_string()))?;
        Ok(Box::new(DirectUdpHandle(socket)))
    }
}

fn listener(id: &str, kind: ListenerKind) -> ListenerConfig {
    ListenerConfig {
        id: ListenerId::new(id),
        kind,
        platform: std::env::consts::OS.to_owned(),
        bind: Some(Endpoint {
            host: "127.0.0.1".to_owned(),
            port: 0,
        }),
        allowed_sources: vec!["127.0.0.1/32".to_owned()],
        authentication: AuthenticationMode::Disabled,
        credentials_ref: None,
        mark: None,
        route_table: None,
        protocols: if kind == ListenerKind::Socks5 {
            BTreeSet::from([FlowProtocol::Tcp, FlowProtocol::Udp])
        } else {
            BTreeSet::from([FlowProtocol::Tcp])
        },
        interface: None,
        address: None,
        mtu: None,
        bypass: Vec::new(),
        proxy_ref: None,
        flow_tags: BTreeSet::new(),
        process_metadata: ProcessMetadataRequest::default(),
    }
}

fn ipv4_target_bytes(target: SocketAddr) -> [u8; 6] {
    let SocketAddr::V4(target) = target else {
        panic!("test targets must be IPv4");
    };
    let [a, b, c, d] = target.ip().octets();
    let [high, low] = target.port().to_be_bytes();
    [a, b, c, d, high, low]
}

async fn socks_command(
    proxy: SocketAddr,
    command: u8,
    target: SocketAddr,
) -> (TcpStream, SocketAddr) {
    let mut client = TcpStream::connect(proxy).await.expect("SOCKS connection");
    client.write_all(&[5, 1, 0]).await.expect("SOCKS greeting");
    let mut method = [0; 2];
    client.read_exact(&mut method).await.expect("SOCKS method");
    assert_eq!(method, [5, 0]);
    let mut request = vec![5, command, 0, 1];
    request.extend_from_slice(&ipv4_target_bytes(target));
    client.write_all(&request).await.expect("SOCKS request");
    let mut response = [0; 10];
    client
        .read_exact(&mut response)
        .await
        .expect("SOCKS response");
    assert_eq!(&response[..4], &[5, 0, 0, 1]);
    let bound = SocketAddr::from((
        [response[4], response[5], response[6], response[7]],
        u16::from_be_bytes([response[8], response[9]]),
    ));
    (client, bound)
}

async fn check_tcp_echo(mut client: TcpStream, payload: &[u8]) {
    client.write_all(payload).await.expect("TCP payload");
    client.shutdown().await.expect("TCP half-close");
    let mut response = Vec::new();
    client.read_to_end(&mut response).await.expect("TCP echo");
    assert_eq!(response, payload);
}

#[tokio::test]
async fn native_http_and_socks_forward_tcp_udp_and_shutdown() {
    tokio::time::timeout(Duration::from_secs(15), async {
        let tcp_target = TcpListener::bind("127.0.0.1:0").await.expect("TCP target");
        let tcp_address = tcp_target.local_addr().unwrap();
        let tcp_echo = tokio::spawn(async move {
            for _ in 0..2 {
                let (mut connection, _) = tcp_target.accept().await.expect("TCP target accept");
                let (mut input, mut output) = connection.split();
                tokio::io::copy(&mut input, &mut output)
                    .await
                    .expect("TCP target echo");
            }
        });
        let udp_target = UdpSocket::bind("127.0.0.1:0").await.expect("UDP target");
        let udp_address = udp_target.local_addr().unwrap();
        let udp_echo = tokio::spawn(async move {
            let mut payload = [0; 128];
            let (length, source) = udp_target.recv_from(&mut payload).await.unwrap();
            udp_target
                .send_to(&payload[..length], source)
                .await
                .unwrap();
        });

        let policy = PolicyConfig {
            listeners: vec![
                listener("http", ListenerKind::Http),
                listener("socks", ListenerKind::Socks5),
            ],
            ..PolicyConfig::default()
        };
        let mut config = IngressPlatformConfig::new(std::env::temp_dir());
        config.shutdown_timeout = Duration::from_secs(2);
        let runtime = IngressPlatformRuntime::bind(
            config,
            &policy,
            Arc::new(DirectOpener),
            Arc::new(DirectOpener),
            ProtectedEndpointSet::default(),
        )
        .await
        .expect("native platform listeners");
        let addresses = runtime.listener_addresses().unwrap();
        let (stop, shutdown) = oneshot::channel();
        let owner = tokio::spawn(runtime.run_until_shutdown(async move {
            let _ = shutdown.await;
        }));

        let mut http = TcpStream::connect(addresses[&ListenerId::new("http")])
            .await
            .expect("HTTP connection");
        http.write_all(
            format!("CONNECT {tcp_address} HTTP/1.1\r\nHost: {tcp_address}\r\n\r\n").as_bytes(),
        )
        .await
        .expect("HTTP CONNECT");
        let mut response = [0; 39];
        http.read_exact(&mut response).await.expect("HTTP response");
        assert_eq!(&response, b"HTTP/1.1 200 Connection Established\r\n\r\n");
        check_tcp_echo(http, b"http-connect").await;

        let socks_address = addresses[&ListenerId::new("socks")];
        let (socks, _) = socks_command(socks_address, 1, tcp_address).await;
        check_tcp_echo(socks, b"socks-connect").await;

        let (control, relay) = socks_command(socks_address, 3, "0.0.0.0:0".parse().unwrap()).await;
        let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut datagram = vec![0, 0, 0, 1];
        datagram.extend_from_slice(&ipv4_target_bytes(udp_address));
        datagram.extend_from_slice(b"socks-udp");
        udp.send_to(&datagram, relay).await.expect("SOCKS UDP send");
        let mut response = [0; 128];
        let (length, source) = udp.recv_from(&mut response).await.expect("SOCKS UDP echo");
        assert_eq!(source, relay);
        assert_eq!(&response[..length], datagram);

        // Keep the UDP control connection open to exercise runtime cancellation.
        stop.send(()).expect("platform shutdown signal");
        let report = tokio::time::timeout(Duration::from_secs(4), owner)
            .await
            .expect("bounded platform shutdown")
            .expect("platform task")
            .expect("platform shutdown");
        assert_eq!(report.tcp.unwrap().completed_connections, 1);
        let socks = &report.socks[&ListenerId::new("socks")];
        assert_eq!(socks.tcp_connections, 1);
        assert_eq!(socks.udp_associations, 1);
        assert_eq!(socks.udp_datagrams_sent, 1);
        drop(control);
        tcp_echo.await.expect("TCP echo task");
        udp_echo.await.expect("UDP echo task");
    })
    .await
    .expect("bounded explicit-listener test");
}
