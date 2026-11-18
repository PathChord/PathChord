#![cfg(windows)]

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use pathchord_ingress::{
    ListenerId, PlatformProxyAdapter, PlatformProxyKind, PlatformProxyRequest,
    WindowsSystemProxyAdapter,
};
use windows_registry::{CURRENT_USER, Key, Type};

const ENVIRONMENT: &str = "Environment";
const INTERNET: &str = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings";
const VALUES: [(&str, &str); 6] = [
    (ENVIRONMENT, "HTTP_PROXY"),
    (ENVIRONMENT, "HTTPS_PROXY"),
    (ENVIRONMENT, "ALL_PROXY"),
    (INTERNET, "ProxyEnable"),
    (INTERNET, "ProxyServer"),
    (INTERNET, "ProxyOverride"),
];

#[derive(Debug, PartialEq, Eq)]
struct Value {
    key: &'static str,
    name: &'static str,
    data: Option<(u32, Vec<u8>)>,
}

fn snapshot() -> Vec<Value> {
    VALUES
        .map(|(key, name)| Value {
            key,
            name,
            data: CURRENT_USER
                .create(key)
                .unwrap()
                .get_value(name)
                .ok()
                .map(|value| (value.ty().into(), value.as_ref().to_vec())),
        })
        .into_iter()
        .collect()
}

fn restore(values: &[Value]) {
    for value in values {
        let key = CURRENT_USER.create(value.key).unwrap();
        if let Some((kind, data)) = &value.data {
            key.set_bytes(value.name, Type::from(*kind), data).unwrap();
        } else if key.get_value(value.name).is_ok() {
            key.remove_value(value.name).unwrap();
        }
    }
}

struct PreviousValues(Vec<Value>);

impl Drop for PreviousValues {
    fn drop(&mut self) {
        restore(&self.0);
    }
}

fn utf16_bytes(value: &str) -> Vec<u8> {
    value
        .encode_utf16()
        .chain([0])
        .flat_map(u16::to_le_bytes)
        .collect()
}

fn seed_previous_values() {
    let environment = CURRENT_USER.create(ENVIRONMENT).unwrap();
    environment
        .set_bytes(
            "HTTP_PROXY",
            Type::from(2),
            &utf16_bytes("%USERPROFILE%\\proxy"),
        )
        .unwrap();
    if environment.get_value("HTTPS_PROXY").is_ok() {
        environment.remove_value("HTTPS_PROXY").unwrap();
    }
    environment
        .set_bytes("ALL_PROXY", Type::from(3), &[0, 17, 0, 255])
        .unwrap();
    let internet = CURRENT_USER.create(INTERNET).unwrap();
    internet.set_u32("ProxyEnable", 0).unwrap();
    internet
        .set_string("ProxyServer", "http=127.0.0.1:31991")
        .unwrap();
    internet
        .set_bytes(
            "ProxyOverride",
            Type::from(2),
            &utf16_bytes("%COMPUTERNAME%;<local>"),
        )
        .unwrap();
}

fn request(kind: PlatformProxyKind) -> PlatformProxyRequest {
    PlatformProxyRequest {
        listener_id: ListenerId::new("native-windows-acceptance"),
        kind,
        endpoint: "[::1]:31891".parse().unwrap(),
    }
}

fn assert_applied(environment: &Key, internet: &Key, kind: PlatformProxyKind) {
    let (url, server) = match kind {
        PlatformProxyKind::Http => ("http://[::1]:31891", "http=[::1]:31891;https=[::1]:31891"),
        PlatformProxyKind::Socks5 => ("socks5://[::1]:31891", "socks=[::1]:31891"),
    };
    for name in ["HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"] {
        assert_eq!(environment.get_string(name).unwrap(), url);
    }
    assert_eq!(internet.get_u32("ProxyEnable").unwrap(), 1);
    assert_eq!(internet.get_string("ProxyServer").unwrap(), server);
    assert_eq!(internet.get_string("ProxyOverride").unwrap(), "<local>");
}

fn native_directory() -> PathBuf {
    let root = std::env::var_os("PATHCHORD_TEST_WINDOWS_ROOT")
        .expect("run native Windows acceptance only in a disposable test guest");
    let directory = PathBuf::from(root).join(format!("registry-{}", std::process::id()));
    std::fs::create_dir_all(&directory).unwrap();
    directory
}

#[test]
#[ignore = "mutates HKCU; run explicitly only in a disposable Windows test guest"]
fn native_windows_proxy_preserves_types_absence_and_crash_recovery() {
    let previous = PreviousValues(snapshot());
    let directory = native_directory();
    let journal = directory.join("system-proxy-journal.json");
    let environment = CURRENT_USER.create(ENVIRONMENT).unwrap();
    let internet = CURRENT_USER.create(INTERNET).unwrap();
    seed_previous_values();
    let expected = snapshot();
    for kind in [PlatformProxyKind::Http, PlatformProxyKind::Socks5] {
        let adapter = WindowsSystemProxyAdapter::new(&journal);
        adapter.recover().unwrap();
        adapter.apply(&request(kind)).unwrap();
        assert!(journal.is_file());
        assert_applied(&environment, &internet, kind);
        adapter.restore().unwrap();
        assert!(!journal.exists());
        assert_eq!(snapshot(), expected);
        adapter.apply(&request(kind)).unwrap();
        drop(adapter);
        assert!(!journal.exists());
        assert_eq!(snapshot(), expected);
    }

    let ready = directory.join("child-ready");
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args([
            "--ignored",
            "--exact",
            "native_windows_proxy_crash_child",
            "--nocapture",
        ])
        .env("PATHCHORD_TEST_WINDOWS_JOURNAL", &journal)
        .env("PATHCHORD_TEST_WINDOWS_READY", &ready)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(30);
    while !ready.exists() {
        assert!(
            child.try_wait().unwrap().is_none(),
            "proxy apply child exited before ready"
        );
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("proxy apply child timed out");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(journal.is_file());
    assert_applied(&environment, &internet, PlatformProxyKind::Http);
    child.kill().unwrap();
    child.wait().unwrap();
    assert!(
        journal.is_file(),
        "forced termination must leave the durable journal"
    );
    let recovery = WindowsSystemProxyAdapter::new(&journal);
    recovery.recover().unwrap();
    assert!(!journal.exists());
    assert_eq!(snapshot(), expected);
    drop(recovery);
    drop(previous);
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
#[ignore = "child entry point used by native Windows crash recovery acceptance"]
fn native_windows_proxy_crash_child() {
    let journal = std::env::var_os("PATHCHORD_TEST_WINDOWS_JOURNAL").unwrap();
    let ready = std::env::var_os("PATHCHORD_TEST_WINDOWS_READY").unwrap();
    let adapter = WindowsSystemProxyAdapter::new(Path::new(&journal));
    adapter.apply(&request(PlatformProxyKind::Http)).unwrap();
    std::fs::write(ready, b"applied").unwrap();
    loop {
        std::thread::sleep(Duration::from_secs(1));
    }
}

mod ipv6 {
    use std::collections::BTreeSet;
    use std::net::{IpAddr, SocketAddr};
    use std::sync::Arc;

    use async_trait::async_trait;
    use pathchord_ingress::{
        BoxedLocalConnection, BoxedUdpFlowHandle, ConnectionContext, FlowBridgeError,
        IngressPlatformConfig, IngressPlatformFactories, IngressPlatformRuntime,
        ListenerCredentialError, ListenerCredentialVerifier, ListenerCredentialVerifierFactory,
        ProtectedEndpointSet, StaticListenerCredentialVerifier, TargetHost, TcpFlowOpener,
        UdpFlowError, UdpFlowHandle, UdpFlowOpener,
    };
    use pathchord_policy::{
        AuthenticationMode, Endpoint, FlowProtocol, ListenerConfig, ListenerId, ListenerKind,
        ProcessMetadataRequest,
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream, UdpSocket};
    use tokio::sync::oneshot;

    use super::Duration;

    #[derive(Debug)]
    struct NativeOpener;

    async fn target(context: &ConnectionContext) -> SocketAddr {
        let address = match &context.target.host {
            TargetHost::Ip(ip) => *ip,
            TargetHost::Hostname(host) => {
                assert_eq!(host, "localhost");
                tokio::net::lookup_host((host.as_str(), context.target.port))
                    .await
                    .unwrap()
                    .find(SocketAddr::is_ipv6)
                    .expect("Windows resolver supplies IPv6 localhost")
                    .ip()
            }
        };
        assert!(matches!(address, IpAddr::V6(_)));
        SocketAddr::new(address, context.target.port)
    }

    #[async_trait]
    impl TcpFlowOpener for NativeOpener {
        async fn connect(
            &self,
            context: ConnectionContext,
        ) -> Result<BoxedLocalConnection, FlowBridgeError> {
            TcpStream::connect(target(&context).await)
                .await
                .map(|stream| Box::new(stream) as BoxedLocalConnection)
                .map_err(|error| FlowBridgeError::Dial(error.to_string()))
        }
    }

    #[derive(Debug)]
    struct NativeUdp(UdpSocket);

    #[async_trait]
    impl UdpFlowHandle for NativeUdp {
        async fn send(&mut self, payload: Vec<u8>) -> Result<(), UdpFlowError> {
            self.0
                .send(&payload)
                .await
                .map(|_| ())
                .map_err(|error| UdpFlowError::Task(error.to_string()))
        }
        async fn receive(&mut self) -> Option<Vec<u8>> {
            let mut data = vec![0; 65_535];
            let size = self.0.recv(&mut data).await.ok()?;
            data.truncate(size);
            Some(data)
        }
        async fn close(self: Box<Self>) -> Result<(), UdpFlowError> {
            Ok(())
        }
    }

    #[async_trait]
    impl UdpFlowOpener for NativeOpener {
        async fn open_udp(
            &self,
            context: &ConnectionContext,
        ) -> Result<BoxedUdpFlowHandle, UdpFlowError> {
            let socket = UdpSocket::bind("[::1]:0")
                .await
                .map_err(|error| UdpFlowError::Open(error.to_string()))?;
            socket
                .connect(target(context).await)
                .await
                .map_err(|error| UdpFlowError::Open(error.to_string()))?;
            Ok(Box::new(NativeUdp(socket)))
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
                "native", "fixture",
            )))
        }
    }

    fn listener(name: &str, kind: ListenerKind) -> ListenerConfig {
        ListenerConfig {
            id: ListenerId::new(name),
            kind,
            platform: "windows".to_owned(),
            bind: Some(Endpoint {
                host: "::1".to_owned(),
                port: 0,
            }),
            allowed_sources: vec!["::1/128".to_owned()],
            authentication: AuthenticationMode::Required,
            backend: Default::default(),
            credentials_ref: Some("native-fixture".to_owned()),
            mark: None,
            route_table: None,
            protocols: BTreeSet::from([FlowProtocol::Tcp, FlowProtocol::Udp]),
            interface: None,
            address: None,
            mtu: None,
            bypass: Vec::new(),
            proxy_ref: None,
            flow_tags: BTreeSet::new(),
            process_metadata: ProcessMetadataRequest::default(),
        }
    }

    async fn echo(mut stream: TcpStream, payload: &[u8]) {
        stream.write_all(payload).await.unwrap();
        stream.shutdown().await.unwrap();
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await.unwrap();
        assert_eq!(response, payload);
    }

    fn address_bytes(address: SocketAddr) -> Vec<u8> {
        let IpAddr::V6(ip) = address.ip() else {
            panic!("IPv6 required")
        };
        let mut encoded = vec![4];
        encoded.extend_from_slice(&ip.octets());
        encoded.extend_from_slice(&address.port().to_be_bytes());
        encoded
    }

    async fn socks(proxy: SocketAddr, command: u8, address: SocketAddr) -> (TcpStream, SocketAddr) {
        let mut client = TcpStream::connect(proxy).await.unwrap();
        client.write_all(&[5, 1, 2]).await.unwrap();
        let mut method = [0; 2];
        client.read_exact(&mut method).await.unwrap();
        assert_eq!(method, [5, 2]);
        client
            .write_all(b"\x01\x06native\x07fixture")
            .await
            .unwrap();
        client.read_exact(&mut method).await.unwrap();
        assert_eq!(method, [1, 0]);
        let mut request = vec![5, command, 0];
        request.extend_from_slice(&address_bytes(address));
        client.write_all(&request).await.unwrap();
        let mut reply = [0; 4];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply[..3], &[5, 0, 0]);
        let relay = match reply[3] {
            1 => {
                let mut address = [0; 6];
                client.read_exact(&mut address).await.unwrap();
                SocketAddr::from((
                    [address[0], address[1], address[2], address[3]],
                    u16::from_be_bytes([address[4], address[5]]),
                ))
            }
            4 => {
                let mut address = [0; 18];
                client.read_exact(&mut address).await.unwrap();
                let ip: [u8; 16] = address[..16].try_into().unwrap();
                SocketAddr::new(
                    std::net::Ipv6Addr::from(ip).into(),
                    u16::from_be_bytes([address[16], address[17]]),
                )
            }
            _ => panic!("SOCKS response must contain an IP address"),
        };
        (client, relay)
    }

    #[tokio::test]
    async fn windows_ipv6_listeners_forward_authenticated_tcp_udp_and_resolved_hostname() {
        tokio::time::timeout(Duration::from_secs(30), async {
            let target = TcpListener::bind("[::1]:0").await.unwrap();
            let tcp_address = target.local_addr().unwrap();
            let echo_task = tokio::spawn(async move {
                for _ in 0..6 {
                    let (mut stream, _) = target.accept().await.unwrap();
                    let (mut read, mut write) = stream.split();
                    tokio::io::copy(&mut read, &mut write).await.unwrap();
                }
            });
            let udp_target = UdpSocket::bind("[::1]:0").await.unwrap();
            let udp_address = udp_target.local_addr().unwrap();
            let udp_task = tokio::spawn(async move {
                let mut data = vec![0; 65_535];
                for _ in 0..2 {
                    let (size, peer) = udp_target.recv_from(&mut data).await.unwrap();
                    udp_target.send_to(&data[..size], peer).await.unwrap();
                }
            });
            let mut config = IngressPlatformConfig::new(std::env::temp_dir());
            config.shutdown_timeout = Duration::from_secs(2);
            let runtime = IngressPlatformRuntime::bind_with_factories(
                config, &[listener("socks", ListenerKind::Socks5), listener("mixed", ListenerKind::Mixed)],
                Arc::new(NativeOpener), Arc::new(NativeOpener), ProtectedEndpointSet::default(),
                IngressPlatformFactories { listener_credentials: Arc::new(Credentials), ..Default::default() },
            ).await.unwrap();
            let addresses = runtime.listener_addresses().unwrap();
            let (stop, signal) = oneshot::channel();
            let owner = tokio::spawn(runtime.run_until_shutdown(async { let _ = signal.await; }));
            let mixed = addresses[&ListenerId::new("mixed")];
            for destination in [tcp_address.to_string(), format!("localhost:{}", tcp_address.port())] {
                let mut client = TcpStream::connect(mixed).await.unwrap();
                client.write_all(format!("CONNECT {destination} HTTP/1.1\r\nHost: {destination}\r\nProxy-Authorization: Basic bmF0aXZlOmZpeHR1cmU=\r\n\r\n").as_bytes()).await.unwrap();
                let mut head = [0; 39]; client.read_exact(&mut head).await.unwrap();
                assert_eq!(&head, b"HTTP/1.1 200 Connection Established\r\n\r\n");
                echo(client, b"ipv6-http-half-close").await;
            }
            for proxy in addresses.values() {
                for _ in 0..2 { let (client, _) = socks(*proxy, 1, tcp_address).await; echo(client, b"ipv6-socks-half-close").await; }
                let (control, relay) = socks(*proxy, 3, "[::]:0".parse().unwrap()).await;
                let udp = UdpSocket::bind("[::1]:0").await.unwrap();
                let mut packet = vec![0, 0, 0]; packet.extend_from_slice(&address_bytes(udp_address));
                packet.extend_from_slice(&vec![0x73; 4096]);
                udp.send_to(&packet, relay).await.unwrap();
                let mut response = vec![0; 8192]; let (size, source) = udp.recv_from(&mut response).await.unwrap();
                assert_eq!(source, relay); assert_eq!(&response[..size], packet);
                drop(control);
            }
            stop.send(()).unwrap(); owner.await.unwrap().unwrap();
            echo_task.await.unwrap(); udp_task.await.unwrap();
        }).await.expect("bounded native IPv6 forwarding");
    }
}
