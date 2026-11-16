//! gRPC transport behavior through the public adapter registry.

use std::{
    collections::BTreeMap, net::SocketAddr, path::PathBuf, process::Stdio, sync::Arc,
    time::Duration,
};

use pathchord_policy::{
    Endpoint as PolicyEndpoint, TransitOptions, TransitProxyConfig, TransitProxyId, TransitReality,
    TransitTls, TransitTransport,
};
use pathchord_transit::{
    AdapterRegistry, ConnectRequest, Endpoint, NoTransitCredentials, TransitAdapter,
    TransitCredential, TransitError,
};
use serde_json::{Value, json};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    process::{Child, Command},
    time::{Instant, sleep, timeout},
};

const UUID: &str = "6cbf3f72-3417-4922-bde6-67820d041f25";
const PASSWORD: &str = "pathchord-grpc-test";
const SERVICE: &str = "pathchord.testing";
const SERVER_NAME: &str = "tls.pathchord.test";

fn grpc_config() -> TransitProxyConfig {
    TransitProxyConfig {
        id: TransitProxyId::new("grpc"),
        source: None,
        protocol: "vless".to_owned(),
        endpoint: PolicyEndpoint {
            host: "127.0.0.1".to_owned(),
            port: 443,
        },
        credentials_ref: None,
        labels: Default::default(),
        tags: Default::default(),
        weight: 100,
        options: TransitOptions {
            transport: Some(TransitTransport {
                kind: "grpc".to_owned(),
                service_name: Some("pathchord".to_owned()),
                ..Default::default()
            }),
            ..Default::default()
        },
    }
}

fn registry() -> AdapterRegistry<NoTransitCredentials> {
    AdapterRegistry::for_configs(
        Arc::new(NoTransitCredentials),
        Duration::from_secs(5),
        [&grpc_config()],
    )
    .unwrap()
}

fn credential() -> TransitCredential {
    TransitCredential::new(BTreeMap::from([("uuid".to_owned(), UUID.to_owned())]))
}

#[derive(Clone, Copy, Debug)]
enum Protocol {
    Vless,
    Vmess,
    Trojan,
}

impl Protocol {
    fn name(self) -> &'static str {
        match self {
            Self::Vless => "vless",
            Self::Vmess => "vmess",
            Self::Trojan => "trojan",
        }
    }

    fn credentials(self) -> TransitCredential {
        let fields = match self {
            Self::Vless => vec![("uuid", UUID)],
            Self::Vmess => vec![
                ("uuid", UUID),
                ("alter_id", "0"),
                ("security", "aes-128-gcm"),
            ],
            Self::Trojan => vec![("password", PASSWORD)],
        };
        TransitCredential::new(
            fields
                .into_iter()
                .map(|(k, v)| (k.to_owned(), v.to_owned()))
                .collect(),
        )
    }

    fn users(self) -> Value {
        match self {
            Self::Vless | Self::Vmess => json!([{ "uuid": UUID }]),
            Self::Trojan => json!([{ "password": PASSWORD }]),
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum Peer {
    SingBox,
    Xray,
}

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new() -> Self {
        let mut suffix = [0; 8];
        getrandom::fill(&mut suffix).unwrap();
        let path = std::env::temp_dir().join(format!(
            "pathchord-grpc-{}-{:016x}",
            std::process::id(),
            u64::from_ne_bytes(suffix)
        ));
        #[cfg_attr(not(unix), allow(unused_mut))]
        let mut directory = std::fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            directory.mode(0o700);
        }
        directory.create(&path).unwrap();
        Self(path)
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

struct Server {
    child: Child,
    directory: TestDirectory,
    port: u16,
    certificate: Option<String>,
}

impl Server {
    async fn start(peer: Peer, protocol: Protocol, tls: bool) -> Self {
        Self::start_with_service(peer, protocol, tls, SERVICE).await
    }

    async fn start_with_service(peer: Peer, protocol: Protocol, tls: bool, service: &str) -> Self {
        let env = match peer {
            Peer::SingBox => "PATHCHORD_TEST_SING_BOX",
            Peer::Xray => "PATHCHORD_TEST_XRAY",
        };
        let binary =
            PathBuf::from(std::env::var_os(env).unwrap_or_else(|| panic!("{env} required")));
        let directory = TestDirectory::new();
        let reserved = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = reserved.local_addr().unwrap().port();
        let certificate = if tls {
            let rcgen::CertifiedKey { cert, signing_key } =
                rcgen::generate_simple_self_signed(vec![SERVER_NAME.to_owned()]).unwrap();
            let certificate = cert.pem();
            std::fs::write(directory.0.join("server.pem"), &certificate).unwrap();
            std::fs::write(directory.0.join("server.key"), signing_key.serialize_pem()).unwrap();
            Some(certificate)
        } else {
            None
        };
        let config = match peer {
            Peer::SingBox => {
                let mut inbound = json!({
                    "type": protocol.name(), "listen": "127.0.0.1", "listen_port": port,
                    "users": protocol.users(),
                    "transport": {"type": "grpc", "service_name": service}
                });
                if tls {
                    inbound["tls"] = json!({
                        "enabled": true, "certificate_path": directory.0.join("server.pem"),
                        "key_path": directory.0.join("server.key"), "alpn": ["h2"]
                    });
                }
                json!({"log":{"level":"error"}, "inbounds":[inbound], "outbounds":[{"type":"direct"}]})
            }
            Peer::Xray => {
                let clients = match protocol {
                    Protocol::Vless => json!([{"id": UUID}]),
                    Protocol::Vmess => json!([{"id": UUID, "alterId": 0}]),
                    Protocol::Trojan => json!([{"password": PASSWORD}]),
                };
                let mut settings = json!({"clients": clients});
                if matches!(protocol, Protocol::Vless) {
                    settings["decryption"] = json!("none");
                }
                let mut stream = json!({"network":"grpc", "grpcSettings":{"serviceName":service}});
                if tls {
                    stream["security"] = json!("tls");
                    stream["tlsSettings"] = json!({"alpn":["h2"],"certificates":[{
                        "certificateFile": directory.0.join("server.pem"),
                        "keyFile": directory.0.join("server.key")
                    }]});
                }
                json!({"log":{"loglevel":"error"}, "inbounds":[{
                    "listen":"127.0.0.1", "port":port, "protocol":protocol.name(),
                    "settings":settings, "streamSettings":stream
                }], "outbounds":[{"protocol":"freedom", "settings":{"finalRules":[{"action":"allow"}]}}]})
            }
        };
        let config_path = directory.0.join("server.json");
        std::fs::write(&config_path, serde_json::to_vec(&config).unwrap()).unwrap();
        let log = std::fs::File::create(directory.0.join("server.log")).unwrap();
        drop(reserved);
        let child = Command::new(binary)
            .args(["run", "-c"])
            .arg(config_path)
            .stdin(Stdio::null())
            .stdout(Stdio::from(log.try_clone().unwrap()))
            .stderr(Stdio::from(log))
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let mut server = Self {
            child,
            directory,
            port,
            certificate,
        };
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if let Some(status) = server.child.try_wait().unwrap() {
                panic!("{peer:?} exited: {status}");
            }
            if TcpStream::connect(("127.0.0.1", port)).await.is_ok() {
                return server;
            }
            assert!(Instant::now() < deadline, "{peer:?} readiness timed out");
            sleep(Duration::from_millis(20)).await;
        }
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.start_kill();
        if std::thread::panicking() {
            eprintln!(
                "peer log:\n{}",
                std::fs::read_to_string(self.directory.0.join("server.log")).unwrap_or_default()
            );
        }
    }
}

fn adapter(
    protocol: Protocol,
    address: SocketAddr,
    certificate: Option<&str>,
    service: &str,
) -> Arc<dyn TransitAdapter> {
    let mut config = grpc_config();
    config.protocol = protocol.name().to_owned();
    config.endpoint.port = address.port();
    config.options.transport.as_mut().unwrap().service_name = Some(service.to_owned());
    config.options.tls = certificate.map(|certificate| TransitTls {
        enabled: true,
        server_name: Some(SERVER_NAME.to_owned()),
        truststore: Vec::new(),
        certificate: vec![certificate.to_owned()],
        ..Default::default()
    });
    registry()
        .build_with_credential(&config, &protocol.credentials())
        .unwrap()
}

fn destination(port: u16) -> ConnectRequest {
    ConnectRequest {
        destination: Endpoint {
            host: "127.0.0.1".to_owned(),
            port,
        },
    }
}

async fn relay(peer: Peer, protocol: Protocol, tls: bool) {
    let server = Server::start(peer, protocol, tls).await;
    let address = SocketAddr::from(([127, 0, 0, 1], server.port));
    let client = adapter(protocol, address, server.certificate.as_deref(), SERVICE);
    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = target.local_addr().unwrap().port();
    let upload: Vec<u8> = (0..393_333).map(|i| (i % 251) as u8).collect();
    let download: Vec<u8> = (0..412_777).map(|i| (i % 239) as u8).collect();
    let upstream = async {
        let (mut stream, _) = target.accept().await.unwrap();
        let (mut read, mut write) = stream.split();
        let (received, sent) = tokio::join!(
            async {
                let mut data = vec![0; upload.len()];
                read.read_exact(&mut data).await.unwrap();
                data
            },
            write.write_all(&download)
        );
        sent.unwrap();
        assert_eq!(received, upload);
    };
    let downstream = async {
        let stream = client.connect(destination(port)).await.unwrap();
        let (mut read, mut write) = tokio::io::split(stream);
        let (sent, received) = tokio::join!(
            async {
                write.write_all(&upload).await.unwrap();
                write.flush().await.unwrap();
            },
            async {
                let mut data = vec![0; download.len()];
                read.read_exact(&mut data).await.unwrap();
                data
            }
        );
        let () = sent;
        assert_eq!(received, download);
    };
    timeout(Duration::from_secs(20), async {
        tokio::join!(upstream, downstream)
    })
    .await
    .unwrap_or_else(|_| panic!("{peer:?} {protocol:?} tls={tls} TCP timeout"));

    let target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let port = target.local_addr().unwrap().port();
    let client = adapter(protocol, address, server.certificate.as_deref(), SERVICE);
    let upstream = async {
        let mut data = [0; 2048];
        for _ in 0..2 {
            let (count, peer) = target.recv_from(&mut data).await.unwrap();
            target.send_to(&data[..count], peer).await.unwrap();
        }
    };
    let downstream = async {
        let mut socket = client.connect_udp(destination(port)).await.unwrap();
        for payload in [b"grpc-datagram".as_slice(), &[0x6d; 1400]] {
            socket.send(payload).await.unwrap();
            assert_eq!(socket.receive().await.unwrap(), payload);
        }
        socket.close().await.unwrap();
    };
    timeout(Duration::from_secs(20), async {
        tokio::join!(upstream, downstream)
    })
    .await
    .unwrap_or_else(|_| panic!("{peer:?} {protocol:?} tls={tls} UDP timeout"));
}

async fn pathchord_half_close(server: &Server, protocol: Protocol) -> Vec<u8> {
    let address = SocketAddr::from(([127, 0, 0, 1], server.port));
    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = target.local_addr().unwrap().port();
    let client = adapter(protocol, address, server.certificate.as_deref(), SERVICE);
    let upstream = async {
        let (mut stream, _) = target.accept().await.unwrap();
        let mut input = Vec::new();
        stream.read_to_end(&mut input).await.unwrap();
        assert_eq!(input, b"upload-half-closed");
        stream.write_all(b"download-after-eof").await.unwrap();
        stream.shutdown().await.unwrap();
    };
    let downstream = async {
        let mut stream = client.connect(destination(port)).await.unwrap();
        stream.write_all(b"upload-half-closed").await.unwrap();
        stream.shutdown().await.unwrap();
        let mut received = Vec::new();
        stream.read_to_end(&mut received).await.unwrap();
        received
    };
    let ((), received) = timeout(Duration::from_secs(20), async {
        tokio::join!(upstream, downstream)
    })
    .await
    .unwrap_or_else(|_| panic!("{protocol:?} half-close timeout"));
    received
}

#[tokio::test]
#[ignore = "requires PATHCHORD_TEST_SING_BOX"]
async fn sing_box_grpc_tcp_udp() {
    for (protocol, tls) in [
        (Protocol::Vless, false),
        (Protocol::Vless, true),
        (Protocol::Vmess, false),
        (Protocol::Vmess, true),
        (Protocol::Trojan, true),
    ] {
        relay(Peer::SingBox, protocol, tls).await;
    }
}

#[tokio::test]
#[ignore = "requires PATHCHORD_TEST_SING_BOX"]
async fn sing_box_grpc_preserves_half_close() {
    for (protocol, tls) in [
        (Protocol::Vless, false),
        (Protocol::Vless, true),
        (Protocol::Vmess, false),
        (Protocol::Vmess, true),
        (Protocol::Trojan, true),
    ] {
        let peer = Server::start(Peer::SingBox, protocol, tls).await;
        assert_eq!(
            pathchord_half_close(&peer, protocol).await,
            b"download-after-eof"
        );
    }
}

#[tokio::test]
#[ignore = "requires PATHCHORD_TEST_XRAY"]
async fn xray_grpc_tcp_udp() {
    for (protocol, tls) in [
        (Protocol::Vless, false),
        (Protocol::Vless, true),
        (Protocol::Vmess, false),
        (Protocol::Vmess, true),
        (Protocol::Trojan, true),
    ] {
        relay(Peer::Xray, protocol, tls).await;
    }
}

async fn check_service_name(peer: Peer, service: &str) {
    let server = Server::start_with_service(peer, Protocol::Vless, false, service).await;
    let address = SocketAddr::from(([127, 0, 0, 1], server.port));
    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = target.local_addr().unwrap().port();
    let client = adapter(Protocol::Vless, address, None, service);
    let upstream = async {
        let (mut stream, _) = target.accept().await.unwrap();
        let mut payload = [0; 7];
        stream.read_exact(&mut payload).await.unwrap();
        stream.write_all(&payload).await.unwrap();
    };
    let downstream = async {
        let mut stream = client.connect(destination(port)).await.unwrap();
        stream.write_all(b"service").await.unwrap();
        let mut payload = [0; 7];
        stream.read_exact(&mut payload).await.unwrap();
        assert_eq!(&payload, b"service");
    };
    timeout(Duration::from_secs(10), async {
        tokio::join!(upstream, downstream)
    })
    .await
    .unwrap_or_else(|_| panic!("{peer:?} custom service timed out"));

    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = target.local_addr().unwrap().port();
    let client = adapter(Protocol::Vless, address, None, "wrong-service");
    let attempt = async {
        if let Ok(mut stream) = client.connect(destination(port)).await {
            let _ = stream.write_all(b"not-forwarded").await;
            let mut byte = [0; 1];
            assert!(stream.read(&mut byte).await.is_err());
        }
    };
    timeout(Duration::from_secs(10), attempt).await.unwrap();
    assert!(
        timeout(Duration::from_millis(50), target.accept())
            .await
            .is_err()
    );
}

#[tokio::test]
#[ignore = "requires PATHCHORD_TEST_SING_BOX"]
async fn sing_box_grpc_service_name_is_preserved_and_mismatch_is_rejected() {
    check_service_name(Peer::SingBox, "service/nested").await;
}

#[tokio::test]
#[ignore = "requires PATHCHORD_TEST_XRAY"]
async fn xray_grpc_custom_service_name_is_preserved_and_mismatch_is_rejected() {
    check_service_name(Peer::Xray, "/service/nested/TunCustom|TunMultiCustom").await;
    check_service_name(Peer::Xray, "service;comma,").await;
}

async fn xray_half_close_reference(peer: &Server) -> Vec<u8> {
    let directory = TestDirectory::new();
    let reserved = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = reserved.local_addr().unwrap().port();
    let config = json!({
        "log": {"loglevel":"error"},
        "inbounds": [{"listen":"127.0.0.1", "port":port, "protocol":"socks", "settings":{"auth":"noauth", "udp":false}}],
        "outbounds": [{"protocol":"vless", "settings":{"vnext":[{"address":"127.0.0.1", "port":peer.port,
            "users":[{"id":UUID, "encryption":"none"}]}]},
            "streamSettings":{"network":"grpc", "grpcSettings":{"serviceName":SERVICE}}}]
    });
    let config_path = directory.0.join("client.json");
    std::fs::write(&config_path, serde_json::to_vec(&config).unwrap()).unwrap();
    let binary = PathBuf::from(std::env::var_os("PATHCHORD_TEST_XRAY").unwrap());
    drop(reserved);
    let mut child = Command::new(binary)
        .args(["run", "-c"])
        .arg(config_path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            panic!("Xray client exited: {status}");
        }
        if TcpStream::connect(("127.0.0.1", port)).await.is_ok() {
            break;
        }
        assert!(Instant::now() < deadline);
        sleep(Duration::from_millis(20)).await;
    }
    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target_port = target.local_addr().unwrap().port();
    let upstream = async {
        let (mut stream, _) = target.accept().await.unwrap();
        let mut input = Vec::new();
        stream.read_to_end(&mut input).await.unwrap();
        assert_eq!(input, b"upload-half-closed");
        stream.write_all(b"download-after-eof").await.unwrap();
        stream.shutdown().await.unwrap();
    };
    let downstream = async {
        let mut stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        stream.write_all(&[5, 1, 0]).await.unwrap();
        let mut greeting = [0; 2];
        stream.read_exact(&mut greeting).await.unwrap();
        assert_eq!(greeting, [5, 0]);
        let mut connect = vec![5, 1, 0, 1, 127, 0, 0, 1];
        connect.extend_from_slice(&target_port.to_be_bytes());
        stream.write_all(&connect).await.unwrap();
        let mut reply = [0; 10];
        stream.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply[..4], &[5, 0, 0, 1]);
        stream.write_all(b"upload-half-closed").await.unwrap();
        stream.shutdown().await.unwrap();
        let mut received = Vec::new();
        stream.read_to_end(&mut received).await.unwrap();
        received
    };
    let ((), received) = timeout(Duration::from_secs(10), async {
        tokio::join!(upstream, downstream)
    })
    .await
    .expect("Xray reference half-close timeout");
    child.start_kill().unwrap();
    received
}

#[tokio::test]
#[ignore = "requires PATHCHORD_TEST_XRAY"]
async fn xray_grpc_half_close_matches_xray_reference() {
    let peer = Server::start(Peer::Xray, Protocol::Vless, false).await;
    let actual = pathchord_half_close(&peer, Protocol::Vless).await;
    let reference = xray_half_close_reference(&peer).await;
    assert_eq!(actual, reference);
    if reference != b"download-after-eof" {
        eprintln!("Xray peer did not preserve the post-FIN response for either client");
    }
}

async fn reality_grpc_round_trip(peer: Peer) -> Result<(), TransitError> {
    use rustls::pki_types::PrivatePkcs8KeyDer;

    const PRIVATE_KEY: &str = "-AxPYYdSOc0L8SVojHT0CHsejcb15DcdD2ZI8QaALlo";
    const PUBLIC_KEY: &str = "Q7VhOFla3pZJiGzjiNfwi3j-QfEr9FOdDpQIiDANtRM";
    const SHORT_ID: &str = "0123456789abcdef";
    let rcgen::CertifiedKey { cert, signing_key } =
        rcgen::generate_simple_self_signed(vec![SERVER_NAME.to_owned()]).unwrap();
    let mut decoy_provider = rustls::crypto::aws_lc_rs::default_provider();
    decoy_provider.kx_groups = if matches!(peer, Peer::Xray) {
        vec![
            rustls::crypto::aws_lc_rs::kx_group::X25519MLKEM768,
            rustls::crypto::aws_lc_rs::kx_group::X25519,
        ]
    } else {
        vec![rustls::crypto::aws_lc_rs::kx_group::X25519]
    };
    let mut tls = rustls::ServerConfig::builder_with_provider(Arc::new(decoy_provider))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.der().clone()],
            PrivatePkcs8KeyDer::from(signing_key.serialize_der()).into(),
        )
        .unwrap();
    tls.alpn_protocols = vec![b"h2".to_vec()];
    tls.cert_compressors.clear();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls));
    let decoy = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let decoy_port = decoy.local_addr().unwrap().port();
    let decoy_task = tokio::spawn(async move {
        while let Ok((stream, _)) = decoy.accept().await {
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let _ = acceptor.accept(stream).await;
            });
        }
    });
    let reserved = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = reserved.local_addr().unwrap().port();
    let config = match peer {
        Peer::SingBox => json!({"log":{"level":"error"}, "inbounds":[{
            "type":"vless", "listen":"127.0.0.1", "listen_port":port,
            "users":[{"uuid":UUID}], "transport":{"type":"grpc", "service_name":SERVICE},
            "tls":{"enabled":true, "server_name":SERVER_NAME, "alpn":["h2"], "reality":{
                "enabled":true, "handshake":{"server":"127.0.0.1", "server_port":decoy_port},
                "private_key":PRIVATE_KEY, "short_id":[SHORT_ID]
            }}
        }], "outbounds":[{"type":"direct"}]}),
        Peer::Xray => json!({"log":{"loglevel":"error"}, "inbounds":[{
            "listen":"127.0.0.1", "port":port, "protocol":"vless",
            "settings":{"clients":[{"id":UUID}], "decryption":"none"},
            "streamSettings":{"network":"grpc", "grpcSettings":{"serviceName":SERVICE},
                "security":"reality", "realitySettings":{"dest":format!("127.0.0.1:{decoy_port}"),
                    "serverNames":[SERVER_NAME], "privateKey":PRIVATE_KEY, "shortIds":[SHORT_ID]}}
        }], "outbounds":[{"protocol":"freedom", "settings":{"finalRules":[{"action":"allow"}]}}]}),
    };
    let directory = TestDirectory::new();
    let config_path = directory.0.join("reality.json");
    std::fs::write(&config_path, serde_json::to_vec(&config).unwrap()).unwrap();
    let binary = PathBuf::from(
        std::env::var_os(match peer {
            Peer::SingBox => "PATHCHORD_TEST_SING_BOX",
            Peer::Xray => "PATHCHORD_TEST_XRAY",
        })
        .unwrap(),
    );
    let log = std::fs::File::create(directory.0.join("server.log")).unwrap();
    drop(reserved);
    let child = Command::new(binary)
        .args(["run", "-c"])
        .arg(config_path)
        .stdin(Stdio::null())
        .stdout(Stdio::from(log.try_clone().unwrap()))
        .stderr(Stdio::from(log))
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let mut server = Server {
        child,
        directory,
        port,
        certificate: None,
    };
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(status) = server.child.try_wait().unwrap() {
            panic!("{peer:?} exited: {status}");
        }
        if TcpStream::connect(("127.0.0.1", port)).await.is_ok() {
            break;
        }
        assert!(Instant::now() < deadline);
        sleep(Duration::from_millis(20)).await;
    }
    let mut node = grpc_config();
    node.endpoint.port = port;
    node.options.transport.as_mut().unwrap().service_name = Some(SERVICE.to_owned());
    node.options.tls = Some(TransitTls {
        enabled: true,
        server_name: Some(SERVER_NAME.to_owned()),
        fingerprint: Some("chrome".into()),
        alpn: vec!["h2".into()],
        reality: Some(TransitReality {
            public_key: PUBLIC_KEY.into(),
            short_id: SHORT_ID.into(),
        }),
        ..Default::default()
    });
    let client = registry()
        .build_with_credential(&node, &credential())
        .unwrap();
    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target_port = target.local_addr().unwrap().port();
    let mut client_stream = match client.connect(destination(target_port)).await {
        Ok(stream) => stream,
        Err(error) => {
            assert!(
                timeout(Duration::from_millis(50), target.accept())
                    .await
                    .is_err()
            );
            decoy_task.abort();
            return Err(error);
        }
    };
    let upstream = async {
        let (mut stream, _) = target.accept().await.unwrap();
        let mut bytes = [0; 7];
        stream.read_exact(&mut bytes).await.unwrap();
        stream.write_all(&bytes).await.unwrap();
    };
    let downstream = async {
        client_stream.write_all(b"reality").await.unwrap();
        let mut bytes = [0; 7];
        client_stream.read_exact(&mut bytes).await.unwrap();
        assert_eq!(&bytes, b"reality");
    };
    timeout(Duration::from_secs(15), async {
        tokio::join!(upstream, downstream)
    })
    .await
    .unwrap_or_else(|_| panic!("{peer:?} REALITY gRPC TCP timeout"));
    let target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let target_port = target.local_addr().unwrap().port();
    let upstream = async {
        let mut bytes = [0; 64];
        let (count, source) = target.recv_from(&mut bytes).await.unwrap();
        target.send_to(&bytes[..count], source).await.unwrap();
    };
    let downstream = async {
        let mut socket = client.connect_udp(destination(target_port)).await.unwrap();
        socket.send(b"reality-udp").await.unwrap();
        assert_eq!(socket.receive().await.unwrap(), b"reality-udp");
        socket.close().await.unwrap();
    };
    timeout(Duration::from_secs(15), async {
        tokio::join!(upstream, downstream)
    })
    .await
    .unwrap_or_else(|_| panic!("{peer:?} REALITY gRPC UDP timeout"));
    decoy_task.abort();
    Ok(())
}

#[tokio::test]
#[ignore = "requires PATHCHORD_TEST_SING_BOX"]
async fn sing_box_reality_grpc_tcp_udp() {
    reality_grpc_round_trip(Peer::SingBox).await.unwrap();
}

#[tokio::test]
#[ignore = "requires PATHCHORD_TEST_XRAY"]
async fn xray_reality_grpc_authenticates_or_fails_closed() {
    match reality_grpc_round_trip(Peer::Xray).await {
        Ok(()) => {}
        Err(TransitError::Connection(message))
            if message.contains("REALITY certificate proof failed") =>
        {
            eprintln!("Xray REALITY gRPC remains unverified: certificate proof failed");
        }
        Err(error) => panic!("unexpected REALITY gRPC failure: {error}"),
    }
}

#[test]
fn vless_grpc_service_name_is_accepted_by_the_native_adapter() {
    assert!(
        registry()
            .build_with_credential(&grpc_config(), &credential())
            .is_ok()
    );
}

#[test]
fn grpc_rejects_unconsumed_transport_fields_and_incompatible_alpn() {
    for option in [
        "path",
        "host",
        "headers",
        "max_early_data",
        "early_data_header_name",
        "alpn",
    ] {
        let mut config = grpc_config();
        let transport = config.options.transport.as_mut().unwrap();
        match option {
            "path" => transport.path = Some("/unused".into()),
            "host" => transport.host.push("unsupported.test".into()),
            "headers" => {
                transport.headers.insert("x-extra".into(), "value".into());
            }
            "max_early_data" => transport.max_early_data = Some(1),
            "early_data_header_name" => transport.early_data_header_name = Some("X-Early".into()),
            "alpn" => {
                config.options.tls = Some(TransitTls {
                    enabled: true,
                    alpn: vec!["http/1.1".into()],
                    ..Default::default()
                })
            }
            _ => unreachable!(),
        }
        assert!(
            matches!(
                registry().build_with_credential(&config, &credential()),
                Err(TransitError::Unsupported(_))
            ),
            "{option} was silently accepted"
        );
    }
}

#[test]
fn grpc_with_vision_flow_is_rejected_before_connecting() {
    let mut config = grpc_config();
    config.options.tls = Some(TransitTls {
        enabled: true,
        ..Default::default()
    });
    let credential = TransitCredential::new(BTreeMap::from([
        ("uuid".to_owned(), UUID.to_owned()),
        ("flow".to_owned(), "xtls-rprx-vision".to_owned()),
    ]));
    assert!(matches!(
        registry().build_with_credential(&config, &credential),
        Err(TransitError::Unsupported(_))
    ));
}
