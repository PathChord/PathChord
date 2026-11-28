//! WebSocket early-data interoperability through the public adapter registry.
//!
//! Run with `PATHCHORD_TEST_SING_BOX=/path/to/sing-box cargo test --locked -p
//! pathchord-transit --test websocket_early_external -- --ignored`.

use std::{
    collections::{BTreeMap, BTreeSet},
    net::SocketAddr,
    path::PathBuf,
    process::Stdio,
    sync::Arc,
    time::Duration,
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use pathchord_policy::{
    Endpoint as PolicyEndpoint, TransitOptions, TransitProxyConfig, TransitProxyId, TransitTls,
    TransitTransport,
};
use pathchord_transit::{
    AdapterRegistry, BoxedTransitConnection, ConnectRequest, Endpoint, NoTransitCredentials,
    TransitAdapter, TransitCredential,
};
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use serde_json::{Value, json};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    process::{Child, Command},
    sync::mpsc,
    task::{JoinHandle, JoinSet},
    time::{Instant, sleep, timeout},
};
use tokio_rustls::{TlsAcceptor, TlsConnector};

const UUID: &str = "6cbf3f72-3417-4922-bde6-67820d041f25";
const PASSWORD: &str = "pathchord-early-test-password";
const PATH: &str = "/pathchord/ws";
const SERVER_NAME: &str = "early.pathchord.test";
const TEST_TIMEOUT: Duration = Duration::from_secs(20);
static START_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

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
enum Placement {
    Path,
    ProtocolHeader,
    CustomHeader,
}

impl Placement {
    fn header(self) -> Option<&'static str> {
        match self {
            Self::Path => None,
            Self::ProtocolHeader => Some("Sec-WebSocket-Protocol"),
            Self::CustomHeader => Some("X-Pathchord-Early"),
        }
    }
}

struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        let mut random = [0; 8];
        getrandom::fill(&mut random).unwrap();
        let path = std::env::temp_dir().join(format!(
            "pathchord-ws-early-{}-{:016x}",
            std::process::id(),
            u64::from_ne_bytes(random)
        ));
        #[cfg_attr(not(unix), allow(unused_mut))]
        let mut builder = std::fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder.create(&path).unwrap();
        Self(path)
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[derive(Clone)]
struct TlsFixture {
    certificate: String,
    acceptor: TlsAcceptor,
    connector: TlsConnector,
}

struct SingBox {
    child: Child,
    directory: Directory,
    address: SocketAddr,
    tls: Option<TlsFixture>,
}

impl SingBox {
    async fn start(protocol: Protocol, placement: Placement, tls: bool, limit: u32) -> Self {
        let _lock = START_LOCK.lock().await;
        let binary = PathBuf::from(
            std::env::var_os("PATHCHORD_TEST_SING_BOX")
                .expect("PATHCHORD_TEST_SING_BOX must name a local sing-box executable"),
        );
        assert!(binary.is_file(), "sing-box executable does not exist");
        let directory = Directory::new();
        let reserved = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = reserved.local_addr().unwrap();
        let mut transport = json!({"type":"ws", "path":PATH, "max_early_data":limit});
        if let Some(header) = placement.header() {
            transport["early_data_header_name"] = json!(header);
        }
        let mut inbound = json!({"type":protocol.name(), "listen":"127.0.0.1", "listen_port":address.port(), "users":protocol.users(), "transport":transport});
        let tls = if tls {
            let rcgen::CertifiedKey { cert, signing_key } =
                rcgen::generate_simple_self_signed(vec![SERVER_NAME.to_owned()]).unwrap();
            let certificate = cert.pem();
            let cert_path = directory.0.join("server.pem");
            let key_path = directory.0.join("server.key");
            std::fs::write(&cert_path, &certificate).unwrap();
            std::fs::write(&key_path, signing_key.serialize_pem()).unwrap();
            inbound["tls"] = json!({"enabled":true, "certificate_path":cert_path, "key_path":key_path, "alpn":["http/1.1"]});
            let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
            let mut server_config =
                rustls::ServerConfig::builder_with_provider(Arc::clone(&provider))
                    .with_safe_default_protocol_versions()
                    .unwrap()
                    .with_no_client_auth()
                    .with_single_cert(
                        vec![cert.der().clone()],
                        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(signing_key.serialize_der())),
                    )
                    .unwrap();
            server_config.alpn_protocols = vec![b"http/1.1".to_vec()];
            let mut roots = rustls::RootCertStore::empty();
            roots.add(cert.der().clone()).unwrap();
            let mut client_config = rustls::ClientConfig::builder_with_provider(provider)
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_root_certificates(roots)
                .with_no_client_auth();
            client_config.alpn_protocols = vec![b"http/1.1".to_vec()];
            Some(TlsFixture {
                certificate,
                acceptor: TlsAcceptor::from(Arc::new(server_config)),
                connector: TlsConnector::from(Arc::new(client_config)),
            })
        } else {
            None
        };
        let config =
            json!({"log":{"level":"error"}, "inbounds":[inbound], "outbounds":[{"type":"direct"}]});
        let path = directory.0.join("server.json");
        std::fs::write(&path, serde_json::to_vec(&config).unwrap()).unwrap();
        let log = std::fs::File::create(directory.0.join("server.log")).unwrap();
        drop(reserved);
        let child = Command::new(binary)
            .args(["run", "-c"])
            .arg(path)
            .stdin(Stdio::null())
            .stdout(Stdio::from(log.try_clone().unwrap()))
            .stderr(Stdio::from(log))
            .kill_on_drop(true)
            .spawn()
            .expect("start sing-box");
        let mut fixture = Self {
            child,
            directory,
            address,
            tls,
        };
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if let Some(status) = fixture.child.try_wait().unwrap() {
                panic!("sing-box exited before readiness: {status}");
            }
            if TcpStream::connect(address).await.is_ok() {
                return fixture;
            }
            assert!(Instant::now() < deadline, "sing-box readiness timed out");
            sleep(Duration::from_millis(20)).await;
        }
    }
}

impl Drop for SingBox {
    fn drop(&mut self) {
        let _ = self.child.start_kill();
        if std::thread::panicking() {
            eprintln!(
                "sing-box fixture log:\n{}",
                std::fs::read_to_string(self.directory.0.join("server.log")).unwrap_or_default()
            );
        }
    }
}

/// Observe the decrypted HTTP upgrade without replacing the sing-box peer.
/// TLS cases terminate and re-establish TLS locally with the ephemeral fixture certificate.
struct Interceptor {
    address: SocketAddr,
    received: mpsc::UnboundedReceiver<usize>,
    task: JoinHandle<()>,
}

impl Interceptor {
    async fn start(peer: &SingBox, placement: Placement, limit: u32) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let destination = peer.address;
        let tls = peer.tls.clone();
        let (send, received) = mpsc::unbounded_channel();
        let task = tokio::spawn(async move {
            let mut connections = JoinSet::new();
            loop {
                tokio::select! {
                    result = listener.accept() => {
                        let (client, _) = result.unwrap();
                        let tls = tls.clone();
                        let send = send.clone();
                        connections.spawn(async move {
                            let mut client: BoxedTransitConnection = if let Some(tls) = &tls {
                                Box::new(tls.acceptor.accept(client).await.expect("client TLS"))
                            } else { Box::new(client) };
                            let target = TcpStream::connect(destination).await.expect("sing-box TCP");
                            let mut target: BoxedTransitConnection = if let Some(tls) = &tls {
                                Box::new(tls.connector.connect(ServerName::try_from(SERVER_NAME).unwrap(), target).await.expect("sing-box TLS"))
                            } else { Box::new(target) };
                            let mut request = Vec::new();
                            while !request.ends_with(b"\r\n\r\n") {
                                request.push(client.read_u8().await.expect("WebSocket request"));
                                assert!(request.len() < 16 * 1024, "oversized test request");
                            }
                            let text = std::str::from_utf8(&request).unwrap();
                            let mut lines = text.lines();
                            let target_path = lines.next().unwrap().split_whitespace().nth(1).unwrap();
                            let encoded = if let Some(header) = placement.header() {
                                assert_eq!(target_path, PATH);
                                lines.find_map(|line| {
                                    let (name, value) = line.split_once(':')?;
                                    name.eq_ignore_ascii_case(header).then(|| value.trim())
                                }).expect("early-data header was not sent")
                            } else {
                                target_path.strip_prefix(PATH).expect("incorrect WebSocket path")
                            };
                            let early = URL_SAFE_NO_PAD.decode(encoded).expect("invalid Base64URL early data");
                            assert!(!early.is_empty(), "WebSocket upgrade omitted early data");
                            assert!(early.len() <= limit as usize, "early data exceeded limit");
                            if matches!(limit, 8 | 56) { assert_eq!(early.len(), limit as usize, "native protocol header must span the early-data boundary"); }
                            else { assert!(early.len() > 8, "native protocol header unexpectedly short"); }
                            send.send(early.len()).unwrap();
                            target.write_all(&request).await.expect("forward upgrade");
                            target.flush().await.unwrap();
                            let _ = tokio::io::copy_bidirectional(&mut client, &mut target).await;
                        });
                    }
                    completed = connections.join_next(), if !connections.is_empty() => {
                        if let Some(Err(error)) = completed { panic!("WebSocket observer task failed: {error}"); }
                    }
                }
            }
        });
        Self {
            address,
            received,
            task,
        }
    }
}
impl Drop for Interceptor {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn adapter(
    protocol: Protocol,
    peer: &SingBox,
    address: SocketAddr,
    placement: Placement,
    limit: u32,
) -> Arc<dyn TransitAdapter> {
    let config = TransitProxyConfig {
        id: TransitProxyId::new("websocket-early-peer"),
        source: None,
        protocol: protocol.name().into(),
        endpoint: PolicyEndpoint {
            host: address.ip().to_string(),
            port: address.port(),
        },
        credentials_ref: None,
        labels: BTreeMap::new(),
        tags: BTreeSet::new(),
        weight: 100,
        options: TransitOptions {
            tls: peer.tls.as_ref().map(|tls| TransitTls {
                enabled: true,
                server_name: Some(SERVER_NAME.into()),
                truststore: Vec::new(),
                certificate: vec![tls.certificate.clone()],
                alpn: vec!["http/1.1".into()],
                ..Default::default()
            }),
            transport: Some(TransitTransport {
                kind: "ws".into(),
                path: Some(PATH.into()),
                max_early_data: Some(limit),
                early_data_header_name: placement.header().map(str::to_owned),
                ..Default::default()
            }),
            udp: Some(true),
            packet_encoding: matches!(protocol, Protocol::Vless).then(|| "xudp".to_owned()),
            ..Default::default()
        },
    };
    let tls = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_root_certificates(rustls::RootCertStore::empty())
    .with_no_client_auth();
    AdapterRegistry::new(
        Arc::new(NoTransitCredentials),
        Duration::from_secs(5),
        Arc::new(tls),
    )
    .build_with_credential(&config, &protocol.credentials())
    .expect("build adapter")
}

fn destination(port: u16) -> ConnectRequest {
    ConnectRequest {
        destination: Endpoint {
            host: "127.0.0.1".into(),
            port,
        },
    }
}

async fn round_trip(protocol: Protocol, placement: Placement, tls: bool, limit: u32) {
    let peer = SingBox::start(protocol, placement, tls, limit).await;
    let mut interceptor = Interceptor::start(&peer, placement, limit).await;
    let adapter = adapter(protocol, &peer, interceptor.address, placement, limit);
    let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = tcp.local_addr().unwrap().port();
    let upload: Vec<u8> = (0..131_333).map(|i| (i % 251) as u8).collect();
    let download: Vec<u8> = (0..148_777).map(|i| (i % 239) as u8).collect();
    let server = async {
        let (mut stream, _) = tcp.accept().await.unwrap();
        let mut data = vec![0; upload.len()];
        stream
            .read_exact(&mut data)
            .await
            .expect("target TCP upload");
        assert!(
            data == upload,
            "TCP upload differs: {protocol:?}/{placement:?}/tls={tls}/limit={limit}"
        );
        stream
            .write_all(&download)
            .await
            .expect("target TCP download");
        stream.flush().await.unwrap();
    };
    let client = async {
        let mut stream = adapter
            .connect(destination(port))
            .await
            .expect("open TCP adapter");
        stream
            .write_all(&upload)
            .await
            .expect("large first TCP write");
        stream.flush().await.unwrap();
        let mut data = vec![0; download.len()];
        stream
            .read_exact(&mut data)
            .await
            .expect("client TCP download");
        assert!(
            data == download,
            "TCP download differs: {protocol:?}/{placement:?}/tls={tls}/limit={limit}"
        );
    };
    tokio::join!(server, client);
    assert!(
        interceptor.received.recv().await.is_some(),
        "TCP early-data observation missing"
    );

    let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let port = udp.local_addr().unwrap().port();
    let packets = [
        vec![0x41],
        vec![0x62; 1400],
        (0..4096).map(|i| (i % 241) as u8).collect(),
    ];
    let server = async {
        for expected in &packets {
            let mut data = vec![0; 8192];
            let (length, source) = udp.recv_from(&mut data).await.unwrap();
            assert_eq!(&data[..length], expected);
            udp.send_to(&data[..length], source).await.unwrap();
        }
    };
    let client = async {
        assert!(adapter.supports_udp());
        let mut socket = adapter
            .connect_udp(destination(port))
            .await
            .expect("open UDP adapter");
        for payload in &packets {
            socket.send(payload).await.expect("send UDP");
            assert_eq!(socket.receive().await.expect("receive UDP"), *payload);
        }
        socket.close().await.expect("close UDP association");
    };
    tokio::join!(server, client);
    assert!(
        interceptor.received.recv().await.is_some(),
        "UDP early-data observation missing"
    );
}

macro_rules! interop_test {
    ($name:ident, $protocol:expr, $placement:expr, $tls:expr) => {
        #[tokio::test]
        #[ignore = "requires PATHCHORD_TEST_SING_BOX"]
        async fn $name() {
            let limits = if matches!($protocol, Protocol::Trojan) {
                [56, 2048]
            } else {
                [8, 2048]
            };
            for limit in limits {
                timeout(TEST_TIMEOUT, round_trip($protocol, $placement, $tls, limit))
                    .await
                    .expect("sing-box WebSocket early-data test timed out");
            }
        }
    };
}

interop_test!(vless_ws_path, Protocol::Vless, Placement::Path, false);
interop_test!(vless_wss_path, Protocol::Vless, Placement::Path, true);
interop_test!(
    vless_ws_protocol_header,
    Protocol::Vless,
    Placement::ProtocolHeader,
    false
);
interop_test!(
    vless_wss_protocol_header,
    Protocol::Vless,
    Placement::ProtocolHeader,
    true
);
interop_test!(
    vless_ws_custom_header,
    Protocol::Vless,
    Placement::CustomHeader,
    false
);
interop_test!(
    vless_wss_custom_header,
    Protocol::Vless,
    Placement::CustomHeader,
    true
);
interop_test!(vmess_ws_path, Protocol::Vmess, Placement::Path, false);
interop_test!(vmess_wss_path, Protocol::Vmess, Placement::Path, true);
interop_test!(
    vmess_ws_protocol_header,
    Protocol::Vmess,
    Placement::ProtocolHeader,
    false
);
interop_test!(
    vmess_wss_protocol_header,
    Protocol::Vmess,
    Placement::ProtocolHeader,
    true
);
interop_test!(
    vmess_ws_custom_header,
    Protocol::Vmess,
    Placement::CustomHeader,
    false
);
interop_test!(
    vmess_wss_custom_header,
    Protocol::Vmess,
    Placement::CustomHeader,
    true
);
interop_test!(trojan_wss_path, Protocol::Trojan, Placement::Path, true);
interop_test!(
    trojan_wss_protocol_header,
    Protocol::Trojan,
    Placement::ProtocolHeader,
    true
);
interop_test!(
    trojan_wss_custom_header,
    Protocol::Trojan,
    Placement::CustomHeader,
    true
);

#[tokio::test]
#[ignore = "requires PATHCHORD_TEST_SING_BOX"]
async fn sing_box_trojan_rejects_early_data_shorter_than_the_password_digest() {
    for placement in [
        Placement::Path,
        Placement::ProtocolHeader,
        Placement::CustomHeader,
    ] {
        timeout(TEST_TIMEOUT, async {
            let peer = SingBox::start(Protocol::Trojan, placement, true, 8).await;
            let mut interceptor = Interceptor::start(&peer, placement, 8).await;
            let adapter = adapter(Protocol::Trojan, &peer, interceptor.address, placement, 8);
            let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let result = adapter
                .connect(destination(tcp.local_addr().unwrap().port()))
                .await;
            if let Ok(mut stream) = result {
                let mut byte = [0];
                assert!(!matches!(stream.read(&mut byte).await, Ok(length) if length > 0));
            }
            assert_eq!(interceptor.received.recv().await, Some(8));
            let deadline = Instant::now() + Duration::from_secs(2);
            loop {
                let log = std::fs::read_to_string(peer.directory.0.join("server.log"))
                    .unwrap_or_default();
                if log.contains("bad request size") {
                    break;
                }
                assert!(
                    Instant::now() < deadline,
                    "sing-box did not record its short-read rejection"
                );
                sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("sing-box Trojan short-early-data test timed out");
    }
}
