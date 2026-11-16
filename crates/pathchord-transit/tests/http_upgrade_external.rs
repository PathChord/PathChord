//! HTTPUpgrade interoperability through the public Transit adapter registry.
//!
//! The independent peer cases require `PATHCHORD_TEST_SING_BOX` and can be
//! run with `cargo test -p pathchord-transit --test http_upgrade_external
//! -- --ignored`. The test executable is never a runtime dependency.

use std::{
    collections::{BTreeMap, BTreeSet},
    net::SocketAddr,
    path::PathBuf,
    process::Stdio,
    sync::Arc,
    time::Duration,
};

use pathchord_policy::{
    Endpoint as PolicyEndpoint, TransitOptions, TransitProxyConfig, TransitProxyId, TransitTls,
    TransitTransport,
};
use pathchord_transit::{
    AdapterRegistry, ConnectRequest, Endpoint, NoTransitCredentials, TransitAdapter,
    TransitCredential, TransitError,
};
use serde_json::{Value, json};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    process::{Child, Command},
    time::{Instant, sleep, timeout},
};

const UUID: &str = "6cbf3f72-3417-4922-bde6-67820d041f25";
const PASSWORD: &str = "pathchord-httpupgrade-test";
const PATH: &str = "/pathchord/upgrade";
const REQUEST_PATH: &str = "/pathchord/upgrade?probe=1";
const HOST: &str = "front.pathchord.test";
const SERVER_NAME: &str = "tls.pathchord.test";
const HEADER_NAME: &str = "X-Pathchord-Fixture";
const HEADER_VALUE: &str = "header-through-upgrade";
const TEST_TIMEOUT: Duration = Duration::from_secs(20);

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
                .map(|(name, value)| (name.to_owned(), value.to_owned()))
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

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new() -> Self {
        let mut suffix = [0; 8];
        getrandom::fill(&mut suffix).unwrap();
        let path = std::env::temp_dir().join(format!(
            "pathchord-httpupgrade-{}-{:016x}",
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

struct SingBox {
    child: Child,
    directory: TestDirectory,
    port: u16,
    certificate: Option<String>,
}

impl SingBox {
    async fn start(protocol: Protocol, tls: bool) -> Self {
        let binary = PathBuf::from(
            std::env::var_os("PATHCHORD_TEST_SING_BOX")
                .expect("PATHCHORD_TEST_SING_BOX must name a local sing-box executable"),
        );
        assert!(binary.is_file(), "sing-box executable does not exist");
        let directory = TestDirectory::new();
        let reserved = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = reserved.local_addr().unwrap().port();
        let mut inbound = json!({
            "type": protocol.name(),
            "listen": "127.0.0.1",
            "listen_port": port,
            "users": protocol.users(),
            "transport": {"type": "httpupgrade", "host": HOST, "path": PATH}
        });
        let certificate = if tls {
            let rcgen::CertifiedKey { cert, signing_key } =
                rcgen::generate_simple_self_signed(vec![SERVER_NAME.to_owned()]).unwrap();
            let certificate = cert.pem();
            let certificate_path = directory.0.join("server.pem");
            let key_path = directory.0.join("server.key");
            std::fs::write(&certificate_path, &certificate).unwrap();
            std::fs::write(&key_path, signing_key.serialize_pem()).unwrap();
            inbound["tls"] = json!({
                "enabled": true,
                "certificate_path": certificate_path,
                "key_path": key_path,
                "alpn": ["http/1.1"]
            });
            Some(certificate)
        } else {
            None
        };
        let config = json!({
            "log": {"level": "error"},
            "inbounds": [inbound],
            "outbounds": [{"type": "direct"}]
        });
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
            .expect("start sing-box");
        let mut fixture = Self {
            child,
            directory,
            port,
            certificate,
        };
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if let Some(status) = fixture.child.try_wait().unwrap() {
                panic!("sing-box exited during startup: {status}");
            }
            if TcpStream::connect(("127.0.0.1", port)).await.is_ok() {
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

fn adapter(
    protocol: Protocol,
    proxy: SocketAddr,
    certificate: Option<&str>,
    path: &str,
    host: &str,
) -> Arc<dyn TransitAdapter> {
    let config = TransitProxyConfig {
        id: TransitProxyId::new("httpupgrade-peer"),
        source: None,
        protocol: protocol.name().to_owned(),
        endpoint: PolicyEndpoint {
            host: proxy.ip().to_string(),
            port: proxy.port(),
        },
        credentials_ref: None,
        labels: BTreeMap::new(),
        tags: BTreeSet::new(),
        weight: 100,
        options: TransitOptions {
            tls: certificate.map(|certificate| TransitTls {
                enabled: true,
                server_name: Some(SERVER_NAME.to_owned()),
                truststore: Vec::new(),
                certificate: vec![certificate.to_owned()],
                alpn: vec!["http/1.1".to_owned()],
                ..Default::default()
            }),
            transport: Some(TransitTransport {
                kind: "httpupgrade".to_owned(),
                path: Some(path.to_owned()),
                host: vec![host.to_owned()],
                headers: BTreeMap::from([(HEADER_NAME.to_owned(), HEADER_VALUE.to_owned())]),
                ..Default::default()
            }),
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

async fn relay_round_trip(protocol: Protocol, tls: bool) {
    let peer = SingBox::start(protocol, tls).await;
    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target_port = target.local_addr().unwrap().port();
    let upload: Vec<u8> = (0..131_333).map(|i| (i % 251) as u8).collect();
    let download: Vec<u8> = (0..148_777).map(|i| (i % 239) as u8).collect();
    let proxy = SocketAddr::from(([127, 0, 0, 1], peer.port));
    let client = adapter(
        protocol,
        proxy,
        peer.certificate.as_deref(),
        REQUEST_PATH,
        HOST,
    );
    let server = async {
        let (mut stream, _) = target.accept().await.unwrap();
        let (mut reader, mut writer) = stream.split();
        let (read, written) = tokio::join!(
            async {
                let mut data = vec![0; upload.len()];
                reader.read_exact(&mut data).await?;
                Ok::<_, std::io::Error>(data)
            },
            writer.write_all(&download)
        );
        written.unwrap();
        assert_eq!(read.unwrap(), upload, "{protocol:?} upload");
    };
    let client = async {
        let stream = client.connect(destination(target_port)).await.unwrap();
        let (mut reader, mut writer) = tokio::io::split(stream);
        let (written, read) = tokio::join!(
            async {
                writer.write_all(&upload).await?;
                writer.flush().await
            },
            async {
                let mut data = vec![0; download.len()];
                reader.read_exact(&mut data).await?;
                Ok::<_, std::io::Error>(data)
            }
        );
        written.unwrap();
        assert_eq!(read.unwrap(), download, "{protocol:?} download");
    };
    timeout(TEST_TIMEOUT, async { tokio::join!(server, client) })
        .await
        .expect("HTTPUpgrade round trip timed out");

    let udp_target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let udp_port = udp_target.local_addr().unwrap().port();
    let udp_client = adapter(
        protocol,
        proxy,
        peer.certificate.as_deref(),
        REQUEST_PATH,
        HOST,
    );
    let server = async {
        let mut data = [0; 2048];
        for _ in 0..2 {
            let (length, source) = udp_target.recv_from(&mut data).await.unwrap();
            udp_target.send_to(&data[..length], source).await.unwrap();
        }
    };
    let client = async {
        let mut socket = udp_client.connect_udp(destination(udp_port)).await.unwrap();
        for payload in [b"httpupgrade-udp".as_slice(), &[0x65; 1400]] {
            socket.send(payload).await.unwrap();
            assert_eq!(socket.receive().await.unwrap(), payload);
        }
        socket.close().await.unwrap();
    };
    timeout(TEST_TIMEOUT, async { tokio::join!(server, client) })
        .await
        .expect("HTTPUpgrade UDP round trip timed out");

    for (path, host) in [
        ("/incorrect-path", HOST),
        (REQUEST_PATH, "incorrect.pathchord.test"),
    ] {
        let client = adapter(protocol, proxy, peer.certificate.as_deref(), path, host);
        let result = timeout(TEST_TIMEOUT, client.connect(destination(target_port)))
            .await
            .expect("rejected peer handshake timed out");
        assert!(
            matches!(result, Err(TransitError::Protocol(_))),
            "sing-box must reject incorrect path or host for {protocol:?}"
        );
    }
}

#[tokio::test]
#[ignore = "requires PATHCHORD_TEST_SING_BOX"]
async fn sing_box_httpupgrade_transports_relay_tcp_and_udp() {
    for (protocol, tls) in [
        (Protocol::Vless, false),
        (Protocol::Vless, true),
        (Protocol::Vmess, false),
        (Protocol::Vmess, true),
        (Protocol::Trojan, true),
    ] {
        relay_round_trip(protocol, tls).await;
    }
}

async fn read_request<S: AsyncRead + Unpin>(stream: &mut S) -> String {
    let mut request = Vec::new();
    while request.len() < 16 * 1024 && !request.ends_with(b"\r\n\r\n") {
        request.push(stream.read_u8().await.unwrap());
    }
    String::from_utf8(request).unwrap()
}

async fn respond_invalid<S: AsyncRead + AsyncWrite + Unpin>(mut stream: S, response: &[u8]) {
    let request = read_request(&mut stream).await;
    assert!(request.starts_with(&format!("GET {REQUEST_PATH} HTTP/1.1\r\n")));
    let headers = request.to_ascii_lowercase();
    assert!(headers.contains(&format!("host: {HOST}\r\n")));
    assert!(headers.contains(&format!(
        "{}: {HEADER_VALUE}\r\n",
        HEADER_NAME.to_ascii_lowercase()
    )));
    stream.write_all(response).await.unwrap();
    stream.flush().await.unwrap();
}

fn tls_fixture() -> (String, tokio_rustls::TlsAcceptor) {
    use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};

    let rcgen::CertifiedKey { cert, signing_key } =
        rcgen::generate_simple_self_signed(vec![SERVER_NAME.to_owned()]).unwrap();
    let certificate = cert.pem();
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(signing_key.serialize_der()));
    let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(vec![cert.der().clone()], key)
    .unwrap();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    (
        certificate,
        tokio_rustls::TlsAcceptor::from(Arc::new(config)),
    )
}

#[tokio::test]
async fn configured_headers_are_sent_over_each_supported_transport() {
    for (protocol, tls) in [
        (Protocol::Vless, false),
        (Protocol::Vless, true),
        (Protocol::Vmess, false),
        (Protocol::Vmess, true),
        (Protocol::Trojan, true),
    ] {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let tls = tls.then(tls_fixture);
        let client = adapter(
            protocol,
            listener.local_addr().unwrap(),
            tls.as_ref().map(|(certificate, _)| certificate.as_str()),
            REQUEST_PATH,
            HOST,
        );
        let server = async {
            let (stream, _) = listener.accept().await.unwrap();
            let response = b"HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n";
            if let Some((_, acceptor)) = tls {
                respond_invalid(acceptor.accept(stream).await.unwrap(), response).await;
            } else {
                respond_invalid(stream, response).await;
            }
        };
        let connect = client.connect(destination(8080));
        let ((), result) = timeout(TEST_TIMEOUT, async { tokio::join!(server, connect) })
            .await
            .expect("request capture timed out");
        assert!(matches!(result, Err(TransitError::Protocol(_))));
    }
}

#[tokio::test]
async fn rejects_invalid_responses_and_sends_configured_request() {
    for response in [
        b"HTTP/1.1 403 Forbidden\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n".as_slice(),
        b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n".as_slice(),
        b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\n\r\n".as_slice(),
        b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: h2c\r\n\r\n"
            .as_slice(),
        b"HTTP/1.1 1010 Invalid\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n".as_slice(),
    ] {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let client = adapter(
            Protocol::Vless,
            listener.local_addr().unwrap(),
            None,
            REQUEST_PATH,
            HOST,
        );
        let server = async {
            let (stream, _) = listener.accept().await.unwrap();
            respond_invalid(stream, response).await;
        };
        let connect = client.connect(destination(8080));
        let ((), result) = timeout(TEST_TIMEOUT, async { tokio::join!(server, connect) })
            .await
            .expect("invalid handshake timed out");
        assert!(matches!(result, Err(TransitError::Protocol(_))));
    }
}
