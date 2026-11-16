//! Native Vision interoperability against a local Xray server.
//!
//! Run with `PATHCHORD_TEST_XRAY=/path/to/xray cargo test --locked -p
//! pathchord-transit --test vision_external -- --ignored`.

use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::pin::Pin;
use std::process::Stdio;
use std::sync::Arc;
use std::task::{Context, Poll, ready};
use std::time::Duration;

use pathchord_policy::{
    Endpoint as PolicyEndpoint, TransitOptions, TransitProxyConfig, TransitTls,
};
use pathchord_transit::{
    AdapterRegistry, ConnectRequest, Endpoint, NoTransitCredentials, TransitAdapter,
    TransitCredential, TransitError,
};
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use serde_json::json;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::process::{Child, Command};
use tokio::time::{Instant, sleep, timeout};
use tokio_rustls::{TlsAcceptor, TlsConnector};

const UUID: &str = "6cbf3f72-3417-4922-bde6-67820d041f25";
const VISION: &str = "xtls-rprx-vision";
const VISION_UDP443: &str = "xtls-rprx-vision-udp443";
const TEST_TIMEOUT: Duration = Duration::from_secs(20);
static XRAY_START_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

struct TestDir(PathBuf);

impl TestDir {
    fn new() -> Self {
        let mut random = [0_u8; 8];
        getrandom::fill(&mut random).expect("test directory randomness");
        let suffix = u64::from_ne_bytes(random);
        let path = std::env::temp_dir().join(format!(
            "pathchord-vision-test-{}-{suffix:016x}",
            std::process::id()
        ));
        #[cfg_attr(not(unix), allow(unused_mut))]
        let mut builder = std::fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder
            .create(&path)
            .expect("create private test directory");
        Self(path)
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

struct XrayFixture {
    child: Child,
    directory: TestDir,
    port: u16,
    certificate: String,
}

impl XrayFixture {
    async fn start(redirect: Option<SocketAddr>) -> Self {
        // Keep parallel cases from selecting the same port between releasing
        // the reservation and Xray binding it.
        let _start_lock = XRAY_START_LOCK.lock().await;
        let binary = PathBuf::from(
            std::env::var_os("PATHCHORD_TEST_XRAY").expect("PATHCHORD_TEST_XRAY is required"),
        );
        assert!(binary.is_file(), "PATHCHORD_TEST_XRAY must name a file");
        let directory = TestDir::new();
        let reserve = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = reserve.local_addr().unwrap().port();
        let rcgen::CertifiedKey { cert, signing_key } =
            rcgen::generate_simple_self_signed(vec!["vision.test".to_owned()]).unwrap();
        let certificate = cert.pem();
        let mut freedom = json!({"finalRules": [{"action": "allow"}]});
        if let Some(redirect) = redirect {
            freedom["redirect"] = json!(redirect.to_string());
        }
        let config = json!({
            "log": {"loglevel": "debug"},
            "inbounds": [{
                "listen": "127.0.0.1",
                "port": port,
                "protocol": "vless",
                "settings": {
                    "clients": [{"id": UUID, "flow": VISION}],
                    "decryption": "none"
                },
                "streamSettings": {
                    "network": "tcp",
                    "security": "tls",
                    "tlsSettings": {"certificates": [{
                        "certificate": [certificate],
                        "key": [signing_key.serialize_pem()]
                    }]}
                }
            }],
            "outbounds": [{"protocol": "freedom", "settings": freedom}]
        });
        let config_path = directory.0.join("server.json");
        std::fs::write(&config_path, serde_json::to_vec(&config).unwrap()).unwrap();
        let log = std::fs::File::create(directory.0.join("server.log")).unwrap();
        drop(reserve);
        let child = Command::new(binary)
            .arg("run")
            .arg("-c")
            .arg(config_path)
            .stdin(Stdio::null())
            .stdout(Stdio::from(log.try_clone().unwrap()))
            .stderr(Stdio::from(log))
            .kill_on_drop(true)
            .spawn()
            .expect("start Xray");
        let mut fixture = Self {
            child,
            directory,
            port,
            certificate,
        };
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if let Some(status) = fixture.child.try_wait().unwrap() {
                panic!("Xray exited before readiness: {status}");
            }
            if TcpStream::connect(("127.0.0.1", port)).await.is_ok() {
                return fixture;
            }
            assert!(Instant::now() < deadline, "Xray readiness timed out");
            sleep(Duration::from_millis(20)).await;
        }
    }

    fn adapter(&self, flow: &str) -> Arc<dyn TransitAdapter> {
        self.adapter_at(flow, self.port)
    }

    fn adapter_at(&self, flow: &str, port: u16) -> Arc<dyn TransitAdapter> {
        let config = TransitProxyConfig {
            id: pathchord_policy::TransitProxyId::new("xray-vision-test"),
            source: None,
            protocol: "vless".to_owned(),
            endpoint: PolicyEndpoint {
                host: "127.0.0.1".to_owned(),
                port,
            },
            credentials_ref: None,
            labels: BTreeMap::new(),
            tags: BTreeSet::new(),
            weight: 1,
            options: TransitOptions {
                tls: Some(TransitTls {
                    enabled: true,
                    server_name: Some("vision.test".to_owned()),
                    truststore: Vec::new(),
                    certificate: vec![self.certificate.clone()],
                    ..Default::default()
                }),
                udp: Some(true),
                ..Default::default()
            },
        };
        let credentials = TransitCredential::new(BTreeMap::from([
            ("uuid".to_owned(), UUID.to_owned()),
            ("flow".to_owned(), flow.to_owned()),
        ]));
        let client_tls = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(rustls::RootCertStore::empty())
        .with_no_client_auth();
        AdapterRegistry::new(
            Arc::new(NoTransitCredentials),
            Duration::from_secs(5),
            Arc::new(client_tls),
        )
        .build_with_credential(&config, &credentials)
        .expect("build native Vision adapter")
    }

    fn log(&self) -> String {
        std::fs::read_to_string(self.directory.0.join("server.log")).unwrap_or_default()
    }
}

async fn capture_client_tls(peer: u16) -> (u16, Arc<std::sync::Mutex<Vec<u8>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let capture = Arc::new(std::sync::Mutex::new(Vec::new()));
    let recorded = Arc::clone(&capture);
    tokio::spawn(async move {
        let (client, _) = listener.accept().await.unwrap();
        let server = TcpStream::connect(("127.0.0.1", peer)).await.unwrap();
        let (mut client_read, mut client_write) = client.into_split();
        let (mut server_read, mut server_write) = server.into_split();
        let upload = async {
            let mut bytes = [0; 8192];
            loop {
                let count = client_read.read(&mut bytes).await.unwrap();
                if count == 0 {
                    server_write.shutdown().await.unwrap();
                    break;
                }
                recorded.lock().unwrap().extend_from_slice(&bytes[..count]);
                server_write.write_all(&bytes[..count]).await.unwrap();
            }
        };
        let download = async {
            let _ = tokio::io::copy(&mut server_read, &mut client_write).await;
            let _ = client_write.shutdown().await;
        };
        tokio::join!(upload, download);
    });
    (port, capture)
}

fn assert_request_is_one_long_tls_record(capture: &[u8]) {
    let mut rest = capture;
    let mut records = Vec::new();
    while rest.len() >= 5 {
        let size = usize::from(u16::from_be_bytes([rest[3], rest[4]]));
        assert!(rest.len() >= 5 + size, "incomplete captured TLS record");
        records.push((rest[0], size));
        rest = &rest[5 + size..];
    }
    assert!(rest.is_empty(), "incomplete captured TLS record header");
    // VLESS IPv4 request: 44 bytes; first frame: UUID plus five-byte
    // header; TLS 1.3 adds one content-type byte and a 16-byte tag.
    let (kind, size) = records.last().copied().expect("client TLS records");
    assert_eq!(kind, 0x17);
    assert!(
        (44 + 21 + 900 + 17..=44 + 21 + 1399 + 17).contains(&size),
        "request and long Vision frame did not share one TLS record: {records:?}"
    );
}

async fn request_record_roundtrip(flow: &str, server_first: bool) {
    let fixture = XrayFixture::start(None).await;
    let (tap_port, capture) = capture_client_tls(fixture.port).await;
    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target_port = target.local_addr().unwrap().port();

    let mut provider = rustls::crypto::aws_lc_rs::default_provider();
    provider.kx_groups = vec![rustls::crypto::aws_lc_rs::kx_group::X25519];
    let tls = rustls::ClientConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(rustls::RootCertStore::empty())
        .with_no_client_auth();
    let mut inner_tls =
        rustls::ClientConnection::new(Arc::new(tls), ServerName::try_from("inner.test").unwrap())
            .unwrap();
    let mut hello = Vec::new();
    inner_tls.write_tls(&mut hello).unwrap();
    assert!(hello.len() < 900);

    let expected_hello = hello.clone();
    let (accepted, target_ready) = tokio::sync::oneshot::channel();
    let target_task = tokio::spawn(async move {
        let (mut stream, _) = target.accept().await.unwrap();
        let _ = accepted.send(());
        if !server_first {
            let mut received = vec![0; expected_hello.len()];
            stream.read_exact(&mut received).await.unwrap();
            assert_eq!(received, expected_hello);
        }
        stream.write_all(b"response").await.unwrap();
        stream.flush().await.unwrap();
    });
    let adapter = fixture.adapter_at(flow, tap_port);
    let mut stream = adapter.connect(endpoint(target_port)).await.unwrap();
    let started = Instant::now();
    if server_first {
        // The request must reach Xray even before the caller polls the
        // returned stream for reading or writing.
        timeout(Duration::from_secs(2), target_ready)
            .await
            .unwrap()
            .unwrap();
    } else {
        // A real inner TLS ClientHello exercises the long-padding path.
        stream.write_all(&hello).await.unwrap();
        stream.flush().await.unwrap();
    }
    let mut response = [0; 8];
    stream.read_exact(&mut response).await.unwrap();
    assert_eq!(&response, b"response");
    if server_first {
        assert!(started.elapsed() >= Duration::from_millis(400));
    }
    target_task.await.unwrap();
    assert_request_is_one_long_tls_record(&capture.lock().unwrap());
}

impl Drop for XrayFixture {
    fn drop(&mut self) {
        let _ = self.child.start_kill();
        if std::thread::panicking() {
            eprintln!("Xray fixture log:\n{}", self.log());
        }
    }
}

async fn bounded(test: impl Future<Output = ()>) {
    timeout(TEST_TIMEOUT, test).await.expect("test timed out");
}

fn endpoint(port: u16) -> ConnectRequest {
    ConnectRequest {
        destination: Endpoint {
            host: "127.0.0.1".to_owned(),
            port,
        },
    }
}

async fn tcp_roundtrip(flow: &str) {
    let fixture = XrayFixture::start(None).await;
    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = target.local_addr().unwrap().port();
    let upload: Vec<u8> = (0..131_333).map(|i| (i % 251) as u8).collect();
    let download: Vec<u8> = (0..148_777).map(|i| (i % 239) as u8).collect();
    let server = async {
        let (mut stream, _) = target.accept().await.unwrap();
        let mut received = vec![0; upload.len()];
        stream.read_exact(&mut received).await.expect("read upload");
        assert!(received == upload, "TCP upload bytes differ");
        stream.write_all(&download).await.expect("write download");
        stream.flush().await.expect("flush download");
    };
    let client = async {
        let mut stream = fixture.adapter(flow).connect(endpoint(port)).await.unwrap();
        stream.write_all(&upload).await.expect("write upload");
        stream.flush().await.expect("flush upload");
        let mut received = vec![0; download.len()];
        stream
            .read_exact(&mut received)
            .await
            .expect("read download");
        assert!(received == download, "TCP download bytes differ");
    };
    tokio::join!(server, client);
}

async fn udp_roundtrip(flow: &str, port_443: bool) {
    let target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = target.local_addr().unwrap();
    let fixture = XrayFixture::start(port_443.then_some(address)).await;
    let port = if port_443 { 443 } else { address.port() };
    let large = vec![0x5a; 8192];
    let packets: [&[u8]; 5] = [b"first", b"second packet", b"third", b"last packet", &large];
    let server = async {
        for expected in packets {
            let mut buffer = [0_u8; 8192];
            let (size, peer) = target.recv_from(&mut buffer).await.unwrap();
            assert_eq!(&buffer[..size], expected);
            target.send_to(&buffer[..size], peer).await.unwrap();
        }
    };
    let client = async {
        let adapter = fixture.adapter(flow);
        assert!(adapter.supports_udp());
        let mut datagram = adapter.connect_udp(endpoint(port)).await.unwrap();
        for expected in packets {
            datagram.send(expected).await.expect("send XUDP packet");
            assert_eq!(
                datagram.receive().await.expect("receive XUDP packet"),
                expected
            );
        }
        datagram.close().await.expect("close XUDP session");
    };
    tokio::join!(server, client);
}

struct FragmentedIo<S> {
    inner: S,
    limit: usize,
}

impl<S: AsyncRead + Unpin> AsyncRead for FragmentedIo<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        let limit = output.remaining().min(this.limit);
        let count = {
            let mut limited = ReadBuf::new(output.initialize_unfilled_to(limit));
            ready!(Pin::new(&mut this.inner).poll_read(cx, &mut limited))?;
            limited.filled().len()
        };
        output.advance(count);
        Poll::Ready(Ok(()))
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for FragmentedIo<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        Pin::new(&mut this.inner).poll_write(cx, &data[..data.len().min(this.limit)])
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

async fn inner_tls_roundtrip(flow: &str, fragmented: bool, tls13: bool) {
    let fixture = XrayFixture::start(None).await;
    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = target.local_addr().unwrap().port();
    let rcgen::CertifiedKey { cert, signing_key } =
        rcgen::generate_simple_self_signed(vec!["inner.test".to_owned()]).unwrap();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert.der().clone()).unwrap();
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let versions = if tls13 {
        vec![&rustls::version::TLS13]
    } else {
        vec![&rustls::version::TLS12]
    };
    let server_config = rustls::ServerConfig::builder_with_provider(Arc::clone(&provider))
        .with_protocol_versions(&versions)
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.der().clone()],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(signing_key.serialize_der())),
        )
        .unwrap();
    let client_config = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&versions)
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let payload: Vec<u8> = (0..100_123).map(|i| (i % 241) as u8).collect();
    let server = async {
        let (stream, _) = target.accept().await.unwrap();
        let mut stream = TlsAcceptor::from(Arc::new(server_config))
            .accept(stream)
            .await
            .expect("inner TLS server handshake");
        let mut received = vec![0; payload.len()];
        stream
            .read_exact(&mut received)
            .await
            .expect("inner TLS upload");
        assert!(received == payload, "inner TLS upload bytes differ");
        stream
            .write_all(&received)
            .await
            .expect("inner TLS download");
        stream.flush().await.expect("flush inner TLS download");
    };
    let client = async {
        let stream = fixture.adapter(flow).connect(endpoint(port)).await.unwrap();
        let mut stream = TlsConnector::from(Arc::new(client_config))
            .connect(
                ServerName::try_from("inner.test").unwrap(),
                FragmentedIo {
                    inner: stream,
                    limit: if fragmented { 7 } else { usize::MAX },
                },
            )
            .await
            .expect("inner TLS client handshake");
        stream.write_all(&payload).await.expect("inner TLS write");
        stream.flush().await.expect("inner TLS flush");
        let mut received = vec![0; payload.len()];
        stream
            .read_exact(&mut received)
            .await
            .expect("inner TLS read");
        assert!(received == payload, "inner TLS download bytes differ");
    };
    tokio::join!(server, client);
    let log = fixture.log();
    let client_direct = log.lines().any(|line| {
        line.contains("Xtls Unpadding new block")
            && line
                .split_once(" command ")
                .is_some_and(|(_, values)| values.split_whitespace().next() == Some("2"))
    });
    assert_eq!(
        client_direct, tls13,
        "unexpected client Vision DIRECT for inner TLS version: {log}"
    );
    if tls13 && !fragmented {
        assert!(
            log.lines().any(|line| line
                .split_once("XtlsPadding ")
                .is_some_and(|(_, values)| values.split_whitespace().nth(2) == Some("2"))),
            "the real inner TLS session did not exercise Xray Vision DIRECT: {log}"
        );
    }
}

macro_rules! xray_test {
    ($name:ident, $body:expr) => {
        #[tokio::test]
        #[ignore = "requires PATHCHORD_TEST_XRAY pointing to an Xray server binary"]
        async fn $name() {
            bounded($body).await;
        }
    };
}

xray_test!(vision_tcp_large_roundtrip, tcp_roundtrip(VISION));
xray_test!(
    vision_first_tls_hello_shares_the_request_record,
    request_record_roundtrip(VISION, false)
);
xray_test!(
    vision_udp443_server_first_uses_a_long_padded_request_record,
    request_record_roundtrip(VISION_UDP443, true)
);
xray_test!(
    vision_udp443_tcp_large_roundtrip,
    tcp_roundtrip(VISION_UDP443)
);
xray_test!(vision_xudp_multiple_packets, udp_roundtrip(VISION, false));
xray_test!(
    vision_udp443_xudp_multiple_packets,
    udp_roundtrip(VISION_UDP443, false)
);
xray_test!(
    vision_udp443_allows_port_443,
    udp_roundtrip(VISION_UDP443, true)
);
xray_test!(
    vision_inner_tls_direct,
    inner_tls_roundtrip(VISION, false, true)
);
xray_test!(
    vision_fragmented_inner_tls_direct,
    inner_tls_roundtrip(VISION, true, true)
);
xray_test!(
    vision_inner_tls12_does_not_send_direct,
    inner_tls_roundtrip(VISION, false, false)
);
xray_test!(
    vision_udp443_inner_tls_direct,
    inner_tls_roundtrip(VISION_UDP443, false, true)
);

#[tokio::test]
#[ignore = "requires PATHCHORD_TEST_XRAY pointing to an Xray server binary"]
async fn vision_rejects_udp_port_443() {
    bounded(async {
        let fixture = XrayFixture::start(None).await;
        let result = fixture.adapter(VISION).connect_udp(endpoint(443)).await;
        assert!(matches!(result, Err(TransitError::Unsupported(reason)) if reason.contains("443")));
    })
    .await;
}
