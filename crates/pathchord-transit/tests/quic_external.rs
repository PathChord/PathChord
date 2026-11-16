//! V2Ray QUIC transport validation and sing-box interoperability.

use std::{collections::BTreeMap, path::PathBuf, process::Stdio, sync::Arc, time::Duration};

use pathchord_policy::{
    Endpoint as PolicyEndpoint, TransitOptions, TransitProxyConfig, TransitProxyId, TransitTls,
    TransitTransport,
};
use pathchord_transit::{
    AdapterRegistry, ConnectRequest, Endpoint, NoTransitCredentials, TransitAdapter,
    TransitCredential,
};
use serde_json::json;
use sha2::{Digest, Sha256};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, UdpSocket},
    process::{Child, Command},
    time::{sleep, timeout},
};

const UUID: &str = "6cbf3f72-3417-4922-bde6-67820d041f25";

fn config() -> TransitProxyConfig {
    TransitProxyConfig {
        id: TransitProxyId::new("quic-test"),
        source: None,
        protocol: "vless".into(),
        endpoint: PolicyEndpoint {
            host: "127.0.0.1".into(),
            port: 443,
        },
        credentials_ref: None,
        labels: Default::default(),
        tags: Default::default(),
        weight: 1,
        options: TransitOptions {
            tls: Some(TransitTls {
                enabled: true,
                insecure: true,
                ..Default::default()
            }),
            transport: Some(TransitTransport {
                kind: "quic".into(),
                ..Default::default()
            }),
            ..Default::default()
        },
    }
}

fn credential() -> TransitCredential {
    TransitCredential::new(BTreeMap::from([("uuid".into(), UUID.into())]))
}

fn build(node: &TransitProxyConfig, credentials: &TransitCredential) -> bool {
    AdapterRegistry::for_configs(
        Arc::new(NoTransitCredentials),
        Duration::from_secs(3),
        [node],
    )
    .unwrap()
    .build_with_credential(node, credentials)
    .is_ok()
}

#[test]
fn quic_requires_tls_and_rejects_unconsumed_parameters_and_vision() {
    let base = config();
    assert!(build(&base, &credential()));
    let mut node = base.clone();
    node.options.tls = None;
    assert!(!build(&node, &credential()));
    node.protocol = "trojan".into();
    let trojan = TransitCredential::new(BTreeMap::from([(
        "password".into(),
        "test-password".into(),
    )]));
    assert!(build(&node, &trojan));
    node.options.tls = Some(TransitTls::default());
    assert!(!build(&node, &trojan));
    for field in 0..6 {
        let mut node = base.clone();
        let transport = node.options.transport.as_mut().unwrap();
        match field {
            0 => transport.path = Some("/not-consumed".into()),
            1 => transport.host.push("not-consumed".into()),
            2 => {
                transport.headers.insert("x-test".into(), "value".into());
            }
            3 => transport.service_name = Some("not-consumed".into()),
            4 => transport.max_early_data = Some(1),
            _ => transport.early_data_header_name = Some("x-early".into()),
        }
        assert!(!build(&node, &credential()), "unconsumed field {field}");
    }
    let mut node = base.clone();
    node.options.tls.as_mut().unwrap().fingerprint = Some("chrome".into());
    assert!(!build(&node, &credential()));
    let mut node = base.clone();
    node.options.tls.as_mut().unwrap().reality = Some(pathchord_policy::TransitReality {
        public_key: "Q7VhOFla3pZJiGzjiNfwi3j-QfEr9FOdDpQIiDANtRM".into(),
        short_id: "0123456789abcdef".into(),
    });
    assert!(!build(&node, &credential()));
    for flow in ["xtls-rprx-vision", "xtls-rprx-vision-udp443"] {
        let vision = TransitCredential::new(BTreeMap::from([
            ("uuid".into(), UUID.into()),
            ("flow".into(), flow.into()),
        ]));
        assert!(!build(&base, &vision));
    }
    let mut anytls = base.clone();
    anytls.protocol = "anytls".into();
    let password = TransitCredential::new(BTreeMap::from([(
        "password".into(),
        "test-password".into(),
    )]));
    assert!(!build(&anytls, &password));
}

#[test]
fn quic_transport_preserves_disabled_protocol_udp() {
    let mut node = config();
    node.options.udp = Some(false);
    let adapter = AdapterRegistry::for_configs(
        Arc::new(NoTransitCredentials),
        Duration::from_secs(3),
        [&node],
    )
    .unwrap()
    .build_with_credential(&node, &credential())
    .unwrap();
    assert!(adapter.supports_tcp());
    assert!(!adapter.supports_udp());
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
            Self::Trojan => vec![("password", "pathchord-quic-password")],
        };
        TransitCredential::new(
            fields
                .into_iter()
                .map(|(key, value)| (key.into(), value.into()))
                .collect(),
        )
    }

    fn users(self) -> serde_json::Value {
        match self {
            Self::Vless | Self::Vmess => json!([{ "uuid": UUID }]),
            Self::Trojan => json!([{ "password": "pathchord-quic-password" }]),
        }
    }
}

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new() -> Self {
        let mut random = [0; 8];
        getrandom::fill(&mut random).unwrap();
        let path = std::env::temp_dir().join(format!(
            "pathchord-quic-{}-{:016x}",
            std::process::id(),
            u64::from_ne_bytes(random)
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
    _directory: TestDirectory,
    port: u16,
    certificate: String,
}

impl Server {
    async fn start(protocol: Protocol, alpn: Option<&str>) -> Self {
        let binary =
            std::env::var_os("PATHCHORD_TEST_SING_BOX").expect("PATHCHORD_TEST_SING_BOX required");
        let directory = TestDirectory::new();
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = socket.local_addr().unwrap().port();
        drop(socket);
        let rcgen::CertifiedKey { cert, signing_key } =
            rcgen::generate_simple_self_signed(vec!["quic.test".into()]).unwrap();
        let certificate = cert.pem();
        std::fs::write(directory.0.join("server.pem"), &certificate).unwrap();
        std::fs::write(directory.0.join("server.key"), signing_key.serialize_pem()).unwrap();
        let mut tls = json!({"enabled": true, "certificate_path": directory.0.join("server.pem"), "key_path": directory.0.join("server.key")});
        if let Some(alpn) = alpn {
            tls["alpn"] = json!([alpn]);
        }
        let body = json!({
            "log": {"disabled": true},
            "inbounds": [{"type": protocol.name(), "listen": "127.0.0.1", "listen_port": port,
                "users": protocol.users(), "tls": tls, "transport": {"type":"quic"}}],
            "outbounds": [{"type":"direct", "tag":"direct"}], "route": {"final":"direct"}
        });
        let config = directory.0.join("config.json");
        std::fs::write(&config, serde_json::to_vec(&body).unwrap()).unwrap();
        let mut child = Command::new(binary)
            .args(["run", "-c"])
            .arg(config)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        timeout(Duration::from_secs(5), async {
            loop {
                assert!(
                    child.try_wait().unwrap().is_none(),
                    "sing-box exited before QUIC readiness"
                );
                match std::net::UdpSocket::bind(("127.0.0.1", port)) {
                    Err(error) if error.kind() == std::io::ErrorKind::AddrInUse => break,
                    Ok(socket) => drop(socket),
                    Err(error) => panic!("QUIC readiness bind failed: {error}"),
                }
                sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("sing-box QUIC startup timed out");
        Self {
            child,
            _directory: directory,
            port,
            certificate,
        }
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.start_kill();
    }
}

fn adapter(
    server: &Server,
    protocol: Protocol,
    alpn: Option<&str>,
    trust: bool,
) -> Arc<dyn TransitAdapter> {
    adapter_with_server_name(server, protocol, alpn, trust, "quic.test")
}

fn adapter_with_server_name(
    server: &Server,
    protocol: Protocol,
    alpn: Option<&str>,
    trust: bool,
    server_name: &str,
) -> Arc<dyn TransitAdapter> {
    let mut node = config();
    node.protocol = protocol.name().into();
    node.endpoint.port = server.port;
    node.options.tls = Some(TransitTls {
        enabled: true,
        server_name: Some(server_name.into()),
        certificate: if trust {
            vec![server.certificate.clone()]
        } else {
            Vec::new()
        },
        alpn: alpn.map(|value| vec![value.into()]).unwrap_or_default(),
        ..Default::default()
    });
    AdapterRegistry::for_configs(
        Arc::new(NoTransitCredentials),
        Duration::from_secs(3),
        [&node],
    )
    .unwrap()
    .build_with_credential(&node, &protocol.credentials())
    .unwrap()
}

fn destination(port: u16) -> ConnectRequest {
    ConnectRequest {
        destination: Endpoint {
            host: "127.0.0.1".into(),
            port,
        },
    }
}

async fn relay(protocol: Protocol) {
    let server = Server::start(protocol, None).await;
    let adapter = adapter(&server, protocol, None, true);
    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = target.local_addr().unwrap();
    let target_task = tokio::spawn(async move {
        let (mut stream, _) = target.accept().await.unwrap();
        let mut data = vec![0; 131_333];
        stream.read_exact(&mut data).await.unwrap();
        stream.write_all(&data).await.unwrap();
    });
    let mut stream = adapter.connect(destination(address.port())).await.unwrap();
    let payload: Vec<_> = (0..131_333).map(|i| (i % 251) as u8).collect();
    let (mut reader, mut writer) = tokio::io::split(&mut stream);
    let (sent, received) = tokio::join!(
        async {
            writer.write_all(&payload).await?;
            writer.flush().await
        },
        async {
            let mut data = vec![0; payload.len()];
            reader.read_exact(&mut data).await?;
            Ok::<_, std::io::Error>(data)
        }
    );
    sent.unwrap();
    assert_eq!(received.unwrap(), payload, "{protocol:?}");
    drop(reader);
    drop(writer);
    drop(stream);
    target_task.await.unwrap();

    let target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = target.local_addr().unwrap();
    let target_task = tokio::spawn(async move {
        let mut packet = [0; 2048];
        for _ in 0..2 {
            let (size, peer) = target.recv_from(&mut packet).await.unwrap();
            target.send_to(&packet[..size], peer).await.unwrap();
        }
    });
    let mut datagram = adapter
        .connect_udp(destination(address.port()))
        .await
        .unwrap();
    for payload in [b"quic-udp".as_slice(), &[0x5a; 1400]] {
        datagram.send(payload).await.unwrap();
        assert_eq!(datagram.receive().await.unwrap(), payload, "{protocol:?}");
    }
    datagram.close().await.unwrap();
    target_task.await.unwrap();
}

#[tokio::test]
#[ignore = "requires PATHCHORD_TEST_SING_BOX built with QUIC"]
async fn sing_box_quic_transports_relay_tcp_and_udp() {
    timeout(Duration::from_secs(45), async {
        for protocol in [Protocol::Vless, Protocol::Vmess, Protocol::Trojan] {
            relay(protocol).await;
        }
    })
    .await
    .expect("V2Ray QUIC interoperability timed out");
}

#[tokio::test]
#[ignore = "requires PATHCHORD_TEST_SING_BOX built with QUIC"]
async fn sing_box_quic_preserves_tcp_half_close() {
    timeout(Duration::from_secs(30), async {
        for protocol in [Protocol::Vless, Protocol::Vmess, Protocol::Trojan] {
            let server = Server::start(protocol, None).await;
            let adapter = adapter(&server, protocol, None, true);
            let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = target.local_addr().unwrap();
            let target_task = tokio::spawn(async move {
                let (mut stream, _) = target.accept().await.unwrap();
                let mut request = Vec::new();
                stream.read_to_end(&mut request).await.unwrap();
                assert_eq!(request, b"quic-half-close");
                stream.write_all(b"response-after-eof").await.unwrap();
                stream.shutdown().await.unwrap();
            });
            let mut stream = adapter.connect(destination(address.port())).await.unwrap();
            stream.write_all(b"quic-half-close").await.unwrap();
            stream.shutdown().await.unwrap();
            let mut response = Vec::new();
            stream.read_to_end(&mut response).await.unwrap();
            assert_eq!(response, b"response-after-eof", "{protocol:?}");
            target_task.await.unwrap();
        }
    })
    .await
    .expect("V2Ray QUIC half-close timed out");
}

#[tokio::test]
#[ignore = "requires PATHCHORD_TEST_SING_BOX built with QUIC"]
async fn sing_box_quic_honors_custom_alpn_and_rejects_mismatched_tls() {
    timeout(Duration::from_secs(20), async {
        let server = Server::start(Protocol::Vless, Some("pc-quic-test")).await;
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = target.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let (mut stream, _) = target.accept().await.unwrap();
            stream.write_all(b"verified").await.unwrap();
        });
        let valid = adapter(&server, Protocol::Vless, Some("pc-quic-test"), true);
        let mut stream = valid.connect(destination(address.port())).await.unwrap();
        let mut response = [0; 8];
        stream.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"verified");
        task.await.unwrap();
        let bad_alpn = adapter(&server, Protocol::Vless, Some("different-alpn"), true);
        assert!(bad_alpn.connect(destination(address.port())).await.is_err());
        let bad_cert = adapter(&server, Protocol::Vless, Some("pc-quic-test"), false);
        assert!(bad_cert.connect(destination(address.port())).await.is_err());
        let bad_name = adapter_with_server_name(
            &server,
            Protocol::Vless,
            Some("pc-quic-test"),
            true,
            "wrong.quic.test",
        );
        assert!(bad_name.connect(destination(address.port())).await.is_err());
    })
    .await
    .expect("V2Ray QUIC TLS negative checks timed out");
}

#[tokio::test]
#[ignore = "requires PATHCHORD_TEST_SING_BOX built with QUIC"]
async fn sing_box_quic_enforces_certificate_pin_with_explicit_insecure() {
    use rustls::pki_types::{CertificateDer, pem::PemObject};

    timeout(Duration::from_secs(12), async {
        let server = Server::start(Protocol::Vless, None).await;
        let certificate = CertificateDer::from_pem_slice(server.certificate.as_bytes()).unwrap();
        let mut digest = Sha256::digest(certificate.as_ref()).to_vec();
        let hex = |bytes: &[u8]| {
            bytes
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        };
        let valid_pin = hex(&digest);
        digest[0] ^= 1;
        let wrong_pin = hex(&digest);
        let build_pinned = |pin: String| {
            let mut node = config();
            node.endpoint.port = server.port;
            node.options.tls = Some(TransitTls {
                enabled: true,
                insecure: true,
                server_name: Some("quic.test".into()),
                certificate_sha256: Some(pin),
                ..Default::default()
            });
            AdapterRegistry::for_configs(
                Arc::new(NoTransitCredentials),
                Duration::from_secs(3),
                [&node],
            )
            .unwrap()
            .build_with_credential(&node, &credential())
            .unwrap()
        };
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = target.local_addr().unwrap();
        let peer = tokio::spawn(async move {
            let (mut stream, _) = target.accept().await.unwrap();
            stream.write_all(b"pinned").await.unwrap();
        });
        let mut stream = build_pinned(valid_pin)
            .connect(destination(address.port()))
            .await
            .unwrap();
        let mut response = [0; 6];
        stream.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"pinned");
        peer.await.unwrap();
        assert!(
            build_pinned(wrong_pin)
                .connect(destination(address.port()))
                .await
                .is_err()
        );
    })
    .await
    .expect("QUIC certificate pin checks timed out");
}
