//! Native dae-compatible Meek transport against an independent V2Fly server.

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
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    process::{Child, Command},
    time::{sleep, timeout},
};

const UUID: &str = "6cbf3f72-3417-4922-bde6-67820d041f25";

#[derive(Clone, Copy, Debug)]
enum Protocol {
    Vless,
    Vmess,
}

impl Protocol {
    fn name(self) -> &'static str {
        match self {
            Self::Vless => "vless",
            Self::Vmess => "vmess",
        }
    }
    fn credentials(self, url: &str) -> TransitCredential {
        let mut fields = BTreeMap::from([
            ("uuid".into(), UUID.into()),
            ("meek_url".into(), url.into()),
        ]);
        if matches!(self, Self::Vmess) {
            fields.insert("security".into(), "aes-128-gcm".into());
            fields.insert("alter_id".into(), "0".into());
        }
        TransitCredential::new(fields)
    }
}

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new() -> Self {
        let mut random = [0; 8];
        getrandom::fill(&mut random).unwrap();
        let path = std::env::temp_dir().join(format!(
            "pathchord-meek-{}-{:016x}",
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
    async fn start(protocol: Protocol) -> Self {
        let binary =
            std::env::var_os("PATHCHORD_TEST_V2FLY").expect("PATHCHORD_TEST_V2FLY is required");
        let directory = TestDirectory::new();
        let reserved = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = reserved.local_addr().unwrap().port();
        drop(reserved);
        let rcgen::CertifiedKey { cert, signing_key } =
            rcgen::generate_simple_self_signed(vec!["meek.test".into()]).unwrap();
        let certificate = cert.pem();
        let cert_path = directory.0.join("server.pem");
        let key_path = directory.0.join("server.key");
        std::fs::write(&cert_path, &certificate).unwrap();
        std::fs::write(&key_path, signing_key.serialize_pem()).unwrap();
        let document = json!({
            "log": {"error": {"level":"Error", "type":"Console"}, "access":{"type":"None"}},
            "outbounds": [{"protocol":"freedom"}],
            "inbounds": [{"listen":"127.0.0.1", "port":port, "protocol":protocol.name(),
                "settings":{"users":[UUID]}, "streamSettings":{
                    "transport":"meek", "transportSettings":{"url":format!("http://127.0.0.1:{port}/tunnel")},
                    "security":"tls", "securitySettings":{"certificate":[{"usage":"ENCIPHERMENT","certificateFile":cert_path,"keyFile":key_path}]}
                }}]
        });
        let config = directory.0.join("config.json");
        std::fs::write(&config, serde_json::to_vec(&document).unwrap()).unwrap();
        let mut child = Command::new(binary)
            .args(["run", "-format=jsonv5", "-c"])
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
                    "V2Fly Meek server exited"
                );
                if TcpStream::connect(("127.0.0.1", port)).await.is_ok() {
                    break;
                }
                sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("V2Fly Meek server startup timed out");
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

fn node(server: &Server, alpn: &str) -> TransitProxyConfig {
    TransitProxyConfig {
        id: TransitProxyId::new("meek-test"),
        source: None,
        protocol: "vless".into(),
        endpoint: PolicyEndpoint {
            host: "meek.test".into(),
            port: server.port,
        },
        credentials_ref: None,
        labels: Default::default(),
        tags: Default::default(),
        weight: 1,
        options: TransitOptions {
            tls: Some(TransitTls {
                enabled: true,
                certificate: vec![server.certificate.clone()],
                alpn: vec![alpn.into()],
                ..Default::default()
            }),
            transport: Some(TransitTransport {
                kind: "meek".into(),
                ..Default::default()
            }),
            ..Default::default()
        },
    }
}

fn build_vless(node: &TransitProxyConfig, url: &str) -> Arc<dyn TransitAdapter> {
    AdapterRegistry::for_configs(
        Arc::new(NoTransitCredentials),
        Duration::from_secs(3),
        [node],
    )
    .unwrap()
    .build_with_credential(node, &Protocol::Vless.credentials(url))
    .unwrap()
}

fn adapter(server: &Server, protocol: Protocol, alpn: &str) -> Arc<dyn TransitAdapter> {
    let mut node = node(server, alpn);
    node.protocol = protocol.name().into();
    let url = format!(
        "https://127.0.0.1:{}/tunnel?token=private-test-token",
        server.port
    );
    AdapterRegistry::for_configs(
        Arc::new(NoTransitCredentials),
        Duration::from_secs(5),
        [&node],
    )
    .unwrap()
    .build_with_credential(&node, &protocol.credentials(&url))
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

async fn relay(protocol: Protocol, alpn: &str) {
    let server = Server::start(protocol).await;
    let adapter = adapter(&server, protocol, alpn);
    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = target.local_addr().unwrap();
    let peer = tokio::spawn(async move {
        let (mut stream, _) = target.accept().await.unwrap();
        let mut data = vec![0; 131_333];
        stream.read_exact(&mut data).await.unwrap();
        stream.write_all(&data).await.unwrap();
    });
    let mut stream = adapter.connect(destination(address.port())).await.unwrap();
    let payload: Vec<_> = (0..131_333).map(|index| (index % 251) as u8).collect();
    let (mut reader, mut writer) = tokio::io::split(&mut stream);
    let (sent, received) = tokio::join!(
        async {
            writer.write_all(&payload).await?;
            writer.flush().await
        },
        async {
            let mut response = vec![0; payload.len()];
            reader.read_exact(&mut response).await?;
            Ok::<_, std::io::Error>(response)
        }
    );
    sent.unwrap();
    assert_eq!(received.unwrap(), payload, "{protocol:?} {alpn}");
    drop(reader);
    drop(writer);
    drop(stream);
    peer.await.unwrap();

    let target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = target.local_addr().unwrap();
    let peer = tokio::spawn(async move {
        let mut packet = [0; 2048];
        for _ in 0..2 {
            let (size, source) = target.recv_from(&mut packet).await.unwrap();
            target.send_to(&packet[..size], source).await.unwrap();
        }
    });
    let mut datagram = adapter
        .connect_udp(destination(address.port()))
        .await
        .unwrap();
    for data in [b"meek-udp".as_slice(), &[0x5a; 1400]] {
        datagram.send(data).await.unwrap();
        assert_eq!(
            datagram.receive().await.unwrap(),
            data,
            "{protocol:?} {alpn}"
        );
    }
    datagram.close().await.unwrap();
    peer.await.unwrap();
}

#[tokio::test]
#[ignore = "requires PATHCHORD_TEST_V2FLY pointing to a V2Fly server with jsonv5 Meek support"]
async fn v2fly_meek_relays_vless_and_vmess_tcp_udp_over_http1_and_h2() {
    timeout(Duration::from_secs(90), async {
        for protocol in [Protocol::Vless, Protocol::Vmess] {
            for alpn in ["http/1.1", "h2"] {
                relay(protocol, alpn).await;
            }
        }
    })
    .await
    .expect("V2Fly Meek interoperability timed out");
}

#[tokio::test]
#[ignore = "requires PATHCHORD_TEST_V2FLY pointing to a V2Fly server with jsonv5 Meek support"]
async fn v2fly_meek_rejects_bad_certificate_sni_and_alpn() {
    timeout(Duration::from_secs(15), async {
        let server = Server::start(Protocol::Vless).await;
        let url = format!(
            "https://127.0.0.1:{}/tunnel?token=private-test-token",
            server.port
        );
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = target.local_addr().unwrap().port();
        let mut bad_ca = node(&server, "http/1.1");
        bad_ca.options.tls.as_mut().unwrap().certificate.clear();
        let mut bad_name = node(&server, "http/1.1");
        bad_name.options.tls.as_mut().unwrap().server_name = Some("wrong-meek.test".into());
        let mut bad_alpn = node(&server, "unsupported-alpn");
        bad_alpn
            .options
            .tls
            .as_mut()
            .unwrap()
            .alpn
            .push("http/1.1".into());
        for candidate in [&bad_ca, &bad_name] {
            assert!(
                build_vless(candidate, &url)
                    .connect(destination(port))
                    .await
                    .is_err()
            );
            assert!(
                timeout(Duration::from_millis(100), target.accept())
                    .await
                    .is_err()
            );
        }
        let registry = AdapterRegistry::for_configs(
            Arc::new(NoTransitCredentials),
            Duration::from_secs(2),
            [&bad_alpn],
        )
        .unwrap();
        assert!(
            registry
                .build_with_credential(&bad_alpn, &Protocol::Vless.credentials(&url))
                .is_err()
        );
    })
    .await
    .expect("Meek TLS negative test timed out");
}

#[test]
fn meek_requires_private_https_url_without_unconsumed_public_fields() {
    let base = TransitProxyConfig {
        id: TransitProxyId::new("meek-config-test"),
        source: None,
        protocol: "vless".into(),
        endpoint: PolicyEndpoint {
            host: "example.test".into(),
            port: 443,
        },
        credentials_ref: None,
        labels: Default::default(),
        tags: Default::default(),
        weight: 1,
        options: TransitOptions {
            tls: Some(TransitTls {
                enabled: true,
                ..Default::default()
            }),
            transport: Some(TransitTransport {
                kind: "meek".into(),
                ..Default::default()
            }),
            ..Default::default()
        },
    };
    let build = |node: &TransitProxyConfig, credential: &TransitCredential| {
        AdapterRegistry::for_configs(
            Arc::new(NoTransitCredentials),
            Duration::from_secs(2),
            [node],
        )
        .unwrap()
        .build_with_credential(node, credential)
        .is_ok()
    };
    let valid = Protocol::Vless.credentials("https://example.test/tunnel?token=private");
    assert!(build(&base, &valid));
    let missing = TransitCredential::new(BTreeMap::from([("uuid".into(), UUID.into())]));
    assert!(!build(&base, &missing));
    for url in [
        "http://example.test/",
        "https://user:password@example.test/",
        "https://example.test/#fragment",
    ] {
        assert!(!build(&base, &Protocol::Vless.credentials(url)));
    }
    let mut no_tls = base.clone();
    no_tls.options.tls = None;
    assert!(!build(&no_tls, &valid));
    for field in 0..6 {
        let mut invalid = base.clone();
        let transport = invalid.options.transport.as_mut().unwrap();
        match field {
            0 => transport.path = Some("/private".into()),
            1 => transport.host.push("unused.test".into()),
            2 => {
                transport
                    .headers
                    .insert("x-private".into(), "secret".into());
            }
            3 => transport.max_early_data = Some(1),
            4 => transport.service_name = Some("unused".into()),
            _ => transport.early_data_header_name = Some("x-early".into()),
        }
        assert!(!build(&invalid, &valid));
    }
    let mut ordinary = base.clone();
    ordinary.options.transport = None;
    assert!(!build(&ordinary, &valid));
    let mut trojan = base.clone();
    trojan.protocol = "trojan".into();
    let trojan_credential = TransitCredential::new(BTreeMap::from([
        ("password".into(), "secret".into()),
        ("meek_url".into(), "https://example.test/".into()),
    ]));
    assert!(!build(&trojan, &trojan_credential));
    let vision = TransitCredential::new(BTreeMap::from([
        ("uuid".into(), UUID.into()),
        ("flow".into(), "xtls-rprx-vision".into()),
        ("meek_url".into(), "https://example.test/".into()),
    ]));
    assert!(!build(&base, &vision));
}
