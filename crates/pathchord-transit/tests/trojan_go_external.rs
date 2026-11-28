//! Imported Trojan-go links against independent local servers.
//!
//! `PATHCHORD_TEST_TROJAN_GO` selects a full-featured Trojan-Go v0.10.6 for TCP/WS;
//! `PATHCHORD_TEST_SING_BOX` selects the sing-box executable for dae gRPC/HTTPUpgrade.

use std::{collections::BTreeSet, path::PathBuf, process::Stdio, sync::Arc, time::Duration};

use pathchord_policy::{
    SubscriptionConfig, SubscriptionId, SubscriptionSource, SubscriptionSourceType,
};
use pathchord_transit::{
    AdapterRegistry, ConnectRequest, Endpoint, NoTransitCredentials, RefreshOutcome,
    SubscriptionError, SubscriptionFetchRequest, SubscriptionFetcher, SubscriptionManager,
    TransitAdapter,
};
use serde_json::{Value, json};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    process::{Child, Command},
    time::{Instant, sleep, timeout},
};

const PASSWORD: &str = "trojan-go-fixture";
const SNI: &str = "trojan.test";
const SS_PASSWORD: &str = "ss-fixture:colon;semicolon";

struct Fetcher(Vec<u8>);

#[async_trait::async_trait]
impl SubscriptionFetcher for Fetcher {
    async fn fetch(&self, _: SubscriptionFetchRequest) -> Result<Vec<u8>, SubscriptionError> {
        Ok(self.0.clone())
    }
}

async fn imported_adapter(uri: String) -> Arc<dyn TransitAdapter> {
    let subscription = SubscriptionConfig {
        id: SubscriptionId::new("trojan-go-fixture"),
        enabled: true,
        source: SubscriptionSource {
            source_type: SubscriptionSourceType::Auto,
            url: "https://fixture.invalid/subscription".into(),
            credentials_ref: None,
            user_agent: None,
        },
        refresh: Default::default(),
        cache: None,
    };
    let mut manager = SubscriptionManager::new(
        Arc::new(Fetcher(uri.into_bytes())),
        std::env::temp_dir(),
        BTreeSet::from(["trojan".into()]),
    );
    assert!(matches!(
        manager.refresh(&subscription).await,
        RefreshOutcome::Published { .. }
    ));
    let registry = AdapterRegistry::for_configs(
        Arc::new(NoTransitCredentials),
        Duration::from_secs(4),
        manager.snapshot().nodes.values().map(|node| &node.config),
    )
    .unwrap();
    let prepared = manager.snapshot().prepare_adapters(&registry).await;
    manager.commit_prepared_adapters(prepared).unwrap();
    let node = manager
        .snapshot()
        .selectable_nodes()
        .next()
        .expect("Trojan-go node admission");
    manager
        .snapshot()
        .validated_adapter(&node.config.id)
        .unwrap()
}

struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        let mut suffix = [0; 8];
        getrandom::fill(&mut suffix).unwrap();
        let path = std::env::temp_dir().join(format!(
            "pathchord-trojan-go-{}-{:016x}",
            std::process::id(),
            u64::from_ne_bytes(suffix)
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

struct Peer {
    child: Child,
    _directory: Directory,
    port: u16,
}

impl Peer {
    async fn start(
        binary_var: &str,
        transport: &str,
        server_transport: Value,
        encryption: Option<&str>,
    ) -> Self {
        let binary =
            PathBuf::from(std::env::var_os(binary_var).expect("reference peer executable"));
        assert!(binary.is_file());
        let directory = Directory::new();
        let reserve = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = reserve.local_addr().unwrap().port();
        let rcgen::CertifiedKey { cert, signing_key } =
            rcgen::generate_simple_self_signed(vec![SNI.to_owned()]).unwrap();
        let cert_path = directory.0.join("cert.pem");
        let key_path = directory.0.join("key.pem");
        std::fs::write(&cert_path, cert.pem()).unwrap();
        std::fs::write(&key_path, signing_key.serialize_pem()).unwrap();
        let document = if binary_var == "PATHCHORD_TEST_TROJAN_GO" {
            json!({
                "run_type":"server", "local_addr":"127.0.0.1", "local_port":port,
                "remote_addr":"127.0.0.1", "remote_port":9, "disable_http_check":true,
                "password":[PASSWORD],
                "ssl":{"cert":cert_path,"key":key_path},
                "websocket":{"enabled":transport == "ws","host":"front.test","path":"/tunnel"},
                "shadowsocks":{"enabled":encryption.is_some(),"method":encryption.unwrap_or("aes-128-gcm"),"password":SS_PASSWORD},
                "log_level":2
            })
        } else {
            json!({
                "log":{"disabled":true},
                "inbounds":[{"type":"trojan","listen":"127.0.0.1","listen_port":port,
                    "users":[{"password":PASSWORD}],"transport":server_transport,
                    "tls":{"enabled":true,"certificate_path":cert_path,"key_path":key_path}}],
                "outbounds":[{"type":"direct"}]
            })
        };
        let config_path = directory.0.join("server.json");
        std::fs::write(&config_path, serde_json::to_vec(&document).unwrap()).unwrap();
        drop(reserve);
        let mut command = Command::new(binary);
        if binary_var == "PATHCHORD_TEST_TROJAN_GO" {
            command.arg("-config").arg(config_path);
        } else {
            command.args(["run", "-c"]).arg(config_path);
        }
        let child = command
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let mut peer = Self {
            child,
            _directory: directory,
            port,
        };
        let deadline = Instant::now() + Duration::from_secs(6);
        loop {
            assert!(
                peer.child.try_wait().unwrap().is_none(),
                "reference peer exited"
            );
            if TcpStream::connect(("127.0.0.1", port)).await.is_ok() {
                return peer;
            }
            assert!(
                Instant::now() < deadline,
                "reference peer readiness timed out"
            );
            sleep(Duration::from_millis(20)).await;
        }
    }
}
impl Drop for Peer {
    fn drop(&mut self) {
        let _ = self.child.start_kill();
    }
}

async fn roundtrip(adapter: Arc<dyn TransitAdapter>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let tcp_port = listener.local_addr().unwrap().port();
    let tcp = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut data = vec![0; 32_777];
        stream.read_exact(&mut data).await.unwrap();
        stream.write_all(&data).await.unwrap();
    });
    let mut stream = adapter
        .connect(ConnectRequest {
            destination: Endpoint {
                host: "127.0.0.1".into(),
                port: tcp_port,
            },
        })
        .await
        .unwrap();
    let data = vec![0x5a; 32_777];
    stream.write_all(&data).await.unwrap();
    stream.flush().await.unwrap();
    let mut received = vec![0; data.len()];
    stream.read_exact(&mut received).await.unwrap();
    assert_eq!(received, data);
    tcp.await.unwrap();

    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let udp_port = socket.local_addr().unwrap().port();
    let udp = tokio::spawn(async move {
        for _ in 0..3 {
            let mut bytes = [0; 2048];
            let (length, source) = socket.recv_from(&mut bytes).await.unwrap();
            socket.send_to(&bytes[..length], source).await.unwrap();
        }
    });
    let mut datagram = adapter
        .connect_udp(ConnectRequest {
            destination: Endpoint {
                host: "127.0.0.1".into(),
                port: udp_port,
            },
        })
        .await
        .unwrap();
    for payload in [b"first".as_slice(), b"second packet", b"third"] {
        datagram.send(payload).await.unwrap();
        assert_eq!(datagram.receive().await.unwrap(), payload);
    }
    datagram.close().await.unwrap();
    udp.await.unwrap();
}

#[tokio::test]
#[ignore = "requires PATHCHORD_TEST_TROJAN_GO pointing to Trojan-Go v0.10.6"]
async fn imported_trojan_go_tcp_and_websocket_roundtrip_with_trojan_go() {
    timeout(Duration::from_secs(30), async {
        for transport in ["original", "ws"] {
            let peer = Peer::start("PATHCHORD_TEST_TROJAN_GO", transport, Value::Null, None).await;
            let options = if transport == "ws" {
                "type=ws&host=front.test&path=%2Ftunnel"
            } else {
                "type=original"
            };
            let uri = format!(
                "trojan-go://{PASSWORD}@127.0.0.1:{}?sni={SNI}&allowInsecure=1&{options}",
                peer.port
            );
            roundtrip(imported_adapter(uri).await).await;
        }
    })
    .await
    .expect("Trojan-Go fixture timed out");
}

#[tokio::test]
#[ignore = "requires PATHCHORD_TEST_TROJAN_GO pointing to Trojan-Go v0.10.6"]
async fn imported_trojan_go_encrypted_websocket_roundtrip() {
    timeout(Duration::from_secs(45), async {
        let transport = "ws";
        let options = "type=ws&host=front.test&path=%2Ftunnel";
        for method in ["aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305"] {
            let peer = Peer::start(
                "PATHCHORD_TEST_TROJAN_GO",
                transport,
                Value::Null,
                Some(method),
            )
            .await;
            let uri = format!(
                "trojan-go://{PASSWORD}@127.0.0.1:{}?sni={SNI}&allowInsecure=1&{options}&encryption=ss%3B{method}%3Ass-fixture%3Acolon%3Bsemicolon",
                peer.port
            );
            timeout(Duration::from_secs(6), roundtrip(imported_adapter(uri).await))
                .await
                .unwrap_or_else(|_| panic!("encrypted {transport} {method} roundtrip timed out"));
        }
    }).await.expect("encrypted Trojan-Go fixture timed out");
}

#[tokio::test]
#[ignore = "requires PATHCHORD_TEST_SING_BOX"]
async fn imported_trojan_go_dae_grpc_and_httpupgrade_roundtrip_with_sing_box() {
    timeout(Duration::from_secs(30), async {
        for (transport, server, options) in [
            (
                "grpc",
                json!({"type":"grpc","service_name":"GunService"}),
                "type=grpc",
            ),
            (
                "grpc",
                json!({"type":"grpc","service_name":"custom.service"}),
                "type=grpc&path=custom.service",
            ),
            (
                "httpupgrade",
                json!({"type":"httpupgrade","host":"front.test","path":"/upgrade"}),
                "type=httpupgrade&host=front.test&path=upgrade",
            ),
        ] {
            let peer = Peer::start("PATHCHORD_TEST_SING_BOX", transport, server, None).await;
            let uri = format!(
                "trojan-go://{PASSWORD}@127.0.0.1:{}?sni={SNI}&allowInsecure=1&{options}",
                peer.port
            );
            roundtrip(imported_adapter(uri).await).await;
        }
    })
    .await
    .expect("sing-box Trojan-go fixture timed out");
}
