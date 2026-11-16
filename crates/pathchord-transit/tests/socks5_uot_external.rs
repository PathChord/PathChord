use std::collections::{BTreeMap, BTreeSet};
use std::process::Stdio;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use pathchord_policy::{
    Endpoint as PolicyEndpoint, TransitOptions, TransitProxyConfig, TransitProxyId, TransitTls,
};
use pathchord_transit::{
    ConnectRequest, Endpoint, Socks5TransitAdapter, TransitAdapter, TransitCredential,
};
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt, copy_bidirectional};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::process::{Child, Command};
use tokio_rustls::TlsAcceptor;

fn config(proxy: std::net::SocketAddr, version: u8) -> TransitProxyConfig {
    TransitProxyConfig {
        id: TransitProxyId::new("socks-uot-test"),
        source: None,
        protocol: "socks5".into(),
        endpoint: PolicyEndpoint {
            host: proxy.ip().to_string(),
            port: proxy.port(),
        },
        credentials_ref: None,
        labels: BTreeMap::new(),
        tags: BTreeSet::new(),
        weight: 100,
        options: TransitOptions {
            udp: Some(true),
            udp_over_tcp: Some(version),
            ..Default::default()
        },
    }
}

fn credentials(password: &str) -> TransitCredential {
    TransitCredential::new(BTreeMap::from([
        ("username".into(), "test-user".into()),
        ("password".into(), password.into()),
    ]))
}

async fn start_sing_box() -> (Child, std::net::SocketAddr) {
    let binary = std::env::var_os("PATHCHORD_TEST_SING_BOX").expect("reference sing-box binary");
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    drop(listener);
    let document = json!({
        "log": {"disabled": true},
        "inbounds": [{
            "type": "socks", "listen": "127.0.0.1", "listen_port": address.port(),
            "users": [{"username": "test-user", "password": "test-password"}]
        }],
        "outbounds": [{"type": "direct", "tag": "direct"}],
        "route": {"final": "direct"}
    });
    let mut child = Command::new(binary)
        .arg("run")
        .arg("-c")
        .arg("stdin")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(&serde_json::to_vec(&document).unwrap())
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        while TcpStream::connect(address).await.is_err() {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("sing-box SOCKS listener readiness");
    (child, address)
}

async fn udp_round_trip(adapter: &Socks5TransitAdapter, bind: &str) {
    let target = UdpSocket::bind(bind).await.unwrap();
    let address = target.local_addr().unwrap();
    let echo = tokio::spawn(async move {
        let mut input = [0_u8; 8192];
        for _ in 0..3 {
            let (length, peer) = target.recv_from(&mut input).await.unwrap();
            target.send_to(&input[..length], peer).await.unwrap();
        }
    });
    let mut tunnel = adapter
        .connect_udp(ConnectRequest {
            destination: Endpoint {
                host: address.ip().to_string(),
                port: address.port(),
            },
        })
        .await
        .unwrap();
    for payload in [b"".to_vec(), b"request".to_vec(), vec![0x5a; 4096]] {
        tunnel.send(&payload).await.unwrap();
        let reply = tokio::time::timeout(Duration::from_secs(5), tunnel.receive())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(reply, payload);
    }
    tunnel.close().await.unwrap();
    echo.await.unwrap();
}

async fn tcp_round_trip(adapter: &Socks5TransitAdapter) {
    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = target.local_addr().unwrap();
    let echo = tokio::spawn(async move {
        let (mut stream, _) = target.accept().await.unwrap();
        let mut bytes = [0; 5];
        stream.read_exact(&mut bytes).await.unwrap();
        stream.write_all(&bytes).await.unwrap();
    });
    let mut stream = adapter
        .connect(ConnectRequest {
            destination: Endpoint {
                host: address.ip().to_string(),
                port: address.port(),
            },
        })
        .await
        .unwrap();
    stream.write_all(b"hello").await.unwrap();
    let mut result = [0; 5];
    stream.read_exact(&mut result).await.unwrap();
    assert_eq!(&result, b"hello");
    stream.shutdown().await.unwrap();
    echo.await.unwrap();
}

#[tokio::test]
#[ignore = "requires PATHCHORD_TEST_SING_BOX"]
async fn socks5_udp_over_tcp_interoperates_with_sing_box() {
    let (mut peer, proxy) = start_sing_box().await;
    let valid = credentials("test-password");
    let invalid = credentials("wrong-password");
    for version in [1, 2] {
        let cfg = config(proxy, version);
        let adapter =
            Socks5TransitAdapter::from_config(&cfg, Some(&valid), Duration::from_secs(3)).unwrap();
        assert!(adapter.supports_udp());
        tcp_round_trip(&adapter).await;
        udp_round_trip(&adapter, "127.0.0.1:0").await;
        udp_round_trip(&adapter, "[::1]:0").await;
        let wrong = Socks5TransitAdapter::from_config(&cfg, Some(&invalid), Duration::from_secs(3))
            .unwrap();
        assert!(
            wrong
                .connect_udp(ConnectRequest {
                    destination: Endpoint {
                        host: "127.0.0.1".into(),
                        port: 53
                    }
                })
                .await
                .is_err()
        );
        assert!(
            wrong
                .connect(ConnectRequest {
                    destination: Endpoint {
                        host: "127.0.0.1".into(),
                        port: 53
                    }
                })
                .await
                .is_err()
        );
    }
    peer.kill().await.unwrap();
    peer.wait().await.unwrap();
}

#[tokio::test]
#[ignore = "requires PATHCHORD_TEST_SING_BOX"]
async fn socks5_udp_over_tcp_uses_the_configured_tls_tunnel() {
    let (mut peer, proxy) = start_sing_box().await;
    let rcgen::CertifiedKey { cert, signing_key } =
        rcgen::generate_simple_self_signed(vec!["socks.test".into()]).unwrap();
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(signing_key.serialize_der()));
    let server = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert.der().clone()], key)
        .unwrap();
    let acceptor = TlsAcceptor::from(Arc::new(server));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let tls_proxy = listener.local_addr().unwrap();
    let accepted = Arc::new(AtomicUsize::new(0));
    let count = Arc::clone(&accepted);
    let bridge = tokio::spawn(async move {
        let mut tasks = tokio::task::JoinSet::new();
        for _ in 0..5 {
            let (socket, _) = listener.accept().await.unwrap();
            let acceptor = acceptor.clone();
            let count = Arc::clone(&count);
            tasks.spawn(async move {
                if let Ok(mut tls) = acceptor.accept(socket).await {
                    count.fetch_add(1, Ordering::Relaxed);
                    let mut server = TcpStream::connect(proxy).await.unwrap();
                    copy_bidirectional(&mut tls, &mut server).await.unwrap();
                }
            });
        }
        while let Some(result) = tasks.join_next().await {
            result.unwrap();
        }
    });
    let valid = credentials("test-password");
    for version in [1, 2] {
        let mut cfg = config(tls_proxy, version);
        cfg.options.tls = Some(TransitTls {
            enabled: true,
            server_name: Some("socks.test".into()),
            truststore: Vec::new(),
            certificate: vec![cert.pem()],
            ..Default::default()
        });
        let adapter =
            Socks5TransitAdapter::from_config(&cfg, Some(&valid), Duration::from_secs(3)).unwrap();
        tcp_round_trip(&adapter).await;
        udp_round_trip(&adapter, "127.0.0.1:0").await;
    }
    let mut wrong_tls = config(tls_proxy, 2);
    wrong_tls.options.tls = Some(TransitTls {
        enabled: true,
        server_name: Some("wrong.test".into()),
        truststore: Vec::new(),
        certificate: vec![cert.pem()],
        ..Default::default()
    });
    let adapter =
        Socks5TransitAdapter::from_config(&wrong_tls, Some(&valid), Duration::from_secs(3))
            .unwrap();
    assert!(
        adapter
            .connect_udp(ConnectRequest {
                destination: Endpoint {
                    host: "127.0.0.1".into(),
                    port: 53
                }
            })
            .await
            .is_err()
    );
    bridge.await.unwrap();
    assert_eq!(accepted.load(Ordering::Relaxed), 4);
    peer.kill().await.unwrap();
    peer.wait().await.unwrap();
}
