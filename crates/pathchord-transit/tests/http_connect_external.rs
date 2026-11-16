//! CONNECT interoperability with the sing-box HTTP inbound.

use std::{collections::BTreeMap, process::Stdio, sync::Arc, time::Duration};

use pathchord_policy::{
    Endpoint as PolicyEndpoint, TransitOptions, TransitProxyConfig, TransitProxyId, TransitTls,
};
use pathchord_transit::{
    ConnectRequest, Endpoint, HttpConnectTransitAdapter, HttpsConnectTransitAdapter,
    TransitAdapter, TransitCredential,
};
use serde_json::json;
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::{TcpListener, TcpStream},
    process::Command,
};

#[tokio::test]
#[ignore = "requires PATHCHORD_TEST_SING_BOX"]
async fn standard_http_connect_auth_and_tls_interoperate_with_sing_box() {
    for tls in [false, true] {
        let cert = rcgen::generate_simple_self_signed(vec!["http-proxy.test".into()]).unwrap();
        let reserved = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = reserved.local_addr().unwrap().port();
        let mut inbound = json!({"type":"http", "listen":"127.0.0.1", "listen_port":port,
            "users":[{"username":"test-user", "password":"test-password"}]});
        if tls {
            inbound["tls"] = json!({"enabled":true, "certificate":cert.cert.pem(), "key":cert.signing_key.serialize_pem()});
        }
        let document =
            json!({"log":{"disabled":true}, "inbounds":[inbound], "outbounds":[{"type":"direct"}]});
        drop(reserved);
        let mut peer = Command::new(std::env::var_os("PATHCHORD_TEST_SING_BOX").unwrap())
            .args(["run", "-c", "stdin"])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        peer.stdin
            .take()
            .unwrap()
            .write_all(&serde_json::to_vec(&document).unwrap())
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(5), async {
            while TcpStream::connect(("127.0.0.1", port)).await.is_err() {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .unwrap();

        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_address = target.local_addr().unwrap();
        let target_task = tokio::spawn(async move {
            for _ in 0..1 {
                let (mut socket, _) = target.accept().await.unwrap();
                let mut bytes = [0; 5];
                socket.read_exact(&mut bytes).await.unwrap();
                socket.write_all(&bytes).await.unwrap();
                socket.shutdown().await.unwrap();
            }
        });
        let node = TransitProxyConfig {
            id: TransitProxyId::new("http-connect-peer"),
            source: None,
            protocol: if tls { "https" } else { "http" }.into(),
            endpoint: PolicyEndpoint {
                host: "127.0.0.1".into(),
                port,
            },
            credentials_ref: None,
            labels: BTreeMap::new(),
            tags: Default::default(),
            weight: 100,
            options: TransitOptions {
                tls: tls.then(|| TransitTls {
                    enabled: true,
                    server_name: Some("http-proxy.test".into()),
                    certificate: vec![cert.cert.pem()],
                    ..Default::default()
                }),
                ..Default::default()
            },
        };
        for _ in 0..1 {
            let fields = BTreeMap::from([
                ("username".into(), "test-user".into()),
                ("password".into(), "test-password".into()),
            ]);
            let credential = TransitCredential::new(fields);
            let adapter: Box<dyn TransitAdapter> = if tls {
                let base = rustls::ClientConfig::builder()
                    .with_root_certificates(rustls::RootCertStore::empty())
                    .with_no_client_auth();
                Box::new(
                    HttpsConnectTransitAdapter::from_config(
                        &node,
                        Some(&credential),
                        Duration::from_secs(3),
                        Arc::new(base),
                    )
                    .unwrap(),
                )
            } else {
                Box::new(
                    HttpConnectTransitAdapter::from_config(
                        &node,
                        Some(&credential),
                        Duration::from_secs(3),
                    )
                    .unwrap(),
                )
            };
            let mut stream = adapter
                .connect(ConnectRequest {
                    destination: Endpoint {
                        host: "127.0.0.1".into(),
                        port: target_address.port(),
                    },
                })
                .await
                .unwrap();
            stream.write_all(b"hello").await.unwrap();
            let mut reply = [0; 5];
            stream.read_exact(&mut reply).await.unwrap();
            assert_eq!(&reply, b"hello");
            stream.shutdown().await.unwrap();
        }
        target_task.await.unwrap();
        peer.kill().await.unwrap();
        peer.wait().await.unwrap();
    }
}

#[tokio::test]
#[ignore = "requires a Go toolchain to build the independent HTTP peer"]
async fn private_path_and_host_override_interoperate_with_go_http_peer() {
    let temporary =
        std::env::temp_dir().join(format!("pathchord-http-peer-{}", std::process::id()));
    let status = Command::new("go")
        .args(["build", "-o"])
        .arg(&temporary)
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/http_connect_proxy.go"
        ))
        .status()
        .await
        .unwrap();
    assert!(status.success());
    for mode in ["path", "host"] {
        let mut peer = Command::new(&temporary)
            .env("PATHCHORD_HTTP_PEER_MODE", mode)
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let mut address = String::new();
        BufReader::new(peer.stdout.take().unwrap())
            .read_line(&mut address)
            .await
            .unwrap();
        let address: std::net::SocketAddr = address.trim().parse().unwrap();
        let mut node = TransitProxyConfig {
            id: TransitProxyId::new("go-http-peer"),
            source: None,
            protocol: "http".into(),
            endpoint: PolicyEndpoint {
                host: address.ip().to_string(),
                port: address.port(),
            },
            credentials_ref: None,
            labels: BTreeMap::new(),
            tags: Default::default(),
            weight: 100,
            options: TransitOptions::default(),
        };
        let mut fields = BTreeMap::from([
            ("username".into(), "test-user".into()),
            ("password".into(), "test-password".into()),
        ]);
        if mode == "path" {
            fields.insert("http_path".into(), "/token%2Fpart?x=1".into());
        } else {
            node.options
                .headers
                .insert("Host".into(), "front.test".into());
        }
        let credential = TransitCredential::new(fields);
        let adapter = HttpConnectTransitAdapter::from_config(
            &node,
            Some(&credential),
            Duration::from_secs(3),
        )
        .unwrap();
        let mut stream = adapter
            .connect(ConnectRequest {
                destination: Endpoint {
                    host: "target.test".into(),
                    port: 443,
                },
            })
            .await
            .unwrap();
        stream.write_all(b"hello").await.unwrap();
        let mut reply = [0; 5];
        stream.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply, b"hello");
        stream.shutdown().await.unwrap();
        let wrong = TransitCredential::new(BTreeMap::from([
            ("username".into(), "test-user".into()),
            ("password".into(), "wrong".into()),
        ]));
        let rejected =
            HttpConnectTransitAdapter::from_config(&node, Some(&wrong), Duration::from_secs(3))
                .unwrap();
        assert!(
            rejected
                .connect(ConnectRequest {
                    destination: Endpoint {
                        host: "target.test".into(),
                        port: 443
                    }
                })
                .await
                .is_err()
        );
        peer.kill().await.unwrap();
        peer.wait().await.unwrap();
    }
    std::fs::remove_file(temporary).unwrap();
}
