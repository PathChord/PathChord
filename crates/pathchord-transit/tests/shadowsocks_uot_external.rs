//! Shadowsocks UDP-over-TCP interoperability with a separate sing-box peer.

use std::{collections::BTreeMap, path::PathBuf, process::Stdio, time::Duration};

use pathchord_policy::{
    Endpoint as PolicyEndpoint, TransitOptions, TransitProxyConfig, TransitProxyId,
};
use pathchord_transit::{
    ConnectRequest, Endpoint, ShadowsocksTransitAdapter, SubscriptionCredential, TransitAdapter,
};
use serde_json::json;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    process::Command,
    time::{Instant, sleep, timeout},
};

#[tokio::test]
#[ignore = "requires PATHCHORD_TEST_SING_BOX pointing to a sing-box 1.14.4 server"]
async fn shadowsocks_udp_over_tcp_interoperates_with_sing_box() {
    for cipher in ["aes-128-gcm", "aes-192-gcm"] {
        timeout(Duration::from_secs(20), exercise(cipher))
            .await
            .expect("bounded Shadowsocks UoT fixture");
    }
}

async fn exercise(cipher: &str) {
    let binary =
        PathBuf::from(std::env::var_os("PATHCHORD_TEST_SING_BOX").expect("sing-box binary"));
    let reserve = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = reserve.local_addr().unwrap().port();
    let config = json!({"log":{"disabled":true}, "inbounds":[{"type":"shadowsocks","listen":"127.0.0.1","listen_port":port,"method":cipher,"password":"uot-fixture-password"}],"outbounds":[{"type":"direct"}]});
    drop(reserve);
    let mut peer = Command::new(binary)
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
        .write_all(&serde_json::to_vec(&config).unwrap())
        .await
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    while TcpStream::connect(("127.0.0.1", port)).await.is_err() {
        assert!(Instant::now() < deadline, "sing-box readiness");
        sleep(Duration::from_millis(20)).await;
    }
    for version in [1, 2] {
        let node = TransitProxyConfig {
            id: TransitProxyId::new("ss-uot"),
            source: None,
            protocol: "ss".into(),
            endpoint: PolicyEndpoint {
                host: "127.0.0.1".into(),
                port,
            },
            credentials_ref: None,
            labels: Default::default(),
            tags: Default::default(),
            weight: 1,
            options: TransitOptions {
                udp_over_tcp: Some(version),
                ..Default::default()
            },
        };
        let credential = SubscriptionCredential::new(BTreeMap::from([
            ("cipher".into(), cipher.into()),
            ("password".into(), "uot-fixture-password".into()),
        ]));
        let adapter = ShadowsocksTransitAdapter::from_subscription(
            &node,
            &credential,
            Duration::from_secs(5),
        )
        .unwrap();
        assert!(adapter.supports_udp());
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_port = target.local_addr().unwrap().port();
        let echo = tokio::spawn(async move {
            let (mut stream, _) = target.accept().await.unwrap();
            let mut buf = [0; 4];
            stream.read_exact(&mut buf).await.unwrap();
            stream.write_all(&buf).await.unwrap();
        });
        let mut stream = adapter
            .connect(ConnectRequest {
                destination: Endpoint {
                    host: "127.0.0.1".into(),
                    port: target_port,
                },
            })
            .await
            .unwrap();
        stream.write_all(b"ping").await.unwrap();
        let mut reply = [0; 4];
        stream.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply, b"ping");
        echo.await.unwrap();
        for bind in ["127.0.0.1:0", "[::1]:0"] {
            let socket = UdpSocket::bind(bind).await.unwrap();
            let address = socket.local_addr().unwrap();
            let echo = tokio::spawn(async move {
                let mut buf = [0; 4096];
                for _ in 0..3 {
                    let (size, source) = socket.recv_from(&mut buf).await.unwrap();
                    socket.send_to(&buf[..size], source).await.unwrap();
                }
            });
            let mut datagram = adapter
                .connect_udp(ConnectRequest {
                    destination: Endpoint {
                        host: address.ip().to_string(),
                        port: address.port(),
                    },
                })
                .await
                .unwrap();
            for payload in [b"".as_slice(), b"packet".as_slice(), &[0x45; 4096]] {
                datagram.send(payload).await.unwrap();
                assert_eq!(
                    datagram.receive().await.unwrap(),
                    payload,
                    "{cipher}, v{version}, {bind}"
                );
            }
            datagram.close().await.unwrap();
            echo.await.unwrap();
        }
    }
    peer.kill().await.unwrap();
    peer.wait().await.unwrap();
}
