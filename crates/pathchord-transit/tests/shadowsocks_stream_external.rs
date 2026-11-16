//! PathChord client against an independently started local Shadowsocks server.
//!
//! The server binary and its test configuration are supplied externally and
//! never become runtime dependencies. Set `PATHCHORD_TEST_SS_SERVER` to its
//! loopback address and `PATHCHORD_TEST_SS_CIPHER` to the configured method.

use std::{collections::BTreeMap, net::SocketAddr, time::Duration};

use pathchord_policy::{Endpoint as PolicyEndpoint, TransitProxyConfig, TransitProxyId};
use pathchord_transit::{
    ConnectRequest, Endpoint, ShadowsocksTransitAdapter, SubscriptionCredential, TransitAdapter,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, UdpSocket},
    time::timeout,
};

#[tokio::test]
#[ignore = "requires an independently started local Shadowsocks server"]
async fn independent_server_relays_tcp_and_udp() {
    let proxy: SocketAddr = std::env::var("PATHCHORD_TEST_SS_SERVER")
        .expect("PATHCHORD_TEST_SS_SERVER is required")
        .parse()
        .expect("proxy address must be a socket address");
    assert!(proxy.ip().is_loopback(), "test server must be loopback");
    let cipher = std::env::var("PATHCHORD_TEST_SS_CIPHER").expect("cipher is required");
    let password = std::env::var("PATHCHORD_TEST_SS_PASSWORD")
        .unwrap_or_else(|_| "pathchord-test-password".into());
    let config = TransitProxyConfig {
        id: TransitProxyId::new("external-shadowsocks"),
        source: None,
        protocol: "ss".into(),
        endpoint: PolicyEndpoint {
            host: proxy.ip().to_string(),
            port: proxy.port(),
        },
        credentials_ref: None,
        labels: BTreeMap::new(),
        tags: Default::default(),
        weight: 100,
        options: Default::default(),
    };
    let credential = SubscriptionCredential::new(BTreeMap::from([
        ("cipher".into(), cipher),
        ("password".into(), password),
    ]));
    let adapter =
        ShadowsocksTransitAdapter::from_subscription(&config, &credential, Duration::from_secs(3))
            .unwrap();

    timeout(Duration::from_secs(20), async {
        let tcp_target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let tcp_address = tcp_target.local_addr().unwrap();
        let tcp_server = tokio::spawn(async move {
            let (mut stream, _) = tcp_target.accept().await.unwrap();
            let (mut reader, mut writer) = stream.split();
            tokio::io::copy(&mut reader, &mut writer).await.unwrap();
        });
        let mut stream = adapter
            .connect(ConnectRequest {
                destination: Endpoint {
                    host: tcp_address.ip().to_string(),
                    port: tcp_address.port(),
                },
            })
            .await
            .unwrap();
        let data: Vec<u8> = (0..65_537).map(|index| (index % 251) as u8).collect();
        let (mut reader, mut writer) = tokio::io::split(&mut stream);
        let (sent, received) = tokio::join!(
            async {
                writer.write_all(&data).await?;
                writer.flush().await
            },
            async {
                let mut received = vec![0; data.len()];
                reader.read_exact(&mut received).await?;
                Ok::<_, std::io::Error>(received)
            }
        );
        sent.unwrap();
        assert_eq!(received.unwrap(), data);
        writer.shutdown().await.unwrap();
        drop(reader);
        drop(writer);
        drop(stream);
        tcp_server.await.unwrap();

        let udp_target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let udp_address = udp_target.local_addr().unwrap();
        let udp_server = tokio::spawn(async move {
            let mut buffer = vec![0; 4096];
            for _ in 0..2 {
                let (len, peer) = udp_target.recv_from(&mut buffer).await.unwrap();
                udp_target.send_to(&buffer[..len], peer).await.unwrap();
            }
        });
        let mut datagram = adapter
            .connect_udp(ConnectRequest {
                destination: Endpoint {
                    host: udp_address.ip().to_string(),
                    port: udp_address.port(),
                },
            })
            .await
            .unwrap();
        for payload in [b"legacy-ss-udp".as_slice(), &[0x63; 1400]] {
            datagram.send(payload).await.unwrap();
            assert_eq!(datagram.receive().await.unwrap(), payload);
        }
        datagram.close().await.unwrap();
        udp_server.await.unwrap();
    })
    .await
    .expect("Shadowsocks exchange timed out");
}

#[tokio::test]
#[ignore = "requires an independently started AES-192-GCM Shadowsocks server"]
async fn independent_server_rejects_aes192_with_the_wrong_password() {
    let proxy: SocketAddr = std::env::var("PATHCHORD_TEST_SS_SERVER")
        .expect("PATHCHORD_TEST_SS_SERVER is required")
        .parse()
        .unwrap();
    assert!(proxy.ip().is_loopback());
    assert_eq!(
        std::env::var("PATHCHORD_TEST_SS_CIPHER").unwrap(),
        "aes-192-gcm"
    );
    assert_ne!(
        std::env::var("PATHCHORD_TEST_SS_PASSWORD").unwrap(),
        "intentionally-wrong"
    );
    let config = TransitProxyConfig {
        id: TransitProxyId::new("external-shadowsocks-wrong-password"),
        source: None,
        protocol: "ss".into(),
        endpoint: PolicyEndpoint {
            host: proxy.ip().to_string(),
            port: proxy.port(),
        },
        credentials_ref: None,
        labels: BTreeMap::new(),
        tags: Default::default(),
        weight: 100,
        options: Default::default(),
    };
    let credentials = SubscriptionCredential::new(BTreeMap::from([
        ("cipher".into(), "aes-192-gcm".into()),
        ("password".into(), "intentionally-wrong".into()),
    ]));
    let adapter =
        ShadowsocksTransitAdapter::from_subscription(&config, &credentials, Duration::from_secs(2))
            .unwrap();
    timeout(Duration::from_secs(5), async {
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_address = target.local_addr().unwrap();
        let mut stream = adapter.connect(ConnectRequest {
            destination: Endpoint { host: target_address.ip().to_string(), port: target_address.port() },
        }).await.unwrap();
        let _ = stream.write_all(b"must-not-arrive").await;
        let _ = stream.flush().await;
        let mut read = [0; 64];
        assert!(!matches!(timeout(Duration::from_millis(500), stream.read(&mut read)).await, Ok(Ok(count)) if count > 0));
        assert!(timeout(Duration::from_millis(200), target.accept()).await.is_err());

        let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let target_address = udp.local_addr().unwrap();
        let mut datagram = adapter.connect_udp(ConnectRequest {
            destination: Endpoint { host: target_address.ip().to_string(), port: target_address.port() },
        }).await.unwrap();
        datagram.send(b"must-not-arrive").await.unwrap();
        assert!(!matches!(timeout(Duration::from_millis(500), datagram.receive()).await, Ok(Ok(_))));
        assert!(timeout(Duration::from_millis(200), udp.recv_from(&mut read)).await.is_err());
    }).await.expect("wrong-password rejection timed out");
}
