//! Interoperability of the V2Ray HTTP transport with an independent peer.

use std::{collections::BTreeMap, path::PathBuf, process::Stdio, sync::Arc, time::Duration};

use pathchord_policy::{
    Endpoint as PolicyEndpoint, TransitOptions, TransitProxyConfig, TransitProxyId, TransitTls,
    TransitTransport,
};
use pathchord_transit::{
    AdapterRegistry, ConnectRequest, Endpoint, NoTransitCredentials, TransitCredential,
};
use serde_json::json;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    process::Command,
    time::{Instant, sleep, timeout},
};

const UUID: &str = "6cbf3f72-3417-4922-bde6-67820d041f25";

#[tokio::test]
#[ignore = "requires PATHCHORD_TEST_SING_BOX"]
async fn sing_box_http_transport_relays_tcp_and_udp() {
    for (protocol, tls) in [
        ("vless", false),
        ("vless", true),
        ("vmess", false),
        ("vmess", true),
        ("trojan", true),
    ] {
        timeout(Duration::from_secs(20), round_trip(protocol, tls))
            .await
            .expect("HTTP transport fixture timed out");
    }
}

async fn round_trip(protocol: &str, tls: bool) {
    let binary =
        PathBuf::from(std::env::var_os("PATHCHORD_TEST_SING_BOX").expect("sing-box binary"));
    let cert = rcgen::generate_simple_self_signed(vec!["tls.test".into()]).unwrap();
    let reserved = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = reserved.local_addr().unwrap().port();
    let users = if protocol == "trojan" {
        json!([{"password": "fixture-password"}])
    } else {
        json!([{"uuid": UUID}])
    };
    let mut inbound = json!({"type":protocol,"listen":"127.0.0.1","listen_port":port,"users":users,"transport":{"type":"http","host":["front.test"],"path":"/pathchord"}});
    if tls {
        inbound["tls"] = json!({"enabled":true,"certificate":cert.cert.pem(),"key":cert.signing_key.serialize_pem(),"alpn":["h2"]});
    }
    let body = serde_json::to_vec(
        &json!({"log":{"disabled":true},"inbounds":[inbound],"outbounds":[{"type":"direct"}]}),
    )
    .unwrap();
    drop(reserved);
    let mut peer = Command::new(binary)
        .args(["run", "-c", "stdin"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    peer.stdin.take().unwrap().write_all(&body).await.unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    while TcpStream::connect(("127.0.0.1", port)).await.is_err() {
        assert!(Instant::now() < deadline, "sing-box readiness");
        sleep(Duration::from_millis(20)).await;
    }
    let config = TransitProxyConfig {
        id: TransitProxyId::new("http-peer"),
        source: None,
        protocol: protocol.into(),
        endpoint: PolicyEndpoint {
            host: "127.0.0.1".into(),
            port,
        },
        credentials_ref: None,
        labels: Default::default(),
        tags: Default::default(),
        weight: 100,
        options: TransitOptions {
            tls: tls.then(|| TransitTls {
                enabled: true,
                server_name: Some("tls.test".into()),
                certificate: vec![cert.cert.pem()],
                alpn: vec!["h2".into()],
                ..Default::default()
            }),
            transport: Some(TransitTransport {
                kind: "http".into(),
                path: Some("/pathchord?test=1".into()),
                host: vec!["front.test".into()],
                headers: BTreeMap::from([("x-pathchord-test".into(), "present".into())]),
                ..Default::default()
            }),
            ..Default::default()
        },
    };
    let fields = match protocol {
        "trojan" => vec![("password", "fixture-password")],
        "vmess" => vec![("uuid", UUID), ("security", "aes-128-gcm")],
        _ => vec![("uuid", UUID)],
    };
    let credential = TransitCredential::new(
        fields
            .into_iter()
            .map(|(k, v)| (k.into(), v.into()))
            .collect(),
    );
    let registry = AdapterRegistry::for_configs(
        Arc::new(NoTransitCredentials),
        Duration::from_secs(5),
        [&config],
    )
    .unwrap();
    let adapter = registry
        .build_with_credential(&config, &credential)
        .unwrap();
    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target_port = target.local_addr().unwrap().port();
    let target_task = tokio::spawn(async move {
        let (mut stream, _) = target.accept().await.unwrap();
        let mut bytes = vec![0; 128 * 1024];
        stream.read_exact(&mut bytes).await.unwrap();
        stream.write_all(&bytes).await.unwrap();
        stream.shutdown().await.unwrap();
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
    let data: Vec<_> = (0..128 * 1024).map(|index| (index % 251) as u8).collect();
    stream.write_all(&data).await.unwrap();
    stream.flush().await.unwrap();
    let mut reply = vec![0; data.len()];
    stream.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply, data, "{protocol}, tls={tls}");
    target_task.await.unwrap();
    let target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let port = target.local_addr().unwrap().port();
    let target_task = tokio::spawn(async move {
        let mut data = [0; 2048];
        for _ in 0..2 {
            let (length, address) = target.recv_from(&mut data).await.unwrap();
            target.send_to(&data[..length], address).await.unwrap();
        }
    });
    let mut datagram = adapter
        .connect_udp(ConnectRequest {
            destination: Endpoint {
                host: "127.0.0.1".into(),
                port,
            },
        })
        .await
        .unwrap();
    for data in [b"packet".as_slice(), &[0x31; 1400]] {
        datagram.send(data).await.unwrap();
        assert_eq!(
            datagram.receive().await.unwrap(),
            data,
            "{protocol}, tls={tls}"
        );
    }
    datagram.close().await.unwrap();
    target_task.await.unwrap();

    for (path, host) in [("/wrong", "front.test"), ("/pathchord", "wrong.test")] {
        let mut bad = config.clone();
        let transport = bad.options.transport.as_mut().unwrap();
        transport.path = Some(path.into());
        transport.host = vec![host.into()];
        let bad = registry.build_with_credential(&bad, &credential).unwrap();
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let rejected = async {
            let Ok(mut stream) = bad
                .connect(ConnectRequest {
                    destination: Endpoint {
                        host: "127.0.0.1".into(),
                        port: target.local_addr().unwrap().port(),
                    },
                })
                .await
            else {
                return true;
            };
            if stream.write_all(b"must-not-reach-target").await.is_err() {
                return true;
            }
            let mut byte = [0];
            !matches!(stream.read(&mut byte).await, Ok(n) if n > 0)
        };
        // A rejected request may surface during connect or first read. The
        // target itself must never receive a tunneled connection.
        assert!(
            timeout(Duration::from_secs(3), rejected)
                .await
                .unwrap_or(false),
            "expected rejection for {protocol}, tls={tls}"
        );
        assert!(
            timeout(Duration::from_millis(100), target.accept())
                .await
                .is_err()
        );
    }
    peer.kill().await.unwrap();
    peer.wait().await.unwrap();
}
