//! Android 11 OkHttp wire fingerprint against independent TLS/VLESS peers.

use std::{collections::BTreeMap, net::SocketAddr, process::Stdio, sync::Arc, time::Duration};

use pathchord_policy::{
    Endpoint as PolicyEndpoint, TransitOptions, TransitProxyConfig, TransitProxyId, TransitTls,
};
use pathchord_transit::{
    AdapterRegistry, ConnectRequest, Endpoint, NoTransitCredentials, TransitCredential,
};
use serde_json::json;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    process::Command,
    sync::oneshot,
    time::{Instant, sleep, timeout},
};

const UUID: &str = "6cbf3f72-3417-4922-bde6-67820d041f25";
const SERVER_NAME: &str = "tls.pathchord.test";

fn normalized_hello(wire: &[u8]) -> Vec<u8> {
    let mut hello = if wire.first() == Some(&22) {
        wire[5..].to_vec()
    } else {
        wire.to_vec()
    };
    assert_eq!(hello[0], 1);
    hello[6..38].fill(0);
    let session_length = usize::from(hello[38]);
    assert_eq!(session_length, 32);
    hello[39..39 + session_length].fill(0);
    hello
}

async fn capture_proxy(
    target: SocketAddr,
) -> (
    SocketAddr,
    oneshot::Receiver<Vec<u8>>,
    tokio::task::JoinHandle<()>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (tx, rx) = oneshot::channel();
    let task = tokio::spawn(async move {
        let mut sender = Some(tx);
        while let Ok((mut client, _)) = listener.accept().await {
            let capture = sender.take();
            tokio::spawn(async move {
                let mut header = [0; 5];
                if client.read_exact(&mut header).await.is_err() {
                    return;
                }
                let mut body = vec![0; usize::from(u16::from_be_bytes([header[3], header[4]]))];
                if client.read_exact(&mut body).await.is_err() {
                    return;
                }
                let mut first = header.to_vec();
                first.extend_from_slice(&body);
                if let Some(capture) = capture {
                    let _ = capture.send(first.clone());
                }
                if let Ok(mut upstream) = TcpStream::connect(target).await
                    && upstream.write_all(&first).await.is_ok()
                {
                    let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
                }
            });
        }
    });
    (address, rx, task)
}

async fn exercise(binary: &str, xray: bool, tls13_only: bool) {
    timeout(Duration::from_secs(15), async {
        let reservation = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = reservation.local_addr().unwrap().port();
        drop(reservation);
        let rcgen::CertifiedKey { cert, signing_key } =
            rcgen::generate_simple_self_signed(vec![SERVER_NAME.to_owned()]).unwrap();
        let certificate = cert.pem();
        let key = signing_key.serialize_pem();
        let min_version = if tls13_only { "1.3" } else { "1.2" };
        let document = if xray {
            json!({
                "log": {"loglevel": "none"},
                "inbounds": [{"listen": "127.0.0.1", "port": port, "protocol": "vless",
                    "settings": {"clients": [{"id": UUID}], "decryption": "none"},
                    "streamSettings": {"network": "tcp", "security": "tls", "tlsSettings": {
                        "minVersion": min_version, "maxVersion": "1.3",
                        "certificates": [{"certificate": [certificate], "key": [key]}]
                    }}
                }],
                "outbounds": [{"protocol": "freedom", "settings": {"finalRules": [{"action": "allow"}]}}]
            })
        } else {
            json!({
                "log": {"disabled": true},
                "inbounds": [{"type": "vless", "listen": "127.0.0.1", "listen_port": port,
                    "users": [{"uuid": UUID}], "tls": {"enabled": true,
                    "min_version": min_version, "max_version": "1.3", "certificate": certificate, "key": key}}],
                "outbounds": [{"type": "direct", "tag": "direct"}], "route": {"final": "direct"}
            })
        };
        let mut peer = Command::new(binary).arg("run").arg("-c")
            .arg(if xray { "stdin:" } else { "stdin" })
            .stdin(Stdio::piped()).stdout(Stdio::null()).stderr(Stdio::null())
            .kill_on_drop(true).spawn().unwrap();
        peer.stdin.take().unwrap().write_all(&serde_json::to_vec(&document).unwrap()).await.unwrap();
        let endpoint: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        while TcpStream::connect(endpoint).await.is_err() {
            assert!(peer.try_wait().unwrap().is_none(), "TLS peer exited");
            assert!(Instant::now() < deadline, "TLS peer readiness timed out");
            sleep(Duration::from_millis(20)).await;
        }
        let (address, capture, relay) = capture_proxy(endpoint).await;
        let config = TransitProxyConfig {
            id: TransitProxyId::new("android-tls-test"), source: None, protocol: "vless".into(),
            endpoint: PolicyEndpoint { host: "127.0.0.1".into(), port: address.port() },
            credentials_ref: None, labels: Default::default(), tags: Default::default(), weight: 1,
            options: TransitOptions { tls: Some(TransitTls { enabled: true,
                server_name: Some(SERVER_NAME.into()), truststore: Vec::new(),
                certificate: vec![cert.pem()], fingerprint: Some("android".into()), ..Default::default()
            }), ..Default::default() },
        };
        let credential = TransitCredential::new(BTreeMap::from([("uuid".into(), UUID.into())]));
        let adapter = AdapterRegistry::for_configs(Arc::new(NoTransitCredentials), Duration::from_secs(5), [&config])
            .unwrap().build_with_credential(&config, &credential).unwrap();
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_address = target.local_addr().unwrap();
        let request = ConnectRequest { destination: Endpoint { host: "127.0.0.1".into(), port: target_address.port() } };
        let result = adapter.connect(request).await;
        let hello = capture.await.unwrap();
        assert_eq!(normalized_hello(&hello), normalized_hello(include_bytes!("fixtures/dae-utls-1.8.2/android.bin")));
        if tls13_only {
            assert!(result.is_err(), "TLS 1.3-only peer must reject Android 11");
        } else {
            let mut stream = result.unwrap();
            let echo = tokio::spawn(async move {
                let (mut stream, _) = target.accept().await.unwrap();
                let mut data = [0; 7];
                stream.read_exact(&mut data).await.unwrap();
                stream.write_all(&data).await.unwrap();
            });
            stream.write_all(b"android").await.unwrap();
            stream.flush().await.unwrap();
            let mut response = [0; 7];
            stream.read_exact(&mut response).await.unwrap();
            assert_eq!(&response, b"android");
            echo.await.unwrap();
            let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let udp_address = udp.local_addr().unwrap();
            let echo = tokio::spawn(async move {
                let mut packet = [0; 64];
                let (size, from) = udp.recv_from(&mut packet).await.unwrap();
                udp.send_to(&packet[..size], from).await.unwrap();
            });
            let mut datagram = adapter.connect_udp(ConnectRequest { destination: Endpoint { host: "127.0.0.1".into(), port: udp_address.port() } }).await.unwrap();
            datagram.send(b"udp").await.unwrap();
            assert_eq!(datagram.receive().await.unwrap(), b"udp");
            datagram.close().await.unwrap();
            echo.await.unwrap();
        }
        relay.abort();
        peer.kill().await.unwrap();
        peer.wait().await.unwrap();
    }).await.expect("Android TLS peer test timed out");
}

#[tokio::test]
#[ignore = "requires PATHCHORD_TEST_SING_BOX and PATHCHORD_TEST_XRAY"]
async fn android_matches_utls_and_interoperates_with_independent_tls_peers() {
    for (variable, xray) in [
        ("PATHCHORD_TEST_SING_BOX", false),
        ("PATHCHORD_TEST_XRAY", true),
    ] {
        let binary = std::env::var(variable).expect("reference peer");
        exercise(&binary, xray, false).await;
        exercise(&binary, xray, true).await;
    }
}
