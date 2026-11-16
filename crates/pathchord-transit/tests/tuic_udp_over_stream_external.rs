//! Independent sing-box verification of the TUIC UDP-over-stream extension.

use std::{collections::BTreeMap, process::Stdio, sync::Arc, time::Duration};

use pathchord_policy::{
    Endpoint as PolicyEndpoint, TransitOptions, TransitProxyConfig, TransitProxyId, TransitTls,
};
use pathchord_transit::{
    AdapterRegistry, ConnectRequest, Endpoint, NoTransitCredentials, TransitCredential,
};
use serde_json::json;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, UdpSocket},
    process::Command,
    time::{Instant, sleep, timeout},
};

const UUID: &str = "6cbf3f72-3417-4922-bde6-67820d041f25";
const PASSWORD: &str = "tuic-stream-fixture-password";

#[tokio::test]
#[ignore = "requires PATHCHORD_TEST_SING_BOX pointing to sing-box 1.14.4"]
async fn tuic_udp_over_stream_interoperates_with_sing_box() {
    timeout(Duration::from_secs(25), async {
        let cert = rcgen::generate_simple_self_signed(vec!["tuic-stream.test".into()]).unwrap();
        let reserved = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = reserved.local_addr().unwrap().port();
        drop(reserved);
        let config = json!({"log":{"disabled":true}, "inbounds":[{
            "type":"tuic", "listen":"127.0.0.1", "listen_port":port,
            "users":[{"uuid":UUID,"password":PASSWORD}],
            "tls":{"enabled":true, "alpn":["h3"], "certificate":cert.cert.pem(), "key":cert.signing_key.serialize_pem()}
        }], "outbounds":[{"type":"direct"}]});
        let mut peer = Command::new(std::env::var_os("PATHCHORD_TEST_SING_BOX").unwrap())
            .args(["run", "-c", "stdin"]).stdin(Stdio::piped()).stdout(Stdio::null())
            .stderr(Stdio::null()).kill_on_drop(true).spawn().unwrap();
        peer.stdin.take().unwrap().write_all(&serde_json::to_vec(&config).unwrap()).await.unwrap();

        let node = TransitProxyConfig {
            id: TransitProxyId::new("tuic-stream-test"), source: None, protocol:"tuic".into(),
            endpoint:PolicyEndpoint {host:"127.0.0.1".into(), port}, credentials_ref:None,
            labels:BTreeMap::new(), tags:Default::default(), weight:100,
            options:TransitOptions { tls:Some(TransitTls {
                enabled:true, server_name:Some("tuic-stream.test".into()),
                truststore:Vec::new(), certificate:vec![cert.cert.pem()], alpn:vec!["h3".into()],
                ..Default::default()
            }), ..Default::default() },
        };
        let tls = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::aws_lc_rs::default_provider()))
            .with_safe_default_protocol_versions().unwrap().with_root_certificates(rustls::RootCertStore::empty()).with_no_client_auth();
        let registry = AdapterRegistry::new(Arc::new(NoTransitCredentials), Duration::from_secs(3), Arc::new(tls));
        let credentials = TransitCredential::new(BTreeMap::from([
            ("uuid".into(), UUID.into()), ("password".into(), PASSWORD.into()),
            ("udp_over_stream".into(), "true".into()), ("heartbeat".into(), "1s".into())
        ]));
        let adapter = registry.build_with_credential(&node, &credentials).unwrap();
        assert!(adapter.supports_udp());
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let tcp_address = target.local_addr().unwrap();
        let tcp_echo = tokio::spawn(async move {
            let (mut stream, _) = target.accept().await.unwrap();
            let mut payload = Vec::new();
            stream.read_to_end(&mut payload).await.unwrap();
            stream.write_all(&payload).await.unwrap();
            stream.shutdown().await.unwrap();
        });
        let deadline = Instant::now() + Duration::from_secs(6);
        let mut tcp = loop {
            let request = ConnectRequest {destination:Endpoint {host:"127.0.0.1".into(), port:tcp_address.port()}};
            match adapter.connect(request).await {
                Ok(stream) => break stream,
                Err(_) if Instant::now() < deadline => sleep(Duration::from_millis(40)).await,
                Err(error) => panic!("sing-box TUIC peer did not start: {error}"),
            }
        };
        tcp.write_all(b"tcp-half-close").await.unwrap();
        tcp.shutdown().await.unwrap();
        let mut response = Vec::new();
        tcp.read_to_end(&mut response).await.unwrap();
        assert_eq!(response, b"tcp-half-close");
        drop(tcp);
        tcp_echo.await.unwrap();

        for bind in ["127.0.0.1:0", "[::1]:0"] {
            let target = match UdpSocket::bind(bind).await {
                Ok(target) => target,
                Err(error) if bind.starts_with('[') && error.kind() == std::io::ErrorKind::AddrNotAvailable => continue,
                Err(error) => panic!("UDP target bind failed: {error}"),
            };
            let address = target.local_addr().unwrap();
            let echo = tokio::spawn(async move {
                let mut payload = vec![0; 65_536];
                for _ in 0..4 {
                    let (length, peer) = target.recv_from(&mut payload).await.unwrap();
                    target.send_to(&payload[..length], peer).await.unwrap();
                }
            });
            let mut socket = adapter.connect_udp(ConnectRequest { destination:Endpoint {host:address.ip().to_string(), port:address.port()} }).await.unwrap();
            for payload in [Vec::new(), b"udp-stream".to_vec(), vec![0x5a; 4096], vec![0x35; 16_384]] {
                socket.send(&payload).await.unwrap();
                let reply = timeout(Duration::from_secs(5), socket.receive()).await.unwrap().unwrap_or_else(|error| panic!("UDP reply failed for {bind}, length {}: {error}", payload.len()));
                assert_eq!(reply, payload);
            }
            socket.close().await.unwrap();
            echo.await.unwrap();
        }

        // The reference server's standard packet buffer is 16 KiB. The
        // protocol permits a larger frame, but this peer closes the stream
        // before forwarding a 16,385-byte datagram.
        let target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut oversized_for_peer = adapter.connect_udp(ConnectRequest {destination:Endpoint {host:"127.0.0.1".into(), port:target.local_addr().unwrap().port()}}).await.unwrap();
        oversized_for_peer.send(&vec![0x35; 16_385]).await.unwrap();
        let error = timeout(Duration::from_secs(5), oversized_for_peer.receive()).await.unwrap();
        assert!(error.is_err());
        assert!(timeout(Duration::from_millis(200), target.recv_from(&mut [0; 32])).await.is_err());
        drop(oversized_for_peer);

        let bad_credentials = TransitCredential::new(BTreeMap::from([
            ("uuid".into(), UUID.into()), ("password".into(), "wrong-password".into()),
            ("udp_over_stream".into(), "true".into())
        ]));
        let bad = registry.build_with_credential(&node, &bad_credentials).unwrap();
        let target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        if let Ok(mut rejected) = bad.connect_udp(ConnectRequest {destination:Endpoint {host:"127.0.0.1".into(), port:target.local_addr().unwrap().port()}}).await {
            let _ = rejected.send(b"must-not-arrive").await;
            let response = timeout(Duration::from_secs(5), rejected.receive()).await;
            assert!(response.is_err() || response.unwrap().is_err());
        }
        assert!(timeout(Duration::from_millis(200), target.recv_from(&mut [0; 32])).await.is_err());

        let mut wrong_server_name = node.clone();
        wrong_server_name.options.tls.as_mut().unwrap().server_name = Some("wrong.test".into());
        let wrong_tls = registry.build_with_credential(&wrong_server_name, &credentials).unwrap();
        assert!(wrong_tls.connect_udp(ConnectRequest {destination:Endpoint {host:"127.0.0.1".into(), port:53}}).await.is_err());
        peer.kill().await.unwrap();
        peer.wait().await.unwrap();
    }).await.expect("TUIC UDP-over-stream fixture timed out");
}
