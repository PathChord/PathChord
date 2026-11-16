//! VLESS packetaddr interoperability with independent sing-box and Xray peers.

use std::{collections::BTreeMap, process::Stdio, sync::Arc, time::Duration};

use pathchord_policy::{
    Endpoint as PolicyEndpoint, TransitOptions, TransitProxyConfig, TransitProxyId,
};
use pathchord_transit::{
    AdapterRegistry, ConnectRequest, Endpoint, NoTransitCredentials, TransitCredential,
    TransitError,
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
#[ignore = "requires PATHCHORD_TEST_SING_BOX and PATHCHORD_TEST_XRAY"]
async fn vless_packetaddr_roundtrips_with_singbox_and_xray_lacks_packetaddr() {
    timeout(Duration::from_secs(20), async {
        for (environment, xray) in [("PATHCHORD_TEST_SING_BOX", false), ("PATHCHORD_TEST_XRAY", true)] {
            let binary = std::env::var_os(environment).expect("independent server binary");
            let reserved = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let port = reserved.local_addr().unwrap().port();
            drop(reserved);
            let document = if xray {
                json!({"log": {"loglevel": "none"},
                    "inbounds": [{"listen": "127.0.0.1", "port": port, "protocol": "vless", "settings": {"clients": [{"id": UUID}], "decryption": "none"}}],
                    "outbounds": [{"protocol": "freedom", "settings": {"finalRules": [{"action": "allow"}]}}]})
            } else {
                json!({"log": {"disabled": true},
                    "inbounds": [{"type": "vless", "listen": "127.0.0.1", "listen_port": port, "users": [{"uuid": UUID}]}],
                    "outbounds": [{"type": "direct", "tag": "direct"}], "route": {"final": "direct"}})
            };
            let mut peer = Command::new(binary).arg("run").arg("-c").arg(if xray { "stdin:" } else { "stdin" })
                .stdin(Stdio::piped()).stdout(Stdio::null()).stderr(Stdio::null()).kill_on_drop(true).spawn().unwrap();
            peer.stdin.take().unwrap().write_all(&serde_json::to_vec(&document).unwrap()).await.unwrap();
            let deadline = Instant::now() + Duration::from_secs(5);
            while TcpStream::connect(("127.0.0.1", port)).await.is_err() {
                assert!(peer.try_wait().unwrap().is_none(), "server exited");
                assert!(Instant::now() < deadline, "server readiness timed out");
                sleep(Duration::from_millis(20)).await;
            }
            let config = TransitProxyConfig {
                id: TransitProxyId::new("vless-packetaddr"), source: None, protocol: "vless".into(),
                endpoint: PolicyEndpoint { host: "127.0.0.1".into(), port }, credentials_ref: None,
                labels: Default::default(), tags: Default::default(), weight: 1,
                options: TransitOptions { packet_encoding: Some("packetaddr".into()), ..Default::default() },
            };
            let credential = TransitCredential::new(BTreeMap::from([("uuid".into(), UUID.into())]));
            let adapter = AdapterRegistry::for_configs(Arc::new(NoTransitCredentials), Duration::from_secs(3), [&config])
                .unwrap().build_with_credential(&config, &credential).unwrap();
            let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let tcp_port = target.local_addr().unwrap().port();
            let echo = tokio::spawn(async move {
                let (mut stream, _) = target.accept().await.unwrap();
                let mut payload = [0; 3]; stream.read_exact(&mut payload).await.unwrap();
                stream.write_all(&payload).await.unwrap();
            });
            let mut stream = adapter.connect(ConnectRequest { destination: Endpoint { host: "127.0.0.1".into(), port: tcp_port } }).await.unwrap();
            stream.write_all(b"tcp").await.unwrap(); stream.flush().await.unwrap();
            let mut response = [0; 3]; stream.read_exact(&mut response).await.unwrap();
            assert_eq!(&response, b"tcp"); echo.await.unwrap();
            let domain = adapter.connect_udp(ConnectRequest { destination: Endpoint { host: "example.test".into(), port: 53 } }).await;
            assert!(matches!(domain, Err(TransitError::Unsupported(reason)) if reason.contains("IP destination")));
            for host in ["127.0.0.1", "::1"] {
                let udp = UdpSocket::bind((host, 0)).await.unwrap();
                let address = udp.local_addr().unwrap();
                let echo = tokio::spawn(async move {
                    let mut bytes = [0; 8192];
                    for _ in 0..3 {
                        let (n, source) = udp.recv_from(&mut bytes).await.unwrap();
                        udp.send_to(&bytes[..n], source).await.unwrap();
                    }
                });
                let mut socket = adapter.connect_udp(ConnectRequest { destination: Endpoint { host: address.ip().to_string(), port: address.port() } }).await.unwrap();
                let large = vec![0x53; 4096];
                if xray {
                    socket.send(b"unsupported").await.unwrap();
                    assert!(!matches!(timeout(Duration::from_millis(800), socket.receive()).await, Ok(Ok(_))), "Xray unexpectedly accepted packetaddr");
                    echo.abort();
                    let _ = socket.close().await;
                } else {
                    for payload in [b"one".as_slice(), b"two", large.as_slice()] {
                        socket.send(payload).await.unwrap();
                        assert_eq!(timeout(Duration::from_secs(3), socket.receive()).await.unwrap().unwrap(), payload);
                    }
                    socket.close().await.unwrap(); echo.await.unwrap();
                }
            }
            peer.kill().await.unwrap(); peer.wait().await.unwrap();
        }
    }).await.expect("packetaddr peer test timed out");
}

#[tokio::test]
#[ignore = "requires PATHCHORD_TEST_SING_BOX"]
async fn direct_tls_packetaddr_preserves_tcp_and_udp() {
    use pathchord_policy::TransitTls;
    timeout(Duration::from_secs(15), async {
        let binary = std::env::var_os("PATHCHORD_TEST_SING_BOX").expect("sing-box binary");
        let cert = rcgen::generate_simple_self_signed(vec!["packetaddr.test".into()]).unwrap();
        let reserved = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = reserved.local_addr().unwrap().port(); drop(reserved);
        let document = json!({"log":{"disabled":true}, "inbounds":[{
            "type":"vless", "listen":"127.0.0.1", "listen_port":port, "users":[{"uuid":UUID}],
            "tls":{"enabled":true,"certificate":cert.cert.pem(),"key":cert.signing_key.serialize_pem()}
        }], "outbounds":[{"type":"direct","tag":"direct"}], "route":{"final":"direct"}});
        let mut peer = Command::new(binary).args(["run", "-c", "stdin"]).stdin(Stdio::piped())
            .stdout(Stdio::null()).stderr(Stdio::null()).kill_on_drop(true).spawn().unwrap();
        peer.stdin.take().unwrap().write_all(&serde_json::to_vec(&document).unwrap()).await.unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        while TcpStream::connect(("127.0.0.1",port)).await.is_err() {
            assert!(peer.try_wait().unwrap().is_none()); assert!(Instant::now()<deadline); sleep(Duration::from_millis(20)).await;
        }
        let config = TransitProxyConfig { id: TransitProxyId::new("tls-packetaddr"), source: None, protocol: "vless".into(),
            endpoint: PolicyEndpoint { host:"127.0.0.1".into(), port }, credentials_ref:None, labels:Default::default(), tags:Default::default(), weight:1,
            options: TransitOptions { packet_encoding:Some("packetaddr".into()), tls:Some(TransitTls {
                enabled:true, server_name:Some("packetaddr.test".into()), truststore:Vec::new(), certificate:vec![cert.cert.pem()], ..Default::default()
            }), ..Default::default() } };
        let credential=TransitCredential::new(BTreeMap::from([("uuid".into(),UUID.into())]));
        let adapter=AdapterRegistry::for_configs(Arc::new(NoTransitCredentials),Duration::from_secs(3),[&config]).unwrap().build_with_credential(&config,&credential).unwrap();
        let tcp=TcpListener::bind("127.0.0.1:0").await.unwrap(); let port=tcp.local_addr().unwrap().port();
        let echo=tokio::spawn(async move { let (mut s,_)=tcp.accept().await.unwrap(); let mut b=[0;3]; s.read_exact(&mut b).await.unwrap(); s.write_all(&b).await.unwrap(); });
        let mut stream=adapter.connect(ConnectRequest { destination:Endpoint {host:"127.0.0.1".into(),port} }).await.unwrap();
        stream.write_all(b"tcp").await.unwrap();stream.flush().await.unwrap();let mut result=[0;3];stream.read_exact(&mut result).await.unwrap();assert_eq!(&result,b"tcp");echo.await.unwrap();
        for host in ["127.0.0.1","::1"] {
            let udp=UdpSocket::bind((host,0)).await.unwrap();let address=udp.local_addr().unwrap();
            let echo=tokio::spawn(async move {let mut b=[0;64];let (n,from)=udp.recv_from(&mut b).await.unwrap();udp.send_to(&b[..n],from).await.unwrap();});
            let mut socket=adapter.connect_udp(ConnectRequest {destination:Endpoint {host:address.ip().to_string(),port:address.port()}}).await.unwrap();
            socket.send(b"udp").await.unwrap();assert_eq!(timeout(Duration::from_secs(3),socket.receive()).await.unwrap().unwrap(),b"udp");socket.close().await.unwrap();echo.await.unwrap();
        }
        peer.kill().await.unwrap();peer.wait().await.unwrap();
    }).await.expect("TLS packetaddr test timed out");
}

#[tokio::test]
#[ignore = "requires PATHCHORD_TEST_SING_BOX"]
async fn reality_packetaddr_preserves_tcp_and_udp() {
    use pathchord_policy::{TransitReality, TransitTls};
    use rustls::pki_types::PrivatePkcs8KeyDer;
    use tokio_rustls::TlsAcceptor;
    timeout(Duration::from_secs(20), async {
        let binary = std::env::var_os("PATHCHORD_TEST_SING_BOX").expect("sing-box binary");
        let decoy_cert = rcgen::generate_simple_self_signed(vec!["decoy.test".into()]).unwrap();
        let mut provider = rustls::crypto::aws_lc_rs::default_provider();
        provider.kx_groups = vec![rustls::crypto::aws_lc_rs::kx_group::X25519];
        let server_tls = rustls::ServerConfig::builder_with_provider(Arc::new(provider))
            .with_safe_default_protocol_versions().unwrap().with_no_client_auth()
            .with_single_cert(vec![decoy_cert.cert.der().clone()], PrivatePkcs8KeyDer::from(decoy_cert.signing_key.serialize_der()).into()).unwrap();
        let decoy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let decoy_port = decoy.local_addr().unwrap().port();
        let acceptor = TlsAcceptor::from(Arc::new(server_tls));
        let decoy_task = tokio::spawn(async move {
            while let Ok((stream, _)) = decoy.accept().await {
                let acceptor = acceptor.clone();
                tokio::spawn(async move { let _ = acceptor.accept(stream).await; });
            }
        });
        let reservation = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = reservation.local_addr().unwrap().port(); drop(reservation);
        let document = json!({"log": {"disabled": true}, "inbounds": [{
            "type": "vless", "listen": "127.0.0.1", "listen_port": port, "users": [{"uuid": UUID}],
            "tls": {"enabled": true, "server_name": "decoy.test", "reality": {"enabled": true,
                "handshake": {"server": "127.0.0.1", "server_port": decoy_port},
                "private_key": "-AxPYYdSOc0L8SVojHT0CHsejcb15DcdD2ZI8QaALlo", "short_id": ["0123456789abcdef"]}}
        }], "outbounds": [{"type": "direct", "tag": "direct"}], "route": {"final": "direct"}});
        let mut peer = Command::new(binary).args(["run", "-c", "stdin"]).stdin(Stdio::piped())
            .stdout(Stdio::null()).stderr(Stdio::null()).kill_on_drop(true).spawn().unwrap();
        peer.stdin.take().unwrap().write_all(&serde_json::to_vec(&document).unwrap()).await.unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        while TcpStream::connect(("127.0.0.1", port)).await.is_err() {
            assert!(peer.try_wait().unwrap().is_none()); assert!(Instant::now() < deadline); sleep(Duration::from_millis(20)).await;
        }
        let mut config = TransitProxyConfig { id: TransitProxyId::new("reality-packetaddr"), source: None,
            protocol: "vless".into(), endpoint: PolicyEndpoint { host: "127.0.0.1".into(), port },
            credentials_ref: None, labels: Default::default(), tags: Default::default(), weight: 1,
            options: TransitOptions { tls: Some(TransitTls { enabled: true, server_name: Some("decoy.test".into()),
                fingerprint: Some("ios".into()), reality: Some(TransitReality {
                    public_key: "Q7VhOFla3pZJiGzjiNfwi3j-QfEr9FOdDpQIiDANtRM".into(), short_id: "0123456789abcdef".into(),
                }), ..Default::default() }), packet_encoding: Some("packetaddr".into()), ..Default::default() },
        };
        let credential = TransitCredential::new(BTreeMap::from([("uuid".into(), UUID.into())]));
        let registry = AdapterRegistry::for_configs(Arc::new(NoTransitCredentials), Duration::from_secs(5), [&config]).unwrap();
        let adapter = registry.build_with_credential(&config, &credential).unwrap();
        let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap(); let tcp_port = tcp.local_addr().unwrap().port();
        let echo = tokio::spawn(async move { let (mut stream, _) = tcp.accept().await.unwrap(); let mut data = [0; 3]; stream.read_exact(&mut data).await.unwrap(); stream.write_all(&data).await.unwrap(); });
        let mut stream = adapter.connect(ConnectRequest { destination: Endpoint { host: "127.0.0.1".into(), port: tcp_port } }).await.unwrap();
        stream.write_all(b"tcp").await.unwrap(); stream.flush().await.unwrap(); let mut reply = [0; 3]; stream.read_exact(&mut reply).await.unwrap(); assert_eq!(&reply, b"tcp"); echo.await.unwrap();
        for host in ["127.0.0.1", "::1"] {
            let udp = UdpSocket::bind((host, 0)).await.unwrap(); let address = udp.local_addr().unwrap();
            let echo = tokio::spawn(async move { let mut data = [0; 4096]; for _ in 0..2 { let (n, source) = udp.recv_from(&mut data).await.unwrap(); udp.send_to(&data[..n], source).await.unwrap(); } });
            let mut socket = adapter.connect_udp(ConnectRequest { destination: Endpoint { host: address.ip().to_string(), port: address.port() } }).await.unwrap();
            let large = vec![0x62; 4096]; for payload in [b"hello".as_slice(), large.as_slice()] { socket.send(payload).await.unwrap(); assert_eq!(timeout(Duration::from_secs(3), socket.receive()).await.unwrap().unwrap(), payload); }
            socket.close().await.unwrap(); echo.await.unwrap();
        }
        let domain = adapter.connect_udp(ConnectRequest { destination: Endpoint { host: "example.test".into(), port: 53 } }).await;
        assert!(matches!(domain, Err(TransitError::Unsupported(reason)) if reason.contains("IP destination")));
        let vision = TransitCredential::new(BTreeMap::from([("uuid".into(), UUID.into()), ("flow".into(), "xtls-rprx-vision".into())]));
        assert!(matches!(registry.build_with_credential(&config, &vision), Err(TransitError::Unsupported(reason)) if reason.contains("Vision") && reason.contains("XUDP")));
        config.options.packet_encoding = Some("xudp".into());
        assert!(registry.build_with_credential(&config, &vision).is_ok());
        peer.kill().await.unwrap(); peer.wait().await.unwrap(); decoy_task.abort();
    }).await.expect("REALITY packetaddr test timed out");
}
