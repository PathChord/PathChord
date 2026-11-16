//! sing-box multiplex interoperability against an independent server.

use std::{
    collections::BTreeMap,
    process::Stdio,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use pathchord_policy::{
    Endpoint as PolicyEndpoint, SubscriptionConfig, SubscriptionId, SubscriptionSource,
    SubscriptionSourceType, TransitMultiplex, TransitOptions, TransitProxyConfig, TransitProxyId,
    TransitTls,
};
use pathchord_transit::{
    AdapterRegistry, ConnectRequest, Endpoint, NoTransitCredentials, RefreshOutcome,
    SubscriptionError, SubscriptionFetchRequest, SubscriptionFetcher, SubscriptionManager,
    TransitCredential,
};
use serde_json::json;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, copy_bidirectional},
    net::{TcpListener, TcpStream, UdpSocket},
    process::Command,
    time::{Instant, sleep, timeout},
};

struct FixtureSubscription(Vec<u8>);

#[async_trait::async_trait]
impl SubscriptionFetcher for FixtureSubscription {
    async fn fetch(&self, _: SubscriptionFetchRequest) -> Result<Vec<u8>, SubscriptionError> {
        Ok(self.0.clone())
    }
}

#[tokio::test]
#[ignore = "requires PATHCHORD_TEST_SING_BOX pointing to sing-box 1.14.4"]
async fn revoked_subscription_blocks_new_selection_while_mux_stream_drains() {
    revoked_subscription_drains("h2mux").await;
}

#[tokio::test]
#[ignore = "requires PATHCHORD_TEST_SING_BOX pointing to sing-box 1.14.4"]
async fn revoked_subscription_blocks_new_selection_while_yamux_stream_drains() {
    revoked_subscription_drains("yamux").await;
}

#[tokio::test]
#[ignore = "requires PATHCHORD_TEST_SING_BOX pointing to sing-box 1.14.4"]
async fn revoked_subscription_blocks_new_selection_while_smux_stream_drains() {
    revoked_subscription_drains("smux").await;
}

async fn revoked_subscription_drains(mux_protocol: &str) {
    timeout(Duration::from_secs(15), async {
        let reserved = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = reserved.local_addr().unwrap().port();
        drop(reserved);
        let document = json!({"log":{"disabled":true},"inbounds":[{"type":"shadowsocks", "listen":"127.0.0.1", "listen_port":port, "method":"aes-128-gcm", "password":"test-password", "multiplex":{"enabled":true}}],"outbounds":[{"type":"direct"}]});
        let mut peer = Command::new(std::env::var_os("PATHCHORD_TEST_SING_BOX").unwrap())
            .args(["run", "-c", "stdin"]).stdin(Stdio::piped()).stdout(Stdio::null()).stderr(Stdio::null()).kill_on_drop(true).spawn().unwrap();
        peer.stdin.take().unwrap().write_all(&serde_json::to_vec(&document).unwrap()).await.unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        while TcpStream::connect(("127.0.0.1", port)).await.is_err() {
            assert!(Instant::now() < deadline, "sing-box peer readiness");
            sleep(Duration::from_millis(20)).await;
        }
        let imported = json!({"outbounds":[{"type":"shadowsocks", "tag":"fixture", "server":"127.0.0.1", "server_port":port, "method":"aes-128-gcm", "password":"test-password", "multiplex":{"enabled":true,"protocol":mux_protocol,"max_connections":1}}]});
        let subscription = SubscriptionConfig {
            id:SubscriptionId::new("mux-source"), enabled:true,
            source:SubscriptionSource {source_type:SubscriptionSourceType::SingBox, url:"https://fixture.invalid/subscription".into(), credentials_ref:None, user_agent:None},
            refresh:Default::default(), cache:None,
        };
        let mut manager = SubscriptionManager::new(Arc::new(FixtureSubscription(serde_json::to_vec(&imported).unwrap())), std::env::temp_dir(), ["ss".to_owned()].into_iter().collect());
        assert!(matches!(manager.refresh(&subscription).await, RefreshOutcome::Published{..}));
        let registry = AdapterRegistry::for_configs(Arc::new(NoTransitCredentials),Duration::from_secs(5),manager.snapshot().nodes.values().map(|node| &node.config)).unwrap();
        let prepared = manager.snapshot().prepare_adapters(&registry).await;
        manager.commit_prepared_adapters(prepared).unwrap();
        let id = manager.snapshot().selectable_nodes().next().unwrap().config.id.clone();
        let snapshot = manager.snapshot().clone();
        let admission = snapshot.validated_admission(&id).unwrap();
        let adapter = admission.adapter();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let tcp_port = listener.local_addr().unwrap().port();
        let echo = tokio::spawn(async move { let (mut stream, _)=listener.accept().await.unwrap(); let (mut read,mut write)=stream.split(); tokio::io::copy(&mut read,&mut write).await.unwrap(); });
        let mut stream = adapter.connect(ConnectRequest {destination:Endpoint {host:"127.0.0.1".into(),port:tcp_port}}).await.unwrap();
        stream.write_all(b"before").await.unwrap();
        let mut response=[0;6]; stream.read_exact(&mut response).await.unwrap(); assert_eq!(&response,b"before");
        manager.reconcile(&[]);
        assert!(!admission.revocation().is_valid());
        assert!(snapshot.validated_admission(&id).is_none());
        assert_eq!(manager.snapshot().selectable_nodes().count(),0);
        drop(admission); drop(adapter); drop(snapshot); drop(manager);
        stream.write_all(b"after!").await.unwrap();
        stream.read_exact(&mut response).await.unwrap(); assert_eq!(&response,b"after!");
        stream.shutdown().await.unwrap(); drop(stream); echo.await.unwrap();
        peer.kill().await.unwrap(); peer.wait().await.unwrap();
    }).await.expect("revoked subscription mux fixture timed out");
}

#[tokio::test]
#[ignore = "requires PATHCHORD_TEST_SING_BOX pointing to sing-box 1.14.4"]
async fn h2mux_interoperates_with_vless_vmess_and_trojan() {
    multiplex_protocol_matrix("h2mux", false).await;
}

#[tokio::test]
#[ignore = "requires PATHCHORD_TEST_SING_BOX pointing to sing-box 1.14.4"]
async fn yamux_interoperates_with_vless_vmess_and_trojan() {
    multiplex_protocol_matrix("yamux", false).await;
}

#[tokio::test]
#[ignore = "requires PATHCHORD_TEST_SING_BOX pointing to sing-box 1.14.4"]
async fn smux_interoperates_with_vless_vmess_and_trojan() {
    multiplex_protocol_matrix("smux", false).await;
}

#[tokio::test]
#[ignore = "requires PATHCHORD_TEST_SING_BOX pointing to sing-box 1.14.4"]
async fn padded_h2mux_interoperates_with_vless_vmess_and_trojan() {
    multiplex_protocol_matrix("h2mux", true).await;
}

#[tokio::test]
#[ignore = "requires PATHCHORD_TEST_SING_BOX pointing to sing-box 1.14.4"]
async fn padded_yamux_interoperates_with_vless_vmess_and_trojan() {
    multiplex_protocol_matrix("yamux", true).await;
}

#[tokio::test]
#[ignore = "requires PATHCHORD_TEST_SING_BOX pointing to sing-box 1.14.4"]
async fn padded_smux_interoperates_with_vless_vmess_and_trojan() {
    multiplex_protocol_matrix("smux", true).await;
}

async fn multiplex_protocol_matrix(mux_protocol: &str, padding: bool) {
    timeout(Duration::from_secs(25), async {
        let uuid = "6cbf3f72-3417-4922-bde6-67820d041f25";
        for (protocol, flow) in [("vless",None), ("vmess",None), ("trojan",None), ("vless",Some("xtls-rprx-vision")), ("vless",Some("xtls-rprx-vision-udp443"))] {
            let cert = rcgen::generate_simple_self_signed(vec!["mux-peer.test".into()]).unwrap();
            let reserved = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let port = reserved.local_addr().unwrap().port();
            drop(reserved);
            let users = if protocol == "trojan" {json!([{"password":"test-password"}])} else if flow.is_some() {json!([{"uuid":uuid,"flow":"xtls-rprx-vision"}])} else {json!([{"uuid":uuid}])};
            let mut inbound = json!({"type":protocol,"listen":"127.0.0.1","listen_port":port,"users":users,"multiplex":{"enabled":true,"padding":padding}});
            if protocol == "trojan" || flow.is_some() {
                inbound["tls"] = json!({"enabled":true,"certificate":cert.cert.pem(),"key":cert.signing_key.serialize_pem()});
            }
            let document = json!({"log":{"disabled":true},"inbounds":[inbound],"outbounds":[{"type":"direct"}]});
            let mut peer = Command::new(std::env::var_os("PATHCHORD_TEST_SING_BOX").unwrap())
                .args(["run", "-c", "stdin"]).stdin(Stdio::piped()).stdout(Stdio::null()).stderr(Stdio::null()).kill_on_drop(true).spawn().unwrap();
            peer.stdin.take().unwrap().write_all(&serde_json::to_vec(&document).unwrap()).await.unwrap();
            let deadline = Instant::now() + Duration::from_secs(5);
            while TcpStream::connect(("127.0.0.1",port)).await.is_err() {
                assert!(Instant::now() < deadline, "sing-box {protocol} readiness");
                sleep(Duration::from_millis(20)).await;
            }
            let node = TransitProxyConfig {
                id:TransitProxyId::new("mux-protocol-test"), source:None, protocol:protocol.into(),
                endpoint:PolicyEndpoint {host:"127.0.0.1".into(), port}, credentials_ref:None,
                labels:BTreeMap::new(), tags:Default::default(), weight:100,
                options:TransitOptions {
                    tls:(protocol == "trojan" || flow.is_some()).then(|| TransitTls {enabled:true, server_name:Some("mux-peer.test".into()), certificate:vec![cert.cert.pem()], ..Default::default()}),
                    multiplex:Some(TransitMultiplex {enabled:true, protocol:Some(mux_protocol.into()), max_connections:Some(1), padding, ..Default::default()}),
                    ..Default::default()
                },
            };
            let mut credentials = if protocol == "trojan" {
                BTreeMap::from([("password".into(), "test-password".into())])
            } else if protocol == "vmess" {
                BTreeMap::from([("uuid".into(), uuid.into()), ("security".into(), "aes-128-gcm".into())])
            } else { BTreeMap::from([("uuid".into(),uuid.into())]) };
            if let Some(flow) = flow { credentials.insert("flow".into(),flow.into()); }
            let credential = TransitCredential::new(credentials);
            let registry = AdapterRegistry::for_configs(Arc::new(NoTransitCredentials), Duration::from_secs(5), [&node]).unwrap();
            let adapter = registry.build_with_credential(&node, &credential).unwrap();
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let tcp_port = listener.local_addr().unwrap().port();
            let echo = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut data=[0; 5]; stream.read_exact(&mut data).await.unwrap(); stream.write_all(&data).await.unwrap();
            });
            let mut stream = adapter.connect(ConnectRequest {destination:Endpoint {host:"127.0.0.1".into(),port:tcp_port}}).await.unwrap();
            stream.write_all(b"hello").await.unwrap();
            let mut result = [0;5]; stream.read_exact(&mut result).await.unwrap(); assert_eq!(&result,b"hello", "{protocol}");
            echo.await.unwrap();
            let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let udp_port = udp.local_addr().unwrap().port();
            let udp_echo = tokio::spawn(async move {let mut data=[0;128];let (length,source)=udp.recv_from(&mut data).await.unwrap();udp.send_to(&data[..length],source).await.unwrap();});
            let mut packet=adapter.connect_udp(ConnectRequest {destination:Endpoint {host:"127.0.0.1".into(),port:udp_port}}).await.unwrap();
            packet.send(b"datagram").await.unwrap();
            assert_eq!(packet.receive().await.unwrap(),b"datagram", "{protocol}");
            packet.close().await.unwrap(); udp_echo.await.unwrap();
            drop(stream); drop(adapter); peer.kill().await.unwrap(); peer.wait().await.unwrap();
        }
    }).await.expect("sing-box h2mux protocol matrix timed out");
}

#[tokio::test]
#[ignore = "requires PATHCHORD_TEST_SING_BOX pointing to sing-box 1.14.4"]
async fn h2mux_reuses_one_shadowsocks_connection_for_tcp_and_udp() {
    multiplex_reuses_connection("h2mux", false).await;
}

#[tokio::test]
#[ignore = "requires PATHCHORD_TEST_SING_BOX pointing to sing-box 1.14.4"]
async fn yamux_reuses_one_shadowsocks_connection_for_tcp_and_udp() {
    multiplex_reuses_connection("yamux", false).await;
}

#[tokio::test]
#[ignore = "requires PATHCHORD_TEST_SING_BOX pointing to sing-box 1.14.4"]
async fn smux_reuses_one_shadowsocks_connection_for_tcp_and_udp() {
    multiplex_reuses_connection("smux", false).await;
}

#[tokio::test]
#[ignore = "requires PATHCHORD_TEST_SING_BOX pointing to sing-box 1.14.4"]
async fn padded_h2mux_reuses_one_shadowsocks_connection_for_tcp_and_udp() {
    multiplex_reuses_connection("h2mux", true).await;
}

#[tokio::test]
#[ignore = "requires PATHCHORD_TEST_SING_BOX pointing to sing-box 1.14.4"]
async fn padded_yamux_reuses_one_shadowsocks_connection_for_tcp_and_udp() {
    multiplex_reuses_connection("yamux", true).await;
}

#[tokio::test]
#[ignore = "requires PATHCHORD_TEST_SING_BOX pointing to sing-box 1.14.4"]
async fn padded_smux_reuses_one_shadowsocks_connection_for_tcp_and_udp() {
    multiplex_reuses_connection("smux", true).await;
}

#[tokio::test]
#[ignore = "requires PATHCHORD_TEST_SING_BOX pointing to sing-box 1.14.4"]
async fn smux_fin_matches_sing_box_full_close_semantics() {
    timeout(Duration::from_secs(15), async {
        let reserved = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = reserved.local_addr().unwrap().port();
        drop(reserved);
        let document = json!({"log":{"disabled":true},"inbounds":[{"type":"shadowsocks","listen":"127.0.0.1","listen_port":port,"method":"aes-128-gcm","password":"test-password","multiplex":{"enabled":true}}],"outbounds":[{"type":"direct"}]});
        let mut peer = Command::new(std::env::var_os("PATHCHORD_TEST_SING_BOX").unwrap())
            .args(["run", "-c", "stdin"])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        peer.stdin.take().unwrap().write_all(&serde_json::to_vec(&document).unwrap()).await.unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        while TcpStream::connect(("127.0.0.1", port)).await.is_err() {
            assert!(Instant::now() < deadline, "sing-box peer readiness");
            sleep(Duration::from_millis(20)).await;
        }
        let node = TransitProxyConfig {
            id: TransitProxyId::new("smux-fin-test"), source: None, protocol: "ss".into(),
            endpoint: PolicyEndpoint { host: "127.0.0.1".into(), port }, credentials_ref: None,
            labels: BTreeMap::new(), tags: Default::default(), weight: 100,
            options: TransitOptions { multiplex: Some(TransitMultiplex { enabled: true, protocol: Some("smux".into()), ..Default::default() }), ..Default::default() },
        };
        let credential = TransitCredential::new(BTreeMap::from([("cipher".into(), "aes-128-gcm".into()), ("password".into(), "test-password".into())]));
        let registry = AdapterRegistry::for_configs(Arc::new(NoTransitCredentials), Duration::from_secs(5), [&node]).unwrap();
        let adapter = registry.build_with_credential(&node, &credential).unwrap();
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_port = target.local_addr().unwrap().port();
        let backend = tokio::spawn(async move {
            let (mut connection, _) = target.accept().await.unwrap();
            connection.write_all(b"ready").await.unwrap();
            let mut request = Vec::new();
            connection.read_to_end(&mut request).await.unwrap();
            let _ = connection.write_all(b"late-response").await;
            request
        });
        let mut stream = adapter.connect(ConnectRequest {destination: Endpoint {host: "127.0.0.1".into(), port: target_port}}).await.unwrap();
        let mut ready = [0; 5];
        stream.read_exact(&mut ready).await.unwrap();
        assert_eq!(&ready, b"ready");
        stream.write_all(b"complete-request").await.unwrap();
        stream.shutdown().await.unwrap();
        assert_eq!(backend.await.unwrap(), b"complete-request");
        let mut late = [0; 32];
        let result = timeout(Duration::from_secs(1), stream.read(&mut late)).await;
        assert!(!matches!(result, Ok(Ok(length)) if length > 0), "sing-box smux does not forward a response sent after FIN");
        peer.kill().await.unwrap();
        peer.wait().await.unwrap();
    }).await.expect("smux FIN fixture timed out");
}

async fn multiplex_reuses_connection(mux_protocol: &str, padding: bool) {
    timeout(Duration::from_secs(20), async {
        let reserved = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = reserved.local_addr().unwrap().port();
        drop(reserved);
        let document = json!({"log":{"disabled":true},"inbounds":[{"type":"shadowsocks", "listen":"127.0.0.1", "listen_port":port, "method":"aes-128-gcm", "password":"test-password", "multiplex":{"enabled":true,"padding":padding}}],"outbounds":[{"type":"direct"}]});
        let mut peer = Command::new(std::env::var_os("PATHCHORD_TEST_SING_BOX").unwrap())
            .args(["run", "-c", "stdin"]).stdin(Stdio::piped()).stdout(Stdio::null()).stderr(Stdio::null()).kill_on_drop(true).spawn().unwrap();
        peer.stdin.take().unwrap().write_all(&serde_json::to_vec(&document).unwrap()).await.unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        while TcpStream::connect(("127.0.0.1", port)).await.is_err() {
            assert!(Instant::now() < deadline, "sing-box peer readiness");
            sleep(Duration::from_millis(20)).await;
        }
        let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = proxy.local_addr().unwrap();
        let accepted = Arc::new(AtomicUsize::new(0));
        let count = Arc::clone(&accepted);
        let forwarder = tokio::spawn(async move {
            while let Ok((mut client, _)) = proxy.accept().await {
                count.fetch_add(1, Ordering::SeqCst);
                tokio::spawn(async move {
                    if let Ok(mut server) = TcpStream::connect(("127.0.0.1", port)).await {
                        let _ = copy_bidirectional(&mut client, &mut server).await;
                    }
                });
            }
        });
        let node = TransitProxyConfig {
            id:TransitProxyId::new("sing-mux-test"), source:None, protocol:"ss".into(),
            endpoint:PolicyEndpoint {host:"127.0.0.1".into(), port:address.port()}, credentials_ref:None,
            labels:BTreeMap::new(), tags:Default::default(), weight:100,
            options:TransitOptions {multiplex:Some(TransitMultiplex {enabled:true, protocol:Some(mux_protocol.into()), max_connections:Some(1), padding, ..Default::default()}), ..Default::default()},
        };
        let credential = TransitCredential::new(BTreeMap::from([("cipher".into(), "aes-128-gcm".into()), ("password".into(), "test-password".into())]));
        let registry = AdapterRegistry::for_configs(Arc::new(NoTransitCredentials), Duration::from_secs(5), [&node]).unwrap();
        let adapter = registry.build_with_credential(&node, &credential).unwrap();
        assert!(adapter.supports_udp());
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let tcp_port = listener.local_addr().unwrap().port();
        let echo = tokio::spawn(async move {
            for _ in 0..2 {
                let (mut stream, _) = listener.accept().await.unwrap();
                tokio::spawn(async move { let (mut read, mut write) = stream.split(); let _ = tokio::io::copy(&mut read, &mut write).await; });
            }
        });
        let request = || ConnectRequest {destination:Endpoint {host:"127.0.0.1".into(), port:tcp_port}};
        let (first, second) = tokio::join!(adapter.connect(request()), adapter.connect(request()));
        let mut first = first.unwrap();
        let mut second = second.unwrap();
        first.write_all(b"first").await.unwrap();
        second.write_all(b"second").await.unwrap();
        let mut first_reply = [0;5];
        let mut second_reply = [0;6];
        first.read_exact(&mut first_reply).await.unwrap();
        second.read_exact(&mut second_reply).await.unwrap();
        assert_eq!(&first_reply, b"first");
        assert_eq!(&second_reply, b"second");
        for byte in 0..24 {
            let payload = vec![byte; 8192];
            first.write_all(&payload).await.unwrap();
            let mut response = vec![0; payload.len()];
            first.read_exact(&mut response).await.unwrap();
            assert_eq!(response, payload);
        }

        let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let udp_port = udp.local_addr().unwrap().port();
        let udp_task = tokio::spawn(async move { let mut input=[0;4096]; let (length,source)=udp.recv_from(&mut input).await.unwrap(); udp.send_to(&input[..length],source).await.unwrap(); });
        let mut packet = adapter.connect_udp(ConnectRequest {destination:Endpoint {host:"127.0.0.1".into(), port:udp_port}}).await.unwrap();
        packet.send(b"udp-mux").await.unwrap();
        assert_eq!(packet.receive().await.unwrap(), b"udp-mux");
        packet.close().await.unwrap();
        udp_task.await.unwrap();
        for _ in 0..5 {
            let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let mut packet = adapter.connect_udp(ConnectRequest {destination:Endpoint {host:"127.0.0.1".into(), port:udp.local_addr().unwrap().port()}}).await.unwrap();
            packet.send(b"close-after-send").await.unwrap();
            // With no UDP response the sing-box peer ends without a mux
            // success byte, so delivery remains unconfirmed even if the
            // datagram reached the target.
            assert!(packet.close().await.is_err());
            let mut data = [0; 32];
            let (length, _) = timeout(Duration::from_secs(2), udp.recv_from(&mut data)).await.unwrap().unwrap();
            assert_eq!(&data[..length], b"close-after-send");
        }
        let unused = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let unused_port = unused.local_addr().unwrap().port();
        drop(unused);
        let mut rejected = adapter.connect(ConnectRequest {destination:Endpoint {host:"127.0.0.1".into(),port:unused_port}}).await.unwrap();
        let _ = rejected.write_all(b"probe").await;
        let mut rejected_reply = [0; 1];
        let rejected_result = timeout(Duration::from_secs(5), rejected.read(&mut rejected_reply)).await.unwrap();
        assert!(!matches!(rejected_result, Ok(length) if length > 0));
        drop(rejected);
        first.shutdown().await.unwrap();
        drop(first);
        let mut waiting = [0; 1];
        assert!(timeout(Duration::from_millis(50), second.read(&mut waiting)).await.is_err());
        second.write_all(b"still-live").await.unwrap();
        let mut result = [0;10];
        second.read_exact(&mut result).await.unwrap();
        assert_eq!(&result,b"still-live");
        assert_eq!(accepted.load(Ordering::SeqCst), 1, "all flows share one encrypted proxy connection");
        second.shutdown().await.unwrap();
        drop(second);
        echo.await.unwrap();
        let bad_credential = TransitCredential::new(BTreeMap::from([("cipher".into(), "aes-128-gcm".into()), ("password".into(), "wrong-password".into())]));
        let bad = registry.build_with_credential(&node, &bad_credential).unwrap();
        let forbidden = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let bad_request = ConnectRequest {destination:Endpoint {host:"127.0.0.1".into(),port:forbidden.local_addr().unwrap().port()}};
        if let Ok(mut stream) = bad.connect(bad_request).await {
            let _ = stream.write_all(b"must-not-arrive").await;
            let mut byte = [0; 1];
            assert!(!matches!(timeout(Duration::from_secs(3), stream.read(&mut byte)).await, Ok(Ok(length)) if length > 0));
        }
        assert!(timeout(Duration::from_millis(200), forbidden.accept()).await.is_err());
        drop(bad);
        drop(adapter);
        forwarder.abort();
        peer.kill().await.unwrap();
        peer.wait().await.unwrap();
    }).await.expect("sing-box h2mux fixture timed out");
}
