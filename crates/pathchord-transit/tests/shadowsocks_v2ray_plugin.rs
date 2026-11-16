//! Shadowsocks SIP003 v2ray-plugin compatibility and independent peers.
//!
//! Set `PATHCHORD_TEST_V2RAY_PLUGIN` to an upstream server binary and run this
//! target with `-- --ignored` to exercise the external fixtures. In a separate
//! client/server check of upstream commit `7d70ea7a51a79f91f53a490cca40556fa744ce90`,
//! neither `mux=0` nor `mux=1` returned a response sent after the client write
//! half-close. The interoperability fixture therefore makes no end-to-end
//! half-close claim.

use std::{collections::BTreeMap, net::SocketAddr, path::PathBuf, process::Stdio, time::Duration};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use pathchord_policy::{Endpoint as PolicyEndpoint, TransitProxyConfig, TransitProxyId};
use pathchord_transit::{
    ConnectRequest, Endpoint, ShadowsocksTransitAdapter, SubscriptionCredential, TransitAdapter,
};
use sha2::{Digest, Sha256};
use shadowsocks::{
    ProxyListener, ProxySocket,
    config::{ServerConfig, ServerType},
    context::Context,
    crypto::CipherKind,
    relay::socks5::Address,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    process::{Child, Command},
    time::{sleep, timeout},
};

fn config(address: SocketAddr) -> TransitProxyConfig {
    TransitProxyConfig {
        id: TransitProxyId::new("v2ray-plugin-test"),
        source: None,
        protocol: "ss".into(),
        endpoint: PolicyEndpoint {
            host: address.ip().to_string(),
            port: address.port(),
        },
        credentials_ref: None,
        labels: Default::default(),
        tags: Default::default(),
        weight: 1,
        options: Default::default(),
    }
}

fn credentials(options: Option<&str>) -> SubscriptionCredential {
    let mut values = BTreeMap::from([
        ("cipher".into(), "aes-256-gcm".into()),
        ("password".into(), "plugin-test-password".into()),
        ("plugin".into(), "v2ray-plugin".into()),
    ]);
    if let Some(options) = options {
        values.insert("plugin_opts".into(), options.into());
    }
    SubscriptionCredential::new(values)
}

#[test]
fn accepts_v2ray_plugin_sip003_and_clash_websocket_options() {
    let node = config("127.0.0.1:8388".parse().unwrap());
    for options in [
        None,
        Some("mode=websocket;host=plugin.test;path=/proxy;tls;mux=0"),
        Some("host=plugin.test;path=/proxy;mux=1"),
        Some(
            r#"{"mode":"websocket","host":"plugin.test","path":"/proxy","tls":true,"skip-cert-verify":true,"mux":false,"headers":{"x-plugin-test":"value"}}"#,
        ),
    ] {
        let adapter = ShadowsocksTransitAdapter::from_subscription(
            &node,
            &credentials(options),
            Duration::from_secs(3),
        );
        assert!(adapter.is_ok(), "valid plugin options were rejected");
        assert!(adapter.unwrap().supports_udp());
    }
}

#[test]
fn rejects_v2ray_plugin_options_that_cannot_be_consumed() {
    let node = config("127.0.0.1:8388".parse().unwrap());
    for options in [
        "mode=quic;host=plugin.test",
        "mode=websocket;mux=2",
        "mode=websocket;unknown=value",
        "mode=websocket;server",
        "mode=websocket;tls;tls",
        "mode=websocket;host=plugin.test\\",
        "mode=websocket;path=/proxy#fragment",
        "mode=websocket;host=user@plugin.test",
        r#"{"mode":"websocket","mux":2}"#,
        r#"{"mode":"websocket","tls":false,"skip-cert-verify":true}"#,
        r#"{"mode":"websocket","host":"one.test","host":"two.test"}"#,
        r#"{"mode":"websocket","v2ray-http-upgrade":true}"#,
        r#"{"mode":"websocket","headers":{"Host":"different.test"},"host":"one.test"}"#,
    ] {
        assert!(
            ShadowsocksTransitAdapter::from_subscription(
                &node,
                &credentials(Some(options)),
                Duration::from_secs(3)
            )
            .is_err(),
            "unsupported plugin options must be rejected"
        );
    }
}

#[test]
fn plugin_and_shadowsocks_credentials_are_redacted_from_adapter_debug() {
    let node = config("127.0.0.1:8388".parse().unwrap());
    let options = r#"{"mode":"websocket","host":"plugin.test","mux":false,"headers":{"Authorization":"Bearer header-sentinel"}}"#;
    let adapter = ShadowsocksTransitAdapter::from_subscription(
        &node,
        &credentials(Some(options)),
        Duration::from_secs(3),
    )
    .unwrap();
    let debug = format!("{adapter:?}");
    assert!(!debug.contains("header-sentinel"));
    assert!(!debug.contains("plugin-test-password"));
}

#[tokio::test]
async fn websocket_handshake_preserves_path_and_headers_and_cancels_cleanly() {
    timeout(Duration::from_secs(5), async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let node = config(listener.local_addr().unwrap());
        let options = r#"{"mode":"websocket","host":"plugin.test","path":"/proxy?ed=23","mux":false,"headers":{"Authorization":"Bearer header-sentinel","X-Plugin-Test":"custom"}}"#;
        let adapter = ShadowsocksTransitAdapter::from_subscription(&node, &credentials(Some(options)), Duration::from_secs(3)).unwrap();
        let attempt = tokio::spawn(async move { adapter.connect(request()).await });
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut header = Vec::new();
        while !header.ends_with(b"\r\n\r\n") {
            header.push(stream.read_u8().await.unwrap());
            assert!(header.len() < 16 * 1024);
        }
        let header = std::str::from_utf8(&header).unwrap();
        assert!(header.starts_with("GET /proxy?ed=23 HTTP/1.1\r\n"));
        assert!(header.lines().any(|line| line.eq_ignore_ascii_case("host: plugin.test")));
        assert!(header.lines().any(|line| line.eq_ignore_ascii_case("authorization: Bearer header-sentinel")));
        assert!(header.lines().any(|line| line.eq_ignore_ascii_case("x-plugin-test: custom")));
        attempt.abort();
        assert!(matches!(attempt.await, Err(error) if error.is_cancelled()));
        assert_eq!(timeout(Duration::from_secs(2), stream.read(&mut [0; 1])).await.unwrap().unwrap(), 0);
    }).await.expect("cancelled WebSocket handshake was not cleaned up");
}

#[tokio::test]
async fn invalid_websocket_upgrade_does_not_send_shadowsocks_bytes() {
    timeout(Duration::from_secs(5), async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let node = config(listener.local_addr().unwrap());
        let options = "host=plugin.test;path=/proxy;mux=0";
        let adapter = ShadowsocksTransitAdapter::from_subscription(&node, &credentials(Some(options)), Duration::from_secs(3)).unwrap();
        let peer = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut header = Vec::new();
            while !header.ends_with(b"\r\n\r\n") { header.push(stream.read_u8().await.unwrap()); }
            stream.write_all(b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: invalid\r\n\r\n").await.unwrap();
            let mut byte = [0];
            assert_eq!(timeout(Duration::from_secs(2), stream.read(&mut byte)).await.unwrap().unwrap(), 0);
        });
        assert!(adapter.connect(request()).await.is_err());
        peer.await.unwrap();
    }).await.expect("invalid upgrade test timed out");
}

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new() -> Self {
        let mut random = [0; 8];
        getrandom::fill(&mut random).unwrap();
        let path = std::env::temp_dir().join(format!(
            "pathchord-v2ray-plugin-{}-{:016x}",
            std::process::id(),
            u64::from_ne_bytes(random)
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

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

struct PluginServer {
    child: Child,
    _directory: TestDirectory,
    port: u16,
    certificate_raw: String,
}

impl PluginServer {
    async fn start(backend: SocketAddr, port: u16, tls: bool, mux: bool) -> Self {
        let binary = std::env::var_os("PATHCHORD_TEST_V2RAY_PLUGIN")
            .expect("PATHCHORD_TEST_V2RAY_PLUGIN required");
        let directory = TestDirectory::new();
        let rcgen::CertifiedKey { cert, signing_key } =
            rcgen::generate_simple_self_signed(vec!["plugin.test".into()]).unwrap();
        let certificate_raw = STANDARD.encode(cert.der());
        std::fs::write(directory.0.join("server.pem"), cert.pem()).unwrap();
        std::fs::write(directory.0.join("server.key"), signing_key.serialize_pem()).unwrap();
        let mut command = Command::new(binary);
        command.args([
            "-server",
            "-localAddr",
            "127.0.0.1",
            "-localPort",
            &port.to_string(),
            "-remoteAddr",
            "127.0.0.1",
            "-remotePort",
            &backend.port().to_string(),
            "-mode",
            "websocket",
            "-path",
            "/proxy",
            "-host",
            "plugin.test",
            "-mux",
            if mux { "1" } else { "0" },
        ]);
        if tls {
            command
                .arg("-tls")
                .arg("-cert")
                .arg(directory.0.join("server.pem"))
                .arg("-key")
                .arg(directory.0.join("server.key"));
        }
        for variable in [
            "SS_LOCAL_HOST",
            "SS_LOCAL_PORT",
            "SS_REMOTE_HOST",
            "SS_REMOTE_PORT",
            "SS_PLUGIN_OPTIONS",
        ] {
            command.env_remove(variable);
        }
        let mut child = command
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        timeout(Duration::from_secs(5), async {
            loop {
                assert!(
                    child.try_wait().unwrap().is_none(),
                    "v2ray-plugin server exited"
                );
                if TcpStream::connect(("127.0.0.1", port)).await.is_ok() {
                    break;
                }
                sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("v2ray-plugin server startup timed out");
        Self {
            child,
            _directory: directory,
            port,
            certificate_raw,
        }
    }
}

impl Drop for PluginServer {
    fn drop(&mut self) {
        let _ = self.child.start_kill();
    }
}

fn request() -> ConnectRequest {
    ConnectRequest {
        destination: Endpoint {
            host: "target.example".into(),
            port: 443,
        },
    }
}

#[tokio::test]
#[ignore = "requires PATHCHORD_TEST_V2RAY_PLUGIN pointing to an independent server binary"]
async fn upstream_v2ray_plugin_websocket_tls_and_mux_relay_shadowsocks_tcp_udp() {
    timeout(Duration::from_secs(45), async {
        for tls in [false, true] {
            for mux in [false, true] {
                for json_options in [false, true] {
                let backend_config = ServerConfig::new(
                    "127.0.0.1:0".parse::<SocketAddr>().unwrap(),
                    "plugin-test-password",
                    CipherKind::AES_256_GCM,
                )
                .unwrap();
                let backend =
                    ProxyListener::bind(Context::new_shared(ServerType::Server), &backend_config)
                        .await
                        .unwrap();
                let backend_addr = backend.local_addr().unwrap();
                let (handshake_tx, handshake_rx) = tokio::sync::oneshot::channel();
                let backend_task = tokio::spawn(async move {
                    let mut stream = loop {
                        let (mut stream, _) = backend.accept().await.unwrap();
                        if let Ok(address) = stream.handshake().await {
                            assert_eq!(
                                address,
                                Address::DomainNameAddress("target.example".into(), 443)
                            );
                            break stream;
                        }
                    };
                    handshake_tx.send(()).unwrap();
                    let mut payload = vec![0; 131_333];
                    stream.read_exact(&mut payload).await.unwrap();
                    stream.write_all(&payload).await.unwrap();
                    stream.flush().await.unwrap();
                });
                let reserve = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
                let port = reserve.local_addr().unwrap().port();
                drop(reserve);
                let udp_config = ServerConfig::new(
                    SocketAddr::from(([127, 0, 0, 1], port)),
                    "plugin-test-password",
                    CipherKind::AES_256_GCM,
                )
                .unwrap();
                let udp = ProxySocket::bind(Context::new_shared(ServerType::Server), &udp_config)
                    .await
                    .unwrap();
                let udp_task = tokio::spawn(async move {
                    let mut packet = [0; 2048];
                    for _ in 0..2 {
                        let (size, peer, target, _, control) =
                            udp.recv_from_with_ctrl(&mut packet).await.unwrap();
                        assert_eq!(
                            target,
                            Address::DomainNameAddress("target.example".into(), 443)
                        );
                        udp.send_to_with_ctrl(
                            peer,
                            &target,
                            &control.unwrap_or_default(),
                            &packet[..size],
                        )
                        .await
                        .unwrap();
                    }
                });
                let server = PluginServer::start(backend_addr, port, tls, mux).await;
                let options = if !json_options {
                    let mut options = "mode=websocket;host=plugin.test;path=/proxy".to_owned();
                    if !mux {
                        options.push_str(";mux=0");
                    }
                    if tls {
                        options.push_str(&format!(";tls;certRaw={}", server.certificate_raw));
                    }
                    options
                } else {
                    let mut options = serde_json::json!({"mode":"websocket", "host":"plugin.test", "path":"/proxy", "mux":mux, "tls":tls, "headers":{"X-Fixture":"sent"}});
                    if tls {
                        let der = STANDARD.decode(&server.certificate_raw).unwrap();
                        let pin: String = Sha256::digest(der).iter().map(|byte| format!("{byte:02x}")).collect();
                        options["fingerprint"] = serde_json::json!(pin);
                        options["skip-cert-verify"] = serde_json::json!(true);
                    }
                    options.to_string()
                };
                let node = config(SocketAddr::from(([127, 0, 0, 1], port)));
                let adapter = ShadowsocksTransitAdapter::from_subscription(
                    &node,
                    &credentials(Some(&options)),
                    Duration::from_secs(5),
                )
                .unwrap();
                let mut stream = adapter.connect(request()).await.unwrap();
                handshake_rx
                    .await
                    .expect("SS destination must be written before application data");
                let payload: Vec<_> = (0..131_333).map(|index| (index % 251) as u8).collect();
                stream.write_all(&payload).await.unwrap();
                stream.flush().await.unwrap();
                let mut received = vec![0; payload.len()];
                stream.read_exact(&mut received).await.unwrap();
                assert_eq!(received, payload, "tls={tls} mux={mux} json={json_options}");
                drop(stream);
                backend_task.await.unwrap();
                let mut datagram = adapter.connect_udp(request()).await.unwrap();
                for data in [b"plugin-udp".as_slice(), &[0x42; 1400]] {
                    datagram.send(data).await.unwrap();
                    assert_eq!(datagram.receive().await.unwrap(), data);
                }
                datagram.close().await.unwrap();
                udp_task.await.unwrap();
                assert_eq!(server.port, port);
                }
            }
        }
    })
    .await
    .expect("v2ray-plugin independent interoperability timed out");
}

#[tokio::test]
#[ignore = "requires PATHCHORD_TEST_V2RAY_PLUGIN and PATHCHORD_TEST_SING_BOX"]
async fn udp_over_tcp_traverses_the_configured_v2ray_plugin() {
    timeout(Duration::from_secs(30), async {
        let sing_box = std::env::var_os("PATHCHORD_TEST_SING_BOX").expect("sing-box binary");
        let reserve = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let backend_port = reserve.local_addr().unwrap().port();
        let document = serde_json::json!({
            "log": {"disabled":true},
            "inbounds": [{"type":"shadowsocks","listen":"127.0.0.1","listen_port":backend_port,"method":"aes-256-gcm","password":"plugin-test-password"}],
            "outbounds": [{"type":"direct"}]
        });
        drop(reserve);
        let mut backend = Command::new(sing_box).args(["run", "-c", "stdin"])
            .stdin(Stdio::piped()).stdout(Stdio::null()).stderr(Stdio::null()).kill_on_drop(true).spawn().unwrap();
        backend.stdin.take().unwrap().write_all(&serde_json::to_vec(&document).unwrap()).await.unwrap();
        timeout(Duration::from_secs(5), async {
            while TcpStream::connect(("127.0.0.1", backend_port)).await.is_err() {
                sleep(Duration::from_millis(20)).await;
            }
        }).await.unwrap();
        for tls in [false, true] {
            for mux in [false, true] {
                let reserve = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
                let port = reserve.local_addr().unwrap().port();
                drop(reserve);
                let server = PluginServer::start(SocketAddr::from(([127, 0, 0, 1], backend_port)), port, tls, mux).await;
                let mut options = "mode=websocket;host=plugin.test;path=/proxy".to_owned();
                if !mux { options.push_str(";mux=0"); }
                if tls { options.push_str(&format!(";tls;certRaw={}", server.certificate_raw)); }
                for version in [1, 2] {
                    let mut node = config(SocketAddr::from(([127, 0, 0, 1], port)));
                    node.options.udp_over_tcp = Some(version);
                    let adapter = ShadowsocksTransitAdapter::from_subscription(&node, &credentials(Some(&options)), Duration::from_secs(5)).unwrap();
                    let target = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
                    let target_addr = target.local_addr().unwrap();
                    let echo = tokio::spawn(async move {
                        let mut payload = [0; 4096];
                        for _ in 0..2 { let (length, source) = target.recv_from(&mut payload).await.unwrap(); target.send_to(&payload[..length], source).await.unwrap(); }
                    });
                    let mut datagram = adapter.connect_udp(ConnectRequest {destination:Endpoint {host:target_addr.ip().to_string(),port:target_addr.port()}}).await.unwrap();
                    for payload in [b"uot".as_slice(), &[0x39; 4096]] {
                        datagram.send(payload).await.unwrap();
                        assert_eq!(datagram.receive().await.unwrap(), payload, "tls={tls} mux={mux} v{version}");
                    }
                    datagram.close().await.unwrap();
                    echo.await.unwrap();
                }
            }
        }
        backend.kill().await.unwrap();backend.wait().await.unwrap();
    }).await.expect("bounded plugin UoT fixture");
}

#[tokio::test]
#[ignore = "requires PATHCHORD_TEST_V2RAY_PLUGIN pointing to an independent server binary"]
async fn upstream_v2ray_plugin_rejects_wrong_tls_identity_pin_and_websocket_path() {
    timeout(Duration::from_secs(20), async {
        let backend = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let reserve = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = reserve.local_addr().unwrap().port();
        drop(reserve);
        let server = PluginServer::start(backend.local_addr().unwrap(), port, true, false).await;
        let cases = [
            "tls;host=plugin.test;path=/proxy;mux=0".to_owned(),
            format!("tls;host=wrong.test;path=/proxy;mux=0;certRaw={}", server.certificate_raw),
            format!("tls;host=plugin.test;path=/wrong;mux=0;certRaw={}", server.certificate_raw),
            format!(r#"{{"mode":"websocket","host":"plugin.test","path":"/proxy","tls":true,"mux":false,"skip-cert-verify":true,"fingerprint":"{}"}}"#, "00".repeat(32)),
        ];
        let node = config(SocketAddr::from(([127, 0, 0, 1], port)));
        for options in cases {
            let adapter = ShadowsocksTransitAdapter::from_subscription(&node, &credentials(Some(&options)), Duration::from_secs(3)).unwrap();
            assert!(adapter.connect(request()).await.is_err());
            assert!(timeout(Duration::from_millis(100), backend.accept()).await.is_err());
        }
    }).await.expect("v2ray-plugin TLS negative checks timed out");
}

#[tokio::test]
#[ignore = "requires PATHCHORD_TEST_V2RAY_PLUGIN pointing to an independent server binary"]
async fn upstream_v2ray_plugin_does_not_hide_wrong_shadowsocks_password() {
    timeout(Duration::from_secs(12), async {
        let backend_config = ServerConfig::new("127.0.0.1:0".parse::<SocketAddr>().unwrap(), "plugin-test-password", CipherKind::AES_256_GCM).unwrap();
        let backend = ProxyListener::bind(Context::new_shared(ServerType::Server), &backend_config).await.unwrap();
        let backend_addr = backend.local_addr().unwrap();
        let peer = tokio::spawn(async move {
            let (mut stream, _) = backend.accept().await.unwrap();
            assert!(stream.handshake().await.is_err());
        });
        let reserve = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = reserve.local_addr().unwrap().port();
        drop(reserve);
        let _server = PluginServer::start(backend_addr, port, false, true).await;
        let node = config(SocketAddr::from(([127, 0, 0, 1], port)));
        let bad = SubscriptionCredential::new(BTreeMap::from([
            ("cipher".into(), "aes-256-gcm".into()),
            ("password".into(), "incorrect-password".into()),
            ("plugin".into(), "v2ray-plugin".into()),
            ("plugin_opts".into(), "host=plugin.test;path=/proxy".into()),
        ]));
        let adapter = ShadowsocksTransitAdapter::from_subscription(&node, &bad, Duration::from_secs(3)).unwrap();
        let mut stream = adapter.connect(request()).await.unwrap();
        let _ = stream.write_all(b"must-not-arrive").await;
        let _ = stream.flush().await;
        let mut byte = [0; 1];
        assert!(!matches!(timeout(Duration::from_secs(3), stream.read(&mut byte)).await, Ok(Ok(count)) if count > 0));
        peer.await.unwrap();
    }).await.expect("v2ray-plugin wrong-password test timed out");
}
