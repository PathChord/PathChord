//! Independent local simple-obfs peers around a real Shadowsocks listener.

use pathchord_policy::{Endpoint as PolicyEndpoint, TransitProxyConfig, TransitProxyId};
use pathchord_transit::{
    ConnectRequest, Endpoint, ShadowsocksTransitAdapter, SubscriptionCredential, TransitAdapter,
};
use shadowsocks::{
    ProxyListener, ProxySocket,
    config::{ServerConfig, ServerType},
    context::Context,
    crypto::CipherKind,
    relay::socks5::Address,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    process::{Child, Command, Stdio},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    time::timeout,
};

async fn bridge_tls_obfs(mut client: TcpStream, backend_addr: SocketAddr) {
    let mut header = [0; 5];
    client.read_exact(&mut header).await.unwrap();
    assert_eq!(&header[..3], &[0x16, 0x03, 0x01]);
    let mut hello = vec![0; usize::from(u16::from_be_bytes([header[3], header[4]]))];
    client.read_exact(&mut hello).await.unwrap();
    assert_eq!(&hello[133..135], &[0x00, 0x23]);
    let ticket_length = usize::from(u16::from_be_bytes([hello[135], hello[136]]));
    let ticket_end = 137 + ticket_length;
    assert!(
        hello[ticket_end..]
            .windows(b"camouflage.test".len())
            .any(|bytes| bytes == b"camouflage.test")
    );
    let mut backend = TcpStream::connect(backend_addr).await.unwrap();
    backend.write_all(&hello[137..ticket_end]).await.unwrap();
    let (mut client_read, mut client_write) = client.into_split();
    let (mut backend_read, mut backend_write) = backend.into_split();
    let upload = async {
        loop {
            let mut header = [0; 5];
            if client_read.read_exact(&mut header).await.is_err() {
                break;
            }
            assert_eq!(&header[..3], &[0x17, 0x03, 0x03]);
            let length = usize::from(u16::from_be_bytes([header[3], header[4]]));
            let mut data = vec![0; length];
            client_read.read_exact(&mut data).await.unwrap();
            backend_write.write_all(&data).await.unwrap();
        }
        let _ = backend_write.shutdown().await;
    };
    let download = async {
        let mut first = true;
        let mut data = vec![0; 16 * 1024];
        loop {
            let length = backend_read.read(&mut data).await.unwrap();
            if length == 0 {
                break;
            }
            if first {
                let mut hello = vec![0; 96];
                hello[..5].copy_from_slice(&[0x16, 0x03, 0x01, 0, 91]);
                hello[5] = 2;
                hello.extend_from_slice(&[0x14, 0x03, 0x03, 0, 1, 1, 0x16, 0x03, 0x03]);
                hello.extend_from_slice(&(length as u16).to_be_bytes());
                hello.extend_from_slice(&data[..length]);
                for chunk in hello.chunks(7) {
                    client_write.write_all(chunk).await.unwrap();
                }
                first = false;
            } else {
                client_write.write_all(&[0x17, 0x03, 0x03]).await.unwrap();
                client_write
                    .write_all(&(length as u16).to_be_bytes())
                    .await
                    .unwrap();
                client_write.write_all(&data[..length]).await.unwrap();
            }
            client_write.flush().await.unwrap();
        }
        let _ = client_write.shutdown().await;
    };
    tokio::join!(upload, download);
}

fn config(address: SocketAddr) -> TransitProxyConfig {
    TransitProxyConfig {
        id: TransitProxyId::new("obfs-test"),
        source: None,
        protocol: "ss".into(),
        endpoint: PolicyEndpoint {
            host: address.ip().to_string(),
            port: address.port(),
        },
        credentials_ref: None,
        labels: BTreeMap::new(),
        tags: BTreeSet::new(),
        weight: 100,
        options: Default::default(),
    }
}
fn credentials(plugin: &str, opts: &str) -> SubscriptionCredential {
    SubscriptionCredential::new(BTreeMap::from([
        ("cipher".into(), "aes-256-gcm".into()),
        ("password".into(), "test-password".into()),
        ("plugin".into(), plugin.into()),
        ("plugin_opts".into(), opts.into()),
    ]))
}

#[tokio::test]
async fn sip003_http_obfs_roundtrips_large_tcp_payload() {
    timeout(Duration::from_secs(10), async {
        let upstream = ServerConfig::new(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0), "test-password", CipherKind::AES_256_GCM).unwrap();
        let backend = ProxyListener::bind(Context::new_shared(ServerType::Server), &upstream).await.unwrap();
        let backend_addr = backend.local_addr().unwrap();
        let ss = tokio::spawn(async move {
            let (mut stream, _) = backend.accept().await.unwrap();
            stream.handshake().await.unwrap();
            let mut data = vec![0; 131_333];
            stream.read_exact(&mut data).await.unwrap();
            stream.write_all(&data).await.unwrap();
            stream.flush().await.unwrap();
        });
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = listener.local_addr().unwrap();
        let peer = tokio::spawn(async move {
            let (mut client, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            while !request.ends_with(b"\r\n\r\n") { request.push(client.read_u8().await.unwrap()); assert!(request.len() < 8192); }
            let head = std::str::from_utf8(&request).unwrap();
            assert!(head.starts_with("GET / HTTP/1.1\r\n"));
            assert!(head.lines().any(|line| line.eq_ignore_ascii_case(&format!("Host: camouflage.test:{}", proxy_addr.port()))));
            let length: usize = head.lines().find_map(|line| line.split_once(':').and_then(|(k,v)| k.eq_ignore_ascii_case("content-length").then(|| v.trim().parse().unwrap()))).unwrap();
            let mut prefix = vec![0; length];
            client.read_exact(&mut prefix).await.unwrap();
            let mut backend = TcpStream::connect(backend_addr).await.unwrap();
            backend.write_all(&prefix).await.unwrap();
            for chunk in b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n".chunks(3) { client.write_all(chunk).await.unwrap(); }
            let _ = tokio::io::copy_bidirectional(&mut client, &mut backend).await;
        });
        let adapter = ShadowsocksTransitAdapter::from_subscription(&config(proxy_addr), &credentials("obfs-local", "obfs=http;obfs-host=camouflage.test"), Duration::from_secs(3)).unwrap();
        let mut stream = adapter.connect(ConnectRequest { destination: Endpoint {host: "example.test".into(), port: 443} }).await.unwrap();
        let payload: Vec<_> = (0..131_333).map(|i| (i % 251) as u8).collect();
        stream.write_all(&payload).await.unwrap();
        stream.flush().await.unwrap();
        let mut echoed = vec![0; payload.len()];
        stream.read_exact(&mut echoed).await.unwrap();
        assert_eq!(echoed, payload);
        drop(stream);
        ss.await.unwrap();
        peer.await.unwrap();
    }).await.expect("bounded simple-obfs HTTP exchange");
}

#[tokio::test]
async fn clash_tls_obfs_roundtrips_large_tcp_payload() {
    timeout(Duration::from_secs(10), async {
        let upstream = ServerConfig::new(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            "test-password",
            CipherKind::AES_256_GCM,
        )
        .unwrap();
        let backend = ProxyListener::bind(Context::new_shared(ServerType::Server), &upstream)
            .await
            .unwrap();
        let backend_addr = backend.local_addr().unwrap();
        let ss = tokio::spawn(async move {
            let (mut stream, _) = backend.accept().await.unwrap();
            stream.handshake().await.unwrap();
            let mut data = vec![0; 131_333];
            stream.read_exact(&mut data).await.unwrap();
            stream.write_all(&data).await.unwrap();
            stream.flush().await.unwrap();
        });
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = listener.local_addr().unwrap();
        let peer = tokio::spawn(async move {
            let (client, _) = listener.accept().await.unwrap();
            bridge_tls_obfs(client, backend_addr).await;
        });
        let adapter = ShadowsocksTransitAdapter::from_subscription(
            &config(proxy_addr),
            &credentials("obfs", r#"{"mode":"tls","host":"camouflage.test"}"#),
            Duration::from_secs(3),
        )
        .unwrap();
        let mut stream = adapter
            .connect(ConnectRequest {
                destination: Endpoint {
                    host: "example.test".into(),
                    port: 443,
                },
            })
            .await
            .unwrap();
        let payload: Vec<_> = (0..131_333).map(|i| (i % 251) as u8).collect();
        stream.write_all(&payload).await.unwrap();
        stream.flush().await.unwrap();
        let mut echoed = vec![0; payload.len()];
        stream.read_exact(&mut echoed).await.unwrap();
        assert_eq!(echoed, payload);
        drop(stream);
        ss.await.unwrap();
        peer.await.unwrap();
    })
    .await
    .expect("bounded simple-obfs TLS exchange");
}

#[tokio::test]
async fn configured_obfs_does_not_wrap_or_open_tcp_for_udp() {
    timeout(Duration::from_secs(5), async {
        let ss_config = ServerConfig::new(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            "test-password",
            CipherKind::AES_256_GCM,
        )
        .unwrap();
        // TCP and UDP have independent ephemeral port allocators. Keep both
        // sockets once we find a port that can also watch for stray TCP dials.
        let (socket, tcp, address) = loop {
            let socket = ProxySocket::bind(Context::new_shared(ServerType::Server), &ss_config)
                .await
                .unwrap();
            let address = socket.local_addr().unwrap();
            match TcpListener::bind(address).await {
                Ok(tcp) => break (socket, tcp, address),
                Err(error) if error.kind() == std::io::ErrorKind::AddrInUse => continue,
                Err(error) => panic!("cannot bind TCP observer: {error}"),
            }
        };
        let backend = tokio::spawn(async move {
            let mut packet = vec![0; 4096];
            for _ in 0..4 {
                let (length, peer, target, _, control) =
                    socket.recv_from_with_ctrl(&mut packet).await.unwrap();
                assert_eq!(
                    target,
                    Address::DomainNameAddress("udp.example.test".into(), 3478)
                );
                socket
                    .send_to_with_ctrl(
                        peer,
                        &target,
                        &control.unwrap_or_default(),
                        &packet[..length],
                    )
                    .await
                    .unwrap();
            }
        });
        for mode in ["http", "tls"] {
            let mut policy = config(address);
            policy.options.udp = Some(true);
            let adapter = ShadowsocksTransitAdapter::from_subscription(
                &policy,
                &credentials(
                    "obfs-local",
                    &format!("obfs={mode};obfs-host=camouflage.test"),
                ),
                Duration::from_secs(2),
            )
            .unwrap();
            assert!(adapter.supports_udp());
            let mut datagram = adapter
                .connect_udp(ConnectRequest {
                    destination: Endpoint {
                        host: "udp.example.test".into(),
                        port: 3478,
                    },
                })
                .await
                .unwrap();
            for payload in [b"one".as_slice(), b"two-two".as_slice()] {
                datagram.send(payload).await.unwrap();
                assert_eq!(datagram.receive().await.unwrap(), payload);
            }
            datagram.close().await.unwrap();
        }
        backend.await.unwrap();
        assert!(
            timeout(Duration::from_millis(50), tcp.accept())
                .await
                .is_err()
        );
    })
    .await
    .expect("Shadowsocks UDP exchange timed out");
}

#[tokio::test]
async fn half_closed_obfs_connection_still_receives_a_shadowsocks_response() {
    timeout(Duration::from_secs(10), async {
        for mode in ["http", "tls"] {
            let upstream = ServerConfig::new(
                SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
                "test-password",
                CipherKind::AES_256_GCM,
            )
            .unwrap();
            let backend = ProxyListener::bind(Context::new_shared(ServerType::Server), &upstream)
                .await
                .unwrap();
            let backend_addr = backend.local_addr().unwrap();
            let ss = tokio::spawn(async move {
                let (mut stream, _) = backend.accept().await.unwrap();
                stream.handshake().await.unwrap();
                let mut request = Vec::new();
                stream.read_to_end(&mut request).await.unwrap();
                assert_eq!(request, b"after-write-close");
                stream.write_all(b"response-after-eof").await.unwrap();
                stream.shutdown().await.unwrap();
            });
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let proxy_addr = listener.local_addr().unwrap();
            let peer = tokio::spawn(async move {
                let (mut client, _) = listener.accept().await.unwrap();
                if mode == "tls" {
                    bridge_tls_obfs(client, backend_addr).await;
                } else {
                    let mut header = Vec::new();
                    while !header.ends_with(b"\r\n\r\n") {
                        header.push(client.read_u8().await.unwrap());
                        assert!(header.len() < 8192);
                    }
                    let header = std::str::from_utf8(&header).unwrap();
                    let length: usize = header
                        .lines()
                        .find_map(|line| {
                            line.split_once(':').and_then(|(key, value)| {
                                key.eq_ignore_ascii_case("content-length")
                                    .then(|| value.trim().parse().unwrap())
                            })
                        })
                        .unwrap();
                    let mut prefix = vec![0; length];
                    client.read_exact(&mut prefix).await.unwrap();
                    let mut backend = TcpStream::connect(backend_addr).await.unwrap();
                    backend.write_all(&prefix).await.unwrap();
                    client
                        .write_all(b"HTTP/1.1 101 Switching Protocols\r\n\r\n")
                        .await
                        .unwrap();
                    tokio::io::copy_bidirectional(&mut client, &mut backend)
                        .await
                        .unwrap();
                }
            });
            let adapter = ShadowsocksTransitAdapter::from_subscription(
                &config(proxy_addr),
                &credentials(
                    "obfs-local",
                    &format!("obfs={mode};obfs-host=camouflage.test"),
                ),
                Duration::from_secs(3),
            )
            .unwrap();
            let mut stream = adapter
                .connect(ConnectRequest {
                    destination: Endpoint {
                        host: "example.test".into(),
                        port: 443,
                    },
                })
                .await
                .unwrap();
            stream.write_all(b"after-write-close").await.unwrap();
            stream.shutdown().await.unwrap();
            let mut response = Vec::new();
            stream.read_to_end(&mut response).await.unwrap();
            assert_eq!(response, b"response-after-eof", "{mode}");
            ss.await.unwrap();
            peer.await.unwrap();
        }
    })
    .await
    .expect("half-close exchange timed out");
}

#[test]
fn unsupported_simple_obfs_options_are_rejected_by_the_adapter() {
    let address = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8388);
    for options in [
        "obfs=http;unknown=value",
        "obfs=http;fast-open=1",
        "obfs=http;obfs=tls",
        "obfs=tls;obfs-uri=/ignored",
        "obfs=tls;http-method=POST",
        "obfs=http;obfs-host=valid.test\r\nInjected:bad",
        r#"{"mode":"tls","host":true}"#,
        r#"{"mode":"unsupported"}"#,
        r#"{"mode":"http","mode":"tls"}"#,
        r#"{"mode":"http","host":"first.test","host":"second.test"}"#,
    ] {
        assert!(
            ShadowsocksTransitAdapter::from_subscription(
                &config(address),
                &credentials("obfs-local", options),
                Duration::from_secs(1),
            )
            .is_err(),
            "options must not be ignored: {options}"
        );
    }
}

struct ObfsServer(Child);

impl Drop for ObfsServer {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

async fn upstream_obfs_server(mode: &str, backend: SocketAddr) -> (ObfsServer, SocketAddr) {
    let binary = std::env::var_os("PATHCHORD_TEST_OBFS_SERVER")
        .expect("PATHCHORD_TEST_OBFS_SERVER must name the upstream obfs-server binary");
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    drop(listener);
    let mut command = Command::new(binary);
    command
        .args(["-s", "127.0.0.1", "-p", &address.port().to_string()])
        .args(["-r", &backend.to_string(), "--obfs", mode]);
    if mode == "http" {
        command.args(["--obfs-host", "camouflage.test", "--http-method", "POST"]);
    }
    let mut child = ObfsServer(
        command
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    timeout(Duration::from_secs(5), async {
        loop {
            assert!(child.0.try_wait().unwrap().is_none(), "obfs-server exited");
            if TcpStream::connect(address).await.is_ok() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("obfs-server startup timed out");
    (child, address)
}

#[tokio::test]
#[ignore = "requires the upstream obfs-server binary"]
async fn upstream_simple_obfs_http_and_tls_carry_shadowsocks() {
    timeout(Duration::from_secs(30), async {
        for mode in ["http", "tls"] {
            let ss_config = ServerConfig::new(
                SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
                "test-password",
                CipherKind::AES_256_GCM,
            )
            .unwrap();
            let backend = ProxyListener::bind(Context::new_shared(ServerType::Server), &ss_config)
                .await
                .unwrap();
            let backend_addr = backend.local_addr().unwrap();
            let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
            let backend_task = tokio::spawn(async move {
                let mut proxy = loop {
                    let (mut proxy, _) = backend.accept().await.unwrap();
                    if proxy.handshake().await.is_ok() {
                        break proxy;
                    }
                };
                ready_tx.send(()).unwrap();
                let mut data = vec![0; 131_334];
                proxy.read_exact(&mut data).await.unwrap();
                proxy.write_all(&data).await.unwrap();
                proxy.flush().await.unwrap();
            });
            let (_server, server_addr) = upstream_obfs_server(mode, backend_addr).await;
            let inspector = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let inspector_addr = inspector.local_addr().unwrap();
            let inspected_mode = mode.to_owned();
            let inspect_task =
                tokio::spawn(async move {
                    let (mut client, _) = inspector.accept().await.unwrap();
                    let mut first = Vec::new();
                    if inspected_mode == "http" {
                        while !first.ends_with(b"\r\n\r\n") {
                            first.push(client.read_u8().await.unwrap());
                            assert!(first.len() < 16_384);
                        }
                        let header = std::str::from_utf8(&first).unwrap();
                        assert!(header.starts_with("POST /custom?x=1 HTTP/1.1\r\n"));
                        assert!(header.lines().any(|line| line
                            == format!("Host: camouflage.test:{}", inspector_addr.port())));
                    } else {
                        let mut header = [0; 5];
                        client.read_exact(&mut header).await.unwrap();
                        assert_eq!(&header[..3], &[0x16, 0x03, 0x01]);
                        let mut hello =
                            vec![0; usize::from(u16::from_be_bytes([header[3], header[4]]))];
                        client.read_exact(&mut hello).await.unwrap();
                        assert!(
                            hello
                                .windows(b"camouflage.test".len())
                                .any(|value| value == b"camouflage.test")
                        );
                        first.extend_from_slice(&header);
                        first.extend_from_slice(&hello);
                    }
                    let mut server = TcpStream::connect(server_addr).await.unwrap();
                    server.write_all(&first).await.unwrap();
                    let _ = tokio::io::copy_bidirectional(&mut client, &mut server).await;
                });
            let (plugin, opts) = if mode == "http" {
                (
                    "obfs-local",
                    "obfs=http;obfs-host=camouflage.test;obfs-uri=/custom?x=1;http-method=POST",
                )
            } else {
                ("obfs", r#"{"mode":"tls","host":"camouflage.test"}"#)
            };
            let adapter = ShadowsocksTransitAdapter::from_subscription(
                &config(inspector_addr),
                &credentials(plugin, opts),
                Duration::from_secs(3),
            )
            .unwrap();
            let mut stream = adapter
                .connect(ConnectRequest {
                    destination: Endpoint {
                        host: "example.test".into(),
                        port: 443,
                    },
                })
                .await
                .unwrap();
            ready_rx
                .await
                .expect("handshake must be sent before the caller writes");
            stream.write_all(b"x").await.unwrap();
            let payload: Vec<_> = (0..131_333).map(|i| (i % 251) as u8).collect();
            stream.write_all(&payload).await.unwrap();
            stream.flush().await.unwrap();
            let mut echoed = vec![0; payload.len() + 1];
            stream.read_exact(&mut echoed).await.unwrap();
            assert_eq!(echoed[0], b'x');
            assert_eq!(&echoed[1..], payload);
            drop(stream);
            backend_task.await.unwrap();
            inspect_task.await.unwrap();
        }
    })
    .await
    .expect("bounded upstream simple-obfs exchange");
}

#[tokio::test]
#[ignore = "requires upstream obfs-server and an independently started Shadowsocks server"]
async fn custom_cipher_interoperates_with_simple_obfs_and_independent_shadowsocks() {
    let backend: SocketAddr = std::env::var("PATHCHORD_TEST_SS_SERVER")
        .expect("PATHCHORD_TEST_SS_SERVER is required")
        .parse()
        .unwrap();
    assert!(backend.ip().is_loopback());
    let method = std::env::var("PATHCHORD_TEST_SS_CIPHER").expect("cipher is required");
    assert!(matches!(method.as_str(), "aes-192-gcm" | "xchacha20"));
    timeout(Duration::from_secs(20), async {
        for mode in ["http", "tls"] {
            let (_server, proxy_addr) = upstream_obfs_server(mode, backend).await;
            let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let target_addr = target.local_addr().unwrap();
            let target_task = tokio::spawn(async move {
                let (mut stream, _) = target.accept().await.unwrap();
                let mut buffer = vec![0; 65_537];
                stream.read_exact(&mut buffer).await.unwrap();
                stream.write_all(&buffer).await.unwrap();
            });
            let opts = if mode == "http" {
                "obfs=http;obfs-host=camouflage.test;obfs-uri=/custom?x=1;http-method=POST"
            } else {
                "obfs=tls;obfs-host=camouflage.test"
            };
            let credential = SubscriptionCredential::new(BTreeMap::from([
                ("cipher".into(), method.clone()),
                ("password".into(), "pathchord-test-password".into()),
                ("plugin".into(), "obfs-local".into()),
                ("plugin_opts".into(), opts.into()),
            ]));
            let adapter = ShadowsocksTransitAdapter::from_subscription(
                &config(proxy_addr),
                &credential,
                Duration::from_secs(3),
            )
            .unwrap();
            let mut stream = adapter
                .connect(ConnectRequest {
                    destination: Endpoint {
                        host: target_addr.ip().to_string(),
                        port: target_addr.port(),
                    },
                })
                .await
                .unwrap();
            let data: Vec<_> = (0..65_537).map(|index| (index % 251) as u8).collect();
            stream.write_all(&data).await.unwrap();
            stream.flush().await.unwrap();
            let mut received = vec![0; data.len()];
            stream.read_exact(&mut received).await.unwrap();
            assert_eq!(received, data, "{mode}");
            drop(stream);
            target_task.await.unwrap();
        }
    })
    .await
    .expect("Shadowsocks simple-obfs exchange timed out");
}
