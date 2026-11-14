//! PathChord-client interoperability against external mature core servers.
//!
//! Each fixture starts the external core as a native-protocol server and then
//! connects to it with PathChord's native Transit adapter. The binaries are
//! supplied by the test environment and never enter the runtime or Cargo graph.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use pathchord_policy::{Endpoint as PolicyEndpoint, TransitProxyConfig, TransitTls};
use pathchord_transit::{
    AdapterRegistry, ConnectRequest, Endpoint, NoTransitCredentials, TransitCredential,
};
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::process::{Child, Command};
use tokio::time::{Instant, sleep};

#[derive(Clone, Copy)]
enum CoreKind {
    Mihomo,
    Xray,
    V2Fly,
}

impl CoreKind {
    fn env_name(self) -> &'static str {
        match self {
            Self::Mihomo => "PATHCHORD_TEST_MIHOMO",
            Self::Xray => "PATHCHORD_TEST_XRAY",
            Self::V2Fly => "PATHCHORD_TEST_V2FLY",
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Mihomo => "mihomo",
            Self::Xray => "xray",
            Self::V2Fly => "v2fly",
        }
    }
}

#[derive(Clone, Copy)]
enum Protocol {
    Shadowsocks,
    Vmess,
    Vless,
    Trojan,
    AnyTls,
    Hysteria2,
    Tuic,
}

impl Protocol {
    fn label(self) -> &'static str {
        match self {
            Self::Shadowsocks => "ss",
            Self::Vmess => "vmess",
            Self::Vless => "vless",
            Self::Trojan => "trojan",
            Self::AnyTls => "anytls",
            Self::Hysteria2 => "hysteria2",
            Self::Tuic => "tuic",
        }
    }

    fn payload(self) -> &'static [u8] {
        match self {
            Self::Shadowsocks => b"external-ss",
            Self::Vmess => b"external-vmess",
            Self::Vless => b"external-vless",
            Self::Trojan => b"external-trojan",
            Self::AnyTls => b"external-anytls",
            Self::Hysteria2 => b"external-hysteria2",
            Self::Tuic => b"external-tuic",
        }
    }

    fn uses_tls(self, core: CoreKind) -> bool {
        matches!(
            self,
            Self::Trojan | Self::AnyTls | Self::Hysteria2 | Self::Tuic
        ) || (matches!(self, Self::Vless) && matches!(core, CoreKind::Mihomo))
    }
}

#[tokio::test]
#[ignore = "requires PATHCHORD_TEST_MIHOMO pointing to a Mihomo server binary"]
async fn pathchord_client_interoperates_with_mihomo_server() {
    run_core(CoreKind::Mihomo).await;
}

#[tokio::test]
#[ignore = "requires PATHCHORD_TEST_XRAY pointing to an Xray server binary"]
async fn pathchord_client_interoperates_with_xray_server() {
    run_core(CoreKind::Xray).await;
}

#[tokio::test]
#[ignore = "requires PATHCHORD_TEST_V2FLY pointing to a V2Fly server binary"]
async fn pathchord_client_interoperates_with_v2fly_server() {
    run_core(CoreKind::V2Fly).await;
}

async fn run_core(core: CoreKind) {
    let protocols = match core {
        CoreKind::Mihomo => vec![
            Protocol::Shadowsocks,
            Protocol::Vmess,
            Protocol::Vless,
            Protocol::Trojan,
            Protocol::AnyTls,
            Protocol::Hysteria2,
            Protocol::Tuic,
        ],
        CoreKind::Xray | CoreKind::V2Fly => vec![
            Protocol::Shadowsocks,
            Protocol::Vmess,
            Protocol::Vless,
            Protocol::Trojan,
        ],
    };
    for protocol in protocols {
        run_protocol(core, protocol).await;
    }
}

async fn run_protocol(core: CoreKind, protocol: Protocol) {
    let binary = PathBuf::from(
        std::env::var_os(core.env_name())
            .unwrap_or_else(|| panic!("{} is required", core.env_name())),
    );
    assert!(
        binary.is_file(),
        "{} is not a file: {binary:?}",
        core.env_name()
    );
    let port = reserve_port();
    let extension = if matches!(core, CoreKind::Mihomo) {
        "yaml"
    } else {
        "json"
    };
    let config_path = std::env::temp_dir().join(format!(
        "pathchord-{}-{}-{}-{}.{}",
        core.label(),
        protocol.label(),
        std::process::id(),
        port,
        extension
    ));
    let ready_file = matches!(core, CoreKind::Mihomo).then(|| config_path.with_extension("ready"));
    let mut extra_files = write_server_config(core, protocol, &config_path, port).await;
    if let Some(path) = &ready_file {
        extra_files.push(path.clone());
    }
    let mut server = spawn_server(core, &binary, &config_path, ready_file.as_deref()).await;
    wait_until_ready(port, &mut server, ready_file.as_deref()).await;

    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target_address = target.local_addr().unwrap();
    let payload = protocol.payload();
    let target_task = tokio::spawn(async move {
        let (mut stream, _) = target.accept().await.unwrap();
        let mut buffer = vec![0_u8; payload.len()];
        stream.read_exact(&mut buffer).await.unwrap();
        stream.write_all(&buffer).await.unwrap();
    });

    let mut options = pathchord_policy::TransitOptions::default();
    if protocol.uses_tls(core) {
        options.tls = Some(TransitTls {
            enabled: true,
            insecure: true,
            server_name: Some("pathchord.test".to_owned()),
            alpn: if matches!(protocol, Protocol::Hysteria2 | Protocol::Tuic) {
                vec!["h3".to_owned()]
            } else {
                Vec::new()
            },
            ..Default::default()
        });
    }
    let config = TransitProxyConfig {
        id: pathchord_policy::TransitProxyId::new(format!("{}-{}", core.label(), protocol.label())),
        source: None,
        protocol: protocol.label().to_owned(),
        endpoint: PolicyEndpoint {
            host: "127.0.0.1".to_owned(),
            port,
        },
        credentials_ref: None,
        labels: BTreeMap::new(),
        tags: std::collections::BTreeSet::new(),
        weight: 1,
        options,
    };
    let registry = AdapterRegistry::for_configs(
        Arc::new(NoTransitCredentials),
        Duration::from_secs(5),
        [&config],
    )
    .unwrap();
    let credentials = credentials(protocol);
    let adapter = registry
        .build_with_credential(&config, &credentials)
        .unwrap_or_else(|error| {
            panic!(
                "build {} {} client: {error}",
                core.label(),
                protocol.label()
            )
        });
    let mut connection = tokio::time::timeout(
        Duration::from_secs(10),
        adapter.connect(ConnectRequest {
            destination: Endpoint {
                host: "127.0.0.1".to_owned(),
                port: target_address.port(),
            },
        }),
    )
    .await
    .unwrap_or_else(|_| {
        panic!(
            "{} {} client connect timeout",
            core.label(),
            protocol.label()
        )
    })
    .unwrap_or_else(|error| {
        panic!(
            "{} {} client connect: {error}",
            core.label(),
            protocol.label()
        )
    });
    connection.write_all(payload).await.unwrap_or_else(|error| {
        panic!(
            "{} {} client write: {error}",
            core.label(),
            protocol.label()
        )
    });
    connection.flush().await.unwrap_or_else(|error| {
        panic!(
            "{} {} client flush: {error}",
            core.label(),
            protocol.label()
        )
    });
    let mut echoed = vec![0_u8; payload.len()];
    tokio::time::timeout(Duration::from_secs(10), connection.read_exact(&mut echoed))
        .await
        .unwrap_or_else(|_| panic!("{} {} client read timeout", core.label(), protocol.label()))
        .unwrap_or_else(|error| {
            panic!("{} {} client read: {error}", core.label(), protocol.label())
        });
    assert_eq!(&echoed, payload);
    drop(connection);
    target_task.await.unwrap();
    server.kill().await.unwrap();
    server.wait().await.unwrap();
    let _ = tokio::fs::remove_file(config_path).await;
    for path in extra_files {
        let _ = tokio::fs::remove_file(path).await;
    }
}

fn credentials(protocol: Protocol) -> TransitCredential {
    match protocol {
        Protocol::Shadowsocks => TransitCredential::new(BTreeMap::from([
            ("cipher".to_owned(), "aes-256-gcm".to_owned()),
            (
                "password".to_owned(),
                "pathchord-external-password".to_owned(),
            ),
        ])),
        Protocol::Vmess => TransitCredential::new(BTreeMap::from([
            (
                "uuid".to_owned(),
                "6cbf3f72-3417-4922-bde6-67820d041f25".to_owned(),
            ),
            ("security".to_owned(), "aes-128-gcm".to_owned()),
            ("alter_id".to_owned(), "0".to_owned()),
        ])),
        Protocol::Vless => TransitCredential::new(BTreeMap::from([(
            "uuid".to_owned(),
            "6cbf3f72-3417-4922-bde6-67820d041f25".to_owned(),
        )])),
        Protocol::Trojan => TransitCredential::new(BTreeMap::from([(
            "password".to_owned(),
            "pathchord-external-password".to_owned(),
        )])),
        Protocol::AnyTls => TransitCredential::new(BTreeMap::from([(
            "password".to_owned(),
            "pathchord-external-password".to_owned(),
        )])),
        Protocol::Hysteria2 => TransitCredential::new(BTreeMap::from([(
            "password".to_owned(),
            "pathchord-external-password".to_owned(),
        )])),
        Protocol::Tuic => TransitCredential::new(BTreeMap::from([
            (
                "uuid".to_owned(),
                "6cbf3f72-3417-4922-bde6-67820d041f25".to_owned(),
            ),
            (
                "password".to_owned(),
                "pathchord-external-password".to_owned(),
            ),
            ("congestion_control".to_owned(), "cubic".to_owned()),
        ])),
    }
}

fn reserve_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap().port()
}

async fn write_server_config(
    core: CoreKind,
    protocol: Protocol,
    path: &Path,
    port: u16,
) -> Vec<PathBuf> {
    let verbose = std::env::var_os("PATHCHORD_TEST_CORE_VERBOSE").is_some();
    let mut extra_files = Vec::new();
    let mut cert_path = None;
    let mut key_path = None;
    if protocol.uses_tls(core) {
        let cert = rcgen::generate_simple_self_signed(vec!["pathchord.test".to_owned()]).unwrap();
        let cert_file = path.with_extension("crt");
        let key_file = path.with_extension("key");
        tokio::fs::write(&cert_file, cert.cert.pem()).await.unwrap();
        tokio::fs::write(&key_file, cert.signing_key.serialize_pem())
            .await
            .unwrap();
        cert_path = Some(cert_file);
        key_path = Some(key_file);
        extra_files.extend([cert_path.clone().unwrap(), key_path.clone().unwrap()]);
    }
    match core {
        CoreKind::Mihomo => {
            let body = match protocol {
                Protocol::Shadowsocks => format!(
                    "type: shadowsocks\n    listen: 127.0.0.1\n    port: {port}\n    cipher: aes-256-gcm\n    password: pathchord-external-password\n    udp: false"
                ),
                Protocol::Vmess => format!(
                    "type: vmess\n    listen: 127.0.0.1\n    port: {port}\n    users:\n      - username: pathchord\n        uuid: 6cbf3f72-3417-4922-bde6-67820d041f25\n        alterId: 0"
                ),
                Protocol::Vless => format!(
                    "type: vless\n    listen: 127.0.0.1\n    port: {port}\n    certificate: {}\n    private-key: {}\n    users:\n      - username: pathchord\n        uuid: 6cbf3f72-3417-4922-bde6-67820d041f25",
                    cert_path.as_ref().unwrap().display(),
                    key_path.as_ref().unwrap().display()
                ),
                Protocol::Trojan => format!(
                    "type: trojan\n    listen: 127.0.0.1\n    port: {port}\n    certificate: {}\n    private-key: {}\n    users:\n      - username: pathchord\n        password: pathchord-external-password",
                    cert_path.as_ref().unwrap().display(),
                    key_path.as_ref().unwrap().display()
                ),
                Protocol::AnyTls => format!(
                    "type: anytls\n    listen: 127.0.0.1\n    port: {port}\n    users:\n      pathchord: pathchord-external-password\n    certificate: {}\n    private-key: {}",
                    cert_path.as_ref().unwrap().display(),
                    key_path.as_ref().unwrap().display()
                ),
                Protocol::Hysteria2 => format!(
                    "type: hysteria2\n    listen: 127.0.0.1\n    port: {port}\n    users:\n      6cbf3f72-3417-4922-bde6-67820d041f25: pathchord-external-password\n    certificate: {}\n    private-key: {}\n    alpn: [h3]",
                    cert_path.as_ref().unwrap().display(),
                    key_path.as_ref().unwrap().display()
                ),
                Protocol::Tuic => format!(
                    "type: tuic\n    listen: 127.0.0.1\n    port: {port}\n    users:\n      6cbf3f72-3417-4922-bde6-67820d041f25: pathchord-external-password\n    certificate: {}\n    private-key: {}\n    congestion-controller: cubic\n    alpn: [h3]",
                    cert_path.as_ref().unwrap().display(),
                    key_path.as_ref().unwrap().display()
                ),
            };
            let name = format!("pathchord-{}", protocol.label());
            let yaml = format!(
                "log-level: {}\nmode: global\nlisteners:\n  - name: {name}\n    {body}\n",
                if verbose { "debug" } else { "silent" }
            );
            tokio::fs::write(path, yaml).await.unwrap();
        }
        CoreKind::Xray | CoreKind::V2Fly => {
            let settings = match protocol {
                Protocol::Shadowsocks => {
                    json!({"method": "aes-256-gcm", "password": "pathchord-external-password", "network": "tcp"})
                }
                Protocol::Vmess => {
                    json!({"clients": [{"id": "6cbf3f72-3417-4922-bde6-67820d041f25", "alterId": 0}]})
                }
                Protocol::Vless => {
                    json!({"clients": [{"id": "6cbf3f72-3417-4922-bde6-67820d041f25"}], "decryption": "none"})
                }
                Protocol::Trojan => {
                    json!({"clients": [{"password": "pathchord-external-password"}]})
                }
                Protocol::AnyTls | Protocol::Hysteria2 | Protocol::Tuic => {
                    panic!(
                        "{} does not support {} server fixture",
                        core.label(),
                        protocol.label()
                    )
                }
            };
            let protocol_name = match protocol {
                Protocol::Shadowsocks => "shadowsocks",
                Protocol::Vmess => "vmess",
                Protocol::Vless => "vless",
                Protocol::Trojan => "trojan",
                Protocol::AnyTls | Protocol::Hysteria2 | Protocol::Tuic => unreachable!(),
            };
            let mut stream = json!({"network": "tcp"});
            if protocol.uses_tls(core) {
                stream["security"] = json!("tls");
                stream["tlsSettings"] = json!({"certificates": [{"certificate": [std::fs::read_to_string(cert_path.as_ref().unwrap()).unwrap()], "key": [std::fs::read_to_string(key_path.as_ref().unwrap()).unwrap()]}]});
            }
            let outbound = if matches!(core, CoreKind::Xray | CoreKind::V2Fly) {
                json!({"protocol": "freedom", "tag": "direct", "settings": {"finalRules": [{"action": "allow"}]}})
            } else {
                json!({"protocol": "freedom", "tag": "direct"})
            };
            let document = json!({"log": {"loglevel": if verbose { "debug" } else { "none" }}, "inbounds": [{"listen": "127.0.0.1", "port": port, "protocol": protocol_name, "settings": settings, "streamSettings": stream}], "outbounds": [outbound]});
            tokio::fs::write(path, serde_json::to_vec(&document).unwrap())
                .await
                .unwrap();
        }
    }
    extra_files
}

async fn spawn_server(
    core: CoreKind,
    binary: &Path,
    config: &Path,
    ready_file: Option<&Path>,
) -> Child {
    if let Some(path) = ready_file {
        match tokio::fs::remove_file(path).await {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => panic!("remove stale readiness marker {path:?}: {error}"),
        }
    }
    let mut command = Command::new(binary);
    match core {
        CoreKind::Mihomo => {
            // Listeners open before Mihomo allows forwarding. Its post-up
            // hook runs after the tunnel has entered the Running state.
            command
                .arg("-d")
                .arg(config.parent().unwrap())
                .arg("-f")
                .arg(config)
                .arg("--post-up")
                .arg(if cfg!(windows) {
                    r#"echo ready > "%PATHCHORD_TEST_CORE_READY_FILE%""#
                } else {
                    r#"echo ready > "$PATHCHORD_TEST_CORE_READY_FILE""#
                })
                .env(
                    "PATHCHORD_TEST_CORE_READY_FILE",
                    ready_file.expect("Mihomo readiness marker"),
                )
        }
        CoreKind::Xray | CoreKind::V2Fly => command.arg("run").arg("-c").arg(config),
    };
    let verbose = std::env::var_os("PATHCHORD_TEST_CORE_VERBOSE").is_some();
    command
        .stdin(std::process::Stdio::null())
        .stdout(if verbose {
            std::process::Stdio::inherit()
        } else {
            std::process::Stdio::null()
        })
        .stderr(if verbose {
            std::process::Stdio::inherit()
        } else {
            std::process::Stdio::null()
        })
        .kill_on_drop(true)
        .spawn()
        .unwrap_or_else(|error| panic!("start {} server: {error}", core.label()))
}

async fn wait_until_ready(port: u16, server: &mut Child, ready_file: Option<&Path>) {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Ok(Some(status)) = server.try_wait() {
            panic!("external server exited before readiness: {status}");
        }
        let ready = if let Some(path) = ready_file {
            tokio::fs::try_exists(path)
                .await
                .unwrap_or_else(|error| panic!("check readiness marker {path:?}: {error}"))
        } else if let Ok(stream) = TcpStream::connect(("127.0.0.1", port)).await {
            drop(stream);
            true
        } else {
            false
        };
        if ready {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "external server readiness timeout"
        );
        sleep(Duration::from_millis(20)).await;
    }
}

#[cfg(unix)]
#[tokio::test]
async fn open_listener_does_not_replace_post_up_readiness() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let ready_file = std::env::temp_dir().join(format!(
        "pathchord-core-readiness-{}-{port}.ready",
        std::process::id()
    ));
    let _ = tokio::fs::remove_file(&ready_file).await;
    let mut server = Command::new("sh")
        .args(["-c", "read -r _"])
        .stdin(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    {
        let ready = wait_until_ready(port, &mut server, Some(&ready_file));
        tokio::pin!(ready);
        assert!(
            tokio::time::timeout(Duration::from_millis(50), &mut ready)
                .await
                .is_err(),
            "an open listener must not bypass the post-up signal"
        );
        tokio::fs::write(&ready_file, b"ready\n").await.unwrap();
        tokio::time::timeout(Duration::from_secs(2), &mut ready)
            .await
            .expect("post-up signal must release readiness");
    }
    server.kill().await.unwrap();
    server.wait().await.unwrap();
    tokio::fs::remove_file(ready_file).await.unwrap();
}
