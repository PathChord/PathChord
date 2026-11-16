//! Verify RFC 8449 negotiation against an independent OpenSSL TLS peer.
#![cfg(unix)]

use std::{collections::BTreeMap, path::PathBuf, process::Stdio, sync::Arc, time::Duration};

use pathchord_policy::{
    Endpoint as PolicyEndpoint, TransitOptions, TransitProxyConfig, TransitProxyId, TransitTls,
};
use pathchord_transit::{
    AdapterRegistry, ConnectRequest, Endpoint, NoTransitCredentials, TransitCredential,
};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    process::Command,
    time::timeout,
};

#[tokio::test]
async fn unsolicited_and_duplicate_record_limits_fail_the_handshake() {
    for (fingerprint, repeated, expected) in [
        ("chrome", false, "UnsolicitedServerHelloExtension"),
        ("firefox", true, "DuplicateExtension(28)"),
    ] {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let peer = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut header = [0; 5];
            socket.read_exact(&mut header).await.unwrap();
            let mut hello = vec![0; usize::from(u16::from_be_bytes([header[3], header[4]]))];
            socket.read_exact(&mut hello).await.unwrap();
            let extension = [0, 0x1c, 0, 2, 0, 64];
            let mut extensions = extension.to_vec();
            if repeated {
                extensions.extend_from_slice(&extension);
            }
            let mut body = vec![3, 3];
            body.extend_from_slice(&[0x43; 32]);
            body.extend_from_slice(&[0, 0xc0, 0x2b, 0]);
            body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
            body.extend_from_slice(&extensions);
            let length = body.len();
            let mut handshake = vec![2, (length >> 16) as u8, (length >> 8) as u8, length as u8];
            handshake.extend_from_slice(&body);
            let mut record = vec![22, 3, 3];
            record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
            record.extend_from_slice(&handshake);
            socket.write_all(&record).await.unwrap();
        });
        let config = TransitProxyConfig {
            id: TransitProxyId::new("record-limit-negative-test"),
            source: None,
            protocol: "vless".to_owned(),
            endpoint: PolicyEndpoint {
                host: "127.0.0.1".to_owned(),
                port,
            },
            credentials_ref: None,
            labels: Default::default(),
            tags: Default::default(),
            weight: 1,
            options: TransitOptions {
                tls: Some(TransitTls {
                    enabled: true,
                    server_name: Some("tls.pathchord.test".to_owned()),
                    truststore: Vec::new(),
                    fingerprint: Some(fingerprint.to_owned()),
                    ..Default::default()
                }),
                ..Default::default()
            },
        };
        let credential = TransitCredential::new(BTreeMap::from([(
            "uuid".to_owned(),
            "6cbf3f72-3417-4922-bde6-67820d041f25".to_owned(),
        )]));
        let adapter = AdapterRegistry::for_configs(
            Arc::new(NoTransitCredentials),
            Duration::from_secs(5),
            [&config],
        )
        .unwrap()
        .build_with_credential(&config, &credential)
        .unwrap();
        let result = adapter
            .connect(ConnectRequest {
                destination: Endpoint {
                    host: "192.0.2.1".to_owned(),
                    port: 1234,
                },
            })
            .await;
        assert!(
            matches!(result, Err(error) if error.to_string().contains(expected)),
            "{fingerprint} accepted invalid record-size extension"
        );
        peer.await.unwrap();
    }
}

struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        let mut random = [0; 8];
        getrandom::fill(&mut random).unwrap();
        let path = std::env::temp_dir().join(format!(
            "pathchord-rsl-fixture-{}-{:016x}",
            std::process::id(),
            u64::from_ne_bytes(random)
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[tokio::test]
#[ignore = "requires a C compiler and OpenSSL development headers and libraries"]
async fn firefox_record_limit_controls_both_tls_versions_and_rejects_invalid_limits() {
    timeout(Duration::from_secs(30), async {
        let directory = Directory::new();
        let peer_path = directory.0.join("peer");
        let source = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/tls_record_limit_server.c");
        let build = Command::new("cc")
            .arg(source)
            .arg("-o")
            .arg(&peer_path)
            .args(["-lssl", "-lcrypto"])
            .output()
            .await
            .unwrap();
        assert!(build.status.success(), "OpenSSL peer failed to compile");
        let rcgen::CertifiedKey { cert, signing_key } =
            rcgen::generate_simple_self_signed(vec!["tls.pathchord.test".into()]).unwrap();
        let certificate = cert.pem();
        let cert_path = directory.0.join("certificate.pem");
        let key_path = directory.0.join("key.pem");
        std::fs::write(&cert_path, &certificate).unwrap();
        std::fs::write(&key_path, signing_key.serialize_pem()).unwrap();
        for (version, limit, length, valid) in [
            (12, 64, 2, true),
            (13, 64, 2, true),
            (12, 16_384, 2, true),
            (13, 16_385, 2, true),
            (12, 63, 2, false),
            (13, 63, 2, false),
            (12, 16_385, 2, false),
            (13, 16_386, 2, false),
            (13, 64, 1, false),
        ] {
            let mut peer = Command::new(&peer_path)
                .arg(&cert_path)
                .arg(&key_path)
                .arg(version.to_string())
                .arg(limit.to_string())
                .arg(length.to_string())
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .kill_on_drop(true)
                .spawn()
                .unwrap();
            let mut output = BufReader::new(peer.stdout.take().unwrap());
            let mut line = String::new();
            output.read_line(&mut line).await.unwrap();
            let port = line.trim().parse::<u16>().expect("peer listening port");
            let config = TransitProxyConfig {
                id: TransitProxyId::new("record-limit-test"),
                source: None,
                protocol: "vless".to_owned(),
                endpoint: PolicyEndpoint {
                    host: "127.0.0.1".to_owned(),
                    port,
                },
                credentials_ref: None,
                labels: Default::default(),
                tags: Default::default(),
                weight: 1,
                options: TransitOptions {
                    tls: Some(TransitTls {
                        enabled: true,
                        server_name: Some("tls.pathchord.test".to_owned()),
                        truststore: Vec::new(),
                        certificate: vec![certificate.clone()],
                        fingerprint: Some("firefox".to_owned()),
                        ..Default::default()
                    }),
                    ..Default::default()
                },
            };
            let credential = TransitCredential::new(BTreeMap::from([(
                "uuid".to_owned(),
                "6cbf3f72-3417-4922-bde6-67820d041f25".to_owned(),
            )]));
            let adapter = AdapterRegistry::for_configs(
                Arc::new(NoTransitCredentials),
                Duration::from_secs(5),
                [&config],
            )
            .unwrap()
            .build_with_credential(&config, &credential)
            .unwrap();
            let result = adapter
                .connect(ConnectRequest {
                    destination: Endpoint {
                        host: "192.0.2.1".to_owned(),
                        port: 1234,
                    },
                })
                .await;
            if valid {
                let mut stream =
                    result.unwrap_or_else(|error| panic!("TLS {version}, limit {limit}: {error}"));
                stream.write_all(&[0x53; 5000]).await.unwrap();
                stream.flush().await.unwrap();
                let mut response = vec![0; 20_000];
                stream.read_exact(&mut response).await.unwrap();
                assert_eq!(
                    response,
                    (0..20_000).map(|i| (i % 251) as u8).collect::<Vec<_>>()
                );
            } else {
                let error = result
                    .err()
                    .expect("invalid record limit must fail")
                    .to_string();
                let expected = if length == 2 {
                    "InvalidRecordSizeLimit"
                } else {
                    "corrupt message"
                };
                assert!(
                    error.contains(expected),
                    "TLS {version}, invalid limit {limit}/{length}: {error}"
                );
            }
            line.clear();
            output.read_line(&mut line).await.unwrap();
            let fields: Vec<usize> = line
                .split_whitespace()
                .map(|s| s.parse().unwrap())
                .collect();
            assert_eq!(fields.len(), 5);
            assert_eq!(
                fields[1], 1,
                "client did not advertise the Firefox receive limit"
            );
            if valid {
                assert_eq!(fields[0], 1);
                let overhead = if version == 13 { 16 } else { 24 };
                assert!(
                    fields[2] <= limit + overhead,
                    "TLS {version}: record {} exceeded limit {limit}",
                    fields[2]
                );
                if limit == 64 {
                    assert!(fields[3] > 10, "small peer limit did not fragment output");
                    assert!(
                        fields[4] > limit + overhead,
                        "server output was incorrectly limited by its own receive limit"
                    );
                    let inbound_max = if version == 13 { 16_385 } else { 16_384 };
                    assert!(
                        fields[4] <= inbound_max + overhead,
                        "server exceeded the client's advertised receive limit"
                    );
                }
            } else {
                assert_eq!(fields[0], 0);
            }
            assert!(peer.wait().await.unwrap().success());
        }
    })
    .await
    .expect("record limit test timed out");
}
