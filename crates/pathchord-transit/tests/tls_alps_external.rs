//! An OpenSSL peer returns ALPS to fingerprints that advertised it.
//!
//! This test compiles a local synthetic peer using `cc` and OpenSSL headers.

#![cfg(unix)]

use std::{collections::BTreeMap, path::PathBuf, process::Stdio, sync::Arc, time::Duration};

use pathchord_policy::{
    Endpoint as PolicyEndpoint, TransitOptions, TransitProxyConfig, TransitProxyId, TransitTls,
};
use pathchord_transit::{
    AdapterRegistry, ConnectRequest, Endpoint, NoTransitCredentials, TransitCredential,
    TransitError,
};
use tokio::{
    io::{AsyncBufReadExt, BufReader},
    process::Command,
    time::timeout,
};

struct Directory(PathBuf);

impl Directory {
    fn new() -> Self {
        let mut random = [0; 8];
        getrandom::fill(&mut random).unwrap();
        let path = std::env::temp_dir().join(format!(
            "pathchord-alps-fixture-{}-{:016x}",
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
async fn requested_alps_responses_are_rejected_without_silent_downgrade() {
    timeout(Duration::from_secs(20), async {
        let directory = Directory::new();
        let peer_path = directory.0.join("peer");
        let source = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/tls_alps_server.c");
        let result = Command::new("cc")
            .arg(source)
            .arg("-o")
            .arg(&peer_path)
            .args(["-lssl", "-lcrypto"])
            .output()
            .await
            .unwrap();
        assert!(result.status.success(), "OpenSSL peer failed to compile");
        let rcgen::CertifiedKey { cert, signing_key } =
            rcgen::generate_simple_self_signed(vec!["tls.pathchord.test".into()]).unwrap();
        let certificate = cert.pem();
        let cert_path = directory.0.join("certificate.pem");
        let key_path = directory.0.join("key.pem");
        std::fs::write(&cert_path, &certificate).unwrap();
        std::fs::write(&key_path, signing_key.serialize_pem()).unwrap();

        for (fingerprint, extension) in [("chrome", "0x44cd"), ("qq", "0x4469")] {
            let mut peer = Command::new(&peer_path)
                .arg(&cert_path)
                .arg(&key_path)
                .arg(extension)
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .kill_on_drop(true)
                .spawn()
                .unwrap();
            let mut line = String::new();
            BufReader::new(peer.stdout.take().unwrap())
                .read_line(&mut line)
                .await
                .unwrap();
            let port = line.trim().parse::<u16>().expect("peer listening port");
            let config = TransitProxyConfig {
                id: TransitProxyId::new("alps-response-test"),
                source: None,
                protocol: "vless".to_owned(),
                endpoint: PolicyEndpoint { host: "127.0.0.1".to_owned(), port },
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
                Arc::new(NoTransitCredentials), Duration::from_secs(5), [&config],
            ).unwrap().build_with_credential(&config, &credential).unwrap();
            let result = adapter.connect(ConnectRequest {
                destination: Endpoint { host: "192.0.2.1".to_owned(), port: 80 },
            }).await;
            assert!(matches!(result, Err(TransitError::Connection(ref reason)) if reason.contains("server ALPS is unsupported")), "{fingerprint} did not reject the ALPS response");
            assert!(peer.wait().await.unwrap().success());
        }
    }).await.expect("ALPS rejection test timed out");
}
