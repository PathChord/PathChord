//! Exercise Chrome's GREASE ECH against an independent ECH-enabled TLS peer.
//!
//! Run with `PATHCHORD_TEST_OPENSSL` set to an OpenSSL 4 executable that has
//! the `ech` command and `s_server -ech_key` support.

use std::{
    collections::BTreeMap,
    net::SocketAddr,
    path::PathBuf,
    pin::Pin,
    process::Stdio,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

use futures_util::{SinkExt, StreamExt};
use pathchord_policy::{
    Endpoint as PolicyEndpoint, TransitOptions, TransitProxyConfig, TransitProxyId, TransitTls,
    TransitTransport,
};
use pathchord_transit::{
    AdapterRegistry, BoxedTransitConnection, ConnectRequest, Endpoint, NoTransitCredentials,
    TransitAdapter, TransitCredential, TransitError,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    process::{Child, ChildStdin, ChildStdout, Command},
    time::{Instant, sleep, timeout},
};
use tokio_tungstenite::{accept_async, tungstenite::Message};

const SERVER_NAME: &str = "tls.pathchord.test";
const UUID: &str = "6cbf3f72-3417-4922-bde6-67820d041f25";
const PAYLOAD: &[u8] = b"ech-grease-websocket-payload";

struct Directory(PathBuf);

impl Directory {
    fn new() -> Self {
        let mut random = [0; 8];
        getrandom::fill(&mut random).unwrap();
        let path = std::env::temp_dir().join(format!(
            "pathchord-ech-fixture-{}-{:016x}",
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

impl Drop for Directory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

struct Peer {
    child: Child,
    _directory: Directory,
    address: SocketAddr,
    certificate: String,
}

impl Peer {
    async fn start(sct: Option<bool>) -> Self {
        let openssl =
            std::env::var_os("PATHCHORD_TEST_OPENSSL").expect("PATHCHORD_TEST_OPENSSL is required");
        let directory = Directory::new();
        let rcgen::CertifiedKey { cert, signing_key } =
            rcgen::generate_simple_self_signed(vec![SERVER_NAME.to_owned()]).unwrap();
        let certificate = cert.pem();
        let cert_path = directory.0.join("certificate.pem");
        let key_path = directory.0.join("key.pem");
        let ech_path = directory.0.join("ech.pem");
        std::fs::write(&cert_path, &certificate).unwrap();
        std::fs::write(&key_path, signing_key.serialize_pem()).unwrap();
        let output = Command::new(&openssl)
            .args(["ech", "-public_name", SERVER_NAME, "-out"])
            .arg(&ech_path)
            .output()
            .await
            .unwrap();
        assert!(output.status.success(), "OpenSSL ECH key generation failed");

        let reservation = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = reservation.local_addr().unwrap();
        drop(reservation);
        let mut command = Command::new(openssl);
        command
            .args(["s_server", "-quiet", "-naccept", "1", "-accept"])
            .arg(address.to_string())
            .arg("-cert")
            .arg(cert_path)
            .arg("-key")
            .arg(key_path)
            .arg("-ech_key")
            .arg(ech_path)
            .args(["-tls1_3", "-alpn", "http/1.1"]);
        if let Some(well_formed) = sct {
            // OpenSSL serverinfo v2: send a synthetic SCT list on the TLS 1.3
            // Certificate only when the client advertises the SCT extension.
            let info_path = directory.0.join("serverinfo.pem");
            let contents = if well_formed {
                "AAAQoAASAAUAAwABAQ=="
            } else {
                // Inner SCT length exceeds the bytes in the list.
                "AAAQoAASAAUAAwAEAQ=="
            };
            std::fs::write(&info_path, format!("-----BEGIN SERVERINFOV2 FOR TEST-----\n{contents}\n-----END SERVERINFOV2 FOR TEST-----\n")).unwrap();
            command.arg("-serverinfo").arg(info_path);
            if well_formed {
                command.arg("-cert_comp");
            } else {
                command.arg("-no_tx_cert_comp");
            }
            command
                .arg("-msg")
                .arg("-msgfile")
                .arg(directory.0.join("tls-messages.log"));
        }
        let child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        Self {
            child,
            _directory: directory,
            address,
            certificate,
        }
    }
}

struct OpenSslApplicationIo {
    read: ChildStdout,
    write: ChildStdin,
}

impl AsyncRead for OpenSslApplicationIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.read).poll_read(cx, buffer)
    }
}

impl AsyncWrite for OpenSslApplicationIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.write).poll_write(cx, buffer)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.write).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.write).poll_shutdown(cx)
    }
}

fn adapter(
    peer: &Peer,
    certificate: String,
    server_name: &str,
    fingerprint: &str,
) -> Arc<dyn TransitAdapter> {
    let config = TransitProxyConfig {
        id: TransitProxyId::new("ech-grease-test"),
        source: None,
        protocol: "vless".to_owned(),
        endpoint: PolicyEndpoint {
            host: peer.address.ip().to_string(),
            port: peer.address.port(),
        },
        credentials_ref: None,
        labels: Default::default(),
        tags: Default::default(),
        weight: 1,
        options: TransitOptions {
            tls: Some(TransitTls {
                enabled: true,
                server_name: Some(server_name.to_owned()),
                truststore: Vec::new(),
                certificate: vec![certificate],
                fingerprint: Some(fingerprint.to_owned()),
                ..Default::default()
            }),
            transport: Some(TransitTransport {
                kind: "ws".to_owned(),
                path: Some("/ech-test".to_owned()),
                ..Default::default()
            }),
            ..Default::default()
        },
    };
    let credential = TransitCredential::new(BTreeMap::from([("uuid".to_owned(), UUID.to_owned())]));
    AdapterRegistry::for_configs(
        Arc::new(NoTransitCredentials),
        Duration::from_secs(5),
        [&config],
    )
    .unwrap()
    .build_with_credential(&config, &credential)
    .unwrap()
}

async fn connect_when_ready(
    adapter: &dyn TransitAdapter,
) -> Result<BoxedTransitConnection, TransitError> {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let result = adapter
            .connect(ConnectRequest {
                destination: Endpoint {
                    host: "192.0.2.1".to_owned(),
                    port: 1234,
                },
            })
            .await;
        match result {
            Err(TransitError::Connection(ref message))
                if message == "Transit endpoint connection failed" && Instant::now() < deadline =>
            {
                sleep(Duration::from_millis(20)).await;
            }
            result => return result,
        }
    }
}

#[tokio::test]
#[ignore = "requires PATHCHORD_TEST_OPENSSL pointing to an ECH-enabled OpenSSL 4 executable"]
async fn chrome_grease_accepts_ech_retry_configs_and_relays_vless_websocket() {
    echo_roundtrip(None, "chrome").await;
}

#[tokio::test]
#[ignore = "requires PATHCHORD_TEST_OPENSSL pointing to an ECH-enabled OpenSSL 4 executable"]
async fn firefox_grease_accepts_ech_retry_configs_and_relays_vless_websocket() {
    echo_roundtrip(None, "firefox").await;
}

#[tokio::test]
#[ignore = "requires PATHCHORD_TEST_OPENSSL pointing to an ECH-enabled OpenSSL 4 executable"]
async fn chrome_accepts_requested_sct_and_relays_vless_websocket() {
    echo_roundtrip(Some(true), "chrome").await;
}

async fn echo_roundtrip(sct: Option<bool>, fingerprint: &str) {
    timeout(Duration::from_secs(15), async {
        let mut peer = Peer::start(sct).await;
        let client = adapter(&peer, peer.certificate.clone(), SERVER_NAME, fingerprint);
        let application = OpenSslApplicationIo {
            read: peer.child.stdout.take().unwrap(),
            write: peer.child.stdin.take().unwrap(),
        };
        let server = tokio::spawn(async move {
            let mut ws = accept_async(application).await.unwrap();
            let mut expected = vec![0];
            expected.extend_from_slice(uuid::Uuid::parse_str(UUID).unwrap().as_bytes());
            expected.extend_from_slice(&[0, 1, 0x04, 0xd2, 1, 192, 0, 2, 1]);
            expected.extend_from_slice(PAYLOAD);
            let mut received = Vec::new();
            while received.len() < expected.len() {
                received.extend_from_slice(&ws.next().await.unwrap().unwrap().into_data());
            }
            assert_eq!(received, expected);
            let mut response = vec![0, 0];
            response.extend_from_slice(PAYLOAD);
            ws.send(Message::binary(response)).await.unwrap();
        });
        let mut stream = connect_when_ready(client.as_ref()).await.unwrap();
        stream.write_all(PAYLOAD).await.unwrap();
        stream.flush().await.unwrap();
        let mut received = vec![0; PAYLOAD.len()];
        stream.read_exact(&mut received).await.unwrap();
        assert_eq!(received, PAYLOAD);
        server.await.unwrap();
        if sct == Some(true) {
            let trace =
                std::fs::read_to_string(peer._directory.0.join("tls-messages.log")).unwrap();
            assert!(trace.contains("CompressedCertificate"));
        }
    })
    .await
    .expect("ECH WebSocket round trip timed out");
}

#[tokio::test]
#[ignore = "requires PATHCHORD_TEST_OPENSSL pointing to an ECH-enabled OpenSSL 4 executable"]
async fn chrome_grease_still_rejects_untrusted_or_wrong_name_certificates() {
    for wrong_name in [false, true] {
        let peer = Peer::start(Some(true)).await;
        let (certificate, server_name) = if wrong_name {
            (peer.certificate.clone(), "wrong.pathchord.test")
        } else {
            (
                rcgen::generate_simple_self_signed(vec![SERVER_NAME.to_owned()])
                    .unwrap()
                    .cert
                    .pem(),
                SERVER_NAME,
            )
        };
        let client = adapter(&peer, certificate, server_name, "chrome");
        let result = timeout(Duration::from_secs(10), connect_when_ready(client.as_ref()))
            .await
            .expect("TLS certificate check timed out");
        assert!(
            matches!(result, Err(TransitError::Connection(ref reason)) if reason.contains("TLS handshake failed") && reason.contains("certificate")),
            "invalid certificate should fail the TLS handshake"
        );
    }
}

#[tokio::test]
#[ignore = "requires PATHCHORD_TEST_OPENSSL pointing to an ECH-enabled OpenSSL 4 executable"]
async fn chrome_rejects_malformed_sct_list() {
    let peer = Peer::start(Some(false)).await;
    let client = adapter(&peer, peer.certificate.clone(), SERVER_NAME, "chrome");
    let result = timeout(Duration::from_secs(10), connect_when_ready(client.as_ref()))
        .await
        .expect("malformed SCT check timed out");
    match result {
        Err(TransitError::Connection(reason)) => assert!(
            reason.contains("TLS handshake failed") && reason.contains("corrupt message"),
            "malformed SCT should fail the TLS handshake: {reason}"
        ),
        Err(error) => panic!("unexpected malformed SCT result: {error}"),
        Ok(_) => panic!("malformed SCT should fail the TLS handshake"),
    }
}
