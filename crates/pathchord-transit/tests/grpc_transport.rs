//! Behavioral tests for VLESS over a real HTTP/2 gRPC byte stream.

use std::{collections::BTreeMap, future::Future, net::SocketAddr, sync::Arc, time::Duration};

use bytes::{Buf, BufMut, Bytes, BytesMut};
use pathchord_policy::{
    Endpoint as PolicyEndpoint, TransitOptions, TransitProxyConfig, TransitProxyId, TransitTls,
    TransitTransport,
};
use pathchord_transit::{
    AdapterRegistry, ConnectRequest, Endpoint, NoTransitCredentials, TransitAdapter,
    TransitCredential,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    sync::oneshot,
    task::JoinHandle,
    time::timeout,
};

const UUID: &str = "6cbf3f72-3417-4922-bde6-67820d041f25";
const TEST_TIMEOUT: Duration = Duration::from_secs(5);

fn adapter(address: SocketAddr, duration: Duration) -> Arc<dyn TransitAdapter> {
    adapter_with_tls(address, duration, None)
}

fn adapter_with_tls(
    address: SocketAddr,
    duration: Duration,
    tls: Option<TransitTls>,
) -> Arc<dyn TransitAdapter> {
    let config = TransitProxyConfig {
        id: TransitProxyId::new("grpc-fixture"),
        source: None,
        protocol: "vless".into(),
        endpoint: PolicyEndpoint {
            host: address.ip().to_string(),
            port: address.port(),
        },
        credentials_ref: None,
        labels: Default::default(),
        tags: Default::default(),
        weight: 100,
        options: TransitOptions {
            tls,
            transport: Some(TransitTransport {
                kind: "grpc".into(),
                service_name: Some("pathchord.test".into()),
                ..Default::default()
            }),
            ..Default::default()
        },
    };
    let credential = TransitCredential::new(BTreeMap::from([("uuid".to_owned(), UUID.to_owned())]));
    AdapterRegistry::for_configs(Arc::new(NoTransitCredentials), duration, [&config])
        .unwrap()
        .build_with_credential(&config, &credential)
        .unwrap()
}

fn request() -> ConnectRequest {
    ConnectRequest {
        destination: Endpoint {
            host: "example.test".into(),
            port: 443,
        },
    }
}

fn hunk(data: &[u8]) -> Bytes {
    let mut message = BytesMut::new();
    message.put_u8(0x0a);
    let mut length = data.len();
    while length >= 0x80 {
        message.put_u8((length as u8 & 0x7f) | 0x80);
        length >>= 7;
    }
    message.put_u8(length as u8);
    message.extend_from_slice(data);
    let mut frame = BytesMut::new();
    frame.put_u8(0);
    frame.put_u32(message.len() as u32);
    frame.extend_from_slice(&message);
    frame.freeze()
}

struct HunkReader {
    input: h2::RecvStream,
    pending: BytesMut,
}

impl HunkReader {
    async fn next(&mut self) -> Option<Vec<u8>> {
        loop {
            if self.pending.len() >= 5 {
                let size = u32::from_be_bytes(self.pending[1..5].try_into().unwrap()) as usize;
                if self.pending.len() >= 5 + size {
                    assert_eq!(self.pending[0], 0);
                    self.pending.advance(5);
                    let mut message = self.pending.split_to(size).freeze();
                    assert_eq!(message.get_u8(), 0x0a);
                    let mut length = 0_usize;
                    let mut shift = 0;
                    loop {
                        let byte = message.get_u8();
                        length |= usize::from(byte & 0x7f) << shift;
                        if byte & 0x80 == 0 {
                            break;
                        }
                        shift += 7;
                    }
                    assert_eq!(length, message.len());
                    return Some(message.to_vec());
                }
            }
            match self.input.data().await {
                Some(Ok(bytes)) => {
                    self.input
                        .flow_control()
                        .release_capacity(bytes.len())
                        .unwrap();
                    self.pending.extend_from_slice(&bytes);
                }
                Some(Err(error)) => panic!("HTTP/2 request body failed: {error}"),
                None => {
                    assert!(self.pending.is_empty());
                    return None;
                }
            }
        }
    }
}

async fn start_server<F, Fut>(handler: F) -> (SocketAddr, oneshot::Sender<()>, JoinHandle<()>)
where
    F: FnOnce(http::Request<h2::RecvStream>, h2::server::SendResponse<Bytes>) -> Fut
        + Send
        + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    start_server_with_window(65_535, handler).await
}

async fn start_server_with_window<F, Fut>(
    window: u32,
    handler: F,
) -> (SocketAddr, oneshot::Sender<()>, JoinHandle<()>)
where
    F: FnOnce(http::Request<h2::RecvStream>, h2::server::SendResponse<Bytes>) -> Fut
        + Send
        + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (finish, finished) = oneshot::channel();
    let task = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let mut connection = h2::server::Builder::new()
            .initial_window_size(window)
            .handshake(socket)
            .await
            .unwrap();
        let (request, response) = connection.accept().await.unwrap().unwrap();
        assert_eq!(request.uri().path(), "/pathchord.test/Tun");
        assert_eq!(
            request.headers()[http::header::CONTENT_TYPE],
            "application/grpc"
        );
        let mut handler = Box::pin(handler(request, response));
        tokio::select! {
            () = &mut handler => {},
            _ = &mut Box::pin(async { let _ = finished.await; }) => {},
            next = connection.accept() => { assert!(!matches!(next, Some(Ok(_))), "unexpected extra HTTP/2 stream"); }
        }
    });
    (address, finish, task)
}

#[tokio::test]
async fn fragmented_messages_short_writes_and_half_close_preserve_the_stream() {
    let upload: Vec<u8> = (0..393_333).map(|i| (i % 251) as u8).collect();
    let download: Vec<u8> = (0..412_777).map(|i| (i % 239) as u8).collect();
    let expected_upload = upload.clone();
    let expected_download = download.clone();
    let (address, finish, server) = start_server(move |request, mut respond| async move {
        let mut response = response(&mut respond);
        let mut reader = HunkReader {
            input: request.into_body(),
            pending: BytesMut::new(),
        };
        assert!(!reader.next().await.unwrap().is_empty());
        let mut received = Vec::new();
        while let Some(chunk) = reader.next().await {
            received.extend(chunk);
        }
        assert_eq!(received, expected_upload);
        let mut payload = vec![0, 0];
        payload.extend_from_slice(&expected_download);
        let frame = hunk(&payload);
        for byte in &frame[..15] {
            response
                .send_data(Bytes::copy_from_slice(&[*byte]), false)
                .unwrap();
            tokio::task::yield_now().await;
        }
        for chunk in frame[15..].chunks(4093) {
            response
                .send_data(Bytes::copy_from_slice(chunk), false)
                .unwrap();
        }
        let mut trailers = http::HeaderMap::new();
        trailers.insert("grpc-status", http::HeaderValue::from_static("0"));
        response.send_trailers(trailers).unwrap();
        std::future::pending::<()>().await;
    })
    .await;
    let mut stream = adapter(address, TEST_TIMEOUT)
        .connect(request())
        .await
        .unwrap();
    let count = stream.write(&upload).await.unwrap();
    assert!(count > 0 && count < upload.len());
    stream.write_all(&upload[count..]).await.unwrap();
    stream.shutdown().await.unwrap();
    let mut received = Vec::new();
    timeout(TEST_TIMEOUT, stream.read_to_end(&mut received))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(received, download);
    drop(stream);
    let _ = finish.send(());
    server.await.unwrap();
}

#[tokio::test]
async fn a_failed_http2_response_remains_an_error_on_repeated_reads() {
    let (address, finish, server) = start_server(|request, mut respond| async move {
        let mut reader = HunkReader {
            input: request.into_body(),
            pending: BytesMut::new(),
        };
        assert!(!reader.next().await.unwrap().is_empty());
        respond
            .send_response(
                http::Response::builder().status(403).body(()).unwrap(),
                true,
            )
            .unwrap();
        std::future::pending::<()>().await;
    })
    .await;
    let mut stream = adapter(address, TEST_TIMEOUT)
        .connect(request())
        .await
        .unwrap();
    let mut byte = [0; 1];
    for _ in 0..2 {
        assert!(
            timeout(TEST_TIMEOUT, stream.read(&mut byte))
                .await
                .unwrap()
                .is_err()
        );
    }
    drop(stream);
    let _ = finish.send(());
    server.await.unwrap();
}

#[tokio::test]
async fn nonzero_grpc_status_in_headers_is_rejected_before_payload() {
    let (address, finish, server) = start_server(|request, mut respond| async move {
        let mut reader = HunkReader {
            input: request.into_body(),
            pending: BytesMut::new(),
        };
        assert!(!reader.next().await.unwrap().is_empty());
        let mut response = respond
            .send_response(
                http::Response::builder()
                    .status(200)
                    .header(http::header::CONTENT_TYPE, "application/grpc")
                    .header("grpc-status", "7")
                    .body(())
                    .unwrap(),
                false,
            )
            .unwrap();
        response.send_data(hunk(&[0, 0, b'x']), false).unwrap();
        std::future::pending::<()>().await;
    })
    .await;
    let mut stream = adapter(address, TEST_TIMEOUT)
        .connect(request())
        .await
        .unwrap();
    let mut byte = [0; 1];
    assert!(
        timeout(TEST_TIMEOUT, stream.read(&mut byte))
            .await
            .unwrap()
            .is_err()
    );
    drop(stream);
    let _ = finish.send(());
    server.await.unwrap();
}

#[tokio::test]
async fn grpc_rejects_a_similarly_named_but_invalid_content_type() {
    let (address, finish, server) = start_server(|request, mut respond| async move {
        let mut reader = HunkReader {
            input: request.into_body(),
            pending: BytesMut::new(),
        };
        assert!(!reader.next().await.unwrap().is_empty());
        let mut response = respond
            .send_response(
                http::Response::builder()
                    .status(200)
                    .header(http::header::CONTENT_TYPE, "application/grpc-invalid")
                    .body(())
                    .unwrap(),
                false,
            )
            .unwrap();
        response.send_data(hunk(&[0, 0, b'x']), false).unwrap();
        std::future::pending::<()>().await;
    })
    .await;
    let mut stream = adapter(address, TEST_TIMEOUT)
        .connect(request())
        .await
        .unwrap();
    let mut byte = [0; 1];
    assert!(
        timeout(TEST_TIMEOUT, stream.read(&mut byte))
            .await
            .unwrap()
            .is_err()
    );
    drop(stream);
    let _ = finish.send(());
    server.await.unwrap();
}

#[tokio::test]
async fn cancelled_write_does_not_send_its_input_after_flow_control_resumes() {
    let (ready_tx, ready_rx) = oneshot::channel();
    let (resume_tx, resume_rx) = oneshot::channel();
    let (received_tx, received_rx) = oneshot::channel();
    let (address, finish, server) =
        start_server_with_window(1024, move |request, mut respond| async move {
            let mut response = response(&mut respond);
            let mut reader = HunkReader {
                input: request.into_body(),
                pending: BytesMut::new(),
            };
            assert!(!reader.next().await.unwrap().is_empty());
            let _ = ready_tx.send(());
            let _ = resume_rx.await;
            let mut received = Vec::new();
            while let Some(chunk) = reader.next().await {
                received.extend(chunk);
            }
            let _ = received_tx.send(received);
            response
                .send_data(hunk(&[0, 0, b'o', b'k']), false)
                .unwrap();
            std::future::pending::<()>().await;
        })
        .await;
    let mut stream = adapter(address, TEST_TIMEOUT)
        .connect(request())
        .await
        .unwrap();
    timeout(TEST_TIMEOUT, ready_rx).await.unwrap().unwrap();
    let fill = vec![b'A'; 2 * 1024 * 1024];
    assert!(
        timeout(Duration::from_millis(100), stream.write_all(&fill))
            .await
            .is_err()
    );
    assert!(
        timeout(Duration::from_millis(100), stream.write_all(b"CANCELLED"))
            .await
            .is_err()
    );
    let _ = resume_tx.send(());
    timeout(TEST_TIMEOUT, stream.write_all(b"KEPT"))
        .await
        .unwrap()
        .unwrap();
    stream.shutdown().await.unwrap();
    let bytes = timeout(TEST_TIMEOUT, received_rx).await.unwrap().unwrap();
    assert!(bytes.ends_with(b"KEPT"));
    assert!(bytes[..bytes.len() - 4].iter().all(|byte| *byte == b'A'));
    let mut reply = [0; 2];
    stream.read_exact(&mut reply).await.unwrap();
    assert_eq!(&reply, b"ok");
    drop(stream);
    let _ = finish.send(());
    server.await.unwrap();
}

fn response(respond: &mut h2::server::SendResponse<Bytes>) -> h2::SendStream<Bytes> {
    respond
        .send_response(
            http::Response::builder()
                .status(200)
                .header(http::header::CONTENT_TYPE, "application/grpc")
                .body(())
                .unwrap(),
            false,
        )
        .unwrap()
}

#[tokio::test]
async fn writing_then_reading_without_flush_delivers_the_request() {
    let (address, finish, server) = start_server(|request, mut respond| async move {
        let mut response = response(&mut respond);
        let mut reader = HunkReader {
            input: request.into_body(),
            pending: BytesMut::new(),
        };
        assert!(!reader.next().await.unwrap().is_empty());
        let payload = reader.next().await.unwrap();
        assert_eq!(payload, b"ping");
        response
            .send_data(hunk(&[0, 0, b'p', b'o', b'n', b'g']), false)
            .unwrap();
        std::future::pending::<()>().await;
    })
    .await;
    let mut stream = adapter(address, TEST_TIMEOUT)
        .connect(request())
        .await
        .unwrap();
    stream.write_all(b"ping").await.unwrap();
    let mut reply = [0; 4];
    timeout(Duration::from_secs(1), stream.read_exact(&mut reply))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&reply, b"pong");
    drop(stream);
    let _ = finish.send(());
    server.await.unwrap();
}

#[tokio::test]
async fn malformed_or_failed_grpc_messages_never_become_proxy_payload() {
    for (frame, status) in [
        (vec![1, 0, 0, 0, 0], None),
        (vec![0, 0, 0x40, 0, 1], None),
        (vec![0, 0, 0, 0, 5, 0x0a], None),
        (vec![0, 0, 0, 0, 2, 0x12, 0], None),
        (vec![0, 0, 0, 0, 3, 0x0a, 3, 0], None),
        (hunk(&[0, 0]).to_vec(), Some("7")),
    ] {
        let (address, finish, server) = start_server(move |request, mut respond| async move {
            let mut reader = HunkReader {
                input: request.into_body(),
                pending: BytesMut::new(),
            };
            assert!(!reader.next().await.unwrap().is_empty());
            let mut response = response(&mut respond);
            response
                .send_data(Bytes::from(frame), status.is_none())
                .unwrap();
            if let Some(status) = status {
                let mut trailers = http::HeaderMap::new();
                trailers.insert("grpc-status", http::HeaderValue::from_static(status));
                response.send_trailers(trailers).unwrap();
            }
            std::future::pending::<()>().await;
        })
        .await;
        let mut stream = adapter(address, TEST_TIMEOUT)
            .connect(request())
            .await
            .unwrap();
        let mut byte = [0; 1];
        for _ in 0..2 {
            assert!(
                timeout(TEST_TIMEOUT, stream.read(&mut byte))
                    .await
                    .unwrap()
                    .is_err()
            );
        }
        drop(stream);
        let _ = finish.send(());
        server.await.unwrap();
    }
}

#[tokio::test]
async fn sing_box_lite_eof_without_grpc_trailers_remains_compatible() {
    let (address, finish, server) = start_server(|request, mut respond| async move {
        let mut reader = HunkReader {
            input: request.into_body(),
            pending: BytesMut::new(),
        };
        assert!(!reader.next().await.unwrap().is_empty());
        let mut response = response(&mut respond);
        response.send_data(hunk(&[0, 0, b'o', b'k']), true).unwrap();
        std::future::pending::<()>().await;
    })
    .await;
    let mut stream = adapter(address, TEST_TIMEOUT)
        .connect(request())
        .await
        .unwrap();
    let mut received = Vec::new();
    timeout(TEST_TIMEOUT, stream.read_to_end(&mut received))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&received, b"ok");
    drop(stream);
    let _ = finish.send(());
    server.await.unwrap();
}

async fn tls_blackhole() -> (SocketAddr, oneshot::Receiver<()>, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (ready_tx, ready_rx) = oneshot::channel();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut bytes = [0; 4096];
        assert_ne!(stream.read(&mut bytes).await.unwrap(), 0);
        let _ = ready_tx.send(());
        loop {
            if stream.read(&mut bytes).await.unwrap_or_default() == 0 {
                break;
            }
        }
    });
    (address, ready_rx, server)
}

fn insecure_tls() -> TransitTls {
    TransitTls {
        enabled: true,
        insecure: true,
        server_name: Some("grpc.test".into()),
        ..Default::default()
    }
}

#[tokio::test]
async fn stalled_tls_open_times_out_and_releases_its_socket() {
    let (address, ready, server) = tls_blackhole().await;
    let client = adapter_with_tls(address, Duration::from_millis(100), Some(insecure_tls()));
    let opening = tokio::spawn(async move { client.connect(request()).await });
    timeout(TEST_TIMEOUT, ready).await.unwrap().unwrap();
    assert!(matches!(
        timeout(Duration::from_secs(2), opening)
            .await
            .unwrap()
            .unwrap(),
        Err(pathchord_transit::TransitError::Connection(_))
    ));
    timeout(TEST_TIMEOUT, server).await.unwrap().unwrap();
}

#[tokio::test]
async fn cancelling_tls_open_releases_its_socket() {
    let (address, ready, server) = tls_blackhole().await;
    let client = adapter_with_tls(address, TEST_TIMEOUT, Some(insecure_tls()));
    let opening = tokio::spawn(async move { client.connect(request()).await });
    timeout(TEST_TIMEOUT, ready).await.unwrap().unwrap();
    opening.abort();
    assert!(matches!(opening.await, Err(error) if error.is_cancelled()));
    timeout(TEST_TIMEOUT, server).await.unwrap().unwrap();
}

#[tokio::test]
async fn dropping_an_open_grpc_stream_closes_the_http2_connection() {
    let (ready_tx, ready_rx) = oneshot::channel();
    let (address, _finish, server) = start_server(move |request, _respond| async move {
        let mut reader = HunkReader {
            input: request.into_body(),
            pending: BytesMut::new(),
        };
        assert!(!reader.next().await.unwrap().is_empty());
        let _ = ready_tx.send(());
        std::future::pending::<()>().await;
    })
    .await;
    let stream = adapter(address, TEST_TIMEOUT)
        .connect(request())
        .await
        .unwrap();
    timeout(TEST_TIMEOUT, ready_rx).await.unwrap().unwrap();
    drop(stream);
    timeout(TEST_TIMEOUT, server).await.unwrap().unwrap();
}

#[tokio::test]
async fn concurrent_grpc_streams_have_independent_data_and_lifetimes() {
    let mut tasks = tokio::task::JoinSet::new();
    for index in 0..24_u8 {
        tasks.spawn(async move {
            let (address, finish, server) = start_server(move |request, mut respond| async move {
                let mut reader = HunkReader {
                    input: request.into_body(),
                    pending: BytesMut::new(),
                };
                assert!(!reader.next().await.unwrap().is_empty());
                assert_eq!(reader.next().await.unwrap(), vec![index; 32]);
                let mut response = response(&mut respond);
                let mut bytes = vec![0, 0];
                bytes.extend_from_slice(&[index; 32]);
                response.send_data(hunk(&bytes), true).unwrap();
                std::future::pending::<()>().await;
            })
            .await;
            let mut stream = adapter(address, TEST_TIMEOUT)
                .connect(request())
                .await
                .unwrap();
            stream.write_all(&[index; 32]).await.unwrap();
            let mut received = Vec::new();
            timeout(TEST_TIMEOUT, stream.read_to_end(&mut received))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(received, vec![index; 32]);
            drop(stream);
            let _ = finish.send(());
            server.await.unwrap();
        });
    }
    while let Some(result) = tasks.join_next().await {
        result.unwrap();
    }
}

#[tokio::test]
async fn grpc_requires_certificate_authentication_server_name_and_h2_alpn() {
    use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};

    for failure in ["wrong-ca", "wrong-name", "missing-alpn"] {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let rcgen::CertifiedKey { cert, signing_key } =
            rcgen::generate_simple_self_signed(vec!["grpc.test".to_owned()]).unwrap();
        let trusted_cert = if failure == "wrong-ca" {
            rcgen::generate_simple_self_signed(vec!["grpc.test".to_owned()])
                .unwrap()
                .cert
                .pem()
        } else {
            cert.pem()
        };
        let mut server_config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.der().clone()],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(signing_key.serialize_der())),
        )
        .unwrap();
        if failure != "missing-alpn" {
            server_config.alpn_protocols = vec![b"h2".to_vec()];
        }
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let _ = acceptor.accept(stream).await;
        });
        let tls = TransitTls {
            enabled: true,
            server_name: Some(
                if failure == "wrong-name" {
                    "wrong.test"
                } else {
                    "grpc.test"
                }
                .into(),
            ),
            truststore: Vec::new(),
            certificate: vec![trusted_cert],
            ..Default::default()
        };
        let result = timeout(
            TEST_TIMEOUT,
            adapter_with_tls(address, TEST_TIMEOUT, Some(tls)).connect(request()),
        )
        .await
        .unwrap();
        match failure {
            "missing-alpn" => assert!(matches!(
                result,
                Err(pathchord_transit::TransitError::Unsupported(_))
            )),
            _ => assert!(matches!(
                result,
                Err(pathchord_transit::TransitError::Connection(_))
            )),
        }
        timeout(TEST_TIMEOUT, server).await.unwrap().unwrap();
    }
}
