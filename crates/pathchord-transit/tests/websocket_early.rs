//! Standalone local peer tests for the not-yet-registered early-data module.

use std::collections::BTreeMap;
use std::io;
use std::time::Duration;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use futures_util::{SinkExt, StreamExt};
use pathchord_transit::{BoxedTransitConnection, TransitError};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio_tungstenite::tungstenite::{
    Message, client::IntoClientRequest, handshake::derive_accept_key, protocol::Role,
};

#[path = "../src/websocket_early.rs"]
mod websocket_early;
use websocket_early::WebSocketEarlyConfig;

fn config(path: &str, maximum: Option<u32>, header: Option<&str>) -> WebSocketEarlyConfig {
    WebSocketEarlyConfig::new(
        format!("ws://localhost:8080{path}")
            .into_client_request()
            .unwrap(),
        maximum,
        header,
    )
    .unwrap()
}

async fn request<S: AsyncRead + Unpin>(stream: &mut S) -> (String, BTreeMap<String, String>) {
    let mut header = Vec::new();
    while !header.ends_with(b"\r\n\r\n") {
        header.push(stream.read_u8().await.unwrap());
        assert!(header.len() < 100_000);
    }
    let text = String::from_utf8(header).unwrap();
    let mut lines = text.lines();
    let target = lines
        .next()
        .unwrap()
        .split_whitespace()
        .nth(1)
        .unwrap()
        .to_owned();
    let headers = lines
        .filter_map(|line| line.split_once(':'))
        .map(|(name, value)| (name.to_ascii_lowercase(), value.trim().to_owned()))
        .collect();
    (target, headers)
}

async fn accept<S: AsyncWrite + Unpin>(
    stream: &mut S,
    headers: &BTreeMap<String, String>,
    echo_protocol: bool,
) {
    let key = derive_accept_key(headers["sec-websocket-key"].as_bytes());
    let selected = if echo_protocol {
        format!(
            "Sec-WebSocket-Protocol: {}\r\n",
            headers["sec-websocket-protocol"]
        )
    } else {
        String::new()
    };
    let response = format!(
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: keep-alive, Upgrade\r\nSec-WebSocket-Accept: {key}\r\n{selected}\r\n"
    );
    // The client must accept fragmented handshake bytes.
    for chunk in response.as_bytes().chunks(7) {
        stream.write_all(chunk).await.unwrap();
    }
    stream.flush().await.unwrap();
}

#[tokio::test]
async fn path_early_data_is_unpadded_base64url_and_remaining_bytes_are_frames() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let (client, mut server) = tokio::io::duplex(17);
        let peer = tokio::spawn(async move {
            let (target, headers) = request(&mut server).await;
            assert_eq!(
                target,
                format!("/ws{}", URL_SAFE_NO_PAD.encode([0xfb, 0xff, 0x01]))
            );
            assert!(!headers.contains_key("sec-websocket-protocol"));
            accept(&mut server, &headers, false).await;
            let mut ws =
                tokio_tungstenite::WebSocketStream::from_raw_socket(server, Role::Server, None)
                    .await;
            let message = ws.next().await.unwrap().unwrap().into_data();
            assert_eq!(&message[..], b"tail");
            ws.send(Message::binary(b"response".to_vec()))
                .await
                .unwrap();
        });
        let config = config("/ws", Some(3), None);
        assert!(config.enabled());
        let mut stream = config.wrap(Box::new(client), Duration::from_secs(2));
        stream
            .write_all(&[0xfb, 0xff, 0x01, b't', b'a', b'i', b'l'])
            .await
            .unwrap();
        stream.flush().await.unwrap();
        let mut response = [0_u8; 8];
        stream.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"response");
        peer.await.unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn query_ed_sets_protocol_header_removes_only_ed_and_accepts_no_echo() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let (client, mut server) = tokio::io::duplex(64);
        let peer = tokio::spawn(async move {
            let (target, headers) = request(&mut server).await;
            assert_eq!(target, "/ws?token=a%2Fb&x=1");
            assert_eq!(
                headers["sec-websocket-protocol"],
                URL_SAFE_NO_PAD.encode(b"hello")
            );
            accept(&mut server, &headers, false).await;
        });
        let config = config("/ws?token=a%2Fb&ed=5&x=1", None, None);
        assert_eq!(
            config.request().uri().path_and_query().unwrap().as_str(),
            "/ws?token=a%2Fb&x=1"
        );
        let mut stream = config.wrap(Box::new(client), Duration::from_secs(2));
        assert_eq!(stream.write(b"hello").await.unwrap(), 5);
        peer.await.unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn query_eh_overrides_default_early_header() {
    let (client, mut server) = tokio::io::duplex(128);
    let peer = tokio::spawn(async move {
        let (target, headers) = request(&mut server).await;
        assert_eq!(target, "/ws?eh=X-Early&other=1");
        assert_eq!(headers["x-early"], URL_SAFE_NO_PAD.encode(b"abc"));
        accept(&mut server, &headers, false).await;
    });
    let config = config("/ws?ed=3&eh=X-Early&other=1", None, None);
    let mut stream = config.wrap(Box::new(client), Duration::from_secs(2));
    stream.write_all(b"abc").await.unwrap();
    peer.await.unwrap();
}

#[tokio::test]
async fn configured_header_supports_echo_and_fragmented_frames() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let (client, mut server) = tokio::io::duplex(64);
        let peer = tokio::spawn(async move {
            let (target, headers) = request(&mut server).await;
            assert_eq!(target, "/ws?token=one");
            assert_eq!(
                headers["sec-websocket-protocol"],
                URL_SAFE_NO_PAD.encode(b"abc")
            );
            accept(&mut server, &headers, true).await;
            // Two RFC 6455 fragments form one binary message.
            server
                .write_all(&[0x02, 3, b'o', b'n', b'e', 0x80, 3, b't', b'w', b'o'])
                .await
                .unwrap();
        });
        let config = config("/ws?token=one", Some(32), Some("Sec-WebSocket-Protocol"));
        let mut stream = config.wrap(Box::new(client), Duration::from_secs(2));
        stream.write_all(b"abc").await.unwrap();
        let mut bytes = [0_u8; 6];
        stream.read_exact(&mut bytes).await.unwrap();
        assert_eq!(&bytes, b"onetwo");
        peer.await.unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn early_data_round_trips_with_local_tcp_websocket_peer() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let peer = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let (target, headers) = request(&mut stream).await;
            assert_eq!(target, "/local?keep=1");
            assert_eq!(headers["x-early"], URL_SAFE_NO_PAD.encode(b"start"));
            accept(&mut stream, &headers, false).await;
            let mut ws =
                tokio_tungstenite::WebSocketStream::from_raw_socket(stream, Role::Server, None)
                    .await;
            assert_eq!(&ws.next().await.unwrap().unwrap().into_data()[..], b"tail");
            ws.send(Message::binary(b"response".to_vec()))
                .await
                .unwrap();
        });
        let request = format!("ws://{address}/local?keep=1")
            .into_client_request()
            .unwrap();
        let config = WebSocketEarlyConfig::new(request, Some(5), Some("X-Early")).unwrap();
        let socket = tokio::net::TcpStream::connect(address).await.unwrap();
        let mut stream = config.wrap(Box::new(socket), Duration::from_secs(2));
        stream.write_all(b"starttail").await.unwrap();
        stream.flush().await.unwrap();
        let mut response = [0; 8];
        stream.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"response");
        peer.await.unwrap();
    })
    .await
    .expect("local WebSocket peer timed out");
}

#[tokio::test]
async fn preserves_websocket_frame_buffered_with_upgrade_response() {
    let (client, mut server) = tokio::io::duplex(4096);
    let peer = tokio::spawn(async move {
        let (_, headers) = request(&mut server).await;
        let key = derive_accept_key(headers["sec-websocket-key"].as_bytes());
        let mut response = format!("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {key}\r\n\r\n").into_bytes();
        response.extend_from_slice(&[0x82, 5, b'e', b'a', b'r', b'l', b'y']);
        server.write_all(&response).await.unwrap();
    });
    let mut stream = config("/ws", Some(8), None).wrap(Box::new(client), Duration::from_secs(2));
    stream.write_all(b"request").await.unwrap();
    let mut response = [0; 5];
    tokio::time::timeout(Duration::from_secs(2), stream.read_exact(&mut response))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&response, b"early");
    peer.await.unwrap();
}

#[tokio::test]
async fn read_or_flush_before_first_write_performs_upgrade_without_early_data() {
    for read_first in [true, false] {
        tokio::time::timeout(Duration::from_secs(5), async {
            let (client, mut server) = tokio::io::duplex(64);
            let peer = tokio::spawn(async move {
                let (target, headers) = request(&mut server).await;
                assert_eq!(target, "/ws");
                assert!(!headers.contains_key("sec-websocket-protocol"));
                accept(&mut server, &headers, false).await;
                let mut ws =
                    tokio_tungstenite::WebSocketStream::from_raw_socket(server, Role::Server, None)
                        .await;
                if read_first {
                    ws.send(Message::binary(b"hello".to_vec())).await.unwrap();
                } else {
                    assert_eq!(&ws.next().await.unwrap().unwrap().into_data()[..], b"later");
                }
            });
            let mut stream = config("/ws", Some(8), Some("Sec-WebSocket-Protocol"))
                .wrap(Box::new(client), Duration::from_secs(2));
            if read_first {
                let mut bytes = [0; 5];
                stream.read_exact(&mut bytes).await.unwrap();
                assert_eq!(&bytes, b"hello");
            } else {
                stream.flush().await.unwrap();
                stream.write_all(b"later").await.unwrap();
                stream.flush().await.unwrap();
            }
            peer.await.unwrap();
        })
        .await
        .unwrap();
    }
}

#[tokio::test]
async fn cancellation_rejects_replacing_the_first_payload() {
    use std::future::Future;
    use std::task::{Context, Poll, Waker};
    let (client, _server) = tokio::io::duplex(16);
    let mut stream = config("/ws", Some(5), None).wrap(Box::new(client), Duration::from_secs(2));
    {
        let future = stream.write(b"first payload");
        tokio::pin!(future);
        assert!(matches!(
            future
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop())),
            Poll::Pending
        ));
    }
    let error = stream.write(b"different").await.unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    assert!(stream.write(b"first payload").await.is_err());
}

#[tokio::test]
async fn concurrent_read_and_first_write_are_both_woken_when_handshake_finishes() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let (client, mut server) = tokio::io::duplex(32);
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = tokio::sync::oneshot::channel();
        let peer = tokio::spawn(async move {
            let (_, headers) = request(&mut server).await;
            assert_eq!(
                headers["sec-websocket-protocol"],
                URL_SAFE_NO_PAD.encode(b"hello")
            );
            ready_tx.send(()).unwrap();
            release_rx.await.unwrap();
            accept(&mut server, &headers, false).await;
            let mut ws =
                tokio_tungstenite::WebSocketStream::from_raw_socket(server, Role::Server, None)
                    .await;
            ws.send(Message::binary(b"reply".to_vec())).await.unwrap();
        });
        let stream = config("/ws", Some(5), Some("Sec-WebSocket-Protocol"))
            .wrap(Box::new(client), Duration::from_secs(2));
        let (mut read, mut write) = tokio::io::split(stream);
        let writer = tokio::spawn(async move { write.write_all(b"hello").await });
        ready_rx.await.unwrap();
        let reader = tokio::spawn(async move {
            let mut result = [0; 5];
            read.read_exact(&mut result).await.map(|_| result)
        });
        tokio::task::yield_now().await;
        release_tx.send(()).unwrap();
        assert_eq!(&reader.await.unwrap().unwrap(), b"reply");
        writer.await.unwrap().unwrap();
        peer.await.unwrap();
    })
    .await
    .expect("concurrent WebSocket I/O timed out");
}

#[tokio::test]
async fn rejects_failed_handshake_and_times_out_without_retrying() {
    for bad_accept in [false, true] {
        let (client, mut server) = tokio::io::duplex(128);
        let peer = tokio::spawn(async move {
            let (_, headers) = request(&mut server).await;
            let response = if bad_accept {
                "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: invalid\r\n\r\n".to_owned()
            } else {
                format!(
                    "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nX-Key: {}\r\n\r\n",
                    headers["sec-websocket-key"]
                )
            };
            server.write_all(response.as_bytes()).await.unwrap();
        });
        let mut stream =
            config("/ws", Some(8), None).wrap(Box::new(client), Duration::from_secs(1));
        assert!(stream.write_all(b"payload").await.is_err());
        assert!(stream.write_all(b"payload").await.is_err());
        peer.await.unwrap();
    }
    let (client, _server) = tokio::io::duplex(4096);
    let mut stream = config("/ws", Some(8), None).wrap(Box::new(client), Duration::from_millis(50));
    let error = stream.write_all(b"payload").await.unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
}

#[tokio::test]
async fn shutdown_without_first_write_upgrades_and_sends_close() {
    let (client, mut server) = tokio::io::duplex(64);
    let peer = tokio::spawn(async move {
        let (target, headers) = request(&mut server).await;
        assert_eq!(target, "/ws");
        accept(&mut server, &headers, false).await;
        let mut ws =
            tokio_tungstenite::WebSocketStream::from_raw_socket(server, Role::Server, None).await;
        assert!(matches!(ws.next().await, Some(Ok(Message::Close(_)))));
    });
    let mut stream = config("/ws", Some(8), None).wrap(Box::new(client), Duration::from_secs(2));
    tokio::time::timeout(Duration::from_secs(3), stream.shutdown())
        .await
        .unwrap()
        .unwrap();
    peer.await.unwrap();
}

#[tokio::test]
async fn shutdown_keeps_already_sent_peer_data_readable() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let (client, mut server) = tokio::io::duplex(64);
        let peer = tokio::spawn(async move {
            let (_, headers) = request(&mut server).await;
            accept(&mut server, &headers, false).await;
            let mut ws =
                tokio_tungstenite::WebSocketStream::from_raw_socket(server, Role::Server, None)
                    .await;
            ws.send(Message::binary(b"reply".to_vec())).await.unwrap();
            assert!(matches!(ws.next().await, Some(Ok(Message::Close(_)))));
        });
        let mut stream =
            config("/ws", Some(8), None).wrap(Box::new(client), Duration::from_secs(2));
        stream.write_all(b"request").await.unwrap();
        stream.shutdown().await.unwrap();
        let mut bytes = [0; 5];
        stream.read_exact(&mut bytes).await.unwrap();
        assert_eq!(&bytes, b"reply");
        assert_eq!(
            stream.write(b"again").await.unwrap_err().kind(),
            io::ErrorKind::BrokenPipe
        );
        peer.await.unwrap();
    })
    .await
    .expect("WebSocket shutdown timed out");
}

#[test]
fn rejects_conflicts_and_preserves_non_early_query_parameters() {
    let request = || {
        "ws://localhost:8080/ws?foo=1&ed=64"
            .into_client_request()
            .unwrap()
    };
    assert!(WebSocketEarlyConfig::new(request(), Some(63), None).is_err());
    assert!(WebSocketEarlyConfig::new(request(), None, Some("X-Early")).is_err());
    assert!(
        WebSocketEarlyConfig::new(
            "ws://localhost/ws?ed=1&ed=2".into_client_request().unwrap(),
            None,
            None
        )
        .is_err()
    );
    assert!(
        WebSocketEarlyConfig::new(
            "ws://localhost/ws?ed=1&eh=A&eh=B"
                .into_client_request()
                .unwrap(),
            None,
            None
        )
        .is_err()
    );
    assert!(
        WebSocketEarlyConfig::new(
            "ws://localhost/ws?foo=1".into_client_request().unwrap(),
            Some(4),
            None
        )
        .is_err()
    );
    assert!(
        WebSocketEarlyConfig::new(
            "ws://localhost/ws".into_client_request().unwrap(),
            Some(4),
            Some("Host")
        )
        .is_err()
    );
    let mut request = "ws://localhost/ws".into_client_request().unwrap();
    request
        .headers_mut()
        .insert("X-Early", "existing".parse().unwrap());
    assert!(WebSocketEarlyConfig::new(request, Some(4), Some("x-early")).is_err());
    let disabled = config("/ws", Some(0), None);
    assert!(!disabled.enabled());
    assert!(config("/ws?ed=%36%34&foo=1", None, None).enabled());
    assert!(
        WebSocketEarlyConfig::new(
            "ws://localhost/ws".into_client_request().unwrap(),
            Some(65_537),
            None
        )
        .is_err()
    );
}
