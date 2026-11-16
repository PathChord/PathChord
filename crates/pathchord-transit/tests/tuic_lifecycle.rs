//! TUIC lifecycle regressions against a controllable loopback QUIC peer.

use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
    time::Duration,
};

use pathchord_policy::{
    Endpoint as PolicyEndpoint, TransitOptions, TransitProxyConfig, TransitProxyId, TransitTls,
};
use pathchord_transit::{
    AdapterRegistry, ConnectRequest, Endpoint, NoTransitCredentials, TransitAdapter,
    TransitCredential,
};
use quinn::{Endpoint as QuicEndpoint, TransportConfig, VarInt, crypto::rustls::QuicServerConfig};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    time::{sleep, timeout},
};

const UUID: &str = "6cbf3f72-3417-4922-bde6-67820d041f25";
const PASSWORD: &str = "tuic-lifecycle-password";
const SERVER_NAME: &str = "tuic-lifecycle.test";
const TARGET_PORT: u16 = 5353;
const TEST_TIMEOUT: Duration = Duration::from_secs(5);
// Leave enough time for the local QUIC handshake under a loaded test runner;
// the peer still deliberately withholds stream credit after the handshake.
const STALL_TIMEOUT: Duration = Duration::from_secs(2);

struct Peer {
    endpoint: QuicEndpoint,
    certificate: String,
}

impl Peer {
    fn new(uni_limit: u32) -> Self {
        Self::with_stream_window(uni_limit, None)
    }

    fn with_stream_window(uni_limit: u32, window: Option<u32>) -> Self {
        let rcgen::CertifiedKey { cert, signing_key } =
            rcgen::generate_simple_self_signed(vec![SERVER_NAME.to_owned()]).unwrap();
        let certificate = cert.pem();
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let mut tls = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![cert.der().clone()],
                rustls::pki_types::PrivatePkcs8KeyDer::from(signing_key.serialize_der()).into(),
            )
            .unwrap();
        tls.alpn_protocols = vec![b"h3".to_vec()];
        let mut server =
            quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(tls).unwrap()));
        let mut transport = TransportConfig::default();
        transport.max_concurrent_uni_streams(VarInt::from_u32(uni_limit));
        if let Some(window) = window {
            transport.stream_receive_window(VarInt::from_u32(window));
        }
        transport.datagram_receive_buffer_size(Some(256 * 1024));
        transport.datagram_send_buffer_size(256 * 1024);
        server.transport_config(Arc::new(transport));
        let endpoint = QuicEndpoint::server(server, "127.0.0.1:0".parse().unwrap()).unwrap();
        Self {
            endpoint,
            certificate,
        }
    }

    fn adapter(&self, duration: Duration, heartbeat: Option<&str>) -> Arc<dyn TransitAdapter> {
        self.adapter_with_options(duration, heartbeat, [("udp_relay_mode", "quic")])
    }

    fn adapter_with_options(
        &self,
        duration: Duration,
        heartbeat: Option<&str>,
        options: impl IntoIterator<Item = (&'static str, &'static str)>,
    ) -> Arc<dyn TransitAdapter> {
        let address = self.endpoint.local_addr().unwrap();
        let config = TransitProxyConfig {
            id: TransitProxyId::new("tuic-lifecycle"),
            source: None,
            protocol: "tuic".into(),
            endpoint: PolicyEndpoint {
                host: address.ip().to_string(),
                port: address.port(),
            },
            credentials_ref: None,
            labels: BTreeMap::new(),
            tags: BTreeSet::new(),
            weight: 100,
            options: TransitOptions {
                tls: Some(TransitTls {
                    enabled: true,
                    server_name: Some(SERVER_NAME.to_owned()),
                    truststore: Vec::new(),
                    certificate: vec![self.certificate.clone()],
                    alpn: vec!["h3".to_owned()],
                    ..Default::default()
                }),
                ..Default::default()
            },
        };
        let mut fields = BTreeMap::from([
            ("uuid".to_owned(), UUID.to_owned()),
            ("password".to_owned(), PASSWORD.to_owned()),
        ]);
        fields.extend(
            options
                .into_iter()
                .map(|(key, value)| (key.to_owned(), value.to_owned())),
        );
        if let Some(heartbeat) = heartbeat {
            fields.insert("heartbeat".to_owned(), heartbeat.to_owned());
        }
        let tls = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(rustls::RootCertStore::empty())
        .with_no_client_auth();
        AdapterRegistry::new(Arc::new(NoTransitCredentials), duration, Arc::new(tls))
            .build_with_credential(&config, &TransitCredential::new(fields))
            .unwrap()
    }

    async fn accept(&self) -> quinn::Connection {
        timeout(TEST_TIMEOUT, async {
            self.endpoint.accept().await.unwrap().await.unwrap()
        })
        .await
        .expect("QUIC handshake timed out")
    }

    async fn accept_auth(&self) -> quinn::Connection {
        let connection = self.accept().await;
        let mut auth = timeout(TEST_TIMEOUT, connection.accept_uni())
            .await
            .expect("authentication stream timed out")
            .unwrap();
        let auth = auth.read_to_end(50).await.unwrap();
        assert_eq!(auth.len(), 50);
        assert_eq!(&auth[..2], &[5, 0]);
        assert_eq!(
            &auth[2..18],
            uuid::Uuid::parse_str(UUID).unwrap().as_bytes()
        );
        let mut token = [0; 32];
        connection
            .export_keying_material(&mut token, &auth[2..18], PASSWORD.as_bytes())
            .unwrap();
        assert_eq!(&auth[18..], &token);
        connection
    }
}

#[tokio::test]
async fn udp_over_stream_uses_authenticated_tuic_connect_and_survives_cancelled_receive() {
    let peer = Peer::new(8);
    let adapter =
        peer.adapter_with_options(Duration::from_secs(2), None, [("udp_over_stream", "true")]);
    let (connection, socket) = tokio::join!(peer.accept_auth(), adapter.connect_udp(target()));
    let mut socket = socket.unwrap();
    let (mut send, mut recv) = timeout(TEST_TIMEOUT, connection.accept_bi())
        .await
        .unwrap()
        .unwrap();
    let magic = b"sp.v2.udp-over-tcp.arpa";
    let mut command = vec![0; 2 + 1 + 1 + magic.len() + 2];
    recv.read_exact(&mut command).await.unwrap();
    assert_eq!(&command[..4], &[5, 1, 0, magic.len() as u8]);
    assert_eq!(&command[4..4 + magic.len()], magic);
    assert_eq!(&command[4 + magic.len()..], &[0, 0]);
    let mut setup = [0; 8];
    recv.read_exact(&mut setup).await.unwrap();
    assert_eq!(&setup, &[1, 1, 127, 0, 0, 1, 0x14, 0xe9]);
    socket.send(b"request").await.unwrap();
    let mut request = [0; 9];
    recv.read_exact(&mut request).await.unwrap();
    assert_eq!(&request, b"\0\x07request");
    send.write_all(&[0]).await.unwrap();
    assert!(
        timeout(Duration::from_millis(30), socket.receive())
            .await
            .is_err()
    );
    send.write_all(b"\x05reply").await.unwrap();
    assert_eq!(socket.receive().await.unwrap(), b"reply");
    let close = tokio::spawn(async move { socket.close().await });
    assert_eq!(
        timeout(TEST_TIMEOUT, recv.read_u8())
            .await
            .unwrap()
            .unwrap_err()
            .kind(),
        std::io::ErrorKind::UnexpectedEof
    );
    close.await.unwrap().unwrap();
    timeout(TEST_TIMEOUT, connection.closed())
        .await
        .expect("UDP stream closure must release the QUIC session");
}

#[tokio::test]
async fn udp_over_stream_cancelled_send_completes_before_the_next_packet() {
    let peer = Peer::with_stream_window(8, Some(256));
    let adapter =
        peer.adapter_with_options(Duration::from_secs(3), None, [("udp_over_stream", "true")]);
    let (connection, socket) = tokio::join!(peer.accept_auth(), adapter.connect_udp(target()));
    let mut socket = socket.unwrap();
    let (_send, mut recv) = timeout(TEST_TIMEOUT, connection.accept_bi())
        .await
        .unwrap()
        .unwrap();
    let large = vec![0x53; 60_000];
    assert!(
        timeout(Duration::from_millis(100), socket.send(&large))
            .await
            .is_err()
    );
    let server = async {
        let magic = b"sp.v2.udp-over-tcp.arpa";
        let mut setup = vec![0; 4 + magic.len() + 2 + 8];
        recv.read_exact(&mut setup).await.unwrap();
        let mut header = [0; 2];
        recv.read_exact(&mut header).await.unwrap();
        assert_eq!(usize::from(u16::from_be_bytes(header)), large.len());
        let mut payload = vec![0; large.len()];
        recv.read_exact(&mut payload).await.unwrap();
        assert_eq!(payload, large);
        recv.read_exact(&mut header).await.unwrap();
        assert_eq!(u16::from_be_bytes(header), 4);
        let mut next = [0; 4];
        recv.read_exact(&mut next).await.unwrap();
        assert_eq!(&next, b"next");
    };
    timeout(TEST_TIMEOUT, async {
        tokio::join!(server, socket.send(b"next"))
    })
    .await
    .unwrap()
    .1
    .unwrap();
    socket.close().await.unwrap();
}

#[tokio::test]
async fn stalled_udp_over_stream_send_times_out_and_closes_session() {
    let peer = Peer::with_stream_window(8, Some(256));
    let adapter =
        peer.adapter_with_options(STALL_TIMEOUT, Some("1s"), [("udp_over_stream", "true")]);
    let (connection, socket) = tokio::join!(peer.accept_auth(), adapter.connect_udp(target()));
    let mut socket = socket.unwrap();
    let (_send, _unread) = timeout(TEST_TIMEOUT, connection.accept_bi())
        .await
        .unwrap()
        .unwrap();
    let result = timeout(TEST_TIMEOUT, socket.send(&vec![0x61; 60_000]))
        .await
        .unwrap();
    assert!(matches!(result, Err(error) if error.to_string().contains("timed out")));
    timeout(Duration::from_secs(2), connection.closed())
        .await
        .expect("timed-out stream must release the session and heartbeat");
    assert!(socket.send(b"late").await.is_err());
}

#[tokio::test]
async fn dropping_udp_over_stream_closes_session_and_stops_heartbeat() {
    let peer = Peer::new(8);
    let adapter = peer.adapter_with_options(
        Duration::from_secs(2),
        Some("100ms"),
        [("udp_over_stream", "true")],
    );
    let (connection, socket) = tokio::join!(peer.accept_auth(), adapter.connect_udp(target()));
    let socket = socket.unwrap();
    let (_send, _recv) = timeout(TEST_TIMEOUT, connection.accept_bi())
        .await
        .unwrap()
        .unwrap();
    drop(socket);
    timeout(Duration::from_secs(2), connection.closed())
        .await
        .expect("dropping the UDP stream must release the session and heartbeat");
}

#[tokio::test]
async fn udp_over_stream_preserves_maximum_u16_datagram_without_truncation() {
    let peer = Peer::new(8);
    let adapter =
        peer.adapter_with_options(Duration::from_secs(3), None, [("udp_over_stream", "true")]);
    let (connection, socket) = tokio::join!(peer.accept_auth(), adapter.connect_udp(target()));
    let mut socket = socket.unwrap();
    let (mut send, mut recv) = timeout(TEST_TIMEOUT, connection.accept_bi())
        .await
        .unwrap()
        .unwrap();
    let server = async {
        let mut setup = vec![0; 4 + b"sp.v2.udp-over-tcp.arpa".len() + 2 + 8];
        recv.read_exact(&mut setup).await.unwrap();
        assert_eq!(recv.read_u16().await.unwrap(), u16::MAX);
        let mut packet = vec![0; u16::MAX as usize];
        recv.read_exact(&mut packet).await.unwrap();
        assert!(packet.iter().all(|byte| *byte == 0x5a));
        send.write_u16(u16::MAX).await.unwrap();
        send.write_all(&packet).await.unwrap();
    };
    let client = async {
        let packet = vec![0x5a; u16::MAX as usize];
        socket.send(&packet).await.unwrap();
        assert_eq!(socket.receive().await.unwrap(), packet);
        assert!(matches!(
            socket.send(&vec![0; u16::MAX as usize + 1]).await,
            Err(pathchord_transit::TransitError::Unsupported(_))
        ));
    };
    timeout(TEST_TIMEOUT, async { tokio::join!(server, client) })
        .await
        .unwrap();
    socket.close().await.unwrap();
}

#[tokio::test]
async fn udp_over_stream_close_finishes_a_cancelled_partial_send() {
    let peer = Peer::with_stream_window(8, Some(256));
    let adapter =
        peer.adapter_with_options(Duration::from_secs(3), None, [("udp_over_stream", "true")]);
    let (connection, socket) = tokio::join!(peer.accept_auth(), adapter.connect_udp(target()));
    let mut socket = socket.unwrap();
    let (_send, mut recv) = timeout(TEST_TIMEOUT, connection.accept_bi())
        .await
        .unwrap()
        .unwrap();
    let packet = vec![0x71; 60_000];
    assert!(
        timeout(Duration::from_millis(100), socket.send(&packet))
            .await
            .is_err()
    );
    let server = async {
        let mut setup = vec![0; 4 + b"sp.v2.udp-over-tcp.arpa".len() + 2 + 8];
        recv.read_exact(&mut setup).await.unwrap();
        assert_eq!(usize::from(recv.read_u16().await.unwrap()), packet.len());
        let mut received = vec![0; packet.len()];
        recv.read_exact(&mut received).await.unwrap();
        assert_eq!(received, packet);
        assert!(recv.read(&mut [0; 1]).await.unwrap().is_none());
    };
    let ((), result) = timeout(TEST_TIMEOUT, async { tokio::join!(server, socket.close()) })
        .await
        .unwrap();
    result.unwrap();
}

#[tokio::test]
async fn cancelling_udp_over_stream_setup_closes_its_quic_session() {
    let peer = Peer::new(0);
    let adapter = peer.adapter_with_options(
        Duration::from_secs(3),
        Some("100ms"),
        [("udp_over_stream", "true")],
    );
    let pending = tokio::spawn(async move { adapter.connect_udp(target()).await });
    let connection = peer.accept().await;
    tokio::task::yield_now().await;
    pending.abort();
    assert!(pending.await.unwrap_err().is_cancelled());
    timeout(Duration::from_secs(2), connection.closed())
        .await
        .expect("cancelled setup must drop its QUIC session");
}

#[tokio::test]
async fn udp_over_stream_rejects_a_truncated_packet_without_reusing_the_stream() {
    let peer = Peer::new(8);
    let adapter =
        peer.adapter_with_options(Duration::from_secs(2), None, [("udp_over_stream", "true")]);
    let (connection, socket) = tokio::join!(peer.accept_auth(), adapter.connect_udp(target()));
    let mut socket = socket.unwrap();
    let (mut send, _recv) = timeout(TEST_TIMEOUT, connection.accept_bi())
        .await
        .unwrap()
        .unwrap();
    send.write_all(&[0, 5, b'a', b'b']).await.unwrap();
    send.finish().unwrap();
    assert!(
        timeout(TEST_TIMEOUT, socket.receive())
            .await
            .unwrap()
            .is_err()
    );
    assert!(socket.receive().await.is_err());
    drop(socket);
    timeout(Duration::from_secs(2), connection.closed())
        .await
        .expect("broken stream must release its session");
}

fn target() -> ConnectRequest {
    ConnectRequest {
        destination: Endpoint {
            host: "127.0.0.1".into(),
            port: TARGET_PORT,
        },
    }
}

async fn connect_udp(
    peer: &Peer,
    heartbeat: Option<&str>,
) -> (quinn::Connection, pathchord_transit::BoxedTransitDatagram) {
    let adapter = peer.adapter(Duration::from_secs(2), heartbeat);
    let (connection, socket) = tokio::join!(peer.accept_auth(), adapter.connect_udp(target()));
    (connection, socket.unwrap())
}

async fn connect_tcp(
    peer: &Peer,
) -> (quinn::Connection, pathchord_transit::BoxedTransitConnection) {
    let adapter = peer.adapter(Duration::from_secs(2), None);
    let (connection, stream) = tokio::join!(peer.accept_auth(), adapter.connect(target()));
    (connection, stream.unwrap())
}

async fn read_udp_request(connection: &quinn::Connection) -> (u16, Vec<u8>) {
    let mut request = timeout(TEST_TIMEOUT, connection.accept_uni())
        .await
        .expect("UDP request stream timed out")
        .unwrap();
    let request = request.read_to_end(65_805).await.unwrap();
    decode_udp_request(&request)
}

fn decode_udp_request(request: &[u8]) -> (u16, Vec<u8>) {
    assert!(request.len() >= 17);
    assert_eq!(&request[..2], &[5, 2]);
    assert_eq!(&request[6..8], &[1, 0]);
    assert_eq!(&request[10..15], &[1, 127, 0, 0, 1]);
    assert_eq!(&request[15..17], &TARGET_PORT.to_be_bytes());
    let association = u16::from_be_bytes([request[2], request[3]]);
    let length = usize::from(u16::from_be_bytes([request[8], request[9]]));
    assert_eq!(request.len(), 17 + length);
    (association, request[17..].to_vec())
}

fn udp_response(association: u16, packet_id: u16, payload: &[u8]) -> Vec<u8> {
    let mut packet = vec![5, 2];
    packet.extend_from_slice(&association.to_be_bytes());
    packet.extend_from_slice(&packet_id.to_be_bytes());
    packet.extend_from_slice(&[1, 0]);
    packet.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    packet.extend_from_slice(&[1, 127, 0, 0, 1]);
    packet.extend_from_slice(&TARGET_PORT.to_be_bytes());
    packet.extend_from_slice(payload);
    packet
}

async fn send_udp_response(
    connection: &quinn::Connection,
    association: u16,
    packet_id: u16,
    payload: &[u8],
) {
    let mut stream = connection.open_uni().await.unwrap();
    stream
        .write_all(&udp_response(association, packet_id, payload))
        .await
        .unwrap();
    stream.finish().unwrap();
    assert!(
        timeout(TEST_TIMEOUT, stream.stopped())
            .await
            .expect("peer response acknowledgement timed out")
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn cancelled_udp_receive_resumes_a_partially_received_stream() {
    let peer = Peer::new(8);
    let (connection, mut socket) = connect_udp(&peer, None).await;
    socket.send(b"request").await.unwrap();
    let (association, request) = read_udp_request(&connection).await;
    assert_eq!(request, b"request");
    let packet = udp_response(association, 9, b"complete response");
    let mut response = connection.open_uni().await.unwrap();
    response.write_all(&packet[..7]).await.unwrap();
    assert!(
        timeout(Duration::from_millis(100), socket.receive())
            .await
            .is_err()
    );
    response.write_all(&packet[7..]).await.unwrap();
    response.finish().unwrap();
    assert_eq!(
        timeout(TEST_TIMEOUT, socket.receive())
            .await
            .unwrap()
            .unwrap(),
        b"complete response"
    );
    socket.close().await.unwrap();
}

#[tokio::test]
async fn cancelled_udp_send_finishes_before_the_next_packet() {
    let peer = Peer::with_stream_window(8, Some(256));
    let (connection, mut socket) = connect_udp(&peer, None).await;
    let large = vec![0x53; 60_000];
    assert!(
        timeout(Duration::from_millis(100), socket.send(&large))
            .await
            .is_err()
    );
    let mut first = timeout(TEST_TIMEOUT, connection.accept_uni())
        .await
        .unwrap()
        .unwrap();
    let server = async {
        let first = first.read_to_end(65_805).await.unwrap();
        let (association, payload) = decode_udp_request(&first);
        assert_eq!(payload, large);
        let (next_association, next) = read_udp_request(&connection).await;
        assert_eq!(next_association, association);
        assert_eq!(next, b"next packet");
    };
    let client = async {
        socket.send(b"next packet").await.unwrap();
    };
    timeout(TEST_TIMEOUT, async { tokio::join!(server, client) })
        .await
        .expect("resuming a cancelled send timed out");
    socket.close().await.unwrap();
}

#[tokio::test]
async fn stalled_udp_send_respects_timeout_and_closes_the_session() {
    let peer = Peer::with_stream_window(8, Some(256));
    let adapter = peer.adapter(STALL_TIMEOUT, None);
    let (connection, socket) = tokio::join!(peer.accept_auth(), adapter.connect_udp(target()));
    let mut socket = socket.unwrap();
    let payload = vec![0x61; 60_000];
    let (result, stalled_stream) = tokio::join!(
        timeout(TEST_TIMEOUT, socket.send(&payload)),
        connection.accept_uni()
    );
    let result = result.expect("UDP send exceeded the configured timeout");
    assert!(matches!(result, Err(error) if error.to_string().contains("timed out")));
    // Keeping the stream unread ensures the peer never grants further credit.
    let _stalled_stream = stalled_stream.unwrap();
    timeout(Duration::from_secs(2), connection.closed())
        .await
        .expect("timed-out UDP send left the session open");
}

#[tokio::test]
async fn queued_udp_stream_bytes_are_bounded_and_capacity_is_reclaimed() {
    let peer = Peer::new(8);
    let (connection, mut socket) = connect_udp(&peer, None).await;
    socket.send(b"request").await.unwrap();
    let (association, _) = read_udp_request(&connection).await;
    let large = vec![0x42; 60_000];
    // Four packets fit into the 256 KiB queue, but five do not. The count is
    // well below the queue's 64-item limit, so this exercises the byte budget.
    for id in 0..6 {
        send_udp_response(&connection, association, id, &large).await;
    }
    sleep(Duration::from_millis(200)).await;
    for _ in 0..4 {
        assert_eq!(
            timeout(TEST_TIMEOUT, socket.receive())
                .await
                .unwrap()
                .unwrap(),
            large
        );
    }
    assert!(
        timeout(Duration::from_millis(100), socket.receive())
            .await
            .is_err(),
        "responses exceeding the byte budget were not dropped"
    );
    send_udp_response(&connection, association, 7, &large).await;
    assert_eq!(
        timeout(TEST_TIMEOUT, socket.receive())
            .await
            .unwrap()
            .unwrap(),
        large,
        "consuming queued packets must release their byte budget"
    );

    // Close while unread packets remain, then prove a fresh association can
    // use its full budget and the old connection has actually terminated.
    for id in 8..12 {
        send_udp_response(&connection, association, id, &large).await;
    }
    drop(socket);
    timeout(Duration::from_secs(2), connection.closed())
        .await
        .expect("dropping a full queue left its session running");
    let (next_connection, mut next_socket) = connect_udp(&peer, None).await;
    next_socket.send(b"new association").await.unwrap();
    let (next_association, _) = read_udp_request(&next_connection).await;
    for id in 0..4 {
        send_udp_response(&next_connection, next_association, id, &large).await;
    }
    sleep(Duration::from_millis(100)).await;
    for _ in 0..4 {
        assert_eq!(
            timeout(TEST_TIMEOUT, next_socket.receive())
                .await
                .unwrap()
                .unwrap(),
            large
        );
    }
    next_socket.close().await.unwrap();
}

#[tokio::test]
async fn full_udp_stream_queue_drops_new_packets_and_recovers() {
    let peer = Peer::new(8);
    let (connection, mut socket) = connect_udp(&peer, None).await;
    socket.send(b"request").await.unwrap();
    let (association, _) = read_udp_request(&connection).await;
    // These packets are too small to exhaust the byte budget; the 64-entry
    // queue itself must shed the excess instead of blocking the reader.
    for id in 0..70 {
        send_udp_response(&connection, association, id, &[id as u8]).await;
    }
    sleep(Duration::from_millis(200)).await;
    for _ in 0..64 {
        assert_eq!(
            timeout(TEST_TIMEOUT, socket.receive())
                .await
                .unwrap()
                .unwrap()
                .len(),
            1
        );
    }
    assert!(
        timeout(Duration::from_millis(100), socket.receive())
            .await
            .is_err()
    );
    send_udp_response(&connection, association, 70, b"recovered").await;
    assert_eq!(
        timeout(TEST_TIMEOUT, socket.receive())
            .await
            .unwrap()
            .unwrap(),
        b"recovered"
    );
    socket.close().await.unwrap();
}

#[tokio::test]
async fn stalled_udp_stream_does_not_block_a_later_complete_packet() {
    let peer = Peer::new(8);
    let (connection, mut socket) = connect_udp(&peer, None).await;
    socket.send(b"request").await.unwrap();
    let (association, _) = read_udp_request(&connection).await;
    let first = udp_response(association, 1, b"stalled");
    let mut stalled = connection.open_uni().await.unwrap();
    stalled.write_all(&first[..7]).await.unwrap();
    assert!(
        timeout(Duration::from_millis(100), socket.receive())
            .await
            .is_err()
    );
    let mut complete = connection.open_uni().await.unwrap();
    complete
        .write_all(&udp_response(association, 2, b"second response"))
        .await
        .unwrap();
    complete.finish().unwrap();
    assert_eq!(
        timeout(Duration::from_secs(1), socket.receive())
            .await
            .expect("a stalled stream blocked a complete UDP packet")
            .unwrap(),
        b"second response"
    );
    stalled.write_all(&first[7..]).await.unwrap();
    stalled.finish().unwrap();
    assert_eq!(
        timeout(TEST_TIMEOUT, socket.receive())
            .await
            .unwrap()
            .unwrap(),
        b"stalled"
    );
    socket.close().await.unwrap();
}

#[tokio::test]
async fn tcp_half_close_allows_a_delayed_response() {
    let peer = Peer::new(8);
    let (connection, mut stream) = connect_tcp(&peer).await;
    let (mut response, mut request) = connection.accept_bi().await.unwrap();
    let payload: Vec<u8> = (0..131_317).map(|i| (i % 251) as u8).collect();
    let client = async {
        stream.write_all(&payload).await.unwrap();
        stream.shutdown().await.unwrap();
        stream.shutdown().await.unwrap();
        let mut body = Vec::new();
        stream.read_to_end(&mut body).await.unwrap();
        assert_eq!(body, b"response after FIN");
    };
    let server = async {
        let bytes = request.read_to_end(200_000).await.unwrap();
        assert_eq!(&bytes[..9], &[5, 1, 1, 127, 0, 0, 1, 0x14, 0xe9]);
        assert_eq!(&bytes[9..], payload);
        sleep(Duration::from_millis(100)).await;
        response.write_all(b"response after FIN").await.unwrap();
        response.finish().unwrap();
    };
    timeout(TEST_TIMEOUT, async { tokio::join!(server, client) })
        .await
        .expect("half-close exchange timed out");
}

#[tokio::test]
async fn shutdown_then_drop_preserves_queued_upload_and_fin() {
    let peer = Peer::new(8);
    let (connection, mut stream) = connect_tcp(&peer).await;
    let (_response, mut request) = connection.accept_bi().await.unwrap();
    let payload: Vec<u8> = (0..131_317).map(|i| (i % 239) as u8).collect();
    stream.write_all(&payload).await.unwrap();
    stream.shutdown().await.unwrap();
    drop(stream);
    // Delay the application read so close cannot appear correct merely
    // because the mock peer consumed the upload before the client dropped.
    sleep(Duration::from_millis(100)).await;
    let received = timeout(TEST_TIMEOUT, request.read_to_end(200_000))
        .await
        .expect("queued upload timed out")
        .expect("connection closed before queued upload and FIN arrived");
    assert_eq!(&received[..9], &[5, 1, 1, 127, 0, 0, 1, 0x14, 0xe9]);
    assert_eq!(&received[9..], payload);
}

#[tokio::test]
async fn dropping_a_short_tcp_flow_closes_its_session() {
    let peer = Peer::new(8);
    let (connection, stream) = connect_tcp(&peer).await;
    let (_send, mut recv) = connection.accept_bi().await.unwrap();
    let mut command = [0; 9];
    recv.read_exact(&mut command).await.unwrap();
    assert_eq!(&command[..2], &[5, 1]);
    drop(stream);
    timeout(Duration::from_secs(2), connection.closed())
        .await
        .expect("dropped TCP flow left its QUIC session open");
}

#[tokio::test]
async fn configured_heartbeat_uses_datagrams_and_keeps_the_session_usable() {
    let peer = Peer::new(8);
    let (connection, mut socket) = connect_udp(&peer, Some("20ms")).await;
    for _ in 0..3 {
        let heartbeat = timeout(TEST_TIMEOUT, connection.read_datagram())
            .await
            .expect("heartbeat timed out")
            .unwrap();
        assert_eq!(heartbeat.as_ref(), &[5, 4]);
    }
    socket.send(b"after-heartbeats").await.unwrap();
    let (association, data) = read_udp_request(&connection).await;
    assert_eq!(data, b"after-heartbeats");
    let mut response = connection.open_uni().await.unwrap();
    response
        .write_all(&udp_response(association, 1, b"still connected"))
        .await
        .unwrap();
    response.finish().unwrap();
    assert_eq!(
        timeout(TEST_TIMEOUT, socket.receive())
            .await
            .unwrap()
            .unwrap(),
        b"still connected"
    );
    socket.close().await.unwrap();
}

#[tokio::test]
async fn dropping_udp_with_heartbeat_stops_the_quic_session() {
    let peer = Peer::new(8);
    let (connection, socket) = connect_udp(&peer, Some("20ms")).await;
    let heartbeat = timeout(TEST_TIMEOUT, connection.read_datagram())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(heartbeat.as_ref(), &[5, 4]);
    drop(socket);
    timeout(Duration::from_secs(2), connection.closed())
        .await
        .expect("dropped UDP flow left heartbeat and QUIC session running");
}

#[tokio::test]
async fn explicit_udp_close_sends_dissociate_before_session_shutdown() {
    let peer = Peer::new(8);
    let (connection, mut socket) = connect_udp(&peer, None).await;
    socket.send(b"request").await.unwrap();
    let (association, _) = read_udp_request(&connection).await;
    let server = async {
        let mut command = connection.accept_uni().await.unwrap();
        let command = command.read_to_end(4).await.unwrap();
        let mut expected = vec![5, 3];
        expected.extend_from_slice(&association.to_be_bytes());
        assert_eq!(command, expected);
    };
    let close = socket.close();
    let ((), result) = timeout(TEST_TIMEOUT, async { tokio::join!(server, close) })
        .await
        .expect("TUIC dissociate timed out");
    result.unwrap();
    timeout(Duration::from_secs(2), connection.closed())
        .await
        .expect("closed UDP session remained open");
}

#[tokio::test]
async fn auth_stream_credit_exhaustion_respects_connect_timeout() {
    let peer = Peer::new(0);
    let adapter = peer.adapter(STALL_TIMEOUT, None);
    let (connection, result) = tokio::join!(peer.accept(), async {
        timeout(TEST_TIMEOUT, adapter.connect_udp(target())).await
    });
    assert!(result.expect("TUIC connect exceeded its timeout").is_err());
    timeout(Duration::from_secs(2), connection.closed())
        .await
        .expect("timed-out connection remained open");
}
