//! The single-destination XUDP session carried inside a VLESS or VMess MUX stream.
//!
//! XUDP uses MUX datagram frames even when the caller has only one destination.
//! The VLESS MUX request and any Vision framing are established by the caller.

use std::net::IpAddr;

use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::{
    BoxedTransitConnection, BoxedTransitDatagram, Endpoint, TransitDatagram, TransitError,
    validate_destination,
};

const STATUS_NEW: u8 = 1;
const STATUS_KEEP: u8 = 2;
const STATUS_END: u8 = 3;
const STATUS_KEEP_ALIVE: u8 = 4;
const OPTION_DATA: u8 = 1;
const OPTION_ERROR: u8 = 2;
const NETWORK_UDP: u8 = 2;
// Xray's MUX metadata decoder imposes this bound. It also leaves room for the
// maximum encoded address and optional metadata padding.
const MAX_METADATA_LENGTH: usize = 512;
// Xray's MUX packet reader rejects larger datagrams.
const MAX_DATAGRAM_LENGTH: usize = 8192;

pub(crate) fn xudp_datagram(
    stream: BoxedTransitConnection,
    destination: Endpoint,
) -> Result<BoxedTransitDatagram, TransitError> {
    validate_destination(&destination)?;
    let mut address = Vec::new();
    address.extend_from_slice(&destination.port.to_be_bytes());
    match destination.host.parse::<IpAddr>() {
        Ok(IpAddr::V4(ip)) => {
            address.push(1);
            address.extend_from_slice(&ip.octets());
        }
        Ok(IpAddr::V6(ip)) => {
            address.push(3);
            address.extend_from_slice(&ip.octets());
        }
        Err(_) => {
            address.push(2);
            // validate_destination ensures that the UTF-8 byte length is 1..=255.
            address.push(destination.host.len() as u8);
            address.extend_from_slice(destination.host.as_bytes());
        }
    }
    Ok(Box::new(XudpDatagram {
        stream,
        destination,
        address,
        started: false,
        write_interrupted: false,
        ended: false,
        received: Vec::new(),
    }))
}

struct XudpDatagram {
    stream: BoxedTransitConnection,
    destination: Endpoint,
    address: Vec<u8>,
    started: bool,
    // A partially written frame cannot be retried safely. This flag also
    // remains set if an in-flight send future is cancelled.
    write_interrupted: bool,
    ended: bool,
    // Keep bytes on the object rather than in receive's future: callers may
    // cancel receive while a frame is still arriving.
    received: Vec<u8>,
}

impl std::fmt::Debug for XudpDatagram {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("XudpDatagram(..)")
    }
}

fn protocol(message: &str) -> TransitError {
    TransitError::Protocol(message.to_owned())
}

fn closed() -> TransitError {
    TransitError::Connection("XUDP session closed".to_owned())
}

#[async_trait]
impl TransitDatagram for XudpDatagram {
    async fn send(&mut self, payload: &[u8]) -> Result<(), TransitError> {
        if self.ended || self.write_interrupted {
            return Err(closed());
        }
        if payload.len() > MAX_DATAGRAM_LENGTH {
            return Err(TransitError::Unsupported(
                "UDP packet exceeds the interoperable XUDP limit of 8192 bytes".to_owned(),
            ));
        }
        let payload_length = payload.len() as u16;
        let metadata_length = if self.started {
            4
        } else {
            5 + self.address.len()
        };
        let mut frame = Vec::with_capacity(2 + metadata_length + 2 + payload.len());
        frame.extend_from_slice(&(metadata_length as u16).to_be_bytes());
        frame.extend_from_slice(&[0, 0]); // Single MUX session ID.
        frame.push(if self.started {
            STATUS_KEEP
        } else {
            STATUS_NEW
        });
        frame.push(OPTION_DATA);
        if !self.started {
            frame.push(NETWORK_UDP);
            frame.extend_from_slice(&self.address);
        }
        frame.extend_from_slice(&payload_length.to_be_bytes());
        frame.extend_from_slice(payload);

        self.write_interrupted = true;
        self.stream
            .write_all(&frame)
            .await
            .map_err(|_| protocol("XUDP frame write failed"))?;
        self.stream
            .flush()
            .await
            .map_err(|_| protocol("XUDP frame flush failed"))?;
        self.started = true;
        self.write_interrupted = false;
        Ok(())
    }

    async fn receive(&mut self) -> Result<Vec<u8>, TransitError> {
        if self.ended {
            return Err(closed());
        }
        loop {
            if let Some((length, action)) = parse_frame(&self.received, &self.destination)? {
                self.received.drain(..length);
                match action {
                    FrameAction::Packet(packet) => return Ok(packet),
                    FrameAction::Skip => continue,
                    FrameAction::End => {
                        self.ended = true;
                        return Err(closed());
                    }
                }
            }
            let mut chunk = [0_u8; 8192];
            let size = self
                .stream
                .read(&mut chunk)
                .await
                .map_err(|_| protocol("XUDP frame read failed"))?;
            if size == 0 {
                self.ended = true;
                return if self.received.is_empty() {
                    Err(closed())
                } else {
                    Err(protocol("XUDP frame is truncated"))
                };
            }
            self.received.extend_from_slice(&chunk[..size]);
        }
    }

    async fn close(mut self: Box<Self>) -> Result<(), TransitError> {
        if self.started && !self.ended && !self.write_interrupted {
            self.stream
                .write_all(&[0, 4, 0, 0, STATUS_END, 0])
                .await
                .map_err(|_| protocol("XUDP session close failed"))?;
            self.stream
                .flush()
                .await
                .map_err(|_| protocol("XUDP session close failed"))?;
        }
        self.stream
            .shutdown()
            .await
            .map_err(|_| protocol("XUDP shutdown failed"))
    }
}

enum FrameAction {
    Packet(Vec<u8>),
    Skip,
    End,
}

/// Decode only complete frames, so cancelling an in-flight read is safe.
fn parse_frame(
    bytes: &[u8],
    destination: &Endpoint,
) -> Result<Option<(usize, FrameAction)>, TransitError> {
    if bytes.len() < 2 {
        return Ok(None);
    }
    let metadata_length = usize::from(u16::from_be_bytes([bytes[0], bytes[1]]));
    if !(4..=MAX_METADATA_LENGTH).contains(&metadata_length) {
        return Err(protocol("invalid XUDP metadata length"));
    }
    let metadata_end = 2 + metadata_length;
    if bytes.len() < metadata_end {
        return Ok(None);
    }
    let metadata = &bytes[2..metadata_end];
    if metadata[..2] != [0, 0] {
        return Err(protocol("unexpected XUDP session ID"));
    }
    let status = metadata[2];
    let options = metadata[3];
    if options & !(OPTION_DATA | OPTION_ERROR) != 0 {
        return Err(protocol("invalid XUDP frame options"));
    }
    if options & OPTION_ERROR != 0 {
        return Err(protocol("remote XUDP session failed"));
    }
    match status {
        STATUS_KEEP => validate_reply_address(&metadata[4..], destination)?,
        STATUS_END => return Ok(Some((metadata_end, FrameAction::End))),
        STATUS_KEEP_ALIVE => {}
        _ => return Err(protocol("unexpected XUDP frame status")),
    }

    if options & OPTION_DATA == 0 {
        return Ok(Some((metadata_end, FrameAction::Skip)));
    }
    if bytes.len() < metadata_end + 2 {
        return Ok(None);
    }
    let data_length = usize::from(u16::from_be_bytes([
        bytes[metadata_end],
        bytes[metadata_end + 1],
    ]));
    if data_length > MAX_DATAGRAM_LENGTH {
        return Err(protocol(
            "XUDP reply packet exceeds the interoperable limit",
        ));
    }
    let frame_end = metadata_end + 2 + data_length;
    if bytes.len() < frame_end {
        return Ok(None);
    }
    let action = if status == STATUS_KEEP_ALIVE {
        FrameAction::Skip
    } else {
        FrameAction::Packet(bytes[metadata_end + 2..frame_end].to_vec())
    };
    Ok(Some((frame_end, action)))
}

fn validate_reply_address(metadata: &[u8], destination: &Endpoint) -> Result<(), TransitError> {
    // Xray checks the UDP network flag before parsing an address; other bytes
    // here are padding rather than an address.
    if metadata.first() != Some(&NETWORK_UDP) {
        return Ok(());
    }
    if metadata.len() < 4 {
        return Err(protocol("truncated XUDP reply address"));
    }
    let address_length = match metadata[3] {
        1 => 4,
        3 => 16,
        2 => {
            let Some(&length) = metadata.get(4) else {
                return Err(protocol("truncated XUDP reply address"));
            };
            if length == 0 {
                return Err(protocol("invalid XUDP reply address"));
            }
            1 + usize::from(length)
        }
        _ => return Err(protocol("invalid XUDP reply address type")),
    };
    if metadata.len() < 4 + address_length {
        return Err(protocol("truncated XUDP reply address"));
    }
    let port = u16::from_be_bytes([metadata[1], metadata[2]]);
    if port != destination.port {
        return Err(protocol(
            "XUDP reply address differs from the bound destination",
        ));
    }
    match metadata[3] {
        1 => {
            let ip = IpAddr::V4(std::net::Ipv4Addr::new(
                metadata[4],
                metadata[5],
                metadata[6],
                metadata[7],
            ));
            if destination
                .host
                .parse::<IpAddr>()
                .is_ok_and(|expected| expected != ip)
            {
                return Err(protocol(
                    "XUDP reply address differs from the bound destination",
                ));
            }
        }
        3 => {
            let ip = IpAddr::V6(std::net::Ipv6Addr::from(
                <[u8; 16]>::try_from(&metadata[4..20]).expect("length checked"),
            ));
            if destination
                .host
                .parse::<IpAddr>()
                .is_ok_and(|expected| expected != ip)
            {
                return Err(protocol(
                    "XUDP reply address differs from the bound destination",
                ));
            }
        }
        2 => {
            let host = std::str::from_utf8(&metadata[5..5 + usize::from(metadata[4])])
                .map_err(|_| protocol("invalid XUDP reply address"))?;
            if !host.eq_ignore_ascii_case(&destination.host) {
                return Err(protocol(
                    "XUDP reply address differs from the bound destination",
                ));
            }
        }
        _ => unreachable!("address type checked"),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{
        future::Future,
        pin::{Pin, pin},
        task::{Context, Poll, Waker},
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream, duplex};

    use super::*;

    fn poll_once<F: Future + ?Sized>(future: Pin<&mut F>) -> Poll<F::Output> {
        future.poll(&mut Context::from_waker(Waker::noop()))
    }

    fn connection(host: &str, port: u16) -> (BoxedTransitDatagram, DuplexStream) {
        let (client, server) = duplex(131_072);
        let datagram = xudp_datagram(
            Box::new(client),
            Endpoint {
                host: host.to_owned(),
                port,
            },
        )
        .expect("valid destination");
        (datagram, server)
    }

    fn frame(status: u8, options: u8, extra: &[u8], payload: Option<&[u8]>) -> Vec<u8> {
        let mut frame = Vec::new();
        frame.extend_from_slice(&((4 + extra.len()) as u16).to_be_bytes());
        frame.extend_from_slice(&[0, 0, status, options]);
        frame.extend_from_slice(extra);
        if let Some(payload) = payload {
            frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
            frame.extend_from_slice(payload);
        }
        frame
    }

    #[tokio::test]
    async fn writes_new_address_then_keep_for_each_address_family() {
        let examples: [(&str, u16, &[u8]); 3] = [
            ("192.0.2.1", 53, &[0, 53, 1, 192, 0, 2, 1]),
            (
                "2001:db8::1",
                443,
                &[
                    1, 187, 3, 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
                ],
            ),
            (
                "example.org",
                123,
                &[
                    0, 123, 2, 11, b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b'o', b'r', b'g',
                ],
            ),
        ];
        for (host, port, address) in examples {
            let (mut datagram, mut peer) = connection(host, port);
            datagram.send(b"one").await.unwrap();
            let mut extra = vec![NETWORK_UDP];
            extra.extend_from_slice(address);
            let expected = frame(STATUS_NEW, OPTION_DATA, &extra, Some(b"one"));
            let mut actual = vec![0; expected.len()];
            peer.read_exact(&mut actual).await.unwrap();
            assert_eq!(actual, expected, "{host}");

            datagram.send(b"two").await.unwrap();
            let expected = frame(STATUS_KEEP, OPTION_DATA, &[], Some(b"two"));
            let mut actual = vec![0; expected.len()];
            peer.read_exact(&mut actual).await.unwrap();
            assert_eq!(actual, expected, "{host}");
        }
    }

    #[tokio::test]
    async fn reads_multiple_packets_control_frames_and_optional_reply_addresses() {
        let (mut datagram, mut peer) = connection("example.org", 53);
        let mut reply = frame(STATUS_KEEP_ALIVE, OPTION_DATA, &[], Some(b"ignored"));
        reply.extend(frame(STATUS_KEEP, 0, &[0, 0], None));
        reply.extend(frame(STATUS_KEEP, OPTION_DATA, &[], Some(b"first")));
        reply.extend(frame(
            STATUS_KEEP,
            OPTION_DATA,
            &[NETWORK_UDP, 0, 53, 1, 192, 0, 2, 1, 0, 0],
            Some(b"second"),
        ));
        reply.extend(frame(
            STATUS_KEEP,
            OPTION_DATA,
            &[
                NETWORK_UDP,
                0,
                53,
                2,
                11,
                b'e',
                b'x',
                b'a',
                b'm',
                b'p',
                b'l',
                b'e',
                b'.',
                b'o',
                b'r',
                b'g',
            ],
            Some(b""),
        ));
        reply.extend(frame(
            STATUS_KEEP,
            OPTION_DATA,
            &[
                NETWORK_UDP,
                0,
                53,
                3,
                0x20,
                0x01,
                0x0d,
                0xb8,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                1,
            ],
            Some(b"ipv6"),
        ));
        peer.write_all(&reply).await.unwrap();
        assert_eq!(datagram.receive().await.unwrap(), b"first");
        assert_eq!(datagram.receive().await.unwrap(), b"second");
        assert_eq!(datagram.receive().await.unwrap(), b"");
        assert_eq!(datagram.receive().await.unwrap(), b"ipv6");
    }

    #[tokio::test]
    async fn rejects_explicit_reply_addresses_for_another_destination() {
        for address in [
            vec![NETWORK_UDP, 0, 54, 1, 192, 0, 2, 1],
            vec![NETWORK_UDP, 0, 53, 1, 192, 0, 2, 2],
            vec![NETWORK_UDP, 0, 53, 2, 3, b'b', b'a', b'd'],
        ] {
            let (mut datagram, mut peer) = connection("192.0.2.1", 53);
            peer.write_all(&frame(STATUS_KEEP, OPTION_DATA, &address, Some(b"ignored")))
                .await
                .unwrap();
            assert!(
                matches!(datagram.receive().await, Err(TransitError::Protocol(reason)) if reason.contains("differs"))
            );
        }
    }

    #[tokio::test]
    async fn keeps_a_partial_frame_when_receive_is_cancelled() {
        let (mut datagram, mut peer) = connection("example.org", 53);
        let reply = frame(STATUS_KEEP, OPTION_DATA, &[], Some(b"reply"));
        for split in [1, 3, 6, reply.len() - 1] {
            // Deliver another fragment and cancel while the rest is unavailable.
            let start = match split {
                1 => 0,
                3 => 1,
                6 => 3,
                _ => 6,
            };
            peer.write_all(&reply[start..split]).await.unwrap();
            let mut pending = pin!(datagram.receive());
            assert!(matches!(poll_once(pending.as_mut()), Poll::Pending));
        }
        peer.write_all(&reply[reply.len() - 1..]).await.unwrap();
        assert_eq!(datagram.receive().await.unwrap(), b"reply");
    }

    #[tokio::test]
    async fn closes_a_started_session_with_an_end_frame() {
        let (mut datagram, mut peer) = connection("192.0.2.1", 53);
        datagram.send(b"x").await.unwrap();
        let mut request = [0; 17];
        peer.read_exact(&mut request).await.unwrap();
        datagram.close().await.unwrap();
        let mut end = Vec::new();
        peer.read_to_end(&mut end).await.unwrap();
        assert_eq!(end, [0, 4, 0, 0, STATUS_END, 0]);

        let (datagram, mut peer) = connection("192.0.2.1", 53);
        datagram.close().await.unwrap();
        let mut no_frame = Vec::new();
        peer.read_to_end(&mut no_frame).await.unwrap();
        assert!(no_frame.is_empty());
    }

    #[tokio::test]
    async fn end_and_truncated_frames_fail_explicitly() {
        let (mut datagram, mut peer) = connection("example.org", 53);
        peer.write_all(&frame(STATUS_END, 0, &[], None))
            .await
            .unwrap();
        assert!(matches!(
            datagram.receive().await,
            Err(TransitError::Connection(_))
        ));
        assert!(matches!(
            datagram.receive().await,
            Err(TransitError::Connection(_))
        ));

        let (mut datagram, mut peer) = connection("example.org", 53);
        peer.write_all(&[0, 4, 0]).await.unwrap();
        peer.shutdown().await.unwrap();
        assert!(matches!(
            datagram.receive().await,
            Err(TransitError::Protocol(_))
        ));
    }

    #[test]
    fn rejects_invalid_metadata_options_and_reply_addresses() {
        let cases: &[&[u8]] = &[
            &[0, 3],                                                   // Too short.
            &[2, 1],                                                   // More than 512 bytes.
            &[0, 4, 0, 1, STATUS_KEEP, 0],                             // Wrong session.
            &[0, 4, 0, 0, STATUS_NEW, 0],                              // Unexpected server New.
            &[0, 4, 0, 0, STATUS_KEEP, 0x80],                          // Unknown option.
            &[0, 4, 0, 0, STATUS_END, OPTION_ERROR],                   // Remote failure.
            &[0, 5, 0, 0, STATUS_KEEP, 0, NETWORK_UDP],                // Truncated address.
            &[0, 8, 0, 0, STATUS_KEEP, 0, NETWORK_UDP, 0, 53, 9],      // Unknown type.
            &[0, 9, 0, 0, STATUS_KEEP, 0, NETWORK_UDP, 0, 53, 2, 0],   // Empty domain.
            &[0, 9, 0, 0, STATUS_KEEP, 0, NETWORK_UDP, 0, 53, 1, 192], // Short IPv4.
            &[0, 4, 0, 0, STATUS_KEEP, OPTION_DATA, 0x20, 0x01],       // Oversized payload.
        ];
        for bytes in cases {
            assert!(
                matches!(
                    parse_frame(
                        bytes,
                        &Endpoint {
                            host: "example.org".into(),
                            port: 53
                        }
                    ),
                    Err(TransitError::Protocol(_))
                ),
                "{bytes:?}"
            );
        }
    }

    #[tokio::test]
    async fn rejects_oversize_and_does_not_retry_a_cancelled_write() {
        let (mut datagram, _peer) = connection("example.org", 53);
        assert!(matches!(
            datagram.send(&vec![0; MAX_DATAGRAM_LENGTH + 1]).await,
            Err(TransitError::Unsupported(_))
        ));

        let (client, _peer) = duplex(4);
        let mut datagram = xudp_datagram(
            Box::new(client),
            Endpoint {
                host: "example.org".to_owned(),
                port: 53,
            },
        )
        .unwrap();
        {
            let mut pending = pin!(datagram.send(b"first"));
            assert!(matches!(poll_once(pending.as_mut()), Poll::Pending));
        }
        assert!(matches!(
            datagram.send(b"retry").await,
            Err(TransitError::Connection(_))
        ));
    }
}
