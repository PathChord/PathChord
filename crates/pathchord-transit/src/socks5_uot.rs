//! sing-box UDP-over-TCP framing carried inside an authenticated SOCKS tunnel.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::{
    BoxedTransitConnection, BoxedTransitDatagram, Endpoint, TransitDatagram, TransitError,
    validate_destination,
};

pub(crate) fn request_host(version: u8) -> &'static str {
    match version {
        1 => "sp.udp-over-tcp.arpa",
        2 => "sp.v2.udp-over-tcp.arpa",
        _ => unreachable!("version is checked by the adapter constructor"),
    }
}

pub(crate) struct UotDatagram {
    stream: BoxedTransitConnection,
    destination: Endpoint,
    legacy_header: Option<Vec<u8>>,
    received: Vec<u8>,
    pending_write: Vec<u8>,
    written: usize,
    failed: bool,
}

impl std::fmt::Debug for UotDatagram {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("UotDatagram(..)")
    }
}

impl UotDatagram {
    pub(crate) async fn connect(
        mut stream: BoxedTransitConnection,
        destination: Endpoint,
        version: u8,
    ) -> Result<BoxedTransitDatagram, TransitError> {
        validate_destination(&destination)?;
        let legacy_header = match version {
            1 => Some(encode_address(&destination, true)?),
            2 => {
                let mut request = vec![1]; // connected association
                request.extend_from_slice(&encode_address(&destination, false)?);
                stream.write_all(&request).await.map_err(|_| {
                    TransitError::Connection("UDP-over-TCP request write failed".into())
                })?;
                stream.flush().await.map_err(|_| {
                    TransitError::Connection("UDP-over-TCP request flush failed".into())
                })?;
                None
            }
            _ => {
                return Err(TransitError::Unsupported(
                    "invalid UDP-over-TCP version".into(),
                ));
            }
        };
        Ok(Box::new(Self {
            stream,
            destination,
            legacy_header,
            received: Vec::new(),
            pending_write: Vec::new(),
            written: 0,
            failed: false,
        }))
    }

    async fn read_until(&mut self, length: usize) -> Result<(), TransitError> {
        while self.received.len() < length {
            let mut buffer = [0_u8; 4096];
            let remaining = (length - self.received.len()).min(buffer.len());
            let read = match self.stream.read(&mut buffer[..remaining]).await {
                Ok(read) => read,
                Err(_) => {
                    self.failed = true;
                    return Err(TransitError::Connection("UDP-over-TCP read failed".into()));
                }
            };
            if read == 0 {
                self.failed = true;
                return Err(TransitError::Protocol(
                    "UDP-over-TCP frame is truncated".into(),
                ));
            }
            self.received.extend_from_slice(&buffer[..read]);
        }
        Ok(())
    }

    async fn flush_pending(&mut self) -> Result<(), TransitError> {
        while self.written < self.pending_write.len() {
            let result = self.stream.write(&self.pending_write[self.written..]).await;
            match result {
                Ok(0) | Err(_) => {
                    self.failed = true;
                    return Err(TransitError::Connection("UDP-over-TCP write failed".into()));
                }
                Ok(written) => self.written += written,
            }
        }
        if !self.pending_write.is_empty() {
            self.stream.flush().await.map_err(|_| {
                self.failed = true;
                TransitError::Connection("UDP-over-TCP flush failed".into())
            })?;
            self.pending_write.clear();
            self.written = 0;
        }
        Ok(())
    }
}

#[async_trait]
impl TransitDatagram for UotDatagram {
    async fn send(&mut self, payload: &[u8]) -> Result<(), TransitError> {
        if self.failed {
            return Err(TransitError::Connection(
                "UDP-over-TCP stream is closed".into(),
            ));
        }
        if payload.len() > u16::MAX as usize {
            return Err(TransitError::Unsupported(
                "UDP-over-TCP payload exceeds u16 length".into(),
            ));
        }
        // Complete a cancelled prior write before writing a new frame.
        self.flush_pending().await?;
        if let Some(header) = &self.legacy_header {
            self.pending_write.extend_from_slice(header);
        }
        self.pending_write
            .extend_from_slice(&(payload.len() as u16).to_be_bytes());
        self.pending_write.extend_from_slice(payload);
        self.flush_pending().await
    }

    async fn receive(&mut self) -> Result<Vec<u8>, TransitError> {
        if self.failed {
            return Err(TransitError::Connection(
                "UDP-over-TCP stream is closed".into(),
            ));
        }
        let address_len = if self.legacy_header.is_some() {
            self.read_until(1).await?;
            let length = match self.received[0] {
                0 => 1 + 4 + 2,
                1 => 1 + 16 + 2,
                2 => {
                    self.read_until(2).await?;
                    if self.received[1] == 0 {
                        self.failed = true;
                        return Err(TransitError::Protocol(
                            "UDP-over-TCP source hostname is empty".into(),
                        ));
                    }
                    2 + usize::from(self.received[1]) + 2
                }
                _ => {
                    self.failed = true;
                    return Err(TransitError::Protocol(
                        "UDP-over-TCP source address is invalid".into(),
                    ));
                }
            };
            self.read_until(length).await?;
            let source = match decode_legacy_address(&self.received[..length]) {
                Ok(source) => source,
                Err(error) => {
                    self.failed = true;
                    return Err(error);
                }
            };
            if !matches_destination(&self.destination, &source) {
                self.failed = true;
                return Err(TransitError::Protocol(
                    "UDP-over-TCP source does not match its target".into(),
                ));
            }
            length
        } else {
            0
        };
        self.read_until(address_len + 2).await?;
        let length =
            u16::from_be_bytes([self.received[address_len], self.received[address_len + 1]])
                as usize;
        let total = address_len + 2 + length;
        self.read_until(total).await?;
        let payload = self.received[address_len + 2..total].to_vec();
        self.received.drain(..total);
        Ok(payload)
    }

    async fn close(mut self: Box<Self>) -> Result<(), TransitError> {
        self.flush_pending().await?;
        self.stream
            .shutdown()
            .await
            .map_err(|_| TransitError::Connection("UDP-over-TCP shutdown failed".into()))
    }
}

fn encode_address(endpoint: &Endpoint, legacy: bool) -> Result<Vec<u8>, TransitError> {
    validate_destination(endpoint)?;
    let mut output = Vec::new();
    match endpoint.host.parse::<IpAddr>() {
        Ok(IpAddr::V4(address)) => {
            output.push(if legacy { 0 } else { 1 });
            output.extend_from_slice(&address.octets());
        }
        Ok(IpAddr::V6(address)) => {
            output.push(if legacy { 1 } else { 4 });
            output.extend_from_slice(&address.octets());
        }
        Err(_) => {
            output.push(if legacy { 2 } else { 3 });
            output.push(endpoint.host.len() as u8);
            output.extend_from_slice(endpoint.host.as_bytes());
        }
    }
    output.extend_from_slice(&endpoint.port.to_be_bytes());
    Ok(output)
}

fn decode_legacy_address(input: &[u8]) -> Result<Endpoint, TransitError> {
    let (host, offset) = match input[0] {
        0 => (
            Ipv4Addr::new(input[1], input[2], input[3], input[4]).to_string(),
            5,
        ),
        1 => (
            Ipv6Addr::from(<[u8; 16]>::try_from(&input[1..17]).expect("bounded IPv6 address"))
                .to_string(),
            17,
        ),
        2 => {
            let offset = 2 + usize::from(input[1]);
            let host = std::str::from_utf8(&input[2..offset]).map_err(|_| {
                TransitError::Protocol("UDP-over-TCP source hostname is invalid".into())
            })?;
            (host.to_owned(), offset)
        }
        _ => {
            return Err(TransitError::Protocol(
                "UDP-over-TCP source address is invalid".into(),
            ));
        }
    };
    let endpoint = Endpoint {
        host,
        port: u16::from_be_bytes([input[offset], input[offset + 1]]),
    };
    validate_destination(&endpoint)
        .map_err(|_| TransitError::Protocol("UDP-over-TCP source endpoint is invalid".into()))?;
    Ok(endpoint)
}

fn matches_destination(expected: &Endpoint, received: &Endpoint) -> bool {
    expected.port == received.port
        && match expected.host.parse::<IpAddr>() {
            Ok(expected) => received.host.parse::<IpAddr>() == Ok(expected),
            Err(_) => {
                received.host.parse::<IpAddr>().is_ok()
                    || received.host.eq_ignore_ascii_case(&expected.host)
            }
        }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn both_versions_frame_datagrams_and_preserve_partial_reads() {
        for version in [1, 2] {
            let (client, mut peer) = tokio::io::duplex(1024);
            let destination = Endpoint {
                host: "127.0.0.1".into(),
                port: 5353,
            };
            let mut datagram = UotDatagram::connect(Box::new(client), destination, version)
                .await
                .unwrap();
            if version == 2 {
                let mut request = [0; 8];
                peer.read_exact(&mut request).await.unwrap();
                assert_eq!(request, [1, 1, 127, 0, 0, 1, 0x14, 0xe9]);
            }
            datagram.send(b"query").await.unwrap();
            if version == 1 {
                let mut address = [0; 7];
                peer.read_exact(&mut address).await.unwrap();
                assert_eq!(address, [0, 127, 0, 0, 1, 0x14, 0xe9]);
            }
            let mut frame = [0; 7];
            peer.read_exact(&mut frame).await.unwrap();
            assert_eq!(&frame, b"\0\x05query");
            if version == 1 {
                peer.write_all(&[0, 127, 0, 0, 1, 0x14, 0xe9])
                    .await
                    .unwrap();
            }
            peer.write_all(&[0]).await.unwrap();
            assert!(
                tokio::time::timeout(Duration::from_millis(10), datagram.receive())
                    .await
                    .is_err()
            );
            peer.write_all(b"\x05reply").await.unwrap();
            assert_eq!(datagram.receive().await.unwrap(), b"reply");
            assert!(datagram.send(&vec![0; 65_536]).await.is_err());
        }
    }

    #[tokio::test]
    async fn cancelled_partial_write_finishes_before_the_next_datagram() {
        let (client, mut peer) = tokio::io::duplex(2);
        let destination = Endpoint {
            host: "127.0.0.1".into(),
            port: 53,
        };
        let mut datagram = UotDatagram::connect(Box::new(client), destination, 1)
            .await
            .unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(10), datagram.send(b"first"))
                .await
                .is_err()
        );
        let reader = tokio::spawn(async move {
            let mut bytes = vec![0; 2 * 7 + 2 * 2 + 5 + 4];
            peer.read_exact(&mut bytes).await.unwrap();
            bytes
        });
        datagram.send(b"next").await.unwrap();
        let bytes = reader.await.unwrap();
        assert_eq!(
            &bytes[..14],
            &[0, 127, 0, 0, 1, 0, 53, 0, 5, b'f', b'i', b'r', b's', b't']
        );
        assert_eq!(
            &bytes[14..],
            &[0, 127, 0, 0, 1, 0, 53, 0, 4, b'n', b'e', b'x', b't']
        );
    }

    #[tokio::test]
    async fn legacy_rejects_malformed_or_unexpected_source() {
        for frame in [vec![9], vec![0, 127, 0, 0, 2, 0, 53]] {
            let (client, mut peer) = tokio::io::duplex(1024);
            let destination = Endpoint {
                host: "127.0.0.1".into(),
                port: 53,
            };
            let mut datagram = UotDatagram::connect(Box::new(client), destination, 1)
                .await
                .unwrap();
            peer.write_all(&frame).await.unwrap();
            assert!(matches!(
                datagram.receive().await,
                Err(TransitError::Protocol(_))
            ));
        }
    }
}
