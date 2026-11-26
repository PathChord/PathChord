//! Rust-native VLESS and Trojan wire adapters over maintained TLS/WS transports.

use std::net::IpAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use async_trait::async_trait;
use rustls::ClientConfig;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::time::timeout;
use zeroize::{Zeroize, Zeroizing};

use crate::{
    AdapterKind, BoxedTransitConnection, BoxedTransitDatagram, ConnectRequest, Endpoint,
    TransitAdapter, TransitCredential, TransitDatagram, TransitError, TransitMetadata,
};

#[path = "trojan_go_encryption.rs"]
mod trojan_go_encryption;

#[derive(Clone, Copy)]
enum Protocol {
    Vless,
    Trojan,
}

enum Authentication {
    Vless(Zeroizing<[u8; 16]>, Option<crate::vision::VisionFlow>),
    Trojan(Zeroizing<String>),
}

pub(crate) struct NativeProtocolAdapter {
    metadata: TransitMetadata,
    authentication: Authentication,
    transport: crate::native_transport::NativeTransport,
    trojan_go_encryption: Option<trojan_go_encryption::Encryption>,
    udp: bool,
    packet_encoding: VlessPacketEncoding,
    timeout: Duration,
}

impl std::fmt::Debug for NativeProtocolAdapter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NativeProtocolAdapter")
            .field("metadata", &self.metadata)
            .finish_non_exhaustive()
    }
}

impl NativeProtocolAdapter {
    pub fn from_config(
        config: &pathchord_policy::TransitProxyConfig,
        credential: &TransitCredential,
        duration: Duration,
        tls: Arc<ClientConfig>,
    ) -> Result<Self, TransitError> {
        let mut allowed = match config.protocol.as_str() {
            "vless" => vec!["uuid", "flow"],
            "trojan" => vec!["password", "trojan_go_ss_method", "trojan_go_ss_password"],
            _ => return Err(unsupported("protocol has no matching native adapter")),
        };
        if config.protocol == "vless"
            && config
                .options
                .transport
                .as_ref()
                .is_some_and(|transport| transport.kind == "meek")
        {
            allowed.push("meek_url");
        }
        allowed.extend(
            config
                .options
                .tls
                .as_ref()
                .and_then(|tls| tls.client_key_field.as_deref()),
        );
        crate::adapter_registry::validate_credentials(Some(credential), &allowed)?;
        let authentication = match config.protocol.as_str() {
            "vless" => {
                let flow = crate::vision::VisionFlow::parse(credential.field("flow"))
                    .map_err(unsupported)?;
                let uuid = uuid::Uuid::parse_str(
                    credential
                        .field("uuid")
                        .ok_or_else(|| unsupported("VLESS UUID is missing"))?,
                )
                .map_err(|_| unsupported("VLESS UUID is invalid"))?;
                Authentication::Vless(Zeroizing::new(*uuid.as_bytes()), flow)
            }
            _ => {
                let password = credential
                    .field("password")
                    .filter(|value| !value.is_empty())
                    .ok_or_else(|| unsupported("Trojan password is missing"))?;
                Authentication::Trojan(Zeroizing::new(password.to_owned()))
            }
        };
        let trojan_go_encryption = if matches!(&authentication, Authentication::Trojan(_)) {
            trojan_go_encryption::Encryption::from_credential(credential)?
        } else {
            None
        };
        if trojan_go_encryption.is_some()
            && config
                .options
                .transport
                .as_ref()
                .is_none_or(|transport| transport.kind == "tcp")
        {
            return Err(unsupported(
                "Trojan-Go Shadowsocks encryption over original TCP is unsupported",
            ));
        }
        let (transport_config, packet_encoding, vision) = match &authentication {
            Authentication::Vless(_, flow) => {
                let (config, xudp) = vless_transport_config(config, *flow)?;
                (config, xudp, flow.is_some())
            }
            Authentication::Trojan(_) => (config.clone(), VlessPacketEncoding::Plain, false),
        };
        let mut transport = crate::native_transport::NativeTransport::new(
            &transport_config,
            credential,
            tls,
            duration,
        )?;
        if vision {
            transport = transport.require_tls13();
        }
        Ok(Self {
            metadata: TransitMetadata {
                adapter_id: config.id.as_str().to_owned(),
                kind: AdapterKind::ExternalProxy {
                    protocol: config.protocol.clone(),
                },
                labels: config.labels.clone(),
            },
            authentication,
            transport,
            trojan_go_encryption,
            udp: config.options.udp != Some(false),
            packet_encoding,
            timeout: duration,
        })
    }

    async fn open(
        &self,
        destination: &Endpoint,
        udp: bool,
    ) -> Result<BoxedTransitConnection, TransitError> {
        if !(udp && self.packet_encoding == VlessPacketEncoding::PacketAddr) {
            crate::validate_destination(destination)?;
        }
        timeout(self.timeout, async {
            let vision = matches!(&self.authentication, Authentication::Vless(_, Some(_)));
            let (mut stream, direct) = if vision {
                let (stream, direct) = self.transport.connect_vision().await?;
                (stream, Some(direct))
            } else {
                (self.transport.connect().await?, None)
            };
            if let Some(encryption) = &self.trojan_go_encryption {
                stream = encryption.wrap(stream);
            }
            let header = Zeroizing::new(match &self.authentication {
                Authentication::Vless(uuid, flow) => vless_request_with_flow(
                    uuid,
                    destination,
                    udp,
                    udp && self.packet_encoding == VlessPacketEncoding::Xudp,
                    flow.map(|_| crate::vision::FLOW_VISION),
                )?,
                Authentication::Trojan(password) => {
                    use sha2::Digest;
                    let digest = Zeroizing::new(sha2::Sha224::digest(password.as_bytes()).to_vec());
                    let mut hash = Zeroizing::new([0; 56]);
                    for (index, byte) in digest.iter().enumerate() {
                        hash[2 * index] = b"0123456789abcdef"[usize::from(byte >> 4)];
                        hash[2 * index + 1] = b"0123456789abcdef"[usize::from(byte & 15)];
                    }
                    let target = trojan_address(destination);
                    let mut header = bytes::BytesMut::new();
                    trojan_proto::write_request_header(
                        &mut header,
                        hash.as_ref(),
                        if udp {
                            trojan_proto::CMD_UDP_ASSOCIATE
                        } else {
                            trojan_proto::CMD_CONNECT
                        },
                        &target,
                    )
                    .map_err(|_| unsupported("Trojan target cannot be encoded"))?;
                    let output = header.to_vec();
                    header.as_mut().zeroize();
                    output
                }
            });
            if let Authentication::Vless(uuid, Some(_)) = &self.authentication {
                let response = Box::new(VlessResponseIo::new(stream));
                return Ok(Box::new(
                    crate::vision::VisionStream::new(
                        response,
                        crate::vision::VisionContext::new(uuid),
                    )
                    .with_request_header(header)
                    .with_direct_signal(direct.expect("Vision connection has a direct signal"))
                    .drive_request(),
                ) as BoxedTransitConnection);
            }
            stream
                .write_all(&header)
                .await
                .map_err(|_| protocol("native protocol request write failed"))?;
            stream
                .flush()
                .await
                .map_err(|_| protocol("native protocol request flush failed"))?;
            if matches!(&self.authentication, Authentication::Vless(_, _)) {
                stream = Box::new(VlessResponseIo::new(stream));
            }
            Ok(stream)
        })
        .await
        .map_err(|_| TransitError::Connection("native protocol opening timed out".into()))?
    }
}

#[async_trait]
impl TransitAdapter for NativeProtocolAdapter {
    fn metadata(&self) -> &TransitMetadata {
        &self.metadata
    }
    fn supports_udp(&self) -> bool {
        self.udp
    }
    async fn connect(
        &self,
        request: ConnectRequest,
    ) -> Result<BoxedTransitConnection, TransitError> {
        self.open(&request.destination, false).await
    }
    async fn connect_udp(
        &self,
        request: ConnectRequest,
    ) -> Result<BoxedTransitDatagram, TransitError> {
        if !self.udp {
            return Err(unsupported("node UDP is disabled"));
        }
        if let Authentication::Vless(_, Some(flow)) = &self.authentication
            && request.destination.port == 443
            && !flow.allow_udp_443
        {
            return Err(unsupported("VLESS Vision rejects UDP to port 443"));
        }
        crate::validate_destination(&request.destination)?;
        let target = if self.packet_encoding == VlessPacketEncoding::PacketAddr {
            if request.destination.host.parse::<IpAddr>().is_err() {
                return Err(unsupported("VLESS packetaddr requires an IP destination"));
            }
            packetaddr_magic_destination()
        } else {
            request.destination.clone()
        };
        let stream = self.open(&target, true).await?;
        match self.packet_encoding {
            VlessPacketEncoding::Xudp => crate::xudp::xudp_datagram(stream, request.destination),
            VlessPacketEncoding::PacketAddr => {
                let inner = vless_datagram(stream, target);
                Ok(Box::new(crate::vmess::PacketAddrDatagram::new(
                    inner,
                    request.destination,
                    usize::from(u16::MAX),
                )?))
            }
            VlessPacketEncoding::Plain => Ok(Box::new(NativeDatagram::new(
                stream,
                request.destination,
                match self.authentication {
                    Authentication::Vless(_, _) => Protocol::Vless,
                    Authentication::Trojan(_) => Protocol::Trojan,
                },
            ))),
        }
    }
}

/// Remove only packet settings consumed by the VLESS adapter before the
/// shared byte-transport validation runs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum VlessPacketEncoding {
    Plain,
    Xudp,
    PacketAddr,
}

pub(crate) fn packetaddr_magic_destination() -> Endpoint {
    Endpoint {
        host: "sp.packet-addr.v2fly.arpa".into(),
        port: 0,
    }
}

pub(crate) fn vless_transport_config(
    config: &pathchord_policy::TransitProxyConfig,
    vision: Option<crate::vision::VisionFlow>,
) -> Result<(pathchord_policy::TransitProxyConfig, VlessPacketEncoding), TransitError> {
    config.options.validate().map_err(unsupported)?;
    if vision.is_some() {
        if !config.options.tls.as_ref().is_some_and(|tls| tls.enabled) {
            return Err(unsupported("VLESS Vision requires enabled TLS"));
        }
        if config
            .options
            .transport
            .as_ref()
            .is_some_and(|transport| transport.kind != "tcp")
        {
            return Err(unsupported("VLESS Vision requires direct TLS transport"));
        }
    }
    let encoding = match config.options.packet_encoding.as_deref() {
        Some("xudp") => VlessPacketEncoding::Xudp,
        Some("packetaddr") if vision.is_none() => VlessPacketEncoding::PacketAddr,
        Some("packetaddr") => {
            return Err(unsupported(
                "VLESS Vision requires XUDP and cannot use packetaddr",
            ));
        }
        Some(_) => return Err(unsupported("VLESS packet encoding is unsupported")),
        None if vision.is_some() => VlessPacketEncoding::Xudp,
        None => VlessPacketEncoding::Plain,
    };
    let mut transport_config = config.clone();
    transport_config.options.packet_encoding = None;
    Ok((transport_config, encoding))
}

pub(crate) fn vless_request_with_flow(
    uuid: &[u8; 16],
    destination: &Endpoint,
    udp: bool,
    xudp: bool,
    flow: Option<&str>,
) -> Result<Vec<u8>, TransitError> {
    let mut request = vec![0];
    request.extend_from_slice(uuid);
    let addons = flow.map_or_else(Vec::new, |flow| {
        let bytes = flow.as_bytes();
        let mut addons = Vec::with_capacity(bytes.len() + 2);
        addons.push((1 << 3) | 2);
        addons.push(bytes.len() as u8);
        addons.extend_from_slice(bytes);
        addons
    });
    if addons.len() > u8::MAX as usize {
        return Err(unsupported("VLESS flow addon is too long"));
    }
    request.push(addons.len() as u8);
    request.extend_from_slice(&addons);
    request.push(if xudp {
        3
    } else if udp {
        2
    } else {
        1
    });
    if xudp {
        return Ok(request);
    }
    request.extend_from_slice(&destination.port.to_be_bytes());
    match destination.host.parse::<IpAddr>() {
        Ok(IpAddr::V4(ip)) => {
            request.push(1);
            request.extend_from_slice(&ip.octets());
        }
        Ok(IpAddr::V6(ip)) => {
            request.push(3);
            request.extend_from_slice(&ip.octets());
        }
        Err(_) => {
            let bytes = destination.host.as_bytes();
            if bytes.is_empty() || bytes.len() > 255 {
                return Err(unsupported("VLESS target hostname is invalid"));
            }
            request.push(2);
            request.push(bytes.len() as u8);
            request.extend_from_slice(bytes);
        }
    }
    Ok(request)
}

fn unsupported(message: &str) -> TransitError {
    TransitError::Unsupported(message.to_owned())
}
fn protocol(message: &str) -> TransitError {
    TransitError::Protocol(message.to_owned())
}

fn trojan_address(destination: &Endpoint) -> trojan_proto::AddressRef<'_> {
    let host = match destination.host.parse::<IpAddr>() {
        Ok(IpAddr::V4(ip)) => trojan_proto::HostRef::Ipv4(ip.octets()),
        Ok(IpAddr::V6(ip)) => trojan_proto::HostRef::Ipv6(ip.octets()),
        Err(_) => trojan_proto::HostRef::Domain(destination.host.as_bytes()),
    };
    trojan_proto::AddressRef {
        host,
        port: destination.port,
    }
}

pub(crate) struct VlessResponseIo {
    inner: BoxedTransitConnection,
    header: [u8; 2],
    filled: usize,
    addon_remaining: Option<usize>,
}
impl VlessResponseIo {
    pub(crate) fn new(inner: BoxedTransitConnection) -> Self {
        Self {
            inner,
            header: [0; 2],
            filled: 0,
            addon_remaining: None,
        }
    }
}
impl AsyncRead for VlessResponseIo {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        if buffer.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        while this.filled < 2 {
            let mut header = ReadBuf::new(&mut this.header[this.filled..]);
            match Pin::new(&mut this.inner).poll_read(cx, &mut header) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(())) => {
                    if header.filled().is_empty() {
                        return Poll::Ready(Err(std::io::ErrorKind::UnexpectedEof.into()));
                    }
                    this.filled += header.filled().len();
                }
            }
        }
        if this.header[0] != 0 {
            return Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid VLESS response version",
            )));
        }
        let remaining = this
            .addon_remaining
            .get_or_insert(usize::from(this.header[1]));
        while *remaining > 0 {
            let mut ignored = [0; 255];
            let mut read = ReadBuf::new(&mut ignored[..*remaining]);
            match Pin::new(&mut this.inner).poll_read(cx, &mut read) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(())) => {
                    if read.filled().is_empty() {
                        return Poll::Ready(Err(std::io::ErrorKind::UnexpectedEof.into()));
                    }
                    *remaining -= read.filled().len();
                }
            }
        }
        Pin::new(&mut this.inner).poll_read(cx, buffer)
    }
}
impl AsyncWrite for VlessResponseIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buffer)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

pub(crate) struct NativeDatagram {
    stream: BoxedTransitConnection,
    destination: Endpoint,
    protocol: Protocol,
    received: Vec<u8>,
    write_interrupted: bool,
}
impl NativeDatagram {
    fn new(stream: BoxedTransitConnection, destination: Endpoint, protocol: Protocol) -> Self {
        Self {
            stream,
            destination,
            protocol,
            received: Vec::new(),
            write_interrupted: false,
        }
    }
}
pub(crate) fn vless_datagram(
    stream: BoxedTransitConnection,
    destination: Endpoint,
) -> BoxedTransitDatagram {
    Box::new(NativeDatagram::new(stream, destination, Protocol::Vless))
}
impl std::fmt::Debug for NativeDatagram {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("NativeProtocolDatagram(..)")
    }
}
#[async_trait]
impl TransitDatagram for NativeDatagram {
    async fn send(&mut self, payload: &[u8]) -> Result<(), TransitError> {
        if self.write_interrupted {
            return Err(protocol("native UDP write was interrupted"));
        }
        let length = u16::try_from(payload.len())
            .map_err(|_| unsupported("UDP packet exceeds the native protocol limit"))?;
        let mut packet = Vec::new();
        if matches!(self.protocol, Protocol::Trojan) {
            encode_trojan_address(&self.destination, &mut packet)?;
        }
        packet.extend_from_slice(&length.to_be_bytes());
        if matches!(self.protocol, Protocol::Trojan) {
            packet.extend_from_slice(b"\r\n");
        }
        packet.extend_from_slice(payload);
        self.write_interrupted = true;
        self.stream
            .write_all(&packet)
            .await
            .map_err(|_| protocol("native UDP packet write failed"))?;
        self.stream
            .flush()
            .await
            .map_err(|_| protocol("native UDP packet flush failed"))?;
        self.write_interrupted = false;
        Ok(())
    }
    async fn receive(&mut self) -> Result<Vec<u8>, TransitError> {
        use trojan_proto::{HostRef, ParseResult};

        let mut chunk = [0; 8192];
        loop {
            let frame = match self.protocol {
                Protocol::Vless => self.received.first_chunk::<2>().and_then(|length| {
                    let end = 2 + usize::from(u16::from_be_bytes(*length));
                    self.received.get(2..end).map(|payload| (end, payload))
                }),
                Protocol::Trojan => match trojan_proto::parse_udp_packet(&self.received) {
                    ParseResult::Complete(packet) => {
                        let source = match packet.address.host {
                            HostRef::Ipv4(ip) => Some(IpAddr::from(ip)),
                            HostRef::Ipv6(ip) => Some(IpAddr::from(ip)),
                            HostRef::Domain(_) => None,
                        };
                        if packet.address.port == 0
                            || packet.address.port != self.destination.port
                            || self
                                .destination
                                .host
                                .parse::<IpAddr>()
                                .is_ok_and(|expected| source != Some(expected))
                        {
                            return Err(protocol(
                                "Trojan UDP reply target does not match the association",
                            ));
                        }
                        Some((packet.packet_len, packet.payload))
                    }
                    ParseResult::Incomplete(_) => None,
                    ParseResult::Invalid(_) => {
                        return Err(protocol("Trojan UDP packet header is invalid"));
                    }
                },
            };
            if let Some((length, payload)) = frame {
                let payload = payload.to_vec();
                self.received.drain(..length);
                return Ok(payload);
            }
            // Keep consumed bytes across cancelled reads until a frame is complete.
            let size = self
                .stream
                .read(&mut chunk)
                .await
                .map_err(|_| protocol("native UDP packet read failed"))?;
            if size == 0 {
                return Err(protocol("native UDP packet is truncated"));
            }
            self.received.extend_from_slice(&chunk[..size]);
        }
    }
    async fn close(mut self: Box<Self>) -> Result<(), TransitError> {
        self.stream
            .shutdown()
            .await
            .map_err(|_| protocol("native UDP shutdown failed"))
    }
}

fn encode_trojan_address(destination: &Endpoint, packet: &mut Vec<u8>) -> Result<(), TransitError> {
    match destination.host.parse::<IpAddr>() {
        Ok(IpAddr::V4(ip)) => {
            packet.push(1);
            packet.extend_from_slice(&ip.octets());
        }
        Ok(IpAddr::V6(ip)) => {
            packet.push(4);
            packet.extend_from_slice(&ip.octets());
        }
        Err(_) => {
            let bytes = destination.host.as_bytes();
            if bytes.is_empty() || bytes.len() > 255 {
                return Err(unsupported("Trojan UDP hostname is invalid"));
            }
            packet.push(3);
            packet.push(bytes.len() as u8);
            packet.extend_from_slice(bytes);
        }
    }
    packet.extend_from_slice(&destination.port.to_be_bytes());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::collections::BTreeMap;
    use std::path::PathBuf;
    use std::process::Stdio;

    fn node(protocol: &str, port: u16) -> pathchord_policy::TransitProxyConfig {
        pathchord_policy::TransitProxyConfig {
            id: pathchord_policy::TransitProxyId::new("native-test"),
            source: None,
            protocol: protocol.into(),
            endpoint: pathchord_policy::Endpoint {
                host: "127.0.0.1".into(),
                port,
            },
            credentials_ref: None,
            labels: Default::default(),
            tags: Default::default(),
            weight: 1,
            options: Default::default(),
        }
    }

    #[test]
    fn native_credentials_reject_trojan_go_encryption_over_original_tcp() {
        let mut config = node("trojan", 443);
        let credential = TransitCredential::new(BTreeMap::from([
            ("password".into(), "fixture-password".into()),
            ("trojan_go_ss_method".into(), "aes-128-gcm".into()),
            ("trojan_go_ss_password".into(), "fixture-ss-password".into()),
        ]));
        let tls = crate::adapter_registry::native_tls_roots();
        for transport in [None, Some("tcp"), Some("ws")] {
            config.options.transport = transport.map(|kind| pathchord_policy::TransitTransport {
                kind: kind.into(),
                ..Default::default()
            });
            let result = NativeProtocolAdapter::from_config(
                &config,
                &credential,
                Duration::from_secs(1),
                Arc::clone(&tls),
            );
            if transport == Some("ws") {
                assert!(result.is_ok());
            } else {
                assert!(matches!(
                    result,
                    Err(TransitError::Unsupported(reason)) if reason.contains("original TCP")
                ));
            }
        }
    }

    #[test]
    fn vless_request_encodes_remote_domains_and_ipv6_without_local_resolution() {
        let uuid = [7; 16];
        let request = vless_request_with_flow(
            &uuid,
            &Endpoint {
                host: "remote.test".into(),
                port: 443,
            },
            false,
            false,
            None,
        )
        .unwrap();
        assert_eq!(&request[..18], &[vec![0], uuid.to_vec(), vec![0]].concat());
        assert_eq!(
            &request[18..],
            &[vec![1, 1, 187, 2, 11], b"remote.test".to_vec()].concat()
        );
        let request = vless_request_with_flow(
            &uuid,
            &Endpoint {
                host: "::1".into(),
                port: 53,
            },
            true,
            false,
            None,
        )
        .unwrap();
        assert_eq!(&request[18..22], &[2, 0, 53, 3]);
        assert_eq!(&request[22..], &std::net::Ipv6Addr::LOCALHOST.octets());
    }

    #[tokio::test]
    async fn vless_datagram_retains_partial_reads_and_fails_closed_after_cancelled_write() {
        use std::{
            future::Future,
            pin::pin,
            task::{Context, Poll, Waker},
        };
        let destination = Endpoint {
            host: "192.0.2.1".into(),
            port: 53,
        };
        let (stream, mut peer) = tokio::io::duplex(64);
        let mut datagram = vless_datagram(Box::new(stream), destination.clone());
        peer.write_all(&[0]).await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(10), datagram.receive())
                .await
                .is_err()
        );
        peer.write_all(&[3, b'a']).await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(10), datagram.receive())
                .await
                .is_err()
        );
        peer.write_all(&[b'b', b'c', 0, 2, b'd', b'e'])
            .await
            .unwrap();
        assert_eq!(datagram.receive().await.unwrap(), b"abc");
        assert_eq!(datagram.receive().await.unwrap(), b"de");

        let (stream, _peer) = tokio::io::duplex(1);
        let mut datagram = vless_datagram(Box::new(stream), destination);
        {
            let mut send = pin!(datagram.send(b"partial"));
            assert!(matches!(
                send.as_mut().poll(&mut Context::from_waker(Waker::noop())),
                Poll::Pending
            ));
        }
        assert!(
            matches!(datagram.send(b"retry").await, Err(TransitError::Protocol(reason)) if reason.contains("interrupted"))
        );
    }

    #[tokio::test]
    async fn trojan_datagram_retains_address_and_payload_across_cancelled_reads() {
        let destination = Endpoint {
            host: "example.test".into(),
            port: 53,
        };
        let (stream, mut peer) = tokio::io::duplex(128);
        let mut datagram =
            NativeDatagram::new(Box::new(stream), destination.clone(), Protocol::Trojan);
        let mut packets = bytes::BytesMut::new();
        let address = trojan_address(&destination);
        trojan_proto::write_udp_packet(&mut packets, &address, b"one").unwrap();
        let first_end = packets.len();
        trojan_proto::write_udp_packet(&mut packets, &address, b"two").unwrap();

        for prefix in [&packets[..5], &packets[5..first_end - 1]] {
            peer.write_all(prefix).await.unwrap();
            {
                let receive = datagram.receive();
                tokio::pin!(receive);
                assert!(futures_util::poll!(receive).is_pending());
            }
        }
        peer.write_all(&packets[first_end - 1..]).await.unwrap();
        assert_eq!(datagram.receive().await.unwrap(), b"one");
        assert_eq!(datagram.receive().await.unwrap(), b"two");
    }

    #[tokio::test]
    async fn packetaddr_retains_split_vless_frame_across_cancelled_receive() {
        let destination = Endpoint {
            host: "192.0.2.1".into(),
            port: 53,
        };
        let (stream, mut peer) = tokio::io::duplex(64);
        let inner = vless_datagram(Box::new(stream), packetaddr_magic_destination());
        let mut datagram =
            crate::vmess::PacketAddrDatagram::new(inner, destination, usize::from(u16::MAX))
                .unwrap();
        peer.write_all(&[0, 10, 1, 192]).await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(10), datagram.receive())
                .await
                .is_err()
        );
        peer.write_all(&[0, 2, 1, 0, 53, b'a', b'b', b'c'])
            .await
            .unwrap();
        assert_eq!(datagram.receive().await.unwrap(), b"abc");
    }

    #[test]
    fn packetaddr_with_vision_is_rejected_for_direct_tls_and_reality() {
        let mut config = node("vless", 443);
        config.options.tls = Some(pathchord_policy::TransitTls {
            enabled: true,
            ..Default::default()
        });
        config.options.packet_encoding = Some("packetaddr".into());
        let credential = TransitCredential::new(BTreeMap::from([
            ("uuid".into(), "6cbf3f72-3417-4922-bde6-67820d041f25".into()),
            ("flow".into(), "xtls-rprx-vision".into()),
        ]));
        assert!(
            matches!(NativeProtocolAdapter::from_config(&config, &credential, Duration::from_secs(1), crate::adapter_registry::native_tls_roots()), Err(TransitError::Unsupported(reason)) if reason.contains("Vision") && reason.contains("XUDP"))
        );
        config.options.tls.as_mut().unwrap().reality = Some(pathchord_policy::TransitReality {
            public_key: "Q7VhOFla3pZJiGzjiNfwi3j-QfEr9FOdDpQIiDANtRM".into(),
            short_id: "0123456789abcdef".into(),
        });
        assert!(
            matches!(crate::reality_adapter::RealityVlessAdapter::from_config(&config, &credential, Duration::from_secs(1), crate::adapter_registry::native_tls_roots()), Err(TransitError::Unsupported(reason)) if reason.contains("Vision") && reason.contains("XUDP"))
        );
    }

    #[test]
    fn vless_request_encodes_vision_flow_addon() {
        let uuid = [7; 16];
        let request = vless_request_with_flow(
            &uuid,
            &Endpoint {
                host: "remote.test".into(),
                port: 443,
            },
            false,
            false,
            Some(crate::vision::FLOW_VISION),
        )
        .unwrap();
        let flow = crate::vision::FLOW_VISION.as_bytes();
        assert_eq!(request[17], (flow.len() + 2) as u8);
        assert_eq!(&request[18..20], &[0x0a, flow.len() as u8]);
        assert_eq!(&request[20..20 + flow.len()], flow);

        let mux = vless_request_with_flow(
            &uuid,
            &Endpoint {
                host: "remote.test".into(),
                port: 443,
            },
            true,
            true,
            Some(crate::vision::FLOW_VISION),
        )
        .unwrap();
        assert_eq!(
            &mux[18..20 + flow.len()],
            &[&[0x0a, flow.len() as u8], flow].concat()
        );
        assert_eq!(&mux[20 + flow.len()..], &[3]);
    }

    #[tokio::test]
    async fn vision_udp_443_requires_explicit_variant_before_dialing() {
        let mut node = node("vless", 1);
        node.options.tls = Some(pathchord_policy::TransitTls {
            enabled: true,
            insecure: true,
            ..Default::default()
        });
        let make_adapter = |flow: &str| {
            let credential = TransitCredential::new(BTreeMap::from([
                ("uuid".into(), "6cbf3f72-3417-4922-bde6-67820d041f25".into()),
                ("flow".into(), flow.into()),
            ]));
            NativeProtocolAdapter::from_config(
                &node,
                &credential,
                Duration::from_millis(250),
                crate::adapter_registry::native_tls_roots(),
            )
            .unwrap()
        };
        let request = ConnectRequest {
            destination: Endpoint {
                host: "127.0.0.1".into(),
                port: 443,
            },
        };
        let ordinary = make_adapter(crate::vision::FLOW_VISION);
        assert!(ordinary.supports_udp());
        assert!(matches!(
            ordinary.connect_udp(request.clone()).await,
            Err(TransitError::Unsupported(_))
        ));
        let allow = make_adapter(crate::vision::FLOW_VISION_UDP443);
        assert!(allow.supports_udp());
        assert!(matches!(
            allow.connect_udp(request).await,
            Err(TransitError::Connection(_))
        ));
    }

    #[tokio::test]
    async fn vless_response_strips_only_bounded_protocol_metadata() {
        for version in [0, 1] {
            let (mut peer, io) = tokio::io::duplex(64);
            let mut stream = VlessResponseIo {
                inner: Box::new(io),
                header: [0; 2],
                filled: 0,
                addon_remaining: None,
            };
            let task = tokio::spawn(async move {
                peer.write_all(&[version, 3, 1, 2, 3]).await.unwrap();
                peer.write_all(b"application").await.unwrap();
                peer.shutdown().await.unwrap();
            });
            let mut output = Vec::new();
            let result = stream.read_to_end(&mut output).await;
            if version == 0 {
                assert!(result.is_ok());
                assert_eq!(&output, b"application");
            } else {
                assert!(result.is_err());
                assert!(output.is_empty());
            }
            task.await.unwrap();
        }
    }

    #[test]
    fn native_protocols_accept_vision_and_reject_other_flow_or_transport_options() {
        let mut node = node("vless", 443);
        node.options.tls = Some(pathchord_policy::TransitTls {
            enabled: true,
            insecure: true,
            ..Default::default()
        });
        let credentials = TransitCredential::new(BTreeMap::from([
            ("uuid".into(), "6cbf3f72-3417-4922-bde6-67820d041f25".into()),
            ("flow".into(), "xtls-rprx-vision".into()),
        ]));
        assert!(
            NativeProtocolAdapter::from_config(
                &node,
                &credentials,
                Duration::from_secs(1),
                crate::adapter_registry::native_tls_roots()
            )
            .is_ok()
        );
        let invalid_flow = TransitCredential::new(BTreeMap::from([
            ("uuid".into(), "6cbf3f72-3417-4922-bde6-67820d041f25".into()),
            ("flow".into(), "unsupported-flow".into()),
        ]));
        assert!(
            NativeProtocolAdapter::from_config(
                &node,
                &invalid_flow,
                Duration::from_secs(1),
                crate::adapter_registry::native_tls_roots()
            )
            .is_err()
        );
        node.options.transport = Some(pathchord_policy::TransitTransport {
            kind: "grpc".into(),
            service_name: Some("service".into()),
            ..Default::default()
        });
        let credentials = TransitCredential::new(BTreeMap::from([(
            "uuid".into(),
            "6cbf3f72-3417-4922-bde6-67820d041f25".into(),
        )]));
        assert!(
            NativeProtocolAdapter::from_config(
                &node,
                &credentials,
                Duration::from_secs(1),
                crate::adapter_registry::native_tls_roots()
            )
            .is_ok()
        );
        node.options.transport.as_mut().unwrap().kind = "quic".into();
        assert!(
            NativeProtocolAdapter::from_config(
                &node,
                &credentials,
                Duration::from_secs(1),
                crate::adapter_registry::native_tls_roots()
            )
            .is_err()
        );
    }

    #[tokio::test]
    #[ignore = "requires PATHCHORD_TEST_SING_BOX for native Rust protocol interoperability"]
    async fn rust_vless_and_trojan_interoperate_over_tcp_tls_and_websocket() {
        timeout(Duration::from_secs(45),async {
            let binary=PathBuf::from(std::env::var_os("PATHCHORD_TEST_SING_BOX").expect("reference engine"));
            for (protocol,tls,websocket) in [("vless",false,false),("vless",true,false),("vless",false,true),("vless",true,true),("trojan",true,false),("trojan",true,true)] {
                let listener=std::net::TcpListener::bind("127.0.0.1:0").unwrap();let port=listener.local_addr().unwrap().port();drop(listener);
                let field=if protocol=="vless"{"uuid"}else{"password"};
                let secret=if protocol=="vless"{"6cbf3f72-3417-4922-bde6-67820d041f25"}else{"native-trojan-secret"};
                let mut inbound=json!({"type":protocol,"listen":"127.0.0.1","listen_port":port,"users":[{field:secret}]});
                let mut config=node(protocol,port);
                if tls {
                    let rcgen::CertifiedKey{cert,signing_key}=rcgen::generate_simple_self_signed(vec!["proxy.test".into()]).unwrap();
                    inbound["tls"]=json!({"enabled":true,"certificate":cert.pem(),"key":signing_key.serialize_pem()});
                    config.options.tls=Some(pathchord_policy::TransitTls{enabled:true,server_name:Some("proxy.test".into()),certificate:vec![cert.pem()],..Default::default()});
                }
                if websocket {
                    inbound["transport"]=json!({"type":"ws","path":"/rust-native"});
                    config.options.transport=Some(pathchord_policy::TransitTransport{kind:"ws".into(),path:Some("/rust-native".into()),host:vec!["proxy.test".into()],..Default::default()});
                }
                let body=Zeroizing::new(serde_json::to_vec(&json!({"log":{"disabled":true},"inbounds":[inbound],"outbounds":[{"type":"direct","tag":"direct"}],"route":{"final":"direct"}})).unwrap());
                let mut server=tokio::process::Command::new(&binary).arg("run").arg("-c").arg("stdin").stdin(Stdio::piped()).stdout(Stdio::null()).stderr(Stdio::null()).kill_on_drop(true).spawn().unwrap();
                server.stdin.take().unwrap().write_all(&body).await.unwrap();
                let deadline=tokio::time::Instant::now()+Duration::from_secs(3);
                while tokio::net::TcpStream::connect(("127.0.0.1",port)).await.is_err(){assert!(tokio::time::Instant::now()<deadline,"reference readiness");tokio::time::sleep(Duration::from_millis(10)).await;}
                let credentials=TransitCredential::new(BTreeMap::from([(field.into(),secret.into())]));
                let adapter=NativeProtocolAdapter::from_config(&config,&credentials,Duration::from_secs(3),crate::adapter_registry::native_tls_roots()).unwrap();
                let tcp=tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();let target=tcp.local_addr().unwrap();
                let task=tokio::spawn(async move {let(mut io,_)=tcp.accept().await.unwrap();let mut buffer=[0;6];io.read_exact(&mut buffer).await.unwrap();io.write_all(&buffer).await.unwrap();});
                let mut stream=adapter.connect(ConnectRequest {destination:Endpoint{host:"localhost".into(),port:target.port()}}).await.unwrap();
                stream.write_all(b"native").await.unwrap();stream.flush().await.unwrap();let mut received=[0;6];stream.read_exact(&mut received).await.unwrap();assert_eq!(&received,b"native","{protocol}, tls={tls}, ws={websocket}");drop(stream);task.await.unwrap();
                let udp=tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();let target=udp.local_addr().unwrap();
                let task=tokio::spawn(async move {let mut buffer=[0;128];let(length,peer)=udp.recv_from(&mut buffer).await.unwrap();udp.send_to(&buffer[..length],peer).await.unwrap();});
                let mut association=adapter.connect_udp(ConnectRequest{destination:Endpoint{host:target.ip().to_string(),port:target.port()}}).await.unwrap();association.send(b"datagram").await.unwrap();assert_eq!(association.receive().await.unwrap(),b"datagram","{protocol}, tls={tls}, ws={websocket}");association.close().await.unwrap();task.await.unwrap();server.kill().await.unwrap();server.wait().await.unwrap();
            }
        }).await.expect("bounded native protocol interop");
    }
}
