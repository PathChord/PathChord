//! Bounded native UDP transports for direct, SOCKS5, and Shadowsocks routes.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use async_trait::async_trait;
use shadowsocks::ProxySocket;
use shadowsocks::config::ServerConfig;
use shadowsocks::context::SharedContext;
use shadowsocks::relay::socks5::Address;
use shadowsocks::relay::udprelay::options::UdpSocketControlData;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket, lookup_host};
use tokio::time::timeout;
use zeroize::Zeroizing;

use crate::{
    BoxedTransitDatagram, Endpoint, TransitDatagram, TransitError, connect_tcp_endpoint,
    validate_destination,
};

const MAX_PACKET: usize = 65_507;

fn connection(message: &str) -> TransitError {
    TransitError::Connection(message.to_owned())
}

fn protocol(message: &str) -> TransitError {
    TransitError::Protocol(message.to_owned())
}

fn check_payload(payload: &[u8], overhead: usize) -> Result<(), TransitError> {
    if payload.len().saturating_add(overhead) > MAX_PACKET {
        return Err(TransitError::Unsupported(
            "UDP datagram exceeds the transport limit".to_owned(),
        ));
    }
    Ok(())
}

#[derive(Debug)]
struct DirectDatagram {
    socket: UdpSocket,
}

pub(crate) async fn direct_connect_udp(
    destination: &Endpoint,
    connect_timeout: Duration,
) -> Result<BoxedTransitDatagram, TransitError> {
    validate_destination(destination)?;
    timeout(connect_timeout, async {
        let addresses = lookup_host((destination.host.as_str(), destination.port))
            .await
            .map_err(|_| connection("direct UDP name resolution failed"))?;
        for address in addresses {
            let bind = if address.is_ipv4() {
                "0.0.0.0:0"
            } else {
                "[::]:0"
            };
            let socket = UdpSocket::bind(bind)
                .await
                .map_err(|_| connection("direct UDP bind failed"))?;
            if socket.connect(address).await.is_ok() {
                return Ok(Box::new(DirectDatagram { socket }) as BoxedTransitDatagram);
            }
        }
        Err(connection("direct UDP destination is unavailable"))
    })
    .await
    .map_err(|_| connection("direct UDP connection timed out"))?
}

#[async_trait]
impl TransitDatagram for DirectDatagram {
    async fn send(&mut self, payload: &[u8]) -> Result<(), TransitError> {
        check_payload(payload, 0)?;
        self.socket
            .send(payload)
            .await
            .map_err(|_| connection("direct UDP send failed"))?;
        Ok(())
    }

    async fn receive(&mut self) -> Result<Vec<u8>, TransitError> {
        let mut packet = vec![0; 65_536];
        let length = self
            .socket
            .recv(&mut packet)
            .await
            .map_err(|_| connection("direct UDP receive failed"))?;
        packet.truncate(length);
        Ok(packet)
    }
}

#[derive(Debug)]
struct SocksDatagram {
    socket: UdpSocket,
    control: TcpStream,
    destination: Endpoint,
    header: Vec<u8>,
}

pub(crate) async fn socks5_connect_udp(
    proxy: &Endpoint,
    credentials: Option<&(String, String)>,
    destination: &Endpoint,
    connect_timeout: Duration,
) -> Result<BoxedTransitDatagram, TransitError> {
    validate_destination(destination)?;
    timeout(connect_timeout, async {
        let mut control = connect_tcp_endpoint(proxy, connect_timeout).await?;
        authenticate_socks(&mut control, credentials).await?;
        let peer = control
            .peer_addr()
            .map_err(|_| connection("SOCKS5 control peer is unavailable"))?;
        // The relay learns the actual UDP source rather than assuming the TCP
        // source port or a private endpoint survives NAT unchanged.
        let associate: &[u8] = if peer.is_ipv4() {
            &[5, 3, 0, 1, 0, 0, 0, 0, 0, 0]
        } else {
            &[
                5, 3, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            ]
        };
        control
            .write_all(associate)
            .await
            .map_err(|_| connection("SOCKS5 UDP ASSOCIATE write failed"))?;
        let mut response = [0; 4];
        control
            .read_exact(&mut response)
            .await
            .map_err(|_| protocol("SOCKS5 UDP ASSOCIATE response is truncated"))?;
        if response[..3] != [5, 0, 0] {
            return Err(protocol("SOCKS5 proxy rejected UDP ASSOCIATE"));
        }
        let relay = read_socks_address(&mut control, response[3]).await?;
        let relay = match relay.host.parse::<IpAddr>() {
            Ok(ip) => SocketAddr::new(if ip.is_unspecified() { peer.ip() } else { ip }, relay.port),
            Err(_) => lookup_host((relay.host.as_str(), relay.port))
                .await
                .map_err(|_| connection("SOCKS5 relay name resolution failed"))?
                .find(|address| address.is_ipv4() == peer.is_ipv4())
                .ok_or_else(|| connection("SOCKS5 relay has no compatible address"))?,
        };
        if relay.port() == 0
            || relay.ip().is_unspecified()
            || relay.ip().is_multicast()
            || relay.ip() == IpAddr::V4(Ipv4Addr::BROADCAST)
        {
            return Err(protocol("SOCKS5 relay endpoint is invalid"));
        }
        let socket = UdpSocket::bind(if relay.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        })
        .await
        .map_err(|_| connection("SOCKS5 UDP socket bind failed"))?;
        socket
            .connect(relay)
            .await
            .map_err(|_| connection("SOCKS5 relay connection failed"))?;
        let mut header = vec![0, 0, 0];
        encode_address(destination, &mut header)?;
        Ok(Box::new(SocksDatagram {
            socket,
            control,
            destination: destination.clone(),
            header,
        }) as BoxedTransitDatagram)
    })
    .await
    .map_err(|_| connection("SOCKS5 UDP handshake timed out"))?
}

async fn authenticate_socks(
    control: &mut TcpStream,
    credentials: Option<&(String, String)>,
) -> Result<(), TransitError> {
    if credentials.is_some_and(|(username, password)| {
        username.is_empty() || username.len() > 255 || password.len() > 255
    }) {
        return Err(TransitError::Unsupported(
            "SOCKS5 UDP credentials are invalid".to_owned(),
        ));
    }
    let method = if credentials.is_some() { 2 } else { 0 };
    control
        .write_all(&[5, 1, method])
        .await
        .map_err(|_| connection("SOCKS5 greeting write failed"))?;
    let mut selected = [0; 2];
    control
        .read_exact(&mut selected)
        .await
        .map_err(|_| protocol("SOCKS5 greeting is truncated"))?;
    if selected != [5, method] {
        return Err(protocol(
            "SOCKS5 selected an unoffered authentication method",
        ));
    }
    if let Some((username, password)) = credentials {
        let mut authentication = Zeroizing::new(vec![1, username.len() as u8]);
        authentication.extend_from_slice(username.as_bytes());
        authentication.push(password.len() as u8);
        authentication.extend_from_slice(password.as_bytes());
        control
            .write_all(&authentication)
            .await
            .map_err(|_| connection("SOCKS5 authentication write failed"))?;
        let mut response = [0; 2];
        control
            .read_exact(&mut response)
            .await
            .map_err(|_| protocol("SOCKS5 authentication response is truncated"))?;
        if response != [1, 0] {
            return Err(protocol("SOCKS5 proxy rejected credentials"));
        }
    }
    Ok(())
}

async fn read_socks_address(control: &mut TcpStream, kind: u8) -> Result<Endpoint, TransitError> {
    let host = match kind {
        1 => {
            let mut address = [0; 4];
            control
                .read_exact(&mut address)
                .await
                .map_err(|_| protocol("SOCKS5 relay IPv4 address is truncated"))?;
            Ipv4Addr::from(address).to_string()
        }
        4 => {
            let mut address = [0; 16];
            control
                .read_exact(&mut address)
                .await
                .map_err(|_| protocol("SOCKS5 relay IPv6 address is truncated"))?;
            Ipv6Addr::from(address).to_string()
        }
        3 => {
            let length = control
                .read_u8()
                .await
                .map_err(|_| protocol("SOCKS5 relay hostname is truncated"))?
                as usize;
            let mut name = vec![0; length];
            control
                .read_exact(&mut name)
                .await
                .map_err(|_| protocol("SOCKS5 relay hostname is truncated"))?;
            String::from_utf8(name).map_err(|_| protocol("SOCKS5 relay hostname is invalid"))?
        }
        _ => return Err(protocol("SOCKS5 relay address type is invalid")),
    };
    let port = control
        .read_u16()
        .await
        .map_err(|_| protocol("SOCKS5 relay port is truncated"))?;
    let endpoint = Endpoint { host, port };
    validate_destination(&endpoint)?;
    Ok(endpoint)
}

fn encode_address(destination: &Endpoint, packet: &mut Vec<u8>) -> Result<(), TransitError> {
    validate_destination(destination)?;
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
            packet.extend_from_slice(&[3, destination.host.len() as u8]);
            packet.extend_from_slice(destination.host.as_bytes());
        }
    }
    packet.extend_from_slice(&destination.port.to_be_bytes());
    Ok(())
}

fn decode_packet_address(packet: &[u8]) -> Result<(Endpoint, usize), TransitError> {
    let kind = *packet
        .first()
        .ok_or_else(|| protocol("SOCKS5 UDP address is missing"))?;
    let (host, offset) = match kind {
        1 if packet.len() >= 7 => (
            Ipv4Addr::new(packet[1], packet[2], packet[3], packet[4]).to_string(),
            5,
        ),
        4 if packet.len() >= 19 => {
            let bytes: [u8; 16] = packet[1..17].try_into().unwrap();
            (Ipv6Addr::from(bytes).to_string(), 17)
        }
        3 if packet.len() >= 2 => {
            let end = 2 + usize::from(packet[1]);
            let host = packet
                .get(2..end)
                .ok_or_else(|| protocol("SOCKS5 UDP hostname is truncated"))?;
            (
                std::str::from_utf8(host)
                    .map_err(|_| protocol("SOCKS5 UDP hostname is invalid"))?
                    .to_owned(),
                end,
            )
        }
        _ => return Err(protocol("SOCKS5 UDP address is invalid")),
    };
    let port = packet
        .get(offset..offset + 2)
        .ok_or_else(|| protocol("SOCKS5 UDP port is truncated"))?;
    let endpoint = Endpoint {
        host,
        port: u16::from_be_bytes([port[0], port[1]]),
    };
    validate_destination(&endpoint)?;
    Ok((endpoint, offset + 2))
}

fn matches_destination(expected: &Endpoint, received: &Endpoint) -> bool {
    expected.port == received.port
        && match expected.host.parse::<IpAddr>() {
            Ok(expected) => received.host.parse::<IpAddr>() == Ok(expected),
            // Resolving an outbound hostname here would bypass remote DNS policy.
            Err(_) => {
                received.host.parse::<IpAddr>().is_ok()
                    || received.host.eq_ignore_ascii_case(&expected.host)
            }
        }
}

#[async_trait]
impl TransitDatagram for SocksDatagram {
    async fn send(&mut self, payload: &[u8]) -> Result<(), TransitError> {
        check_payload(payload, self.header.len())?;
        let mut probe = [0; 1];
        match self.control.try_read(&mut probe) {
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
            _ => return Err(connection("SOCKS5 UDP control connection closed")),
        }
        let mut packet = self.header.clone();
        packet.extend_from_slice(payload);
        self.socket
            .send(&packet)
            .await
            .map_err(|_| connection("SOCKS5 UDP send failed"))?;
        Ok(())
    }

    async fn receive(&mut self) -> Result<Vec<u8>, TransitError> {
        let mut packet = vec![0; 65_536];
        let mut control = [0; 1];
        let length = tokio::select! {
            _ = self.control.read(&mut control) => return Err(connection("SOCKS5 UDP control connection closed")),
            received = self.socket.recv(&mut packet) => received.map_err(|_| connection("SOCKS5 UDP receive failed"))?,
        };
        if length < 4 || packet[..3] != [0, 0, 0] {
            return Err(protocol(
                "SOCKS5 UDP reserved or fragment header is invalid",
            ));
        }
        let (source, offset) = decode_packet_address(&packet[3..length])?;
        if !matches_destination(&self.destination, &source) {
            return Err(protocol(
                "SOCKS5 UDP response source does not match its target",
            ));
        }
        Ok(packet[3 + offset..length].to_vec())
    }

    async fn close(mut self: Box<Self>) -> Result<(), TransitError> {
        self.control
            .shutdown()
            .await
            .map_err(|_| connection("SOCKS5 UDP control shutdown failed"))
    }
}

#[derive(Debug, Default)]
struct ReplayWindow {
    highest: Option<u64>,
    seen: u64,
}

impl ReplayWindow {
    fn accept(&mut self, packet: u64) -> bool {
        let Some(highest) = self.highest else {
            self.highest = Some(packet);
            self.seen = 1;
            return true;
        };
        if packet > highest {
            let distance = packet - highest;
            self.seen = if distance >= 64 {
                1
            } else {
                (self.seen << distance) | 1
            };
            self.highest = Some(packet);
            return true;
        }
        let distance = highest - packet;
        if distance >= 64 || self.seen & (1 << distance) != 0 {
            return false;
        }
        self.seen |= 1 << distance;
        true
    }
}

#[derive(Debug)]
struct ShadowsocksDatagram {
    socket: ProxySocket<shadowsocks::net::UdpSocket>,
    target: Address,
    destination: Endpoint,
    aead_2022: bool,
    client_session_id: u64,
    server_session_id: Option<u64>,
    packet_id: u64,
    replay: ReplayWindow,
}

pub(crate) async fn ss_connect_udp(
    context: SharedContext,
    server: &ServerConfig,
    destination: &Endpoint,
    connect_timeout: Duration,
) -> Result<BoxedTransitDatagram, TransitError> {
    validate_destination(destination)?;
    let socket = timeout(connect_timeout, ProxySocket::connect(context, server))
        .await
        .map_err(|_| connection("Shadowsocks UDP connection timed out"))?
        .map_err(|_| connection("Shadowsocks UDP connection failed"))?;
    let mut identifier = [0; 8];
    getrandom::fill(&mut identifier)
        .map_err(|_| connection("Shadowsocks UDP identifier generation failed"))?;
    let target = match destination.host.parse::<IpAddr>() {
        Ok(address) => Address::SocketAddress(SocketAddr::new(address, destination.port)),
        Err(_) => Address::DomainNameAddress(destination.host.clone(), destination.port),
    };
    Ok(Box::new(ShadowsocksDatagram {
        socket,
        target,
        destination: destination.clone(),
        aead_2022: server.method().is_aead_2022(),
        client_session_id: u64::from_be_bytes(identifier),
        server_session_id: None,
        packet_id: 0,
        replay: ReplayWindow::default(),
    }))
}

#[async_trait]
impl TransitDatagram for ShadowsocksDatagram {
    async fn send(&mut self, payload: &[u8]) -> Result<(), TransitError> {
        check_payload(payload, 512)?;
        self.packet_id = self
            .packet_id
            .checked_add(1)
            .ok_or_else(|| protocol("Shadowsocks UDP packet identifier exhausted"))?;
        let mut control = UdpSocketControlData::default();
        control.client_session_id = self.client_session_id;
        control.packet_id = self.packet_id;
        self.socket
            .send_with_ctrl(&self.target, &control, payload)
            .await
            .map_err(|_| connection("Shadowsocks UDP send failed"))?;
        Ok(())
    }

    async fn receive(&mut self) -> Result<Vec<u8>, TransitError> {
        let mut packet = vec![0; 65_536];
        let (length, source, _, control) = self
            .socket
            .recv_with_ctrl(&mut packet)
            .await
            .map_err(|_| protocol("Shadowsocks UDP response failed authentication"))?;
        let source = match source {
            Address::SocketAddress(address) => Endpoint {
                host: address.ip().to_string(),
                port: address.port(),
            },
            Address::DomainNameAddress(host, port) => Endpoint { host, port },
        };
        if !matches_destination(&self.destination, &source) {
            return Err(protocol(
                "Shadowsocks UDP response source does not match its target",
            ));
        }
        if self.aead_2022 {
            let control = control
                .ok_or_else(|| protocol("Shadowsocks 2022 UDP response lacks session metadata"))?;
            if control.client_session_id != self.client_session_id
                || self
                    .server_session_id
                    .is_some_and(|id| id != control.server_session_id)
                || !self.replay.accept(control.packet_id)
            {
                return Err(protocol(
                    "Shadowsocks 2022 UDP response session or packet identity is invalid",
                ));
            }
            self.server_session_id = Some(control.server_session_id);
        }
        packet.truncate(length);
        Ok(packet)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use shadowsocks::config::ServerType;
    use shadowsocks::context::Context;
    use shadowsocks::crypto::CipherKind;
    use tokio::net::TcpListener;
    use tokio::sync::oneshot;

    #[tokio::test]
    async fn direct_udp_preserves_datagram_boundaries() {
        timeout(Duration::from_secs(5), async {
            let target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let address = target.local_addr().unwrap();
            let server = tokio::spawn(async move {
                let mut packet = [0; 64];
                for expected in [b"one".as_slice(), b"two-two".as_slice()] {
                    let (length, peer) = target.recv_from(&mut packet).await.unwrap();
                    assert_eq!(&packet[..length], expected);
                    target.send_to(&packet[..length], peer).await.unwrap();
                }
            });
            let mut datagram = direct_connect_udp(
                &Endpoint {
                    host: address.ip().to_string(),
                    port: address.port(),
                },
                Duration::from_secs(1),
            )
            .await
            .unwrap();
            for payload in [b"one".as_slice(), b"two-two".as_slice()] {
                datagram.send(payload).await.unwrap();
                assert_eq!(datagram.receive().await.unwrap(), payload);
            }
            datagram.close().await.unwrap();
            server.await.unwrap();
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn socks_udp_preserves_remote_domain_and_keeps_control_until_close() {
        timeout(Duration::from_secs(5),async {
            let tcp=TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address=tcp.local_addr().unwrap();
            let udp=UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let relay=udp.local_addr().unwrap();
            let (closed_tx,closed_rx)=oneshot::channel();
            let server=tokio::spawn(async move {
                let (mut control,_)=tcp.accept().await.unwrap();
                let mut greeting=[0;3];
                control.read_exact(&mut greeting).await.unwrap();
                assert_eq!(greeting,[5,1,2]);
                control.write_all(&[5,2]).await.unwrap();
                let mut auth=[0;14];
                control.read_exact(&mut auth).await.unwrap();
                assert_eq!(&auth,b"\x01\x05alice\x06secret");
                control.write_all(&[1,0]).await.unwrap();
                let mut associate=[0;10];
                control.read_exact(&mut associate).await.unwrap();
                assert_eq!(&associate[..4],&[5,3,0,1]);
                let mut response=vec![5,0,0,1,0,0,0,0];
                response.extend_from_slice(&relay.port().to_be_bytes());
                control.write_all(&response).await.unwrap();
                let mut packet=[0;512];
                let (length,source)=udp.recv_from(&mut packet).await.unwrap();
                assert_eq!(&packet[..3],&[0,0,0]);
                let (target,offset)=decode_packet_address(&packet[3..length]).unwrap();
                assert_eq!(target,Endpoint{host:"remote-only.invalid".into(),port:53});
                assert_eq!(&packet[3+offset..length],b"udp-domain");
                assert!(matches!(control.try_read(&mut [0]),Err(error) if error.kind()==std::io::ErrorKind::WouldBlock));
                udp.send_to(&packet[..length],source).await.unwrap();
                assert_eq!(control.read(&mut [0]).await.unwrap(),0);
                closed_tx.send(()).unwrap();
            });
            let mut datagram=socks5_connect_udp(&Endpoint{host:address.ip().to_string(),port:address.port()},Some(&("alice".into(),"secret".into())),&Endpoint{host:"remote-only.invalid".into(),port:53},Duration::from_secs(1)).await.unwrap();
            datagram.send(b"udp-domain").await.unwrap();
            assert_eq!(datagram.receive().await.unwrap(),b"udp-domain");
            datagram.close().await.unwrap();
            closed_rx.await.unwrap();
            server.await.unwrap();
        }).await.unwrap();
    }

    #[tokio::test]
    async fn socks_udp_rejects_fragmented_relay_responses() {
        timeout(Duration::from_secs(5), async {
            let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = tcp.local_addr().unwrap();
            let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let relay = udp.local_addr().unwrap();
            let server = tokio::spawn(async move {
                let (mut control, _) = tcp.accept().await.unwrap();
                control.read_exact(&mut [0; 3]).await.unwrap();
                control.write_all(&[5, 0]).await.unwrap();
                control.read_exact(&mut [0; 10]).await.unwrap();
                let mut response = vec![5, 0, 0, 1, 127, 0, 0, 1];
                response.extend_from_slice(&relay.port().to_be_bytes());
                control.write_all(&response).await.unwrap();
                let mut packet = [0; 128];
                let (length, source) = udp.recv_from(&mut packet).await.unwrap();
                packet[2] = 1;
                udp.send_to(&packet[..length], source).await.unwrap();
                let _ = control.read(&mut [0]).await;
            });
            let mut datagram = socks5_connect_udp(
                &Endpoint {
                    host: address.ip().to_string(),
                    port: address.port(),
                },
                None,
                &Endpoint {
                    host: "127.0.0.1".into(),
                    port: 53,
                },
                Duration::from_secs(1),
            )
            .await
            .unwrap();
            datagram.send(b"fragmented").await.unwrap();
            assert!(matches!(
                datagram.receive().await,
                Err(TransitError::Protocol(_))
            ));
            datagram.close().await.unwrap();
            server.await.unwrap();
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn shadowsocks_udp_roundtrips_classic_and_2022_ciphers() {
        timeout(Duration::from_secs(10), async {
            for (method, password) in [
                (CipherKind::AES_256_GCM, "test-password"),
                (
                    CipherKind::AEAD2022_BLAKE3_AES_128_GCM,
                    "AAAAAAAAAAAAAAAAAAAAAA==",
                ),
                (
                    CipherKind::AEAD2022_BLAKE3_AES_256_GCM,
                    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                ),
                (
                    CipherKind::AEAD2022_BLAKE3_CHACHA20_POLY1305,
                    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                ),
            ] {
                let mut config = ServerConfig::new(
                    "127.0.0.1:0".parse::<SocketAddr>().unwrap(),
                    password,
                    method,
                )
                .unwrap();
                let socket = ProxySocket::bind(Context::new_shared(ServerType::Server), &config)
                    .await
                    .unwrap();
                config.set_addr(socket.local_addr().unwrap());
                let server = tokio::spawn(async move {
                    let mut packet = vec![0; 65_536];
                    for packet_id in 1..=2 {
                        let (length, peer, target, _, control) =
                            socket.recv_from_with_ctrl(&mut packet).await.unwrap();
                        assert_eq!(
                            target,
                            Address::DomainNameAddress("remote-only.invalid".into(), 53)
                        );
                        let mut response = control.unwrap_or_default();
                        response.server_session_id = 1234;
                        response.packet_id = packet_id;
                        socket
                            .send_to_with_ctrl(peer, &target, &response, &packet[..length])
                            .await
                            .unwrap();
                    }
                });
                let mut datagram = ss_connect_udp(
                    Context::new_shared(ServerType::Local),
                    &config,
                    &Endpoint {
                        host: "remote-only.invalid".into(),
                        port: 53,
                    },
                    Duration::from_secs(1),
                )
                .await
                .unwrap();
                for payload in [b"dns-one".as_slice(), b"dns-two".as_slice()] {
                    datagram.send(payload).await.unwrap();
                    assert_eq!(datagram.receive().await.unwrap(), payload);
                }
                datagram.close().await.unwrap();
                server.await.unwrap();
            }
        })
        .await
        .unwrap();
    }

    #[test]
    fn bounded_2022_replay_window_accepts_reordering_and_rejects_duplicates() {
        let mut window = ReplayWindow::default();
        assert!(window.accept(4));
        assert!(window.accept(2));
        assert!(!window.accept(2));
        assert!(window.accept(80));
        assert!(!window.accept(4));
        assert!(window.accept(79));
    }

    #[tokio::test]
    async fn shadowsocks_2022_adapter_carries_tcp_with_a_remote_hostname() {
        use crate::{
            ConnectRequest, ShadowsocksTransitAdapter, SubscriptionCredential, TransitAdapter,
        };
        use pathchord_policy::{TransitProxyConfig, TransitProxyId};
        use std::collections::BTreeMap;
        timeout(Duration::from_secs(10), async {
            let password = "AAAAAAAAAAAAAAAAAAAAAA==";
            let config = ServerConfig::new(
                "127.0.0.1:0".parse::<SocketAddr>().unwrap(),
                password,
                CipherKind::AEAD2022_BLAKE3_AES_128_GCM,
            )
            .unwrap();
            let listener =
                shadowsocks::ProxyListener::bind(Context::new_shared(ServerType::Server), &config)
                    .await
                    .unwrap();
            let address = listener.local_addr().unwrap();
            let task = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                assert_eq!(
                    stream.handshake().await.unwrap(),
                    Address::DomainNameAddress("remote-only.invalid".into(), 443)
                );
                let mut packet = [0; 8];
                stream.read_exact(&mut packet).await.unwrap();
                stream.write_all(&packet).await.unwrap();
            });
            let config = TransitProxyConfig {
                id: TransitProxyId::new("ss2022"),
                source: None,
                protocol: "ss".into(),
                endpoint: pathchord_policy::Endpoint {
                    host: address.ip().to_string(),
                    port: address.port(),
                },
                credentials_ref: None,
                options: Default::default(),
                labels: Default::default(),
                tags: Default::default(),
                weight: 100,
            };
            let credentials = SubscriptionCredential::new(BTreeMap::from([
                ("cipher".into(), "2022-blake3-aes-128-gcm".into()),
                ("password".into(), password.into()),
            ]));
            let adapter = ShadowsocksTransitAdapter::from_subscription(
                &config,
                &credentials,
                Duration::from_secs(2),
            )
            .unwrap();
            let mut stream = adapter
                .connect(ConnectRequest {
                    destination: Endpoint {
                        host: "remote-only.invalid".into(),
                        port: 443,
                    },
                })
                .await
                .unwrap();
            stream.write_all(b"ss2022ok").await.unwrap();
            let mut packet = [0; 8];
            stream.read_exact(&mut packet).await.unwrap();
            assert_eq!(&packet, b"ss2022ok");
            task.await.unwrap();
        })
        .await
        .unwrap();
    }
}
