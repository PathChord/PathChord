//! Linux TPROXY UDP adapter preserving datagram and original-destination metadata.

use std::io::IoSliceMut;
use std::net::{IpAddr, SocketAddr, SocketAddrV6};
use std::os::fd::AsRawFd;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use nix::errno::Errno;
use nix::sys::socket::sockopt::{IpTransparent, Ipv4OrigDstAddr, Ipv6OrigDstAddr};
use nix::sys::socket::{
    ControlMessageOwned, MsgFlags, SockaddrIn, SockaddrIn6, SockaddrStorage, recvmsg, setsockopt,
};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use tokio::sync::mpsc;

use crate::ProtectedEndpointSet;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransparentDatagram {
    pub source: SocketAddr,
    pub target: SocketAddr,
    pub payload: Vec<u8>,
}

#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum TransparentUdpError {
    #[error("transparent UDP socket I/O failed: {0}")]
    Io(String),
    #[error("transparent UDP datagram did not contain an original destination")]
    MissingOriginalDestination,
    #[error("transparent UDP datagram source address is unavailable")]
    MissingSource,
    #[error("transparent UDP target is protected from interception")]
    ProtectedTarget,
    #[error("transparent UDP datagram exceeds the configured payload bound")]
    Oversized,
    #[error("transparent UDP socket is not currently readable")]
    WouldBlock,
}

#[async_trait]
pub trait TransparentUdpAdapter: std::fmt::Debug + Send + Sync {
    async fn receive(&self) -> Result<TransparentDatagram, TransparentUdpError>;

    async fn send(&self, datagram: &TransparentDatagram) -> Result<(), TransparentUdpError>;
}

#[derive(Debug)]
pub struct FakeTransparentUdpAdapter {
    inbound: tokio::sync::Mutex<mpsc::Receiver<TransparentDatagram>>,
    injector: mpsc::Sender<TransparentDatagram>,
    sent: Mutex<Vec<TransparentDatagram>>,
}

impl FakeTransparentUdpAdapter {
    #[must_use]
    pub fn new(capacity: usize) -> Arc<Self> {
        let (injector, inbound) = mpsc::channel(capacity.max(1));
        Arc::new(Self {
            inbound: tokio::sync::Mutex::new(inbound),
            injector,
            sent: Mutex::new(Vec::new()),
        })
    }

    pub async fn inject(&self, datagram: TransparentDatagram) -> Result<(), TransparentUdpError> {
        self.injector
            .send(datagram)
            .await
            .map_err(|_| TransparentUdpError::Io("fake UDP adapter is closed".to_owned()))
    }

    #[must_use]
    pub fn sent(&self) -> Vec<TransparentDatagram> {
        self.sent
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }
}

#[async_trait]
impl TransparentUdpAdapter for FakeTransparentUdpAdapter {
    async fn receive(&self) -> Result<TransparentDatagram, TransparentUdpError> {
        self.inbound
            .lock()
            .await
            .recv()
            .await
            .ok_or_else(|| TransparentUdpError::Io("fake UDP adapter is closed".to_owned()))
    }

    async fn send(&self, datagram: &TransparentDatagram) -> Result<(), TransparentUdpError> {
        self.sent
            .lock()
            .map_err(|_| TransparentUdpError::Io("fake UDP adapter lock poisoned".to_owned()))?
            .push(datagram.clone());
        Ok(())
    }
}

#[derive(Debug)]
pub struct LinuxTproxyUdpSocket {
    socket: tokio::net::UdpSocket,
    protected: ProtectedEndpointSet,
    max_payload: usize,
}

impl LinuxTproxyUdpSocket {
    pub fn bind(
        bind: SocketAddr,
        protected: ProtectedEndpointSet,
        max_payload: usize,
    ) -> Result<Self, TransparentUdpError> {
        if max_payload == 0 || max_payload > u16::MAX as usize {
            return Err(TransparentUdpError::Oversized);
        }
        let socket = transparent_datagram_socket(bind)?;
        match bind.ip() {
            IpAddr::V4(_) => setsockopt(&socket, Ipv4OrigDstAddr, &true),
            IpAddr::V6(_) => setsockopt(&socket, Ipv6OrigDstAddr, &true),
        }
        .map_err(|error| TransparentUdpError::Io(error.to_string()))?;
        socket
            .bind(&SockAddr::from(bind))
            .map_err(|error| TransparentUdpError::Io(error.to_string()))?;
        socket
            .set_nonblocking(true)
            .map_err(|error| TransparentUdpError::Io(error.to_string()))?;
        let socket = tokio::net::UdpSocket::from_std(socket.into())
            .map_err(|error| TransparentUdpError::Io(error.to_string()))?;
        Ok(Self {
            socket,
            protected,
            max_payload,
        })
    }

    fn receive_ready(&self) -> Result<TransparentDatagram, TransparentUdpError> {
        let mut payload = vec![0_u8; self.max_payload];
        let mut iov = [IoSliceMut::new(&mut payload)];
        let mut control = nix::cmsg_space!(nix::libc::sockaddr_in, nix::libc::sockaddr_in6);
        let message = match recvmsg::<SockaddrStorage>(
            self.socket.as_raw_fd(),
            &mut iov,
            Some(&mut control),
            MsgFlags::MSG_DONTWAIT,
        ) {
            Ok(message) => message,
            Err(Errno::EAGAIN) => return Err(TransparentUdpError::WouldBlock),
            Err(error) => return Err(TransparentUdpError::Io(error.to_string())),
        };
        if message.flags.contains(MsgFlags::MSG_TRUNC) {
            return Err(TransparentUdpError::Oversized);
        }
        let length = message.bytes;
        let source = message
            .address
            .as_ref()
            .and_then(storage_socket_addr)
            .ok_or(TransparentUdpError::MissingSource)?;
        let mut target = None;
        for control in message
            .cmsgs()
            .map_err(|error| TransparentUdpError::Io(error.to_string()))?
        {
            match control {
                ControlMessageOwned::Ipv4OrigDstAddr(address) => {
                    let address = SockaddrIn::from(address);
                    target = Some(SocketAddr::new(IpAddr::V4(address.ip()), address.port()));
                }
                ControlMessageOwned::Ipv6OrigDstAddr(address) => {
                    let address = SockaddrIn6::from(address);
                    target = Some(SocketAddr::V6(SocketAddrV6::new(
                        address.ip(),
                        address.port(),
                        address.flowinfo(),
                        address.scope_id(),
                    )));
                }
                _ => {}
            }
        }
        let target = target.ok_or(TransparentUdpError::MissingOriginalDestination)?;
        if self.protected.contains(&target) {
            return Err(TransparentUdpError::ProtectedTarget);
        }
        payload.truncate(length);
        Ok(TransparentDatagram {
            source,
            target,
            payload,
        })
    }
}

#[async_trait]
impl TransparentUdpAdapter for LinuxTproxyUdpSocket {
    async fn receive(&self) -> Result<TransparentDatagram, TransparentUdpError> {
        loop {
            self.socket
                .readable()
                .await
                .map_err(|error| TransparentUdpError::Io(error.to_string()))?;
            match self.receive_ready() {
                Err(TransparentUdpError::WouldBlock) => {}
                result => return result,
            }
        }
    }

    async fn send(&self, datagram: &TransparentDatagram) -> Result<(), TransparentUdpError> {
        if datagram.payload.len() > self.max_payload {
            return Err(TransparentUdpError::Oversized);
        }
        let socket = transparent_datagram_socket(datagram.target)?;
        socket
            .set_reuse_address(true)
            .map_err(|error| TransparentUdpError::Io(error.to_string()))?;
        #[cfg(unix)]
        socket
            .set_reuse_port(true)
            .map_err(|error| TransparentUdpError::Io(error.to_string()))?;
        socket
            .bind(&SockAddr::from(datagram.target))
            .map_err(|error| TransparentUdpError::Io(error.to_string()))?;
        socket
            .set_nonblocking(true)
            .map_err(|error| TransparentUdpError::Io(error.to_string()))?;
        let socket = tokio::net::UdpSocket::from_std(socket.into())
            .map_err(|error| TransparentUdpError::Io(error.to_string()))?;
        let sent = socket
            .send_to(&datagram.payload, datagram.source)
            .await
            .map_err(|error| TransparentUdpError::Io(error.to_string()))?;
        if sent != datagram.payload.len() {
            return Err(TransparentUdpError::Io(
                "partial transparent UDP datagram write".to_owned(),
            ));
        }
        Ok(())
    }
}

fn transparent_datagram_socket(address: SocketAddr) -> Result<Socket, TransparentUdpError> {
    let domain = if address.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))
        .map_err(|error| TransparentUdpError::Io(error.to_string()))?;
    socket
        .set_reuse_address(true)
        .map_err(|error| TransparentUdpError::Io(error.to_string()))?;
    setsockopt(&socket, IpTransparent, &true)
        .map_err(|error| TransparentUdpError::Io(error.to_string()))?;
    Ok(socket)
}

fn storage_socket_addr(storage: &SockaddrStorage) -> Option<SocketAddr> {
    if let Some(address) = storage.as_sockaddr_in() {
        return Some(SocketAddr::new(IpAddr::V4(address.ip()), address.port()));
    }
    storage.as_sockaddr_in6().map(|address| {
        SocketAddr::V6(SocketAddrV6::new(
            address.ip(),
            address.port(),
            address.flowinfo(),
            address.scope_id(),
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn sockaddr_conversion_preserves_ipv4_and_ipv6() {
        let v4 = SockaddrStorage::from(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            8080,
        ));
        assert_eq!(
            storage_socket_addr(&v4),
            Some("192.0.2.1:8080".parse().unwrap())
        );

        let v6 = SockaddrStorage::from(SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 5353));
        assert_eq!(
            storage_socket_addr(&v6),
            Some("[::1]:5353".parse().unwrap())
        );
    }

    #[tokio::test]
    async fn fake_adapter_preserves_datagram_boundaries_and_addresses() {
        let adapter = FakeTransparentUdpAdapter::new(2);
        let datagram = TransparentDatagram {
            source: "192.0.2.10:12345".parse().unwrap(),
            target: "198.51.100.20:53".parse().unwrap(),
            payload: vec![1, 2, 3, 4],
        };
        adapter.inject(datagram.clone()).await.unwrap();
        assert_eq!(adapter.receive().await.unwrap(), datagram);
        adapter.send(&datagram).await.unwrap();
        assert_eq!(adapter.sent(), vec![datagram]);
    }
}
