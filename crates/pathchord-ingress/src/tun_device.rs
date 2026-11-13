//! TUN packet-device lifecycle and packet-to-flow seam.

use std::future::Future;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use thiserror::Error;
use tokio::sync::mpsc;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunDeviceConfig {
    pub name: String,
    pub address: IpAddr,
    pub prefix: u8,
    pub mtu: u16,
}

impl TunDeviceConfig {
    pub fn parse(
        name: impl Into<String>,
        address: &str,
        mtu: u16,
    ) -> Result<Self, PacketDeviceError> {
        let (address, prefix) = address
            .split_once('/')
            .ok_or(PacketDeviceError::InvalidAddress)?;
        let address = address
            .parse::<IpAddr>()
            .map_err(|_| PacketDeviceError::InvalidAddress)?;
        let prefix = prefix
            .parse::<u8>()
            .map_err(|_| PacketDeviceError::InvalidAddress)?;
        if (address.is_ipv4() && prefix > 32)
            || (address.is_ipv6() && prefix > 128)
            || !(576..=u16::MAX).contains(&mtu)
        {
            return Err(PacketDeviceError::InvalidAddress);
        }
        let name = name.into();
        if name.is_empty() {
            return Err(PacketDeviceError::InvalidName);
        }
        Ok(Self {
            name,
            address,
            prefix,
            mtu,
        })
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum PacketDeviceError {
    #[error("TUN interface name is invalid")]
    InvalidName,
    #[error("TUN address, prefix, or MTU is invalid")]
    InvalidAddress,
    #[error("TUN device I/O failed: {0}")]
    Io(String),
    #[error("packet flow engine failed: {0}")]
    Flow(String),
    #[error("fake packet device is closed")]
    Closed,
}

#[async_trait]
pub trait PacketDevice: std::fmt::Debug + Send + Sync {
    fn mtu(&self) -> usize;

    async fn receive_packet(&self) -> Result<Vec<u8>, PacketDeviceError>;

    async fn send_packet(&self, packet: &[u8]) -> Result<(), PacketDeviceError>;
}

/// Mature TCP/IP engines implement this seam; PathChord does not reconstruct
/// TCP or UDP directly from IP packets in the platform adapter.
#[async_trait]
pub trait PacketFlowEngine: std::fmt::Debug + Send + Sync {
    async fn ingest_packet(&self, packet: Vec<u8>) -> Result<Vec<Vec<u8>>, PacketDeviceError>;
}

pub struct TunRsPacketDevice {
    device: tun_rs::AsyncDevice,
    mtu: usize,
}

impl std::fmt::Debug for TunRsPacketDevice {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TunRsPacketDevice")
            .field("mtu", &self.mtu)
            .finish_non_exhaustive()
    }
}

impl TunRsPacketDevice {
    pub fn create(config: &TunDeviceConfig) -> Result<Self, PacketDeviceError> {
        let mut builder = tun_rs::DeviceBuilder::new()
            .name(config.name.clone())
            .mtu(config.mtu);
        builder = match config.address {
            IpAddr::V4(address) => builder.ipv4(address, config.prefix, None),
            IpAddr::V6(address) => builder.ipv6(address, config.prefix),
        };
        let device = builder
            .build_async()
            .map_err(|error| PacketDeviceError::Io(error.to_string()))?;
        Ok(Self {
            device,
            mtu: usize::from(config.mtu),
        })
    }
}

#[async_trait]
impl PacketDevice for TunRsPacketDevice {
    fn mtu(&self) -> usize {
        self.mtu
    }

    async fn receive_packet(&self) -> Result<Vec<u8>, PacketDeviceError> {
        let mut packet = vec![0_u8; self.mtu];
        let length = self
            .device
            .recv(&mut packet)
            .await
            .map_err(|error| PacketDeviceError::Io(error.to_string()))?;
        packet.truncate(length);
        Ok(packet)
    }

    async fn send_packet(&self, packet: &[u8]) -> Result<(), PacketDeviceError> {
        if packet.len() > self.mtu {
            return Err(PacketDeviceError::Io(
                "packet exceeds configured MTU".to_owned(),
            ));
        }
        let written = self
            .device
            .send(packet)
            .await
            .map_err(|error| PacketDeviceError::Io(error.to_string()))?;
        if written != packet.len() {
            return Err(PacketDeviceError::Io("partial TUN packet write".to_owned()));
        }
        Ok(())
    }
}

#[derive(Debug)]
pub struct FakePacketDevice {
    mtu: usize,
    inbound: tokio::sync::Mutex<mpsc::Receiver<Vec<u8>>>,
    injector: mpsc::Sender<Vec<u8>>,
    outbound: Mutex<Vec<Vec<u8>>>,
}

impl FakePacketDevice {
    #[must_use]
    pub fn new(mtu: usize, capacity: usize) -> Arc<Self> {
        let (injector, inbound) = mpsc::channel(capacity.max(1));
        Arc::new(Self {
            mtu,
            inbound: tokio::sync::Mutex::new(inbound),
            injector,
            outbound: Mutex::new(Vec::new()),
        })
    }

    pub async fn inject(&self, packet: Vec<u8>) -> Result<(), PacketDeviceError> {
        self.injector
            .send(packet)
            .await
            .map_err(|_| PacketDeviceError::Closed)
    }

    #[must_use]
    pub fn outbound(&self) -> Vec<Vec<u8>> {
        self.outbound
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    pub fn take_outbound(&self) -> Vec<Vec<u8>> {
        std::mem::take(
            &mut *self
                .outbound
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        )
    }
}

#[async_trait]
impl PacketDevice for FakePacketDevice {
    fn mtu(&self) -> usize {
        self.mtu
    }

    async fn receive_packet(&self) -> Result<Vec<u8>, PacketDeviceError> {
        self.inbound
            .lock()
            .await
            .recv()
            .await
            .ok_or(PacketDeviceError::Closed)
    }

    async fn send_packet(&self, packet: &[u8]) -> Result<(), PacketDeviceError> {
        if packet.len() > self.mtu {
            return Err(PacketDeviceError::Io(
                "packet exceeds configured MTU".to_owned(),
            ));
        }
        self.outbound
            .lock()
            .map_err(|_| PacketDeviceError::Closed)?
            .push(packet.to_vec());
        Ok(())
    }
}

pub async fn run_packet_device<D, E, F>(
    device: Arc<D>,
    engine: Arc<E>,
    shutdown: F,
) -> Result<(), PacketDeviceError>
where
    D: PacketDevice + 'static,
    E: PacketFlowEngine + 'static,
    F: Future<Output = ()> + Send,
{
    let mut shutdown = Box::pin(shutdown);
    loop {
        let packet = tokio::select! {
            () = shutdown.as_mut() => return Ok(()),
            packet = device.receive_packet() => packet?,
        };
        let responses = tokio::select! {
            () = shutdown.as_mut() => return Ok(()),
            responses = engine.ingest_packet(packet) => responses?,
        };
        for response in responses {
            tokio::select! {
                () = shutdown.as_mut() => return Ok(()),
                result = device.send_packet(&response) => result?,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::oneshot;

    #[derive(Debug)]
    struct EchoEngine;

    #[async_trait]
    impl PacketFlowEngine for EchoEngine {
        async fn ingest_packet(
            &self,
            mut packet: Vec<u8>,
        ) -> Result<Vec<Vec<u8>>, PacketDeviceError> {
            packet.reverse();
            Ok(vec![packet])
        }
    }

    #[test]
    fn validates_tun_configuration() {
        let config = TunDeviceConfig::parse("PathChord", "198.18.0.1/30", 1500).unwrap();
        assert_eq!(config.address, "198.18.0.1".parse::<IpAddr>().unwrap());
        assert_eq!(config.prefix, 30);
        assert_eq!(config.mtu, 1500);
        assert!(TunDeviceConfig::parse("", "198.18.0.1/30", 1500).is_err());
        assert!(TunDeviceConfig::parse("PathChord", "198.18.0.1/33", 1500).is_err());
    }

    #[tokio::test]
    async fn fake_device_exercises_packet_flow_and_shutdown() {
        let device = FakePacketDevice::new(1500, 4);
        let (shutdown, signal) = oneshot::channel();
        let runner = tokio::spawn(run_packet_device(
            Arc::clone(&device),
            Arc::new(EchoEngine),
            async move {
                let _ = signal.await;
            },
        ));
        device.inject(vec![1, 2, 3, 4]).await.unwrap();
        for _ in 0..100 {
            if !device.outbound().is_empty() {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert_eq!(device.outbound(), vec![vec![4, 3, 2, 1]]);
        shutdown.send(()).unwrap();
        runner.await.unwrap().unwrap();
    }
}
