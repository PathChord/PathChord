//! Replaceable Transit Proxy adapter boundary.
//!
//! Phase 0 defines how direct and fake adapters plug in. It intentionally does
//! not implement a concrete proxy protocol or subscription format.

use std::collections::BTreeMap;
use std::time::Duration;

use async_trait::async_trait;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpStream, lookup_host};
use tokio::time::timeout;

pub trait TransitConnection: AsyncRead + AsyncWrite + Send + Unpin {}

impl<T> TransitConnection for T where T: AsyncRead + AsyncWrite + Send + Unpin {}

pub type BoxedTransitConnection = Box<dyn TransitConnection>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoint {
    pub host: String,
    pub port: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdapterKind {
    Direct,
    ExternalProxy { protocol: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransitMetadata {
    pub adapter_id: String,
    pub kind: AdapterKind,
    pub labels: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectRequest {
    /// The Egress endpoint for Egress mode, or final target for ordinary mode.
    pub destination: Endpoint,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum TransitError {
    #[error("Transit adapter does not support this request: {0}")]
    Unsupported(String),
    #[error("Transit connection failed: {0}")]
    Connection(String),
}

#[async_trait]
pub trait TransitAdapter: Send + Sync {
    fn metadata(&self) -> &TransitMetadata;

    async fn connect(
        &self,
        request: ConnectRequest,
    ) -> Result<BoxedTransitConnection, TransitError>;
}

/// Direct TCP Transit adapter.
///
/// This owns only the byte connection. Noise records and PathChord frames are
/// layered above it by the Path/session owner.
#[derive(Debug, Clone)]
pub struct DirectTransitAdapter {
    metadata: TransitMetadata,
    connect_timeout: Duration,
}

impl DirectTransitAdapter {
    #[must_use]
    pub fn new(adapter_id: impl Into<String>, connect_timeout: Duration) -> Self {
        Self {
            metadata: TransitMetadata {
                adapter_id: adapter_id.into(),
                kind: AdapterKind::Direct,
                labels: BTreeMap::new(),
            },
            connect_timeout,
        }
    }

    async fn connect_address(
        &self,
        address: std::net::SocketAddr,
    ) -> Result<TcpStream, TransitError> {
        timeout(self.connect_timeout, TcpStream::connect(address))
            .await
            .map_err(|_| TransitError::Connection("direct Transit connection timed out".into()))?
            .map_err(|_| TransitError::Connection("direct Transit connection failed".into()))
    }
}

#[async_trait]
impl TransitAdapter for DirectTransitAdapter {
    fn metadata(&self) -> &TransitMetadata {
        &self.metadata
    }

    async fn connect(
        &self,
        request: ConnectRequest,
    ) -> Result<BoxedTransitConnection, TransitError> {
        if request.destination.host.is_empty() {
            return Err(TransitError::Unsupported(
                "direct Transit destination host is empty".into(),
            ));
        }
        if request.destination.port == 0 {
            return Err(TransitError::Unsupported(
                "direct Transit destination port is zero".into(),
            ));
        }
        let addresses = lookup_host((request.destination.host.as_str(), request.destination.port))
            .await
            .map_err(|_| {
                TransitError::Connection("direct Transit name resolution failed".into())
            })?;
        let mut last_error = None;
        for address in addresses {
            match self.connect_address(address).await {
                Ok(stream) => return Ok(Box::new(stream)),
                Err(error) => last_error = Some(error),
            }
        }
        Err(last_error.unwrap_or_else(|| {
            TransitError::Connection("direct Transit returned no addresses".into())
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::net::TcpListener;

    struct FakeAdapter {
        metadata: TransitMetadata,
    }

    #[async_trait]
    impl TransitAdapter for FakeAdapter {
        fn metadata(&self) -> &TransitMetadata {
            &self.metadata
        }

        async fn connect(
            &self,
            _request: ConnectRequest,
        ) -> Result<BoxedTransitConnection, TransitError> {
            let (client, _server) = tokio::io::duplex(64);
            Ok(Box::new(client))
        }
    }

    #[tokio::test]
    async fn fake_adapter_uses_the_same_boundary_as_future_real_adapters() {
        let adapter = FakeAdapter {
            metadata: TransitMetadata {
                adapter_id: "fake-1".into(),
                kind: AdapterKind::ExternalProxy {
                    protocol: "fake".into(),
                },
                labels: BTreeMap::new(),
            },
        };

        let connection = adapter
            .connect(ConnectRequest {
                destination: Endpoint {
                    host: "egress.example.net".into(),
                    port: 443,
                },
            })
            .await
            .expect("fake connection");

        assert_eq!(adapter.metadata().adapter_id, "fake-1");
        drop(connection);
    }

    #[tokio::test]
    async fn direct_adapter_connects_to_a_tcp_endpoint_with_a_bound() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("target bind");
        let address = listener.local_addr().expect("target address");
        let accepted = tokio::spawn(async move { listener.accept().await.expect("accept") });
        let adapter = DirectTransitAdapter::new("direct-test", Duration::from_secs(1));
        let connection = adapter
            .connect(ConnectRequest {
                destination: Endpoint {
                    host: address.ip().to_string(),
                    port: address.port(),
                },
            })
            .await
            .expect("direct connection");
        assert_eq!(adapter.metadata().kind, AdapterKind::Direct);
        drop(connection);
        accepted.await.expect("accepted task");
    }

    #[tokio::test]
    async fn direct_adapter_rejects_invalid_destination() {
        let adapter = DirectTransitAdapter::new("direct-test", Duration::from_secs(1));
        assert!(matches!(
            adapter
                .connect(ConnectRequest {
                    destination: Endpoint {
                        host: String::new(),
                        port: 443,
                    },
                })
                .await,
            Err(TransitError::Unsupported(_))
        ));
    }
}
