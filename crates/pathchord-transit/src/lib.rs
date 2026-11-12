//! Replaceable Transit Proxy adapter boundary.
//!
//! Phase 0 defines how direct and fake adapters plug in. It intentionally does
//! not implement a concrete proxy protocol or subscription format.

use std::collections::BTreeMap;

use async_trait::async_trait;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite};

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

#[cfg(test)]
mod tests {
    use super::*;

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
}
