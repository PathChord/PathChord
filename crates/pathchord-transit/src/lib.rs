//! Replaceable Transit Proxy adapter boundary.
//!
//! Byte transports and dynamic Transit Proxy subscription normalization.

use std::collections::BTreeMap;
use std::fmt;
use std::time::Duration;

use async_trait::async_trait;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpStream, lookup_host};
use tokio::time::timeout;
use zeroize::Zeroize;

mod adapter_registry;
// The codec is intentionally kept ready for the native AnyTLS adapter while
// its TLS/session handshake is completed; it is not registered as a node
// backend until an interop fixture covers the full session lifecycle.
#[allow(dead_code)]
mod anytls_adapter;
#[allow(dead_code)]
mod anytls_codec;
mod credential_provider;
mod datagram;
mod http_connect_adapter;
#[allow(dead_code)]
mod hysteria2_codec;
mod native_protocol;
mod native_transport;
#[allow(dead_code)]
mod reality_codec;
mod shadowsocks_adapter;
mod socks5_adapter;
mod subscription;
mod tls;
#[allow(dead_code)]
mod tuic_codec;
mod vmess;

pub use adapter_registry::AdapterRegistry;
pub use credential_provider::FileTransitCredentialProvider;
pub use http_connect_adapter::{HttpConnectTransitAdapter, HttpsConnectTransitAdapter};
pub use shadowsocks_adapter::ShadowsocksTransitAdapter;
pub use socks5_adapter::Socks5TransitAdapter;
pub use subscription::{
    CacheLoadOutcome, DynamicNodeState, DynamicTransitNode, DynamicTransitSnapshot,
    HttpSubscriptionFetcher, MAX_SUBSCRIPTION_BYTES, MAX_SUBSCRIPTION_NODES,
    NoSubscriptionCredentials, NodeDiagnostic, NodeUnavailableReason, RefreshOutcome, SnapshotDiff,
    SubscriptionCredential, SubscriptionCredentialProvider, SubscriptionDocument,
    SubscriptionError, SubscriptionFetchRequest, SubscriptionFetcher, SubscriptionManager,
    SubscriptionUsage,
};

pub trait TransitConnection: AsyncRead + AsyncWrite + Send + Unpin {}

impl<T> TransitConnection for T where T: AsyncRead + AsyncWrite + Send + Unpin {}

pub type BoxedTransitConnection = Box<dyn TransitConnection>;

#[async_trait]
pub trait TransitDatagram: std::fmt::Debug + Send {
    async fn send(&mut self, payload: &[u8]) -> Result<(), TransitError>;
    async fn receive(&mut self) -> Result<Vec<u8>, TransitError>;
    async fn close(self: Box<Self>) -> Result<(), TransitError> {
        Ok(())
    }
}

pub type BoxedTransitDatagram = Box<dyn TransitDatagram>;

#[derive(Clone, Default, PartialEq, Eq)]
pub struct TransitCredential {
    fields: BTreeMap<String, String>,
}

impl fmt::Debug for TransitCredential {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TransitCredential")
            .field("field_names", &self.fields.keys().collect::<Vec<_>>())
            .finish_non_exhaustive()
    }
}

impl Drop for TransitCredential {
    fn drop(&mut self) {
        for value in self.fields.values_mut() {
            value.zeroize();
        }
    }
}

impl TransitCredential {
    #[must_use]
    pub fn new(fields: BTreeMap<String, String>) -> Self {
        Self { fields }
    }

    #[must_use]
    pub fn field(&self, name: &str) -> Option<&str> {
        self.fields.get(name).map(String::as_str)
    }

    pub(crate) fn fields(&self) -> BTreeMap<String, String> {
        self.fields.clone()
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.fields.is_empty()
    }
}

#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum TransitCredentialError {
    #[error("Transit credential provider is unavailable")]
    Unavailable,
    #[error("Transit credential reference is invalid")]
    InvalidReference,
    #[error("Transit credential file is not a regular non-symlink file")]
    UnsafeFileType,
    #[error("Transit credential file permissions are too broad")]
    InsecurePermissions,
    #[error("Transit credential file exceeds the size bound")]
    TooLarge,
    #[error("Transit credential document is invalid")]
    InvalidDocument,
    #[error("Transit credential file I/O failed")]
    Io,
}

#[async_trait]
pub trait TransitCredentialProvider: Send + Sync {
    async fn resolve(
        &self,
        reference: &str,
    ) -> Result<Option<TransitCredential>, TransitCredentialError>;
}

#[derive(Debug, Clone, Copy, Default)]
pub struct NoTransitCredentials;

#[async_trait]
impl TransitCredentialProvider for NoTransitCredentials {
    async fn resolve(
        &self,
        _reference: &str,
    ) -> Result<Option<TransitCredential>, TransitCredentialError> {
        Ok(None)
    }
}

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
    #[error("Transit adapter {protocol} is unavailable: {reason}")]
    AdapterUnavailable {
        protocol: String,
        reason: &'static str,
    },
    #[error("Transit credential reference is unavailable: {reference}")]
    CredentialUnavailable { reference: String },
    #[error("Transit credential provider failed")]
    CredentialProvider,
    #[error("Transit proxy protocol failed: {0}")]
    Protocol(String),
}

#[async_trait]
pub trait TransitAdapter: Send + Sync {
    fn metadata(&self) -> &TransitMetadata;

    fn supports_tcp(&self) -> bool {
        true
    }

    /// Validates the native adapter before publishing it to runtime.
    async fn prepare(&self) -> Result<(), TransitError> {
        Ok(())
    }

    fn supports_udp(&self) -> bool {
        false
    }

    async fn connect_udp(
        &self,
        _request: ConnectRequest,
    ) -> Result<BoxedTransitDatagram, TransitError> {
        Err(TransitError::Unsupported(
            "this Transit adapter does not support UDP".to_owned(),
        ))
    }

    async fn connect(
        &self,
        request: ConnectRequest,
    ) -> Result<BoxedTransitConnection, TransitError>;
}

pub(crate) async fn connect_tcp_endpoint(
    endpoint: &Endpoint,
    connect_timeout: Duration,
) -> Result<TcpStream, TransitError> {
    if endpoint.host.is_empty() || endpoint.port == 0 {
        return Err(TransitError::Unsupported(
            "Transit endpoint is invalid".to_owned(),
        ));
    }
    let addresses = lookup_host((endpoint.host.as_str(), endpoint.port))
        .await
        .map_err(|_| TransitError::Connection("Transit endpoint resolution failed".into()))?;
    let mut last_error = None;
    for address in addresses {
        match timeout(connect_timeout, TcpStream::connect(address)).await {
            Ok(Ok(stream)) => return Ok(stream),
            Ok(Err(_)) => last_error = Some("Transit endpoint connection failed"),
            Err(_) => last_error = Some("Transit endpoint connection timed out"),
        }
    }
    Err(TransitError::Connection(
        last_error
            .unwrap_or("Transit endpoint returned no addresses")
            .to_owned(),
    ))
}

pub(crate) fn validate_destination(destination: &Endpoint) -> Result<(), TransitError> {
    if destination.host.is_empty()
        || destination.port == 0
        || destination.host.len() > 255
        || destination
            .host
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
    {
        return Err(TransitError::Unsupported(
            "Transit destination is invalid".to_owned(),
        ));
    }
    Ok(())
}

/// Direct TCP Transit adapter.
///
/// This owns only the byte connection. Noise records and PathChord frames are
/// layered above it by the Path/session owner.
#[derive(Debug, Clone)]
pub struct DirectTransitAdapter {
    metadata: TransitMetadata,
    connect_timeout: Duration,
    udp_enabled: bool,
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
            udp_enabled: true,
        }
    }

    #[must_use]
    pub fn with_udp_enabled(mut self, enabled: bool) -> Self {
        self.udp_enabled = enabled;
        self
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

    fn supports_udp(&self) -> bool {
        self.udp_enabled
    }

    async fn connect_udp(
        &self,
        request: ConnectRequest,
    ) -> Result<BoxedTransitDatagram, TransitError> {
        if !self.udp_enabled {
            return Err(TransitError::Unsupported(
                "UDP is disabled for this node".to_owned(),
            ));
        }
        datagram::direct_connect_udp(&request.destination, self.connect_timeout).await
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
