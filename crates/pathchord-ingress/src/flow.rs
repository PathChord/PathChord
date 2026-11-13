//! Transport-neutral direct TCP flow bridging.
//!
//! Listener adapters stop after producing an [`AcceptedConnection`]. This
//! module owns the narrow next step: an injected target dialer supplies a
//! target byte stream, and Tokio copies bytes in both directions. Session and
//! Path multiplexing remain outside this direct bridge.

use async_trait::async_trait;
use pathchord_core::ErrorClass;
use std::sync::Mutex;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, copy_bidirectional};

use crate::{AcceptedConnection, BoxedLocalConnection, ConnectionContext, ConnectionResponse};

const HTTP_CONNECTED: &[u8] = b"HTTP/1.1 200 Connection Established\r\n\r\n";
const HTTP_FORBIDDEN: &[u8] = b"HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n";
const HTTP_BAD_GATEWAY: &[u8] = b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n";
const HTTP_UNAVAILABLE: &[u8] = b"HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\n\r\n";

#[derive(Debug, Error, PartialEq, Eq)]
pub enum FlowBridgeError {
    #[error("local policy rejected the TCP flow")]
    PolicyRejected,
    #[error("no usable route is available for the TCP flow")]
    NoUsableRoute,
    #[error("PathChord Session is unavailable")]
    SessionUnavailable,
    #[error("Egress rejected the Stream with {error:?}")]
    EgressRejected { error: ErrorClass, reason: Vec<u8> },
    #[error("TCP flow resource limit is exhausted")]
    ResourceLimit,
    #[error("TCP flow runtime is shutting down")]
    ShuttingDown,
    #[error("target dial failed: {0}")]
    Dial(String),
    #[error("local proxy response failed: {0}")]
    Reply(String),
    #[error("TCP flow copy failed: {0}")]
    Copy(String),
}

/// Opens one TCP flow using the complete policy and target context.
#[async_trait]
pub trait TcpFlowOpener: Send + Sync {
    async fn connect(
        &self,
        context: ConnectionContext,
    ) -> Result<BoxedLocalConnection, FlowBridgeError>;
}

/// Compatibility name retained for existing embedders.
pub use TcpFlowOpener as IngressTargetDialer;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FlowBridgeStats {
    pub local_to_target_bytes: u64,
    pub target_to_local_bytes: u64,
}

/// Dials the accepted target and copies the flow in both directions.
///
/// `copy_bidirectional` preserves EOF propagation and half-close behavior for
/// the two stream halves. The target connection is not recreated after a
/// failure; the caller owns retry/session policy.
pub async fn bridge_connection<D>(
    accepted: AcceptedConnection,
    dialer: &D,
) -> Result<FlowBridgeStats, FlowBridgeError>
where
    D: IngressTargetDialer + ?Sized,
{
    let AcceptedConnection {
        mut io,
        context,
        response,
    } = accepted;
    let mut target = match dialer.connect(context).await {
        Ok(target) => {
            send_success(&mut io, response).await?;
            target
        }
        Err(error) => {
            send_failure(&mut io, response, &error).await?;
            return Err(error);
        }
    };
    let (local_to_target_bytes, target_to_local_bytes) = copy_bidirectional(&mut io, &mut target)
        .await
        .map_err(|error| FlowBridgeError::Copy(error.to_string()))?;
    Ok(FlowBridgeStats {
        local_to_target_bytes,
        target_to_local_bytes,
    })
}

async fn send_success(
    io: &mut BoxedLocalConnection,
    response: ConnectionResponse,
) -> Result<(), FlowBridgeError> {
    let bytes: &[u8] = match response {
        ConnectionResponse::None => return Ok(()),
        ConnectionResponse::HttpConnect => HTTP_CONNECTED,
        ConnectionResponse::Socks5 => &[5, 0, 0, 1, 0, 0, 0, 0, 0, 0],
    };
    io.write_all(bytes)
        .await
        .map_err(|error| FlowBridgeError::Reply(error.to_string()))?;
    io.flush()
        .await
        .map_err(|error| FlowBridgeError::Reply(error.to_string()))
}

async fn send_failure(
    io: &mut BoxedLocalConnection,
    response: ConnectionResponse,
    error: &FlowBridgeError,
) -> Result<(), FlowBridgeError> {
    let bytes: &[u8] = match response {
        ConnectionResponse::None => return Ok(()),
        ConnectionResponse::HttpConnect => match error {
            FlowBridgeError::PolicyRejected => HTTP_FORBIDDEN,
            FlowBridgeError::EgressRejected { .. } | FlowBridgeError::Dial(_) => HTTP_BAD_GATEWAY,
            _ => HTTP_UNAVAILABLE,
        },
        ConnectionResponse::Socks5 => {
            let code = match error {
                FlowBridgeError::PolicyRejected => 2,
                FlowBridgeError::NoUsableRoute => 4,
                FlowBridgeError::EgressRejected { .. } | FlowBridgeError::Dial(_) => 5,
                _ => 1,
            };
            let response = [5, code, 0, 1, 0, 0, 0, 0, 0, 0];
            io.write_all(&response)
                .await
                .map_err(|error| FlowBridgeError::Reply(error.to_string()))?;
            return io
                .flush()
                .await
                .map_err(|error| FlowBridgeError::Reply(error.to_string()));
        }
    };
    io.write_all(bytes)
        .await
        .map_err(|error| FlowBridgeError::Reply(error.to_string()))?;
    io.flush()
        .await
        .map_err(|error| FlowBridgeError::Reply(error.to_string()))
}

impl AcceptedConnection {
    /// Completes the local proxy handshake after the remote TCP flow has opened.
    /// Runtime owners normally call this through [`bridge_connection`].
    pub async fn confirm_success(&mut self) -> Result<(), FlowBridgeError> {
        let response = std::mem::replace(&mut self.response, ConnectionResponse::None);
        send_success(&mut self.io, response).await
    }
}

/// Convenience adapter for tests and platform wrappers that already own a
/// target stream. It does not perform DNS or target validation.
pub struct FixedTargetDialer<F> {
    factory: Mutex<F>,
}

impl<F> FixedTargetDialer<F> {
    #[must_use]
    pub fn new(factory: F) -> Self {
        Self {
            factory: Mutex::new(factory),
        }
    }
}

#[async_trait]
impl<F, S> IngressTargetDialer for FixedTargetDialer<F>
where
    F: FnMut(ConnectionContext) -> Result<S, FlowBridgeError> + Send,
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    async fn connect(
        &self,
        context: ConnectionContext,
    ) -> Result<BoxedLocalConnection, FlowBridgeError> {
        let mut factory = self
            .factory
            .lock()
            .map_err(|_| FlowBridgeError::Dial("target dialer lock poisoned".to_owned()))?;
        Ok(Box::new((factory)(context)?) as BoxedLocalConnection)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::TargetAddress;
    use std::net::SocketAddr;
    use std::sync::{Arc, Mutex};
    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

    fn accepted(local: tokio::io::DuplexStream) -> AcceptedConnection {
        AcceptedConnection {
            io: Box::new(local),
            context: crate::ConnectionContext {
                flow_tags: std::collections::BTreeSet::new(),
                listener_id: crate::ListenerId::new("local-http"),
                source: "127.0.0.1:12345".parse::<SocketAddr>().unwrap(),
                authentication_identity: None,
                process: None,
                protocol: crate::FlowProtocol::Tcp,
                target: TargetAddress {
                    host: crate::TargetHost::Hostname("example.test".into()),
                    port: 443,
                },
            },
            response: crate::ConnectionResponse::None,
        }
    }

    #[tokio::test]
    async fn bridges_bytes_in_both_directions() {
        let (mut local_peer, local_stream) = duplex(1024);
        let (mut target_peer, target_stream) = duplex(1024);
        let seen_target = Arc::new(Mutex::new(None));
        let seen_target_for_dialer = Arc::clone(&seen_target);
        let target_slot = Arc::new(Mutex::new(Some(target_stream)));
        let target_slot_for_dialer = Arc::clone(&target_slot);
        let dialer = FixedTargetDialer::new(move |target| {
            *seen_target_for_dialer.lock().unwrap() = Some(target);
            Ok::<_, FlowBridgeError>(
                target_slot_for_dialer
                    .lock()
                    .unwrap()
                    .take()
                    .expect("target stream"),
            )
        });

        let bridge =
            tokio::spawn(async move { bridge_connection(accepted(local_stream), &dialer).await });
        local_peer.write_all(b"to-target").await.unwrap();
        let mut inbound = [0_u8; 9];
        target_peer.read_exact(&mut inbound).await.unwrap();
        assert_eq!(&inbound, b"to-target");

        target_peer.write_all(b"to-local").await.unwrap();
        let mut outbound = [0_u8; 8];
        local_peer.read_exact(&mut outbound).await.unwrap();
        assert_eq!(&outbound, b"to-local");

        drop(local_peer);
        drop(target_peer);
        let stats = bridge.await.unwrap().unwrap();
        assert_eq!(stats.local_to_target_bytes, 9);
        assert_eq!(stats.target_to_local_bytes, 8);
        let seen = seen_target.lock().unwrap();
        let context = seen.as_ref().unwrap();
        assert_eq!(context.listener_id.as_str(), "local-http");
        assert_eq!(context.source, "127.0.0.1:12345".parse().unwrap());
        assert_eq!(context.target.port, 443);
    }

    #[tokio::test]
    async fn returns_dial_failure_without_touching_local_stream() {
        let (_local_peer, local_stream) = duplex(64);
        let dialer = FixedTargetDialer::new(|_| {
            Err::<tokio::io::DuplexStream, _>(FlowBridgeError::Dial("offline".into()))
        });
        assert_eq!(
            bridge_connection(accepted(local_stream), &dialer).await,
            Err(FlowBridgeError::Dial("offline".into()))
        );
    }

    #[tokio::test]
    async fn reports_policy_failure_before_http_connect_success() {
        let (mut local_peer, local_stream) = duplex(1024);
        let mut connection = accepted(local_stream);
        connection.response = crate::ConnectionResponse::HttpConnect;
        let dialer = FixedTargetDialer::new(|_| {
            Err::<tokio::io::DuplexStream, _>(FlowBridgeError::PolicyRejected)
        });
        let bridge = tokio::spawn(async move { bridge_connection(connection, &dialer).await });
        let mut response = Vec::new();
        local_peer.read_to_end(&mut response).await.unwrap();
        assert!(response.starts_with(b"HTTP/1.1 403"));
        assert_eq!(bridge.await.unwrap(), Err(FlowBridgeError::PolicyRejected));
    }

    #[tokio::test]
    async fn reports_target_failure_with_a_socks_reply() {
        let (mut local_peer, local_stream) = duplex(1024);
        let mut connection = accepted(local_stream);
        connection.response = crate::ConnectionResponse::Socks5;
        let dialer = FixedTargetDialer::new(|_| {
            Err::<tokio::io::DuplexStream, _>(FlowBridgeError::EgressRejected {
                error: ErrorClass::TargetFailure,
                reason: b"refused".to_vec(),
            })
        });
        let bridge = tokio::spawn(async move { bridge_connection(connection, &dialer).await });
        let mut response = [0_u8; 10];
        local_peer.read_exact(&mut response).await.unwrap();
        assert_eq!(response[1], 5);
        assert!(matches!(
            bridge.await.unwrap(),
            Err(FlowBridgeError::EgressRejected {
                error: ErrorClass::TargetFailure,
                ..
            })
        ));
    }

    #[tokio::test]
    async fn propagates_local_eof_to_target() {
        let (mut local_peer, local_stream) = duplex(1024);
        let (mut target_peer, target_stream) = duplex(1024);
        let target_slot = Arc::new(Mutex::new(Some(target_stream)));
        let target_slot_for_dialer = Arc::clone(&target_slot);
        let dialer = FixedTargetDialer::new(move |_| {
            Ok::<_, FlowBridgeError>(
                target_slot_for_dialer
                    .lock()
                    .unwrap()
                    .take()
                    .expect("target stream"),
            )
        });
        let bridge =
            tokio::spawn(async move { bridge_connection(accepted(local_stream), &dialer).await });
        local_peer.write_all(b"final").await.unwrap();
        local_peer.shutdown().await.unwrap();
        let mut data = Vec::new();
        target_peer.read_to_end(&mut data).await.unwrap();
        assert_eq!(data, b"final");
        drop(target_peer);
        let stats = bridge.await.unwrap().unwrap();
        assert_eq!(stats.local_to_target_bytes, 5);
    }
}
