//! Transport-neutral direct TCP flow bridging.
//!
//! Listener adapters stop after producing an [`AcceptedConnection`]. This
//! module owns the narrow next step: an injected target dialer supplies a
//! target byte stream, and Tokio copies bytes in both directions. Session and
//! Path multiplexing remain outside this direct bridge.

use async_trait::async_trait;
use std::sync::Mutex;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite, copy_bidirectional};

use crate::{AcceptedConnection, BoxedLocalConnection, TargetAddress};

#[derive(Debug, Error, PartialEq, Eq)]
pub enum FlowBridgeError {
    #[error("target dial failed: {0}")]
    Dial(String),
    #[error("TCP flow copy failed: {0}")]
    Copy(String),
}

/// Supplies a target connection for one accepted local flow.
#[async_trait]
pub trait IngressTargetDialer: Send + Sync {
    async fn connect(&self, target: TargetAddress)
    -> Result<BoxedLocalConnection, FlowBridgeError>;
}

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
    D: IngressTargetDialer,
{
    let mut local = accepted.io;
    let mut target = dialer.connect(accepted.context.target).await?;
    let (local_to_target_bytes, target_to_local_bytes) =
        copy_bidirectional(&mut local, &mut target)
            .await
            .map_err(|error| FlowBridgeError::Copy(error.to_string()))?;
    Ok(FlowBridgeStats {
        local_to_target_bytes,
        target_to_local_bytes,
    })
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
    F: FnMut(TargetAddress) -> Result<S, FlowBridgeError> + Send,
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    async fn connect(
        &self,
        target: TargetAddress,
    ) -> Result<BoxedLocalConnection, FlowBridgeError> {
        let mut factory = self
            .factory
            .lock()
            .map_err(|_| FlowBridgeError::Dial("target dialer lock poisoned".to_owned()))?;
        Ok(Box::new((factory)(target)?) as BoxedLocalConnection)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;
    use std::sync::{Arc, Mutex};
    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

    fn accepted(local: tokio::io::DuplexStream) -> AcceptedConnection {
        AcceptedConnection {
            io: Box::new(local),
            context: crate::ConnectionContext {
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
        assert_eq!(seen_target.lock().unwrap().as_ref().unwrap().port, 443);
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
