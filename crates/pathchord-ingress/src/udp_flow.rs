//! Platform-independent UDP flow opener seam.

use async_trait::async_trait;

use crate::{ConnectionContext, IngressDataPlane};

#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum UdpFlowError {
    #[error("UDP flow opener failed: {0}")]
    Open(String),
    #[error("UDP flow task failed: {0}")]
    Task(String),
}

#[async_trait]
pub trait UdpFlowHandle: std::fmt::Debug + Send {
    async fn send(&mut self, payload: Vec<u8>) -> Result<(), UdpFlowError>;

    async fn receive(&mut self) -> Option<Vec<u8>>;

    async fn close(self: Box<Self>) -> Result<(), UdpFlowError>;
}

pub type BoxedUdpFlowHandle = Box<dyn UdpFlowHandle>;

#[async_trait]
pub trait UdpFlowOpener: std::fmt::Debug + Send + Sync {
    async fn open_udp(
        &self,
        context: &ConnectionContext,
    ) -> Result<BoxedUdpFlowHandle, UdpFlowError>;
}

#[async_trait]
impl UdpFlowHandle for pathchord_path::IngressUdpHandle {
    async fn send(&mut self, payload: Vec<u8>) -> Result<(), UdpFlowError> {
        pathchord_path::IngressUdpHandle::send(self, payload)
            .await
            .map_err(|error| UdpFlowError::Task(error.to_string()))
    }

    async fn receive(&mut self) -> Option<Vec<u8>> {
        pathchord_path::IngressUdpHandle::receive(self).await
    }

    async fn close(self: Box<Self>) -> Result<(), UdpFlowError> {
        pathchord_path::IngressUdpHandle::close(*self)
            .await
            .map_err(|error| UdpFlowError::Task(error.to_string()))
    }
}

#[async_trait]
impl UdpFlowOpener for IngressDataPlane {
    async fn open_udp(
        &self,
        context: &ConnectionContext,
    ) -> Result<BoxedUdpFlowHandle, UdpFlowError> {
        IngressDataPlane::open_udp(self, context)
            .await
            .map(|handle| Box::new(handle) as BoxedUdpFlowHandle)
            .map_err(|error| UdpFlowError::Open(error.to_string()))
    }
}
