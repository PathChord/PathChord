//! One TCP listener for HTTP and SOCKS proxy protocols.

use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;
use tokio::net::{TcpListener, TcpStream};

use crate::{
    AcceptedConnection, HttpConnectListener, IngressListener, ListenerCredentialVerifier,
    ListenerDescriptor, ListenerError, ListenerKind, RejectListenerCredentials, Socks5Listener,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProxyProtocol {
    Http,
    Socks,
}

pub(crate) async fn detect_protocol(stream: &TcpStream) -> Result<ProxyProtocol, ListenerError> {
    let mut first = [0; 1];
    if stream
        .peek(&mut first)
        .await
        .map_err(|error| ListenerError::Accept(error.to_string()))?
        == 0
    {
        return Err(ListenerError::Protocol(
            "mixed client closed before its request".to_owned(),
        ));
    }
    Ok(match first[0] {
        4 | 5 => ProxyProtocol::Socks,
        _ => ProxyProtocol::Http,
    })
}

/// TCP-only adapter for embedders. The platform runtime also supplies the
/// SOCKS5 UDP relay on this same TCP listener.
#[derive(Debug)]
pub struct MixedListener {
    listener: TcpListener,
    descriptor: ListenerDescriptor,
    credentials: Arc<dyn ListenerCredentialVerifier>,
}

impl MixedListener {
    pub async fn bind(descriptor: ListenerDescriptor) -> Result<Self, ListenerError> {
        if descriptor.kind != ListenerKind::Mixed {
            return Err(ListenerError::InvalidDescriptor(
                "mixed adapter requires a mixed Listener".to_owned(),
            ));
        }
        let listener = TcpListener::bind(descriptor.required_bind()?)
            .await
            .map_err(|error| ListenerError::Bind(error.to_string()))?;
        Ok(Self {
            listener,
            descriptor,
            credentials: Arc::new(RejectListenerCredentials),
        })
    }

    #[must_use]
    pub fn with_credential_verifier(
        mut self,
        credentials: Arc<dyn ListenerCredentialVerifier>,
    ) -> Self {
        self.credentials = credentials;
        self
    }

    pub fn local_addr(&self) -> Result<SocketAddr, ListenerError> {
        self.listener
            .local_addr()
            .map_err(|error| ListenerError::Accept(error.to_string()))
    }
}

#[async_trait]
impl IngressListener for MixedListener {
    fn descriptor(&self) -> &ListenerDescriptor {
        &self.descriptor
    }

    fn local_addr(&self) -> Result<SocketAddr, ListenerError> {
        Self::local_addr(self)
    }

    async fn accept(&self) -> Result<AcceptedConnection, ListenerError> {
        let (stream, source) = self
            .listener
            .accept()
            .await
            .map_err(|error| ListenerError::Accept(error.to_string()))?;
        if !self.descriptor.allows_source(source.ip()) {
            return Err(ListenerError::Policy(
                "source address is not allowed".to_owned(),
            ));
        }
        let mut descriptor = self.descriptor.clone();
        match detect_protocol(&stream).await? {
            ProxyProtocol::Http => {
                descriptor.kind = ListenerKind::Http;
                HttpConnectListener::accept_stream_with_verifier(
                    &descriptor,
                    stream,
                    source,
                    Arc::clone(&self.credentials),
                )
                .await
            }
            ProxyProtocol::Socks => {
                descriptor.kind = ListenerKind::Socks5;
                Socks5Listener::accept_stream_with_verifier(
                    stream,
                    source,
                    &descriptor,
                    Arc::clone(&self.credentials),
                )
                .await
            }
        }
    }
}
