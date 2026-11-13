//! Linux REDIRECT and TPROXY TCP listener adapters.

use std::net::{IpAddr, SocketAddr};

use async_trait::async_trait;
use nix::sys::socket::{setsockopt, sockopt::IpTransparent};
use socket2::{Domain, Protocol, SockAddr, SockRef, Socket, Type};
use tokio::net::{TcpListener, TcpStream};

use crate::{
    AcceptedConnection, ConnectionContext, FlowProtocol, IngressListener, ListenerDescriptor,
    ListenerError, ListenerKind, ProtectedEndpointSet, TargetAddress, TargetHost,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TransparentMode {
    Redirect,
    Tproxy,
}

pub struct LinuxTransparentTcpListener {
    descriptor: ListenerDescriptor,
    listener: TcpListener,
    mode: TransparentMode,
    protected: ProtectedEndpointSet,
}

impl std::fmt::Debug for LinuxTransparentTcpListener {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("LinuxTransparentTcpListener")
            .field("descriptor", &self.descriptor)
            .field("mode", &self.mode)
            .finish_non_exhaustive()
    }
}

impl LinuxTransparentTcpListener {
    pub fn bind(
        descriptor: ListenerDescriptor,
        protected: ProtectedEndpointSet,
    ) -> Result<Self, ListenerError> {
        let mode = match descriptor.kind {
            ListenerKind::Redirect => TransparentMode::Redirect,
            ListenerKind::Tproxy => TransparentMode::Tproxy,
            kind => {
                return Err(ListenerError::InvalidDescriptor(format!(
                    "listener kind {kind:?} is not a Linux transparent TCP adapter"
                )));
            }
        };
        let bind = descriptor.required_bind()?;
        let domain = if bind.is_ipv4() {
            Domain::IPV4
        } else {
            Domain::IPV6
        };
        let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))
            .map_err(|error| ListenerError::Bind(error.to_string()))?;
        socket
            .set_reuse_address(true)
            .map_err(|error| ListenerError::Bind(error.to_string()))?;
        if mode == TransparentMode::Tproxy {
            setsockopt(&socket, IpTransparent, &true)
                .map_err(|error| ListenerError::Bind(error.to_string()))?;
        }
        socket
            .bind(&SockAddr::from(bind))
            .map_err(|error| ListenerError::Bind(error.to_string()))?;
        socket
            .listen(1024)
            .map_err(|error| ListenerError::Bind(error.to_string()))?;
        socket
            .set_nonblocking(true)
            .map_err(|error| ListenerError::Bind(error.to_string()))?;
        let listener = TcpListener::from_std(socket.into())
            .map_err(|error| ListenerError::Bind(error.to_string()))?;
        Ok(Self {
            descriptor,
            listener,
            mode,
            protected,
        })
    }

    pub fn local_addr(&self) -> Result<SocketAddr, ListenerError> {
        self.listener
            .local_addr()
            .map_err(|error| ListenerError::Accept(error.to_string()))
    }

    fn original_destination(&self, stream: &TcpStream) -> Result<SocketAddr, ListenerError> {
        if self.mode == TransparentMode::Tproxy {
            return stream
                .local_addr()
                .map_err(|error| ListenerError::Protocol(error.to_string()));
        }
        let socket = SockRef::from(stream);
        let local = stream
            .local_addr()
            .map_err(|error| ListenerError::Protocol(error.to_string()))?;
        let original = match local.ip() {
            IpAddr::V4(_) => socket.original_dst_v4(),
            IpAddr::V6(_) => socket.original_dst_v6(),
        }
        .map_err(|_| ListenerError::Protocol("original destination is unavailable".to_owned()))?;
        original.as_socket().ok_or_else(|| {
            ListenerError::Protocol("original destination has an invalid address family".to_owned())
        })
    }
}

#[async_trait]
impl IngressListener for LinuxTransparentTcpListener {
    fn descriptor(&self) -> &ListenerDescriptor {
        &self.descriptor
    }

    fn local_addr(&self) -> Result<SocketAddr, ListenerError> {
        LinuxTransparentTcpListener::local_addr(self)
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
        let target = self.original_destination(&stream)?;
        if self.protected.contains(&target) {
            return Err(ListenerError::Policy(
                "original destination is protected from interception".to_owned(),
            ));
        }
        Ok(AcceptedConnection {
            io: Box::new(stream),
            context: ConnectionContext {
                flow_tags: self.descriptor.flow_tags.clone(),
                listener_id: self.descriptor.id.clone(),
                source,
                authentication_identity: None,
                process: None,
                protocol: FlowProtocol::Tcp,
                target: TargetAddress {
                    host: TargetHost::Ip(target.ip()),
                    port: target.port(),
                },
            },
            response: crate::ConnectionResponse::None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn descriptor(kind: ListenerKind) -> ListenerDescriptor {
        ListenerDescriptor {
            id: crate::ListenerId::new("transparent"),
            kind,
            bind: Some("127.0.0.1:0".parse().unwrap()),
            interface: None,
            address: None,
            mtu: None,
            flow_tags: std::collections::BTreeSet::new(),
            process_metadata: crate::ProcessMetadataRequest::default(),
            allowed_sources: vec!["127.0.0.1/32".to_owned()],
            authentication_required: false,
        }
    }

    #[tokio::test]
    async fn redirect_listener_binds_without_transparent_privileges() {
        let listener = LinuxTransparentTcpListener::bind(
            descriptor(ListenerKind::Redirect),
            ProtectedEndpointSet::default(),
        )
        .unwrap();
        assert!(listener.local_addr().unwrap().port() > 0);
    }

    #[test]
    fn rejects_non_transparent_listener_kinds() {
        assert!(matches!(
            LinuxTransparentTcpListener::bind(
                descriptor(ListenerKind::Http),
                ProtectedEndpointSet::default()
            ),
            Err(ListenerError::InvalidDescriptor(_))
        ));
    }
}
