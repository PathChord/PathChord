//! SOCKS5 CONNECT listener adapter.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use async_trait::async_trait;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;

use crate::{
    AcceptedConnection, BoxedLocalConnection, ConnectionContext, FlowProtocol, IngressListener,
    ListenerCredentialVerifier, ListenerDescriptor, ListenerError, ListenerKind,
    RejectListenerCredentials, TargetAddress, TargetHost,
};

const VERSION: u8 = 5;
const NO_AUTH: u8 = 0;
const USERPASS: u8 = 2;
const NO_METHOD: u8 = 0xff;
pub(crate) const CONNECT: u8 = 1;
pub(crate) const UDP_ASSOCIATE: u8 = 3;
pub(crate) const IPV4: u8 = 1;
pub(crate) const DOMAIN: u8 = 3;
pub(crate) const IPV6: u8 = 4;
const MAX_DOMAIN: usize = 255;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SocksCommand {
    Connect,
    UdpAssociate,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SocksRequest {
    pub command: SocksCommand,
    pub target: TargetAddress,
}

pub struct Socks5Listener {
    listener: TcpListener,
    descriptor: ListenerDescriptor,
    credential_verifier: Arc<dyn ListenerCredentialVerifier>,
}

impl std::fmt::Debug for Socks5Listener {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Socks5Listener")
            .field("descriptor", &self.descriptor)
            .finish_non_exhaustive()
    }
}

impl Socks5Listener {
    pub async fn bind(descriptor: ListenerDescriptor) -> Result<Self, ListenerError> {
        Self::validate_descriptor(&descriptor)?;
        let listener = TcpListener::bind(descriptor.required_bind()?)
            .await
            .map_err(|e| ListenerError::Bind(e.to_string()))?;
        Ok(Self {
            listener,
            descriptor,
            credential_verifier: Arc::new(RejectListenerCredentials),
        })
    }

    pub fn from_listener(
        listener: TcpListener,
        descriptor: ListenerDescriptor,
    ) -> Result<Self, ListenerError> {
        Self::validate_descriptor(&descriptor)?;
        Ok(Self {
            listener,
            descriptor,
            credential_verifier: Arc::new(RejectListenerCredentials),
        })
    }

    #[must_use]
    pub fn with_credential_verifier(
        mut self,
        credential_verifier: Arc<dyn ListenerCredentialVerifier>,
    ) -> Self {
        self.credential_verifier = credential_verifier;
        self
    }

    pub fn local_addr(&self) -> Result<SocketAddr, ListenerError> {
        self.listener
            .local_addr()
            .map_err(|error| ListenerError::Accept(error.to_string()))
    }

    pub async fn accept_stream<S>(
        stream: S,
        source: SocketAddr,
        descriptor: &ListenerDescriptor,
    ) -> Result<AcceptedConnection, ListenerError>
    where
        S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
        Self::accept_stream_with_verifier(
            stream,
            source,
            descriptor,
            Arc::new(RejectListenerCredentials),
        )
        .await
    }

    pub async fn accept_stream_with_verifier<S>(
        stream: S,
        source: SocketAddr,
        descriptor: &ListenerDescriptor,
        credential_verifier: Arc<dyn ListenerCredentialVerifier>,
    ) -> Result<AcceptedConnection, ListenerError>
    where
        S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
        Self::validate_descriptor(descriptor)?;
        if !descriptor.allows_source(source.ip()) {
            return Err(policy_error("source address is not allowed"));
        }
        let mut stream = stream;
        let identity = negotiate(
            &mut stream,
            descriptor.authentication_required,
            credential_verifier.as_ref(),
        )
        .await?;
        let request = read_request(&mut stream).await?;
        if request.command != SocksCommand::Connect {
            send_reply(&mut stream, 7).await?;
            return Err(error("SOCKS command is not CONNECT"));
        }
        Ok(AcceptedConnection {
            io: Box::new(stream) as BoxedLocalConnection,
            context: ConnectionContext {
                flow_tags: descriptor.flow_tags.clone(),
                listener_id: descriptor.id.clone(),
                source,
                authentication_identity: identity,
                process: None,
                protocol: FlowProtocol::Tcp,
                target: request.target,
            },
            response: crate::ConnectionResponse::Socks5,
        })
    }

    fn validate_descriptor(descriptor: &ListenerDescriptor) -> Result<(), ListenerError> {
        if descriptor.kind == ListenerKind::Socks5 {
            Ok(())
        } else {
            Err(ListenerError::InvalidDescriptor(
                "SOCKS5 adapter requires a socks5 Listener".to_owned(),
            ))
        }
    }
}

#[async_trait]
impl IngressListener for Socks5Listener {
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
            .map_err(|e| ListenerError::Accept(e.to_string()))?;
        Self::accept_stream_with_verifier(
            stream,
            source,
            &self.descriptor,
            Arc::clone(&self.credential_verifier),
        )
        .await
    }
}

pub(crate) async fn negotiate<S>(
    stream: &mut S,
    authentication_required: bool,
    credential_verifier: &dyn ListenerCredentialVerifier,
) -> Result<Option<String>, ListenerError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    if read_u8(stream, "greeting version").await? != VERSION {
        return Err(error("SOCKS greeting version is not 5"));
    }
    let count = read_u8(stream, "greeting method count").await? as usize;
    if count == 0 {
        send_method(stream, NO_METHOD).await?;
        return Err(error("SOCKS greeting has no methods"));
    }
    let mut methods = vec![0_u8; count];
    stream
        .read_exact(&mut methods)
        .await
        .map_err(|e| ListenerError::Protocol(e.to_string()))?;
    let selected = if authentication_required {
        USERPASS
    } else {
        NO_AUTH
    };
    if !methods.contains(&selected) {
        send_method(stream, NO_METHOD).await?;
        return Err(error("SOCKS client does not offer a supported method"));
    }
    send_method(stream, selected).await?;
    if selected == NO_AUTH {
        return Ok(None);
    }
    if read_u8(stream, "auth version").await? != 1 {
        send_auth(stream, false).await?;
        return Err(error("unsupported username/password version"));
    }
    let username = read_bytes(stream, "username", 255).await?;
    let password = read_bytes(stream, "password", 255).await?;
    let username_string =
        String::from_utf8(username.clone()).map_err(|_| error("SOCKS username is not UTF-8"))?;
    let valid = !username.is_empty()
        && !password.is_empty()
        && credential_verifier
            .verify(&username_string, &password)
            .await;
    send_auth(stream, valid).await?;
    if !valid {
        return Err(policy_error("SOCKS credentials were rejected"));
    }
    Ok(Some(username_string))
}

pub(crate) async fn read_request<S>(stream: &mut S) -> Result<SocksRequest, ListenerError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let version = read_u8(stream, "request version").await?;
    let command = read_u8(stream, "request command").await?;
    let reserved = read_u8(stream, "request reserved").await?;
    let atyp = read_u8(stream, "request address type").await?;
    if version != VERSION || reserved != 0 {
        send_reply(stream, 1).await?;
        return Err(error("malformed SOCKS request header"));
    }
    let command = match command {
        CONNECT => SocksCommand::Connect,
        UDP_ASSOCIATE => SocksCommand::UdpAssociate,
        _ => {
            send_reply(stream, 7).await?;
            return Err(error("unsupported SOCKS command"));
        }
    };
    let host = match atyp {
        IPV4 => {
            let mut bytes = [0_u8; 4];
            stream
                .read_exact(&mut bytes)
                .await
                .map_err(|e| ListenerError::Protocol(e.to_string()))?;
            TargetHost::Ip(IpAddr::V4(Ipv4Addr::from(bytes)))
        }
        IPV6 => {
            let mut bytes = [0_u8; 16];
            stream
                .read_exact(&mut bytes)
                .await
                .map_err(|e| ListenerError::Protocol(e.to_string()))?;
            TargetHost::Ip(IpAddr::V6(Ipv6Addr::from(bytes)))
        }
        DOMAIN => {
            let bytes = read_bytes(stream, "domain", MAX_DOMAIN).await?;
            let value = String::from_utf8(bytes).map_err(|_| error("SOCKS domain is not UTF-8"))?;
            if value.is_empty() {
                send_reply(stream, 8).await?;
                return Err(error("SOCKS domain is empty"));
            }
            TargetHost::Hostname(value)
        }
        _ => {
            send_reply(stream, 8).await?;
            return Err(error("unsupported SOCKS address type"));
        }
    };
    let port = read_u16(stream, "target port").await?;
    if command == SocksCommand::Connect && port == 0 {
        send_reply(stream, 8).await?;
        return Err(error("SOCKS target port is zero"));
    }
    Ok(SocksRequest {
        command,
        target: TargetAddress { host, port },
    })
}

async fn send_method<S>(stream: &mut S, method: u8) -> Result<(), ListenerError>
where
    S: AsyncWrite + Unpin,
{
    stream
        .write_all(&[VERSION, method])
        .await
        .map_err(|e| ListenerError::Protocol(e.to_string()))
}

async fn send_auth<S>(stream: &mut S, success: bool) -> Result<(), ListenerError>
where
    S: AsyncWrite + Unpin,
{
    stream
        .write_all(&[1, if success { 0 } else { 1 }])
        .await
        .map_err(|e| ListenerError::Protocol(e.to_string()))
}

pub(crate) async fn send_reply<S>(stream: &mut S, code: u8) -> Result<(), ListenerError>
where
    S: AsyncWrite + Unpin,
{
    stream
        .write_all(&[VERSION, code, 0, IPV4, 0, 0, 0, 0, 0, 0])
        .await
        .map_err(|e| ListenerError::Protocol(e.to_string()))
}

pub(crate) async fn send_reply_address<S>(
    stream: &mut S,
    code: u8,
    address: SocketAddr,
) -> Result<(), ListenerError>
where
    S: AsyncWrite + Unpin,
{
    let mut reply = vec![VERSION, code, 0];
    match address.ip() {
        IpAddr::V4(address) => {
            reply.push(IPV4);
            reply.extend_from_slice(&address.octets());
        }
        IpAddr::V6(address) => {
            reply.push(IPV6);
            reply.extend_from_slice(&address.octets());
        }
    }
    reply.extend_from_slice(&address.port().to_be_bytes());
    stream
        .write_all(&reply)
        .await
        .map_err(|error| ListenerError::Protocol(error.to_string()))
}

async fn read_u8<S>(stream: &mut S, field: &'static str) -> Result<u8, ListenerError>
where
    S: AsyncRead + Unpin,
{
    let mut value = [0_u8; 1];
    stream
        .read_exact(&mut value)
        .await
        .map_err(|e| ListenerError::Protocol(format!("{field}: {e}")))?;
    Ok(value[0])
}

async fn read_u16<S>(stream: &mut S, field: &'static str) -> Result<u16, ListenerError>
where
    S: AsyncRead + Unpin,
{
    let mut value = [0_u8; 2];
    stream
        .read_exact(&mut value)
        .await
        .map_err(|e| ListenerError::Protocol(format!("{field}: {e}")))?;
    Ok(u16::from_be_bytes(value))
}

async fn read_bytes<S>(
    stream: &mut S,
    field: &'static str,
    maximum: usize,
) -> Result<Vec<u8>, ListenerError>
where
    S: AsyncRead + Unpin,
{
    let length = read_u8(stream, field).await? as usize;
    if length > maximum {
        return Err(error(format!("{field} exceeds maximum length")));
    }
    let mut bytes = vec![0_u8; length];
    stream
        .read_exact(&mut bytes)
        .await
        .map_err(|e| ListenerError::Protocol(format!("{field}: {e}")))?;
    Ok(bytes)
}

fn error(message: impl Into<String>) -> ListenerError {
    ListenerError::Protocol(message.into())
}

fn policy_error(message: impl Into<String>) -> ListenerError {
    ListenerError::Policy(message.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use std::str::FromStr;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

    #[derive(Debug)]
    struct TestVerifier;

    #[async_trait]
    impl ListenerCredentialVerifier for TestVerifier {
        async fn verify(&self, username: &str, password: &[u8]) -> bool {
            username == "alice" && password == b"secret"
        }
    }

    fn descriptor(authentication_required: bool) -> ListenerDescriptor {
        ListenerDescriptor {
            id: crate::ListenerId::new("socks"),
            kind: ListenerKind::Socks5,
            bind: Some(SocketAddr::from_str("127.0.0.1:1080").unwrap()),
            interface: None,
            address: None,
            mtu: None,
            flow_tags: std::collections::BTreeSet::new(),
            process_metadata: crate::ProcessMetadataRequest::default(),
            allowed_sources: Vec::new(),
            authentication_required,
        }
    }

    async fn read_exact<R: AsyncRead + Unpin>(reader: &mut R, length: usize) -> Vec<u8> {
        let mut output = vec![0_u8; length];
        reader.read_exact(&mut output).await.unwrap();
        output
    }

    #[tokio::test]
    async fn accepts_no_auth_domain_connect() {
        let (mut client, server) = duplex(1024);
        let descriptor2 = descriptor(false);
        let task = tokio::spawn(async move {
            let mut accepted = Socks5Listener::accept_stream(
                server,
                SocketAddr::from_str("127.0.0.1:1234").unwrap(),
                &descriptor2,
            )
            .await
            .expect("accepted connection");
            accepted.confirm_success().await.expect("SOCKS success");
            accepted
        });
        client.write_all(&[5, 1, NO_AUTH]).await.unwrap();
        assert_eq!(&read_exact(&mut client, 2).await, &[5, NO_AUTH]);
        client
            .write_all(&[5, CONNECT, 0, DOMAIN, 12])
            .await
            .unwrap();
        client.write_all(b"example.test").await.unwrap();
        client.write_all(&443_u16.to_be_bytes()).await.unwrap();
        assert_eq!(read_exact(&mut client, 10).await[1], 0);
        let accepted = task.await.unwrap();
        assert_eq!(accepted.context.authentication_identity, None);
        assert_eq!(accepted.context.target.port, 443);
        assert_eq!(
            accepted.context.target.host,
            TargetHost::Hostname("example.test".into())
        );
    }

    #[tokio::test]
    async fn accepts_username_password_when_required() {
        let (mut client, server) = duplex(1024);
        let descriptor = descriptor(true);
        let task = tokio::spawn(async move {
            let mut accepted = Socks5Listener::accept_stream_with_verifier(
                server,
                SocketAddr::from_str("127.0.0.1:1234").unwrap(),
                &descriptor,
                Arc::new(TestVerifier),
            )
            .await
            .expect("accepted connection");
            accepted.confirm_success().await.expect("SOCKS success");
            accepted
        });
        client.write_all(&[5, 2, NO_AUTH, USERPASS]).await.unwrap();
        assert_eq!(&read_exact(&mut client, 2).await, &[5, USERPASS]);
        client.write_all(&[1, 5]).await.unwrap();
        client.write_all(b"alice").await.unwrap();
        client.write_all(&[6]).await.unwrap();
        client.write_all(b"secret").await.unwrap();
        assert_eq!(&read_exact(&mut client, 2).await, &[1, 0]);
        client
            .write_all(&[5, CONNECT, 0, IPV4, 192, 0, 2, 1, 0x01, 0xbb])
            .await
            .unwrap();
        assert_eq!(read_exact(&mut client, 10).await[1], 0);
        let accepted = task.await.unwrap();
        assert_eq!(
            accepted.context.authentication_identity.as_deref(),
            Some("alice")
        );
    }

    #[tokio::test]
    async fn rejects_unsupported_method_and_malformed_command() {
        let (mut client, server) = duplex(1024);
        let descriptor_malformed = descriptor(false);
        let task = tokio::spawn(async move {
            Socks5Listener::accept_stream(
                server,
                SocketAddr::from_str("127.0.0.1:1234").unwrap(),
                &descriptor_malformed,
            )
            .await
        });
        client.write_all(&[5, 1, USERPASS]).await.unwrap();
        assert_eq!(&read_exact(&mut client, 2).await, &[5, NO_METHOD]);
        assert!(task.await.unwrap().is_err());

        let (mut client, server) = duplex(1024);
        let descriptor2 = descriptor(false);
        let task = tokio::spawn(async move {
            Socks5Listener::accept_stream(
                server,
                SocketAddr::from_str("127.0.0.1:1234").unwrap(),
                &descriptor2,
            )
            .await
        });
        client.write_all(&[5, 1, NO_AUTH]).await.unwrap();
        assert_eq!(&read_exact(&mut client, 2).await, &[5, NO_AUTH]);
        client
            .write_all(&[5, 2, 0, IPV4, 127, 0, 0, 1, 0, 80])
            .await
            .unwrap();
        assert_eq!(read_exact(&mut client, 10).await[1], 7);
        assert!(task.await.unwrap().is_err());
    }

    #[tokio::test]
    async fn rejects_disallowed_source_before_socks_negotiation() {
        let mut descriptor = descriptor(false);
        descriptor.allowed_sources = vec!["192.0.2.0/24".to_owned()];
        let (_client, server) = duplex(1024);
        let result = Socks5Listener::accept_stream(
            server,
            SocketAddr::from_str("127.0.0.1:1234").unwrap(),
            &descriptor,
        )
        .await;
        assert!(matches!(result, Err(ListenerError::Policy(_))));
    }
}
