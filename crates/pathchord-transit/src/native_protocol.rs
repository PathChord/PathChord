//! Rust-native VLESS and Trojan wire adapters over maintained TLS/WS transports.

use std::net::IpAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use async_trait::async_trait;
use rustls::ClientConfig;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::time::timeout;
use zeroize::{Zeroize, Zeroizing};

use crate::{
    AdapterKind, BoxedTransitConnection, BoxedTransitDatagram, ConnectRequest, Endpoint,
    TransitAdapter, TransitCredential, TransitDatagram, TransitError, TransitMetadata,
};

#[derive(Clone, Copy)]
enum Protocol {
    Vless,
    Trojan,
}

enum Authentication {
    Vless(Zeroizing<[u8; 16]>),
    Trojan(Zeroizing<String>),
}

pub(crate) struct NativeProtocolAdapter {
    metadata: TransitMetadata,
    authentication: Authentication,
    transport: crate::native_transport::NativeTransport,
    udp: bool,
    timeout: Duration,
}

impl std::fmt::Debug for NativeProtocolAdapter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NativeProtocolAdapter")
            .field("metadata", &self.metadata)
            .finish_non_exhaustive()
    }
}

impl NativeProtocolAdapter {
    pub fn from_config(
        config: &pathchord_policy::TransitProxyConfig,
        credential: &TransitCredential,
        duration: Duration,
        tls: Arc<ClientConfig>,
    ) -> Result<Self, TransitError> {
        let mut allowed = match config.protocol.as_str() {
            "vless" => vec!["uuid", "flow"],
            "trojan" => vec!["password"],
            _ => return Err(unsupported("protocol has no matching native adapter")),
        };
        allowed.extend(
            config
                .options
                .tls
                .as_ref()
                .and_then(|tls| tls.client_key_field.as_deref()),
        );
        crate::adapter_registry::validate_credentials(Some(credential), &allowed)?;
        let authentication = match config.protocol.as_str() {
            "vless" => {
                if credential
                    .field("flow")
                    .is_some_and(|flow| !flow.is_empty())
                {
                    return Err(unsupported(
                        "VLESS flow requires a validated Vision backend",
                    ));
                }
                let uuid = uuid::Uuid::parse_str(
                    credential
                        .field("uuid")
                        .ok_or_else(|| unsupported("VLESS UUID is missing"))?,
                )
                .map_err(|_| unsupported("VLESS UUID is invalid"))?;
                Authentication::Vless(Zeroizing::new(*uuid.as_bytes()))
            }
            _ => {
                let password = credential
                    .field("password")
                    .filter(|value| !value.is_empty())
                    .ok_or_else(|| unsupported("Trojan password is missing"))?;
                Authentication::Trojan(Zeroizing::new(password.to_owned()))
            }
        };
        let transport =
            crate::native_transport::NativeTransport::new(config, credential, tls, duration)?;
        Ok(Self {
            metadata: TransitMetadata {
                adapter_id: config.id.as_str().to_owned(),
                kind: AdapterKind::ExternalProxy {
                    protocol: config.protocol.clone(),
                },
                labels: config.labels.clone(),
            },
            authentication,
            transport,
            udp: config.options.udp != Some(false),
            timeout: duration,
        })
    }

    async fn open(
        &self,
        destination: &Endpoint,
        udp: bool,
    ) -> Result<BoxedTransitConnection, TransitError> {
        crate::validate_destination(destination)?;
        timeout(self.timeout, async {
            let mut stream = self.transport.connect().await?;
            let header = Zeroizing::new(match &self.authentication {
                Authentication::Vless(uuid) => vless_request(uuid, destination, udp)?,
                Authentication::Trojan(password) => {
                    use sha2::Digest;
                    let digest = Zeroizing::new(sha2::Sha224::digest(password.as_bytes()).to_vec());
                    let mut hash = Zeroizing::new([0; 56]);
                    for (index, byte) in digest.iter().enumerate() {
                        hash[2 * index] = b"0123456789abcdef"[usize::from(byte >> 4)];
                        hash[2 * index + 1] = b"0123456789abcdef"[usize::from(byte & 15)];
                    }
                    let target = trojan_address(destination);
                    let mut header = bytes::BytesMut::new();
                    trojan_proto::write_request_header(
                        &mut header,
                        hash.as_ref(),
                        if udp {
                            trojan_proto::CMD_UDP_ASSOCIATE
                        } else {
                            trojan_proto::CMD_CONNECT
                        },
                        &target,
                    )
                    .map_err(|_| unsupported("Trojan target cannot be encoded"))?;
                    let output = header.to_vec();
                    header.as_mut().zeroize();
                    output
                }
            });
            stream
                .write_all(&header)
                .await
                .map_err(|_| protocol("native protocol request write failed"))?;
            stream
                .flush()
                .await
                .map_err(|_| protocol("native protocol request flush failed"))?;
            if matches!(self.authentication, Authentication::Vless(_)) {
                stream = Box::new(VlessResponseIo {
                    inner: stream,
                    header: [0; 2],
                    filled: 0,
                    addon_remaining: None,
                });
            }
            Ok(stream)
        })
        .await
        .map_err(|_| TransitError::Connection("native protocol opening timed out".into()))?
    }
}

#[async_trait]
impl TransitAdapter for NativeProtocolAdapter {
    fn metadata(&self) -> &TransitMetadata {
        &self.metadata
    }
    fn supports_udp(&self) -> bool {
        self.udp
    }
    async fn connect(
        &self,
        request: ConnectRequest,
    ) -> Result<BoxedTransitConnection, TransitError> {
        self.open(&request.destination, false).await
    }
    async fn connect_udp(
        &self,
        request: ConnectRequest,
    ) -> Result<BoxedTransitDatagram, TransitError> {
        if !self.udp {
            return Err(unsupported("node UDP is disabled"));
        }
        let stream = self.open(&request.destination, true).await?;
        Ok(Box::new(NativeDatagram {
            stream,
            destination: request.destination,
            protocol: match self.authentication {
                Authentication::Vless(_) => Protocol::Vless,
                Authentication::Trojan(_) => Protocol::Trojan,
            },
        }))
    }
}

pub(crate) fn vless_request(
    uuid: &[u8; 16],
    destination: &Endpoint,
    udp: bool,
) -> Result<Vec<u8>, TransitError> {
    let mut request = vec![0];
    request.extend_from_slice(uuid);
    request.push(0);
    request.push(if udp { 2 } else { 1 });
    request.extend_from_slice(&destination.port.to_be_bytes());
    match destination.host.parse::<IpAddr>() {
        Ok(IpAddr::V4(ip)) => {
            request.push(1);
            request.extend_from_slice(&ip.octets());
        }
        Ok(IpAddr::V6(ip)) => {
            request.push(3);
            request.extend_from_slice(&ip.octets());
        }
        Err(_) => {
            let bytes = destination.host.as_bytes();
            if bytes.is_empty() || bytes.len() > 255 {
                return Err(unsupported("VLESS target hostname is invalid"));
            }
            request.push(2);
            request.push(bytes.len() as u8);
            request.extend_from_slice(bytes);
        }
    }
    Ok(request)
}

fn unsupported(message: &str) -> TransitError {
    TransitError::Unsupported(message.to_owned())
}
fn protocol(message: &str) -> TransitError {
    TransitError::Protocol(message.to_owned())
}

fn trojan_address(destination: &Endpoint) -> trojan_proto::AddressRef<'_> {
    let host = match destination.host.parse::<IpAddr>() {
        Ok(IpAddr::V4(ip)) => trojan_proto::HostRef::Ipv4(ip.octets()),
        Ok(IpAddr::V6(ip)) => trojan_proto::HostRef::Ipv6(ip.octets()),
        Err(_) => trojan_proto::HostRef::Domain(destination.host.as_bytes()),
    };
    trojan_proto::AddressRef {
        host,
        port: destination.port,
    }
}

pub(crate) struct VlessResponseIo {
    inner: BoxedTransitConnection,
    header: [u8; 2],
    filled: usize,
    addon_remaining: Option<usize>,
}
impl VlessResponseIo {
    pub(crate) fn new(inner: BoxedTransitConnection) -> Self {
        Self {
            inner,
            header: [0; 2],
            filled: 0,
            addon_remaining: None,
        }
    }
}
impl AsyncRead for VlessResponseIo {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        if buffer.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        while this.filled < 2 {
            let mut header = ReadBuf::new(&mut this.header[this.filled..]);
            match Pin::new(&mut this.inner).poll_read(cx, &mut header) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(())) => {
                    if header.filled().is_empty() {
                        return Poll::Ready(Err(std::io::ErrorKind::UnexpectedEof.into()));
                    }
                    this.filled += header.filled().len();
                }
            }
        }
        if this.header[0] != 0 {
            return Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid VLESS response version",
            )));
        }
        let remaining = this
            .addon_remaining
            .get_or_insert(usize::from(this.header[1]));
        while *remaining > 0 {
            let mut ignored = [0; 255];
            let mut read = ReadBuf::new(&mut ignored[..*remaining]);
            match Pin::new(&mut this.inner).poll_read(cx, &mut read) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(())) => {
                    if read.filled().is_empty() {
                        return Poll::Ready(Err(std::io::ErrorKind::UnexpectedEof.into()));
                    }
                    *remaining -= read.filled().len();
                }
            }
        }
        Pin::new(&mut this.inner).poll_read(cx, buffer)
    }
}
impl AsyncWrite for VlessResponseIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buffer)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

pub(crate) struct NativeDatagram {
    stream: BoxedTransitConnection,
    destination: Endpoint,
    protocol: Protocol,
}
pub(crate) fn vless_datagram(
    stream: BoxedTransitConnection,
    destination: Endpoint,
) -> BoxedTransitDatagram {
    Box::new(NativeDatagram {
        stream,
        destination,
        protocol: Protocol::Vless,
    })
}
impl std::fmt::Debug for NativeDatagram {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("NativeProtocolDatagram(..)")
    }
}
#[async_trait]
impl TransitDatagram for NativeDatagram {
    async fn send(&mut self, payload: &[u8]) -> Result<(), TransitError> {
        let length = u16::try_from(payload.len())
            .map_err(|_| unsupported("UDP packet exceeds the native protocol limit"))?;
        let mut packet = Vec::new();
        if matches!(self.protocol, Protocol::Trojan) {
            encode_trojan_address(&self.destination, &mut packet)?;
        }
        packet.extend_from_slice(&length.to_be_bytes());
        if matches!(self.protocol, Protocol::Trojan) {
            packet.extend_from_slice(b"\r\n");
        }
        packet.extend_from_slice(payload);
        self.stream
            .write_all(&packet)
            .await
            .map_err(|_| protocol("native UDP packet write failed"))?;
        self.stream
            .flush()
            .await
            .map_err(|_| protocol("native UDP packet flush failed"))
    }
    async fn receive(&mut self) -> Result<Vec<u8>, TransitError> {
        if matches!(self.protocol, Protocol::Trojan) {
            let source = read_trojan_address(&mut self.stream).await?;
            if source.port != self.destination.port
                || self
                    .destination
                    .host
                    .parse::<IpAddr>()
                    .is_ok_and(|expected| source.host.parse::<IpAddr>() != Ok(expected))
            {
                return Err(protocol(
                    "Trojan UDP reply target does not match the association",
                ));
            }
        }
        let length = self
            .stream
            .read_u16()
            .await
            .map_err(|_| protocol("native UDP length is truncated"))?;
        if matches!(self.protocol, Protocol::Trojan) {
            let mut separator = [0; 2];
            self.stream
                .read_exact(&mut separator)
                .await
                .map_err(|_| protocol("Trojan UDP separator is truncated"))?;
            if separator != *b"\r\n" {
                return Err(protocol("Trojan UDP separator is invalid"));
            }
        }
        let mut payload = vec![0; usize::from(length)];
        self.stream
            .read_exact(&mut payload)
            .await
            .map_err(|_| protocol("native UDP payload is truncated"))?;
        Ok(payload)
    }
    async fn close(mut self: Box<Self>) -> Result<(), TransitError> {
        self.stream
            .shutdown()
            .await
            .map_err(|_| protocol("native UDP shutdown failed"))
    }
}

fn encode_trojan_address(destination: &Endpoint, packet: &mut Vec<u8>) -> Result<(), TransitError> {
    match destination.host.parse::<IpAddr>() {
        Ok(IpAddr::V4(ip)) => {
            packet.push(1);
            packet.extend_from_slice(&ip.octets());
        }
        Ok(IpAddr::V6(ip)) => {
            packet.push(4);
            packet.extend_from_slice(&ip.octets());
        }
        Err(_) => {
            let bytes = destination.host.as_bytes();
            if bytes.is_empty() || bytes.len() > 255 {
                return Err(unsupported("Trojan UDP hostname is invalid"));
            }
            packet.push(3);
            packet.push(bytes.len() as u8);
            packet.extend_from_slice(bytes);
        }
    }
    packet.extend_from_slice(&destination.port.to_be_bytes());
    Ok(())
}

async fn read_trojan_address(
    stream: &mut BoxedTransitConnection,
) -> Result<Endpoint, TransitError> {
    let atyp = stream
        .read_u8()
        .await
        .map_err(|_| protocol("Trojan UDP address is truncated"))?;
    let host = match atyp {
        1 => {
            let mut ip = [0; 4];
            stream
                .read_exact(&mut ip)
                .await
                .map_err(|_| protocol("Trojan UDP address is truncated"))?;
            std::net::Ipv4Addr::from(ip).to_string()
        }
        4 => {
            let mut ip = [0; 16];
            stream
                .read_exact(&mut ip)
                .await
                .map_err(|_| protocol("Trojan UDP address is truncated"))?;
            std::net::Ipv6Addr::from(ip).to_string()
        }
        3 => {
            let length = stream
                .read_u8()
                .await
                .map_err(|_| protocol("Trojan UDP domain is truncated"))?;
            if length == 0 {
                return Err(protocol("Trojan UDP domain is empty"));
            }
            let mut domain = vec![0; usize::from(length)];
            stream
                .read_exact(&mut domain)
                .await
                .map_err(|_| protocol("Trojan UDP domain is truncated"))?;
            String::from_utf8(domain).map_err(|_| protocol("Trojan UDP domain is invalid"))?
        }
        _ => return Err(protocol("Trojan UDP address type is invalid")),
    };
    let port = stream
        .read_u16()
        .await
        .map_err(|_| protocol("Trojan UDP port is truncated"))?;
    if port == 0 {
        return Err(protocol("Trojan UDP port is invalid"));
    }
    Ok(Endpoint { host, port })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::collections::BTreeMap;
    use std::path::PathBuf;
    use std::process::Stdio;

    fn node(protocol: &str, port: u16) -> pathchord_policy::TransitProxyConfig {
        pathchord_policy::TransitProxyConfig {
            id: pathchord_policy::TransitProxyId::new("native-test"),
            source: None,
            protocol: protocol.into(),
            endpoint: pathchord_policy::Endpoint {
                host: "127.0.0.1".into(),
                port,
            },
            credentials_ref: None,
            labels: Default::default(),
            tags: Default::default(),
            weight: 1,
            options: Default::default(),
        }
    }

    #[test]
    fn vless_request_encodes_remote_domains_and_ipv6_without_local_resolution() {
        let uuid = [7; 16];
        let request = vless_request(
            &uuid,
            &Endpoint {
                host: "remote.test".into(),
                port: 443,
            },
            false,
        )
        .unwrap();
        assert_eq!(&request[..18], &[vec![0], uuid.to_vec(), vec![0]].concat());
        assert_eq!(
            &request[18..],
            &[vec![1, 1, 187, 2, 11], b"remote.test".to_vec()].concat()
        );
        let request = vless_request(
            &uuid,
            &Endpoint {
                host: "::1".into(),
                port: 53,
            },
            true,
        )
        .unwrap();
        assert_eq!(&request[18..22], &[2, 0, 53, 3]);
        assert_eq!(&request[22..], &std::net::Ipv6Addr::LOCALHOST.octets());
    }

    #[tokio::test]
    async fn vless_response_strips_only_bounded_protocol_metadata() {
        for version in [0, 1] {
            let (mut peer, io) = tokio::io::duplex(64);
            let mut stream = VlessResponseIo {
                inner: Box::new(io),
                header: [0; 2],
                filled: 0,
                addon_remaining: None,
            };
            let task = tokio::spawn(async move {
                peer.write_all(&[version, 3, 1, 2, 3]).await.unwrap();
                peer.write_all(b"application").await.unwrap();
                peer.shutdown().await.unwrap();
            });
            let mut output = Vec::new();
            let result = stream.read_to_end(&mut output).await;
            if version == 0 {
                assert!(result.is_ok());
                assert_eq!(&output, b"application");
            } else {
                assert!(result.is_err());
                assert!(output.is_empty());
            }
            task.await.unwrap();
        }
    }

    #[test]
    fn native_protocols_reject_unimplemented_flow_and_transport_options() {
        let mut node = node("vless", 443);
        let credentials = TransitCredential::new(BTreeMap::from([
            ("uuid".into(), "6cbf3f72-3417-4922-bde6-67820d041f25".into()),
            ("flow".into(), "xtls-rprx-vision".into()),
        ]));
        assert!(
            NativeProtocolAdapter::from_config(
                &node,
                &credentials,
                Duration::from_secs(1),
                crate::adapter_registry::native_tls_roots()
            )
            .is_err()
        );
        node.options.transport = Some(pathchord_policy::TransitTransport {
            kind: "grpc".into(),
            service_name: Some("service".into()),
            ..Default::default()
        });
        let credentials = TransitCredential::new(BTreeMap::from([(
            "uuid".into(),
            "6cbf3f72-3417-4922-bde6-67820d041f25".into(),
        )]));
        assert!(
            NativeProtocolAdapter::from_config(
                &node,
                &credentials,
                Duration::from_secs(1),
                crate::adapter_registry::native_tls_roots()
            )
            .is_err()
        );
    }

    #[tokio::test]
    #[ignore = "requires PATHCHORD_TEST_SING_BOX for native Rust protocol interoperability"]
    async fn rust_vless_and_trojan_interoperate_over_tcp_tls_and_websocket() {
        timeout(Duration::from_secs(45),async {
            let binary=PathBuf::from(std::env::var_os("PATHCHORD_TEST_SING_BOX").expect("reference engine"));
            for (protocol,tls,websocket) in [("vless",false,false),("vless",true,false),("vless",false,true),("vless",true,true),("trojan",true,false),("trojan",true,true)] {
                let listener=std::net::TcpListener::bind("127.0.0.1:0").unwrap();let port=listener.local_addr().unwrap().port();drop(listener);
                let field=if protocol=="vless"{"uuid"}else{"password"};
                let secret=if protocol=="vless"{"6cbf3f72-3417-4922-bde6-67820d041f25"}else{"native-trojan-secret"};
                let mut inbound=json!({"type":protocol,"listen":"127.0.0.1","listen_port":port,"users":[{field:secret}]});
                let mut config=node(protocol,port);
                if tls {
                    let rcgen::CertifiedKey{cert,signing_key}=rcgen::generate_simple_self_signed(vec!["proxy.test".into()]).unwrap();
                    inbound["tls"]=json!({"enabled":true,"certificate":cert.pem(),"key":signing_key.serialize_pem()});
                    config.options.tls=Some(pathchord_policy::TransitTls{enabled:true,server_name:Some("proxy.test".into()),certificate:vec![cert.pem()],..Default::default()});
                }
                if websocket {
                    inbound["transport"]=json!({"type":"ws","path":"/rust-native"});
                    config.options.transport=Some(pathchord_policy::TransitTransport{kind:"ws".into(),path:Some("/rust-native".into()),host:vec!["proxy.test".into()],..Default::default()});
                }
                let body=Zeroizing::new(serde_json::to_vec(&json!({"log":{"disabled":true},"inbounds":[inbound],"outbounds":[{"type":"direct","tag":"direct"}],"route":{"final":"direct"}})).unwrap());
                let mut server=tokio::process::Command::new(&binary).arg("run").arg("-c").arg("stdin").stdin(Stdio::piped()).stdout(Stdio::null()).stderr(Stdio::null()).kill_on_drop(true).spawn().unwrap();
                server.stdin.take().unwrap().write_all(&body).await.unwrap();
                let deadline=tokio::time::Instant::now()+Duration::from_secs(3);
                while tokio::net::TcpStream::connect(("127.0.0.1",port)).await.is_err(){assert!(tokio::time::Instant::now()<deadline,"reference readiness");tokio::time::sleep(Duration::from_millis(10)).await;}
                let credentials=TransitCredential::new(BTreeMap::from([(field.into(),secret.into())]));
                let adapter=NativeProtocolAdapter::from_config(&config,&credentials,Duration::from_secs(3),crate::adapter_registry::native_tls_roots()).unwrap();
                let tcp=tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();let target=tcp.local_addr().unwrap();
                let task=tokio::spawn(async move {let(mut io,_)=tcp.accept().await.unwrap();let mut buffer=[0;6];io.read_exact(&mut buffer).await.unwrap();io.write_all(&buffer).await.unwrap();});
                let mut stream=adapter.connect(ConnectRequest {destination:Endpoint{host:"localhost".into(),port:target.port()}}).await.unwrap();
                stream.write_all(b"native").await.unwrap();stream.flush().await.unwrap();let mut received=[0;6];stream.read_exact(&mut received).await.unwrap();assert_eq!(&received,b"native","{protocol}, tls={tls}, ws={websocket}");drop(stream);task.await.unwrap();
                let udp=tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();let target=udp.local_addr().unwrap();
                let task=tokio::spawn(async move {let mut buffer=[0;128];let(length,peer)=udp.recv_from(&mut buffer).await.unwrap();udp.send_to(&buffer[..length],peer).await.unwrap();});
                let mut association=adapter.connect_udp(ConnectRequest{destination:Endpoint{host:target.ip().to_string(),port:target.port()}}).await.unwrap();association.send(b"datagram").await.unwrap();assert_eq!(association.receive().await.unwrap(),b"datagram","{protocol}, tls={tls}, ws={websocket}");association.close().await.unwrap();task.await.unwrap();server.kill().await.unwrap();server.wait().await.unwrap();
            }
        }).await.expect("bounded native protocol interop");
    }
}
