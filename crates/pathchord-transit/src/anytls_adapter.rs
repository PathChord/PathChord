//! Native AnyTLS single-stream adapter.
//!
//! AnyTLS sessions are multiplexed by the protocol, but a Transit adapter owns
//! one bounded stream at a time. The session handshake and frame relay are kept
//! here so the codec remains transport-neutral and can be tested independently.

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use bytes::BytesMut;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio::time::timeout;
use zeroize::Zeroizing;

use crate::anytls_codec::{
    AnyTlsAddress, AnyTlsCommand, AnyTlsFrame, AnyTlsSettings, MAX_FRAME_PAYLOAD,
    authentication_record,
};
use crate::native_transport::NativeTransport;
use crate::{
    AdapterKind, BoxedTransitConnection, ConnectRequest, Endpoint, TransitAdapter,
    TransitCredential, TransitError, TransitMetadata,
};

const STREAM_ID: u32 = 1;
const MAX_HANDSHAKE_BYTES: usize = 128 * 1024;

pub(crate) struct AnyTlsAdapter {
    metadata: TransitMetadata,
    password: Zeroizing<String>,
    transport: NativeTransport,
    udp_enabled: bool,
    timeout: Duration,
}

impl std::fmt::Debug for AnyTlsAdapter {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AnyTlsAdapter")
            .field("metadata", &self.metadata)
            .field("timeout", &self.timeout)
            .finish_non_exhaustive()
    }
}

impl AnyTlsAdapter {
    pub fn from_config(
        config: &pathchord_policy::TransitProxyConfig,
        credential: &TransitCredential,
        timeout: Duration,
        tls: Arc<rustls::ClientConfig>,
    ) -> Result<Self, TransitError> {
        let mut config = config.clone();
        if config.protocol != "anytls" {
            return Err(unsupported("AnyTLS adapter requires protocol anytls"));
        }
        let tls_options = config
            .options
            .tls
            .clone()
            .unwrap_or(pathchord_policy::TransitTls {
                enabled: true,
                ..Default::default()
            });
        if !tls_options.enabled {
            return Err(unsupported("native AnyTLS requires TLS"));
        }
        config.options.tls = Some(tls_options);
        let mut allowed = vec!["password"];
        if let Some(field) = config
            .options
            .tls
            .as_ref()
            .and_then(|tls| tls.client_key_field.as_deref())
        {
            allowed.push(field);
        }
        crate::adapter_registry::validate_credentials(Some(credential), &allowed)?;
        let password = credential
            .field("password")
            .filter(|value| !value.is_empty())
            .ok_or_else(|| unsupported("AnyTLS password is missing"))?;
        let transport = NativeTransport::new(&config, credential, tls, timeout)?;
        Ok(Self {
            metadata: TransitMetadata {
                adapter_id: config.id.as_str().to_owned(),
                kind: AdapterKind::ExternalProxy {
                    protocol: "anytls".to_owned(),
                },
                labels: config.labels.clone(),
            },
            password: Zeroizing::new(password.to_owned()),
            transport,
            udp_enabled: config.options.udp != Some(false),
            timeout,
        })
    }

    async fn open(
        &self,
        destination: &Endpoint,
        eager_payload: Option<bytes::Bytes>,
    ) -> Result<BoxedTransitConnection, TransitError> {
        let destination = anytls_address(destination)?;
        timeout(self.timeout, async {
            let mut stream = self.transport.connect().await?;
            let auth = authentication_record(&self.password, &[]).map_err(protocol)?;
            stream.write_all(&auth).await.map_err(io_failure)?;

            let mut initial = BytesMut::new();
            let settings = AnyTlsSettings(BTreeMap::from([
                ("v".to_owned(), "2".to_owned()),
                ("client".to_owned(), "pathchord".to_owned()),
            ]));
            AnyTlsFrame {
                command: AnyTlsCommand::Settings,
                stream_id: 0,
                payload: settings.encode().map_err(protocol)?,
            }
            .encode(&mut initial)
            .map_err(protocol)?;
            AnyTlsFrame {
                command: AnyTlsCommand::Syn,
                stream_id: STREAM_ID,
                payload: bytes::Bytes::new(),
            }
            .encode(&mut initial)
            .map_err(protocol)?;
            let mut destination_payload = BytesMut::new();
            destination
                .encode(&mut destination_payload)
                .map_err(protocol)?;
            AnyTlsFrame {
                command: AnyTlsCommand::Push,
                stream_id: STREAM_ID,
                payload: destination_payload.freeze(),
            }
            .encode(&mut initial)
            .map_err(protocol)?;
            if let Some(payload) = eager_payload {
                AnyTlsFrame {
                    command: AnyTlsCommand::Push,
                    stream_id: STREAM_ID,
                    payload,
                }
                .encode(&mut initial)
                .map_err(protocol)?;
            }
            stream.write_all(&initial).await.map_err(io_failure)?;
            stream.flush().await.map_err(io_failure)?;
            wait_synack(&mut stream).await?;
            Ok(spawn_stream_relay(stream))
        })
        .await
        .map_err(|_| TransitError::Connection("AnyTLS session timed out".to_owned()))?
    }
}

#[async_trait]
impl TransitAdapter for AnyTlsAdapter {
    fn metadata(&self) -> &TransitMetadata {
        &self.metadata
    }

    fn supports_udp(&self) -> bool {
        self.udp_enabled
    }

    async fn connect(
        &self,
        request: ConnectRequest,
    ) -> Result<BoxedTransitConnection, TransitError> {
        self.open(&request.destination, None).await
    }

    async fn connect_udp(
        &self,
        request: ConnectRequest,
    ) -> Result<crate::BoxedTransitDatagram, TransitError> {
        if !self.udp_enabled {
            return Err(unsupported("AnyTLS UDP is disabled"));
        }
        let target = anytls_address(&request.destination)?;
        let mut request_payload = BytesMut::new();
        request_payload.extend_from_slice(&[1]);
        target.encode(&mut request_payload).map_err(protocol)?;
        let stream = self
            .open(
                &Endpoint {
                    host: "sp.v2.udp-over-tcp.arpa".into(),
                    port: 0,
                },
                Some(request_payload.freeze()),
            )
            .await?;
        Ok(Box::new(AnyTlsDatagram { stream }))
    }
}

struct AnyTlsDatagram {
    stream: BoxedTransitConnection,
}

impl std::fmt::Debug for AnyTlsDatagram {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("AnyTlsDatagram(..)")
    }
}

#[async_trait]
impl crate::TransitDatagram for AnyTlsDatagram {
    async fn send(&mut self, payload: &[u8]) -> Result<(), TransitError> {
        if payload.len() > u16::MAX as usize {
            return Err(unsupported("AnyTLS UDP payload exceeds u16 length"));
        }
        self.stream
            .write_all(&(payload.len() as u16).to_be_bytes())
            .await
            .map_err(io_failure)?;
        self.stream.write_all(payload).await.map_err(io_failure)?;
        self.stream.flush().await.map_err(io_failure)
    }

    async fn receive(&mut self) -> Result<Vec<u8>, TransitError> {
        let mut length = [0_u8; 2];
        self.stream
            .read_exact(&mut length)
            .await
            .map_err(io_failure)?;
        let mut payload = vec![0_u8; u16::from_be_bytes(length) as usize];
        self.stream
            .read_exact(&mut payload)
            .await
            .map_err(io_failure)?;
        Ok(payload)
    }

    async fn close(mut self: Box<Self>) -> Result<(), TransitError> {
        self.stream.shutdown().await.map_err(io_failure)
    }
}

fn anytls_address(endpoint: &Endpoint) -> Result<AnyTlsAddress, TransitError> {
    if endpoint.host.is_empty()
        || (endpoint.port == 0 && endpoint.host != "sp.v2.udp-over-tcp.arpa")
    {
        return Err(unsupported("AnyTLS destination is invalid"));
    }
    if let Ok(address) = endpoint.host.parse::<IpAddr>() {
        return Ok(match address {
            IpAddr::V4(value) => AnyTlsAddress::Ipv4(value.octets(), endpoint.port),
            IpAddr::V6(value) => AnyTlsAddress::Ipv6(value.octets(), endpoint.port),
        });
    }
    Ok(AnyTlsAddress::Domain(endpoint.host.clone(), endpoint.port))
}

async fn wait_synack(stream: &mut BoxedTransitConnection) -> Result<(), TransitError> {
    let mut input = BytesMut::new();
    let mut buffer = [0_u8; 8192];
    loop {
        if input.len() > MAX_HANDSHAKE_BYTES {
            return Err(protocol("AnyTLS handshake exceeded the size bound"));
        }
        if let Some(frame) = AnyTlsFrame::decode(&mut input).map_err(protocol)? {
            match frame.command {
                AnyTlsCommand::SynAck if frame.stream_id == STREAM_ID => return Ok(()),
                AnyTlsCommand::Alert => return Err(protocol("AnyTLS peer rejected the stream")),
                AnyTlsCommand::HeartRequest => {
                    let mut response = BytesMut::new();
                    AnyTlsFrame {
                        command: AnyTlsCommand::HeartResponse,
                        stream_id: 0,
                        payload: frame.payload,
                    }
                    .encode(&mut response)
                    .map_err(protocol)?;
                    stream.write_all(&response).await.map_err(io_failure)?;
                }
                _ => {}
            }
            continue;
        }
        let read = stream.read(&mut buffer).await.map_err(io_failure)?;
        if read == 0 {
            return Err(protocol("AnyTLS peer closed before SYNACK"));
        }
        input.extend_from_slice(&buffer[..read]);
    }
}

fn spawn_stream_relay(stream: BoxedTransitConnection) -> BoxedTransitConnection {
    let (client, server) = tokio::io::duplex(MAX_FRAME_PAYLOAD * 2);
    let (mut client_read, mut client_write) = tokio::io::split(server);
    let (mut upstream_read, mut upstream_write) = tokio::io::split(stream);
    let (control_tx, mut control_rx) = mpsc::channel::<BytesMut>(8);
    tokio::spawn(async move {
        let mut data = vec![0_u8; MAX_FRAME_PAYLOAD];
        loop {
            tokio::select! {
                result = client_read.read(&mut data) => {
                    let Ok(size) = result else { break; };
                    if size == 0 { break; }
                    let mut frame = BytesMut::new();
                    if (AnyTlsFrame { command: AnyTlsCommand::Push, stream_id: STREAM_ID, payload: bytes::Bytes::copy_from_slice(&data[..size]) }).encode(&mut frame).is_err() { break; }
                    if upstream_write.write_all(&frame).await.is_err() { break; }
                }
                control = control_rx.recv() => {
                    let Some(control) = control else { break; };
                    if upstream_write.write_all(&control).await.is_err() { break; }
                }
            }
        }
        let mut fin = BytesMut::new();
        let _ = (AnyTlsFrame {
            command: AnyTlsCommand::Fin,
            stream_id: STREAM_ID,
            payload: bytes::Bytes::new(),
        })
        .encode(&mut fin);
        let _ = upstream_write.write_all(&fin).await;
        let _ = upstream_write.shutdown().await;
    });
    tokio::spawn(async move {
        let mut input = BytesMut::new();
        let mut buffer = [0_u8; 8192];
        while let Ok(read) = upstream_read.read(&mut buffer).await {
            if read == 0 {
                break;
            }
            input.extend_from_slice(&buffer[..read]);
            loop {
                let Ok(Some(frame)) = AnyTlsFrame::decode(&mut input) else {
                    break;
                };
                match frame.command {
                    AnyTlsCommand::Push if frame.stream_id == STREAM_ID => {
                        if client_write.write_all(&frame.payload).await.is_err() {
                            return;
                        }
                    }
                    AnyTlsCommand::HeartRequest => {
                        let mut response = BytesMut::new();
                        if (AnyTlsFrame {
                            command: AnyTlsCommand::HeartResponse,
                            stream_id: 0,
                            payload: frame.payload,
                        })
                        .encode(&mut response)
                        .is_ok()
                        {
                            let _ = control_tx.send(response).await;
                        }
                    }
                    AnyTlsCommand::Fin if frame.stream_id == STREAM_ID => {
                        let _ = client_write.shutdown().await;
                        return;
                    }
                    AnyTlsCommand::Alert => {
                        let _ = client_write.shutdown().await;
                        return;
                    }
                    _ => {}
                }
            }
        }
        let _ = client_write.shutdown().await;
    });
    Box::new(client)
}

fn unsupported(message: &str) -> TransitError {
    TransitError::Unsupported(message.to_owned())
}
fn protocol(message: &str) -> TransitError {
    TransitError::Protocol(message.to_owned())
}
fn io_failure(error: std::io::Error) -> TransitError {
    TransitError::Connection(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::TransitDatagram;
    use pathchord_policy::{Endpoint as PolicyEndpoint, TransitOptions, TransitProxyId};
    use serde_json::json;
    use std::collections::{BTreeMap, BTreeSet};
    use std::path::PathBuf;
    use std::process::Stdio;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::process::Command;

    #[tokio::test]
    #[ignore = "requires PATHCHORD_TEST_SING_BOX pointing to sing-box 1.14.4"]
    async fn native_anytls_tcp_and_udp_interoperate_with_sing_box() {
        let binary =
            PathBuf::from(std::env::var_os("PATHCHORD_TEST_SING_BOX").expect("reference peer"));
        let password = "pathchord-anytls-password";
        let rcgen::CertifiedKey { cert, signing_key } =
            rcgen::generate_simple_self_signed(vec!["anytls.test".into()])
                .expect("test certificate");
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let document = json!({
            "log": {"disabled": true},
            "inbounds": [{
                "type": "anytls",
                "listen": "127.0.0.1",
                "listen_port": port,
                "users": [{"name": "pathchord", "password": password}],
                "udp_timeout": "5m",
                "tls": {"enabled": true, "certificate": cert.pem(), "key": signing_key.serialize_pem()}
            }],
            "outbounds": [{"type": "direct", "tag": "direct"}],
            "route": {"final": "direct"}
        });
        let mut peer = Command::new(binary)
            .arg("run")
            .arg("-c")
            .arg("stdin")
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .expect("start sing-box peer");
        peer.stdin
            .take()
            .expect("peer stdin")
            .write_all(serde_json::to_vec(&document).unwrap().as_slice())
            .await
            .unwrap();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .is_err()
        {
            assert!(
                tokio::time::Instant::now() < deadline,
                "AnyTLS peer readiness"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let target = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_address = target.local_addr().unwrap();
        let target_task = tokio::spawn(async move {
            let (mut stream, _) = target.accept().await.unwrap();
            let mut payload = [0_u8; 7];
            stream.read_exact(&mut payload).await.unwrap();
            stream.write_all(&payload).await.unwrap();
        });
        let config = pathchord_policy::TransitProxyConfig {
            id: TransitProxyId::new("anytls-test"),
            source: None,
            protocol: "anytls".into(),
            endpoint: PolicyEndpoint {
                host: "127.0.0.1".into(),
                port,
            },
            credentials_ref: None,
            labels: BTreeMap::new(),
            tags: BTreeSet::new(),
            weight: 100,
            options: TransitOptions {
                tls: Some(pathchord_policy::TransitTls {
                    enabled: true,
                    insecure: true,
                    server_name: Some("anytls.test".into()),
                    ..Default::default()
                }),
                ..Default::default()
            },
        };
        let credentials =
            TransitCredential::new(BTreeMap::from([("password".into(), password.into())]));
        let adapter = AnyTlsAdapter::from_config(
            &config,
            &credentials,
            Duration::from_secs(5),
            crate::adapter_registry::native_tls_roots(),
        )
        .unwrap();
        let mut stream = adapter
            .connect(ConnectRequest {
                destination: Endpoint {
                    host: "127.0.0.1".into(),
                    port: target_address.port(),
                },
            })
            .await
            .unwrap();
        stream.write_all(b"anytls!").await.unwrap();
        stream.flush().await.unwrap();
        let mut echoed = [0_u8; 7];
        stream.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"anytls!");
        target_task.await.unwrap();
        let udp_target = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let udp_address = udp_target.local_addr().unwrap();
        let udp_task = tokio::spawn(async move {
            let mut payload = [0_u8; 256];
            let (length, peer) = udp_target.recv_from(&mut payload).await.unwrap();
            udp_target.send_to(&payload[..length], peer).await.unwrap();
        });
        let mut datagram = adapter
            .connect_udp(ConnectRequest {
                destination: Endpoint {
                    host: "127.0.0.1".into(),
                    port: udp_address.port(),
                },
            })
            .await
            .unwrap();
        datagram.send(b"anytls-udp").await.unwrap();
        assert_eq!(datagram.receive().await.unwrap(), b"anytls-udp");
        datagram.close().await.unwrap();
        udp_task.await.unwrap();
        peer.kill().await.unwrap();
        peer.wait().await.unwrap();
    }

    #[tokio::test]
    async fn anytls_udp_over_tcp_uses_bounded_length_frames() {
        let (client, mut peer) = tokio::io::duplex(1024);
        let mut datagram = AnyTlsDatagram {
            stream: Box::new(client),
        };
        datagram.send(b"request").await.unwrap();
        let mut header = [0_u8; 2];
        peer.read_exact(&mut header).await.unwrap();
        assert_eq!(u16::from_be_bytes(header), 7);
        let mut request = [0_u8; 7];
        peer.read_exact(&mut request).await.unwrap();
        assert_eq!(&request, b"request");
        peer.write_all(&5_u16.to_be_bytes()).await.unwrap();
        peer.write_all(b"reply").await.unwrap();
        assert_eq!(datagram.receive().await.unwrap(), b"reply");
        assert!(
            datagram
                .send(&vec![0_u8; u16::MAX as usize + 1])
                .await
                .is_err()
        );
    }
}
