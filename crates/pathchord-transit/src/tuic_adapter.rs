//! Narrow native TUIC v5 TCP adapter over Quinn.
//!
//! This owns the TUIC TLS-exporter authentication and TCP CONNECT stream. UDP
//! relay and 0-RTT remain explicit follow-up work; no external proxy process
//! is involved.

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use async_trait::async_trait;
use quinn::crypto::rustls::QuicClientConfig;
use quinn::{ClientConfig, Endpoint, RecvStream, SendStream, TransportConfig};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::time::timeout;

use crate::tuic_codec::{
    TuicAddress, TuicCredentials, TuicEndpoint, TuicPacket, decode_packet,
    encode_authenticate_token, encode_connect, encode_dissociate, encode_packet,
};
use crate::{
    AdapterKind, BoxedTransitConnection, BoxedTransitDatagram, ConnectRequest,
    Endpoint as TransitEndpoint, TransitAdapter, TransitCredential, TransitDatagram, TransitError,
    TransitMetadata,
};

pub(crate) struct TuicAdapter {
    metadata: TransitMetadata,
    endpoint: TransitEndpoint,
    credentials: TuicCredentials,
    tls: Arc<rustls::ClientConfig>,
    server_name: String,
    timeout: Duration,
}

impl std::fmt::Debug for TuicAdapter {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TuicAdapter")
            .field("metadata", &self.metadata)
            .finish_non_exhaustive()
    }
}

impl TuicAdapter {
    pub fn from_config(
        config: &pathchord_policy::TransitProxyConfig,
        credential: &TransitCredential,
        timeout: Duration,
        base_tls: Arc<rustls::ClientConfig>,
    ) -> Result<Self, TransitError> {
        if config.protocol != "tuic" {
            return Err(unsupported("TUIC adapter requires protocol tuic"));
        }
        crate::adapter_registry::validate_native_options(config, true, false, false)?;
        let uuid = credential
            .field("uuid")
            .ok_or_else(|| unsupported("TUIC UUID is missing"))?;
        let password = credential
            .field("password")
            .ok_or_else(|| unsupported("TUIC password is missing"))?;
        let credentials = TuicCredentials::parse(uuid, password)
            .map_err(|error| unsupported(error.to_string()))?;
        let tls_options = config
            .options
            .tls
            .clone()
            .unwrap_or(pathchord_policy::TransitTls {
                enabled: true,
                alpn: vec!["h3".into()],
                ..Default::default()
            });
        if !tls_options.enabled {
            return Err(unsupported("TUIC requires TLS"));
        }
        let tls = crate::tls::configure(base_tls, Some(&tls_options), Some(credential))?;
        let server_name = tls_options
            .server_name
            .clone()
            .unwrap_or_else(|| config.endpoint.host.clone());
        Ok(Self {
            metadata: TransitMetadata {
                adapter_id: config.id.as_str().to_owned(),
                kind: AdapterKind::ExternalProxy {
                    protocol: "tuic".into(),
                },
                labels: config.labels.clone(),
            },
            endpoint: TransitEndpoint {
                host: config.endpoint.host.clone(),
                port: config.endpoint.port,
            },
            credentials,
            tls,
            server_name,
            timeout,
        })
    }

    async fn connect_session(&self) -> Result<quinn::Connection, TransitError> {
        let address = timeout(
            self.timeout,
            tokio::net::lookup_host((self.endpoint.host.as_str(), self.endpoint.port)),
        )
        .await
        .map_err(|_| TransitError::Connection("TUIC endpoint resolution timed out".into()))?
        .map_err(|_| TransitError::Connection("TUIC endpoint resolution failed".into()))?
        .next()
        .ok_or_else(|| TransitError::Connection("TUIC endpoint did not resolve".into()))?;
        let mut quic = ClientConfig::new(Arc::new(
            QuicClientConfig::try_from((*self.tls).clone())
                .map_err(|_| unsupported("TUIC TLS config is invalid"))?,
        ));
        let mut transport = TransportConfig::default();
        transport.datagram_receive_buffer_size(Some(2 * 1024 * 1024));
        transport.datagram_send_buffer_size(2 * 1024 * 1024);
        quic.transport_config(Arc::new(transport));
        let bind = if address.is_ipv6() {
            "[::]:0"
        } else {
            "0.0.0.0:0"
        };
        let mut endpoint = Endpoint::client(
            bind.parse()
                .map_err(|_| TransitError::Connection("TUIC local bind failed".into()))?,
        )
        .map_err(|_| TransitError::Connection("TUIC QUIC endpoint failed".into()))?;
        endpoint.set_default_client_config(quic);
        let connection = timeout(
            self.timeout,
            endpoint
                .connect(address, &self.server_name)
                .map_err(|_| TransitError::Connection("TUIC QUIC connect failed".into()))?,
        )
        .await
        .map_err(|_| TransitError::Connection("TUIC handshake timed out".into()))?
        .map_err(|error| TransitError::Connection(format!("TUIC handshake failed: {error}")))?;
        let keepalive = connection.clone();
        tokio::spawn(async move {
            keepalive.closed().await;
            drop(endpoint);
        });
        Ok(connection)
    }
}

#[async_trait]
impl TransitAdapter for TuicAdapter {
    fn metadata(&self) -> &TransitMetadata {
        &self.metadata
    }
    fn supports_udp(&self) -> bool {
        true
    }

    async fn connect(
        &self,
        request: ConnectRequest,
    ) -> Result<BoxedTransitConnection, TransitError> {
        crate::validate_destination(&request.destination)?;
        let connection = self.connect_session().await?;
        let mut token = [0_u8; 32];
        connection
            .export_keying_material(
                &mut token,
                &self.credentials.uuid,
                self.credentials.password.as_bytes(),
            )
            .map_err(|_| TransitError::Protocol("TUIC TLS exporter failed".into()))?;
        let mut auth = connection
            .open_uni()
            .await
            .map_err(|_| TransitError::Connection("TUIC auth stream failed".into()))?;
        auth.write_all(&encode_authenticate_token(&self.credentials.uuid, &token))
            .await
            .map_err(|_| TransitError::Connection("TUIC auth write failed".into()))?;
        auth.finish()
            .map_err(|_| TransitError::Connection("TUIC auth finish failed".into()))?;
        let endpoint = TuicEndpoint {
            address: tuic_address(&request.destination)?,
            port: request.destination.port,
        };
        let command = encode_connect(&endpoint).map_err(|error| unsupported(error.to_string()))?;
        let (mut send, recv) = connection
            .open_bi()
            .await
            .map_err(|_| TransitError::Connection("TUIC connect stream failed".into()))?;
        send.write_all(&command)
            .await
            .map_err(|_| TransitError::Connection("TUIC connect command failed".into()))?;
        Ok(Box::new(TuicStream { send, recv }))
    }

    async fn connect_udp(
        &self,
        request: ConnectRequest,
    ) -> Result<BoxedTransitDatagram, TransitError> {
        crate::validate_destination(&request.destination)?;
        let connection = self.connect_session().await?;
        let mut token = [0_u8; 32];
        connection
            .export_keying_material(
                &mut token,
                &self.credentials.uuid,
                self.credentials.password.as_bytes(),
            )
            .map_err(|_| TransitError::Protocol("TUIC TLS exporter failed".into()))?;
        let mut auth = connection
            .open_uni()
            .await
            .map_err(|_| TransitError::Connection("TUIC auth stream failed".into()))?;
        auth.write_all(&encode_authenticate_token(&self.credentials.uuid, &token))
            .await
            .map_err(|_| TransitError::Connection("TUIC auth write failed".into()))?;
        auth.finish()
            .map_err(|_| TransitError::Connection("TUIC auth finish failed".into()))?;
        let endpoint = TuicEndpoint {
            address: tuic_address(&request.destination)?,
            port: request.destination.port,
        };
        let mut association = [0_u8; 2];
        getrandom::fill(&mut association).map_err(|_| {
            TransitError::Connection("TUIC association ID generation failed".into())
        })?;
        let association_id = u16::from_be_bytes(association).max(1);
        Ok(Box::new(TuicDatagram {
            connection,
            endpoint,
            association_id,
            packet_id: 0,
        }))
    }
}

fn tuic_address(endpoint: &TransitEndpoint) -> Result<TuicAddress, TransitError> {
    if let Ok(ip) = endpoint.host.parse::<std::net::IpAddr>() {
        Ok(match ip {
            std::net::IpAddr::V4(value) => TuicAddress::Ipv4(value.octets()),
            std::net::IpAddr::V6(value) => TuicAddress::Ipv6(value.octets()),
        })
    } else if endpoint.host.is_empty() || endpoint.host.len() > 255 {
        Err(unsupported("TUIC destination hostname is invalid"))
    } else {
        Ok(TuicAddress::Domain(endpoint.host.clone()))
    }
}

struct TuicStream {
    send: SendStream,
    recv: RecvStream,
}

#[derive(Debug)]
struct TuicDatagram {
    connection: quinn::Connection,
    endpoint: TuicEndpoint,
    association_id: u16,
    packet_id: u16,
}

#[async_trait]
impl TransitDatagram for TuicDatagram {
    async fn send(&mut self, payload: &[u8]) -> Result<(), TransitError> {
        let packet = encode_packet(&TuicPacket {
            association_id: self.association_id,
            packet_id: self.packet_id,
            fragment_total: 1,
            fragment_id: 0,
            endpoint: self.endpoint.clone(),
            payload: bytes::Bytes::copy_from_slice(payload),
        })
        .map_err(|error| unsupported(error.to_string()))?;
        self.packet_id = self.packet_id.wrapping_add(1);
        self.connection
            .send_datagram(packet)
            .map_err(|_| TransitError::Connection("TUIC UDP datagram send failed".into()))
    }

    async fn receive(&mut self) -> Result<Vec<u8>, TransitError> {
        let packet = self
            .connection
            .read_datagram()
            .await
            .map_err(|_| TransitError::Connection("TUIC UDP datagram receive failed".into()))?;
        let packet = decode_packet(&packet).map_err(|error| unsupported(error.to_string()))?;
        if packet.association_id != self.association_id {
            return Err(TransitError::Protocol(
                "TUIC UDP association ID mismatch".into(),
            ));
        }
        Ok(packet.payload.to_vec())
    }

    async fn close(self: Box<Self>) -> Result<(), TransitError> {
        let mut command = self
            .connection
            .open_uni()
            .await
            .map_err(|_| TransitError::Connection("TUIC dissociate stream failed".into()))?;
        command
            .write_all(&encode_dissociate(self.association_id))
            .await
            .map_err(|_| TransitError::Connection("TUIC dissociate write failed".into()))?;
        command
            .finish()
            .map_err(|_| TransitError::Connection("TUIC dissociate finish failed".into()))?;
        self.connection.close(0u32.into(), b"closed");
        Ok(())
    }
}
impl AsyncRead for TuicStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.recv).poll_read(cx, buffer)
    }
}
impl AsyncWrite for TuicStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.send)
            .poll_write(cx, bytes)
            .map_err(io::Error::other)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.send).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.send).poll_shutdown(cx)
    }
}

fn unsupported(message: impl Into<String>) -> TransitError {
    TransitError::Unsupported(message.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use pathchord_policy::{
        Endpoint as PolicyEndpoint, TransitOptions, TransitProxyId, TransitTls,
    };
    use serde_json::json;
    use std::collections::{BTreeMap, BTreeSet};
    use std::path::PathBuf;
    use std::process::Stdio;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::UdpSocket;
    use tokio::process::Command;

    #[tokio::test]
    #[ignore = "requires PATHCHORD_TEST_SING_BOX pointing to sing-box 1.14.4"]
    async fn native_tuic_tcp_interoperates_with_sing_box() {
        let binary =
            PathBuf::from(std::env::var_os("PATHCHORD_TEST_SING_BOX").expect("reference peer"));
        let uuid = "6cbf3f72-3417-4922-bde6-67820d041f25";
        let password = "pathchord-tuic-password";
        let cert =
            rcgen::generate_simple_self_signed(vec!["tuic.test".into()]).expect("certificate");
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let config = json!({
            "log": {"level": "debug"},
            "inbounds": [{
                "type": "tuic", "listen": "127.0.0.1", "listen_port": port,
                "users": [{"uuid": uuid, "password": password}],
                "tls": {"enabled": true, "alpn": ["h3"], "certificate": cert.cert.pem(), "key": cert.signing_key.serialize_pem()}
            }],
            "outbounds": [{"type": "direct", "tag": "direct"}], "route": {"final": "direct"}
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
            .expect("start reference peer");
        peer.stdin
            .take()
            .expect("peer stdin")
            .write_all(&serde_json::to_vec(&config).unwrap())
            .await
            .unwrap();
        let target = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_addr = target.local_addr().unwrap();
        let target_task = tokio::spawn(async move {
            let (mut stream, _) = target.accept().await.unwrap();
            let mut payload = [0_u8; 6];
            stream.read_exact(&mut payload).await.unwrap();
            stream.write_all(&payload).await.unwrap();
        });
        let node = pathchord_policy::TransitProxyConfig {
            id: TransitProxyId::new("tuic-test"),
            source: None,
            protocol: "tuic".into(),
            endpoint: PolicyEndpoint {
                host: "127.0.0.1".into(),
                port,
            },
            credentials_ref: None,
            labels: BTreeMap::new(),
            tags: BTreeSet::new(),
            weight: 100,
            options: TransitOptions {
                tls: Some(TransitTls {
                    enabled: true,
                    insecure: true,
                    server_name: Some("tuic.test".into()),
                    alpn: vec!["h3".into()],
                    ..Default::default()
                }),
                ..Default::default()
            },
        };
        let credentials = TransitCredential::new(BTreeMap::from([
            ("uuid".into(), uuid.into()),
            ("password".into(), password.into()),
        ]));
        let adapter = TuicAdapter::from_config(
            &node,
            &credentials,
            Duration::from_secs(5),
            crate::adapter_registry::native_tls_roots(),
        )
        .unwrap();
        assert_eq!(adapter.tls.alpn_protocols, vec![b"h3".to_vec()]);
        let mut stream = adapter
            .connect(ConnectRequest {
                destination: TransitEndpoint {
                    host: "127.0.0.1".into(),
                    port: target_addr.port(),
                },
            })
            .await
            .unwrap();
        stream.write_all(b"tuic!!").await.unwrap();
        stream.flush().await.unwrap();
        let mut echoed = [0_u8; 6];
        stream.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"tuic!!");
        target_task.await.unwrap();
        let udp_target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let udp_address = udp_target.local_addr().unwrap();
        let udp_task = tokio::spawn(async move {
            let mut packet = [0_u8; 256];
            let (length, peer) = udp_target.recv_from(&mut packet).await.unwrap();
            udp_target.send_to(&packet[..length], peer).await.unwrap();
        });
        let mut datagram = adapter
            .connect_udp(ConnectRequest {
                destination: TransitEndpoint {
                    host: "127.0.0.1".into(),
                    port: udp_address.port(),
                },
            })
            .await
            .unwrap();
        datagram.send(b"udp-tuic").await.unwrap();
        let received = timeout(Duration::from_secs(5), datagram.receive())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(received, b"udp-tuic");
        datagram.close().await.unwrap();
        udp_task.await.unwrap();
        peer.kill().await.unwrap();
        peer.wait().await.unwrap();
    }
}
