use std::str::FromStr;
use std::time::Duration;

use async_trait::async_trait;
use pathchord_policy::TransitProxyConfig;
use shadowsocks::ProxyClientStream;
use shadowsocks::config::{ServerConfig, ServerType};
use shadowsocks::context::{Context, SharedContext};
use shadowsocks::crypto::CipherKind;
use tokio::time::timeout;

use crate::{
    AdapterKind, BoxedTransitConnection, ConnectRequest, SubscriptionCredential, TransitAdapter,
    TransitError, TransitMetadata,
};

/// TCP Transit adapter backed by the maintained `shadowsocks-rust` core.
#[derive(Debug)]
pub struct ShadowsocksTransitAdapter {
    metadata: TransitMetadata,
    context: SharedContext,
    server: ServerConfig,
    connect_timeout: Duration,
    udp_enabled: bool,
}

impl ShadowsocksTransitAdapter {
    pub fn from_subscription(
        config: &TransitProxyConfig,
        credential: &SubscriptionCredential,
        connect_timeout: Duration,
    ) -> Result<Self, TransitError> {
        if config.protocol != "ss" {
            return Err(TransitError::Unsupported(
                "Shadowsocks adapter requires protocol ss".into(),
            ));
        }
        crate::adapter_registry::validate_native_options(config, false, false, true)?;
        crate::adapter_registry::validate_subscription_credentials(
            credential,
            &["cipher", "password", "plugin", "plugin_opts"],
        )?;
        if credential
            .field("plugin")
            .is_some_and(|value| !value.is_empty())
            || credential
                .field("plugin_opts")
                .is_some_and(|value| !value.is_empty())
        {
            return Err(TransitError::Unsupported(
                "Shadowsocks plugins are not supported by this adapter".into(),
            ));
        }
        let cipher = credential
            .field("cipher")
            .ok_or_else(|| TransitError::Unsupported("Shadowsocks cipher is missing".into()))?;
        let password = credential
            .field("password")
            .ok_or_else(|| TransitError::Unsupported("Shadowsocks password is missing".into()))?;
        let method = CipherKind::from_str(cipher)
            .map_err(|_| TransitError::Unsupported("Shadowsocks cipher is unsupported".into()))?;
        if !method.is_aead() && !method.is_aead_2022() {
            return Err(TransitError::Unsupported(
                "legacy non-AEAD Shadowsocks ciphers are not supported".into(),
            ));
        }
        let mut server = ServerConfig::new(
            (config.endpoint.host.clone(), config.endpoint.port),
            password,
            method,
        )
        .map_err(|_| TransitError::Unsupported("Shadowsocks credentials are invalid".into()))?;
        server.set_timeout(connect_timeout);
        Ok(Self {
            metadata: TransitMetadata {
                adapter_id: config.id.as_str().to_owned(),
                kind: AdapterKind::ExternalProxy {
                    protocol: "ss".into(),
                },
                labels: config.labels.clone(),
            },
            context: Context::new_shared(ServerType::Local),
            server,
            connect_timeout,
            udp_enabled: config.options.udp != Some(false),
        })
    }
}

#[async_trait]
impl TransitAdapter for ShadowsocksTransitAdapter {
    fn metadata(&self) -> &TransitMetadata {
        &self.metadata
    }

    async fn connect(
        &self,
        request: ConnectRequest,
    ) -> Result<BoxedTransitConnection, TransitError> {
        if request.destination.host.is_empty() || request.destination.port == 0 {
            return Err(TransitError::Unsupported(
                "Shadowsocks destination is invalid".into(),
            ));
        }
        let destination = (request.destination.host, request.destination.port);
        let stream = timeout(
            self.connect_timeout,
            ProxyClientStream::connect(self.context.clone(), &self.server, destination),
        )
        .await
        .map_err(|_| TransitError::Connection("Shadowsocks connection timed out".into()))?
        .map_err(|_| TransitError::Connection("Shadowsocks connection failed".into()))?;
        Ok(Box::new(stream))
    }

    fn supports_udp(&self) -> bool {
        self.udp_enabled
    }

    async fn connect_udp(
        &self,
        request: ConnectRequest,
    ) -> Result<crate::BoxedTransitDatagram, TransitError> {
        if !self.udp_enabled {
            return Err(TransitError::Unsupported(
                "Shadowsocks UDP is disabled".into(),
            ));
        }
        crate::datagram::ss_connect_udp(
            self.context.clone(),
            &self.server,
            &request.destination,
            self.connect_timeout,
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use pathchord_policy::{Endpoint, TransitProxyId, TransitSource};
    use shadowsocks::ProxyListener;
    use shadowsocks::relay::socks5::Address;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, copy_bidirectional};
    use tokio::net::{TcpListener, TcpStream};

    use super::*;

    fn config(server: SocketAddr) -> TransitProxyConfig {
        TransitProxyConfig {
            id: TransitProxyId::new("sip-node"),
            source: Some(TransitSource {
                source_type: "sip008".into(),
                subscription: "provider-a".into(),
            }),
            protocol: "ss".into(),
            endpoint: Endpoint {
                host: server.ip().to_string(),
                port: server.port(),
            },
            credentials_ref: None,
            labels: BTreeMap::new(),
            tags: BTreeSet::new(),
            weight: 100,
            options: Default::default(),
        }
    }

    fn credentials() -> SubscriptionCredential {
        SubscriptionCredential::new(BTreeMap::from([
            ("cipher".into(), "aes-256-gcm".into()),
            ("password".into(), "test-password".into()),
        ]))
    }

    #[test]
    fn rejects_plugins_explicitly() {
        let config = config(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8388));
        let credential = SubscriptionCredential::new(BTreeMap::from([
            ("cipher".into(), "aes-256-gcm".into()),
            ("password".into(), "test-password".into()),
            ("plugin".into(), "obfs-local".into()),
        ]));
        assert!(matches!(
            ShadowsocksTransitAdapter::from_subscription(
                &config,
                &credential,
                Duration::from_secs(1)
            ),
            Err(TransitError::Unsupported(_))
        ));
    }

    #[test]
    fn rejects_legacy_non_aead_ciphers() {
        let config = config(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8388));
        let credential = SubscriptionCredential::new(BTreeMap::from([
            ("cipher".into(), "aes-256-ctr".into()),
            ("password".into(), "test-password".into()),
        ]));
        assert!(matches!(
            ShadowsocksTransitAdapter::from_subscription(
                &config,
                &credential,
                Duration::from_secs(1)
            ),
            Err(TransitError::Unsupported(_))
        ));
    }

    #[tokio::test]
    async fn carries_tcp_bytes_through_a_real_shadowsocks_server() {
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_address = target.local_addr().unwrap();
        let target_task = tokio::spawn(async move {
            let (mut stream, _) = target.accept().await.unwrap();
            let mut payload = [0_u8; 5];
            stream.read_exact(&mut payload).await.unwrap();
            stream.write_all(&payload).await.unwrap();
        });

        let method = CipherKind::from_str("aes-256-gcm").unwrap();
        let server_context = Context::new_shared(ServerType::Server);
        let server_config = ServerConfig::new(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            "test-password",
            method,
        )
        .unwrap();
        let listener = ProxyListener::bind(server_context, &server_config)
            .await
            .unwrap();
        let server_address = listener.local_addr().unwrap();
        let server_task = tokio::spawn(async move {
            let (mut proxy, _) = listener.accept().await.unwrap();
            let destination = proxy.handshake().await.unwrap();
            let address = match destination {
                Address::SocketAddress(address) => address,
                Address::DomainNameAddress(host, port) => {
                    tokio::net::lookup_host((host.as_str(), port))
                        .await
                        .unwrap()
                        .next()
                        .unwrap()
                }
            };
            let mut target = TcpStream::connect(address).await.unwrap();
            copy_bidirectional(&mut proxy, &mut target).await.unwrap();
        });

        let adapter = ShadowsocksTransitAdapter::from_subscription(
            &config(server_address),
            &credentials(),
            Duration::from_secs(2),
        )
        .unwrap();
        let mut stream = adapter
            .connect(ConnectRequest {
                destination: crate::Endpoint {
                    host: target_address.ip().to_string(),
                    port: target_address.port(),
                },
            })
            .await
            .unwrap();
        stream.write_all(b"hello").await.unwrap();
        let mut echoed = [0_u8; 5];
        stream.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"hello");
        drop(stream);

        target_task.await.unwrap();
        server_task.await.unwrap();
    }
}
