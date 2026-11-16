use std::str::FromStr;
use std::time::Duration;

use async_trait::async_trait;
use pathchord_policy::TransitProxyConfig;
use shadowsocks::ProxyClientStream;
use shadowsocks::config::{ServerConfig, ServerType};
use shadowsocks::context::{Context, SharedContext};
use shadowsocks::crypto::CipherKind;
use tokio::io::AsyncWriteExt;
use tokio::time::timeout;

use crate::{
    AdapterKind, BoxedTransitConnection, ConnectRequest, SubscriptionCredential, TransitAdapter,
    TransitError, TransitMetadata,
};

#[path = "shadowsocks_aes192.rs"]
mod shadowsocks_aes192;
#[path = "shadowsocks_legacy_common.rs"]
mod shadowsocks_legacy_common;
#[path = "shadowsocks_v2ray_mux.rs"]
mod shadowsocks_v2ray_mux;
#[path = "shadowsocks_v2ray_plugin.rs"]
mod shadowsocks_v2ray_plugin;
#[path = "shadowsocks_xchacha20.rs"]
mod shadowsocks_xchacha20;
#[path = "simple_obfs.rs"]
mod simple_obfs;

/// TCP and UDP Transit adapter backed by the maintained `shadowsocks-rust` core.
pub struct ShadowsocksTransitAdapter {
    metadata: TransitMetadata,
    context: SharedContext,
    server: ShadowsocksServer,
    connect_timeout: Duration,
    udp_enabled: bool,
    udp_over_tcp_version: Option<u8>,
    plugin: Option<Plugin>,
}

impl std::fmt::Debug for ShadowsocksTransitAdapter {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ShadowsocksTransitAdapter")
            .field("metadata", &self.metadata)
            .field("udp_enabled", &self.udp_enabled)
            .field("plugin_configured", &self.plugin.is_some())
            .finish_non_exhaustive()
    }
}

#[derive(Debug)]
enum Plugin {
    Simple(simple_obfs::Config),
    V2ray(shadowsocks_v2ray_plugin::Config),
}

impl Plugin {
    async fn wrap(
        &self,
        stream: BoxedTransitConnection,
        duration: Duration,
    ) -> Result<BoxedTransitConnection, TransitError> {
        match self {
            Self::Simple(config) => Ok(Box::new(simple_obfs::Stream::new(stream, config.clone()))),
            Self::V2ray(config) => config.wrap(stream, duration).await,
        }
    }
}

#[derive(Debug)]
enum ShadowsocksServer {
    Native(Box<ServerConfig>),
    Aes192(shadowsocks_aes192::Config),
    XChaCha20(shadowsocks_xchacha20::Config),
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
        if config
            .options
            .udp_over_tcp
            .is_some_and(|version| !matches!(version, 1 | 2))
            || config.options.udp_over_tcp.is_some() && config.options.udp == Some(false)
        {
            return Err(TransitError::Unsupported(
                "Shadowsocks UDP-over-TCP options are invalid".into(),
            ));
        }
        crate::adapter_registry::validate_native_options(config, false, false, true)?;
        crate::adapter_registry::validate_subscription_credentials(
            credential,
            &["cipher", "password", "plugin", "plugin_opts"],
        )?;
        let plugin = if credential.field("plugin") == Some("v2ray-plugin") {
            Some(Plugin::V2ray(shadowsocks_v2ray_plugin::Config::parse(
                config,
                credential.field("plugin_opts"),
            )?))
        } else {
            simple_obfs::Config::parse(
                credential.field("plugin"),
                credential.field("plugin_opts"),
                config.endpoint.port,
            )?
            .map(Plugin::Simple)
        };
        let cipher = credential
            .field("cipher")
            .ok_or_else(|| TransitError::Unsupported("Shadowsocks cipher is missing".into()))?;
        let server = if cipher == "aes-192-gcm" {
            let password = credential.field("password").ok_or_else(|| {
                TransitError::Unsupported("Shadowsocks password is missing".into())
            })?;
            ShadowsocksServer::Aes192(shadowsocks_aes192::Config::new(
                crate::Endpoint {
                    host: config.endpoint.host.clone(),
                    port: config.endpoint.port,
                },
                password,
            ))
        } else if cipher == "xchacha20" {
            let password = credential.field("password").ok_or_else(|| {
                TransitError::Unsupported("Shadowsocks password is missing".into())
            })?;
            ShadowsocksServer::XChaCha20(shadowsocks_xchacha20::Config::new(
                crate::Endpoint {
                    host: config.endpoint.host.clone(),
                    port: config.endpoint.port,
                },
                password,
            ))
        } else {
            let method = CipherKind::from_str(cipher).map_err(|_| {
                TransitError::Unsupported("Shadowsocks cipher is unsupported".into())
            })?;
            if !method.is_none()
                && !method.is_aead()
                && !method.is_aead_2022()
                && !supported_stream_cipher(method)
            {
                return Err(TransitError::Unsupported(
                    "Shadowsocks cipher is unsupported".into(),
                ));
            }
            let password = match credential.field("password") {
                Some(password) if method.is_none() && !password.is_empty() => {
                    return Err(TransitError::Unsupported(
                        "Shadowsocks none does not use a password".into(),
                    ));
                }
                Some(password) => password,
                None if method.is_none() => "",
                None => {
                    return Err(TransitError::Unsupported(
                        "Shadowsocks password is missing".into(),
                    ));
                }
            };
            let mut server = ServerConfig::new(
                (config.endpoint.host.clone(), config.endpoint.port),
                password,
                method,
            )
            .map_err(|_| TransitError::Unsupported("Shadowsocks credentials are invalid".into()))?;
            server.set_timeout(connect_timeout);
            ShadowsocksServer::Native(Box::new(server))
        };
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
            udp_over_tcp_version: config.options.udp_over_tcp,
            plugin,
        })
    }
    async fn connect_destination(
        &self,
        destination: crate::Endpoint,
    ) -> Result<BoxedTransitConnection, TransitError> {
        let server = match &self.server {
            ShadowsocksServer::Aes192(config) => {
                return config
                    .connect(destination, self.plugin.as_ref(), self.connect_timeout)
                    .await;
            }
            ShadowsocksServer::XChaCha20(config) => {
                return config
                    .connect(destination, self.plugin.as_ref(), self.connect_timeout)
                    .await;
            }
            ShadowsocksServer::Native(server) => server,
        };
        let destination = (destination.host, destination.port);
        let stream: BoxedTransitConnection = timeout(self.connect_timeout, async {
            let mut stream = if let Some(Plugin::V2ray(plugin)) = &self.plugin {
                let endpoint = crate::Endpoint {
                    host: server.addr().host(),
                    port: server.addr().port(),
                };
                let raw = crate::connect_tcp_endpoint(&endpoint, self.connect_timeout).await?;
                let stream = plugin.wrap(Box::new(raw), self.connect_timeout).await?;
                ProxyClientStream::from_stream(self.context.clone(), stream, server, destination)
            } else {
                ProxyClientStream::connect_map(
                    self.context.clone(),
                    server,
                    destination,
                    |stream| -> BoxedTransitConnection {
                        match &self.plugin {
                            Some(Plugin::Simple(config)) => {
                                Box::new(simple_obfs::Stream::new(stream, config.clone()))
                            }
                            None => Box::new(stream),
                            Some(Plugin::V2ray(_)) => unreachable!(),
                        }
                    },
                )
                .await
                .map_err(|_| TransitError::Connection("Shadowsocks connection failed".into()))?
            };
            // Finish the address handshake before accepting caller data.
            // The dependency batches its first write into one encrypted
            // record, which can otherwise truncate a large first payload.
            if stream
                .write(&[])
                .await
                .map_err(|_| TransitError::Connection("Shadowsocks connection failed".into()))?
                != 0
            {
                return Err(TransitError::Connection(
                    "invalid Shadowsocks handshake write".into(),
                ));
            }
            stream
                .flush()
                .await
                .map_err(|_| TransitError::Connection("Shadowsocks connection failed".into()))?;
            Ok::<BoxedTransitConnection, TransitError>(Box::new(stream))
        })
        .await
        .map_err(|_| TransitError::Connection("Shadowsocks connection timed out".into()))??;
        Ok(stream)
    }
}

// Only methods included in the selected upstream client matrix are admitted.
fn supported_stream_cipher(method: CipherKind) -> bool {
    matches!(
        method,
        CipherKind::SS_RC4_MD5
            | CipherKind::RC4
            | CipherKind::CHACHA20
            | CipherKind::AES_128_CTR
            | CipherKind::AES_192_CTR
            | CipherKind::AES_256_CTR
            | CipherKind::AES_128_CFB128
            | CipherKind::AES_192_CFB128
            | CipherKind::AES_256_CFB128
            | CipherKind::AES_128_OFB
            | CipherKind::AES_192_OFB
            | CipherKind::AES_256_OFB
            | CipherKind::CAMELLIA_128_CFB128
            | CipherKind::CAMELLIA_192_CFB128
            | CipherKind::CAMELLIA_256_CFB128
    )
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
        crate::validate_destination(&request.destination)?;
        self.connect_destination(request.destination).await
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
        if let Some(version) = self.udp_over_tcp_version {
            crate::validate_destination(&request.destination)?;
            let target = crate::Endpoint {
                host: crate::uot::request_host(version).into(),
                port: 0,
            };
            let stream = self.connect_destination(target).await?;
            return timeout(
                self.connect_timeout,
                crate::uot::UotDatagram::connect(stream, request.destination, version),
            )
            .await
            .map_err(|_| {
                TransitError::Connection("Shadowsocks UDP-over-TCP handshake timed out".into())
            })?;
        }
        match &self.server {
            ShadowsocksServer::Aes192(config) => {
                config
                    .connect_udp(request.destination, self.connect_timeout)
                    .await
            }
            ShadowsocksServer::XChaCha20(config) => {
                config
                    .connect_udp(request.destination, self.connect_timeout)
                    .await
            }
            ShadowsocksServer::Native(server) => {
                crate::datagram::ss_connect_udp(
                    self.context.clone(),
                    server,
                    &request.destination,
                    self.connect_timeout,
                )
                .await
            }
        }
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
    fn rejects_unknown_plugins_explicitly() {
        let config = config(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8388));
        let credential = SubscriptionCredential::new(BTreeMap::from([
            ("cipher".into(), "aes-256-gcm".into()),
            ("password".into(), "test-password".into()),
            ("plugin".into(), "unknown-plugin".into()),
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
    fn accepts_selected_upstream_stream_ciphers() {
        let config = config(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8388));
        for cipher in [
            "aes-128-ctr",
            "aes-192-ctr",
            "aes-256-ctr",
            "aes-128-cfb",
            "aes-192-cfb",
            "aes-256-cfb",
            "aes-128-ofb",
            "aes-192-ofb",
            "aes-256-ofb",
            "camellia-128-cfb",
            "camellia-192-cfb",
            "camellia-256-cfb",
            "rc4-md5",
            "rc4",
            "chacha20-ietf",
        ] {
            let credential = SubscriptionCredential::new(BTreeMap::from([
                ("cipher".into(), cipher.into()),
                ("password".into(), "test-password".into()),
            ]));
            let adapter = ShadowsocksTransitAdapter::from_subscription(
                &config,
                &credential,
                Duration::from_secs(1),
            )
            .unwrap_or_else(|error| panic!("{cipher}: {error}"));
            assert!(adapter.supports_udp());
        }
    }

    #[test]
    fn accepts_aes_192_gcm_with_udp() {
        let server = config(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8388));
        let credential = SubscriptionCredential::new(BTreeMap::from([
            ("cipher".into(), "aes-192-gcm".into()),
            ("password".into(), "test-password".into()),
        ]));
        let adapter = ShadowsocksTransitAdapter::from_subscription(
            &server,
            &credential,
            Duration::from_secs(1),
        )
        .unwrap();
        assert!(adapter.supports_udp());
    }

    #[test]
    fn accepts_xchacha20_with_udp() {
        let server = config(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8388));
        let credential = SubscriptionCredential::new(BTreeMap::from([
            ("cipher".into(), "xchacha20".into()),
            ("password".into(), "test-password".into()),
        ]));
        let adapter = ShadowsocksTransitAdapter::from_subscription(
            &server,
            &credential,
            Duration::from_secs(1),
        )
        .unwrap();
        assert!(adapter.supports_udp());
    }

    #[test]
    fn accepts_explicit_none_without_ignoring_a_password() {
        let config = config(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8388));
        for cipher in ["none", "plain"] {
            for password in [None, Some("")] {
                let mut fields = BTreeMap::from([("cipher".into(), cipher.into())]);
                if let Some(password) = password {
                    fields.insert("password".into(), password.into());
                }
                let adapter = ShadowsocksTransitAdapter::from_subscription(
                    &config,
                    &SubscriptionCredential::new(fields),
                    Duration::from_secs(1),
                )
                .unwrap();
                assert!(adapter.supports_udp());
            }
            let credentials = SubscriptionCredential::new(BTreeMap::from([
                ("cipher".into(), cipher.into()),
                ("password".into(), "would-be-ignored".into()),
            ]));
            assert!(matches!(
                ShadowsocksTransitAdapter::from_subscription(
                    &config,
                    &credentials,
                    Duration::from_secs(1)
                ),
                Err(TransitError::Unsupported(_))
            ));
        }
    }

    #[test]
    fn rejects_unimplemented_methods() {
        let config = config(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8388));
        for cipher in [
            "",
            "table",
            "chacha20",
            "salsa20",
            "rc4-md5-6",
            "des-cfb",
            "bf-cfb",
            "cast5-cfb",
            "idea-cfb",
            "rc2-cfb",
            "seed-cfb",
        ] {
            let credential = SubscriptionCredential::new(BTreeMap::from([
                ("cipher".into(), cipher.into()),
                ("password".into(), "test-password".into()),
            ]));
            assert!(
                matches!(
                    ShadowsocksTransitAdapter::from_subscription(
                        &config,
                        &credential,
                        Duration::from_secs(1),
                    ),
                    Err(TransitError::Unsupported(_))
                ),
                "{cipher} must be rejected"
            );
        }
    }

    #[tokio::test]
    async fn rejects_invalid_destination_before_opening_socket() {
        let adapter = ShadowsocksTransitAdapter::from_subscription(
            &config(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8388)),
            &credentials(),
            Duration::from_secs(1),
        )
        .unwrap();
        for host in ["a".repeat(256), "bad host".into()] {
            assert!(matches!(
                adapter
                    .connect(ConnectRequest {
                        destination: crate::Endpoint { host, port: 443 },
                    })
                    .await,
                Err(TransitError::Unsupported(_))
            ));
        }
    }

    #[tokio::test]
    async fn carries_tcp_bytes_through_a_real_shadowsocks_server() {
        const PAYLOAD_LENGTH: usize = 65_537;
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_address = target.local_addr().unwrap();
        let target_task = tokio::spawn(async move {
            let (mut stream, _) = target.accept().await.unwrap();
            let mut payload = vec![0_u8; PAYLOAD_LENGTH];
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
        let payload: Vec<_> = (0..PAYLOAD_LENGTH)
            .map(|index| (index % 251) as u8)
            .collect();
        stream.write_all(&payload).await.unwrap();
        let mut echoed = vec![0; PAYLOAD_LENGTH];
        stream.read_exact(&mut echoed).await.unwrap();
        assert_eq!(echoed, payload);
        drop(stream);

        target_task.await.unwrap();
        server_task.await.unwrap();
    }
}
