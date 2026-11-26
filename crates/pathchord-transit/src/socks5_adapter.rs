use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use pathchord_policy::TransitProxyConfig;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;
use zeroize::Zeroize;

use crate::{
    AdapterKind, BoxedTransitConnection, ConnectRequest, Endpoint, TransitAdapter,
    TransitCredential, TransitError, TransitMetadata, connect_tcp_endpoint, validate_destination,
};

use crate::uot;

const SOCKS_VERSION: u8 = 5;
const NO_AUTH: u8 = 0;
const USERNAME_PASSWORD: u8 = 2;
const NO_ACCEPTABLE_METHOD: u8 = 0xff;

#[derive(Clone)]
pub struct Socks5TransitAdapter {
    metadata: TransitMetadata,
    proxy: Endpoint,
    credentials: Option<(String, String)>,
    connect_timeout: Duration,
    tls: Option<(
        Arc<rustls::ClientConfig>,
        rustls::pki_types::ServerName<'static>,
    )>,
    udp_enabled: bool,
    udp_over_tcp_version: Option<u8>,
}

impl std::fmt::Debug for Socks5TransitAdapter {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Socks5TransitAdapter")
            .field("metadata", &self.metadata)
            .field("proxy", &self.proxy)
            .field("authenticated", &self.credentials.is_some())
            .field("connect_timeout", &self.connect_timeout)
            .finish()
    }
}

impl Drop for Socks5TransitAdapter {
    fn drop(&mut self) {
        if let Some((username, password)) = &mut self.credentials {
            username.zeroize();
            password.zeroize();
        }
    }
}

impl Socks5TransitAdapter {
    pub fn from_config(
        config: &TransitProxyConfig,
        credential: Option<&TransitCredential>,
        connect_timeout: Duration,
    ) -> Result<Self, TransitError> {
        Self::from_config_with_udp_over_tcp(
            config,
            credential,
            connect_timeout,
            config.options.udp_over_tcp,
        )
    }

    fn from_config_with_udp_over_tcp(
        config: &TransitProxyConfig,
        credential: Option<&TransitCredential>,
        connect_timeout: Duration,
        udp_over_tcp_version: Option<u8>,
    ) -> Result<Self, TransitError> {
        if udp_over_tcp_version.is_some_and(|version| !matches!(version, 1 | 2)) {
            return Err(TransitError::Unsupported(
                "SOCKS5 UDP-over-TCP version must be 1 or 2".into(),
            ));
        }
        if udp_over_tcp_version.is_some() && config.options.udp == Some(false) {
            return Err(TransitError::Unsupported(
                "SOCKS5 UDP-over-TCP conflicts with disabled UDP".into(),
            ));
        }
        if config.protocol != "socks5" {
            return Err(TransitError::Unsupported(
                "SOCKS5 adapter requires protocol socks5".to_owned(),
            ));
        }
        crate::adapter_registry::validate_native_options(config, true, false, true)?;
        let mut allowed = vec!["username", "password"];
        allowed.extend(
            config
                .options
                .tls
                .as_ref()
                .and_then(|tls| tls.client_key_field.as_deref()),
        );
        crate::adapter_registry::validate_credentials(credential, &allowed)?;
        let tls = match config.options.tls.as_ref() {
            Some(options) if options.enabled => Some((
                crate::tls::configure(
                    crate::adapter_registry::native_tls_roots(),
                    Some(options),
                    credential,
                )?,
                crate::tls::server_name(&config.endpoint.host, Some(options))?,
            )),
            Some(options) if options == &pathchord_policy::TransitTls::default() => None,
            Some(_) => {
                return Err(TransitError::Unsupported(
                    "SOCKS TLS options must enable TLS".into(),
                ));
            }
            None => None,
        };
        if tls.is_some() && config.options.udp == Some(true) && udp_over_tcp_version.is_none() {
            return Err(TransitError::Unsupported(
                "SOCKS UDP over a TLS control connection is unsupported".into(),
            ));
        }
        let udp_enabled =
            config.options.udp != Some(false) && (tls.is_none() || udp_over_tcp_version.is_some());
        let username = credential.and_then(|value| value.field("username"));
        let password = credential.and_then(|value| value.field("password"));
        let credentials = match (username, password) {
            (None, None) => None,
            (Some(username), Some(password))
                if !username.is_empty()
                    && username.len() <= u8::MAX as usize
                    && !password.is_empty()
                    && password.len() <= u8::MAX as usize =>
            {
                Some((username.to_owned(), password.to_owned()))
            }
            _ => {
                return Err(TransitError::Unsupported(
                    "SOCKS5 username/password credentials are incomplete or invalid".to_owned(),
                ));
            }
        };
        Ok(Self {
            metadata: TransitMetadata {
                adapter_id: config.id.as_str().to_owned(),
                kind: AdapterKind::ExternalProxy {
                    protocol: "socks5".to_owned(),
                },
                labels: config.labels.clone(),
            },
            proxy: Endpoint {
                host: config.endpoint.host.clone(),
                port: config.endpoint.port,
            },
            credentials,
            connect_timeout,
            tls,
            udp_enabled,
            udp_over_tcp_version,
        })
    }

    async fn open_tunnel(
        &self,
        destination: &Endpoint,
    ) -> Result<BoxedTransitConnection, TransitError> {
        let stream = connect_tcp_endpoint(&self.proxy, self.connect_timeout).await?;
        let mut stream: BoxedTransitConnection = if let Some((tls, name)) = &self.tls {
            let stream = timeout(
                self.connect_timeout,
                tokio_rustls::TlsConnector::from(Arc::clone(tls)).connect(name.clone(), stream),
            )
            .await
            .map_err(|_| TransitError::Connection("SOCKS TLS handshake timed out".into()))?
            .map_err(|_| TransitError::Connection("SOCKS TLS handshake failed".into()))?;
            Box::new(stream)
        } else {
            Box::new(stream)
        };
        timeout(
            self.connect_timeout,
            establish_socks5_tunnel(&mut stream, destination, self.credentials.as_ref()),
        )
        .await
        .map_err(|_| TransitError::Connection("SOCKS5 handshake timed out".to_owned()))??;
        Ok(stream)
    }
}

#[async_trait]
impl TransitAdapter for Socks5TransitAdapter {
    fn metadata(&self) -> &TransitMetadata {
        &self.metadata
    }

    async fn connect(
        &self,
        request: ConnectRequest,
    ) -> Result<BoxedTransitConnection, TransitError> {
        validate_destination(&request.destination)?;
        self.open_tunnel(&request.destination).await
    }

    fn supports_udp(&self) -> bool {
        self.udp_enabled
    }

    async fn connect_udp(
        &self,
        request: ConnectRequest,
    ) -> Result<crate::BoxedTransitDatagram, TransitError> {
        if !self.supports_udp() {
            return Err(TransitError::Unsupported(
                "SOCKS UDP is disabled or unavailable over TLS".into(),
            ));
        }
        if let Some(version) = self.udp_over_tcp_version {
            validate_destination(&request.destination)?;
            let destination = Endpoint {
                host: uot::request_host(version).to_owned(),
                port: 0,
            };
            let stream = self.open_tunnel(&destination).await?;
            return timeout(
                self.connect_timeout,
                uot::UotDatagram::connect(stream, request.destination, version),
            )
            .await
            .map_err(|_| {
                TransitError::Connection("SOCKS5 UDP-over-TCP handshake timed out".into())
            })?;
        }
        crate::datagram::socks5_connect_udp(
            &self.proxy,
            self.credentials.as_ref(),
            &request.destination,
            self.connect_timeout,
        )
        .await
    }
}

async fn establish_socks5_tunnel<S>(
    stream: &mut S,
    destination: &Endpoint,
    credentials: Option<&(String, String)>,
) -> Result<(), TransitError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let method = if credentials.is_some() {
        USERNAME_PASSWORD
    } else {
        NO_AUTH
    };
    stream
        .write_all(&[SOCKS_VERSION, 1, method])
        .await
        .map_err(|_| TransitError::Connection("SOCKS5 greeting write failed".to_owned()))?;
    let mut selection = [0_u8; 2];
    stream
        .read_exact(&mut selection)
        .await
        .map_err(|_| TransitError::Protocol("SOCKS5 greeting is truncated".to_owned()))?;
    if selection[0] != SOCKS_VERSION || selection[1] == NO_ACCEPTABLE_METHOD {
        return Err(TransitError::Protocol(
            "SOCKS5 proxy rejected authentication methods".to_owned(),
        ));
    }
    if selection[1] != method {
        return Err(TransitError::Protocol(
            "SOCKS5 proxy selected an unoffered authentication method".to_owned(),
        ));
    }
    match selection[1] {
        NO_AUTH => {}
        USERNAME_PASSWORD => {
            let (username, password) = credentials.ok_or_else(|| {
                TransitError::Protocol("SOCKS5 proxy unexpectedly requires credentials".to_owned())
            })?;
            let mut authentication =
                zeroize::Zeroizing::new(Vec::with_capacity(3 + username.len() + password.len()));
            authentication.push(1);
            authentication.push(username.len() as u8);
            authentication.extend_from_slice(username.as_bytes());
            authentication.push(password.len() as u8);
            authentication.extend_from_slice(password.as_bytes());
            stream.write_all(&authentication).await.map_err(|_| {
                TransitError::Connection("SOCKS5 authentication write failed".to_owned())
            })?;
            let mut result = [0_u8; 2];
            stream.read_exact(&mut result).await.map_err(|_| {
                TransitError::Protocol("SOCKS5 authentication response is truncated".to_owned())
            })?;
            if result != [1, 0] {
                return Err(TransitError::Protocol(
                    "SOCKS5 proxy rejected credentials".to_owned(),
                ));
            }
        }
        _ => {
            return Err(TransitError::Protocol(
                "SOCKS5 proxy selected an unoffered authentication method".to_owned(),
            ));
        }
    }

    let mut connect = vec![SOCKS_VERSION, 1, 0];
    if let Ok(address) = destination.host.parse::<IpAddr>() {
        match address {
            IpAddr::V4(address) => {
                connect.push(1);
                connect.extend_from_slice(&address.octets());
            }
            IpAddr::V6(address) => {
                connect.push(4);
                connect.extend_from_slice(&address.octets());
            }
        }
    } else {
        let host = destination.host.as_bytes();
        if host.is_empty() || host.len() > u8::MAX as usize {
            return Err(TransitError::Unsupported(
                "SOCKS5 destination hostname is invalid".to_owned(),
            ));
        }
        connect.push(3);
        connect.push(host.len() as u8);
        connect.extend_from_slice(host);
    }
    connect.extend_from_slice(&destination.port.to_be_bytes());
    stream
        .write_all(&connect)
        .await
        .map_err(|_| TransitError::Connection("SOCKS5 CONNECT write failed".to_owned()))?;

    let mut response = [0_u8; 4];
    stream
        .read_exact(&mut response)
        .await
        .map_err(|_| TransitError::Protocol("SOCKS5 CONNECT response is truncated".to_owned()))?;
    if response[0] != SOCKS_VERSION || response[2] != 0 {
        return Err(TransitError::Protocol(
            "SOCKS5 CONNECT response is malformed".to_owned(),
        ));
    }
    if response[1] != 0 {
        return Err(TransitError::Protocol(
            "SOCKS5 proxy rejected the destination".to_owned(),
        ));
    }
    match response[3] {
        1 => {
            let mut tail = [0_u8; 6];
            stream.read_exact(&mut tail).await.map_err(|_| {
                TransitError::Protocol("SOCKS5 IPv4 bind response is truncated".to_owned())
            })?;
        }
        4 => {
            let mut tail = [0_u8; 18];
            stream.read_exact(&mut tail).await.map_err(|_| {
                TransitError::Protocol("SOCKS5 IPv6 bind response is truncated".to_owned())
            })?;
        }
        3 => {
            let mut length = [0_u8; 1];
            stream.read_exact(&mut length).await.map_err(|_| {
                TransitError::Protocol("SOCKS5 domain bind response is truncated".to_owned())
            })?;
            let mut tail = vec![0_u8; usize::from(length[0]) + 2];
            stream.read_exact(&mut tail).await.map_err(|_| {
                TransitError::Protocol("SOCKS5 domain bind response is truncated".to_owned())
            })?;
        }
        _ => {
            return Err(TransitError::Protocol(
                "SOCKS5 proxy returned an unknown address type".to_owned(),
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use pathchord_policy::{Endpoint as PolicyEndpoint, TransitProxyId};
    use std::collections::{BTreeMap, BTreeSet};
    use tokio::io::{AsyncReadExt, AsyncWriteExt, copy_bidirectional};
    use tokio::net::{TcpListener, TcpStream};

    fn config(proxy: std::net::SocketAddr) -> TransitProxyConfig {
        TransitProxyConfig {
            id: TransitProxyId::new("socks-node"),
            source: None,
            protocol: "socks5".to_owned(),
            endpoint: PolicyEndpoint {
                host: proxy.ip().to_string(),
                port: proxy.port(),
            },
            credentials_ref: Some("socks-auth".to_owned()),
            labels: BTreeMap::new(),
            tags: BTreeSet::new(),
            weight: 100,
            options: Default::default(),
        }
    }

    fn credential() -> TransitCredential {
        TransitCredential::new(BTreeMap::from([
            ("username".to_owned(), "socks-user".to_owned()),
            ("password".to_owned(), "socks-secret".to_owned()),
        ]))
    }

    #[test]
    fn socks5_rejects_an_empty_password_during_preparation() {
        let config = config("127.0.0.1:1080".parse().unwrap());
        let credential = TransitCredential::new(BTreeMap::from([
            ("username".to_owned(), "socks-user".to_owned()),
            ("password".to_owned(), String::new()),
        ]));
        assert!(matches!(
            Socks5TransitAdapter::from_config(&config, Some(&credential), Duration::from_secs(1)),
            Err(TransitError::Unsupported(_))
        ));
    }

    async fn echo_target() -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut payload = [0_u8; 5];
            stream.read_exact(&mut payload).await.unwrap();
            stream.write_all(&payload).await.unwrap();
        });
        (address, task)
    }

    async fn serve_socks5(
        listener: TcpListener,
        target: std::net::SocketAddr,
        authenticated: bool,
    ) {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut greeting = [0_u8; 2];
        stream.read_exact(&mut greeting).await.unwrap();
        assert_eq!(greeting[0], 5);
        let mut methods = vec![0_u8; usize::from(greeting[1])];
        stream.read_exact(&mut methods).await.unwrap();
        let method = if authenticated { 2 } else { 0 };
        assert!(methods.contains(&method));
        stream.write_all(&[5, method]).await.unwrap();
        if authenticated {
            let mut header = [0_u8; 2];
            stream.read_exact(&mut header).await.unwrap();
            assert_eq!(header[0], 1);
            let mut username = vec![0_u8; usize::from(header[1])];
            stream.read_exact(&mut username).await.unwrap();
            let mut password_length = [0_u8; 1];
            stream.read_exact(&mut password_length).await.unwrap();
            let mut password = vec![0_u8; usize::from(password_length[0])];
            stream.read_exact(&mut password).await.unwrap();
            assert_eq!(username, b"socks-user");
            assert_eq!(password, b"socks-secret");
            stream.write_all(&[1, 0]).await.unwrap();
        }
        let mut request = [0_u8; 4];
        stream.read_exact(&mut request).await.unwrap();
        assert_eq!(&request[..3], &[5, 1, 0]);
        match request[3] {
            1 => {
                let mut tail = [0_u8; 6];
                stream.read_exact(&mut tail).await.unwrap();
            }
            3 => {
                let mut length = [0_u8; 1];
                stream.read_exact(&mut length).await.unwrap();
                let mut tail = vec![0_u8; usize::from(length[0]) + 2];
                stream.read_exact(&mut tail).await.unwrap();
            }
            4 => {
                let mut tail = [0_u8; 18];
                stream.read_exact(&mut tail).await.unwrap();
            }
            _ => panic!("unexpected address type"),
        }
        let mut target = TcpStream::connect(target).await.unwrap();
        stream
            .write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0])
            .await
            .unwrap();
        copy_bidirectional(&mut stream, &mut target).await.unwrap();
    }

    async fn run_case(authenticated: bool) {
        let (target, target_task) = echo_target().await;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy = listener.local_addr().unwrap();
        let server = tokio::spawn(serve_socks5(listener, target, authenticated));
        let credential = credential();
        let adapter = Socks5TransitAdapter::from_config(
            &config(proxy),
            authenticated.then_some(&credential),
            Duration::from_secs(2),
        )
        .unwrap();
        assert!(!format!("{adapter:?}").contains("socks-secret"));
        let mut stream = adapter
            .connect(ConnectRequest {
                destination: Endpoint {
                    host: target.ip().to_string(),
                    port: target.port(),
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
        server.await.unwrap();
    }

    #[tokio::test]
    async fn socks5_no_auth_carries_raw_tunnel_bytes() {
        run_case(false).await;
    }

    #[tokio::test]
    async fn socks5_username_password_carries_raw_tunnel_bytes() {
        run_case(true).await;
    }

    #[tokio::test]
    async fn configured_credentials_cannot_be_silently_downgraded_to_no_auth() {
        for udp in [false, true] {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let proxy = listener.local_addr().unwrap();
            let server = tokio::spawn(async move {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut greeting = [0; 3];
                socket.read_exact(&mut greeting).await.unwrap();
                assert_eq!(greeting, [5, 1, 2]);
                socket.write_all(&[5, 0]).await.unwrap();
                let mut byte = [0; 1];
                assert_eq!(socket.read(&mut byte).await.unwrap(), 0);
            });
            let mut cfg = config(proxy);
            cfg.options.udp_over_tcp = Some(2);
            let adapter = Socks5TransitAdapter::from_config(
                &cfg,
                Some(&credential()),
                Duration::from_secs(2),
            )
            .unwrap();
            let request = ConnectRequest {
                destination: Endpoint {
                    host: "127.0.0.1".into(),
                    port: 53,
                },
            };
            if udp {
                assert!(adapter.connect_udp(request).await.is_err());
            } else {
                assert!(adapter.connect(request).await.is_err());
            }
            server.await.unwrap();
        }
    }

    #[test]
    fn udp_over_tcp_rejects_unknown_versions_and_disabled_udp() {
        let mut cfg = config("127.0.0.1:1080".parse().unwrap());
        for version in [0, 3, u8::MAX] {
            cfg.options.udp_over_tcp = Some(version);
            assert!(Socks5TransitAdapter::from_config(&cfg, None, Duration::from_secs(1)).is_err());
        }
        cfg.options.udp_over_tcp = Some(2);
        cfg.options.udp = Some(false);
        assert!(Socks5TransitAdapter::from_config(&cfg, None, Duration::from_secs(1)).is_err());
    }
}
