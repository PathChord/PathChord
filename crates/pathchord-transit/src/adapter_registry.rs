use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

use pathchord_policy::TransitProxyConfig;
use rustls::{ClientConfig, RootCertStore};

use crate::{
    DirectTransitAdapter, DynamicNodeState, DynamicTransitNode, HttpConnectTransitAdapter,
    HttpsConnectTransitAdapter, ShadowsocksTransitAdapter, Socks5TransitAdapter,
    SubscriptionCredential, TransitAdapter, TransitCredential, TransitCredentialProvider,
    TransitError,
};

pub struct AdapterRegistry<P> {
    credentials: Arc<P>,
    connect_timeout: Duration,
    tls: Arc<ClientConfig>,
}

impl<P> std::fmt::Debug for AdapterRegistry<P> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AdapterRegistry")
            .field("connect_timeout", &self.connect_timeout)
            .finish_non_exhaustive()
    }
}

impl<P> AdapterRegistry<P>
where
    P: TransitCredentialProvider + 'static,
{
    #[must_use]
    pub fn new(credentials: Arc<P>, connect_timeout: Duration, tls: Arc<ClientConfig>) -> Self {
        Self {
            credentials,
            connect_timeout,
            tls,
        }
    }

    #[must_use]
    pub fn available_protocols(&self) -> BTreeSet<String> {
        let protocols: BTreeSet<_> = [
            "direct", "http", "https", "socks5", "ss", "vless", "trojan", "vmess",
        ]
        .map(str::to_owned)
        .into();
        protocols
    }

    pub fn with_native_roots(
        credentials: Arc<P>,
        connect_timeout: Duration,
    ) -> Result<Self, TransitError> {
        let loaded = rustls_native_certs::load_native_certs();
        let mut roots = RootCertStore::empty();
        let mut accepted = 0_usize;
        for certificate in loaded.certs {
            if roots.add(certificate).is_ok() {
                accepted += 1;
            }
        }
        if accepted == 0 {
            return Err(TransitError::AdapterUnavailable {
                protocol: "https".to_owned(),
                reason: "native TLS root store is empty",
            });
        }
        let tls = crate::tls::client_builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        Ok(Self::new(credentials, connect_timeout, Arc::new(tls)))
    }

    pub fn for_configs<'a>(
        credentials: Arc<P>,
        connect_timeout: Duration,
        configs: impl IntoIterator<Item = &'a TransitProxyConfig>,
    ) -> Result<Self, TransitError> {
        if configs.into_iter().any(|config| {
            matches!(config.protocol.as_str(), "https" | "trojan")
                || config.options.tls.as_ref().is_some_and(|tls| tls.enabled)
        }) {
            return Self::with_native_roots(credentials, connect_timeout);
        }
        let tls = crate::tls::client_builder()
            .with_root_certificates(RootCertStore::empty())
            .with_no_client_auth();
        Ok(Self::new(credentials, connect_timeout, Arc::new(tls)))
    }

    pub async fn build(
        &self,
        config: &TransitProxyConfig,
    ) -> Result<Arc<dyn TransitAdapter>, TransitError> {
        let credential = match config.credentials_ref.as_deref() {
            Some(reference) if !reference.is_empty() => self
                .credentials
                .resolve(reference)
                .await
                .map_err(|_| TransitError::CredentialProvider)?
                .ok_or_else(|| TransitError::CredentialUnavailable {
                    reference: reference.to_owned(),
                })?,
            Some(_) => {
                return Err(TransitError::Unsupported(
                    "Transit credentialsRef is empty".to_owned(),
                ));
            }
            None => TransitCredential::default(),
        };
        self.build_with_credential(config, &credential)
    }

    pub fn build_with_credential(
        &self,
        config: &TransitProxyConfig,
        credential: &TransitCredential,
    ) -> Result<Arc<dyn TransitAdapter>, TransitError> {
        self.build_native(config, credential)
    }

    fn build_native(
        &self,
        config: &TransitProxyConfig,
        credential: &TransitCredential,
    ) -> Result<Arc<dyn TransitAdapter>, TransitError> {
        let adapter: Arc<dyn TransitAdapter> = match config.protocol.as_str() {
            "direct" => {
                validate_native_options(config, false, false, true)?;
                validate_credentials(nonempty_credential(credential), &[])?;
                Arc::new(
                    DirectTransitAdapter::new(config.id.as_str(), self.connect_timeout)
                        .with_udp_enabled(config.options.udp != Some(false)),
                )
            }
            "http" if config.options.tls.as_ref().is_some_and(|tls| tls.enabled) => {
                Arc::new(HttpsConnectTransitAdapter::from_config(
                    config,
                    nonempty_credential(credential),
                    self.connect_timeout,
                    Arc::clone(&self.tls),
                )?)
            }
            "http" => Arc::new(HttpConnectTransitAdapter::from_config(
                config,
                nonempty_credential(credential),
                self.connect_timeout,
            )?),
            "https" => Arc::new(HttpsConnectTransitAdapter::from_config(
                config,
                nonempty_credential(credential),
                self.connect_timeout,
                Arc::clone(&self.tls),
            )?),
            "socks5" => Arc::new(Socks5TransitAdapter::from_config(
                config,
                nonempty_credential(credential),
                self.connect_timeout,
            )?),
            "ss" => {
                let subscription = SubscriptionCredential::new(credential.fields());
                Arc::new(ShadowsocksTransitAdapter::from_subscription(
                    config,
                    &subscription,
                    self.connect_timeout,
                )?)
            }
            "vless" | "trojan" => {
                Arc::new(crate::native_protocol::NativeProtocolAdapter::from_config(
                    config,
                    credential,
                    self.connect_timeout,
                    Arc::clone(&self.tls),
                )?)
            }
            "vmess" => Arc::new(crate::vmess::VmessAdapter::from_config(
                config,
                credential,
                self.connect_timeout,
                Arc::clone(&self.tls),
            )?),
            "xtls" => {
                return Err(TransitError::AdapterUnavailable {
                    protocol: "xtls".to_owned(),
                    reason: "XTLS Vision requires an encrypting outer transport not represented by the v1 config",
                });
            }
            protocol => {
                return Err(TransitError::AdapterUnavailable {
                    protocol: protocol.to_owned(),
                    reason: "protocol is not registered by this runtime",
                });
            }
        };
        Ok(adapter)
    }

    pub fn build_dynamic(
        &self,
        node: &DynamicTransitNode,
    ) -> Result<Arc<dyn TransitAdapter>, TransitError> {
        if node.state != DynamicNodeState::Active {
            return Err(TransitError::AdapterUnavailable {
                protocol: node.config.protocol.clone(),
                reason: "dynamic Transit node is not active",
            });
        }
        let credential = TransitCredential::new(node.credential().fields());
        self.build_with_credential(&node.config, &credential)
    }
}

fn nonempty_credential(credential: &TransitCredential) -> Option<&TransitCredential> {
    (!credential.is_empty()).then_some(credential)
}

pub(crate) fn native_tls_roots() -> Arc<ClientConfig> {
    let mut roots = RootCertStore::empty();
    for certificate in rustls_native_certs::load_native_certs().certs {
        let _ = roots.add(certificate);
    }
    Arc::new(
        crate::tls::client_builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    )
}

pub(crate) fn validate_credentials(
    credential: Option<&TransitCredential>,
    allowed: &[&str],
) -> Result<(), TransitError> {
    if credential.is_some_and(|credential| {
        credential
            .fields
            .keys()
            .any(|name| !allowed.contains(&name.as_str()))
    }) {
        return Err(TransitError::Unsupported(
            "node contains unsupported credential parameters".into(),
        ));
    }
    Ok(())
}

pub(crate) fn validate_subscription_credentials(
    credential: &SubscriptionCredential,
    allowed: &[&str],
) -> Result<(), TransitError> {
    validate_credentials(Some(&TransitCredential::new(credential.fields())), allowed)
}

pub(crate) fn validate_native_options(
    config: &TransitProxyConfig,
    tls: bool,
    headers: bool,
    udp: bool,
) -> Result<(), TransitError> {
    let options = &config.options;
    let transport_supported = options.transport.as_ref().is_none_or(|transport| {
        transport.kind == "tcp"
            && transport.path.is_none()
            && transport.host.is_empty()
            && transport.headers.is_empty()
            && transport.service_name.is_none()
            && transport.max_early_data.is_none()
            && transport.early_data_header_name.is_none()
    });
    let multiplex_supported = options.multiplex.as_ref().is_none_or(|multiplex| {
        !multiplex.enabled
            && multiplex.protocol.is_none()
            && multiplex.max_connections.is_none()
            && multiplex.min_streams.is_none()
            && multiplex.max_streams.is_none()
            && !multiplex.padding
    });
    if (!tls
        && options
            .tls
            .as_ref()
            .is_some_and(|options| options != &pathchord_policy::TransitTls::default()))
        || (!headers && !options.headers.is_empty())
        || (!udp && options.udp == Some(true))
        || !transport_supported
        || !multiplex_supported
        || options.tcp_fast_open == Some(true)
        || options.bind_interface.is_some()
        || options.routing_mark.is_some()
        || options.packet_encoding.is_some()
    {
        return Err(TransitError::Unsupported(
            "node options require a compatible configured outbound engine".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use pathchord_policy::{Endpoint, TransitProxyId};
    use std::collections::{BTreeMap, BTreeSet};
    use std::sync::Mutex;

    struct Credentials {
        requested: Mutex<Vec<String>>,
    }

    #[async_trait]
    impl TransitCredentialProvider for Credentials {
        async fn resolve(
            &self,
            reference: &str,
        ) -> Result<Option<TransitCredential>, crate::TransitCredentialError> {
            self.requested.lock().unwrap().push(reference.to_owned());
            Ok(Some(TransitCredential::new(BTreeMap::from([
                ("username".to_owned(), "user".to_owned()),
                ("password".to_owned(), "secret-value".to_owned()),
            ]))))
        }
    }

    fn config(protocol: &str) -> TransitProxyConfig {
        TransitProxyConfig {
            id: TransitProxyId::new("proxy-a"),
            source: None,
            protocol: protocol.to_owned(),
            endpoint: Endpoint {
                host: "127.0.0.1".to_owned(),
                port: 8080,
            },
            credentials_ref: Some("opaque-ref".to_owned()),
            labels: BTreeMap::new(),
            tags: BTreeSet::new(),
            weight: 100,
            options: Default::default(),
        }
    }

    fn registry(provider: Arc<Credentials>) -> AdapterRegistry<Credentials> {
        let tls = crate::tls::client_builder()
            .with_root_certificates(RootCertStore::empty())
            .with_no_client_auth();
        AdapterRegistry::new(provider, Duration::from_secs(1), Arc::new(tls))
    }

    #[tokio::test]
    async fn registry_resolves_only_the_opaque_reference() {
        let provider = Arc::new(Credentials {
            requested: Mutex::new(Vec::new()),
        });
        let registry = registry(Arc::clone(&provider));
        let adapter = registry.build(&config("socks5")).await.unwrap();
        assert_eq!(adapter.metadata().adapter_id, "proxy-a");
        assert_eq!(
            provider.requested.lock().unwrap().as_slice(),
            ["opaque-ref"]
        );
    }

    #[test]
    fn credential_debug_never_contains_values() {
        let credential = TransitCredential::new(BTreeMap::from([(
            "password".to_owned(),
            "do-not-print".to_owned(),
        )]));
        let debug = format!("{credential:?}");
        assert!(debug.contains("password"));
        assert!(!debug.contains("do-not-print"));
    }

    #[tokio::test]
    async fn unregistered_protocol_is_typed_unavailable() {
        let provider = Arc::new(Credentials {
            requested: Mutex::new(Vec::new()),
        });
        let registry = registry(provider);
        assert!(matches!(
            registry.build(&config("unregistered-protocol")).await,
            Err(TransitError::AdapterUnavailable { protocol, .. }) if protocol == "unregistered-protocol"
        ));
    }

    #[test]
    fn native_vless_and_trojan_are_available_without_an_external_engine() {
        let provider = Arc::new(Credentials {
            requested: Mutex::new(Vec::new()),
        });
        let registry = registry(provider);
        for (protocol, key, value) in [
            ("vless", "uuid", "6cbf3f72-3417-4922-bde6-67820d041f25"),
            ("trojan", "password", "native-secret"),
        ] {
            let mut config = config(protocol);
            config.credentials_ref = None;
            let credentials = TransitCredential::new(BTreeMap::from([(key.into(), value.into())]));
            let adapter = registry
                .build_with_credential(&config, &credentials)
                .unwrap();
            assert!(adapter.supports_tcp());
            assert!(adapter.supports_udp());
            assert!(registry.available_protocols().contains(protocol));
            config.options.udp = Some(false);
            assert!(
                !registry
                    .build_with_credential(&config, &credentials)
                    .unwrap()
                    .supports_udp()
            );
        }
    }
}
