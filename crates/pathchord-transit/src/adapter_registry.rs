use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
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
    source_dir: Option<PathBuf>,
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
            source_dir: None,
        }
    }

    /// Resolve relative TLS truststore sources against the selected
    /// configuration source before an adapter consumes the node.
    #[must_use]
    pub fn with_source_dir(mut self, source_dir: impl Into<PathBuf>) -> Self {
        self.source_dir = Some(source_dir.into());
        self
    }

    #[must_use]
    pub fn available_protocols(&self) -> BTreeSet<String> {
        let protocols: BTreeSet<_> = [
            "direct",
            "http",
            "https",
            "socks5",
            "ss",
            "vless",
            "xtls",
            "trojan",
            "vmess",
            "anytls",
            "hysteria2",
            "tuic",
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
        let config = self.resolve_config(config);
        self.build_native(&config, credential)
    }

    fn resolve_config(&self, config: &TransitProxyConfig) -> TransitProxyConfig {
        let Some(source_dir) = &self.source_dir else {
            return config.clone();
        };
        let mut resolved = config.clone();
        if let Some(tls) = resolved.options.tls.as_mut() {
            for source in &mut tls.truststore {
                if source != "system" && !Path::new(source).is_absolute() {
                    *source = source_dir.join(&*source).to_string_lossy().into_owned();
                }
            }
        }
        resolved
    }

    fn build_native(
        &self,
        config: &TransitProxyConfig,
        credential: &TransitCredential,
    ) -> Result<Arc<dyn TransitAdapter>, TransitError> {
        let mut normalized = config.clone();
        if normalized.protocol == "xtls" {
            if crate::vision::VisionFlow::parse(credential.field("flow"))
                .map_err(|reason| TransitError::Unsupported(reason.to_owned()))?
                .is_none()
            {
                return Err(TransitError::Unsupported(
                    "XTLS alias requires a supported Vision flow".to_owned(),
                ));
            }
            normalized.protocol = "vless".to_owned();
        }
        let multiplex = normalized
            .options
            .multiplex
            .clone()
            .filter(|option| option.enabled);
        if multiplex.is_some() {
            if !matches!(
                normalized.protocol.as_str(),
                "ss" | "vless" | "vmess" | "trojan"
            ) {
                return Err(TransitError::Unsupported(
                    "multiplex is not supported for this Transit protocol".into(),
                ));
            }
            if normalized.options.udp_over_tcp.is_some()
                || normalized.options.packet_encoding.is_some()
            {
                return Err(TransitError::Unsupported(
                    "multiplex conflicts with the configured UDP encoding".into(),
                ));
            }
            normalized.options.multiplex = None;
        }
        let config = &normalized;
        if let Some(tls) = config.options.tls.as_ref()
            && tls
                .fingerprint
                .as_deref()
                .is_some_and(|value| value.eq_ignore_ascii_case("android"))
        {
            if tls.reality.is_some()
                || config.protocol == "vless"
                    && credential
                        .field("flow")
                        .is_some_and(|flow| !flow.is_empty())
            {
                return Err(TransitError::Unsupported(
                    "Android fingerprint supports TLS 1.2 only; Vision and REALITY require TLS 1.3"
                        .into(),
                ));
            }
            if !tls.alpn.is_empty() {
                return Err(TransitError::Unsupported(
                    "Android TLS fingerprint cannot carry ALPN".into(),
                ));
            }
            if config
                .options
                .transport
                .as_ref()
                .is_some_and(|transport| transport.kind != "tcp")
            {
                return Err(TransitError::Unsupported(
                    "Android TLS fingerprint cannot use transports requiring ALPN".into(),
                ));
            }
        }
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
            "vless"
                if config
                    .options
                    .tls
                    .as_ref()
                    .is_some_and(|tls| tls.reality.is_some()) =>
            {
                Arc::new(crate::reality_adapter::RealityVlessAdapter::from_config(
                    config,
                    credential,
                    self.connect_timeout,
                    Arc::clone(&self.tls),
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
            "anytls" => Arc::new(crate::anytls_adapter::AnyTlsAdapter::from_config(
                config,
                credential,
                self.connect_timeout,
                Arc::clone(&self.tls),
            )?),
            "hysteria2" => Arc::new(crate::hysteria2_adapter::Hysteria2Adapter::from_config(
                config,
                credential,
                self.connect_timeout,
                Arc::clone(&self.tls),
            )?),
            "tuic" => Arc::new(crate::tuic_adapter::TuicAdapter::from_config(
                config,
                credential,
                self.connect_timeout,
                Arc::clone(&self.tls),
            )?),
            protocol => {
                return Err(TransitError::AdapterUnavailable {
                    protocol: protocol.to_owned(),
                    reason: "protocol is not registered by this runtime",
                });
            }
        };
        if let Some(multiplex) = multiplex {
            let allow_udp_443 = config.protocol != "vless"
                || !crate::vision::VisionFlow::parse(credential.field("flow"))
                    .map_err(|reason| TransitError::Unsupported(reason.to_owned()))?
                    .is_some_and(|flow| !flow.allow_udp_443);
            Ok(Arc::new(crate::sing_mux::MultiplexAdapter::new(
                adapter,
                &multiplex,
                config.options.udp != Some(false),
                allow_udp_443,
                self.connect_timeout,
            )?))
        } else {
            Ok(adapter)
        }
    }

    pub fn build_dynamic(
        &self,
        node: &DynamicTransitNode,
    ) -> Result<Arc<dyn TransitAdapter>, TransitError> {
        if !matches!(
            node.state,
            DynamicNodeState::Pending | DynamicNodeState::Active
        ) {
            return Err(TransitError::AdapterUnavailable {
                protocol: node.config.protocol.clone(),
                reason: "dynamic Transit node is not active",
            });
        }
        let credential = TransitCredential::new(node.credential().fields());
        self.build_with_credential(&node.config, &credential)
    }

    pub(crate) async fn prepare_dynamic(
        &self,
        node: &DynamicTransitNode,
    ) -> Result<Arc<dyn TransitAdapter>, TransitError> {
        let adapter = self.build_dynamic(node)?;
        prepare_adapter(adapter.as_ref(), self.connect_timeout).await?;
        Ok(adapter)
    }
}

pub(crate) async fn prepare_adapter(
    adapter: &dyn TransitAdapter,
    duration: Duration,
) -> Result<(), TransitError> {
    tokio::time::timeout(duration, adapter.prepare())
        .await
        .map_err(|_| TransitError::Connection("Transit adapter preparation timed out".into()))?
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
        || options.udp_over_tcp.is_some() && !matches!(config.protocol.as_str(), "socks5" | "ss")
        || options.vmess.is_some()
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

    #[tokio::test]
    async fn adapter_preparation_timeout_and_abort_cancel_the_pending_operation() {
        struct BlockingAdapter {
            cancelled: Arc<std::sync::atomic::AtomicBool>,
            entered: Arc<tokio::sync::Notify>,
        }
        struct DropSignal(Arc<std::sync::atomic::AtomicBool>);
        impl Drop for DropSignal {
            fn drop(&mut self) {
                self.0.store(true, std::sync::atomic::Ordering::SeqCst);
            }
        }
        #[async_trait]
        impl TransitAdapter for BlockingAdapter {
            fn metadata(&self) -> &crate::TransitMetadata {
                panic!("not used")
            }
            async fn prepare(&self) -> Result<(), TransitError> {
                let _signal = DropSignal(Arc::clone(&self.cancelled));
                self.entered.notify_one();
                std::future::pending().await
            }
            async fn connect(
                &self,
                _: crate::ConnectRequest,
            ) -> Result<crate::BoxedTransitConnection, TransitError> {
                panic!("not used")
            }
        }
        let cancelled = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let adapter = BlockingAdapter {
            cancelled: Arc::clone(&cancelled),
            entered: Arc::new(tokio::sync::Notify::new()),
        };
        assert!(
            prepare_adapter(&adapter, Duration::from_millis(20))
                .await
                .is_err()
        );
        assert!(cancelled.load(std::sync::atomic::Ordering::SeqCst));
        cancelled.store(false, std::sync::atomic::Ordering::SeqCst);
        let entered = Arc::new(tokio::sync::Notify::new());
        let adapter = Arc::new(BlockingAdapter {
            cancelled: Arc::clone(&cancelled),
            entered: Arc::clone(&entered),
        });
        let task =
            tokio::spawn(
                async move { prepare_adapter(adapter.as_ref(), Duration::from_secs(2)).await },
            );
        tokio::time::timeout(Duration::from_secs(1), entered.notified())
            .await
            .unwrap();
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        assert!(cancelled.load(std::sync::atomic::Ordering::SeqCst));
    }

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

    #[test]
    fn relative_truststore_sources_resolve_from_selected_source_directory() {
        let provider = Arc::new(Credentials {
            requested: Mutex::new(Vec::new()),
        });
        let registry = registry(provider).with_source_dir("/var/lib/pathchord/config");
        let mut node = config("https");
        node.options.tls = Some(pathchord_policy::TransitTls {
            enabled: true,
            truststore: vec!["certs/ca.pem".to_owned(), "system".to_owned()],
            ..Default::default()
        });
        let resolved = registry.resolve_config(&node);
        assert_eq!(
            resolved.options.tls.unwrap().truststore,
            vec![
                "/var/lib/pathchord/config/certs/ca.pem".to_owned(),
                "system".to_owned()
            ]
        );
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

    #[tokio::test]
    async fn namespaced_nodes_retain_distinct_ids_and_original_opaque_credential_references() {
        let provider = Arc::new(Credentials {
            requested: Mutex::new(Vec::new()),
        });
        let registry = registry(provider.clone());
        let mut adapter_ids = BTreeSet::new();
        for (namespace, reference) in [("alpha", "secret-a"), ("beta", "secret-b")] {
            let mut config = config("socks5");
            config.id = TransitProxyId::in_namespace(namespace, "shared-proxy");
            config.credentials_ref = Some(reference.into());
            let adapter = registry.build(&config).await.unwrap();
            assert_eq!(adapter.metadata().adapter_id, config.id.as_str());
            adapter_ids.insert(adapter.metadata().adapter_id.clone());
        }
        assert_eq!(adapter_ids.len(), 2);
        assert_eq!(
            *provider.requested.lock().unwrap(),
            ["secret-a", "secret-b"]
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

    #[test]
    fn xtls_alias_requires_an_explicit_supported_vision_flow() {
        let registry = registry(Arc::new(Credentials {
            requested: Mutex::new(Vec::new()),
        }));
        let mut node = config("xtls");
        node.options.tls = Some(pathchord_policy::TransitTls {
            enabled: true,
            ..Default::default()
        });
        let mut fields =
            BTreeMap::from([("uuid".into(), "6cbf3f72-3417-4922-bde6-67820d041f25".into())]);
        assert!(matches!(
            registry.build_with_credential(&node, &TransitCredential::new(fields.clone())),
            Err(TransitError::Unsupported(_))
        ));
        fields.insert("flow".into(), crate::vision::FLOW_VISION_UDP443.into());
        assert!(
            registry
                .build_with_credential(&node, &TransitCredential::new(fields))
                .is_ok()
        );
    }

    #[tokio::test]
    async fn native_quic_adapters_honor_explicit_udp_enablement_and_disable_before_dialing() {
        let registry = registry(Arc::new(Credentials {
            requested: Mutex::new(Vec::new()),
        }));
        for protocol in ["hysteria2", "tuic"] {
            let mut config = config(protocol);
            // A disabled datagram request must fail before resolution or dialing.
            config.endpoint.host = "must-not-resolve.invalid".into();
            let mut fields = BTreeMap::from([("password".into(), "fixture-password".into())]);
            if protocol == "tuic" {
                fields.insert("uuid".into(), "6cbf3f72-3417-4922-bde6-67820d041f25".into());
            }
            let credentials = TransitCredential::new(fields);
            for udp in [None, Some(true), Some(false)] {
                config.options.udp = udp;
                let adapter = registry
                    .build_with_credential(&config, &credentials)
                    .unwrap();
                assert!(adapter.supports_tcp());
                assert_eq!(adapter.supports_udp(), udp != Some(false), "{protocol}");
                if udp == Some(false) {
                    assert!(matches!(
                        adapter
                            .connect_udp(crate::ConnectRequest {
                                destination: crate::Endpoint {
                                    host: "target.invalid".into(),
                                    port: 53,
                                },
                            })
                            .await,
                        Err(TransitError::Unsupported(_))
                    ));
                }
            }
        }
    }
}
