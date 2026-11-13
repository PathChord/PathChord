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
        let tls = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        Ok(Self::new(credentials, connect_timeout, Arc::new(tls)))
    }

    pub fn for_configs<'a>(
        credentials: Arc<P>,
        connect_timeout: Duration,
        configs: impl IntoIterator<Item = &'a TransitProxyConfig>,
    ) -> Result<Self, TransitError> {
        if configs.into_iter().any(|config| config.protocol == "https") {
            return Self::with_native_roots(credentials, connect_timeout);
        }
        let tls = ClientConfig::builder()
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
        let adapter: Arc<dyn TransitAdapter> = match config.protocol.as_str() {
            "direct" => Arc::new(DirectTransitAdapter::new(
                config.id.as_str(),
                self.connect_timeout,
            )),
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
            "vless" => {
                return Err(TransitError::AdapterUnavailable {
                    protocol: "vless".to_owned(),
                    reason: "candidate engine requires a specified UUID/transport mapping and loopback conformance fixture",
                });
            }
            "vmess" => {
                return Err(TransitError::AdapterUnavailable {
                    protocol: "vmess".to_owned(),
                    reason: "candidate engine requires BoringSSL and cross-target interoperability validation",
                });
            }
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
        }
    }

    fn registry(provider: Arc<Credentials>) -> AdapterRegistry<Credentials> {
        let tls = ClientConfig::builder()
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
    async fn unreviewed_protocols_are_typed_unavailable() {
        let provider = Arc::new(Credentials {
            requested: Mutex::new(Vec::new()),
        });
        let registry = registry(provider);
        assert!(matches!(
            registry.build(&config("vless")).await,
            Err(TransitError::AdapterUnavailable { protocol, .. }) if protocol == "vless"
        ));
        assert!(matches!(
            registry.build(&config("vmess")).await,
            Err(TransitError::AdapterUnavailable { protocol, .. }) if protocol == "vmess"
        ));
        assert!(matches!(
            registry.build(&config("xtls")).await,
            Err(TransitError::AdapterUnavailable { protocol, .. }) if protocol == "xtls"
        ));
    }
}
