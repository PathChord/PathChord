use std::{collections::BTreeMap, sync::Arc, time::Duration};

use pathchord_policy::{Endpoint, TransitOptions, TransitProxyConfig, TransitProxyId, TransitTls};
use pathchord_transit::{AdapterRegistry, NoTransitCredentials, TransitCredential, TransitError};

#[test]
fn quic_adapters_reject_client_hello_fingerprints_before_dialing() {
    for protocol in ["hysteria2", "tuic"] {
        let mut config = TransitProxyConfig {
            id: TransitProxyId::new("quic-fingerprint-test"),
            source: None,
            protocol: protocol.to_owned(),
            endpoint: Endpoint {
                host: "127.0.0.1".into(),
                port: 443,
            },
            credentials_ref: None,
            labels: Default::default(),
            tags: Default::default(),
            weight: 1,
            options: TransitOptions {
                tls: Some(TransitTls {
                    enabled: true,
                    truststore: Vec::new(),
                    ..Default::default()
                }),
                ..Default::default()
            },
        };
        let mut fields = BTreeMap::from([("password".to_owned(), "test-password".to_owned())]);
        if protocol == "tuic" {
            fields.insert(
                "uuid".to_owned(),
                "6cbf3f72-3417-4922-bde6-67820d041f25".to_owned(),
            );
        }
        let credential = TransitCredential::new(fields);
        let registry = AdapterRegistry::for_configs(
            Arc::new(NoTransitCredentials),
            Duration::from_secs(1),
            [&config],
        )
        .unwrap();
        assert!(registry.build_with_credential(&config, &credential).is_ok());
        for fingerprint in ["chrome", "firefox", "unrecognized"] {
            config.options.tls.as_mut().unwrap().fingerprint = Some(fingerprint.to_owned());
            assert!(
                matches!(
                    registry.build_with_credential(&config, &credential),
                    Err(TransitError::Unsupported(reason)) if reason.contains("QUIC") && reason.contains("fingerprint")
                ),
                "{protocol} must reject {fingerprint} before dialing"
            );
        }
    }
}
