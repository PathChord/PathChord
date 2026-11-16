use std::{collections::BTreeMap, sync::Arc, time::Duration};

use pathchord_policy::{
    Endpoint, TransitOptions, TransitProxyConfig, TransitProxyId, TransitReality, TransitTls,
    TransitTransport,
};
use pathchord_transit::{AdapterRegistry, NoTransitCredentials, TransitCredential, TransitError};

fn node(fingerprint: &str) -> TransitProxyConfig {
    TransitProxyConfig {
        id: TransitProxyId::new("legacy-fingerprint"),
        source: None,
        protocol: "vless".into(),
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
                fingerprint: Some(fingerprint.into()),
                ..Default::default()
            }),
            ..Default::default()
        },
    }
}

fn credential(flow: Option<&str>) -> TransitCredential {
    let mut fields =
        BTreeMap::from([("uuid".into(), "6cbf3f72-3417-4922-bde6-67820d041f25".into())]);
    if let Some(flow) = flow {
        fields.insert("flow".into(), flow.into());
    }
    TransitCredential::new(fields)
}

#[test]
fn android_tls12_is_eligible_but_incompatible_combinations_are_rejected() {
    let mut config = node("android");
    let registry = AdapterRegistry::for_configs(
        Arc::new(NoTransitCredentials),
        Duration::from_secs(2),
        [&config],
    )
    .unwrap();
    assert!(
        registry
            .build_with_credential(&config, &credential(None))
            .is_ok()
    );
    config.options.tls.as_mut().unwrap().alpn = vec!["http/1.1".into()];
    assert!(
        matches!(registry.build_with_credential(&config, &credential(None)), Err(TransitError::Unsupported(reason)) if reason.contains("Android") && reason.contains("ALPN"))
    );
    config.options.tls.as_mut().unwrap().alpn.clear();
    for kind in ["ws", "httpupgrade", "http", "grpc", "quic"] {
        config.options.transport = Some(TransitTransport {
            kind: kind.into(),
            ..Default::default()
        });
        assert!(
            matches!(registry.build_with_credential(&config, &credential(None)), Err(TransitError::Unsupported(reason)) if reason.contains("Android")),
            "{kind}"
        );
    }
    config.options.transport = None;
    assert!(
        matches!(registry.build_with_credential(&config, &credential(Some("xtls-rprx-vision"))), Err(TransitError::Unsupported(reason)) if reason.contains("Android") && reason.contains("TLS 1.3"))
    );
}

#[test]
fn legacy_tls12_only_profiles_are_rejected_for_reality_before_dialing() {
    for fingerprint in ["android", "360"] {
        let mut config = node(fingerprint);
        config.options.tls.as_mut().unwrap().reality = Some(TransitReality {
            public_key: "Q7VhOFla3pZJiGzjiNfwi3j-QfEr9FOdDpQIiDANtRM".into(),
            short_id: "0123456789abcdef".into(),
        });
        let registry = AdapterRegistry::for_configs(
            Arc::new(NoTransitCredentials),
            Duration::from_secs(2),
            [&config],
        )
        .unwrap();
        assert!(
            matches!(registry.build_with_credential(&config, &credential(None)), Err(TransitError::Unsupported(reason)) if reason.contains("TLS 1.3")),
            "{fingerprint}"
        );
    }
}

#[test]
fn unsupported_360_cipher_suites_are_reported_before_dialing() {
    let config = node("360");
    let registry = AdapterRegistry::for_configs(
        Arc::new(NoTransitCredentials),
        Duration::from_secs(2),
        [&config],
    )
    .unwrap();
    assert!(
        matches!(registry.build_with_credential(&config, &credential(None)), Err(TransitError::Unsupported(reason)) if reason.contains("360") && reason.contains("cipher"))
    );
}

#[test]
fn upstream_legacy_presets_do_not_offer_tls13_and_360_has_no_native_cipher() {
    fn hello(bytes: &[u8]) -> (Vec<u16>, Vec<u16>) {
        assert_eq!(&bytes[4..6], &[3, 3]);
        let mut pos = 4 + 2 + 32;
        pos += 1 + usize::from(bytes[pos]);
        let count = usize::from(u16::from_be_bytes([bytes[pos], bytes[pos + 1]]));
        pos += 2;
        let ciphers = bytes[pos..pos + count]
            .as_chunks::<2>()
            .0
            .iter()
            .map(|value| u16::from_be_bytes(*value))
            .collect();
        pos += count;
        pos += 1 + usize::from(bytes[pos]);
        let ext_len = usize::from(u16::from_be_bytes([bytes[pos], bytes[pos + 1]]));
        pos += 2;
        let end = pos + ext_len;
        let mut extensions = Vec::new();
        while pos < end {
            extensions.push(u16::from_be_bytes([bytes[pos], bytes[pos + 1]]));
            let size = usize::from(u16::from_be_bytes([bytes[pos + 2], bytes[pos + 3]]));
            pos += 4 + size;
        }
        assert_eq!(pos, bytes.len());
        (ciphers, extensions)
    }
    let (android, android_extensions) =
        hello(include_bytes!("fixtures/dae-utls-1.8.2/android.bin"));
    let (browser360, browser360_extensions) =
        hello(include_bytes!("fixtures/dae-utls-1.8.2/360.bin"));
    for extensions in [android_extensions, browser360_extensions] {
        assert!(
            !extensions.contains(&0x002b),
            "no TLS 1.3 supported_versions"
        );
        assert!(!extensions.contains(&0x0033), "no TLS 1.3 key share");
    }
    let native: Vec<u16> = rustls::crypto::aws_lc_rs::default_provider()
        .cipher_suites
        .iter()
        .map(|suite| u16::from(suite.suite()))
        .collect();
    assert!(android.iter().any(|suite| native.contains(suite)));
    assert!(browser360.iter().all(|suite| !native.contains(suite)));
}

#[tokio::test]
async fn android_rejects_an_advertised_but_unimplemented_cipher() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let peer = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut header = [0; 5];
        stream.read_exact(&mut header).await.unwrap();
        let mut client_hello = vec![0; usize::from(u16::from_be_bytes([header[3], header[4]]))];
        stream.read_exact(&mut client_hello).await.unwrap();
        let mut body = vec![3, 3];
        body.extend_from_slice(&[0x43; 32]);
        body.extend_from_slice(&[0, 0xc0, 0x13, 0, 0, 0]);
        let mut response = vec![2, 0, 0, body.len() as u8];
        response.extend_from_slice(&body);
        let mut record = vec![22, 3, 3];
        record.extend_from_slice(&(response.len() as u16).to_be_bytes());
        record.extend_from_slice(&response);
        stream.write_all(&record).await.unwrap();
    });
    let mut config = node("android");
    config.endpoint.port = port;
    config.options.tls.as_mut().unwrap().truststore.clear();
    let registry = AdapterRegistry::for_configs(
        Arc::new(NoTransitCredentials),
        Duration::from_secs(2),
        [&config],
    )
    .unwrap();
    let adapter = registry
        .build_with_credential(&config, &credential(None))
        .unwrap();
    let result = adapter
        .connect(pathchord_transit::ConnectRequest {
            destination: pathchord_transit::Endpoint {
                host: "192.0.2.1".into(),
                port: 80,
            },
        })
        .await;
    assert!(
        matches!(result, Err(TransitError::Connection(reason)) if reason.contains("Android") && reason.contains("cipher"))
    );
    peer.await.unwrap();
}
