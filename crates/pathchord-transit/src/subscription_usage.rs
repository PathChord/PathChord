//! Optional provider-reported accounting; absence is never fabricated as zero.

use reqwest::header::HeaderMap;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubscriptionUsage {
    pub upload_bytes: Option<u64>,
    pub download_bytes: Option<u64>,
    pub total_bytes: Option<u64>,
    pub expires_at: Option<u64>,
    pub traffic_multiplier_basis_points: Option<u32>,
}

impl SubscriptionUsage {
    #[must_use]
    pub fn remaining_bytes(&self) -> Option<u64> {
        let used = self.upload_bytes?.checked_add(self.download_bytes?)?;
        self.total_bytes.map(|total| total.saturating_sub(used))
    }

    #[must_use]
    pub fn remaining_ratio(&self) -> Option<f64> {
        let total = self.total_bytes.filter(|total| *total > 0)?;
        Some(self.remaining_bytes()? as f64 / total as f64)
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct SubscriptionDocument {
    pub body: Vec<u8>,
    pub usage: Option<SubscriptionUsage>,
}

impl std::fmt::Debug for SubscriptionDocument {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SubscriptionDocument")
            .field("body_bytes", &self.body.len())
            .field("usage", &self.usage)
            .finish_non_exhaustive()
    }
}

/// `PathChord-Traffic-Multiplier` is an explicit extension header containing a
/// positive decimal multiplier with at most four fractional digits. No
/// multiplier is guessed from names, URLs, traffic counts, or quota.
pub(super) fn parse_usage(headers: &HeaderMap) -> Option<SubscriptionUsage> {
    let mut multiplier_headers = headers.get_all("pathchord-traffic-multiplier").iter();
    let multiplier = multiplier_headers
        .next()
        .and_then(|header| header.to_str().ok())
        .and_then(parse_multiplier);
    let multiplier = if multiplier_headers.next().is_some() {
        None
    } else {
        multiplier
    };
    let statistics = parse_statistics(headers);
    if statistics.is_none() && multiplier.is_none() {
        return None;
    }
    let (upload_bytes, download_bytes, total_bytes, expires_at) = statistics
        .map(|(upload, download, total, expire)| (Some(upload), Some(download), total, expire))
        .unwrap_or_default();
    Some(SubscriptionUsage {
        upload_bytes,
        download_bytes,
        total_bytes,
        expires_at,
        traffic_multiplier_basis_points: multiplier,
    })
}

fn parse_statistics(headers: &HeaderMap) -> Option<(u64, u64, Option<u64>, Option<u64>)> {
    let mut values = headers.get_all("subscription-userinfo").iter();
    let value = values.next()?.to_str().ok()?;
    if values.next().is_some() || value.len() > 1024 {
        return None;
    }
    let mut facts = std::collections::BTreeMap::new();
    for field in value
        .split(';')
        .map(str::trim)
        .filter(|field| !field.is_empty())
    {
        let (key, value) = field.split_once('=').unwrap_or((field, ""));
        let key = key.trim().to_ascii_lowercase();
        if !matches!(key.as_str(), "upload" | "download" | "total" | "expire") {
            continue;
        }
        let value = value.trim();
        let parsed = (!value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()))
            .then(|| value.parse::<u64>().ok())
            .flatten();
        // Duplicate or malformed optional facts invalidate only that fact.
        facts
            .entry(key)
            .and_modify(|value| *value = None)
            .or_insert(parsed);
    }
    let upload = facts.get("upload").copied().flatten()?;
    let download = facts.get("download").copied().flatten()?;
    upload.checked_add(download)?;
    Some((
        upload,
        download,
        facts.get("total").copied().flatten(),
        facts.get("expire").copied().flatten(),
    ))
}

fn parse_multiplier(value: &str) -> Option<u32> {
    let value = value.trim();
    if value.len() > 16 {
        return None;
    }
    let (integer, fraction) = value.split_once('.').unwrap_or((value, ""));
    if integer.is_empty()
        || fraction.len() > 4
        || !integer
            .bytes()
            .chain(fraction.bytes())
            .all(|byte| byte.is_ascii_digit())
    {
        return None;
    }
    let units = integer.parse::<u32>().ok()?.checked_mul(10_000)?;
    let fraction = if fraction.is_empty() {
        0
    } else {
        fraction
            .parse::<u32>()
            .ok()?
            .checked_mul(10_u32.pow(4 - fraction.len() as u32))?
    };
    let result = units.checked_add(fraction)?;
    (1..=1_000_000).contains(&result).then_some(result)
}

#[cfg(test)]
mod tests {
    use super::super::{
        CacheLoadOutcome, HttpSubscriptionFetcher, RefreshOutcome, SubscriptionError,
        SubscriptionFetchRequest, SubscriptionFetcher, SubscriptionManager,
    };
    use super::*;
    use pathchord_policy::{
        SubscriptionCache, SubscriptionConfig, SubscriptionId, SubscriptionRefresh,
        SubscriptionSource, SubscriptionSourceType,
    };
    use std::{collections::BTreeSet, sync::Arc, time::Duration};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn usage(value: &str, multiplier: Option<&str>) -> Option<SubscriptionUsage> {
        let mut headers = HeaderMap::new();
        headers.insert("subscription-userinfo", value.parse().unwrap());
        if let Some(value) = multiplier {
            headers.insert("pathchord-traffic-multiplier", value.parse().unwrap());
        }
        parse_usage(&headers)
    }

    #[test]
    fn parses_explicit_usage_and_multiplier_without_fabricating_missing_metadata() {
        let value = usage(
            "upload=100; download=250; total=1000; expire=1900000000",
            Some("2.1250"),
        )
        .unwrap();
        assert_eq!(value.remaining_bytes(), Some(650));
        assert_eq!(value.remaining_ratio(), Some(0.65));
        assert_eq!(value.expires_at, Some(1_900_000_000));
        assert_eq!(value.traffic_multiplier_basis_points, Some(21_250));
        let value = usage("upload=1; download=2", None).unwrap();
        assert_eq!(value.remaining_bytes(), None);
        assert_eq!(value.remaining_ratio(), None);
        assert_eq!(value.expires_at, None);
        assert_eq!(value.traffic_multiplier_basis_points, None);
    }

    #[test]
    fn malformed_or_overflowing_usage_is_unknown_and_invalid_multiplier_is_absent() {
        for text in [
            "upload=1",
            "upload=no; download=1",
            "upload=1; upload=2; download=1",
            "upload=-1; download=0",
            "upload=18446744073709551615; download=1",
        ] {
            assert!(usage(text, None).is_none());
        }
        for multiplier in ["NaN", "inf", "-1", "0", "1000000000000", "1.12345", "1e2"] {
            assert_eq!(
                usage("upload=1; download=2; total=1", Some(multiplier))
                    .unwrap()
                    .traffic_multiplier_basis_points,
                None
            );
        }
        assert_eq!(
            usage("upload=1; download=2; total=1", None)
                .unwrap()
                .remaining_bytes(),
            Some(0)
        );
        assert_eq!(
            usage("upload=0; download=0; total=0", None)
                .unwrap()
                .remaining_ratio(),
            None
        );
    }

    #[test]
    fn malformed_optional_usage_facts_preserve_required_counts_and_independent_multiplier() {
        for (header, total, expire) in [
            (
                "upload=1; download=2; total=NaN; expire=1900000000",
                None,
                Some(1_900_000_000),
            ),
            (
                "upload=1; download=2; total=100; expire=invalid",
                Some(100),
                None,
            ),
            (
                "upload=1; download=2; total=100; total=101; expire=1900000000",
                None,
                Some(1_900_000_000),
            ),
            (
                "upload=1; download=2; total; expire=18446744073709551616",
                None,
                None,
            ),
        ] {
            let parsed = usage(header, Some("2.5")).unwrap();
            assert_eq!(parsed.upload_bytes, Some(1));
            assert_eq!(parsed.download_bytes, Some(2));
            assert_eq!(parsed.total_bytes, total);
            assert_eq!(parsed.expires_at, expire);
            assert_eq!(parsed.traffic_multiplier_basis_points, Some(25_000));
        }
        for header in [
            "upload=invalid; download=2",
            "upload=1",
            "upload=1; upload=2; download=1",
        ] {
            let parsed = usage(header, Some("2.5")).unwrap();
            assert_eq!((parsed.upload_bytes, parsed.download_bytes), (None, None));
            assert_eq!(parsed.remaining_bytes(), None);
            assert_eq!(parsed.traffic_multiplier_basis_points, Some(25_000));
        }
        let mut headers = HeaderMap::new();
        headers.insert("pathchord-traffic-multiplier", "2.5".parse().unwrap());
        let parsed = parse_usage(&headers).unwrap();
        assert_eq!((parsed.upload_bytes, parsed.download_bytes), (None, None));
        assert_eq!(parsed.remaining_ratio(), None);
        assert_eq!(parsed.traffic_multiplier_basis_points, Some(25_000));
    }

    #[tokio::test]
    async fn http_fetch_extracts_usage_and_private_cache_restores_it() {
        for (userinfo, expected_usage) in [
            (
                Some("upload=100; download=250; total=1000; expire=1900000000"),
                SubscriptionUsage {
                    upload_bytes: Some(100),
                    download_bytes: Some(250),
                    total_bytes: Some(1000),
                    expires_at: Some(1_900_000_000),
                    traffic_multiplier_basis_points: Some(25_000),
                },
            ),
            (
                Some("upload=100; download=250; total=NaN; expire=invalid"),
                SubscriptionUsage {
                    upload_bytes: Some(100),
                    download_bytes: Some(250),
                    total_bytes: None,
                    expires_at: None,
                    traffic_multiplier_basis_points: Some(25_000),
                },
            ),
            (
                None,
                SubscriptionUsage {
                    upload_bytes: None,
                    download_bytes: None,
                    total_bytes: None,
                    expires_at: None,
                    traffic_multiplier_basis_points: Some(25_000),
                },
            ),
        ] {
            let body = "proxies: [{name: node, type: socks5, server: proxy.test, port: 1080}]";
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let endpoint = listener.local_addr().unwrap();
            let server = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut request = Vec::new();
                while !request.ends_with(b"\r\n\r\n") {
                    request.push(stream.read_u8().await.unwrap());
                    assert!(request.len() < 8192);
                }
                let userinfo = userinfo
                    .map(|value| format!("Subscription-Userinfo: {value}\r\n"))
                    .unwrap_or_default();
                stream.write_all(format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n{userinfo}PathChord-Traffic-Multiplier: 2.5\r\nConnection: close\r\n\r\n{body}", body.len()).as_bytes()).await.unwrap();
            });
            static SEQUENCE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            let directory = std::env::temp_dir().join(format!(
                "pathchord-usage-{}-{}",
                std::process::id(),
                SEQUENCE.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            ));
            let config = SubscriptionConfig {
                id: SubscriptionId::new("usage-fixture"),
                enabled: true,
                source: SubscriptionSource {
                    source_type: SubscriptionSourceType::Auto,
                    url: format!("http://{endpoint}/subscription"),
                    credentials_ref: None,
                    user_agent: None,
                },
                refresh: SubscriptionRefresh {
                    max_attempts: 1,
                    ..SubscriptionRefresh::default()
                },
                cache: Some(SubscriptionCache {
                    path: "usage.snapshot".to_owned(),
                    max_age_seconds: 3600,
                }),
            };
            let mut manager = SubscriptionManager::new(
                Arc::new(HttpSubscriptionFetcher::new().unwrap()),
                &directory,
                BTreeSet::from(["socks5".to_owned()]),
            );
            assert!(matches!(
                manager.refresh(&config).await,
                RefreshOutcome::Published { .. }
            ));
            let expected = manager.snapshot().clone();
            let usage = expected
                .nodes
                .values()
                .next()
                .unwrap()
                .usage
                .as_ref()
                .unwrap();
            assert_eq!(usage, &expected_usage);
            server.await.unwrap();
            let mut restored = SubscriptionManager::new(
                Arc::new(HttpSubscriptionFetcher::new().unwrap()),
                &directory,
                BTreeSet::from(["socks5".to_owned()]),
            );
            assert!(matches!(
                restored.load_cache(&config).await.unwrap(),
                CacheLoadOutcome::Loaded { .. }
            ));
            assert_eq!(restored.snapshot(), &expected);
            std::fs::remove_dir_all(directory).unwrap();
        }
    }

    #[test]
    fn previous_cache_numeric_usage_fields_remain_readable() {
        let parsed: SubscriptionUsage = serde_json::from_str(r#"{"upload_bytes":100,"download_bytes":250,"total_bytes":1000,"expires_at":null,"traffic_multiplier_basis_points":25000}"#).unwrap();
        assert_eq!(
            (parsed.upload_bytes, parsed.download_bytes),
            (Some(100), Some(250))
        );
        assert_eq!(parsed.remaining_bytes(), Some(650));
    }

    #[tokio::test]
    async fn malformed_accounting_headers_do_not_discard_a_valid_document() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            while !request.ends_with(b"\r\n\r\n") {
                request.push(stream.read_u8().await.unwrap());
            }
            stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nSubscription-Userinfo: upload=invalid; download=1; total=9\r\nConnection: close\r\n\r\n[]").await.unwrap();
        });
        let document = HttpSubscriptionFetcher::new()
            .unwrap()
            .fetch_document(SubscriptionFetchRequest {
                url: format!("http://{endpoint}/subscription"),
                credentials_ref: None,
                user_agent: None,
                timeout: Duration::from_secs(2),
                max_bytes: 1024,
            })
            .await
            .unwrap();
        assert_eq!(document.body, b"[]");
        assert!(document.usage.is_none());
        server.await.unwrap();
    }

    struct MetadataFetcher;
    #[async_trait::async_trait]
    impl SubscriptionFetcher for MetadataFetcher {
        async fn fetch(&self, _: SubscriptionFetchRequest) -> Result<Vec<u8>, SubscriptionError> {
            unreachable!("metadata adapter is used");
        }
        async fn fetch_document(
            &self,
            request: SubscriptionFetchRequest,
        ) -> Result<SubscriptionDocument, SubscriptionError> {
            let (body, total) = if request.url == "https://root.invalid/sub" {
                (
                    "proxies: [{name: inline, type: socks5, server: proxy.test, port: 1080}]\nproxy-providers: {nested: {type: http, url: https://provider.invalid/sub}}",
                    1000,
                )
            } else {
                (
                    "proxies: [{name: nested, type: socks5, server: proxy.test, port: 1080}]",
                    2000,
                )
            };
            Ok(SubscriptionDocument {
                body: body.as_bytes().to_vec(),
                usage: Some(SubscriptionUsage {
                    upload_bytes: Some(100),
                    download_bytes: Some(200),
                    total_bytes: Some(total),
                    expires_at: None,
                    traffic_multiplier_basis_points: None,
                }),
            })
        }
    }

    #[tokio::test]
    async fn referenced_provider_accounting_overrides_parent_metadata_only_for_its_nodes() {
        let config = SubscriptionConfig {
            id: SubscriptionId::new("provider-usage"),
            enabled: true,
            source: SubscriptionSource {
                source_type: SubscriptionSourceType::Auto,
                url: "https://root.invalid/sub".to_owned(),
                credentials_ref: None,
                user_agent: None,
            },
            refresh: SubscriptionRefresh {
                max_attempts: 1,
                ..SubscriptionRefresh::default()
            },
            cache: None,
        };
        let mut manager = SubscriptionManager::new(
            Arc::new(MetadataFetcher),
            std::env::temp_dir(),
            BTreeSet::from(["socks5".to_owned()]),
        );
        assert!(matches!(
            manager.refresh(&config).await,
            RefreshOutcome::Published { .. }
        ));
        let root = manager
            .snapshot()
            .nodes
            .values()
            .find(|node| node.config.labels["source.name"] == "inline")
            .unwrap();
        let nested = manager
            .snapshot()
            .nodes
            .values()
            .find(|node| node.config.labels["source.name"] == "nested")
            .unwrap();
        assert_eq!(root.usage.as_ref().unwrap().total_bytes, Some(1000));
        assert_eq!(nested.usage.as_ref().unwrap().total_bytes, Some(2000));
    }
}
