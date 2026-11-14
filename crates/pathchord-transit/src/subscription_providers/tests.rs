use std::collections::BTreeMap;
use std::sync::Mutex;

use pathchord_policy::{SubscriptionRefresh, SubscriptionSource};

use super::*;

type Documents = BTreeMap<String, VecDeque<Result<Vec<u8>, SubscriptionError>>>;

#[derive(Default)]
struct Fetcher {
    documents: Mutex<Documents>,
    requests: Mutex<Vec<SubscriptionFetchRequest>>,
}

impl Fetcher {
    fn document(&self, url: &str, body: &str) {
        self.documents
            .lock()
            .unwrap()
            .entry(url.to_owned())
            .or_default()
            .push_back(Ok(body.as_bytes().to_vec()));
    }
}

#[async_trait]
impl SubscriptionFetcher for Fetcher {
    async fn fetch(&self, request: SubscriptionFetchRequest) -> Result<Vec<u8>, SubscriptionError> {
        self.requests.lock().unwrap().push(request.clone());
        self.documents
            .lock()
            .unwrap()
            .get_mut(&request.url)
            .and_then(VecDeque::pop_front)
            .unwrap_or(Err(SubscriptionError::Fetch))
    }

    async fn fetch_document_with_budget(
        &self,
        request: SubscriptionFetchRequest,
        budget: &SubscriptionDownloadBudget,
    ) -> Result<SubscriptionDocument, SubscriptionError> {
        // Scripted failures have no partial transport body to account for.
        let document = self.fetch_document(request).await?;
        budget.charge(document.body.len())?;
        Ok(document)
    }
}

fn config() -> SubscriptionConfig {
    let refresh = SubscriptionRefresh {
        max_attempts: 1,
        ..SubscriptionRefresh::default()
    };
    SubscriptionConfig {
        id: SubscriptionId::new("provider-fixture"),
        enabled: true,
        source: SubscriptionSource {
            source_type: SubscriptionSourceType::Auto,
            url: "https://root.invalid/sub".to_owned(),
            credentials_ref: Some("opaque-reference".to_owned()),
        },
        refresh,
        cache: None,
    }
}

fn manager(fetcher: Arc<Fetcher>) -> SubscriptionManager {
    SubscriptionManager::new(
        fetcher,
        std::env::temp_dir(),
        BTreeSet::from(["http".to_owned(), "socks5".to_owned()]),
    )
}

fn node(name: &str) -> String {
    format!("proxies: [{{name: {name}, type: socks5, server: proxy.test, port: 1080}}]\n")
}

fn reference(name: &str, url: &str) -> String {
    format!("proxy-providers: {{{name}: {{type: http, url: '{url}', path: ignored-cache.yaml}}}}\n")
}

#[tokio::test]
async fn fetches_nested_http_providers_with_one_bound_and_no_local_file_reads() {
    let fetcher = Arc::new(Fetcher::default());
    fetcher.document(
        "https://root.invalid/sub",
        &(node("inline") + &reference("outer", "https://provider.invalid/outer")),
    );
    fetcher.document(
        "https://provider.invalid/outer",
        &(node("outer-node") + &reference("inner", "https://provider.invalid/inner")),
    );
    fetcher.document("https://provider.invalid/inner", &node("inner-node"));
    let mut manager = manager(fetcher.clone());
    let RefreshOutcome::Published { diff, .. } = manager.refresh(&config()).await else {
        panic!("provider expansion");
    };
    assert_eq!(diff.added.len(), 3);
    assert!(diff.unavailable.is_empty());
    assert_eq!(manager.snapshot.selectable_nodes().count(), 3);
    let requests = fetcher.requests.lock().unwrap();
    assert_eq!(requests.len(), 3);
    assert_eq!(
        requests[0].credentials_ref.as_deref(),
        Some("opaque-reference")
    );
    assert!(
        requests[1..]
            .iter()
            .all(|request| request.credentials_ref.is_none())
    );
    assert!(requests[1].max_bytes < MAX_SUBSCRIPTION_BYTES);
    assert!(
        manager
            .snapshot
            .nodes
            .values()
            .filter(|node| node.config.labels.contains_key("source.provider"))
            .count()
            == 2
    );
}

#[tokio::test]
async fn failed_provider_retains_its_last_good_nodes_and_other_sources_continue() {
    let fetcher = Arc::new(Fetcher::default());
    let body = node("inline") + &reference("retained", "https://provider.invalid/nodes");
    fetcher.document("https://root.invalid/sub", &body);
    fetcher.document("https://provider.invalid/nodes", &node("old-provider-node"));
    fetcher.document("https://root.invalid/sub", &body);
    let mut manager = manager(fetcher.clone());
    assert!(matches!(
        manager.refresh(&config()).await,
        RefreshOutcome::Published { .. }
    ));
    let old = manager
        .snapshot
        .nodes
        .values()
        .find(|node| node.config.labels["source.name"] == "old-provider-node")
        .unwrap()
        .config
        .id
        .clone();
    let RefreshOutcome::Published { diff, .. } = manager.refresh(&config()).await else {
        panic!("partial refresh");
    };
    assert!(!diff.draining.contains(&old));
    assert_eq!(manager.snapshot.selectable_nodes().count(), 2);
    assert_eq!(manager.snapshot.nodes[&old].state, DynamicNodeState::Active);
    assert!(manager.snapshot.nodes.values().any(|node| {
        node.diagnostic
            .as_ref()
            .is_some_and(|diagnostic| diagnostic.fields == ["proxy-providers"])
    }));
}

#[tokio::test]
async fn cycles_invalid_urls_and_local_providers_are_retained_as_safe_diagnostics() {
    let fetcher = Arc::new(Fetcher::default());
    fetcher.document(
        "https://root.invalid/sub",
        &(node("good")
            + r#"
proxy-providers:
  cycle: {type: http, url: https://root.invalid/sub}
  disk: {type: file, path: /etc/shadow}
  secret-url: {type: http, url: 'https://user:secret@provider.invalid/sub?token=private'}
  unknown-header: {type: http, url: https://provider.invalid/sub, headers: {Authorization: private}}
"#),
    );
    let mut manager = manager(fetcher.clone());
    assert!(matches!(
        manager.refresh(&config()).await,
        RefreshOutcome::Published { .. }
    ));
    assert_eq!(manager.snapshot.selectable_nodes().count(), 1);
    assert_eq!(fetcher.requests.lock().unwrap().len(), 1);
    assert_eq!(manager.snapshot.nodes.len(), 5);
    let debug = format!("{:?}", manager.snapshot);
    assert!(
        !debug.contains("/etc/shadow")
            && !debug.contains("token=private")
            && !debug.contains("user:secret")
    );
}

#[tokio::test]
async fn provider_depth_reference_count_and_total_bytes_are_bounded() {
    let fetcher = Arc::new(Fetcher::default());
    fetcher.document(
        "https://root.invalid/sub",
        &reference("one", "https://provider.invalid/1"),
    );
    for index in 1..=4 {
        fetcher.document(
            &format!("https://provider.invalid/{index}"),
            &reference("next", &format!("https://provider.invalid/{}", index + 1)),
        );
    }
    let mut instance = manager(fetcher.clone());
    assert!(matches!(
        instance.refresh(&config()).await,
        RefreshOutcome::Published { .. }
    ));
    assert_eq!(
        fetcher.requests.lock().unwrap().len(),
        1 + MAX_PROVIDER_DEPTH
    );
    assert_eq!(instance.snapshot.selectable_nodes().count(), 0);

    let fetcher = Arc::new(Fetcher::default());
    let mut body = String::from("proxy-providers:\n");
    for index in 0..40 {
        body.push_str(&format!(
            "  p{index}: {{type: http, url: https://provider.invalid/{index}}}\n"
        ));
        fetcher.document(
            &format!("https://provider.invalid/{index}"),
            &node(&format!("node-{index}")),
        );
    }
    fetcher.document("https://root.invalid/sub", &body);
    let mut instance = manager(fetcher.clone());
    assert!(matches!(
        instance.refresh(&config()).await,
        RefreshOutcome::Published { .. }
    ));
    assert_eq!(
        fetcher.requests.lock().unwrap().len(),
        1 + MAX_PROVIDER_REFERENCES
    );
    assert_eq!(
        instance.snapshot.selectable_nodes().count(),
        MAX_PROVIDER_REFERENCES
    );

    let fetcher = Arc::new(Fetcher::default());
    fetcher.document(
        "https://root.invalid/sub",
        &(node("good") + &reference("big", "https://provider.invalid/big")),
    );
    fetcher
        .documents
        .lock()
        .unwrap()
        .entry("https://provider.invalid/big".to_owned())
        .or_default()
        .push_back(Ok(vec![b'x'; MAX_SUBSCRIPTION_BYTES]));
    let mut instance = manager(fetcher.clone());
    assert!(matches!(
        instance.refresh(&config()).await,
        RefreshOutcome::Published { .. }
    ));
    assert_eq!(instance.snapshot.selectable_nodes().count(), 1);
    assert!(fetcher.requests.lock().unwrap()[1].max_bytes < MAX_SUBSCRIPTION_BYTES);
}

#[tokio::test]
async fn repeated_display_names_across_providers_have_distinct_stable_ids() {
    let fetcher = Arc::new(Fetcher::default());
    let root = "proxy-providers: {one: {type: http, url: https://provider.invalid/one}, two: {type: http, url: https://provider.invalid/two}}";
    for _ in 0..2 {
        fetcher.document("https://root.invalid/sub", root);
        fetcher.document("https://provider.invalid/one", &node("same-name"));
        fetcher.document("https://provider.invalid/two", &node("same-name"));
    }
    let mut manager = manager(fetcher);
    assert!(matches!(
        manager.refresh(&config()).await,
        RefreshOutcome::Published { .. }
    ));
    let first: BTreeSet<_> = manager.snapshot.nodes.keys().cloned().collect();
    assert_eq!(first.len(), 2);
    assert!(matches!(
        manager.refresh(&config()).await,
        RefreshOutcome::Published { .. }
    ));
    assert_eq!(
        manager
            .snapshot
            .nodes
            .keys()
            .cloned()
            .collect::<BTreeSet<_>>(),
        first
    );
}

#[tokio::test]
async fn provider_fetch_credentials_do_not_cross_origin_boundaries() {
    let fetcher = Arc::new(Fetcher::default());
    fetcher.document("https://root.invalid/sub", "proxy-providers: {same: {type: http, url: https://root.invalid/nodes}, cross: {type: http, url: https://external.invalid/nodes}, downgrade: {type: http, url: http://root.invalid/nodes}}");
    fetcher.document("https://root.invalid/nodes", &node("same"));
    fetcher.document("https://external.invalid/nodes", &node("cross"));
    fetcher.document("http://root.invalid/nodes", &node("downgrade"));
    let mut instance = manager(fetcher.clone());
    assert!(matches!(
        instance.refresh(&config()).await,
        RefreshOutcome::Published { .. }
    ));
    let requests = fetcher.requests.lock().unwrap();
    assert_eq!(requests.len(), 4);
    for request in requests.iter() {
        if request.url.starts_with("https://root.invalid/") {
            assert_eq!(request.credentials_ref.as_deref(), Some("opaque-reference"));
        } else {
            assert!(request.credentials_ref.is_none());
        }
    }
}

struct RecordingHttpFetcher {
    http: HttpSubscriptionFetcher,
    requests: Mutex<Vec<SubscriptionFetchRequest>>,
    remaining: Mutex<Vec<usize>>,
}

#[async_trait]
impl SubscriptionFetcher for RecordingHttpFetcher {
    async fn fetch(&self, request: SubscriptionFetchRequest) -> Result<Vec<u8>, SubscriptionError> {
        self.http.fetch(request).await
    }

    async fn fetch_document_with_budget(
        &self,
        request: SubscriptionFetchRequest,
        budget: &SubscriptionDownloadBudget,
    ) -> Result<SubscriptionDocument, SubscriptionError> {
        self.requests.lock().unwrap().push(request.clone());
        let result = self.http.fetch_document_with_budget(request, budget).await;
        self.remaining.lock().unwrap().push(budget.remaining());
        result
    }
}

#[tokio::test]
async fn interrupted_chunked_providers_share_one_refresh_body_budget() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = listener.local_addr().unwrap();
    let root = format!(
        "{}proxy-providers:\n  a: {{type: http, url: http://{endpoint}/a}}\n  b: {{type: http, url: http://{endpoint}/b}}\n  c: {{type: http, url: http://{endpoint}/c}}\n",
        node("inline"),
    );
    let root_bytes = root.len();
    let server = tokio::spawn(async move {
        for index in 0..3 {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            while !request.ends_with(b"\r\n\r\n") {
                request.push(stream.read_u8().await.unwrap());
                assert!(request.len() < 8192);
            }
            if index == 0 {
                stream.write_all(format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{root}", root.len()
                ).as_bytes()).await.unwrap();
            } else {
                let payload = vec![b'x'; 3 * 1024 * 1024];
                stream.write_all(format!(
                    "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n{:x}\r\n", payload.len()
                ).as_bytes()).await.unwrap();
                if stream.write_all(&payload).await.is_ok() {
                    // The first response transfers a complete 3 MiB body chunk
                    // before framing fails. The next exhausts the remainder.
                    let _ = stream.write_all(b"\r\nINVALID\r\n").await;
                }
            }
        }
    });
    let fetcher = Arc::new(RecordingHttpFetcher {
        http: HttpSubscriptionFetcher::new().unwrap(),
        requests: Mutex::new(Vec::new()),
        remaining: Mutex::new(Vec::new()),
    });
    let mut subscription = config();
    subscription.source.url = format!("http://{endpoint}/sub");
    subscription.source.credentials_ref = None;
    let mut manager = SubscriptionManager::new(
        fetcher.clone(),
        std::env::temp_dir(),
        BTreeSet::from(["socks5".into()]),
    );
    assert!(matches!(
        manager.refresh(&subscription).await,
        RefreshOutcome::Published { .. }
    ));
    server.await.unwrap();
    assert_eq!(manager.snapshot().selectable_nodes().count(), 1);
    let requests = fetcher.requests.lock().unwrap();
    assert_eq!(
        requests.len(),
        3,
        "budget exhaustion must prevent fetching provider c"
    );
    assert!(requests[1].url.ends_with("/a"));
    assert!(requests[2].url.ends_with("/b"));
    let remaining = fetcher.remaining.lock().unwrap();
    assert_eq!(remaining[0], MAX_SUBSCRIPTION_BYTES - root_bytes);
    assert_eq!(
        remaining[1],
        MAX_SUBSCRIPTION_BYTES - root_bytes - 3 * 1024 * 1024
    );
    assert_eq!(requests[2].max_bytes, remaining[1]);
    assert_eq!(remaining[2], 0);
}

#[tokio::test]
async fn same_name_subscriptions_keep_namespace_identity_through_refresh_cache_and_disable() {
    use pathchord_policy::SubscriptionCache;

    static SEQUENCE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

    let directory = std::env::temp_dir().join(format!(
        "pathchord-namespace-cache-{}-{}",
        std::process::id(),
        SEQUENCE.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
    ));
    let fetcher = Arc::new(Fetcher::default());
    let root = node("same-name") + &reference("nested", "https://root.invalid/nested");
    let mut configs = Vec::new();
    for namespace in ["alpha", "beta"] {
        fetcher.document("https://root.invalid/sub", &root);
        fetcher.document("https://root.invalid/nested", &node("same-name"));
        let mut subscription = config();
        subscription.id = SubscriptionId::in_namespace(namespace, "shared-provider");
        subscription.source.credentials_ref = Some(format!("{namespace}-opaque-reference"));
        subscription.cache = Some(SubscriptionCache {
            path: format!("{namespace}.snapshot"),
            max_age_seconds: 3600,
        });
        configs.push(subscription);
    }
    let mut manager = SubscriptionManager::new(
        fetcher.clone(),
        &directory,
        BTreeSet::from(["socks5".into()]),
    );
    for subscription in &configs {
        assert!(matches!(
            manager.refresh(subscription).await,
            RefreshOutcome::Published { .. }
        ));
    }
    assert_eq!(manager.snapshot().selectable_nodes().count(), 4);
    for subscription in &configs {
        let owned = manager
            .snapshot()
            .nodes
            .values()
            .filter(|node| node.source_subscription == subscription.id)
            .collect::<Vec<_>>();
        assert_eq!(owned.len(), 2);
        for node in owned {
            assert_eq!(node.config.id.namespace(), subscription.id.namespace());
            assert!(
                node.config
                    .id
                    .resource_name()
                    .starts_with("shared-provider-")
            );
            assert_eq!(
                node.config.source.as_ref().unwrap().subscription,
                subscription.id.as_str()
            );
        }
    }
    assert_eq!(
        fetcher
            .requests
            .lock()
            .unwrap()
            .iter()
            .map(|request| request.credentials_ref.as_deref())
            .collect::<Vec<_>>(),
        [
            Some("alpha-opaque-reference"),
            Some("alpha-opaque-reference"),
            Some("beta-opaque-reference"),
            Some("beta-opaque-reference")
        ]
    );
    let expected = manager.snapshot().clone();
    let mut restored = SubscriptionManager::new(
        Arc::new(Fetcher::default()),
        &directory,
        BTreeSet::from(["socks5".into()]),
    );
    for subscription in &configs {
        assert!(matches!(
            restored.load_cache(subscription).await.unwrap(),
            CacheLoadOutcome::Loaded { .. }
        ));
    }
    assert_eq!(restored.snapshot(), &expected);
    let mut disabled = configs[0].clone();
    disabled.enabled = false;
    assert!(matches!(
        restored.refresh(&disabled).await,
        RefreshOutcome::Disabled { .. }
    ));
    assert_eq!(restored.snapshot().selectable_nodes().count(), 2);
    assert!(
        restored
            .snapshot()
            .selectable_nodes()
            .all(|node| node.config.id.namespace() == "beta")
    );

    let cache_path = directory.join("alpha.snapshot");
    let mut forged: CacheEnvelope =
        serde_json::from_slice(&std::fs::read(&cache_path).unwrap()).unwrap();
    forged.nodes[0].config.id =
        TransitProxyId::in_namespace("beta", forged.nodes[0].config.id.resource_name());
    atomic_write(&cache_path, &serde_json::to_vec(&forged).unwrap())
        .await
        .unwrap();
    let mut isolated = SubscriptionManager::new(
        Arc::new(Fetcher::default()),
        &directory,
        BTreeSet::from(["socks5".into()]),
    );
    assert!(matches!(
        isolated.load_cache(&configs[1]).await.unwrap(),
        CacheLoadOutcome::Loaded { .. }
    ));
    assert_eq!(
        isolated.load_cache(&configs[0]).await.unwrap_err(),
        SubscriptionError::InvalidCache
    );
    assert_eq!(isolated.snapshot().selectable_nodes().count(), 2);
    assert!(
        isolated
            .snapshot()
            .selectable_nodes()
            .all(|node| node.config.id.namespace() == "beta")
    );
    std::fs::remove_dir_all(directory).unwrap();
}

#[tokio::test]
async fn long_same_prefix_sources_keep_nodes_isolated_through_cache_refresh_and_drain() {
    use pathchord_policy::SubscriptionCache;
    static SEQUENCE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let directory = std::env::temp_dir().join(format!(
        "pathchord-long-source-cache-{}-{}",
        std::process::id(),
        SEQUENCE.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    let fetcher = Arc::new(Fetcher::default());
    let display = "same-very-long-node-display-name";
    let body = format!(
        "proxies: [{{name: {display}, type: socks5, server: proxy.test, port: 1080}}, {{name: {display}, type: socks5, server: proxy.test, port: 1081}}]\n"
    );
    let prefix = "a".repeat(24);
    let mut configs = Vec::new();
    for (index, ending) in ["one", "two"].into_iter().enumerate() {
        let mut source = config();
        source.id = SubscriptionId::in_namespace("tenant", format!("{prefix}-{ending}"));
        source.source.url = format!("https://root.invalid/{ending}");
        source.cache = Some(SubscriptionCache {
            path: format!("{index}.snapshot"),
            max_age_seconds: 3600,
        });
        fetcher.document(&source.source.url, &body);
        configs.push(source);
    }
    let mut manager = SubscriptionManager::new(
        fetcher.clone(),
        &directory,
        BTreeSet::from(["socks5".into()]),
    );
    for source in &configs {
        assert!(matches!(
            manager.refresh(source).await,
            RefreshOutcome::Published { .. }
        ));
    }
    assert_eq!(manager.snapshot().selectable_nodes().count(), 4);
    for node in manager.snapshot().nodes.values() {
        assert_eq!(node.config.id.namespace(), "tenant");
        assert!(node.config.id.resource_name().len() <= 63);
    }
    let expected = manager.snapshot().clone();
    let mut restored = SubscriptionManager::new(
        fetcher.clone(),
        &directory,
        BTreeSet::from(["socks5".into()]),
    );
    for source in &configs {
        assert!(matches!(
            restored.load_cache(source).await.unwrap(),
            CacheLoadOutcome::Loaded { .. }
        ));
    }
    assert_eq!(restored.snapshot(), &expected);
    let mut disabled = configs[0].clone();
    disabled.enabled = false;
    assert!(matches!(
        restored.refresh(&disabled).await,
        RefreshOutcome::Disabled { .. }
    ));
    assert_eq!(restored.snapshot().selectable_nodes().count(), 2);
    assert!(
        restored
            .snapshot()
            .selectable_nodes()
            .all(|node| node.source_subscription == configs[1].id)
    );
    let draining: BTreeSet<_> = restored
        .snapshot()
        .nodes
        .values()
        .filter(|node| node.source_subscription == configs[0].id)
        .map(|node| node.config.id.clone())
        .collect();
    fetcher.document(&configs[0].source.url, &body);
    assert!(matches!(
        restored.refresh(&configs[0]).await,
        RefreshOutcome::Published { .. }
    ));
    restored.complete_draining(&draining);
    assert_eq!(restored.snapshot().selectable_nodes().count(), 4);

    // Old cache IDs are readable; refresh retires them under the same source
    // instead of stealing another source's nodes or resurrecting old Paths.
    let cache_path = directory.join("0.snapshot");
    let mut legacy: CacheEnvelope =
        serde_json::from_slice(&std::fs::read(&cache_path).unwrap()).unwrap();
    let legacy_base = format!(
        "{}-{}",
        canonical_segment(configs[0].id.resource_name(), 24),
        canonical_segment(display, 28)
    );
    let mut legacy_ids = BTreeSet::new();
    for (index, node) in legacy.nodes.iter_mut().enumerate() {
        node.config.id = TransitProxyId::in_namespace(
            "tenant",
            if index == 0 {
                legacy_base.clone()
            } else {
                format!("{legacy_base}-{}", index + 1)
            },
        );
        legacy_ids.insert(node.config.id.clone());
    }
    atomic_write(&cache_path, &serde_json::to_vec(&legacy).unwrap())
        .await
        .unwrap();
    let mut migrated = SubscriptionManager::new(
        fetcher.clone(),
        &directory,
        BTreeSet::from(["socks5".into()]),
    );
    assert!(matches!(
        migrated.load_cache(&configs[0]).await.unwrap(),
        CacheLoadOutcome::Loaded { .. }
    ));
    fetcher.document(&configs[0].source.url, &body);
    let RefreshOutcome::Published { diff, .. } = migrated.refresh(&configs[0]).await else {
        panic!("long source refresh must publish")
    };
    assert_eq!(
        diff.draining.into_iter().collect::<BTreeSet<_>>(),
        legacy_ids
    );
    migrated.complete_draining(&legacy_ids);
    assert_eq!(migrated.snapshot().selectable_nodes().count(), 2);
    assert!(
        migrated
            .snapshot()
            .nodes
            .keys()
            .all(|id| !legacy_ids.contains(id))
    );
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn generated_source_ids_keep_short_compatibility_and_bound_hashed_duplicate_names() {
    let mut used = BTreeSet::new();
    assert_eq!(
        unique_node_id(&SubscriptionId::new("provider-a"), "Node A", 0, &mut used),
        "provider-a-node-a"
    );
    let source = SubscriptionId::in_namespace("tenant", "a".repeat(40));
    used.clear();
    let display = "abcdefghijklmnop-q";
    let first = unique_node_id(&source, display, 0, &mut used);
    let second = unique_node_id(&source, display, 1, &mut used);
    assert_ne!(first, second);
    assert!(first.len() <= 63 && second.len() <= 63);
    let foreign = SubscriptionId::in_namespace("another", source.resource_name());
    assert_ne!(
        first,
        unique_node_id(&foreign, display, 0, &mut BTreeSet::new())
    );
    let normalized = SubscriptionId::new("provider--a");
    assert_ne!(
        unique_node_id(&normalized, "Node A", 0, &mut BTreeSet::new()),
        "provider-a-node-a"
    );
}
