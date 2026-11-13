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
