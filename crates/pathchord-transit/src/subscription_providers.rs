//! Bounded HTTP-only expansion of Clash proxy-provider references.

use std::collections::VecDeque;

use serde_json::Value;
use url::Url;

use super::*;

const MAX_PROVIDER_DEPTH: usize = 3;
const MAX_PROVIDER_REFERENCES: usize = 32;

struct Reference {
    name: String,
    url: Option<String>,
}

struct Pending {
    segment: usize,
    reference: Reference,
    key: String,
    depth: usize,
    ancestors: Vec<String>,
    usage: Option<SubscriptionUsage>,
}

pub(super) async fn normalize_fetched(
    manager: &SubscriptionManager,
    config: &SubscriptionConfig,
    document: SubscriptionDocument,
    budget: &SubscriptionDownloadBudget,
) -> Result<Vec<NormalizedNode>, SubscriptionError> {
    let body = &document.body;
    let mut root = normalize(config, body, &manager.available_adapters)?;
    for node in &mut root {
        node.usage = document.usage.clone();
    }
    if !matches!(
        config.source.source_type,
        SubscriptionSourceType::Clash | SubscriptionSourceType::Auto
    ) {
        return Ok(root);
    }
    let mut segments = vec![root];
    let mut queue = VecDeque::new();
    let root_url = Url::parse(&config.source.url).ok().map(|mut url| {
        url.set_fragment(None);
        url.to_string()
    });
    let mut references = 0;
    for reference in references_in(body) {
        let key = provider_segment(&reference.name);
        queue.push_back(Pending {
            segment: 0,
            reference,
            key,
            depth: 1,
            ancestors: root_url.iter().cloned().collect(),
            usage: document.usage.clone(),
        });
    }
    while let Some(pending) = queue.pop_front() {
        references += 1;
        let permitted = references <= MAX_PROVIDER_REFERENCES
            && pending.depth <= MAX_PROVIDER_DEPTH
            && pending
                .reference
                .url
                .as_ref()
                .is_some_and(|url| !pending.ancestors.contains(url))
            && budget.remaining() > 0;
        let request = permitted.then(|| SubscriptionFetchRequest {
            url: pending
                .reference
                .url
                .clone()
                .expect("permitted provider URL"),
            credentials_ref: pending.reference.url.as_deref().and_then(|url| {
                let root = Url::parse(&config.source.url).ok()?;
                let provider = Url::parse(url).ok()?;
                (root.origin() == provider.origin())
                    .then(|| config.source.credentials_ref.clone())
                    .flatten()
            }),
            user_agent: config.source.user_agent.clone(),
            timeout: Duration::from_secs(config.refresh.timeout_seconds.clamp(1, 300)),
            max_bytes: budget.remaining(),
        });
        let fetched = match request {
            Some(request) => {
                match tokio::time::timeout(
                    request.timeout,
                    manager.fetcher.fetch_document_with_budget(request, budget),
                )
                .await
                {
                    Ok(Ok(document)) => Some(document),
                    _ => None,
                }
            }
            None => None,
        };
        let parsed = fetched.as_ref().and_then(|document| {
            let mut provider_config = config.clone();
            provider_config.source.source_type = SubscriptionSourceType::Clash;
            normalize(
                &provider_config,
                &document.body,
                &manager.available_adapters,
            )
            .ok()
        });
        let Some(mut parsed) = parsed else {
            mark_failed(&mut segments[pending.segment], &pending.reference.name);
            retain_previous(
                manager,
                config,
                &pending.key,
                &mut segments[pending.segment],
            );
            continue;
        };
        segments[pending.segment].retain(|node| !is_reference(node, &pending.reference.name));
        let usage = fetched
            .as_ref()
            .and_then(|document| document.usage.clone())
            .or(pending.usage);
        for node in &mut parsed {
            node.config
                .labels
                .insert("source.provider".to_owned(), pending.key.clone());
            node.usage = usage.clone();
        }
        let segment = segments.len();
        segments.push(parsed);
        let mut ancestors = pending.ancestors;
        ancestors.push(pending.reference.url.expect("parsed provider URL"));
        for reference in references_in(&fetched.as_ref().unwrap().body) {
            let key = format!("{}/{}", pending.key, provider_segment(&reference.name));
            queue.push_back(Pending {
                segment,
                reference,
                key,
                depth: pending.depth + 1,
                ancestors: ancestors.clone(),
                usage: usage.clone(),
            });
        }
        if segments.iter().map(Vec::len).sum::<usize>() > MAX_SUBSCRIPTION_NODES {
            return Err(SubscriptionError::TooManyNodes);
        }
    }
    let mut nodes: Vec<_> = segments.into_iter().flatten().collect();
    if nodes.len() > MAX_SUBSCRIPTION_NODES {
        return Err(SubscriptionError::TooManyNodes);
    }
    let mut used = BTreeSet::new();
    for (index, node) in nodes.iter_mut().enumerate() {
        let name = node
            .config
            .labels
            .get("source.name")
            .cloned()
            .unwrap_or_else(|| format!("node-{index}"));
        let name = match node.config.labels.get("source.provider") {
            Some(provider) => format!(
                "{}-{:08x}",
                canonical_segment(&name, 18),
                hash(provider) as u32
            ),
            None => name,
        };
        node.config.id = TransitProxyId::in_namespace(
            config.id.namespace(),
            unique_node_id(&config.id, &name, index, &mut used),
        );
    }
    Ok(nodes)
}

fn references_in(body: &[u8]) -> Vec<Reference> {
    let Ok(document) = serde_yaml::from_slice::<Value>(body) else {
        return Vec::new();
    };
    let Some(providers) = document.get("proxy-providers").and_then(Value::as_object) else {
        return Vec::new();
    };
    providers
        .iter()
        .map(|(name, value)| {
            let url = value.as_object().and_then(|fields| {
                if fields.get("type").and_then(Value::as_str) != Some("http")
                    || fields.keys().any(|key| {
                        !matches!(
                            key.as_str(),
                            "type" | "url" | "path" | "interval" | "health-check"
                        )
                    })
                {
                    return None;
                }
                let mut url = Url::parse(fields.get("url")?.as_str()?).ok()?;
                if !matches!(url.scheme(), "http" | "https")
                    || !url.username().is_empty()
                    || url.password().is_some()
                {
                    return None;
                }
                url.set_fragment(None);
                Some(url.to_string())
            });
            Reference {
                name: name.clone(),
                url,
            }
        })
        .collect()
}

fn is_reference(node: &NormalizedNode, name: &str) -> bool {
    node.config
        .labels
        .get("source.name")
        .is_some_and(|value| value == name)
        && node.diagnostic.as_ref().is_some_and(|diagnostic| {
            diagnostic
                .fields
                .iter()
                .any(|field| field == "proxy-providers")
        })
}

fn mark_failed(nodes: &mut [NormalizedNode], name: &str) {
    for node in nodes.iter_mut().filter(|node| is_reference(node, name)) {
        node.state = DynamicNodeState::Unavailable(NodeUnavailableReason::AdapterUnavailable);
        node.diagnostic = Some(NodeDiagnostic {
            code: NodeUnavailableReason::AdapterUnavailable,
            fields: vec!["proxy-providers".to_owned()],
            message: "HTTP provider is unavailable, cyclic, unsupported, or exceeds import limits"
                .to_owned(),
        });
    }
}

fn retain_previous(
    manager: &SubscriptionManager,
    config: &SubscriptionConfig,
    key: &str,
    nodes: &mut Vec<NormalizedNode>,
) {
    let prefix = format!("{key}/");
    let fingerprint = subscription_source_fingerprint(config);
    for previous in manager.snapshot.nodes.values().filter(|node| {
        node.source_subscription == config.id
            && node.source_fingerprint == fingerprint
            && node.state != DynamicNodeState::Draining
            && node
                .config
                .labels
                .get("source.provider")
                .is_some_and(|provider| provider == key || provider.starts_with(&prefix))
    }) {
        nodes.push(NormalizedNode {
            config: previous.config.clone(),
            credential: previous.credential.clone(),
            state: previous.state,
            diagnostic: previous.diagnostic.clone(),
            usage: previous.usage.clone(),
        });
    }
}

fn provider_segment(name: &str) -> String {
    format!("{}-{:08x}", canonical_segment(name, 16), hash(name) as u32)
}

fn hash(value: &str) -> u64 {
    value.bytes().fold(0xcbf2_9ce4_8422_2325, |hash, byte| {
        (hash ^ u64::from(byte)).wrapping_mul(0x100_0000_01b3)
    })
}

#[cfg(test)]
#[path = "subscription_providers/tests.rs"]
mod tests;
