use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::path::Path;
use std::sync::Mutex;
#[cfg(test)]
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use pathchord_core::RequestId;
use rusqlite::{Connection, TransactionBehavior, params};
use thiserror::Error;

use crate::control::{
    CachedCommand, ControlEvent, ControlEventKind, IngressControlSnapshot, MAX_EVENT_COUNT,
    MAX_NODE_COUNT, MAX_REQUEST_CACHE_COUNT, MAX_SUBSCRIPTION_COUNT, MutationReceipt,
    NodeAdminState, NodeId, REQUEST_CACHE_TTL_MS, SubscriptionId, SubscriptionRefreshState,
    SubscriptionSpec, SubscriptionState,
};

const MAX_AUDIT_ROWS: usize = 100_000;

const SCHEMA: &str = r#"
PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS control_metadata (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    generation INTEGER NOT NULL CHECK (generation >= 0),
    next_event_id INTEGER NOT NULL CHECK (next_event_id >= 0)
);
CREATE TABLE IF NOT EXISTS node_admin (
    node_id TEXT PRIMARY KEY,
    labels_json TEXT NOT NULL,
    tags_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS subscriptions (
    subscription_id TEXT PRIMARY KEY,
    source_type TEXT NOT NULL,
    display_name TEXT NOT NULL,
    source_url TEXT NOT NULL,
    credentials_ref TEXT,
    refresh_interval_seconds INTEGER NOT NULL CHECK (refresh_interval_seconds BETWEEN 60 AND 604800),
    refresh_timeout_seconds INTEGER NOT NULL CHECK (refresh_timeout_seconds BETWEEN 1 AND 300),
    refresh_max_attempts INTEGER NOT NULL CHECK (refresh_max_attempts BETWEEN 1 AND 10),
    refresh_backoff_seconds INTEGER NOT NULL CHECK (refresh_backoff_seconds BETWEEN 1 AND 3600),
    cache_path TEXT,
    cache_max_age_seconds INTEGER CHECK (cache_max_age_seconds BETWEEN 60 AND 2592000),
    enabled INTEGER NOT NULL CHECK (enabled IN (0, 1)),
    revision INTEGER NOT NULL CHECK (revision >= 0),
    refresh_state TEXT NOT NULL,
    last_error TEXT,
    cache_metadata_json TEXT NOT NULL,
    last_refresh_at_ms INTEGER
);
CREATE TABLE IF NOT EXISTS refresh_queue (
    position INTEGER PRIMARY KEY CHECK (position >= 0),
    subscription_id TEXT NOT NULL UNIQUE REFERENCES subscriptions(subscription_id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS request_cache (
    actor TEXT NOT NULL,
    request_id TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    generation INTEGER NOT NULL CHECK (generation >= 0),
    event_id INTEGER NOT NULL CHECK (event_id >= 0),
    created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0),
    PRIMARY KEY(actor, request_id)
);
CREATE TABLE IF NOT EXISTS control_events (
    event_id INTEGER PRIMARY KEY CHECK (event_id >= 0),
    generation INTEGER NOT NULL CHECK (generation >= 0),
    kind TEXT NOT NULL,
    resource_id TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS control_audit (
    audit_id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp_ms INTEGER NOT NULL CHECK (timestamp_ms >= 0),
    actor TEXT NOT NULL,
    request_id TEXT,
    operation TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    generation INTEGER NOT NULL CHECK (generation >= 0)
);
"#;

const SUBSCRIPTION_SCHEMA_MIGRATIONS: [(&str, &str); 8] = [
    (
        "source_url",
        "ALTER TABLE subscriptions ADD COLUMN source_url TEXT NOT NULL DEFAULT 'https://legacy.invalid/subscription'",
    ),
    (
        "credentials_ref",
        "ALTER TABLE subscriptions ADD COLUMN credentials_ref TEXT",
    ),
    (
        "refresh_interval_seconds",
        "ALTER TABLE subscriptions ADD COLUMN refresh_interval_seconds INTEGER NOT NULL DEFAULT 3600 CHECK (refresh_interval_seconds BETWEEN 60 AND 604800)",
    ),
    (
        "refresh_timeout_seconds",
        "ALTER TABLE subscriptions ADD COLUMN refresh_timeout_seconds INTEGER NOT NULL DEFAULT 30 CHECK (refresh_timeout_seconds BETWEEN 1 AND 300)",
    ),
    (
        "refresh_max_attempts",
        "ALTER TABLE subscriptions ADD COLUMN refresh_max_attempts INTEGER NOT NULL DEFAULT 3 CHECK (refresh_max_attempts BETWEEN 1 AND 10)",
    ),
    (
        "refresh_backoff_seconds",
        "ALTER TABLE subscriptions ADD COLUMN refresh_backoff_seconds INTEGER NOT NULL DEFAULT 5 CHECK (refresh_backoff_seconds BETWEEN 1 AND 3600)",
    ),
    (
        "cache_path",
        "ALTER TABLE subscriptions ADD COLUMN cache_path TEXT",
    ),
    (
        "cache_max_age_seconds",
        "ALTER TABLE subscriptions ADD COLUMN cache_max_age_seconds INTEGER CHECK (cache_max_age_seconds BETWEEN 60 AND 2592000)",
    ),
];

fn migrate_subscription_schema(connection: &Connection) -> Result<(), IngressControlStoreError> {
    let columns = {
        let mut statement =
            connection.prepare("SELECT name FROM pragma_table_info('subscriptions')")?;
        let rows = statement.query_map([], |row| row.get::<_, String>(0))?;
        rows.collect::<Result<BTreeSet<_>, _>>()?
    };
    for (name, migration) in SUBSCRIPTION_SCHEMA_MIGRATIONS {
        if !columns.contains(name) {
            connection.execute_batch(migration)?;
        }
    }
    Ok(())
}

#[derive(Debug, Error)]
pub enum IngressControlStoreError {
    #[error("Ingress control SQLite operation failed")]
    Sql(#[from] rusqlite::Error),
    #[error("Ingress control state contains an invalid field")]
    InvalidState,
    #[error("Ingress control JSON state is invalid")]
    Json(#[from] serde_json::Error),
    #[error("Ingress control store lock is unavailable")]
    Lock,
}

#[derive(Debug)]
pub struct IngressControlStore {
    connection: Mutex<Connection>,
    #[cfg(test)]
    fail_next_commit: AtomicBool,
}

pub(crate) struct DurableControlState {
    pub(crate) snapshot: IngressControlSnapshot,
    pub(crate) events: VecDeque<ControlEvent>,
    pub(crate) refresh_queue: VecDeque<SubscriptionId>,
    pub(crate) request_cache: HashMap<(String, RequestId), CachedCommand>,
    pub(crate) next_event_id: u64,
}

pub(crate) struct AuditRecord {
    actor: String,
    request_id: Option<RequestId>,
    operation: &'static str,
    resource_id: String,
    generation: u64,
    timestamp_ms: u64,
}

pub(crate) struct StoreCommit<'a> {
    pub(crate) snapshot: &'a IngressControlSnapshot,
    pub(crate) events: &'a VecDeque<ControlEvent>,
    pub(crate) refresh_queue: &'a VecDeque<SubscriptionId>,
    pub(crate) request_cache: &'a HashMap<(String, RequestId), CachedCommand>,
    pub(crate) next_event_id: u64,
    pub(crate) audit: Option<AuditRecord>,
}

impl AuditRecord {
    pub(crate) fn new(
        actor: impl Into<String>,
        request_id: Option<RequestId>,
        operation: &'static str,
        resource_id: String,
        generation: u64,
    ) -> Self {
        Self {
            actor: actor.into(),
            request_id,
            operation,
            resource_id,
            generation,
            timestamp_ms: now_ms(),
        }
    }
}

impl IngressControlStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, IngressControlStoreError> {
        Self::from_connection(Connection::open(path)?)
    }

    #[cfg(test)]
    pub(crate) fn open_in_memory() -> Result<Self, IngressControlStoreError> {
        Self::from_connection(Connection::open_in_memory()?)
    }

    fn from_connection(connection: Connection) -> Result<Self, IngressControlStoreError> {
        connection.execute_batch(SCHEMA)?;
        migrate_subscription_schema(&connection)?;
        connection.execute(
            "INSERT OR IGNORE INTO control_metadata(singleton, generation, next_event_id) VALUES (1, 0, 0)",
            [],
        )?;
        Ok(Self {
            connection: Mutex::new(connection),
            #[cfg(test)]
            fail_next_commit: AtomicBool::new(false),
        })
    }

    pub(crate) fn load(&self) -> Result<DurableControlState, IngressControlStoreError> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| IngressControlStoreError::Lock)?;
        let (generation, next_event_id) = connection.query_row(
            "SELECT generation, next_event_id FROM control_metadata WHERE singleton = 1",
            [],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
        )?;
        let mut nodes = BTreeMap::new();
        let mut statement = connection.prepare(
            "SELECT node_id, labels_json, tags_json FROM node_admin ORDER BY node_id LIMIT ?1",
        )?;
        let rows = statement.query_map([i64::try_from(MAX_NODE_COUNT + 1).unwrap()], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })?;
        for row in rows {
            let (id, labels, tags) = row?;
            if nodes.len() >= MAX_NODE_COUNT {
                return Err(IngressControlStoreError::InvalidState);
            }
            let labels: BTreeMap<String, String> = serde_json::from_str(&labels)?;
            let tags: BTreeSet<String> = serde_json::from_str(&tags)?;
            if labels.len() > 256 || tags.len() > 256 {
                return Err(IngressControlStoreError::InvalidState);
            }
            nodes.insert(
                NodeId::new(id).map_err(|_| IngressControlStoreError::InvalidState)?,
                NodeAdminState { labels, tags },
            );
        }

        let mut subscriptions = BTreeMap::new();
        let mut statement = connection.prepare(
            "SELECT subscription_id, source_type, display_name, source_url, credentials_ref, refresh_interval_seconds, refresh_timeout_seconds, refresh_max_attempts, refresh_backoff_seconds, cache_path, cache_max_age_seconds, enabled, revision, refresh_state, last_error, cache_metadata_json, last_refresh_at_ms FROM subscriptions ORDER BY subscription_id LIMIT ?1",
        )?;
        let rows = statement.query_map(
            [i64::try_from(MAX_SUBSCRIPTION_COUNT + 1).unwrap()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, Option<String>>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, i64>(6)?,
                    row.get::<_, i64>(7)?,
                    row.get::<_, i64>(8)?,
                    row.get::<_, Option<String>>(9)?,
                    row.get::<_, Option<i64>>(10)?,
                    row.get::<_, i64>(11)?,
                    row.get::<_, i64>(12)?,
                    row.get::<_, String>(13)?,
                    row.get::<_, Option<String>>(14)?,
                    row.get::<_, String>(15)?,
                    row.get::<_, Option<i64>>(16)?,
                ))
            },
        )?;
        for row in rows {
            let (
                id,
                source_type,
                display_name,
                source_url,
                credentials_ref,
                refresh_interval_seconds,
                refresh_timeout_seconds,
                refresh_max_attempts,
                refresh_backoff_seconds,
                cache_path,
                cache_max_age_seconds,
                enabled,
                revision,
                refresh,
                error,
                cache_metadata_json,
                last,
            ) = row?;
            if subscriptions.len() >= MAX_SUBSCRIPTION_COUNT {
                return Err(IngressControlStoreError::InvalidState);
            }
            let id = SubscriptionId::new(id).map_err(|_| IngressControlStoreError::InvalidState)?;
            let cache_metadata: BTreeMap<String, String> =
                serde_json::from_str(&cache_metadata_json)?;
            if cache_metadata.len() > 32
                || cache_metadata
                    .iter()
                    .any(|(key, value)| key.is_empty() || key.len() > 64 || value.len() > 1024)
            {
                return Err(IngressControlStoreError::InvalidState);
            }
            let cache = match (cache_path, cache_max_age_seconds) {
                (None, None) => None,
                (Some(path), Some(max_age_seconds)) => Some(crate::SubscriptionCacheSpec {
                    path,
                    max_age_seconds: to_u64(max_age_seconds)?,
                }),
                _ => return Err(IngressControlStoreError::InvalidState),
            };
            let spec = SubscriptionSpec {
                id: id.clone(),
                source_type,
                display_name,
                enabled: enabled != 0,
                url: source_url,
                credentials_ref,
                refresh: crate::SubscriptionRefreshSpec {
                    interval_seconds: to_u64(refresh_interval_seconds)?,
                    timeout_seconds: to_u64(refresh_timeout_seconds)?,
                    max_attempts: u32::try_from(refresh_max_attempts)
                        .map_err(|_| IngressControlStoreError::InvalidState)?,
                    backoff_seconds: to_u64(refresh_backoff_seconds)?,
                },
                cache,
            };
            spec.validate()
                .map_err(|_| IngressControlStoreError::InvalidState)?;
            subscriptions.insert(
                id.clone(),
                SubscriptionState {
                    spec,
                    revision: to_u64(revision)?,
                    refresh_state: decode_refresh_state(&refresh)?,
                    last_error: error,
                    cache_metadata,
                    last_refresh_at_ms: last.map(to_u64).transpose()?,
                },
            );
        }

        let mut refresh_queue = VecDeque::new();
        let mut statement = connection
            .prepare("SELECT subscription_id FROM refresh_queue ORDER BY position LIMIT ?1")?;
        let rows = statement.query_map(
            [i64::try_from(crate::MAX_REFRESH_QUEUE_COUNT + 1).unwrap()],
            |row| row.get::<_, String>(0),
        )?;
        for row in rows {
            if refresh_queue.len() >= crate::MAX_REFRESH_QUEUE_COUNT {
                return Err(IngressControlStoreError::InvalidState);
            }
            let id =
                SubscriptionId::new(row?).map_err(|_| IngressControlStoreError::InvalidState)?;
            if !subscriptions.contains_key(&id) {
                return Err(IngressControlStoreError::InvalidState);
            }
            refresh_queue.push_back(id);
        }

        let cutoff = now_ms().saturating_sub(REQUEST_CACHE_TTL_MS);
        let mut request_cache = HashMap::new();
        let mut statement = connection.prepare(
            "SELECT actor, request_id, fingerprint, generation, event_id, created_at_ms FROM request_cache WHERE created_at_ms >= ?1 ORDER BY created_at_ms DESC LIMIT ?2",
        )?;
        let rows = statement.query_map(
            params![to_i64(cutoff)?, to_i64(MAX_REQUEST_CACHE_COUNT as u64)?],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, i64>(5)?,
                ))
            },
        )?;
        for row in rows {
            let (actor, request_id, fingerprint, generation, event_id, created_at_ms) = row?;
            request_cache.insert(
                (actor, parse_request_id(&request_id)?),
                CachedCommand {
                    fingerprint,
                    receipt: MutationReceipt {
                        generation: to_u64(generation)?,
                        event_id: to_u64(event_id)?,
                        replayed: false,
                    },
                    created_at_ms: to_u64(created_at_ms)?,
                },
            );
        }

        let mut events = VecDeque::new();
        let mut statement = connection.prepare(
            "SELECT event_id, generation, kind, resource_id FROM control_events ORDER BY event_id",
        )?;
        let rows = statement.query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
            ))
        })?;
        for row in rows {
            let (id, event_generation, kind, resource_id) = row?;
            if events.len() >= MAX_EVENT_COUNT {
                return Err(IngressControlStoreError::InvalidState);
            }
            events.push_back(ControlEvent {
                id: to_u64(id)?,
                generation: to_u64(event_generation)?,
                kind: decode_event_kind(&kind)?,
                resource_id,
            });
        }

        Ok(DurableControlState {
            snapshot: IngressControlSnapshot {
                generation: to_u64(generation)?,
                nodes,
                subscriptions,
            },
            events,
            refresh_queue,
            request_cache,
            next_event_id: to_u64(next_event_id)?,
        })
    }

    pub(crate) fn commit(&self, state: StoreCommit<'_>) -> Result<(), IngressControlStoreError> {
        #[cfg(test)]
        if self.fail_next_commit.swap(false, Ordering::AcqRel) {
            return Err(IngressControlStoreError::InvalidState);
        }
        let StoreCommit {
            snapshot,
            events,
            refresh_queue,
            request_cache,
            next_event_id,
            audit,
        } = state;
        if snapshot.nodes.len() > MAX_NODE_COUNT
            || snapshot.subscriptions.len() > MAX_SUBSCRIPTION_COUNT
            || events.len() > MAX_EVENT_COUNT
            || refresh_queue.len() > crate::MAX_REFRESH_QUEUE_COUNT
            || request_cache.len() > MAX_REQUEST_CACHE_COUNT
        {
            return Err(IngressControlStoreError::InvalidState);
        }
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| IngressControlStoreError::Lock)?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute(
            "UPDATE control_metadata SET generation = ?1, next_event_id = ?2 WHERE singleton = 1",
            params![to_i64(snapshot.generation)?, to_i64(next_event_id)?],
        )?;

        transaction.execute("DELETE FROM node_admin", [])?;
        for (id, state) in &snapshot.nodes {
            transaction.execute(
                "INSERT INTO node_admin(node_id, labels_json, tags_json) VALUES (?1, ?2, ?3)",
                params![
                    id.as_str(),
                    serde_json::to_string(&state.labels)?,
                    serde_json::to_string(&state.tags)?,
                ],
            )?;
        }

        transaction.execute("DELETE FROM refresh_queue", [])?;
        transaction.execute("DELETE FROM subscriptions", [])?;
        for (id, state) in &snapshot.subscriptions {
            state
                .spec
                .validate()
                .map_err(|_| IngressControlStoreError::InvalidState)?;
            transaction.execute(
                "INSERT INTO subscriptions(subscription_id, source_type, display_name, source_url, credentials_ref, refresh_interval_seconds, refresh_timeout_seconds, refresh_max_attempts, refresh_backoff_seconds, cache_path, cache_max_age_seconds, enabled, revision, refresh_state, last_error, cache_metadata_json, last_refresh_at_ms) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17)",
                params![
                    id.as_str(),
                    state.spec.source_type,
                    state.spec.display_name,
                    state.spec.url,
                    state.spec.credentials_ref,
                    to_i64(state.spec.refresh.interval_seconds)?,
                    to_i64(state.spec.refresh.timeout_seconds)?,
                    i64::from(state.spec.refresh.max_attempts),
                    to_i64(state.spec.refresh.backoff_seconds)?,
                    state.spec.cache.as_ref().map(|cache| cache.path.as_str()),
                    state
                        .spec
                        .cache
                        .as_ref()
                        .map(|cache| to_i64(cache.max_age_seconds))
                        .transpose()?,
                    i64::from(state.spec.enabled),
                    to_i64(state.revision)?,
                    encode_refresh_state(state.refresh_state),
                    state.last_error,
                    serde_json::to_string(&state.cache_metadata)?,
                    state.last_refresh_at_ms.map(to_i64).transpose()?,
                ],
            )?;
        }
        for (position, id) in refresh_queue.iter().enumerate() {
            transaction.execute(
                "INSERT INTO refresh_queue(position, subscription_id) VALUES (?1, ?2)",
                params![
                    i64::try_from(position).map_err(|_| IngressControlStoreError::InvalidState)?,
                    id.as_str()
                ],
            )?;
        }

        let cutoff = now_ms().saturating_sub(REQUEST_CACHE_TTL_MS);
        transaction.execute("DELETE FROM request_cache", [])?;
        for ((actor, request_id), cached) in request_cache
            .iter()
            .filter(|(_, cached)| cached.created_at_ms >= cutoff)
        {
            transaction.execute(
                "INSERT INTO request_cache(actor, request_id, fingerprint, generation, event_id, created_at_ms) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    actor,
                    format_request_id(*request_id),
                    cached.fingerprint,
                    to_i64(cached.receipt.generation)?,
                    to_i64(cached.receipt.event_id)?,
                    to_i64(cached.created_at_ms)?,
                ],
            )?;
        }

        transaction.execute("DELETE FROM control_events", [])?;
        for event in events {
            transaction.execute(
                "INSERT INTO control_events(event_id, generation, kind, resource_id) VALUES (?1, ?2, ?3, ?4)",
                params![
                    to_i64(event.id)?,
                    to_i64(event.generation)?,
                    encode_event_kind(event.kind),
                    event.resource_id,
                ],
            )?;
        }
        if let Some(audit) = audit {
            transaction.execute(
                "INSERT INTO control_audit(timestamp_ms, actor, request_id, operation, resource_id, generation) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    to_i64(audit.timestamp_ms)?,
                    audit.actor,
                    audit.request_id.map(format_request_id),
                    audit.operation,
                    audit.resource_id,
                    to_i64(audit.generation)?,
                ],
            )?;
            transaction.execute(
                "DELETE FROM control_audit WHERE audit_id NOT IN (SELECT audit_id FROM control_audit ORDER BY audit_id DESC LIMIT ?1)",
                [to_i64(MAX_AUDIT_ROWS as u64)?],
            )?;
        }
        transaction.commit()?;
        Ok(())
    }

    pub fn audit_count(&self) -> Result<u64, IngressControlStoreError> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| IngressControlStoreError::Lock)?;
        let count = connection.query_row("SELECT COUNT(*) FROM control_audit", [], |row| {
            row.get::<_, i64>(0)
        })?;
        to_u64(count)
    }

    #[cfg(test)]
    pub(crate) fn fail_next_commit(&self) {
        self.fail_next_commit.store(true, Ordering::Release);
    }
}

fn encode_refresh_state(state: SubscriptionRefreshState) -> &'static str {
    match state {
        SubscriptionRefreshState::Idle => "idle",
        SubscriptionRefreshState::Queued => "queued",
        SubscriptionRefreshState::Healthy => "healthy",
        SubscriptionRefreshState::Failed => "failed",
    }
}

fn decode_refresh_state(value: &str) -> Result<SubscriptionRefreshState, IngressControlStoreError> {
    match value {
        "idle" => Ok(SubscriptionRefreshState::Idle),
        "queued" => Ok(SubscriptionRefreshState::Queued),
        "healthy" => Ok(SubscriptionRefreshState::Healthy),
        "failed" => Ok(SubscriptionRefreshState::Failed),
        _ => Err(IngressControlStoreError::InvalidState),
    }
}

fn encode_event_kind(kind: ControlEventKind) -> &'static str {
    match kind {
        ControlEventKind::NodeChanged => "node_changed",
        ControlEventKind::SubscriptionChanged => "subscription_changed",
        ControlEventKind::SubscriptionRefreshRequested => "subscription_refresh_requested",
        ControlEventKind::ObservationChanged => "observation_changed",
        ControlEventKind::SystemProxyChanged => "system_proxy_changed",
    }
}

fn decode_event_kind(value: &str) -> Result<ControlEventKind, IngressControlStoreError> {
    match value {
        "node_changed" => Ok(ControlEventKind::NodeChanged),
        "subscription_changed" => Ok(ControlEventKind::SubscriptionChanged),
        "subscription_refresh_requested" => Ok(ControlEventKind::SubscriptionRefreshRequested),
        "observation_changed" => Ok(ControlEventKind::ObservationChanged),
        "system_proxy_changed" => Ok(ControlEventKind::SystemProxyChanged),
        _ => Err(IngressControlStoreError::InvalidState),
    }
}

fn format_request_id(request_id: RequestId) -> String {
    format!("{:032x}", request_id.get())
}

fn parse_request_id(value: &str) -> Result<RequestId, IngressControlStoreError> {
    u128::from_str_radix(value, 16)
        .map(RequestId::new)
        .map_err(|_| IngressControlStoreError::InvalidState)
}

fn to_i64(value: u64) -> Result<i64, IngressControlStoreError> {
    i64::try_from(value).map_err(|_| IngressControlStoreError::InvalidState)
}

fn to_u64(value: i64) -> Result<u64, IngressControlStoreError> {
    u64::try_from(value).map_err(|_| IngressControlStoreError::InvalidState)
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| {
            duration.as_millis().min(u128::from(u64::MAX)) as u64
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{IngressControlService, NodeAdminPatch};
    use std::collections::BTreeSet;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static NEXT_DATABASE: AtomicUsize = AtomicUsize::new(0);

    fn database_path() -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "pathchord-ingress-control-{}-{}.sqlite",
            std::process::id(),
            NEXT_DATABASE.fetch_add(1, Ordering::Relaxed)
        ))
    }

    fn subscription() -> SubscriptionSpec {
        SubscriptionSpec {
            id: SubscriptionId::new("provider-a").unwrap(),
            source_type: "clash".to_owned(),
            display_name: "Provider A".to_owned(),
            enabled: true,
            url: "https://provider.example/subscription".to_owned(),
            credentials_ref: Some("provider-a-token".to_owned()),
            refresh: crate::SubscriptionRefreshSpec {
                interval_seconds: 900,
                timeout_seconds: 15,
                max_attempts: 4,
                backoff_seconds: 7,
            },
            cache: Some(crate::SubscriptionCacheSpec {
                path: "provider-a.snapshot".to_owned(),
                max_age_seconds: 86_400,
            }),
        }
    }

    #[test]
    fn durable_service_reopens_snapshot_idempotency_and_audit() {
        let store = Arc::new(IngressControlStore::open_in_memory().unwrap());
        let mut service = IngressControlService::open(Arc::clone(&store)).unwrap();
        let node = NodeId::new("node-a").unwrap();
        service.add_node(node.clone()).unwrap();
        let patch = NodeAdminPatch {
            set_labels: BTreeMap::from([("admin.region".to_owned(), "jp".to_owned())]),
            add_tags: BTreeSet::from(["preferred".to_owned()]),
            ..NodeAdminPatch::default()
        };
        let patched = service
            .patch_node("admin", RequestId::new(1), node, 0, patch.clone())
            .unwrap();
        assert_eq!(patched.generation, 1);
        let created = service
            .add_subscription("admin", RequestId::new(2), 1, subscription())
            .unwrap();
        assert_eq!(created.generation, 2);
        let id = SubscriptionId::new("provider-a").unwrap();
        service
            .request_subscription_refresh("admin", RequestId::new(3), &id)
            .unwrap();
        service
            .set_subscription_cache_metadata(
                &id,
                BTreeMap::from([("etag".to_owned(), "revision-a".to_owned())]),
            )
            .unwrap();
        service
            .complete_subscription_refresh(&id, true, None)
            .unwrap();
        let expected = service.snapshot();
        drop(service);

        let mut reopened = IngressControlService::open(Arc::clone(&store)).unwrap();
        assert_eq!(reopened.snapshot(), expected);
        assert_eq!(
            reopened.snapshot().subscriptions[&id].cache_metadata["etag"],
            "revision-a"
        );
        let replay = reopened
            .patch_node(
                "admin",
                RequestId::new(1),
                NodeId::new("node-a").unwrap(),
                0,
                patch,
            )
            .unwrap();
        assert!(replay.replayed);
        assert!(store.audit_count().unwrap() >= 6);
    }

    #[test]
    fn failed_commit_restores_the_previous_memory_snapshot() {
        let store = Arc::new(IngressControlStore::open_in_memory().unwrap());
        let mut service = IngressControlService::open(Arc::clone(&store)).unwrap();
        let node = NodeId::new("node-a").unwrap();
        service.add_node(node.clone()).unwrap();
        let before = service.snapshot();
        store.fail_next_commit();
        assert_eq!(
            service.patch_node(
                "admin",
                RequestId::new(10),
                node,
                0,
                NodeAdminPatch {
                    add_tags: BTreeSet::from(["should-not-publish".to_owned()]),
                    ..NodeAdminPatch::default()
                },
            ),
            Err(crate::ControlError::PersistenceUnavailable)
        );
        assert_eq!(service.snapshot(), before);
    }

    #[test]
    fn sqlite_file_survives_process_style_reopen() {
        let path = database_path();
        {
            let store = Arc::new(IngressControlStore::open(&path).unwrap());
            let mut service = IngressControlService::open(store).unwrap();
            service
                .add_node(NodeId::new("persisted-node").unwrap())
                .unwrap();
        }
        {
            let store = Arc::new(IngressControlStore::open(&path).unwrap());
            let service = IngressControlService::open(store).unwrap();
            assert!(
                service
                    .snapshot()
                    .nodes
                    .contains_key(&NodeId::new("persisted-node").unwrap())
            );
        }
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn concurrent_queries_and_serialized_mutations_remain_consistent() {
        let store = Arc::new(IngressControlStore::open_in_memory().unwrap());
        let service = Arc::new(Mutex::new(
            IngressControlService::open(Arc::clone(&store)).unwrap(),
        ));
        service
            .lock()
            .unwrap()
            .add_node(NodeId::new("node-a").unwrap())
            .unwrap();
        std::thread::scope(|scope| {
            for _ in 0..4 {
                let store = Arc::clone(&store);
                scope.spawn(move || {
                    for _ in 0..50 {
                        let _ = store.load().unwrap();
                    }
                });
            }
            let service = Arc::clone(&service);
            scope.spawn(move || {
                for generation in 0..20_u64 {
                    service
                        .lock()
                        .unwrap()
                        .patch_node(
                            "admin",
                            RequestId::new(u128::from(generation) + 100),
                            NodeId::new("node-a").unwrap(),
                            generation,
                            NodeAdminPatch {
                                set_labels: BTreeMap::from([(
                                    "admin.sequence".to_owned(),
                                    generation.to_string(),
                                )]),
                                ..NodeAdminPatch::default()
                            },
                        )
                        .unwrap();
                }
            });
        });
        let loaded = store.load().unwrap();
        assert_eq!(loaded.snapshot.generation, 20);
        assert_eq!(
            loaded.snapshot.nodes[&NodeId::new("node-a").unwrap()].labels["admin.sequence"],
            "19"
        );
    }
}
