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
    CachedCommand, ControlEvent, ControlEventKind, DeclarativeSubscriptionBaseline,
    IngressControlSnapshot, MAX_EVENT_COUNT, MAX_NODE_COUNT, MAX_REQUEST_CACHE_COUNT,
    MAX_SUBSCRIPTION_COUNT, MutationReceipt, NodeAdminState, NodeId, REQUEST_CACHE_TTL_MS,
    SubscriptionId, SubscriptionRefreshState, SubscriptionSpec, SubscriptionState,
};

const MAX_AUDIT_ROWS: usize = 100_000;

const SCHEMA: &str = r#"
PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS control_metadata (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    generation INTEGER NOT NULL CHECK (generation >= 0),
    next_event_id INTEGER NOT NULL CHECK (next_event_id >= 0),
    declarative_initialized INTEGER NOT NULL DEFAULT 0 CHECK (declarative_initialized IN (0, 1))
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
CREATE TABLE IF NOT EXISTS declarative_subscriptions (
    subscription_id TEXT PRIMARY KEY,
    fingerprint TEXT NOT NULL,
    deleted INTEGER NOT NULL CHECK (deleted IN (0, 1))
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
    system_proxy_status_json TEXT,
    response_fingerprint TEXT,
    response_json TEXT,
    PRIMARY KEY(actor, request_id)
);
CREATE TABLE IF NOT EXISTS control_events (
    event_id INTEGER PRIMARY KEY CHECK (event_id >= 0),
    generation INTEGER NOT NULL CHECK (generation >= 0),
    kind TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    emitted_at_ms INTEGER,
    payload_json TEXT
);
CREATE TABLE IF NOT EXISTS control_audit (
    audit_id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp_ms INTEGER NOT NULL CHECK (timestamp_ms >= 0),
    actor TEXT NOT NULL,
    request_id TEXT,
    operation TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    generation INTEGER NOT NULL CHECK (generation >= 0),
    event_id INTEGER,
    source TEXT,
    expected_scope TEXT,
    expected_value INTEGER,
    applied_scope TEXT,
    applied_value INTEGER,
    result TEXT,
    reason TEXT
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

fn migrate_control_metadata_schema(
    connection: &Connection,
) -> Result<(), IngressControlStoreError> {
    let exists: bool = connection.query_row(
        "SELECT COUNT(*) > 0 FROM pragma_table_info('control_metadata') WHERE name = 'declarative_initialized'",
        [],
        |row| row.get(0),
    )?;
    if !exists {
        connection.execute_batch("ALTER TABLE control_metadata ADD COLUMN declarative_initialized INTEGER NOT NULL DEFAULT 0 CHECK (declarative_initialized IN (0, 1))")?;
    }
    Ok(())
}

fn migrate_event_schema(connection: &Connection) -> Result<(), IngressControlStoreError> {
    let columns = {
        let mut statement =
            connection.prepare("SELECT name FROM pragma_table_info('control_events')")?;
        let rows = statement.query_map([], |row| row.get::<_, String>(0))?;
        rows.collect::<Result<BTreeSet<_>, _>>()?
    };
    if !columns.contains("emitted_at_ms") {
        connection.execute_batch("ALTER TABLE control_events ADD COLUMN emitted_at_ms INTEGER")?;
    }
    if !columns.contains("payload_json") {
        connection.execute_batch("ALTER TABLE control_events ADD COLUMN payload_json TEXT")?;
    }
    Ok(())
}

fn migrate_request_cache_schema(connection: &Connection) -> Result<(), IngressControlStoreError> {
    let exists: bool = connection.query_row("SELECT COUNT(*) > 0 FROM pragma_table_info('request_cache') WHERE name = 'system_proxy_status_json'", [], |row| row.get(0))?;
    if !exists {
        connection
            .execute_batch("ALTER TABLE request_cache ADD COLUMN system_proxy_status_json TEXT")?;
    }
    for (name, sql) in [
        (
            "response_fingerprint",
            "ALTER TABLE request_cache ADD COLUMN response_fingerprint TEXT",
        ),
        (
            "response_json",
            "ALTER TABLE request_cache ADD COLUMN response_json TEXT",
        ),
    ] {
        let exists: bool = connection.query_row(
            "SELECT COUNT(*) > 0 FROM pragma_table_info('request_cache') WHERE name = ?1",
            [name],
            |row| row.get(0),
        )?;
        if !exists {
            connection.execute_batch(sql)?;
        }
    }
    let legacy = {
        let mut statement = connection.prepare("SELECT actor, request_id, fingerprint FROM request_cache WHERE fingerprint NOT LIKE 'sha256:%'")?;
        let rows = statement.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })?;
        rows.collect::<Result<Vec<_>, _>>()?
    };
    for (actor, request_id, fingerprint) in legacy {
        connection.execute(
            "UPDATE request_cache SET fingerprint = ?1 WHERE actor = ?2 AND request_id = ?3",
            params![
                crate::control::fingerprint_digest(&fingerprint),
                actor,
                request_id
            ],
        )?;
    }
    Ok(())
}

fn migrate_audit_schema(connection: &Connection) -> Result<(), IngressControlStoreError> {
    let columns = {
        let mut statement =
            connection.prepare("SELECT name FROM pragma_table_info('control_audit')")?;
        let rows = statement.query_map([], |row| row.get::<_, String>(0))?;
        rows.collect::<Result<BTreeSet<_>, _>>()?
    };
    for (name, sql_type) in [
        ("event_id", "INTEGER"),
        ("source", "TEXT"),
        ("expected_scope", "TEXT"),
        ("expected_value", "INTEGER"),
        ("applied_scope", "TEXT"),
        ("applied_value", "INTEGER"),
        ("result", "TEXT"),
        ("reason", "TEXT"),
    ] {
        if !columns.contains(name) {
            connection.execute_batch(&format!(
                "ALTER TABLE control_audit ADD COLUMN {name} {sql_type}"
            ))?;
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
    pub(crate) declarative_subscriptions: BTreeMap<SubscriptionId, DeclarativeSubscriptionBaseline>,
    pub(crate) declarative_initialized: bool,
    pub(crate) events: VecDeque<ControlEvent>,
    pub(crate) refresh_queue: VecDeque<SubscriptionId>,
    pub(crate) request_cache: HashMap<(String, RequestId), CachedCommand>,
    pub(crate) next_event_id: u64,
}

pub(crate) struct AuditRecord {
    actor: String,
    request_id: Option<String>,
    operation: String,
    resource_id: String,
    generation: u64,
    timestamp_ms: u64,
    event_id: Option<u64>,
    source: String,
    expected: Option<pathchord_core::management::GenerationExpectation>,
    applied: Option<pathchord_core::management::GenerationExpectation>,
    result: String,
    reason: Option<String>,
}

pub(crate) struct StoreCommit<'a> {
    pub(crate) snapshot: &'a IngressControlSnapshot,
    pub(crate) declarative_subscriptions:
        &'a BTreeMap<SubscriptionId, DeclarativeSubscriptionBaseline>,
    pub(crate) declarative_initialized: bool,
    pub(crate) events: &'a VecDeque<ControlEvent>,
    pub(crate) refresh_queue: &'a VecDeque<SubscriptionId>,
    pub(crate) request_cache: &'a HashMap<(String, RequestId), CachedCommand>,
    pub(crate) next_event_id: u64,
    pub(crate) audit: Option<AuditRecord>,
}

impl AuditRecord {
    pub(crate) fn authentication_failure(source: &str, generation: u64, event_id: u64) -> Self {
        Self {
            actor: "unauthenticated".to_owned(),
            request_id: None,
            operation: "authentication.failure".to_owned(),
            resource_id: "authentication".to_owned(),
            generation,
            timestamp_ms: now_ms(),
            event_id: Some(event_id),
            source: bounded_audit_text(source),
            expected: None,
            applied: None,
            result: "failed".to_owned(),
            reason: Some("AUTHENTICATION_REQUIRED".to_owned()),
        }
    }

    pub(crate) fn new(
        actor: impl Into<String>,
        request_id: Option<RequestId>,
        operation: &'static str,
        resource_id: String,
        generation: u64,
    ) -> Self {
        Self {
            actor: actor.into(),
            request_id: request_id.map(format_request_id),
            operation: operation.to_owned(),
            resource_id,
            generation,
            timestamp_ms: now_ms(),
            event_id: None,
            source: "runtime".to_owned(),
            expected: None,
            applied: Some(pathchord_core::management::GenerationExpectation {
                scope: "configuration".to_owned(),
                value: generation,
            }),
            result: "success".to_owned(),
            reason: None,
        }
    }

    pub(crate) fn management(
        request: &pathchord_core::management::RequestEnvelope,
        response: &pathchord_core::management::ResponseEnvelope,
        resource_id: String,
        generation: u64,
        event_id: u64,
        source: pathchord_core::management::ManagementSource,
    ) -> Self {
        let reason = response
            .error
            .as_ref()
            .and_then(|error| serde_json::to_value(error.code).ok())
            .and_then(|value| value.as_str().map(str::to_owned));
        let applied = response
            .result
            .as_ref()
            .and_then(|result| result.get("applied_generation"))
            .and_then(|value| serde_json::from_value(value.clone()).ok());
        let expected = request.expected_generation.as_ref().map(|value| {
            pathchord_core::management::GenerationExpectation {
                scope: if matches!(
                    value.scope.as_str(),
                    "configuration" | "observation" | "authorization"
                ) {
                    value.scope.clone()
                } else {
                    "invalid".to_owned()
                },
                value: value.value,
            }
        });
        Self {
            actor: bounded_audit_text(&request.actor.id),
            request_id: Some(bounded_audit_text(&request.request_id)),
            operation: bounded_audit_text(&request.operation),
            resource_id,
            generation,
            timestamp_ms: now_ms(),
            event_id: Some(event_id),
            source: source.as_str().to_owned(),
            expected,
            applied,
            result: if response.ok { "success" } else { "failed" }.to_owned(),
            reason,
        }
    }
}

fn bounded_audit_text(value: &str) -> String {
    value
        .chars()
        .filter(|ch| !ch.is_control())
        .take(128)
        .collect()
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
        migrate_control_metadata_schema(&connection)?;
        migrate_subscription_schema(&connection)?;
        migrate_event_schema(&connection)?;
        migrate_request_cache_schema(&connection)?;
        migrate_audit_schema(&connection)?;
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
        let (generation, next_event_id, declarative_initialized) = connection.query_row(
            "SELECT generation, next_event_id, declarative_initialized FROM control_metadata WHERE singleton = 1",
            [],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?, row.get::<_, i64>(2)?)),
        )?;
        if !matches!(declarative_initialized, 0 | 1) {
            return Err(IngressControlStoreError::InvalidState);
        }
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

        let mut declarative_subscriptions = BTreeMap::new();
        let mut statement = connection.prepare(
            "SELECT subscription_id, fingerprint, deleted FROM declarative_subscriptions ORDER BY subscription_id LIMIT ?1",
        )?;
        let rows = statement.query_map(
            [i64::try_from(MAX_SUBSCRIPTION_COUNT + 1).unwrap()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            },
        )?;
        for row in rows {
            let (id, fingerprint, deleted) = row?;
            if declarative_subscriptions.len() >= MAX_SUBSCRIPTION_COUNT
                || !valid_declaration_fingerprint(&fingerprint)
                || !matches!(deleted, 0 | 1)
            {
                return Err(IngressControlStoreError::InvalidState);
            }
            declarative_subscriptions.insert(
                SubscriptionId::new(id).map_err(|_| IngressControlStoreError::InvalidState)?,
                DeclarativeSubscriptionBaseline {
                    fingerprint,
                    deleted: deleted == 1,
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
            "SELECT actor, request_id, fingerprint, generation, event_id, created_at_ms, system_proxy_status_json, response_fingerprint, response_json FROM request_cache WHERE created_at_ms >= ?1 OR generation >= ?2 ORDER BY created_at_ms DESC LIMIT ?3",
        )?;
        let rows = statement.query_map(
            params![
                to_i64(cutoff)?,
                generation,
                to_i64((MAX_REQUEST_CACHE_COUNT + 1) as u64)?
            ],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, Option<String>>(6)?,
                    row.get::<_, Option<String>>(7)?,
                    row.get::<_, Option<String>>(8)?,
                ))
            },
        )?;
        for row in rows {
            if request_cache.len() >= MAX_REQUEST_CACHE_COUNT {
                return Err(IngressControlStoreError::InvalidState);
            }
            let (
                actor,
                request_id,
                fingerprint,
                generation,
                event_id,
                created_at_ms,
                system_proxy_status,
                response_fingerprint,
                response,
            ) = row?;
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
                    system_proxy_status: system_proxy_status
                        .map(|value| serde_json::from_str(&value))
                        .transpose()?,
                    response_fingerprint,
                    response: response
                        .map(|value| serde_json::from_str(&value))
                        .transpose()?,
                },
            );
        }

        let mut events = VecDeque::new();
        let mut statement = connection.prepare(
            "SELECT event_id, generation, kind, resource_id, emitted_at_ms, payload_json FROM control_events ORDER BY event_id",
        )?;
        let rows = statement.query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, Option<i64>>(4)?,
                row.get::<_, Option<String>>(5)?,
            ))
        })?;
        for row in rows {
            let (id, event_generation, kind, resource_id, emitted_at_ms, payload_json) = row?;
            if events.len() >= MAX_EVENT_COUNT {
                return Err(IngressControlStoreError::InvalidState);
            }
            events.push_back(ControlEvent {
                id: to_u64(id)?,
                generation: to_u64(event_generation)?,
                kind: decode_event_kind(&kind)?,
                resource_id,
                emitted_at_ms: emitted_at_ms.map(to_u64).transpose()?,
                payload: payload_json.map_or(Ok(serde_json::Value::Null), |value| {
                    serde_json::from_str(&value)
                })?,
            });
        }

        Ok(DurableControlState {
            snapshot: IngressControlSnapshot {
                generation: to_u64(generation)?,
                nodes,
                subscriptions,
            },
            declarative_subscriptions,
            declarative_initialized: declarative_initialized == 1,
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
            declarative_subscriptions,
            declarative_initialized,
            events,
            refresh_queue,
            request_cache,
            next_event_id,
            audit,
        } = state;
        if snapshot.nodes.len() > MAX_NODE_COUNT
            || snapshot.subscriptions.len() > MAX_SUBSCRIPTION_COUNT
            || declarative_subscriptions.len() > MAX_SUBSCRIPTION_COUNT
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
            "UPDATE control_metadata SET generation = ?1, next_event_id = ?2, declarative_initialized = ?3 WHERE singleton = 1",
            params![to_i64(snapshot.generation)?, to_i64(next_event_id)?, i64::from(declarative_initialized)],
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
        transaction.execute("DELETE FROM declarative_subscriptions", [])?;
        for (id, baseline) in declarative_subscriptions {
            if !valid_declaration_fingerprint(&baseline.fingerprint) {
                return Err(IngressControlStoreError::InvalidState);
            }
            transaction.execute(
                "INSERT INTO declarative_subscriptions(subscription_id, fingerprint, deleted) VALUES (?1, ?2, ?3)",
                params![id.as_str(), baseline.fingerprint, i64::from(baseline.deleted)],
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

        let now = now_ms();
        transaction.execute("DELETE FROM request_cache", [])?;
        for ((actor, request_id), cached) in request_cache
            .iter()
            .filter(|(_, cached)| cached.is_live(snapshot.generation, now))
        {
            transaction.execute(
                "INSERT INTO request_cache(actor, request_id, fingerprint, generation, event_id, created_at_ms, system_proxy_status_json, response_fingerprint, response_json) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                params![
                    actor,
                    format_request_id(*request_id),
                    cached.fingerprint,
                    to_i64(cached.receipt.generation)?,
                    to_i64(cached.receipt.event_id)?,
                    to_i64(cached.created_at_ms)?,
                    cached.system_proxy_status.as_ref().map(serde_json::to_string).transpose()?,
                    cached.response_fingerprint,
                    cached.response.as_ref().map(serde_json::to_string).transpose()?,
                ],
            )?;
        }

        transaction.execute("DELETE FROM control_events", [])?;
        for event in events {
            transaction.execute(
                "INSERT INTO control_events(event_id, generation, kind, resource_id, emitted_at_ms, payload_json) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    to_i64(event.id)?,
                    to_i64(event.generation)?,
                    encode_event_kind(event.kind),
                    event.resource_id,
                    event.emitted_at_ms.map(to_i64).transpose()?,
                    serde_json::to_string(&event.payload)?,
                ],
            )?;
        }
        if let Some(audit) = audit {
            transaction.execute(
                "INSERT INTO control_audit(timestamp_ms, actor, request_id, operation, resource_id, generation, event_id, source, expected_scope, expected_value, applied_scope, applied_value, result, reason) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
                params![
                    to_i64(audit.timestamp_ms)?,
                    audit.actor,
                    audit.request_id,
                    audit.operation,
                    audit.resource_id,
                    to_i64(audit.generation)?,
                    audit.event_id.map(to_i64).transpose()?,
                    audit.source,
                    audit.expected.as_ref().map(|value| value.scope.as_str()),
                    audit.expected.as_ref().and_then(|value| i64::try_from(value.value).ok()),
                    audit.applied.as_ref().map(|value| value.scope.as_str()),
                    audit.applied.as_ref().map(|value| to_i64(value.value)).transpose()?,
                    audit.result,
                    audit.reason,
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
        ControlEventKind::AuditNotice => "audit_notice",
        ControlEventKind::PathChanged => "path_changed",
        ControlEventKind::SessionChanged => "session_changed",
        ControlEventKind::StreamChanged => "stream_changed",
        ControlEventKind::ConnectionChanged => "connection_changed",
    }
}

fn decode_event_kind(value: &str) -> Result<ControlEventKind, IngressControlStoreError> {
    match value {
        "node_changed" => Ok(ControlEventKind::NodeChanged),
        "subscription_changed" => Ok(ControlEventKind::SubscriptionChanged),
        "subscription_refresh_requested" => Ok(ControlEventKind::SubscriptionRefreshRequested),
        "observation_changed" => Ok(ControlEventKind::ObservationChanged),
        "system_proxy_changed" => Ok(ControlEventKind::SystemProxyChanged),
        "audit_notice" => Ok(ControlEventKind::AuditNotice),
        "path_changed" => Ok(ControlEventKind::PathChanged),
        "session_changed" => Ok(ControlEventKind::SessionChanged),
        "stream_changed" => Ok(ControlEventKind::StreamChanged),
        "connection_changed" => Ok(ControlEventKind::ConnectionChanged),
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

fn valid_declaration_fingerprint(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
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
    fn declarative_subscription_overrides_and_deletion_survive_reopen() {
        let path = database_path();
        let store = Arc::new(IngressControlStore::open(&path).unwrap());
        let spec = subscription();
        let id = spec.id.clone();
        let mut service = IngressControlService::open(Arc::clone(&store)).unwrap();
        service
            .reconcile_declarative_resources(1, [], [spec.clone()])
            .unwrap();
        service
            .set_subscription_enabled("admin", RequestId::new(1), 1, &id, false)
            .unwrap();
        drop(service);
        drop(store);

        let store = Arc::new(IngressControlStore::open(&path).unwrap());
        let mut service = IngressControlService::open(Arc::clone(&store)).unwrap();
        service
            .reconcile_declarative_resources(1, [], [spec.clone()])
            .unwrap();
        assert!(!service.snapshot().subscriptions[&id].spec.enabled);
        service
            .delete_subscription("admin", RequestId::new(2), 2, &id)
            .unwrap();
        drop(service);
        drop(store);

        let store = Arc::new(IngressControlStore::open(&path).unwrap());
        let mut service = IngressControlService::open(Arc::clone(&store)).unwrap();
        service
            .reconcile_declarative_resources(1, [], [spec.clone()])
            .unwrap();
        assert!(!service.snapshot().subscriptions.contains_key(&id));
        // A changed declaration is a new administrator intent and clears the tombstone.
        let mut changed = spec.clone();
        changed.url.push_str("?version=2");
        service
            .reconcile_declarative_resources(3, [], [changed.clone()])
            .unwrap();
        assert_eq!(service.snapshot().subscriptions[&id].spec, changed);
        drop(service);
        drop(store);

        let store = Arc::new(IngressControlStore::open(&path).unwrap());
        let service = IngressControlService::open(Arc::clone(&store)).unwrap();
        assert_eq!(service.snapshot().subscriptions[&id].spec, changed);
        let connection = store.connection.lock().unwrap();
        let fingerprint: String = connection
            .query_row(
                "SELECT fingerprint FROM declarative_subscriptions WHERE subscription_id = ?1",
                [id.as_str()],
                |row| row.get(0),
            )
            .unwrap();
        assert!(valid_declaration_fingerprint(&fingerprint));
        assert!(!fingerprint.contains("provider.example"));
        drop(connection);
        drop(service);
        drop(store);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn removing_a_declaration_preserves_unrelated_control_subscriptions() {
        let store = Arc::new(IngressControlStore::open_in_memory().unwrap());
        let mut service = IngressControlService::open(Arc::clone(&store)).unwrap();
        let declared = subscription();
        service
            .reconcile_declarative_resources(1, [], [declared.clone()])
            .unwrap();
        let mut manual = subscription();
        manual.id = SubscriptionId::new("manual").unwrap();
        service
            .add_subscription("admin", RequestId::new(1), 1, manual.clone())
            .unwrap();
        service.reconcile_declarative_resources(2, [], []).unwrap();
        assert!(!service.snapshot().subscriptions.contains_key(&declared.id));
        assert_eq!(service.snapshot().subscriptions[&manual.id].spec, manual);
        drop(service);
        let service = IngressControlService::open(store).unwrap();
        assert!(!service.snapshot().subscriptions.contains_key(&declared.id));
        assert!(service.snapshot().subscriptions.contains_key(&manual.id));
    }

    #[test]
    fn legacy_subscription_is_adopted_without_overwriting_admin_override() {
        let store = Arc::new(IngressControlStore::open_in_memory().unwrap());
        let mut service = IngressControlService::open(Arc::clone(&store)).unwrap();
        let declared = subscription();
        let mut existing = declared.clone();
        existing.enabled = false;
        service
            .add_subscription("admin", RequestId::new(1), 0, existing.clone())
            .unwrap();
        service
            .reconcile_declarative_resources(1, [], [declared.clone()])
            .unwrap();
        drop(service);
        let mut service = IngressControlService::open(store).unwrap();
        service
            .reconcile_declarative_resources(1, [], [declared])
            .unwrap();
        assert_eq!(
            service.snapshot().subscriptions[&existing.id].spec,
            existing
        );
    }

    #[test]
    fn manually_recreating_deleted_declaration_survives_unchanged_yaml() {
        let store = Arc::new(IngressControlStore::open_in_memory().unwrap());
        let declared = subscription();
        let mut service = IngressControlService::open(Arc::clone(&store)).unwrap();
        service
            .reconcile_declarative_resources(1, [], [declared.clone()])
            .unwrap();
        service
            .delete_subscription("admin", RequestId::new(1), 1, &declared.id)
            .unwrap();
        let mut replacement = declared.clone();
        replacement.enabled = false;
        replacement.url = "https://other.example/subscription".to_owned();
        service
            .add_subscription("admin", RequestId::new(2), 2, replacement.clone())
            .unwrap();
        drop(service);
        let mut service = IngressControlService::open(store).unwrap();
        service
            .reconcile_declarative_resources(1, [], [declared])
            .unwrap();
        assert_eq!(
            service.snapshot().subscriptions[&replacement.id].spec,
            replacement
        );
        assert_eq!(service.snapshot().generation, 3);
    }

    #[test]
    fn changed_declaration_advances_existing_control_generation() {
        let store = Arc::new(IngressControlStore::open_in_memory().unwrap());
        let mut service = IngressControlService::open(Arc::clone(&store)).unwrap();
        let mut spec = subscription();
        service
            .reconcile_declarative_resources(1, [], [spec.clone()])
            .unwrap();
        service
            .set_subscription_enabled("admin", RequestId::new(1), 1, &spec.id, false)
            .unwrap();
        spec.url.push_str("?changed=1");
        service
            .reconcile_declarative_resources(1, [], [spec.clone()])
            .unwrap();
        assert_eq!(service.snapshot().generation, 3);
        assert_eq!(service.snapshot().subscriptions[&spec.id].spec, spec);
    }

    #[test]
    fn declaration_added_after_initial_reconciliation_takes_effect() {
        let store = Arc::new(IngressControlStore::open_in_memory().unwrap());
        let mut service = IngressControlService::open(Arc::clone(&store)).unwrap();
        service.reconcile_declarative_resources(0, [], []).unwrap();
        let declared = subscription();
        let mut manual = declared.clone();
        manual.enabled = false;
        service
            .add_subscription("admin", RequestId::new(1), 0, manual)
            .unwrap();
        drop(service);
        let mut service = IngressControlService::open(store).unwrap();
        service
            .reconcile_declarative_resources(1, [], [declared.clone()])
            .unwrap();
        assert_eq!(
            service.snapshot().subscriptions[&declared.id].spec,
            declared
        );
        assert_eq!(service.snapshot().generation, 2);
    }

    #[test]
    fn old_metadata_schema_is_migrated_without_losing_generation() {
        let connection = Connection::open_in_memory().unwrap();
        connection.execute_batch(
            "CREATE TABLE control_metadata (singleton INTEGER PRIMARY KEY, generation INTEGER NOT NULL, next_event_id INTEGER NOT NULL); INSERT INTO control_metadata VALUES (1, 7, 3);",
        ).unwrap();
        let store = Arc::new(IngressControlStore::from_connection(connection).unwrap());
        let service = IngressControlService::open(store).unwrap();
        assert_eq!(service.snapshot().generation, 7);
    }

    #[test]
    fn failed_declarative_reconcile_rolls_back_snapshot_and_baseline() {
        let store = Arc::new(IngressControlStore::open_in_memory().unwrap());
        let mut service = IngressControlService::open(Arc::clone(&store)).unwrap();
        let spec = subscription();
        service
            .reconcile_declarative_resources(1, [], [spec.clone()])
            .unwrap();
        let before = service.snapshot();
        let mut changed = spec.clone();
        changed.enabled = false;
        store.fail_next_commit();
        assert!(
            service
                .reconcile_declarative_resources(2, [], [changed.clone()])
                .is_err()
        );
        assert_eq!(service.snapshot(), before);
        service
            .reconcile_declarative_resources(2, [], [changed.clone()])
            .unwrap();
        assert_eq!(service.snapshot().subscriptions[&spec.id].spec, changed);
    }

    #[test]
    fn invalid_declarative_candidate_cannot_partially_mutate_the_snapshot() {
        let store = Arc::new(IngressControlStore::open_in_memory().unwrap());
        let mut service = IngressControlService::open(store).unwrap();
        let spec = subscription();
        service
            .reconcile_declarative_resources(1, [], [spec.clone()])
            .unwrap();
        let before = service.snapshot();
        let mut invalid = spec;
        invalid.id = SubscriptionId::new("invalid").unwrap();
        invalid.url = "not a URL".to_owned();
        assert!(
            service
                .reconcile_declarative_resources(2, [NodeId::new("new-node").unwrap()], [invalid],)
                .is_err()
        );
        assert_eq!(service.snapshot(), before);
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
    fn reopen_retains_an_old_request_until_its_generation_is_superseded() {
        let store = Arc::new(IngressControlStore::open_in_memory().unwrap());
        let mut service = IngressControlService::open(Arc::clone(&store)).unwrap();
        let node = NodeId::new("node-a").unwrap();
        service.add_node(node.clone()).unwrap();
        let patch = NodeAdminPatch {
            set_labels: BTreeMap::from([("admin.region".into(), "jp".into())]),
            ..NodeAdminPatch::default()
        };
        service
            .patch_node("admin", RequestId::new(1), node.clone(), 0, patch.clone())
            .unwrap();
        let event = service.events_since(None).last().cloned().unwrap();
        drop(service);
        {
            let connection = store.connection.lock().unwrap();
            let old = format!("patch-node:{node:?}:{patch:?}:0");
            connection
                .execute(
                    "UPDATE request_cache SET created_at_ms = 1, fingerprint = ?1",
                    [old],
                )
                .unwrap();
            migrate_request_cache_schema(&connection).unwrap();
            let stored: String = connection
                .query_row("SELECT fingerprint FROM request_cache", [], |row| {
                    row.get(0)
                })
                .unwrap();
            assert!(stored.starts_with("sha256:"));
            assert!(!stored.contains("jp"));
        }

        let mut service = IngressControlService::open(Arc::clone(&store)).unwrap();
        assert_eq!(service.events_since(None).last(), Some(&event));
        assert!(event.emitted_at_ms.is_some());
        assert_eq!(event.payload["admin"]["labels"]["admin.region"], "jp");
        assert!(
            service
                .patch_node("admin", RequestId::new(1), node, 0, patch)
                .unwrap()
                .replayed
        );
    }

    #[test]
    fn failed_management_mutation_is_audited_without_the_request_body() {
        let store = Arc::new(IngressControlStore::open_in_memory().unwrap());
        let service = IngressControlService::open(Arc::clone(&store)).unwrap();
        let mut dispatcher =
            crate::LocalControlDispatcher::with_service(crate::SystemProxyPlatform::Linux, service);
        let response = dispatcher.dispatch(crate::RequestEnvelope {
            api_version: crate::LOCAL_API_VERSION.to_owned(), operation: "nodes.patch_labels".into(), request_id: "request-1".into(),
            actor: crate::Actor { id: "operator".into(), capabilities: vec!["nodes:write".into()] },
            expected_generation: Some(crate::GenerationExpectation { scope: "configuration".into(), value: 0 }),
            body: serde_json::json!({"node_id": "missing", "set": {"admin.region": "private-value"}}),
        });
        assert!(!response.ok);
        let connection = store.connection.lock().unwrap();
        let (operation, result, reason, source, expected): (String, String, String, String, i64) = connection.query_row(
            "SELECT operation, result, reason, source, expected_value FROM control_audit ORDER BY audit_id DESC LIMIT 1", [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
        ).unwrap();
        assert_eq!(
            (
                operation.as_str(),
                result.as_str(),
                reason.as_str(),
                source.as_str(),
                expected
            ),
            ("nodes.patch_labels", "failed", "NOT_FOUND", "local", 0)
        );
        drop(connection);
        let event = dispatcher
            .service()
            .events_since(None)
            .last()
            .cloned()
            .unwrap();
        assert_eq!(event.kind, ControlEventKind::AuditNotice);
        assert_eq!(event.payload["reason"], "NOT_FOUND");
        assert!(!event.payload.to_string().contains("private-value"));
    }

    #[tokio::test]
    async fn audit_source_comes_from_the_transport_not_actor_name() {
        use pathchord_core::management::{ManagementDispatcher, ManagementSource};
        let store = Arc::new(IngressControlStore::open_in_memory().unwrap());
        let service = IngressControlService::open(Arc::clone(&store)).unwrap();
        let mut dispatcher =
            crate::LocalControlDispatcher::with_service(crate::SystemProxyPlatform::Linux, service);
        let request = crate::RequestEnvelope {
            api_version: crate::LOCAL_API_VERSION.to_owned(),
            operation: "nodes.patch_tags".into(),
            request_id: "request-web".into(),
            actor: crate::Actor {
                id: "local-looking-actor".into(),
                capabilities: vec!["nodes:write".into()],
            },
            expected_generation: Some(crate::GenerationExpectation {
                scope: "configuration".into(),
                value: 0,
            }),
            body: serde_json::json!({"node_id": "missing", "add": []}),
        };
        let _ = dispatcher
            .dispatch_from(request, ManagementSource::Web)
            .await;
        let connection = store.connection.lock().unwrap();
        let source: String = connection
            .query_row(
                "SELECT source FROM control_audit ORDER BY audit_id DESC LIMIT 1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(source, "web");
    }

    #[test]
    fn successful_management_response_replays_exactly_after_reopen() {
        let store = Arc::new(IngressControlStore::open_in_memory().unwrap());
        let mut service = IngressControlService::open(Arc::clone(&store)).unwrap();
        service.add_node(NodeId::new("node-a").unwrap()).unwrap();
        let mut dispatcher =
            crate::LocalControlDispatcher::with_service(crate::SystemProxyPlatform::Linux, service);
        let request = crate::RequestEnvelope {
            api_version: crate::LOCAL_API_VERSION.to_owned(),
            operation: "nodes.patch_tags".into(),
            request_id: "persistent-id".into(),
            actor: crate::Actor {
                id: "operator".into(),
                capabilities: vec!["nodes:write".into(), "force".into()],
            },
            expected_generation: None,
            body: serde_json::json!({"node_id": "node-a", "add": ["preferred"]}),
        };
        let first = dispatcher.dispatch(request.clone());
        assert!(first.ok);
        drop(dispatcher);
        let service = IngressControlService::open(Arc::clone(&store)).unwrap();
        let mut reopened =
            crate::LocalControlDispatcher::with_service(crate::SystemProxyPlatform::Linux, service);
        reopened
            .service()
            .observation_handle()
            .set_egress_runtime("different-observation".into(), None, 0, false, 0, 0)
            .unwrap();
        assert_eq!(reopened.dispatch(request), first);
    }

    #[test]
    fn deterministic_failure_replays_after_state_change_and_reopen() {
        let store = Arc::new(IngressControlStore::open_in_memory().unwrap());
        let service = IngressControlService::open(Arc::clone(&store)).unwrap();
        let mut dispatcher =
            crate::LocalControlDispatcher::with_service(crate::SystemProxyPlatform::Linux, service);
        let request = crate::RequestEnvelope {
            api_version: crate::LOCAL_API_VERSION.to_owned(),
            operation: "nodes.patch_tags".into(),
            request_id: "missing-1".into(),
            actor: crate::Actor {
                id: "operator".into(),
                capabilities: vec!["nodes:write".into(), "force".into()],
            },
            expected_generation: None,
            body: serde_json::json!({"node_id": "node-a", "add": ["private-value"]}),
        };
        let first = dispatcher.dispatch(request.clone());
        assert_eq!(
            first.error.as_ref().unwrap().code,
            crate::ErrorCode::NotFound
        );
        let node = NodeId::new("node-a").unwrap();
        dispatcher.service_mut().add_node(node.clone()).unwrap();
        dispatcher
            .service_mut()
            .patch_node(
                "another",
                RequestId::new(25),
                node,
                0,
                NodeAdminPatch::default(),
            )
            .unwrap();
        drop(dispatcher);
        let service = IngressControlService::open(Arc::clone(&store)).unwrap();
        let mut reopened =
            crate::LocalControlDispatcher::with_service(crate::SystemProxyPlatform::Linux, service);
        assert_eq!(reopened.dispatch(request.clone()), first);
        let mut different = request;
        different.body = serde_json::json!({"node_id": "node-a", "add": ["different"]});
        assert_eq!(
            reopened.dispatch(different).error.unwrap().code,
            crate::ErrorCode::IdempotencyConflict
        );
        let connection = store.connection.lock().unwrap();
        let stored: String = connection
            .query_row(
                "SELECT response_json FROM request_cache WHERE actor = 'operator'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(!stored.contains("private-value"));
    }

    #[test]
    fn failure_cache_store_error_leaves_the_request_retryable() {
        let store = Arc::new(IngressControlStore::open_in_memory().unwrap());
        let service = IngressControlService::open(Arc::clone(&store)).unwrap();
        let mut dispatcher =
            crate::LocalControlDispatcher::with_service(crate::SystemProxyPlatform::Linux, service);
        let request = crate::RequestEnvelope {
            api_version: crate::LOCAL_API_VERSION.to_owned(),
            operation: "nodes.patch_tags".into(),
            request_id: "retry-1".into(),
            actor: crate::Actor {
                id: "operator".into(),
                capabilities: vec!["nodes:write".into(), "force".into()],
            },
            expected_generation: None,
            body: serde_json::json!({"node_id": "missing", "add": []}),
        };
        store.fail_next_commit();
        assert_eq!(
            dispatcher.dispatch(request.clone()).error.unwrap().code,
            crate::ErrorCode::PersistenceUnavailable
        );
        assert_eq!(
            dispatcher.dispatch(request).error.unwrap().code,
            crate::ErrorCode::NotFound
        );
    }

    #[test]
    fn unauthorized_and_retryable_failures_are_not_cached() {
        let store = Arc::new(IngressControlStore::open_in_memory().unwrap());
        let mut service = IngressControlService::open(Arc::clone(&store)).unwrap();
        service.add_node(NodeId::new("node-a").unwrap()).unwrap();
        let mut dispatcher =
            crate::LocalControlDispatcher::with_service(crate::SystemProxyPlatform::Linux, service);
        let mut request = crate::RequestEnvelope {
            api_version: crate::LOCAL_API_VERSION.to_owned(),
            operation: "nodes.patch_tags".into(),
            request_id: "auth-retry".into(),
            actor: crate::Actor {
                id: "operator".into(),
                capabilities: vec![],
            },
            expected_generation: Some(crate::GenerationExpectation {
                scope: "configuration".into(),
                value: 0,
            }),
            body: serde_json::json!({"node_id": "node-a", "add": []}),
        };
        assert_eq!(
            dispatcher.dispatch(request.clone()).error.unwrap().code,
            crate::ErrorCode::CapabilityDenied
        );
        request.actor.capabilities.push("nodes:write".into());
        assert!(dispatcher.dispatch(request).ok);

        let mut invalid = crate::RequestEnvelope {
            api_version: crate::LOCAL_API_VERSION.to_owned(),
            operation: "nodes.patch_tags".into(),
            request_id: "invalid-1".into(),
            actor: crate::Actor {
                id: "operator".into(),
                capabilities: vec!["nodes:write".into(), "force".into()],
            },
            expected_generation: None,
            body: serde_json::json!({"node_id": "node-a", "secret-in-field-name": "secret-value"}),
        };
        let response = dispatcher.dispatch(invalid.clone());
        assert_eq!(
            response.error.as_ref().unwrap().code,
            crate::ErrorCode::ValidationFailed
        );
        assert!(!response.error.unwrap().message.contains("secret"));
        invalid.body = serde_json::json!({"node_id": "node-a", "add": []});
        assert_eq!(
            dispatcher.dispatch(invalid).error.unwrap().code,
            crate::ErrorCode::IdempotencyConflict
        );
        let connection = store.connection.lock().unwrap();
        let stored: String = connection.query_row("SELECT response_json FROM request_cache WHERE actor = 'operator' AND response_json LIKE '%VALIDATION_FAILED%'", [], |row| row.get(0)).unwrap();
        assert!(!stored.contains("secret"));
    }

    #[test]
    fn already_queued_refresh_can_retry_with_same_request_id() {
        let store = Arc::new(IngressControlStore::open_in_memory().unwrap());
        let mut service = IngressControlService::open(Arc::clone(&store)).unwrap();
        let spec = subscription();
        let id = spec.id.clone();
        service
            .add_subscription("operator", RequestId::new(1), 0, spec)
            .unwrap();
        let mut dispatcher =
            crate::LocalControlDispatcher::with_service(crate::SystemProxyPlatform::Linux, service);
        let mut request = crate::RequestEnvelope {
            api_version: crate::LOCAL_API_VERSION.to_owned(),
            operation: "subscriptions.refresh".into(),
            request_id: "refresh-first".into(),
            actor: crate::Actor {
                id: "operator".into(),
                capabilities: vec!["subscriptions:write".into(), "force".into()],
            },
            expected_generation: None,
            body: serde_json::json!({"id": id.as_str(), "revision": 0}),
        };
        assert!(dispatcher.dispatch(request.clone()).ok);
        request.request_id = "refresh-retry".into();
        let queued = dispatcher.dispatch(request.clone());
        assert_eq!(
            queued.error.as_ref().unwrap().details.as_ref().unwrap()["retryable"],
            true
        );
        dispatcher
            .service_mut()
            .complete_subscription_refresh(&id, false, Some("temporary".into()))
            .unwrap();
        assert!(dispatcher.dispatch(request).ok);
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
