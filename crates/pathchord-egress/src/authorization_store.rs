use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use thiserror::Error;

use crate::{
    AuthorizationRecord, AuthorizationSnapshot, AuthorizationSnapshotError, AuthorizationState,
    EgressId, IngressId,
};

const MAX_FAILED_REQUESTS: u64 = 4096;
const FAILED_REQUEST_TTL_MS: u64 = 24 * 60 * 60 * 1000;

const SCHEMA: &str = r#"
PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS authorization_metadata (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    generation INTEGER NOT NULL CHECK (generation >= 0),
    egress_id TEXT NOT NULL,
    egress_public_key BLOB NOT NULL CHECK (length(egress_public_key) = 32)
);
CREATE TABLE IF NOT EXISTS authorizations (
    ingress_id TEXT PRIMARY KEY,
    ingress_public_key BLOB NOT NULL CHECK (length(ingress_public_key) = 32),
    state TEXT NOT NULL CHECK (state IN ('enabled', 'disabled', 'revoked')),
    administrator_labels TEXT NOT NULL,
    record_generation INTEGER NOT NULL CHECK (record_generation >= 0)
);
CREATE TABLE IF NOT EXISTS authorization_requests (
    actor_id TEXT NOT NULL,
    request_id TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    applied_generation INTEGER NOT NULL CHECK (applied_generation >= 0),
    state TEXT,
    cleanup_complete INTEGER NOT NULL DEFAULT 0 CHECK (cleanup_complete IN (0, 1)),
    cleanup_paths INTEGER NOT NULL DEFAULT 0 CHECK (cleanup_paths >= 0),
    cleanup_sessions INTEGER NOT NULL DEFAULT 0 CHECK (cleanup_sessions >= 0),
    cleanup_streams INTEGER NOT NULL DEFAULT 0 CHECK (cleanup_streams >= 0),
    cleanup_target_connections INTEGER NOT NULL DEFAULT 0 CHECK (cleanup_target_connections >= 0),
    PRIMARY KEY (actor_id, request_id)
);
CREATE TABLE IF NOT EXISTS authorization_failed_requests (
    actor_id TEXT NOT NULL,
    request_id TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    response_json TEXT NOT NULL,
    owner_generation INTEGER NOT NULL CHECK (owner_generation >= 0),
    created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0),
    PRIMARY KEY (actor_id, request_id)
);
CREATE TABLE IF NOT EXISTS authorization_audit (
    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp_ms INTEGER NOT NULL,
    actor_id TEXT NOT NULL,
    operation TEXT NOT NULL,
    request_id TEXT NOT NULL,
    ingress_id TEXT NOT NULL,
    expected_generation INTEGER NOT NULL,
    applied_generation INTEGER NOT NULL,
    result TEXT NOT NULL,
    source TEXT NOT NULL DEFAULT 'local',
    reason TEXT
);
"#;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthorizationMutation {
    Enroll {
        public_key: [u8; 32],
        administrator_labels: BTreeMap<String, String>,
    },
    Enable,
    Disable,
    Revoke,
    Delete,
}

impl AuthorizationMutation {
    fn operation(&self) -> &'static str {
        match self {
            Self::Enroll { .. } => "enroll",
            Self::Enable => "enable",
            Self::Disable => "disable",
            Self::Revoke => "revoke",
            Self::Delete => "delete",
        }
    }

    fn fingerprint(&self, ingress_id: &IngressId) -> Result<String, AuthorizationStoreError> {
        let body = match self {
            Self::Enroll {
                public_key,
                administrator_labels,
            } => format!(
                "{}:{}:{}",
                self.operation(),
                encode_key(public_key),
                serde_json::to_string(administrator_labels)?
            ),
            _ => self.operation().to_owned(),
        };
        Ok(fingerprint_digest(&format!(
            "{}:{body}",
            ingress_id.as_str()
        )))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationMutationRequest {
    pub actor_id: String,
    pub request_id: String,
    pub expected_generation: u64,
    pub ingress_id: IngressId,
    pub mutation: AuthorizationMutation,
}

pub(crate) struct AuthorizationFailureAudit<'a> {
    pub actor: &'a str,
    pub operation: &'a str,
    pub request_id: &'a str,
    pub ingress_id: &'a str,
    pub expected_generation: Option<u64>,
    pub result: &'a str,
    pub reason: &'a str,
    pub source: &'a str,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AuthorizationCleanup {
    pub paths: u64,
    pub sessions: u64,
    pub streams: u64,
    pub target_connections: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationMutationResult {
    pub applied_generation: u64,
    pub state: Option<AuthorizationState>,
    pub replayed: bool,
    pub cleanup: AuthorizationCleanup,
    pub cleanup_complete: bool,
}

#[derive(Debug, Error)]
pub enum AuthorizationStoreError {
    #[error("authorization store is unavailable")]
    Sql(#[from] rusqlite::Error),
    #[error("authorization metadata does not match the configured Egress identity")]
    IdentityMismatch,
    #[error("authorization request contains an invalid {field}")]
    InvalidField { field: &'static str },
    #[error("authorization generation conflict: expected {expected}, current {current}")]
    GenerationConflict { expected: u64, current: u64 },
    #[error("authorization record already exists")]
    AlreadyExists,
    #[error("authorization record was not found")]
    NotFound,
    #[error("a revoked authorization cannot be enabled or replaced")]
    RevokedIsTerminal,
    #[error("authorization request ID was reused with different input")]
    IdempotencyConflict,
    #[error("authorization failure cache is full")]
    ResourceLimit,
    #[error("authorization snapshot is invalid: {0}")]
    Snapshot(#[from] AuthorizationSnapshotError),
    #[error("authorization label serialization failed")]
    Json(#[from] serde_json::Error),
    #[error("authorization store lock is unavailable")]
    Lock,
    #[error("system clock is before the Unix epoch")]
    Clock,
}

#[derive(Debug)]
pub struct AuthorizationStore {
    connection: Mutex<Connection>,
    mutation_gate: tokio::sync::Mutex<()>,
}

impl AuthorizationStore {
    pub fn open(
        path: impl AsRef<Path>,
        egress_id: EgressId,
        egress_public_key: [u8; 32],
    ) -> Result<Self, AuthorizationStoreError> {
        Self::from_connection(Connection::open(path)?, egress_id, egress_public_key)
    }

    #[cfg(test)]
    fn open_in_memory(
        egress_id: EgressId,
        egress_public_key: [u8; 32],
    ) -> Result<Self, AuthorizationStoreError> {
        Self::from_connection(Connection::open_in_memory()?, egress_id, egress_public_key)
    }

    fn from_connection(
        mut connection: Connection,
        egress_id: EgressId,
        egress_public_key: [u8; 32],
    ) -> Result<Self, AuthorizationStoreError> {
        if egress_id.as_str().is_empty() {
            return Err(AuthorizationStoreError::InvalidField { field: "egress_id" });
        }
        connection.execute_batch(SCHEMA)?;
        migrate_request_cleanup_columns(&connection)?;
        migrate_authorization_audit_columns(&connection)?;
        migrate_failed_request_columns(&connection)?;
        migrate_request_fingerprints(&connection)?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let existing = transaction
            .query_row(
                "SELECT egress_id, egress_public_key FROM authorization_metadata WHERE singleton = 1",
                [],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?)),
            )
            .optional()?;
        match existing {
            Some((stored_id, stored_key))
                if stored_id != egress_id.as_str() || stored_key != egress_public_key =>
            {
                return Err(AuthorizationStoreError::IdentityMismatch);
            }
            Some(_) => {}
            None => {
                transaction.execute(
                    "INSERT INTO authorization_metadata(singleton, generation, egress_id, egress_public_key) VALUES (1, 0, ?1, ?2)",
                    params![egress_id.as_str(), egress_public_key.as_slice()],
                )?;
            }
        }
        transaction.commit()?;
        Ok(Self {
            connection: Mutex::new(connection),
            mutation_gate: tokio::sync::Mutex::new(()),
        })
    }

    pub(crate) async fn lock_mutations(&self) -> tokio::sync::MutexGuard<'_, ()> {
        self.mutation_gate.lock().await
    }

    pub(crate) fn replay_failed_request(
        &self,
        actor: &str,
        request_id: &str,
        fingerprint: &str,
    ) -> Result<Option<pathchord_core::management::ResponseEnvelope>, AuthorizationStoreError> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| AuthorizationStoreError::Lock)?;
        let cutoff = now_ms()?.saturating_sub(FAILED_REQUEST_TTL_MS);
        let row = connection.query_row("SELECT fingerprint, response_json FROM authorization_failed_requests WHERE actor_id = ?1 AND request_id = ?2 AND (created_at_ms >= ?3 OR owner_generation >= (SELECT generation FROM authorization_metadata WHERE singleton = 1))", params![actor, request_id, to_sql_i64(cutoff, "cutoff")?], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))).optional()?;
        match row {
            None => Ok(None),
            Some((stored, response)) if stored == fingerprint => {
                Ok(Some(serde_json::from_str(&response)?))
            }
            Some(_) => Err(AuthorizationStoreError::IdempotencyConflict),
        }
    }

    pub(crate) fn remember_failed_request(
        &self,
        actor: &str,
        request_id: &str,
        fingerprint: &str,
        response: &pathchord_core::management::ResponseEnvelope,
    ) -> Result<pathchord_core::management::ResponseEnvelope, AuthorizationStoreError> {
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| AuthorizationStoreError::Lock)?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let now = now_ms()?;
        let cutoff = now.saturating_sub(FAILED_REQUEST_TTL_MS);
        let current: i64 = transaction.query_row(
            "SELECT generation FROM authorization_metadata WHERE singleton = 1",
            [],
            |row| row.get(0),
        )?;
        transaction.execute("DELETE FROM authorization_failed_requests WHERE created_at_ms < ?1 AND owner_generation < ?2", params![to_sql_i64(cutoff, "cutoff")?, current])?;
        let succeeded: bool = transaction.query_row("SELECT EXISTS(SELECT 1 FROM authorization_requests WHERE actor_id = ?1 AND request_id = ?2)", params![actor, request_id], |row| row.get(0))?;
        if succeeded {
            return Err(AuthorizationStoreError::IdempotencyConflict);
        }
        let stored = transaction.query_row("SELECT fingerprint, response_json FROM authorization_failed_requests WHERE actor_id = ?1 AND request_id = ?2", params![actor, request_id], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))).optional()?;
        if let Some((stored_fingerprint, stored_response)) = stored {
            if stored_fingerprint != fingerprint {
                return Err(AuthorizationStoreError::IdempotencyConflict);
            }
            return Ok(serde_json::from_str(&stored_response)?);
        }
        let count: i64 = transaction.query_row(
            "SELECT COUNT(*) FROM authorization_failed_requests",
            [],
            |row| row.get(0),
        )?;
        if from_sql_u64(count, "failed request count")? >= MAX_FAILED_REQUESTS {
            return Err(AuthorizationStoreError::ResourceLimit);
        }
        let encoded = serde_json::to_string(response)?;
        transaction.execute("INSERT INTO authorization_failed_requests(actor_id, request_id, fingerprint, response_json, owner_generation, created_at_ms) VALUES (?1, ?2, ?3, ?4, ?5, ?6)", params![actor, request_id, fingerprint, encoded, current, to_sql_i64(now, "timestamp")?])?;
        transaction.commit()?;
        Ok(response.clone())
    }

    pub fn snapshot(&self) -> Result<AuthorizationSnapshot, AuthorizationStoreError> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| AuthorizationStoreError::Lock)?;
        let (generation, egress_id, egress_public_key) = metadata(&connection)?;
        let mut statement = connection.prepare(
            "SELECT ingress_id, ingress_public_key, state, administrator_labels, record_generation FROM authorizations ORDER BY ingress_id",
        )?;
        let records = statement
            .query_map([], |row| {
                let public_key: Vec<u8> = row.get(1)?;
                let labels: String = row.get(3)?;
                Ok((
                    row.get::<_, String>(0)?,
                    public_key,
                    row.get::<_, String>(2)?,
                    labels,
                    row.get::<_, i64>(4)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .map(|(ingress_id, key, state, labels, record_generation)| {
                Ok(AuthorizationRecord {
                    ingress_id: IngressId::new(ingress_id),
                    ingress_public_key: decode_key(key)?,
                    state: decode_state(&state)?,
                    administrator_labels: serde_json::from_str(&labels)?,
                    record_generation: from_sql_u64(record_generation, "record_generation")?,
                })
            })
            .collect::<Result<Vec<_>, AuthorizationStoreError>>()?;
        Ok(AuthorizationSnapshot::try_new(
            generation,
            EgressId::new(egress_id),
            decode_key(egress_public_key)?,
            records,
        )?)
    }

    pub fn mutate(
        &self,
        request: AuthorizationMutationRequest,
    ) -> Result<AuthorizationMutationResult, AuthorizationStoreError> {
        self.mutate_from(request, "local")
    }

    pub fn mutate_from(
        &self,
        request: AuthorizationMutationRequest,
        source: &str,
    ) -> Result<AuthorizationMutationResult, AuthorizationStoreError> {
        validate_request(&request)?;
        let fingerprint = request.mutation.fingerprint(&request.ingress_id)?;
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| AuthorizationStoreError::Lock)?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;

        let cutoff = now_ms()?.saturating_sub(FAILED_REQUEST_TTL_MS);
        let failed: bool = transaction.query_row("SELECT EXISTS(SELECT 1 FROM authorization_failed_requests WHERE actor_id = ?1 AND request_id = ?2 AND (created_at_ms >= ?3 OR owner_generation >= (SELECT generation FROM authorization_metadata WHERE singleton = 1)))", params![request.actor_id, request.request_id, to_sql_i64(cutoff, "cutoff")?], |row| row.get(0))?;
        if failed {
            return Err(AuthorizationStoreError::IdempotencyConflict);
        }

        if let Some(result) = replay(&transaction, &request, &fingerprint)? {
            transaction.commit()?;
            return Ok(result);
        }

        let current_generation = transaction.query_row(
            "SELECT generation FROM authorization_metadata WHERE singleton = 1",
            [],
            |row| row.get::<_, i64>(0),
        )?;
        let current_generation = from_sql_u64(current_generation, "generation")?;
        if request.expected_generation != current_generation {
            return Err(AuthorizationStoreError::GenerationConflict {
                expected: request.expected_generation,
                current: current_generation,
            });
        }

        let current_state = record_state(&transaction, &request.ingress_id)?;
        let (changed, state) = apply_mutation(&transaction, &request, current_state)?;
        let applied_generation = if changed {
            current_generation
                .checked_add(1)
                .ok_or(AuthorizationStoreError::InvalidField {
                    field: "generation",
                })?
        } else {
            current_generation
        };
        if changed {
            transaction.execute(
                "UPDATE authorization_metadata SET generation = ?1 WHERE singleton = 1",
                [to_sql_i64(applied_generation, "generation")?],
            )?;
            if state.is_some() {
                transaction.execute(
                    "UPDATE authorizations SET record_generation = ?1 WHERE ingress_id = ?2",
                    params![
                        to_sql_i64(applied_generation, "record_generation")?,
                        request.ingress_id.as_str()
                    ],
                )?;
            }
        }

        let cleanup_complete = !matches!(
            &request.mutation,
            AuthorizationMutation::Disable
                | AuthorizationMutation::Revoke
                | AuthorizationMutation::Delete
        );
        transaction.execute(
            "INSERT INTO authorization_requests(actor_id, request_id, fingerprint, applied_generation, state, cleanup_complete) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                request.actor_id,
                request.request_id,
                fingerprint,
                to_sql_i64(applied_generation, "generation")?,
                state.map(encode_state),
                i64::from(cleanup_complete),
            ],
        )?;
        transaction.execute(
            "INSERT INTO authorization_audit(timestamp_ms, actor_id, operation, request_id, ingress_id, expected_generation, applied_generation, result, source) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'applied', ?8)",
            params![
                to_sql_i64(now_ms()?, "timestamp_ms")?,
                request.actor_id,
                request.mutation.operation(),
                request.request_id,
                request.ingress_id.as_str(),
                to_sql_i64(request.expected_generation, "expected_generation")?,
                to_sql_i64(applied_generation, "generation")?,
                source,
            ],
        )?;
        transaction.commit()?;

        Ok(AuthorizationMutationResult {
            applied_generation,
            state,
            replayed: false,
            cleanup: AuthorizationCleanup::default(),
            cleanup_complete,
        })
    }

    pub fn record_cleanup(
        &self,
        actor_id: &str,
        request_id: &str,
        cleanup: AuthorizationCleanup,
    ) -> Result<(), AuthorizationStoreError> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| AuthorizationStoreError::Lock)?;
        let updated = connection.execute(
            "UPDATE authorization_requests SET cleanup_complete = 1, cleanup_paths = ?1, cleanup_sessions = ?2, cleanup_streams = ?3, cleanup_target_connections = ?4 WHERE actor_id = ?5 AND request_id = ?6",
            params![
                to_sql_i64(cleanup.paths, "cleanup.paths")?,
                to_sql_i64(cleanup.sessions, "cleanup.sessions")?,
                to_sql_i64(cleanup.streams, "cleanup.streams")?,
                to_sql_i64(cleanup.target_connections, "cleanup.target_connections")?,
                actor_id,
                request_id,
            ],
        )?;
        if updated == 0 {
            return Err(AuthorizationStoreError::NotFound);
        }
        Ok(())
    }

    pub fn record_authentication_failure(
        &self,
        source: &str,
    ) -> Result<(), AuthorizationStoreError> {
        if source.is_empty() || source.len() > 256 {
            return Err(AuthorizationStoreError::InvalidField {
                field: "authentication source",
            });
        }
        let connection = self
            .connection
            .lock()
            .map_err(|_| AuthorizationStoreError::Lock)?;
        let generation: i64 = connection.query_row(
            "SELECT generation FROM authorization_metadata WHERE singleton = 1",
            [],
            |row| row.get(0),
        )?;
        connection.execute(
            "INSERT INTO authorization_audit(timestamp_ms, actor_id, operation, request_id, ingress_id, expected_generation, applied_generation, result, source, reason) VALUES (?1, 'unauthenticated', 'authentication.failure', '', '', ?2, ?2, 'denied', ?3, 'AUTHENTICATION_REQUIRED')",
            params![to_sql_i64(now_ms()?, "timestamp_ms")?, generation, source],
        )?;
        Ok(())
    }

    pub(crate) fn record_mutation_failure(
        &self,
        audit: AuthorizationFailureAudit<'_>,
    ) -> Result<(), AuthorizationStoreError> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| AuthorizationStoreError::Lock)?;
        let generation: i64 = connection.query_row(
            "SELECT generation FROM authorization_metadata WHERE singleton = 1",
            [],
            |row| row.get(0),
        )?;
        connection.execute(
            "INSERT INTO authorization_audit(timestamp_ms, actor_id, operation, request_id, ingress_id, expected_generation, applied_generation, result, source, reason) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![to_sql_i64(now_ms()?, "timestamp_ms")?, audit.actor, audit.operation, audit.request_id, audit.ingress_id,
                audit.expected_generation.and_then(|value| i64::try_from(value).ok()).unwrap_or(-1),
                generation, audit.result, audit.source, audit.reason],
        )?;
        Ok(())
    }
}

fn migrate_failed_request_columns(connection: &Connection) -> Result<(), rusqlite::Error> {
    let mut statement = connection.prepare("PRAGMA table_info(authorization_failed_requests)")?;
    let columns = statement
        .query_map([], |row| row.get::<_, String>(1))?
        .collect::<Result<std::collections::HashSet<_>, _>>()?;
    for (name, definition) in [
        ("owner_generation", "INTEGER NOT NULL DEFAULT 0"),
        ("created_at_ms", "INTEGER NOT NULL DEFAULT 0"),
    ] {
        if !columns.contains(name) {
            connection.execute_batch(&format!(
                "ALTER TABLE authorization_failed_requests ADD COLUMN {name} {definition}"
            ))?;
        }
    }
    Ok(())
}

fn migrate_request_fingerprints(connection: &Connection) -> Result<(), rusqlite::Error> {
    let legacy = {
        let mut statement = connection.prepare("SELECT actor_id, request_id, fingerprint FROM authorization_requests WHERE fingerprint NOT LIKE 'sha256:%'")?;
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
        connection.execute("UPDATE authorization_requests SET fingerprint = ?1 WHERE actor_id = ?2 AND request_id = ?3", params![fingerprint_digest(&fingerprint), actor, request_id])?;
    }
    Ok(())
}

pub(crate) fn fingerprint_digest(value: &str) -> String {
    use std::fmt::Write as _;
    let digest = orion::hazardous::hash::sha2::sha256::Sha256::digest(value.as_bytes())
        .expect("bounded authorization fingerprint");
    let mut result = String::from("sha256:");
    for byte in digest.as_ref() {
        write!(result, "{byte:02x}").expect("writing to a String cannot fail");
    }
    result
}

fn migrate_authorization_audit_columns(connection: &Connection) -> Result<(), rusqlite::Error> {
    let mut statement = connection.prepare("PRAGMA table_info(authorization_audit)")?;
    let columns = statement
        .query_map([], |row| row.get::<_, String>(1))?
        .collect::<Result<std::collections::HashSet<_>, _>>()?;
    for (name, definition) in [
        ("source", "TEXT NOT NULL DEFAULT 'local'"),
        ("reason", "TEXT"),
    ] {
        if !columns.contains(name) {
            connection.execute(
                &format!("ALTER TABLE authorization_audit ADD COLUMN {name} {definition}"),
                [],
            )?;
        }
    }
    Ok(())
}

fn migrate_request_cleanup_columns(connection: &Connection) -> Result<(), rusqlite::Error> {
    let mut statement = connection.prepare("PRAGMA table_info(authorization_requests)")?;
    let columns = statement
        .query_map([], |row| row.get::<_, String>(1))?
        .collect::<Result<std::collections::HashSet<_>, _>>()?;
    for (name, definition) in [
        (
            "cleanup_complete",
            "INTEGER NOT NULL DEFAULT 0 CHECK (cleanup_complete IN (0, 1))",
        ),
        (
            "cleanup_paths",
            "INTEGER NOT NULL DEFAULT 0 CHECK (cleanup_paths >= 0)",
        ),
        (
            "cleanup_sessions",
            "INTEGER NOT NULL DEFAULT 0 CHECK (cleanup_sessions >= 0)",
        ),
        (
            "cleanup_streams",
            "INTEGER NOT NULL DEFAULT 0 CHECK (cleanup_streams >= 0)",
        ),
        (
            "cleanup_target_connections",
            "INTEGER NOT NULL DEFAULT 0 CHECK (cleanup_target_connections >= 0)",
        ),
    ] {
        if !columns.contains(name) {
            connection.execute_batch(&format!(
                "ALTER TABLE authorization_requests ADD COLUMN {name} {definition}"
            ))?;
        }
    }
    Ok(())
}

fn metadata(connection: &Connection) -> Result<(u64, String, Vec<u8>), AuthorizationStoreError> {
    let (generation, egress_id, key) = connection.query_row(
        "SELECT generation, egress_id, egress_public_key FROM authorization_metadata WHERE singleton = 1",
        [],
        |row| Ok((row.get::<_, i64>(0)?, row.get(1)?, row.get(2)?)),
    )?;
    Ok((from_sql_u64(generation, "generation")?, egress_id, key))
}

fn validate_request(request: &AuthorizationMutationRequest) -> Result<(), AuthorizationStoreError> {
    for (field, value) in [
        ("actor_id", request.actor_id.as_str()),
        ("request_id", request.request_id.as_str()),
        ("ingress_id", request.ingress_id.as_str()),
    ] {
        if value.is_empty() || value.len() > 255 {
            return Err(AuthorizationStoreError::InvalidField { field });
        }
    }
    if let AuthorizationMutation::Enroll {
        public_key,
        administrator_labels,
    } = &request.mutation
    {
        if public_key.iter().all(|byte| *byte == 0) {
            return Err(AuthorizationStoreError::InvalidField {
                field: "public_key",
            });
        }
        if administrator_labels.len() > 256
            || administrator_labels
                .iter()
                .any(|(key, value)| key.len() > 64 || value.len() > 256)
        {
            return Err(AuthorizationStoreError::InvalidField {
                field: "administrator_labels",
            });
        }
    }
    Ok(())
}

fn replay(
    transaction: &Transaction<'_>,
    request: &AuthorizationMutationRequest,
    fingerprint: &str,
) -> Result<Option<AuthorizationMutationResult>, AuthorizationStoreError> {
    let cached = transaction
        .query_row(
            "SELECT fingerprint, applied_generation, state, cleanup_complete, cleanup_paths, cleanup_sessions, cleanup_streams, cleanup_target_connections FROM authorization_requests WHERE actor_id = ?1 AND request_id = ?2",
            params![request.actor_id, request.request_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, bool>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, i64>(6)?,
                    row.get::<_, i64>(7)?,
                ))
            },
        )
        .optional()?;
    let Some((
        cached_fingerprint,
        applied_generation,
        state,
        cleanup_complete,
        cleanup_paths,
        cleanup_sessions,
        cleanup_streams,
        cleanup_target_connections,
    )) = cached
    else {
        return Ok(None);
    };
    if cached_fingerprint != fingerprint {
        return Err(AuthorizationStoreError::IdempotencyConflict);
    }
    Ok(Some(AuthorizationMutationResult {
        applied_generation: from_sql_u64(applied_generation, "generation")?,
        state: state.as_deref().map(decode_state).transpose()?,
        replayed: true,
        cleanup: AuthorizationCleanup {
            paths: from_sql_u64(cleanup_paths, "cleanup.paths")?,
            sessions: from_sql_u64(cleanup_sessions, "cleanup.sessions")?,
            streams: from_sql_u64(cleanup_streams, "cleanup.streams")?,
            target_connections: from_sql_u64(
                cleanup_target_connections,
                "cleanup.target_connections",
            )?,
        },
        cleanup_complete,
    }))
}

fn record_state(
    transaction: &Transaction<'_>,
    ingress_id: &IngressId,
) -> Result<Option<AuthorizationState>, AuthorizationStoreError> {
    transaction
        .query_row(
            "SELECT state FROM authorizations WHERE ingress_id = ?1",
            [ingress_id.as_str()],
            |row| row.get::<_, String>(0),
        )
        .optional()?
        .as_deref()
        .map(decode_state)
        .transpose()
}

fn apply_mutation(
    transaction: &Transaction<'_>,
    request: &AuthorizationMutationRequest,
    current_state: Option<AuthorizationState>,
) -> Result<(bool, Option<AuthorizationState>), AuthorizationStoreError> {
    match &request.mutation {
        AuthorizationMutation::Enroll {
            public_key,
            administrator_labels,
        } => {
            if current_state == Some(AuthorizationState::Revoked) {
                return Err(AuthorizationStoreError::RevokedIsTerminal);
            }
            if current_state.is_some() {
                return Err(AuthorizationStoreError::AlreadyExists);
            }
            transaction.execute(
                "INSERT INTO authorizations(ingress_id, ingress_public_key, state, administrator_labels, record_generation) VALUES (?1, ?2, 'enabled', ?3, 0)",
                params![
                    request.ingress_id.as_str(),
                    public_key.as_slice(),
                    serde_json::to_string(administrator_labels)?,
                ],
            )?;
            Ok((true, Some(AuthorizationState::Enabled)))
        }
        AuthorizationMutation::Enable => set_state(
            transaction,
            request,
            current_state,
            AuthorizationState::Enabled,
        ),
        AuthorizationMutation::Disable => set_state(
            transaction,
            request,
            current_state,
            AuthorizationState::Disabled,
        ),
        AuthorizationMutation::Revoke => set_state(
            transaction,
            request,
            current_state,
            AuthorizationState::Revoked,
        ),
        AuthorizationMutation::Delete => {
            if current_state.is_none() {
                return Err(AuthorizationStoreError::NotFound);
            }
            transaction.execute(
                "DELETE FROM authorizations WHERE ingress_id = ?1",
                [request.ingress_id.as_str()],
            )?;
            Ok((true, None))
        }
    }
}

fn set_state(
    transaction: &Transaction<'_>,
    request: &AuthorizationMutationRequest,
    current_state: Option<AuthorizationState>,
    desired: AuthorizationState,
) -> Result<(bool, Option<AuthorizationState>), AuthorizationStoreError> {
    let Some(current) = current_state else {
        return Err(AuthorizationStoreError::NotFound);
    };
    if current == AuthorizationState::Revoked && desired != AuthorizationState::Revoked {
        return Err(AuthorizationStoreError::RevokedIsTerminal);
    }
    if current == desired {
        return Ok((false, Some(current)));
    }
    transaction.execute(
        "UPDATE authorizations SET state = ?1 WHERE ingress_id = ?2",
        params![encode_state(desired), request.ingress_id.as_str()],
    )?;
    Ok((true, Some(desired)))
}

fn encode_state(state: AuthorizationState) -> &'static str {
    match state {
        AuthorizationState::Enabled => "enabled",
        AuthorizationState::Disabled => "disabled",
        AuthorizationState::Revoked => "revoked",
    }
}

fn decode_state(value: &str) -> Result<AuthorizationState, AuthorizationStoreError> {
    match value {
        "enabled" => Ok(AuthorizationState::Enabled),
        "disabled" => Ok(AuthorizationState::Disabled),
        "revoked" => Ok(AuthorizationState::Revoked),
        _ => Err(AuthorizationStoreError::InvalidField { field: "state" }),
    }
}

fn decode_key(value: Vec<u8>) -> Result<[u8; 32], AuthorizationStoreError> {
    value
        .try_into()
        .map_err(|_| AuthorizationStoreError::InvalidField {
            field: "public_key",
        })
}

fn to_sql_i64(value: u64, field: &'static str) -> Result<i64, AuthorizationStoreError> {
    i64::try_from(value).map_err(|_| AuthorizationStoreError::InvalidField { field })
}

fn from_sql_u64(value: i64, field: &'static str) -> Result<u64, AuthorizationStoreError> {
    u64::try_from(value).map_err(|_| AuthorizationStoreError::InvalidField { field })
}

fn encode_key(value: &[u8; 32]) -> String {
    value.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn now_ms() -> Result<u64, AuthorizationStoreError> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| AuthorizationStoreError::Clock)?;
    u64::try_from(duration.as_millis()).map_err(|_| AuthorizationStoreError::Clock)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use pathchord_core::management::{
        Actor, ErrorCode, GenerationExpectation, LOCAL_API_VERSION, RequestEnvelope,
    };
    use serde_json::{Value, json};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_DATABASE: AtomicU64 = AtomicU64::new(0);

    fn management_request(
        operation: &str,
        request_id: &str,
        expected: u64,
        body: Value,
    ) -> RequestEnvelope {
        RequestEnvelope {
            api_version: LOCAL_API_VERSION.into(),
            operation: operation.into(),
            request_id: request_id.into(),
            actor: Actor {
                id: "local-admin".into(),
                capabilities: vec!["authorization:write".into()],
            },
            expected_generation: Some(GenerationExpectation {
                scope: "authorization".into(),
                value: expected,
            }),
            body,
        }
    }

    #[tokio::test]
    async fn failed_mutation_replays_across_generation_change_and_database_reopen() {
        let path = std::env::temp_dir().join(format!(
            "pathchord-egress-failure-{}-{}.db",
            std::process::id(),
            NEXT_DATABASE.fetch_add(1, Ordering::Relaxed)
        ));
        let first = {
            let store = Arc::new(
                AuthorizationStore::open(&path, EgressId::new("egress-a"), [9; 32]).unwrap(),
            );
            let dispatcher = crate::AuthorizationControlDispatcher::new(Arc::clone(&store));
            let failed = management_request(
                "authorizations.disable",
                "same-id",
                1,
                json!({"ingress_id": "ingress-a"}),
            );
            let first = dispatcher.dispatch(failed).await;
            assert_eq!(
                first.error.as_ref().unwrap().code,
                ErrorCode::GenerationConflict
            );
            let enroll = management_request(
                "authorizations.enroll",
                "advance",
                0,
                json!({"ingress_id":"ingress-a", "egress_id":"egress-a", "public_key": URL_SAFE_NO_PAD.encode([7; 32])}),
            );
            assert!(dispatcher.dispatch(enroll).await.ok);
            first
        };
        let store =
            Arc::new(AuthorizationStore::open(&path, EgressId::new("egress-a"), [9; 32]).unwrap());
        let dispatcher = crate::AuthorizationControlDispatcher::new(Arc::clone(&store));
        let same = management_request(
            "authorizations.disable",
            "same-id",
            1,
            json!({"ingress_id": "ingress-a"}),
        );
        assert_eq!(dispatcher.dispatch(same.clone()).await, first);
        let mut different = same;
        different.body = json!({"ingress_id": "other"});
        assert_eq!(
            dispatcher.dispatch(different).await.error.unwrap().code,
            ErrorCode::IdempotencyConflict
        );
        assert_eq!(
            store.snapshot().unwrap().records().next().unwrap().state,
            AuthorizationState::Enabled
        );
        drop(dispatcher);
        drop(store);
        std::fs::remove_file(path).unwrap();
    }

    #[tokio::test]
    async fn failure_cache_contains_no_private_request_fields_and_denials_do_not_reserve_ids() {
        let store = Arc::new(
            AuthorizationStore::open_in_memory(EgressId::new("egress-a"), [9; 32]).unwrap(),
        );
        let dispatcher = crate::AuthorizationControlDispatcher::new(Arc::clone(&store));
        let mut invalid = management_request(
            "authorizations.enroll",
            "invalid-id",
            0,
            json!({"ingress_id":"ingress-a", "egress_id":"wrong", "public_key":"secret-key-value", "administrator_labels":{"note":"secret-label-value"}}),
        );
        let response = dispatcher.dispatch(invalid.clone()).await;
        assert_eq!(
            response.error.as_ref().unwrap().code,
            ErrorCode::ValidationFailed
        );
        let (fingerprint, stored): (String, String) = store.connection.lock().unwrap().query_row(
            "SELECT fingerprint, response_json FROM authorization_failed_requests WHERE request_id = 'invalid-id'", [], |row| Ok((row.get(0)?, row.get(1)?)),
        ).unwrap();
        assert!(fingerprint.starts_with("sha256:"));
        assert!(!fingerprint.contains("secret"));
        assert!(!stored.contains("secret"));
        invalid.body = json!({"ingress_id":"ingress-a", "egress_id":"egress-a", "public_key": URL_SAFE_NO_PAD.encode([7; 32])});
        assert_eq!(
            dispatcher.dispatch(invalid).await.error.unwrap().code,
            ErrorCode::IdempotencyConflict
        );

        let mut denied = management_request(
            "authorizations.enroll",
            "auth-retry",
            0,
            json!({"ingress_id":"ingress-b", "egress_id":"egress-a", "public_key": URL_SAFE_NO_PAD.encode([8; 32])}),
        );
        denied.actor.capabilities.clear();
        assert_eq!(
            dispatcher
                .dispatch(denied.clone())
                .await
                .error
                .unwrap()
                .code,
            ErrorCode::CapabilityDenied
        );
        denied.actor.capabilities.push("authorization:write".into());
        assert!(dispatcher.dispatch(denied).await.ok);
    }

    #[tokio::test]
    async fn cache_storage_failure_does_not_block_same_id_retry() {
        let store = Arc::new(
            AuthorizationStore::open_in_memory(EgressId::new("egress-a"), [9; 32]).unwrap(),
        );
        let dispatcher = crate::AuthorizationControlDispatcher::new(Arc::clone(&store));
        let enrollment = management_request(
            "authorizations.enroll",
            "storage-retry",
            0,
            json!({"ingress_id":"ingress-a", "egress_id":"egress-a", "public_key": URL_SAFE_NO_PAD.encode([7; 32])}),
        );
        store
            .connection
            .lock()
            .unwrap()
            .execute_batch("DROP TABLE authorization_failed_requests")
            .unwrap();
        assert_eq!(
            dispatcher
                .dispatch(enrollment.clone())
                .await
                .error
                .unwrap()
                .code,
            ErrorCode::PersistenceUnavailable
        );
        store
            .connection
            .lock()
            .unwrap()
            .execute_batch(SCHEMA)
            .unwrap();
        assert!(dispatcher.dispatch(enrollment).await.ok);
    }

    #[test]
    fn failure_retention_requires_time_and_superseded_generation() {
        let store = AuthorizationStore::open_in_memory(EgressId::new("egress-a"), [9; 32]).unwrap();
        let response = pathchord_core::management::ResponseEnvelope::failure(
            "failure",
            GenerationExpectation {
                scope: "authorization".into(),
                value: 0,
            },
            pathchord_core::management::ErrorBody {
                code: ErrorCode::NotFound,
                message: "missing".into(),
                details: None,
            },
        );
        store
            .remember_failed_request("actor", "failure", "sha256:one", &response)
            .unwrap();
        store
            .connection
            .lock()
            .unwrap()
            .execute(
                "UPDATE authorization_failed_requests SET created_at_ms = 1",
                [],
            )
            .unwrap();
        assert_eq!(
            store
                .replay_failed_request("actor", "failure", "sha256:one")
                .unwrap(),
            Some(response)
        );
        let enrollment = AuthorizationMutationRequest {
            actor_id: "other".into(),
            request_id: "advance".into(),
            expected_generation: 0,
            ingress_id: IngressId::new("ingress-a"),
            mutation: AuthorizationMutation::Enroll {
                public_key: [7; 32],
                administrator_labels: BTreeMap::new(),
            },
        };
        store.mutate(enrollment).unwrap();
        assert_eq!(
            store
                .replay_failed_request("actor", "failure", "sha256:one")
                .unwrap(),
            None
        );
    }

    #[test]
    fn failure_cache_is_bounded_and_expired_records_are_reclaimed() {
        let store = AuthorizationStore::open_in_memory(EgressId::new("egress-a"), [9; 32]).unwrap();
        let response = pathchord_core::management::ResponseEnvelope::failure(
            "failure",
            GenerationExpectation {
                scope: "authorization".into(),
                value: 0,
            },
            pathchord_core::management::ErrorBody {
                code: ErrorCode::NotFound,
                message: "missing".into(),
                details: None,
            },
        );
        {
            let mut connection = store.connection.lock().unwrap();
            let transaction = connection.transaction().unwrap();
            for index in 0..MAX_FAILED_REQUESTS {
                transaction.execute("INSERT INTO authorization_failed_requests(actor_id, request_id, fingerprint, response_json, owner_generation, created_at_ms) VALUES ('actor', ?1, 'sha256:x', '{}', 0, 1)", [index.to_string()]).unwrap();
            }
            transaction.commit().unwrap();
        }
        assert!(matches!(
            store.remember_failed_request("other", "failure", "sha256:y", &response),
            Err(AuthorizationStoreError::ResourceLimit)
        ));
        store
            .mutate(AuthorizationMutationRequest {
                actor_id: "other".into(),
                request_id: "advance".into(),
                expected_generation: 0,
                ingress_id: IngressId::new("ingress-a"),
                mutation: AuthorizationMutation::Enroll {
                    public_key: [7; 32],
                    administrator_labels: BTreeMap::new(),
                },
            })
            .unwrap();
        assert!(
            store
                .remember_failed_request("other", "failure", "sha256:y", &response)
                .is_ok()
        );
        let count: i64 = store
            .connection
            .lock()
            .unwrap()
            .query_row(
                "SELECT COUNT(*) FROM authorization_failed_requests",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn success_and_failure_records_cannot_share_a_request_identity() {
        let store = AuthorizationStore::open_in_memory(EgressId::new("egress-a"), [9; 32]).unwrap();
        let response = pathchord_core::management::ResponseEnvelope::failure(
            "failed-first",
            GenerationExpectation {
                scope: "authorization".into(),
                value: 0,
            },
            pathchord_core::management::ErrorBody {
                code: ErrorCode::NotFound,
                message: "missing".into(),
                details: None,
            },
        );
        store
            .remember_failed_request("local-admin", "failed-first", "sha256:test", &response)
            .unwrap();
        let enrollment = request(
            "failed-first",
            0,
            AuthorizationMutation::Enroll {
                public_key: [7; 32],
                administrator_labels: BTreeMap::new(),
            },
        );
        assert!(matches!(
            store.mutate(enrollment),
            Err(AuthorizationStoreError::IdempotencyConflict)
        ));
        store
            .mutate(request(
                "success-first",
                0,
                AuthorizationMutation::Enroll {
                    public_key: [7; 32],
                    administrator_labels: BTreeMap::new(),
                },
            ))
            .unwrap();
        assert!(matches!(
            store.remember_failed_request("local-admin", "success-first", "sha256:test", &response),
            Err(AuthorizationStoreError::IdempotencyConflict)
        ));
    }

    fn request(
        request_id: &str,
        expected_generation: u64,
        mutation: AuthorizationMutation,
    ) -> AuthorizationMutationRequest {
        AuthorizationMutationRequest {
            actor_id: "local-admin".into(),
            request_id: request_id.into(),
            expected_generation,
            ingress_id: IngressId::new("ingress-a"),
            mutation,
        }
    }

    #[test]
    fn transactions_publish_snapshots_and_replay_idempotently() {
        let store =
            AuthorizationStore::open_in_memory(EgressId::new("egress-a"), [9; 32]).expect("store");
        let enroll = request(
            "request-1",
            0,
            AuthorizationMutation::Enroll {
                public_key: [7; 32],
                administrator_labels: BTreeMap::from([("team".into(), "network".into())]),
            },
        );
        let applied = store.mutate(enroll.clone()).expect("enroll");
        assert_eq!(applied.applied_generation, 1);
        assert_eq!(applied.state, Some(AuthorizationState::Enabled));
        assert!(!applied.replayed);

        let replayed = store.mutate(enroll).expect("replay");
        assert!(replayed.replayed);
        assert_eq!(replayed.applied_generation, 1);

        let snapshot = store.snapshot().expect("snapshot");
        assert_eq!(snapshot.generation(), 1);
        assert_eq!(snapshot.records().count(), 1);
        assert_eq!(
            snapshot.authorize(&IngressId::new("ingress-a"), &[7; 32]),
            crate::AuthorizationDecision::Authorized { generation: 1 }
        );
    }

    #[test]
    fn legacy_success_fingerprint_is_hashed_and_still_replays() {
        let store = AuthorizationStore::open_in_memory(EgressId::new("egress-a"), [9; 32]).unwrap();
        let enrollment = request(
            "legacy",
            0,
            AuthorizationMutation::Enroll {
                public_key: [7; 32],
                administrator_labels: BTreeMap::from([(
                    "admin.note".into(),
                    "private-label".into(),
                )]),
            },
        );
        store.mutate(enrollment.clone()).unwrap();
        {
            let connection = store.connection.lock().unwrap();
            let legacy = format!(
                "{}:enroll:{}:{}",
                enrollment.ingress_id.as_str(),
                encode_key(&[7; 32]),
                serde_json::to_string(&BTreeMap::from([("admin.note", "private-label")])).unwrap()
            );
            connection.execute("UPDATE authorization_requests SET fingerprint = ?1 WHERE request_id = 'legacy'", [legacy]).unwrap();
            migrate_request_fingerprints(&connection).unwrap();
            let stored: String = connection
                .query_row(
                    "SELECT fingerprint FROM authorization_requests WHERE request_id = 'legacy'",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert!(stored.starts_with("sha256:"));
            assert!(!stored.contains("private-label"));
        }
        assert!(store.mutate(enrollment).unwrap().replayed);
    }

    #[test]
    fn audit_uses_trusted_transport_source_instead_of_actor_name() {
        let store = AuthorizationStore::open_in_memory(EgressId::new("egress-a"), [9; 32]).unwrap();
        let mut enrollment = request(
            "source-test",
            0,
            AuthorizationMutation::Enroll {
                public_key: [7; 32],
                administrator_labels: BTreeMap::new(),
            },
        );
        enrollment.actor_id = "operator".into();
        store.mutate_from(enrollment, "web").unwrap();
        let source: String = store
            .connection
            .lock()
            .unwrap()
            .query_row(
                "SELECT source FROM authorization_audit WHERE request_id = 'source-test'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(source, "web");
    }

    #[test]
    fn generation_conflicts_and_request_reuse_do_not_publish() {
        let store =
            AuthorizationStore::open_in_memory(EgressId::new("egress-a"), [9; 32]).expect("store");
        let enroll = request(
            "request-1",
            0,
            AuthorizationMutation::Enroll {
                public_key: [7; 32],
                administrator_labels: BTreeMap::new(),
            },
        );
        store.mutate(enroll.clone()).expect("enroll");
        assert!(matches!(
            store.mutate(request("request-2", 0, AuthorizationMutation::Disable)),
            Err(AuthorizationStoreError::GenerationConflict { current: 1, .. })
        ));
        let mut conflict = enroll;
        conflict.mutation = AuthorizationMutation::Delete;
        assert!(matches!(
            store.mutate(conflict),
            Err(AuthorizationStoreError::IdempotencyConflict)
        ));
        assert_eq!(store.snapshot().expect("snapshot").generation(), 1);
    }

    #[test]
    fn revoked_records_cannot_be_reenabled_or_reenrolled() {
        let store =
            AuthorizationStore::open_in_memory(EgressId::new("egress-a"), [9; 32]).expect("store");
        store
            .mutate(request(
                "request-1",
                0,
                AuthorizationMutation::Enroll {
                    public_key: [7; 32],
                    administrator_labels: BTreeMap::new(),
                },
            ))
            .expect("enroll");
        store
            .mutate(request("request-2", 1, AuthorizationMutation::Revoke))
            .expect("revoke");
        assert!(matches!(
            store.mutate(request("request-3", 2, AuthorizationMutation::Enable)),
            Err(AuthorizationStoreError::RevokedIsTerminal)
        ));
        assert_eq!(
            store
                .snapshot()
                .expect("snapshot")
                .authorize(&IngressId::new("ingress-a"), &[7; 32]),
            crate::AuthorizationDecision::Denied(crate::DenialReason::Revoked)
        );
    }

    #[test]
    fn cleanup_result_is_persisted_with_the_idempotent_mutation() {
        let store =
            AuthorizationStore::open_in_memory(EgressId::new("egress-a"), [9; 32]).expect("store");
        store
            .mutate(request(
                "request-1",
                0,
                AuthorizationMutation::Enroll {
                    public_key: [7; 32],
                    administrator_labels: BTreeMap::new(),
                },
            ))
            .expect("enroll");
        let disable = request("request-2", 1, AuthorizationMutation::Disable);
        let applied = store.mutate(disable.clone()).expect("disable");
        assert!(!applied.cleanup_complete);
        let cleanup = AuthorizationCleanup {
            paths: 1,
            sessions: 1,
            streams: 2,
            target_connections: 2,
        };
        store
            .record_cleanup("local-admin", "request-2", cleanup)
            .expect("record cleanup");
        let replay = store.mutate(disable).expect("replay disable");
        assert!(replay.replayed);
        assert!(replay.cleanup_complete);
        assert_eq!(replay.cleanup, cleanup);
    }

    #[test]
    fn reopening_with_another_identity_fails_closed() {
        let path = std::env::temp_dir().join(format!(
            "pathchord-authorization-{}-{}.db",
            std::process::id(),
            now_ms().expect("clock")
        ));
        let store =
            AuthorizationStore::open(&path, EgressId::new("egress-a"), [9; 32]).expect("store");
        drop(store);
        assert!(matches!(
            AuthorizationStore::open(&path, EgressId::new("egress-b"), [9; 32]),
            Err(AuthorizationStoreError::IdentityMismatch)
        ));
        std::fs::remove_file(path).expect("remove database");
    }
}
