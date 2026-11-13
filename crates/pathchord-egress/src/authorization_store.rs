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
CREATE TABLE IF NOT EXISTS authorization_audit (
    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp_ms INTEGER NOT NULL,
    actor_id TEXT NOT NULL,
    operation TEXT NOT NULL,
    request_id TEXT NOT NULL,
    ingress_id TEXT NOT NULL,
    expected_generation INTEGER NOT NULL,
    applied_generation INTEGER NOT NULL,
    result TEXT NOT NULL
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
        Ok(format!("{}:{body}", ingress_id.as_str()))
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
        })
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
        validate_request(&request)?;
        let fingerprint = request.mutation.fingerprint(&request.ingress_id)?;
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| AuthorizationStoreError::Lock)?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;

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
            "INSERT INTO authorization_audit(timestamp_ms, actor_id, operation, request_id, ingress_id, expected_generation, applied_generation, result) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'applied')",
            params![
                to_sql_i64(now_ms()?, "timestamp_ms")?,
                request.actor_id,
                request.mutation.operation(),
                request.request_id,
                request.ingress_id.as_str(),
                to_sql_i64(request.expected_generation, "expected_generation")?,
                to_sql_i64(applied_generation, "generation")?,
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
            "INSERT INTO authorization_audit(timestamp_ms, actor_id, operation, request_id, ingress_id, expected_generation, applied_generation, result) VALUES (?1, 'unauthenticated', 'authentication.failure', '', ?2, ?3, ?3, 'denied')",
            params![to_sql_i64(now_ms()?, "timestamp_ms")?, source, generation],
        )?;
        Ok(())
    }
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
