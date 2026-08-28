//! Non-secret persona metadata and append-only key lifecycle history.
//!
//! This store never accepts private keys or wallet credentials.

use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use a_quo_core::public_key_fingerprint;
use rusqlite::{Connection, OptionalExtension, Transaction, params};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

const SCHEMA_VERSION: i64 = 1;
const MAX_LABEL_BYTES: usize = 256;
const MAX_NOTE_BYTES: usize = 2_048;
const MAX_POLICY_BYTES: usize = 512;
const MAX_ACTOR_BYTES: usize = 256;

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("database error: {0}")]
    Database(#[from] rusqlite::Error),

    #[error("cannot access {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("refusing symbolic-link database path: {0}")]
    SymlinkDatabase(PathBuf),

    #[error("database parent is not a directory: {0}")]
    InvalidParent(PathBuf),

    #[error("database directory permissions are too broad; require mode 0700 or stricter: {0}")]
    InsecureDirectory(PathBuf),

    #[error("database schema version {0} is newer than this A Quo build supports")]
    UnsupportedSchema(i64),

    #[error("invalid {field}: {reason}")]
    InvalidField { field: &'static str, reason: String },

    #[error("persona not found: {0}")]
    PersonaNotFound(String),

    #[error("persona is archived: {0}")]
    PersonaArchived(String),

    #[error("key is already registered: {0}")]
    KeyAlreadyKnown(String),

    #[error("key not found: {0}")]
    KeyNotFound(String),

    #[error("persona has no active key to rotate: {0}")]
    NoActiveKey(String),

    #[error("invalid key lifecycle transition: {0}")]
    InvalidTransition(String),

    #[error("invalid OpenSSH public key: {0}")]
    InvalidPublicKey(String),

    #[error("system clock is before the Unix epoch")]
    InvalidSystemTime,
}

pub type Result<T> = std::result::Result<T, StoreError>;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum PersonaPurpose {
    Personal,
    Pseudonymous,
    Project,
    Organization,
    LegalBridge,
}

impl PersonaPurpose {
    pub const VALUES: &str = "personal, pseudonymous, project, organization, legal-bridge";

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Personal => "personal",
            Self::Pseudonymous => "pseudonymous",
            Self::Project => "project",
            Self::Organization => "organization",
            Self::LegalBridge => "legal-bridge",
        }
    }
}

impl fmt::Display for PersonaPurpose {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for PersonaPurpose {
    type Err = StoreError;

    fn from_str(value: &str) -> Result<Self> {
        match value {
            "personal" => Ok(Self::Personal),
            "pseudonymous" => Ok(Self::Pseudonymous),
            "project" => Ok(Self::Project),
            "organization" => Ok(Self::Organization),
            "legal-bridge" => Ok(Self::LegalBridge),
            _ => Err(StoreError::InvalidField {
                field: "persona purpose",
                reason: format!("expected one of {}", Self::VALUES),
            }),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum KeyProvider {
    OpensshFile,
    SshAgent,
    Fido2,
}

impl KeyProvider {
    pub const VALUES: &str = "openssh-file, ssh-agent, fido2";

    pub fn as_str(self) -> &'static str {
        match self {
            Self::OpensshFile => "openssh-file",
            Self::SshAgent => "ssh-agent",
            Self::Fido2 => "fido2",
        }
    }
}

impl fmt::Display for KeyProvider {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for KeyProvider {
    type Err = StoreError;

    fn from_str(value: &str) -> Result<Self> {
        match value {
            "openssh-file" => Ok(Self::OpensshFile),
            "ssh-agent" => Ok(Self::SshAgent),
            "fido2" => Ok(Self::Fido2),
            _ => Err(StoreError::InvalidField {
                field: "key provider",
                reason: format!("expected one of {}", Self::VALUES),
            }),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyStatus {
    Active,
    Retired,
    Compromised,
}

impl KeyStatus {
    fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Retired => "retired",
            Self::Compromised => "compromised",
        }
    }
}

impl FromStr for KeyStatus {
    type Err = StoreError;

    fn from_str(value: &str) -> Result<Self> {
        match value {
            "active" => Ok(Self::Active),
            "retired" => Ok(Self::Retired),
            "compromised" => Ok(Self::Compromised),
            _ => Err(StoreError::InvalidField {
                field: "stored key status",
                reason: value.to_owned(),
            }),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RotationReason {
    Routine,
    Recovery,
    Compromise,
}

impl RotationReason {
    pub const VALUES: &str = "routine, recovery, compromise";

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Routine => "routine",
            Self::Recovery => "recovery",
            Self::Compromise => "compromise",
        }
    }
}

impl FromStr for RotationReason {
    type Err = StoreError;

    fn from_str(value: &str) -> Result<Self> {
        match value {
            "routine" => Ok(Self::Routine),
            "recovery" => Ok(Self::Recovery),
            "compromise" => Ok(Self::Compromise),
            _ => Err(StoreError::InvalidField {
                field: "rotation reason",
                reason: format!("expected one of {}", Self::VALUES),
            }),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Persona {
    pub id: String,
    pub label: String,
    pub purpose: PersonaPurpose,
    pub created_at: i64,
    pub archived_at: Option<i64>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct KeyRecord {
    pub fingerprint: String,
    pub persona_id: String,
    pub public_key: String,
    pub provider: KeyProvider,
    pub status: KeyStatus,
    pub added_at: i64,
    pub retired_at: Option<i64>,
    pub compromised_at: Option<i64>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct KeyEvent {
    pub sequence: i64,
    pub persona_id: String,
    pub key_fingerprint: String,
    pub event_type: String,
    pub occurred_at: i64,
    pub actor: String,
    pub policy: String,
    pub note: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RecognizedKey {
    pub persona: Persona,
    pub key: KeyRecord,
}

pub struct PersonaStore {
    connection: Connection,
}

impl PersonaStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        prepare_database_path(path)?;
        let connection = Connection::open(path)?;
        secure_database_file(path)?;
        Self::initialize(connection)
    }

    pub fn open_in_memory() -> Result<Self> {
        Self::initialize(Connection::open_in_memory()?)
    }

    fn initialize(mut connection: Connection) -> Result<Self> {
        connection.busy_timeout(Duration::from_secs(5))?;
        connection.execute_batch(
            "PRAGMA foreign_keys = ON;
             PRAGMA trusted_schema = OFF;
             PRAGMA synchronous = FULL;",
        )?;

        let version: i64 = connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
        match version {
            0 => migrate_v1(&mut connection)?,
            SCHEMA_VERSION => {}
            newer if newer > SCHEMA_VERSION => {
                return Err(StoreError::UnsupportedSchema(newer));
            }
            older => return Err(StoreError::UnsupportedSchema(older)),
        }

        Ok(Self { connection })
    }

    pub fn create_persona(&mut self, label: &str, purpose: PersonaPurpose) -> Result<Persona> {
        let label = validate_required_text("persona label", label, MAX_LABEL_BYTES)?;
        let persona = Persona {
            id: Uuid::new_v4().to_string(),
            label,
            purpose,
            created_at: now_unix_seconds()?,
            archived_at: None,
        };
        self.connection.execute(
            "INSERT INTO personas (id, label, purpose, created_at)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                persona.id,
                persona.label,
                persona.purpose.as_str(),
                persona.created_at
            ],
        )?;
        Ok(persona)
    }

    pub fn list_personas(&self) -> Result<Vec<Persona>> {
        let mut statement = self.connection.prepare(
            "SELECT id, label, purpose, created_at, archived_at
             FROM personas ORDER BY created_at, id",
        )?;
        let rows = statement.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, Option<i64>>(4)?,
            ))
        })?;

        rows.map(|row| persona_from_row(row?)).collect()
    }

    pub fn enroll_key(
        &mut self,
        persona_id: &str,
        public_key: &str,
        provider: KeyProvider,
    ) -> Result<KeyRecord> {
        let now = now_unix_seconds()?;
        let public_key = public_key.trim().to_owned();
        validate_provider_key(&public_key, provider)?;
        let fingerprint = fingerprint(&public_key)?;
        let transaction = self.connection.transaction()?;
        require_active_persona(&transaction, persona_id)?;
        require_unknown_key(&transaction, &fingerprint)?;

        insert_key(
            &transaction,
            persona_id,
            &fingerprint,
            &public_key,
            provider,
            now,
        )?;
        append_event(
            &transaction,
            persona_id,
            &fingerprint,
            "enrolled",
            now,
            "local-user",
            "a-quo:key-enrollment:v1",
            None,
        )?;
        transaction.commit()?;

        Ok(KeyRecord {
            fingerprint,
            persona_id: persona_id.to_owned(),
            public_key,
            provider,
            status: KeyStatus::Active,
            added_at: now,
            retired_at: None,
            compromised_at: None,
        })
    }

    pub fn rotate_key(
        &mut self,
        persona_id: &str,
        public_key: &str,
        provider: KeyProvider,
        reason: RotationReason,
        note: Option<&str>,
    ) -> Result<KeyRecord> {
        let now = now_unix_seconds()?;
        let public_key = public_key.trim().to_owned();
        validate_provider_key(&public_key, provider)?;
        let fingerprint = fingerprint(&public_key)?;
        let note = validate_optional_text("rotation note", note, MAX_NOTE_BYTES)?;
        let transaction = self.connection.transaction()?;
        require_active_persona(&transaction, persona_id)?;
        require_unknown_key(&transaction, &fingerprint)?;

        let active_keys = active_key_fingerprints(&transaction, persona_id)?;
        if active_keys.is_empty() {
            return Err(StoreError::NoActiveKey(persona_id.to_owned()));
        }

        let old_status = if reason == RotationReason::Compromise {
            KeyStatus::Compromised
        } else {
            KeyStatus::Retired
        };
        for old_fingerprint in &active_keys {
            transition_key(&transaction, old_fingerprint, old_status, now)?;
            append_event(
                &transaction,
                persona_id,
                old_fingerprint,
                old_status.as_str(),
                now,
                "local-user",
                rotation_policy(reason),
                note.as_deref(),
            )?;
        }

        insert_key(
            &transaction,
            persona_id,
            &fingerprint,
            &public_key,
            provider,
            now,
        )?;
        append_event(
            &transaction,
            persona_id,
            &fingerprint,
            "rotated_in",
            now,
            "local-user",
            rotation_policy(reason),
            note.as_deref(),
        )?;
        transaction.commit()?;

        Ok(KeyRecord {
            fingerprint,
            persona_id: persona_id.to_owned(),
            public_key,
            provider,
            status: KeyStatus::Active,
            added_at: now,
            retired_at: None,
            compromised_at: None,
        })
    }

    pub fn mark_key_compromised(
        &mut self,
        fingerprint: &str,
        actor: &str,
        policy: &str,
        note: Option<&str>,
    ) -> Result<()> {
        let actor = validate_required_text("revocation actor", actor, MAX_ACTOR_BYTES)?;
        let policy = validate_required_text("revocation policy", policy, MAX_POLICY_BYTES)?;
        let note = validate_optional_text("revocation note", note, MAX_NOTE_BYTES)?;
        let now = now_unix_seconds()?;
        let transaction = self.connection.transaction()?;
        let key = lookup_key_in(&transaction, fingerprint)?
            .ok_or_else(|| StoreError::KeyNotFound(fingerprint.to_owned()))?;
        if key.key.status == KeyStatus::Compromised {
            return Err(StoreError::InvalidTransition(format!(
                "key {fingerprint} is already compromised"
            )));
        }

        transition_key(&transaction, fingerprint, KeyStatus::Compromised, now)?;
        append_event(
            &transaction,
            &key.persona.id,
            fingerprint,
            "compromised",
            now,
            &actor,
            &policy,
            note.as_deref(),
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub fn list_keys(&self, persona_id: &str) -> Result<Vec<KeyRecord>> {
        let mut statement = self.connection.prepare(
            "SELECT fingerprint, persona_id, public_key, provider, status,
                    added_at, retired_at, compromised_at
             FROM key_records WHERE persona_id = ?1 ORDER BY added_at, fingerprint",
        )?;
        let rows = statement.query_map([persona_id], raw_key_row)?;
        rows.map(|row| key_from_row(row?)).collect()
    }

    pub fn key_history(&self, persona_id: &str) -> Result<Vec<KeyEvent>> {
        let mut statement = self.connection.prepare(
            "SELECT sequence, persona_id, key_fingerprint, event_type,
                    occurred_at, actor, policy, note
             FROM key_events WHERE persona_id = ?1 ORDER BY sequence",
        )?;
        let rows = statement.query_map([persona_id], |row| {
            Ok(KeyEvent {
                sequence: row.get(0)?,
                persona_id: row.get(1)?,
                key_fingerprint: row.get(2)?,
                event_type: row.get(3)?,
                occurred_at: row.get(4)?,
                actor: row.get(5)?,
                policy: row.get(6)?,
                note: row.get(7)?,
            })
        })?;
        rows.map(|row| row.map_err(StoreError::from)).collect()
    }

    pub fn lookup_key(&self, fingerprint: &str) -> Result<Option<RecognizedKey>> {
        lookup_key_in(&self.connection, fingerprint)
    }
}

type RawKeyRow = (
    String,
    String,
    String,
    String,
    String,
    i64,
    Option<i64>,
    Option<i64>,
);

fn migrate_v1(connection: &mut Connection) -> Result<()> {
    let transaction = connection.transaction()?;
    transaction.execute_batch(
        "CREATE TABLE personas (
             id TEXT PRIMARY KEY NOT NULL,
             label TEXT NOT NULL CHECK(length(label) BETWEEN 1 AND 256),
             purpose TEXT NOT NULL CHECK(purpose IN
                 ('personal', 'pseudonymous', 'project', 'organization', 'legal-bridge')),
             created_at INTEGER NOT NULL CHECK(created_at >= 0),
             archived_at INTEGER
         ) STRICT;

         CREATE TABLE key_records (
             fingerprint TEXT PRIMARY KEY NOT NULL,
             persona_id TEXT NOT NULL REFERENCES personas(id),
             public_key TEXT NOT NULL CHECK(length(public_key) BETWEEN 1 AND 16384),
             provider TEXT NOT NULL CHECK(
                 provider IN ('openssh-file', 'ssh-agent', 'fido2') AND
                 (provider != 'fido2' OR public_key GLOB 'sk-*')
             ),
             status TEXT NOT NULL CHECK(status IN ('active', 'retired', 'compromised')),
             added_at INTEGER NOT NULL CHECK(added_at >= 0),
             retired_at INTEGER,
             compromised_at INTEGER
         ) STRICT;

         CREATE INDEX key_records_persona_idx
             ON key_records(persona_id, status);

         CREATE TABLE key_events (
             sequence INTEGER PRIMARY KEY AUTOINCREMENT,
             persona_id TEXT NOT NULL REFERENCES personas(id),
             key_fingerprint TEXT NOT NULL REFERENCES key_records(fingerprint),
             event_type TEXT NOT NULL CHECK(event_type IN
                 ('enrolled', 'rotated_in', 'retired', 'compromised')),
             occurred_at INTEGER NOT NULL CHECK(occurred_at >= 0),
             actor TEXT NOT NULL CHECK(length(actor) BETWEEN 1 AND 256),
             policy TEXT NOT NULL CHECK(length(policy) BETWEEN 1 AND 512),
             note TEXT CHECK(note IS NULL OR length(note) <= 2048)
         ) STRICT;

         CREATE TRIGGER key_events_no_update
         BEFORE UPDATE ON key_events BEGIN
             SELECT RAISE(ABORT, 'key lifecycle events are append-only');
         END;

         CREATE TRIGGER key_events_no_delete
         BEFORE DELETE ON key_events BEGIN
             SELECT RAISE(ABORT, 'key lifecycle events are append-only');
         END;

         PRAGMA user_version = 1;",
    )?;
    transaction.commit()?;
    Ok(())
}

fn insert_key(
    transaction: &Transaction<'_>,
    persona_id: &str,
    fingerprint: &str,
    public_key: &str,
    provider: KeyProvider,
    now: i64,
) -> Result<()> {
    transaction.execute(
        "INSERT INTO key_records
         (fingerprint, persona_id, public_key, provider, status, added_at)
         VALUES (?1, ?2, ?3, ?4, 'active', ?5)",
        params![fingerprint, persona_id, public_key, provider.as_str(), now],
    )?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn append_event(
    transaction: &Transaction<'_>,
    persona_id: &str,
    fingerprint: &str,
    event_type: &str,
    occurred_at: i64,
    actor: &str,
    policy: &str,
    note: Option<&str>,
) -> Result<()> {
    transaction.execute(
        "INSERT INTO key_events
         (persona_id, key_fingerprint, event_type, occurred_at, actor, policy, note)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            persona_id,
            fingerprint,
            event_type,
            occurred_at,
            actor,
            policy,
            note
        ],
    )?;
    Ok(())
}

fn transition_key(
    transaction: &Transaction<'_>,
    fingerprint: &str,
    status: KeyStatus,
    now: i64,
) -> Result<()> {
    let (retired_at, compromised_at) = match status {
        KeyStatus::Retired => (Some(now), None),
        KeyStatus::Compromised => (None, Some(now)),
        KeyStatus::Active => {
            return Err(StoreError::InvalidTransition(
                "cannot transition an existing key back to active".to_owned(),
            ));
        }
    };
    let updated = transaction.execute(
        "UPDATE key_records
         SET status = ?1, retired_at = COALESCE(?2, retired_at),
             compromised_at = COALESCE(?3, compromised_at)
         WHERE fingerprint = ?4 AND status != 'compromised'",
        params![status.as_str(), retired_at, compromised_at, fingerprint],
    )?;
    if updated != 1 {
        return Err(StoreError::InvalidTransition(format!(
            "cannot transition key {fingerprint} to {}",
            status.as_str()
        )));
    }
    Ok(())
}

fn active_key_fingerprints(transaction: &Transaction<'_>, persona_id: &str) -> Result<Vec<String>> {
    let mut statement = transaction.prepare(
        "SELECT fingerprint FROM key_records
         WHERE persona_id = ?1 AND status = 'active' ORDER BY fingerprint",
    )?;
    let rows = statement.query_map([persona_id], |row| row.get(0))?;
    rows.map(|row| row.map_err(StoreError::from)).collect()
}

fn require_active_persona(connection: &Connection, persona_id: &str) -> Result<()> {
    let archived_at: Option<Option<i64>> = connection
        .query_row(
            "SELECT archived_at FROM personas WHERE id = ?1",
            [persona_id],
            |row| row.get(0),
        )
        .optional()?;
    match archived_at {
        None => Err(StoreError::PersonaNotFound(persona_id.to_owned())),
        Some(Some(_)) => Err(StoreError::PersonaArchived(persona_id.to_owned())),
        Some(None) => Ok(()),
    }
}

fn require_unknown_key(connection: &Connection, fingerprint: &str) -> Result<()> {
    let exists: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM key_records WHERE fingerprint = ?1)",
        [fingerprint],
        |row| row.get(0),
    )?;
    if exists {
        Err(StoreError::KeyAlreadyKnown(fingerprint.to_owned()))
    } else {
        Ok(())
    }
}

fn lookup_key_in(connection: &Connection, fingerprint: &str) -> Result<Option<RecognizedKey>> {
    let raw = connection
        .query_row(
            "SELECT p.id, p.label, p.purpose, p.created_at, p.archived_at,
                    k.fingerprint, k.persona_id, k.public_key, k.provider,
                    k.status, k.added_at, k.retired_at, k.compromised_at
             FROM key_records k JOIN personas p ON p.id = k.persona_id
             WHERE k.fingerprint = ?1",
            [fingerprint],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, Option<i64>>(4)?,
                    (
                        row.get::<_, String>(5)?,
                        row.get::<_, String>(6)?,
                        row.get::<_, String>(7)?,
                        row.get::<_, String>(8)?,
                        row.get::<_, String>(9)?,
                        row.get::<_, i64>(10)?,
                        row.get::<_, Option<i64>>(11)?,
                        row.get::<_, Option<i64>>(12)?,
                    ),
                ))
            },
        )
        .optional()?;

    raw.map(|(id, label, purpose, created_at, archived_at, key)| {
        Ok(RecognizedKey {
            persona: Persona {
                id,
                label,
                purpose: purpose.parse()?,
                created_at,
                archived_at,
            },
            key: key_from_row(key)?,
        })
    })
    .transpose()
}

fn raw_key_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<RawKeyRow> {
    Ok((
        row.get(0)?,
        row.get(1)?,
        row.get(2)?,
        row.get(3)?,
        row.get(4)?,
        row.get(5)?,
        row.get(6)?,
        row.get(7)?,
    ))
}

fn key_from_row(row: RawKeyRow) -> Result<KeyRecord> {
    Ok(KeyRecord {
        fingerprint: row.0,
        persona_id: row.1,
        public_key: row.2,
        provider: row.3.parse()?,
        status: row.4.parse()?,
        added_at: row.5,
        retired_at: row.6,
        compromised_at: row.7,
    })
}

fn persona_from_row(row: (String, String, String, i64, Option<i64>)) -> Result<Persona> {
    Ok(Persona {
        id: row.0,
        label: row.1,
        purpose: row.2.parse()?,
        created_at: row.3,
        archived_at: row.4,
    })
}

fn rotation_policy(reason: RotationReason) -> &'static str {
    match reason {
        RotationReason::Routine => "a-quo:key-rotation:routine:v1",
        RotationReason::Recovery => "a-quo:key-rotation:recovery:v1",
        RotationReason::Compromise => "a-quo:key-rotation:compromise:v1",
    }
}

fn fingerprint(public_key: &str) -> Result<String> {
    public_key_fingerprint(public_key)
        .map_err(|error| StoreError::InvalidPublicKey(error.to_string()))
}

fn validate_provider_key(public_key: &str, provider: KeyProvider) -> Result<()> {
    if provider != KeyProvider::Fido2 {
        return Ok(());
    }
    let algorithm = public_key.split_whitespace().next().unwrap_or_default();
    if matches!(
        algorithm,
        "sk-ssh-ed25519@openssh.com" | "sk-ecdsa-sha2-nistp256@openssh.com"
    ) {
        Ok(())
    } else {
        Err(StoreError::InvalidField {
            field: "key provider",
            reason: "fido2 requires an OpenSSH security-key public-key algorithm".to_owned(),
        })
    }
}

fn validate_required_text(field: &'static str, value: &str, maximum: usize) -> Result<String> {
    let value = value.trim();
    if value.is_empty() {
        return Err(StoreError::InvalidField {
            field,
            reason: "it cannot be empty".to_owned(),
        });
    }
    if value.len() > maximum {
        return Err(StoreError::InvalidField {
            field,
            reason: format!("it cannot exceed {maximum} UTF-8 bytes"),
        });
    }
    if value.chars().any(is_unsafe_display_character) {
        return Err(StoreError::InvalidField {
            field,
            reason: "control and bidirectional formatting characters are not allowed".to_owned(),
        });
    }
    Ok(value.to_owned())
}

fn is_unsafe_display_character(character: char) -> bool {
    character.is_control()
        || matches!(
            character,
            '\u{061c}'
                | '\u{200e}'
                | '\u{200f}'
                | '\u{202a}'..='\u{202e}'
                | '\u{2066}'..='\u{2069}'
        )
}

fn validate_optional_text(
    field: &'static str,
    value: Option<&str>,
    maximum: usize,
) -> Result<Option<String>> {
    value
        .map(|value| validate_required_text(field, value, maximum))
        .transpose()
}

fn now_unix_seconds() -> Result<i64> {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| StoreError::InvalidSystemTime)?
        .as_secs();
    i64::try_from(seconds).map_err(|_| StoreError::InvalidSystemTime)
}

fn prepare_database_path(path: &Path) -> Result<()> {
    if let Ok(metadata) = fs::symlink_metadata(path)
        && metadata.file_type().is_symlink()
    {
        return Err(StoreError::SymlinkDatabase(path.to_path_buf()));
    }

    let parent = path
        .parent()
        .ok_or_else(|| StoreError::InvalidParent(path.to_path_buf()))?;
    if !parent.exists() {
        fs::create_dir_all(parent).map_err(|source| StoreError::Io {
            path: parent.to_path_buf(),
            source,
        })?;
        secure_directory(parent)?;
    }
    if !parent.is_dir() {
        return Err(StoreError::InvalidParent(parent.to_path_buf()));
    }
    check_directory_permissions(parent)?;
    Ok(())
}

#[cfg(unix)]
fn secure_directory(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(|source| StoreError::Io {
        path: path.to_path_buf(),
        source,
    })
}

#[cfg(not(unix))]
fn secure_directory(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn check_directory_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let mode = fs::metadata(path)
        .map_err(|source| StoreError::Io {
            path: path.to_path_buf(),
            source,
        })?
        .permissions()
        .mode();
    if mode & 0o077 != 0 {
        Err(StoreError::InsecureDirectory(path.to_path_buf()))
    } else {
        Ok(())
    }
}

#[cfg(not(unix))]
fn check_directory_permissions(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn secure_database_file(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).map_err(|source| StoreError::Io {
        path: path.to_path_buf(),
        source,
    })
}

#[cfg(not(unix))]
fn secure_database_file(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY_ONE: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIK2wZ6f9bI6YlF1YyW5iU+a4jvfp9DCf3j6PYfnT1rYA";
    const KEY_TWO: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGfX7hAdqGfF0mYz2oD88dL84M2yr2KoXqhh7sSRvqHQ";

    #[test]
    fn keeps_rotation_and_compromise_history() {
        let mut store = PersonaStore::open_in_memory().unwrap();
        let persona = store
            .create_persona("Project publisher", PersonaPurpose::Project)
            .unwrap();
        let first = store
            .enroll_key(&persona.id, KEY_ONE, KeyProvider::OpensshFile)
            .unwrap();
        let second = store
            .rotate_key(
                &persona.id,
                KEY_TWO,
                KeyProvider::OpensshFile,
                RotationReason::Recovery,
                Some("replacement hardware enrolled"),
            )
            .unwrap();

        assert_eq!(
            store
                .lookup_key(&first.fingerprint)
                .unwrap()
                .unwrap()
                .key
                .status,
            KeyStatus::Retired
        );
        assert_eq!(
            store
                .lookup_key(&second.fingerprint)
                .unwrap()
                .unwrap()
                .key
                .status,
            KeyStatus::Active
        );

        store
            .mark_key_compromised(
                &second.fingerprint,
                "Project owner",
                "example.org/security/key-compromise-v1",
                None,
            )
            .unwrap();
        assert_eq!(
            store
                .lookup_key(&second.fingerprint)
                .unwrap()
                .unwrap()
                .key
                .status,
            KeyStatus::Compromised
        );

        let events = store.key_history(&persona.id).unwrap();
        assert_eq!(
            events
                .iter()
                .map(|event| event.event_type.as_str())
                .collect::<Vec<_>>(),
            ["enrolled", "retired", "rotated_in", "compromised"]
        );
    }

    #[test]
    fn rejects_duplicate_key_across_personas() {
        let mut store = PersonaStore::open_in_memory().unwrap();
        let first = store
            .create_persona("First", PersonaPurpose::Pseudonymous)
            .unwrap();
        let second = store
            .create_persona("Second", PersonaPurpose::Personal)
            .unwrap();
        store
            .enroll_key(&first.id, KEY_ONE, KeyProvider::SshAgent)
            .unwrap();

        let error = store
            .enroll_key(&second.id, KEY_ONE, KeyProvider::SshAgent)
            .unwrap_err();
        assert!(matches!(error, StoreError::KeyAlreadyKnown(_)));
    }

    #[test]
    fn rejects_ordinary_key_labeled_as_fido2() {
        let mut store = PersonaStore::open_in_memory().unwrap();
        let persona = store
            .create_persona("Hardware claim", PersonaPurpose::Project)
            .unwrap();

        let error = store
            .enroll_key(&persona.id, KEY_ONE, KeyProvider::Fido2)
            .unwrap_err();
        assert!(matches!(
            error,
            StoreError::InvalidField {
                field: "key provider",
                ..
            }
        ));
    }

    #[test]
    fn rejects_bidirectional_override_in_event_actor() {
        let mut store = PersonaStore::open_in_memory().unwrap();
        let persona = store
            .create_persona("Publisher", PersonaPurpose::Project)
            .unwrap();
        let key = store
            .enroll_key(&persona.id, KEY_ONE, KeyProvider::OpensshFile)
            .unwrap();

        let error = store
            .mark_key_compromised(
                &key.fingerprint,
                "trusted\u{202e}actor",
                "example.invalid/policy",
                None,
            )
            .unwrap_err();
        assert!(matches!(
            error,
            StoreError::InvalidField {
                field: "revocation actor",
                ..
            }
        ));
    }
}
