//! Non-secret persona metadata and append-only key lifecycle history.
//!
//! This store never accepts private keys or wallet credentials.

use std::collections::{HashMap, HashSet};
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

const SCHEMA_VERSION: i64 = 2;
const MAX_LABEL_BYTES: usize = 256;
const MAX_NOTE_BYTES: usize = 2_048;
const MAX_POLICY_BYTES: usize = 512;
const MAX_ACTOR_BYTES: usize = 256;
const MAX_SIGNING_REFERENCE_BYTES: usize = 4_096;
const MAX_PUBLIC_KEY_BYTES: u64 = 16_384;
const MAX_PERSONA_BACKUP_KEYS: usize = 256;
const MAX_PERSONA_BACKUP_EVENTS: usize = 4_096;

pub const PERSONA_BACKUP_SCHEMA: &str = "urn:a-quo:persona-metadata-backup:v1";
pub const MAX_PERSONA_BACKUP_BYTES: u64 = 4 * 1024 * 1024;

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

    #[error("persona already exists: {0}")]
    PersonaAlreadyKnown(String),

    #[error("persona is archived: {0}")]
    PersonaArchived(String),

    #[error("key is already registered: {0}")]
    KeyAlreadyKnown(String),

    #[error("key not found: {0}")]
    KeyNotFound(String),

    #[error("key is not active and cannot be used for signing: {0}")]
    InactiveSigningKey(String),

    #[error("persona has multiple active keys and signer selection is ambiguous: {0}")]
    AmbiguousActiveKeys(String),

    #[error("key has no configured signing reference: {0}")]
    SigningReferenceNotFound(String),

    #[error("unsafe signing reference {path}: {reason}")]
    UnsafeSigningReference { path: PathBuf, reason: String },

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

/// Portable non-secret backup for one local persona. This is not signing or
/// recovery authority and deliberately excludes every signer reference.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PersonaBackup {
    pub schema: String,
    pub exported_at: i64,
    pub persona: BackupPersona,
    pub keys: Vec<BackupKey>,
    pub events: Vec<BackupKeyEvent>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BackupPersona {
    pub id: String,
    pub label: String,
    pub purpose: PersonaPurpose,
    pub created_at: i64,
    pub archived_at: Option<i64>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BackupKey {
    pub fingerprint: String,
    pub public_key: String,
    pub provider: KeyProvider,
    pub status: KeyStatus,
    pub added_at: i64,
    pub retired_at: Option<i64>,
    pub compromised_at: Option<i64>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BackupKeyEvent {
    pub ordinal: u32,
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SigningReference {
    pub key_fingerprint: String,
    pub locator: PathBuf,
    pub configured_at: i64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SigningReferenceEvent {
    pub sequence: i64,
    pub key_fingerprint: String,
    pub event_type: String,
    pub occurred_at: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActiveSigner {
    pub persona: Persona,
    pub key: KeyRecord,
    pub signing_reference: SigningReference,
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
            0 => {
                migrate_v1(&mut connection)?;
                migrate_v2(&mut connection)?;
            }
            1 => migrate_v2(&mut connection)?,
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
        list_keys_in(&self.connection, persona_id)
    }

    pub fn key_history(&self, persona_id: &str) -> Result<Vec<KeyEvent>> {
        key_history_in(&self.connection, persona_id)
    }

    /// Export one persona's non-secret metadata and lifecycle history.
    ///
    /// Signer references are deliberately excluded: this backup cannot grant
    /// signing or recovery authority on another installation.
    pub fn export_persona_backup(&mut self, persona_id: &str) -> Result<PersonaBackup> {
        let transaction = self.connection.transaction()?;
        let persona = transaction
            .query_row(
                "SELECT id, label, purpose, created_at, archived_at
                 FROM personas WHERE id = ?1",
                [persona_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, Option<i64>>(4)?,
                    ))
                },
            )
            .optional()?
            .ok_or_else(|| StoreError::PersonaNotFound(persona_id.to_owned()))
            .and_then(persona_from_row)?;
        let keys = list_keys_in(&transaction, persona_id)?;
        let events = key_history_in(&transaction, persona_id)?;
        if keys.len() > MAX_PERSONA_BACKUP_KEYS {
            return Err(invalid_backup(format!(
                "keys cannot contain more than {MAX_PERSONA_BACKUP_KEYS} entries"
            )));
        }
        if events.len() > MAX_PERSONA_BACKUP_EVENTS {
            return Err(invalid_backup(format!(
                "events cannot contain more than {MAX_PERSONA_BACKUP_EVENTS} entries"
            )));
        }
        let exported_at = now_unix_seconds()?;

        let backup = PersonaBackup {
            schema: PERSONA_BACKUP_SCHEMA.to_owned(),
            exported_at,
            persona: BackupPersona {
                id: persona.id,
                label: persona.label,
                purpose: persona.purpose,
                created_at: persona.created_at,
                archived_at: persona.archived_at,
            },
            keys: keys
                .into_iter()
                .map(|key| BackupKey {
                    fingerprint: key.fingerprint,
                    public_key: key.public_key,
                    provider: key.provider,
                    status: key.status,
                    added_at: key.added_at,
                    retired_at: key.retired_at,
                    compromised_at: key.compromised_at,
                })
                .collect(),
            events: events
                .into_iter()
                .enumerate()
                .map(|(index, event)| BackupKeyEvent {
                    ordinal: u32::try_from(index + 1)
                        .expect("backup event bound fits in a u32 ordinal"),
                    key_fingerprint: event.key_fingerprint,
                    event_type: event.event_type,
                    occurred_at: event.occurred_at,
                    actor: event.actor,
                    policy: event.policy,
                    note: event.note,
                })
                .collect(),
        };
        validate_persona_backup(&backup)?;
        transaction.commit()?;
        Ok(backup)
    }

    /// Restore a fully validated metadata backup in one transaction.
    ///
    /// Existing persona IDs and public-key fingerprints are never merged.
    /// Signer references remain absent and must be rebound explicitly.
    pub fn import_persona_backup(&mut self, backup: &PersonaBackup) -> Result<Persona> {
        validate_persona_backup(backup)?;
        let persona = Persona {
            id: backup.persona.id.clone(),
            label: backup.persona.label.clone(),
            purpose: backup.persona.purpose,
            created_at: backup.persona.created_at,
            archived_at: backup.persona.archived_at,
        };
        let transaction = self.connection.transaction()?;
        let persona_exists: bool = transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM personas WHERE id = ?1)",
            [&persona.id],
            |row| row.get(0),
        )?;
        if persona_exists {
            return Err(StoreError::PersonaAlreadyKnown(persona.id));
        }
        for key in &backup.keys {
            require_unknown_key(&transaction, &key.fingerprint)?;
        }

        transaction.execute(
            "INSERT INTO personas (id, label, purpose, created_at, archived_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                persona.id,
                persona.label,
                persona.purpose.as_str(),
                persona.created_at,
                persona.archived_at
            ],
        )?;
        for key in &backup.keys {
            transaction.execute(
                "INSERT INTO key_records
                 (fingerprint, persona_id, public_key, provider, status,
                  added_at, retired_at, compromised_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    key.fingerprint,
                    persona.id,
                    key.public_key,
                    key.provider.as_str(),
                    key.status.as_str(),
                    key.added_at,
                    key.retired_at,
                    key.compromised_at
                ],
            )?;
        }
        for event in &backup.events {
            append_event(
                &transaction,
                &persona.id,
                &event.key_fingerprint,
                &event.event_type,
                event.occurred_at,
                &event.actor,
                &event.policy,
                event.note.as_deref(),
            )?;
        }
        transaction.commit()?;
        Ok(persona)
    }

    pub fn lookup_key(&self, fingerprint: &str) -> Result<Option<RecognizedKey>> {
        lookup_key_in(&self.connection, fingerprint)
    }

    pub fn bind_signing_reference(
        &mut self,
        fingerprint: &str,
        locator: impl AsRef<Path>,
    ) -> Result<SigningReference> {
        let now = now_unix_seconds()?;
        let transaction = self.connection.transaction()?;
        let recognized = lookup_key_in(&transaction, fingerprint)?
            .ok_or_else(|| StoreError::KeyNotFound(fingerprint.to_owned()))?;
        require_active_persona(&transaction, &recognized.persona.id)?;
        if recognized.key.status != KeyStatus::Active {
            return Err(StoreError::InactiveSigningKey(fingerprint.to_owned()));
        }

        let locator = validate_signing_reference_path(locator.as_ref(), &recognized.key)?;
        let locator_text = locator
            .to_str()
            .expect("validated signing references are UTF-8");
        let existed: bool = transaction.query_row(
            "SELECT EXISTS(
                 SELECT 1 FROM signing_references WHERE key_fingerprint = ?1
             )",
            [fingerprint],
            |row| row.get(0),
        )?;
        transaction.execute(
            "INSERT INTO signing_references
             (key_fingerprint, locator, configured_at)
             VALUES (?1, ?2, ?3)
             ON CONFLICT(key_fingerprint) DO UPDATE SET
                 locator = excluded.locator,
                 configured_at = excluded.configured_at",
            params![fingerprint, locator_text, now],
        )?;
        append_signing_reference_event(
            &transaction,
            fingerprint,
            if existed { "rebound" } else { "bound" },
            now,
        )?;
        transaction.commit()?;

        Ok(SigningReference {
            key_fingerprint: fingerprint.to_owned(),
            locator,
            configured_at: now,
        })
    }

    pub fn unbind_signing_reference(&mut self, fingerprint: &str) -> Result<()> {
        let now = now_unix_seconds()?;
        let transaction = self.connection.transaction()?;
        if lookup_key_in(&transaction, fingerprint)?.is_none() {
            return Err(StoreError::KeyNotFound(fingerprint.to_owned()));
        }
        let deleted = transaction.execute(
            "DELETE FROM signing_references WHERE key_fingerprint = ?1",
            [fingerprint],
        )?;
        if deleted != 1 {
            return Err(StoreError::SigningReferenceNotFound(fingerprint.to_owned()));
        }
        append_signing_reference_event(&transaction, fingerprint, "unbound", now)?;
        transaction.commit()?;
        Ok(())
    }

    fn lookup_signing_reference(&self, fingerprint: &str) -> Result<Option<SigningReference>> {
        self.connection
            .query_row(
                "SELECT key_fingerprint, locator, configured_at
                 FROM signing_references WHERE key_fingerprint = ?1",
                [fingerprint],
                |row| {
                    Ok(SigningReference {
                        key_fingerprint: row.get(0)?,
                        locator: PathBuf::from(row.get::<_, String>(1)?),
                        configured_at: row.get(2)?,
                    })
                },
            )
            .optional()
            .map_err(StoreError::from)
    }

    pub fn signing_reference_history(
        &self,
        fingerprint: &str,
    ) -> Result<Vec<SigningReferenceEvent>> {
        let mut statement = self.connection.prepare(
            "SELECT sequence, key_fingerprint, event_type, occurred_at
             FROM signing_reference_events
             WHERE key_fingerprint = ?1 ORDER BY sequence",
        )?;
        let rows = statement.query_map([fingerprint], |row| {
            Ok(SigningReferenceEvent {
                sequence: row.get(0)?,
                key_fingerprint: row.get(1)?,
                event_type: row.get(2)?,
                occurred_at: row.get(3)?,
            })
        })?;
        rows.map(|row| row.map_err(StoreError::from)).collect()
    }

    pub fn active_signer_for_persona(&self, persona_id: &str) -> Result<ActiveSigner> {
        require_active_persona(&self.connection, persona_id)?;
        let active_keys = self
            .list_keys(persona_id)?
            .into_iter()
            .filter(|key| key.status == KeyStatus::Active)
            .collect::<Vec<_>>();
        let key = match active_keys.as_slice() {
            [] => return Err(StoreError::NoActiveKey(persona_id.to_owned())),
            [key] => key.clone(),
            _ => return Err(StoreError::AmbiguousActiveKeys(persona_id.to_owned())),
        };
        let recognized = lookup_key_in(&self.connection, &key.fingerprint)?
            .ok_or_else(|| StoreError::KeyNotFound(key.fingerprint.clone()))?;
        let signing_reference = self
            .lookup_signing_reference(&key.fingerprint)?
            .ok_or_else(|| StoreError::SigningReferenceNotFound(key.fingerprint.clone()))?;
        let resolved =
            validate_signing_reference_path(&signing_reference.locator, &recognized.key)?;
        if resolved != signing_reference.locator {
            return Err(StoreError::UnsafeSigningReference {
                path: signing_reference.locator,
                reason: "canonical target changed since this reference was bound".to_owned(),
            });
        }

        Ok(ActiveSigner {
            persona: recognized.persona,
            key: recognized.key,
            signing_reference,
        })
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

fn list_keys_in(connection: &Connection, persona_id: &str) -> Result<Vec<KeyRecord>> {
    let mut statement = connection.prepare(
        "SELECT fingerprint, persona_id, public_key, provider, status,
                added_at, retired_at, compromised_at
         FROM key_records WHERE persona_id = ?1 ORDER BY added_at, fingerprint",
    )?;
    let rows = statement.query_map([persona_id], raw_key_row)?;
    rows.map(|row| key_from_row(row?)).collect()
}

fn key_history_in(connection: &Connection, persona_id: &str) -> Result<Vec<KeyEvent>> {
    let mut statement = connection.prepare(
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

fn migrate_v2(connection: &mut Connection) -> Result<()> {
    let transaction = connection.transaction()?;
    transaction.execute_batch(
        "CREATE TABLE signing_references (
             key_fingerprint TEXT PRIMARY KEY NOT NULL
                 REFERENCES key_records(fingerprint),
             locator TEXT NOT NULL CHECK(length(locator) BETWEEN 1 AND 4096),
             configured_at INTEGER NOT NULL CHECK(configured_at >= 0)
         ) STRICT;

         CREATE TABLE signing_reference_events (
             sequence INTEGER PRIMARY KEY AUTOINCREMENT,
             key_fingerprint TEXT NOT NULL REFERENCES key_records(fingerprint),
             event_type TEXT NOT NULL CHECK(event_type IN
                 ('bound', 'rebound', 'unbound')),
             occurred_at INTEGER NOT NULL CHECK(occurred_at >= 0)
         ) STRICT;

         CREATE INDEX signing_reference_events_key_idx
             ON signing_reference_events(key_fingerprint, sequence);

         CREATE TRIGGER signing_reference_events_no_update
         BEFORE UPDATE ON signing_reference_events BEGIN
             SELECT RAISE(ABORT, 'signing reference events are append-only');
         END;

         CREATE TRIGGER signing_reference_events_no_delete
         BEFORE DELETE ON signing_reference_events BEGIN
             SELECT RAISE(ABORT, 'signing reference events are append-only');
         END;

         PRAGMA user_version = 2;",
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

fn append_signing_reference_event(
    transaction: &Transaction<'_>,
    fingerprint: &str,
    event_type: &str,
    occurred_at: i64,
) -> Result<()> {
    transaction.execute(
        "INSERT INTO signing_reference_events
         (key_fingerprint, event_type, occurred_at)
         VALUES (?1, ?2, ?3)",
        params![fingerprint, event_type, occurred_at],
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

/// Validate a portable metadata backup before it reaches persistent state.
///
/// This replays lifecycle events rather than trusting the redundant final
/// status fields. Callers should still parse with `deny_unknown_fields`.
pub fn validate_persona_backup(backup: &PersonaBackup) -> Result<()> {
    if backup.schema != PERSONA_BACKUP_SCHEMA {
        return Err(invalid_backup(format!(
            "unsupported schema {}; expected {PERSONA_BACKUP_SCHEMA}",
            backup.schema
        )));
    }
    if backup.exported_at < 0 {
        return Err(invalid_backup("exported_at cannot be negative"));
    }
    let parsed_id = Uuid::parse_str(&backup.persona.id)
        .map_err(|_| invalid_backup("persona.id must be a canonical UUID"))?;
    if parsed_id.to_string() != backup.persona.id {
        return Err(invalid_backup(
            "persona.id must use canonical lowercase UUID encoding",
        ));
    }
    validate_backup_text(
        "backup persona label",
        &backup.persona.label,
        MAX_LABEL_BYTES,
    )?;
    validate_backup_time(
        "persona.created_at",
        backup.persona.created_at,
        0,
        backup.exported_at,
    )?;
    if let Some(archived_at) = backup.persona.archived_at {
        validate_backup_time(
            "persona.archived_at",
            archived_at,
            backup.persona.created_at,
            backup.exported_at,
        )?;
    }
    if backup.keys.len() > MAX_PERSONA_BACKUP_KEYS {
        return Err(invalid_backup(format!(
            "keys cannot contain more than {MAX_PERSONA_BACKUP_KEYS} entries"
        )));
    }
    if backup.events.len() > MAX_PERSONA_BACKUP_EVENTS {
        return Err(invalid_backup(format!(
            "events cannot contain more than {MAX_PERSONA_BACKUP_EVENTS} entries"
        )));
    }

    let mut keys_by_fingerprint = HashMap::with_capacity(backup.keys.len());
    for key in &backup.keys {
        validate_backup_public_key(key)?;
        validate_backup_time(
            "key.added_at",
            key.added_at,
            backup.persona.created_at,
            backup.exported_at,
        )?;
        if let Some(retired_at) = key.retired_at {
            validate_backup_time(
                "key.retired_at",
                retired_at,
                key.added_at,
                backup.exported_at,
            )?;
        }
        if let Some(compromised_at) = key.compromised_at {
            validate_backup_time(
                "key.compromised_at",
                compromised_at,
                key.added_at,
                backup.exported_at,
            )?;
        }
        match key.status {
            KeyStatus::Active if key.retired_at.is_none() && key.compromised_at.is_none() => {}
            KeyStatus::Retired if key.retired_at.is_some() && key.compromised_at.is_none() => {}
            KeyStatus::Compromised if key.compromised_at.is_some() => {
                if let Some(retired_at) = key.retired_at
                    && retired_at > key.compromised_at.expect("checked above")
                {
                    return Err(invalid_backup(format!(
                        "key {} was compromised before its recorded retirement",
                        key.fingerprint
                    )));
                }
            }
            _ => {
                return Err(invalid_backup(format!(
                    "key {} has timestamps inconsistent with status {}",
                    key.fingerprint,
                    key.status.as_str()
                )));
            }
        }
        if keys_by_fingerprint
            .insert(key.fingerprint.as_str(), key)
            .is_some()
        {
            return Err(invalid_backup(format!(
                "duplicate key fingerprint {}",
                key.fingerprint
            )));
        }
    }

    let mut states = HashMap::<&str, KeyStatus>::with_capacity(backup.keys.len());
    let mut last_event_times = HashMap::<&str, i64>::with_capacity(backup.keys.len());
    let mut observed_retirements = HashSet::<&str>::with_capacity(backup.keys.len());
    let mut observed_compromises = HashSet::<&str>::with_capacity(backup.keys.len());
    for (index, event) in backup.events.iter().enumerate() {
        let expected_ordinal =
            u32::try_from(index + 1).expect("backup event bound fits in a u32 ordinal");
        if event.ordinal != expected_ordinal {
            return Err(invalid_backup(format!(
                "event ordinal {} is out of sequence; expected {expected_ordinal}",
                event.ordinal
            )));
        }
        let key = keys_by_fingerprint
            .get(event.key_fingerprint.as_str())
            .copied()
            .ok_or_else(|| {
                invalid_backup(format!(
                    "event {} references unknown key {}",
                    event.ordinal, event.key_fingerprint
                ))
            })?;
        validate_backup_time(
            "event.occurred_at",
            event.occurred_at,
            backup.persona.created_at,
            backup.exported_at,
        )?;
        validate_backup_text("backup event actor", &event.actor, MAX_ACTOR_BYTES)?;
        validate_backup_text("backup event policy", &event.policy, MAX_POLICY_BYTES)?;
        if let Some(note) = &event.note {
            validate_backup_text("backup event note", note, MAX_NOTE_BYTES)?;
        }

        let fingerprint = key.fingerprint.as_str();
        if let Some(previous_time) = last_event_times.get(fingerprint)
            && event.occurred_at < *previous_time
        {
            return Err(invalid_backup(format!(
                "events for key {fingerprint} move backward in time"
            )));
        }
        let next_status = match (states.get(fingerprint).copied(), event.event_type.as_str()) {
            (None, "enrolled" | "rotated_in") if event.occurred_at == key.added_at => {
                KeyStatus::Active
            }
            (Some(KeyStatus::Active), "retired") if key.retired_at == Some(event.occurred_at) => {
                observed_retirements.insert(fingerprint);
                KeyStatus::Retired
            }
            (Some(KeyStatus::Active | KeyStatus::Retired), "compromised")
                if key.compromised_at == Some(event.occurred_at) =>
            {
                observed_compromises.insert(fingerprint);
                KeyStatus::Compromised
            }
            (None, "enrolled" | "rotated_in") => {
                return Err(invalid_backup(format!(
                    "initial event time for key {fingerprint} does not match added_at"
                )));
            }
            (_, "enrolled" | "rotated_in" | "retired" | "compromised") => {
                return Err(invalid_backup(format!(
                    "invalid {} transition for key {fingerprint}",
                    event.event_type
                )));
            }
            _ => {
                return Err(invalid_backup(format!(
                    "unknown lifecycle event type {}",
                    event.event_type
                )));
            }
        };
        states.insert(fingerprint, next_status);
        last_event_times.insert(fingerprint, event.occurred_at);
    }

    for key in &backup.keys {
        let fingerprint = key.fingerprint.as_str();
        let replayed = states.get(fingerprint).copied().ok_or_else(|| {
            invalid_backup(format!(
                "key {fingerprint} has no enrollment or rotation event"
            ))
        })?;
        if replayed != key.status {
            return Err(invalid_backup(format!(
                "event history for key {fingerprint} ends as {}, not {}",
                replayed.as_str(),
                key.status.as_str()
            )));
        }
        if key.retired_at.is_some() != observed_retirements.contains(fingerprint) {
            return Err(invalid_backup(format!(
                "retirement timestamp/event mismatch for key {fingerprint}"
            )));
        }
        if key.compromised_at.is_some() != observed_compromises.contains(fingerprint) {
            return Err(invalid_backup(format!(
                "compromise timestamp/event mismatch for key {fingerprint}"
            )));
        }
    }
    Ok(())
}

fn validate_backup_public_key(key: &BackupKey) -> Result<()> {
    if key.public_key.is_empty() {
        return Err(invalid_backup(format!(
            "public key {} cannot be empty",
            key.fingerprint
        )));
    }
    if u64::try_from(key.public_key.len()).unwrap_or(u64::MAX) > MAX_PUBLIC_KEY_BYTES {
        return Err(invalid_backup(format!(
            "public key {} exceeds {MAX_PUBLIC_KEY_BYTES} UTF-8 bytes",
            key.fingerprint
        )));
    }
    if key.public_key.trim() != key.public_key {
        return Err(invalid_backup(format!(
            "public key {} has surrounding whitespace",
            key.fingerprint
        )));
    }
    if key.public_key.chars().any(is_unsafe_display_character) {
        return Err(invalid_backup(format!(
            "public key {} contains control or bidirectional formatting characters",
            key.fingerprint
        )));
    }
    validate_provider_key(&key.public_key, key.provider)?;
    let computed = fingerprint(&key.public_key)?;
    if computed != key.fingerprint {
        return Err(invalid_backup(format!(
            "public key fingerprint mismatch: recorded {}, computed {computed}",
            key.fingerprint
        )));
    }
    Ok(())
}

fn validate_backup_text(field: &'static str, value: &str, maximum: usize) -> Result<()> {
    let canonical = validate_required_text(field, value, maximum)?;
    if canonical != value {
        Err(StoreError::InvalidField {
            field,
            reason: "surrounding whitespace is not canonical in a backup".to_owned(),
        })
    } else {
        Ok(())
    }
}

fn validate_backup_time(field: &str, value: i64, minimum: i64, maximum: i64) -> Result<()> {
    if (minimum..=maximum).contains(&value) {
        Ok(())
    } else {
        Err(invalid_backup(format!(
            "{field} must be between {minimum} and {maximum}; found {value}"
        )))
    }
}

fn invalid_backup(reason: impl Into<String>) -> StoreError {
    StoreError::InvalidField {
        field: "persona backup",
        reason: reason.into(),
    }
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

fn validate_signing_reference_path(path: &Path, key: &KeyRecord) -> Result<PathBuf> {
    if !path.is_absolute() {
        return Err(unsafe_signing_reference(path, "the path must be absolute"));
    }
    validate_signing_reference_text(path)?;

    let entry_metadata = fs::symlink_metadata(path).map_err(|source| StoreError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    if entry_metadata.file_type().is_symlink() {
        return Err(unsafe_signing_reference(
            path,
            "symbolic links are not allowed",
        ));
    }

    let canonical = fs::canonicalize(path).map_err(|source| StoreError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    validate_signing_reference_text(&canonical)?;
    let metadata = fs::symlink_metadata(&canonical).map_err(|source| StoreError::Io {
        path: canonical.clone(),
        source,
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(unsafe_signing_reference(
            &canonical,
            "the target must be a regular non-symlink file",
        ));
    }
    if metadata.len() == 0 {
        return Err(unsafe_signing_reference(
            &canonical,
            "the referenced file cannot be empty",
        ));
    }
    validate_signing_reference_permissions(&canonical, &metadata, key.provider)?;

    if key.provider == KeyProvider::SshAgent {
        if metadata.len() > MAX_PUBLIC_KEY_BYTES {
            return Err(unsafe_signing_reference(
                &canonical,
                "the SSH-agent public-key stub is too large",
            ));
        }
        let public_key = fs::read_to_string(&canonical).map_err(|source| StoreError::Io {
            path: canonical.clone(),
            source,
        })?;
        let locator_fingerprint = fingerprint(public_key.trim()).map_err(|_| {
            unsafe_signing_reference(
                &canonical,
                "the SSH-agent stub is not a valid OpenSSH public key",
            )
        })?;
        if locator_fingerprint != key.fingerprint {
            return Err(unsafe_signing_reference(
                &canonical,
                "the SSH-agent public-key stub does not match the registered key",
            ));
        }
    }

    Ok(canonical)
}

fn validate_signing_reference_text(path: &Path) -> Result<()> {
    let text = path
        .to_str()
        .ok_or_else(|| unsafe_signing_reference(path, "the path must be valid UTF-8"))?;
    if text.len() > MAX_SIGNING_REFERENCE_BYTES {
        return Err(unsafe_signing_reference(
            path,
            &format!("the path cannot exceed {MAX_SIGNING_REFERENCE_BYTES} UTF-8 bytes"),
        ));
    }
    if text.chars().any(is_unsafe_display_character) {
        return Err(unsafe_signing_reference(
            path,
            "control and bidirectional formatting characters are not allowed",
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn validate_signing_reference_permissions(
    path: &Path,
    metadata: &fs::Metadata,
    provider: KeyProvider,
) -> Result<()> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let owner = metadata.uid();
    let expected_owner = rustix::process::geteuid().as_raw();
    let root_owned_public_stub = provider == KeyProvider::SshAgent && owner == 0;
    if owner != expected_owner && !root_owned_public_stub {
        return Err(unsafe_signing_reference(
            path,
            &format!("owner UID {owner} is not the current effective UID {expected_owner}"),
        ));
    }

    let mode = metadata.permissions().mode();
    if mode & 0o022 != 0 {
        return Err(unsafe_signing_reference(
            path,
            "group/world-writable files are not allowed",
        ));
    }
    if provider != KeyProvider::SshAgent && mode & 0o077 != 0 {
        return Err(unsafe_signing_reference(
            path,
            "private and hardware-key stubs cannot grant group/world permissions",
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_signing_reference_permissions(
    _path: &Path,
    _metadata: &fs::Metadata,
    _provider: KeyProvider,
) -> Result<()> {
    Ok(())
}

fn unsafe_signing_reference(path: &Path, reason: &str) -> StoreError {
    StoreError::UnsafeSigningReference {
        path: path.to_path_buf(),
        reason: reason.to_owned(),
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
    use std::path::Path;

    use super::*;

    const KEY_ONE: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIK2wZ6f9bI6YlF1YyW5iU+a4jvfp9DCf3j6PYfnT1rYA";
    const KEY_TWO: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGfX7hAdqGfF0mYz2oD88dL84M2yr2KoXqhh7sSRvqHQ";

    fn private_locator(directory: &Path, name: &str) -> PathBuf {
        let path = directory.join(name);
        fs::write(
            &path,
            b"opaque private key material is not read by the store",
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        path
    }

    fn active_backup() -> PersonaBackup {
        let mut store = PersonaStore::open_in_memory().unwrap();
        let persona = store
            .create_persona("Portable publisher", PersonaPurpose::Project)
            .unwrap();
        store
            .enroll_key(&persona.id, KEY_ONE, KeyProvider::OpensshFile)
            .unwrap();
        store.export_persona_backup(&persona.id).unwrap()
    }

    #[test]
    fn round_trips_metadata_without_restoring_signing_authority() {
        let directory = tempfile::tempdir().unwrap();
        let active_locator = private_locator(directory.path(), "active-key");
        let mut source = PersonaStore::open_in_memory().unwrap();
        let persona = source
            .create_persona("Portable project", PersonaPurpose::Project)
            .unwrap();
        source
            .enroll_key(&persona.id, KEY_ONE, KeyProvider::OpensshFile)
            .unwrap();
        let active_key = source
            .rotate_key(
                &persona.id,
                KEY_TWO,
                KeyProvider::OpensshFile,
                RotationReason::Routine,
                Some("scheduled replacement"),
            )
            .unwrap();
        source
            .bind_signing_reference(&active_key.fingerprint, &active_locator)
            .unwrap();

        let backup = source.export_persona_backup(&persona.id).unwrap();
        let mut destination = PersonaStore::open_in_memory().unwrap();
        let imported = destination.import_persona_backup(&backup).unwrap();
        let restored = destination.export_persona_backup(&imported.id).unwrap();

        assert_eq!(imported, persona);
        assert_eq!(restored.persona, backup.persona);
        assert_eq!(restored.keys, backup.keys);
        assert_eq!(restored.events, backup.events);
        assert!(matches!(
            destination.active_signer_for_persona(&persona.id),
            Err(StoreError::SigningReferenceNotFound(fingerprint))
                if fingerprint == active_key.fingerprint
        ));
        assert!(
            destination
                .signing_reference_history(&active_key.fingerprint)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn rejects_tampered_backup_before_writing_any_state() {
        let mut backup = active_backup();
        backup.keys[0].fingerprint = "SHA256:tampered".to_owned();
        let mut destination = PersonaStore::open_in_memory().unwrap();

        let error = destination.import_persona_backup(&backup).unwrap_err();

        assert!(matches!(error, StoreError::InvalidField { .. }));
        assert!(destination.list_personas().unwrap().is_empty());
    }

    #[test]
    fn rejects_backup_whose_events_do_not_reproduce_key_state() {
        let mut backup = active_backup();
        let added_at = backup.keys[0].added_at;
        backup.keys[0].status = KeyStatus::Retired;
        backup.keys[0].retired_at = Some(added_at);

        let error = validate_persona_backup(&backup).unwrap_err();

        assert!(matches!(error, StoreError::InvalidField { .. }));
    }

    #[test]
    fn refuses_persona_and_key_collisions_without_merging() {
        let backup = active_backup();
        let mut destination = PersonaStore::open_in_memory().unwrap();
        let existing = destination
            .create_persona("Existing", PersonaPurpose::Pseudonymous)
            .unwrap();
        destination
            .enroll_key(&existing.id, KEY_ONE, KeyProvider::SshAgent)
            .unwrap();

        assert!(matches!(
            destination.import_persona_backup(&backup),
            Err(StoreError::KeyAlreadyKnown(_))
        ));
        assert_eq!(destination.list_personas().unwrap(), [existing]);

        let mut clean_destination = PersonaStore::open_in_memory().unwrap();
        clean_destination.import_persona_backup(&backup).unwrap();
        assert!(matches!(
            clean_destination.import_persona_backup(&backup),
            Err(StoreError::PersonaAlreadyKnown(id)) if id == backup.persona.id
        ));
    }

    #[test]
    fn rejects_unknown_backup_schema_and_noncanonical_fields() {
        let mut backup = active_backup();
        backup.schema = "urn:a-quo:persona-metadata-backup:v2".to_owned();
        assert!(validate_persona_backup(&backup).is_err());

        let mut backup = active_backup();
        backup.persona.label.push(' ');
        assert!(validate_persona_backup(&backup).is_err());

        let mut backup = active_backup();
        backup.events[0].ordinal = 2;
        assert!(validate_persona_backup(&backup).is_err());
    }

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

    #[test]
    fn migrates_v1_stores_to_signing_reference_schema() {
        let mut connection = Connection::open_in_memory().unwrap();
        migrate_v1(&mut connection).unwrap();
        let before: i64 = connection
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .unwrap();
        assert_eq!(before, 1);

        let store = PersonaStore::initialize(connection).unwrap();
        let after: i64 = store
            .connection
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .unwrap();
        assert_eq!(after, SCHEMA_VERSION);
        let tables: i64 = store
            .connection
            .query_row(
                "SELECT count(*) FROM sqlite_schema
                 WHERE type = 'table' AND name IN
                     ('signing_references', 'signing_reference_events')",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(tables, 2);
    }

    #[test]
    fn binds_rebinds_resolves_and_unbinds_without_key_contents() {
        let directory = tempfile::tempdir().unwrap();
        let first_path = private_locator(directory.path(), "first-key");
        let second_path = private_locator(directory.path(), "moved-key");
        let mut store = PersonaStore::open_in_memory().unwrap();
        let persona = store
            .create_persona("Signing project", PersonaPurpose::Project)
            .unwrap();
        let key = store
            .enroll_key(&persona.id, KEY_ONE, KeyProvider::OpensshFile)
            .unwrap();

        let first = store
            .bind_signing_reference(&key.fingerprint, &first_path)
            .unwrap();
        assert_eq!(first.locator, fs::canonicalize(&first_path).unwrap());
        let active = store.active_signer_for_persona(&persona.id).unwrap();
        assert_eq!(active.persona, persona);
        assert_eq!(active.key, key);
        assert_eq!(active.signing_reference, first);

        let rebound = store
            .bind_signing_reference(&key.fingerprint, &second_path)
            .unwrap();
        assert_eq!(
            store
                .active_signer_for_persona(&persona.id)
                .unwrap()
                .signing_reference,
            rebound
        );
        store.unbind_signing_reference(&key.fingerprint).unwrap();
        assert!(matches!(
            store.active_signer_for_persona(&persona.id),
            Err(StoreError::SigningReferenceNotFound(_))
        ));
        assert_eq!(
            store
                .signing_reference_history(&key.fingerprint)
                .unwrap()
                .iter()
                .map(|event| event.event_type.as_str())
                .collect::<Vec<_>>(),
            ["bound", "rebound", "unbound"]
        );
        assert!(
            store
                .connection
                .execute("DELETE FROM signing_reference_events", [])
                .is_err()
        );
    }

    #[test]
    fn rotated_and_compromised_keys_fail_closed() {
        let directory = tempfile::tempdir().unwrap();
        let first_path = private_locator(directory.path(), "first-key");
        let second_path = private_locator(directory.path(), "second-key");
        let mut store = PersonaStore::open_in_memory().unwrap();
        let persona = store
            .create_persona("Rotation project", PersonaPurpose::Project)
            .unwrap();
        let first = store
            .enroll_key(&persona.id, KEY_ONE, KeyProvider::OpensshFile)
            .unwrap();
        store
            .bind_signing_reference(&first.fingerprint, &first_path)
            .unwrap();
        let second = store
            .rotate_key(
                &persona.id,
                KEY_TWO,
                KeyProvider::OpensshFile,
                RotationReason::Routine,
                None,
            )
            .unwrap();
        assert!(matches!(
            store.bind_signing_reference(&first.fingerprint, &first_path),
            Err(StoreError::InactiveSigningKey(_))
        ));
        assert!(matches!(
            store.active_signer_for_persona(&persona.id),
            Err(StoreError::SigningReferenceNotFound(fingerprint))
                if fingerprint == second.fingerprint
        ));
        store
            .bind_signing_reference(&second.fingerprint, &second_path)
            .unwrap();
        assert_eq!(
            store
                .active_signer_for_persona(&persona.id)
                .unwrap()
                .key
                .fingerprint,
            second.fingerprint
        );
        store
            .mark_key_compromised(
                &second.fingerprint,
                "Project owner",
                "example.invalid/compromise-policy",
                None,
            )
            .unwrap();
        assert!(matches!(
            store.bind_signing_reference(&second.fingerprint, &second_path),
            Err(StoreError::InactiveSigningKey(_))
        ));
        assert!(matches!(
            store.active_signer_for_persona(&persona.id),
            Err(StoreError::NoActiveKey(_))
        ));
    }

    #[test]
    fn refuses_multiple_active_keys_during_signer_resolution() {
        let mut store = PersonaStore::open_in_memory().unwrap();
        let persona = store
            .create_persona("Ambiguous project", PersonaPurpose::Project)
            .unwrap();
        store
            .enroll_key(&persona.id, KEY_ONE, KeyProvider::OpensshFile)
            .unwrap();
        store
            .enroll_key(&persona.id, KEY_TWO, KeyProvider::OpensshFile)
            .unwrap();
        assert!(matches!(
            store.active_signer_for_persona(&persona.id),
            Err(StoreError::AmbiguousActiveKeys(id)) if id == persona.id
        ));
    }

    #[test]
    fn ssh_agent_reference_must_match_registered_public_key() {
        let directory = tempfile::tempdir().unwrap();
        let wrong_stub = directory.path().join("wrong.pub");
        let correct_stub = directory.path().join("correct.pub");
        fs::write(&wrong_stub, format!("{KEY_TWO}\n")).unwrap();
        fs::write(&correct_stub, format!("{KEY_ONE} comment\n")).unwrap();
        let mut store = PersonaStore::open_in_memory().unwrap();
        let persona = store
            .create_persona("Agent publisher", PersonaPurpose::Project)
            .unwrap();
        let key = store
            .enroll_key(&persona.id, KEY_ONE, KeyProvider::SshAgent)
            .unwrap();

        assert!(matches!(
            store.bind_signing_reference(&key.fingerprint, &wrong_stub),
            Err(StoreError::UnsafeSigningReference { .. })
        ));
        store
            .bind_signing_reference(&key.fingerprint, &correct_stub)
            .unwrap();
        assert!(store.active_signer_for_persona(&persona.id).is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlink_and_permissive_private_key_references() {
        use std::os::unix::fs::{PermissionsExt, symlink};

        let directory = tempfile::tempdir().unwrap();
        let private_path = private_locator(directory.path(), "private-key");
        let symlink_path = directory.path().join("key-link");
        symlink(&private_path, &symlink_path).unwrap();
        let permissive_path = private_locator(directory.path(), "permissive-key");
        fs::set_permissions(&permissive_path, fs::Permissions::from_mode(0o644)).unwrap();
        let mut store = PersonaStore::open_in_memory().unwrap();
        let persona = store
            .create_persona("Strict publisher", PersonaPurpose::Project)
            .unwrap();
        let key = store
            .enroll_key(&persona.id, KEY_ONE, KeyProvider::OpensshFile)
            .unwrap();

        for path in [&symlink_path, &permissive_path] {
            assert!(matches!(
                store.bind_signing_reference(&key.fingerprint, path),
                Err(StoreError::UnsafeSigningReference { .. })
            ));
        }
    }
}
